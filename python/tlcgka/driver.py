"""Route protocol messages between members and collect per-round measurements."""
from dataclasses import dataclass, field
from time import perf_counter_ns, process_time_ns
from functools import wraps
from .codec import pack, require
from . import crypto as c


@dataclass
class Trace:
    timings: dict = field(default_factory=dict)
    cpu_timings: dict = field(default_factory=dict)
    messages: list = field(default_factory=list)
    final_messages: dict = field(default_factory=dict)
    local_elapsed_ns: int = 0
    local_cpu_ns: int = 0
    preprocessing: object = None

    def timed(self, label, member, fn, *args, **kwargs):
        start = perf_counter_ns()
        cpu = process_time_ns()
        result = fn(*args, **kwargs)
        self.cpu_timings.setdefault(label, []).append((member, process_time_ns() - cpu))
        self.timings.setdefault(label, []).append((member, perf_counter_ns() - start))
        return result

    def sent(self, kind, source, wire, recipients):
        self.messages.append((kind, source, len(wire), tuple(recipients)))

    def metrics(self):
        return {
            "local_elapsed_ns": self.local_elapsed_ns,
            "local_cpu_ns": self.local_cpu_ns,
            "operation_ns": self.timings,
            "operation_cpu_ns": self.cpu_timings,
            "logical_bytes": sum(size for _, _, size, _ in self.messages),
            "delivered_bytes": sum(size * len(dst) for _, _, size, dst in self.messages),
            "messages": len(self.messages),
            "wire_by_phase": {kind: sum(size for k, _, size, _ in self.messages if k == kind)
                              for kind in sorted({m[0] for m in self.messages})},
        }


def local_phase(fn):
    """Whole serial local phase, including bookkeeping/encoding/state install.

    Nested Trace.timed entries are diagnostic only: never add them to this
    interval. Initialization, snapshots and external agreement oracles are kept
    outside by callers. No network waiting is simulated. Both clocks retained.
    """
    @wraps(fn)
    def measured(*args, **kwargs):
        wall, cpu = perf_counter_ns(), process_time_ns()
        trace = fn(*args, **kwargs)
        trace.local_cpu_ns = process_time_ns() - cpu
        trace.local_elapsed_ns = perf_counter_ns() - wall
        return trace
    return measured


def prepare_nonces(group):
    epoch = next(iter(group.cores.values())).epoch
    service = group.nonce_service
    if service.ready(epoch + 1):
        return None
    @local_phase
    def prepare():
        trace = Trace()
        service.preprocess(epoch, c.digest('nonce-roster', next(iter(group.cores.values())).global_state.roster), trace)
        return trace
    return prepare()


def round_update(group, rotate=True, handoff=False, deliver=True, verify=True):
    """Preprocessing is accounted separately; online includes server and channels."""
    prep = prepare_nonces(group)
    trace = _round_online(group, rotate, handoff, deliver, verify)
    trace.preprocessing = prep
    return trace


@local_phase
def _round_online(group, rotate, handoff, deliver, verify):
    trace = Trace()
    epoch = next(iter(group.cores.values())).epoch
    require(all(x.epoch == epoch for x in group.cores.values()), "core epochs are not synchronized")
    A, B, broadcasters = [], [], {}
    for s, (ids, _) in enumerate(group.subgroups):
        index = epoch % len(ids) if rotate else 0
        a = ids[index]
        x = ids[(index + 1) % len(ids)] if handoff else a
        A.append((s, a))
        B.append(x)
        broadcasters[s] = x
    A, B = tuple(A), tuple(sorted(B))
    for core in group.cores.values():
        core.configure_round(A, B)
    qls, qgs = {}, []
    for s, a in A:
        ql, qg = trace.timed("prepare", a, group.cores[a].prepare)
        qls[s] = ql
        qgs.append(qg)
        trace.sent("QL", a, ql, [x for x in group.subgroups[s][0] if x != a])
        trace.sent("QG", a, qg, [x for x in group.cores if x != a])
    binding = (group.gid, group.nonce_service.version, epoch + 1, A, B, c.digest('nonce-round', tuple(qgs)))
    prepared = group.nonce_service.aggregate(binding, trace)
    for i, core in group.cores.items():
        core.nonce = prepared[i][1]
    shares = []
    for i, core in group.cores.items():
        wire = trace.timed("share_and_takeover", i, core.share, qls[core.subgroup], qgs,
                           prepared[i][0])
        if wire is not None:
            shares.append(wire)
            trace.sent("confirmation_share", i, wire, [x for x in group.cores if x != i])
    for i, core in group.cores.items():
        send = broadcasters[core.subgroup] == i
        wire = trace.timed("commit", i, core.commit, shares, send)
        if wire is not None:
            trace.final_messages[core.subgroup] = wire
            trace.sent("M", i, wire, group.subgroups[core.subgroup][1])
    if deliver:
        for i, member in group.ordinary.items():
            trace.timed("ordinary_receive", i, member.receive, trace.final_messages[member.subgroup])
        if verify:
            states = {(m.key, m.history) for m in (*group.cores.values(), *group.ordinary.values())}
            require(len(states) == 1 and len(next(iter(states))[0]) == 32, "global key/history agreement failed")
    return trace


def state_sizes(group):
    return {
        "core": [len(pack(x.record())) for x in group.cores.values()],
        "ordinary": [len(pack(x.record())) for x in group.ordinary.values()],
    }
