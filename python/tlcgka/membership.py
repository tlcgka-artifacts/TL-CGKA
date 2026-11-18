"""Core membership changes over serial, reliable delivery.

Members use authenticated X25519 channels for private updates. Pending
source-tree changes are drained before the next group epoch."""
from dataclasses import dataclass
from . import crypto as c, gua, ubkem, refresh
from .codec import pack, unpack, require
from .tl import Core, Ordinary, Source
from .driver import Trace, round_update, local_phase


class Channels:
    def __init__(self, members):
        self.keys = {i: c.nike_gen() for i in members}

    def register(self, member):
        require(member not in self.keys, "duplicate channel identity")
        self.keys[member] = c.nike_gen()

    def deliver(self, source, recipient, value, context, trace):
        ad = ("private", source, recipient, context)
        def send():
            key = c.kdf("private-channel", c.nike(self.keys[source][0], self.keys[recipient][1]), ad)
            return c.seal(key, pack(value), ad)
        wire = trace.timed("private_send", source, send)
        trace.sent("private", source, wire, (recipient,))
        def receive():
            key = c.kdf("private-channel", c.nike(self.keys[recipient][0], self.keys[source][1]), ad)
            return unpack(c.open_seal(key, wire, ad))
        return trace.timed("private_receive", recipient, receive)


@dataclass
class Candidate:
    parent: tuple
    wire: bytes
    target_path: object
    global_next: object
    local_next: object
    tree_next: object


class Membership:
    def __init__(self, group):
        self.group = group
        self.channels = Channels((*group.cores, *group.ordinary))
        self.pending = {}
        self.queues = {i: [] for i in group.cores}
        self.version = 0

    def change_core(self, sponsor, op, target, public_global, public_local):
        g = self.group
        x = g.cores[sponsor]
        require(not self.pending and all(v.pending is None for v in g.cores.values()), "operation already pending")
        require(not any(self.queues.values()), "finish the preceding serial membership transaction first")
        require(op in ("A", "R") and target != sponsor, "invalid core operation")
        ids, users = g.subgroups[x.subgroup]
        if op == "A":
            require(target not in g.cores and target not in g.ordinary, "identity already present")
        else:
            require(target in ids, "target is not a local core")
        header = (g.gid, self.version, x.epoch, x.subgroup, sponsor, op, target, x.history)
        wg, sg = refresh.change(x.global_state, op, target, public_global, header, outer_authenticated=True)
        wl, sl = refresh.change(x.local, op, target, public_local, header, outer_authenticated=True)
        if op == "A":
            ek, dk, cm = ubkem.add(x.ek, target)
        else:
            ek, cm = ubkem.rmv(x.ek, target)
            dk = None
        body = (header, wg, wl, cm, sl.roster)
        wire = pack((body, c.sign(x.global_state.sk, c.digest("ChangeCore", body)),
                     c.sign(x.local.sk, c.digest("ChangeCore", body))))
        candidate = Candidate((x.global_state, x.local, x.ek), wire, dk, sg, sl, ek)
        self.pending[sponsor] = candidate
        return wire, dk

    def _process(self, member, wire, old_global, old_local, new_secrets=None):
        g = self.group
        body, authg, authl = unpack(wire)
        require(isinstance(body, tuple) and len(body) == 5, "invalid core membership control")
        header, wg, wl, cm, local_roster = body
        gid, version, epoch, subgroup, sponsor, op, target, history = header
        require((gid, version) == (g.gid, self.version), "membership replay/context mismatch")
        if not (op == "A" and member == target):
            client = g.cores.get(member) or g.ordinary[member]
            require(epoch == client.epoch and history == client.history, "membership predecessor/history mismatch")
        ids, users = g.subgroups[subgroup]
        require(sponsor in ids and op in ("A", "R"), "invalid sponsor/operation")
        require(op != "R" or member != target, "removed member has no next state")
        local = member in (*ids, *users) or (op == "A" and member == target)
        core = member in g.cores or (op == "A" and member == target)
        if core:
            require(c.verify(dict(old_global[2])[sponsor], c.digest("ChangeCore", body), authg), "global auth failed")
        if local:
            vk = dict(old_local[2])[sponsor] if core else client.sources[sponsor].verification_key
            require(c.verify(vk, c.digest("ChangeCore", body), authl), "local auth failed")
        sg = sl = new_path = None
        if member == sponsor:
            candidate = self.pending[sponsor]
            x = g.cores[sponsor]
            require(candidate.wire == wire and candidate.parent == (x.global_state, x.local, x.ek), "stale candidate")
            require(candidate.local_next.roster == local_roster, "local refresh roster mismatch")
            return candidate.global_next, candidate.local_next, None
        if core:
            sk = new_secrets[0] if member == target and op == "A" else g.cores[member].global_state.sk
            sg = refresh.recover(old_global, member, sk, wg, header, outer_authenticated=True)
        if local and core:
            sk = new_secrets[1] if member == target and op == "A" else g.cores[member].local.sk
            sl = refresh.recover(old_local, member, sk, wl, header, outer_authenticated=True)
            require(sl.roster == local_roster, "local refresh roster mismatch")
        if local and member != target:
            client = g.cores.get(member) or g.ordinary[member]
            new_path = ubkem.proc(client.sources[sponsor].path, cm)
        return sg, sl, new_path

    @local_phase
    def change(self, sponsor, op, target):
        """ChangeCore -> Process -> private provisioning. Does not drain others' queues."""
        g, trace = self.group, Trace()
        x = g.cores[sponsor]
        subgroup = x.subgroup
        ids, users = g.subgroups[subgroup]
        old_global, old_local = refresh.anchor(x.global_state), refresh.anchor(x.local)
        secrets = None
        if op == "A":
            secrets = trace.timed("joiner_keygen", target, lambda: (c.scalar(), c.scalar()))
            require(target not in self.channels.keys, "duplicate channel identity")
            pks = tuple(c.base(sk) for sk in secrets)
        else:
            pks = (dict(old_global[2])[target], dict(old_local[2])[target])
        wire, dk = trace.timed("change_core", sponsor, self.change_core, sponsor, op, target, *pks)
        body = unpack(wire)[0]
        header, public_keys = body[0], dict(body[4])
        active = set((*g.cores, *g.ordinary))
        active = active | {target} if op == "A" else active - {target}
        # Figure 3 advances xi; the serialized experiment delivers the control
        # to every continuing client. Remote ordinary clients only advance xi.
        trace.sent("membership_control", sponsor, wire, sorted(active - {sponsor}))
        candidates = {}
        for i in sorted(active):
            candidates[i] = trace.timed("process_membership", i, self._process, i, wire,
                                         old_global, old_local, secrets if i == target else None)
        staged_paths = {}
        if op == "A":
            # Existing authenticated public anchors provision the joiner; private
            # source path delivery is explicitly serialized and measured.
            trace.timed("channel_keygen", target, self.channels.register, target)
            trace.sent("join_context", sponsor, pack((old_global, old_local)), (target,))
            value = self.channels.deliver(sponsor, target, dk.record(), header, trace)
            staged_paths[sponsor] = Source(ubkem.Receiver.read(value), public_keys[sponsor])
            recipients = tuple((*ids, *users))
            own_tree, own_paths = trace.timed("joiner_tree_init", target, ubkem.gen, recipients)
            own_vk = public_keys[target]
            delivered = {}
            for i, path_state in zip(recipients, own_paths):
                record = self.channels.deliver(target, i, path_state.record(), header, trace)
                delivered[i] = Source(ubkem.Receiver.read(record), own_vk)
        # Commit only after all validation/private delivery above succeeded.
        for i in sorted(active):
            sg, sl, path_state = candidates[i]
            if op == "A" and i == target:
                continue
            client = g.cores.get(i) or g.ordinary[i]
            if sg is not None:
                client.global_state = sg
            if sl is not None:
                client.local = sl
            if i == sponsor:
                client.ek = self.pending[sponsor].tree_next
            elif path_state is not None:
                client.sources[sponsor] = Source(path_state, public_keys[sponsor])
            if client.subgroup == subgroup:
                if op == "R":
                    client.sources.pop(target, None)
                else:
                    client.sources[target] = delivered[i]
            client.epoch += 1
        new_ids = tuple(sorted((*ids, target))) if op == "A" else tuple(i for i in ids if i != target)
        if op == "A":
            sg, sl, _ = candidates[target]
            g.cores[target] = Core(g.gid, subgroup, target, sl, sg, own_tree, staged_paths,
                                   epoch=x.epoch, strict_i_equals_f=x.strict_i_equals_f, history=x.history)
            self.queues[target] = []
        else:
            del g.cores[target]
            self.queues.pop(target)
        roster = list(g.subgroups)
        roster[subgroup] = (new_ids, users)
        g.subgroups = tuple(roster)
        for i in (*new_ids, *users):
            client = g.cores.get(i) or g.ordinary[i]
            for source, record in client.sources.items():
                client.sources[source] = Source(record.path, public_keys[source])
        for i in new_ids:
            if i not in (sponsor, target):
                self.queues[i].append((op, target, c.digest("M_op", wire)))
        self.pending.clear()
        self.version += 1
        g.nonce_service.reconfigure(g.cores, trace)
        return trace

    def process_ordinary(self, member, wire):
        """Authenticate an ordinary membership change and return the staged receiver path."""
        g = self.group
        control = unpack(wire)
        require(isinstance(control, tuple) and len(control) == 3, "invalid ordinary control")
        body, global_sig, local_sig = control
        require(isinstance(body, tuple) and len(body) == 2, "invalid ordinary control body")
        header, tree_update = body
        require(isinstance(header, tuple) and len(header) == 9, "invalid ordinary control header")
        kind, gid, version, epoch, history, subgroup, sponsor, op, target = header
        require((kind, gid, version) == ("ordinary", g.gid, self.version), "ordinary replay/context mismatch")
        client = g.cores.get(member) or g.ordinary.get(member)
        require(client is not None and subgroup == client.subgroup, "invalid ordinary subgroup")
        cores, users = g.subgroups[subgroup]
        require(sponsor in cores and sponsor != target, "invalid ordinary sponsor")
        require((epoch, history) == (client.epoch, client.history), "ordinary predecessor/context mismatch")
        if op == "A":
            require(target not in g.cores and target not in g.ordinary, "identity already present")
        else:
            require(op == "R" and target in users and member != target, "invalid ordinary removal")
        tag = c.digest("ChangeOrdinary", body)
        if member in g.cores:
            require(c.verify(dict(client.global_state.roster)[sponsor], tag, global_sig), "ordinary global auth failed")
            vk = dict(client.local.roster)[sponsor]
        else:
            vk = client.sources[sponsor].verification_key
        require(c.verify(vk, tag, local_sig), "ordinary local auth failed")
        if member != sponsor:
            return ubkem.proc(client.sources[sponsor].path, tree_update)
        return None

    @local_phase
    def change_ordinary(self, sponsor, op, target):
        """Add or remove one receiver in the sponsor's subgroup."""
        g, trace = self.group, Trace()
        require(not self.pending and not any(self.queues.values()), "operation/queue already pending")
        require(all(x.pending is None and x.nonce is None for x in g.cores.values()), "round already pending")
        require(sponsor in g.cores and sponsor != target and op in ("A", "R"), "invalid ordinary operation")
        core = g.cores[sponsor]
        ids, users = g.subgroups[core.subgroup]
        active = sorted((*ids, *users))
        if op == "A":
            require(target not in g.cores and target not in g.ordinary, "identity already present")
            require(target not in self.channels.keys, "duplicate channel identity")
            tree, join_path, update = ubkem.add(core.ek, target)
            next_users = tuple(sorted((*users, target)))
        else:
            require(target in users, "target is not a local ordinary member")
            require(len(active) > 2, "cannot remove the last source-tree receiver")
            tree, update = ubkem.rmv(core.ek, target)
            active.remove(target)
            next_users = tuple(i for i in users if i != target)

        header = ("ordinary", g.gid, self.version, core.epoch, core.history, core.subgroup, sponsor, op, target)
        body = (header, update)
        tag = c.digest("ChangeOrdinary", body)
        wire = pack((body, c.sign(core.global_state.sk, tag), c.sign(core.local.sk, tag)))
        trace.sent("ordinary_membership_control", sponsor, wire, (i for i in active if i != sponsor))
        paths = {i: self.process_ordinary(i, wire) for i in active}

        if op == "A":
            vk = dict(core.local.roster)[sponsor]
            self.channels.register(target)
            try:
                received_header, control, path, received_vk = self.channels.deliver(
                    sponsor, target, (header, wire, join_path.record(), vk), header, trace)
                signed, _, signature = unpack(control)
                require(received_header == header == signed[0] and
                        c.verify(received_vk, c.digest("ChangeOrdinary", signed), signature),
                        "ordinary join context authentication failed")
                sources = {sponsor: Source(ubkem.Receiver.read(path), received_vk)}
                joined = Ordinary(g.gid, core.subgroup, target, sources, epoch=core.epoch, history=core.history)
            except Exception:
                del self.channels.keys[target]
                raise
            g.ordinary[target] = joined
        else:
            del g.ordinary[target]
            del self.channels.keys[target]
        for i, path in paths.items():
            if path is not None:
                receiver = g.cores.get(i) or g.ordinary[i]
                receiver.sources[sponsor] = Source(path, receiver.sources[sponsor].verification_key)
        core.ek = tree
        roster = list(g.subgroups)
        roster[core.subgroup] = (ids, next_users)
        g.subgroups = tuple(roster)
        op_hash = c.digest("M_op", wire)
        for i in ids:
            if i != sponsor:
                self.queues[i].append((op, target, op_hash))
        self.version += 1
        return trace

    @local_phase
    def drain(self):
        """Consume per-source Figure 3 queues before subsequent key establishment."""
        g, trace = self.group, Trace()
        for source, queue in sorted(self.queues.items()):
            core = g.cores[source]
            while queue:
                op, target, op_hash = queue[0]
                def prepare():
                    if op == "A":
                        ek, dk, cm = ubkem.add(core.ek, target)
                    else:
                        ek, cm = ubkem.rmv(core.ek, target)
                        dk = None
                    body = (g.gid, self.version, source, op, target, op_hash, cm)
                    return ek, dk, pack((body, c.sign(core.local.sk, c.digest("queued-source", body))))
                ek, dk, wire = trace.timed("queue_source", source, prepare)
                ids, users = g.subgroups[core.subgroup]
                recipients = tuple(i for i in (*ids, *users) if i != source)
                trace.sent("queued_source_control", source, wire, recipients)
                for i in recipients:
                    client = g.cores.get(i) or g.ordinary[i]
                    if op == "A" and i == target:
                        value = self.channels.deliver(source, i, (dk.record(), dict(core.local.roster)[source]),
                                                      (op_hash, source), trace)
                        client.sources[source] = Source(ubkem.Receiver.read(value[0]), value[1])
                    else:
                        def process():
                            body, signature = unpack(wire)
                            require(c.verify(client.sources[source].verification_key,
                                             c.digest("queued-source", body), signature), "queue signature failed")
                            return ubkem.proc(client.sources[source].path, body[-1])
                        path_state = trace.timed("queue_receive", i, process)
                        client.sources[source] = Source(path_state, client.sources[source].verification_key)
                core.ek = ek
                queue.pop(0)
        return trace

    def update(self, verify=True):
        require(not any(self.queues.values()) and not self.pending, "membership queues must be completed first")
        return round_update(self.group, verify=verify)
