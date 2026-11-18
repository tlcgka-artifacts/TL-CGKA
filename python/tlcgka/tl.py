"""Two-level group key agreement.

Core members run local and global agreement. Ordinary members receive
subgroup broadcasts. The history digest starts at 32 zero bytes and
advances when a member commits or receives a group key."""
from dataclasses import dataclass, field
from . import crypto as c, gua, ubkem
from .codec import ProtocolError, pack, unpack, require


def local_gid(gid, subgroup):
    return c.digest("local-gid", gid, subgroup)


def global_gid(gid):
    return c.digest("global-gid", gid)


def parse_local(wire):
    value = unpack(wire)
    require(isinstance(value, tuple) and len(value) == 5, "invalid QL")
    P, CL, R, za, CT2 = value
    (h, CG), CT1 = P
    return P, h, CG, CT1, CL, R, za, CT2


@dataclass(frozen=True)
class Source:
    path: ubkem.Receiver
    verification_key: bytes

    def record(self):
        return (self.path.record(), self.verification_key)


@dataclass
class Pending:
    ql: bytes
    local_next: gua.State
    theta: tuple
    source: int
    ek_next: ubkem.Sender | None = None
    dk_next: ubkem.Receiver | None = None
    u_global: int | None = None
    global_candidate: gua.Candidate | None = None
    J: bytes | None = None
    weights: tuple = ()
    qgs: tuple = ()
    share: tuple | None = None


@dataclass
class Core:
    gid: bytes
    subgroup: int
    member: int
    local: gua.State
    global_state: gua.State
    ek: ubkem.Sender
    sources: dict
    epoch: int = 0
    key: bytes | None = None
    pending: Pending | None = None
    contributors: tuple = ()  # (subgroup, source_id)
    confirmers: tuple = ()
    nonce: gua.Nonce | None = None
    strict_i_equals_f: bool = True
    history: bytes = bytes(32)

    def record(self):
        # Committed persistent state; transient pending/nonce state reported separately.
        return (self.gid, self.subgroup, self.member, self.epoch, self.local.record(),
                self.global_state.record(), self.ek.record(),
                tuple((i, src.record()) for i, src in sorted(self.sources.items())), self.key, self.history)

    def configure_round(self, contributors, confirmers):
        require(self.pending is None and self.nonce is None, "round already pending")
        A = tuple(contributors)
        B = tuple(sorted(confirmers))
        require(A and A == tuple(sorted(A)) and len(dict(A)) == len(A), "invalid subgroup set")
        ids = tuple(i for _, i in A)
        require(len(set(ids)) == len(ids) and set(ids) <= dict(self.global_state.roster).keys(), "invalid contributors")
        require(self.subgroup in dict(A) and dict(A)[self.subgroup] in dict(self.local.roster), "wrong local contributor")
        require(B and len(set(B)) == len(B) and set(B) <= dict(self.global_state.roster).keys(), "invalid confirmers")
        if self.strict_i_equals_f:
            require(tuple(sorted(ids)) == B, "restricted paper profile requires A=B")
        self.contributors, self.confirmers = A, B

    def header(self, source):
        return ((self.gid, self.epoch + 1), self.subgroup, source)

    def _check_local_header(self, h):
        a = dict(self.contributors).get(self.subgroup)
        require(h == self.header(a), "QL group/epoch/subgroup/source mismatch")
        return a

    def prepare(self):
        """TL.Prepare 1-17: stage own tree and local GUA; return QL and QG bytes."""
        require(self.pending is None, "duplicate Prepare")
        require(dict(self.contributors).get(self.subgroup) == self.member, "not nominated contributor")
        h = self.header(self.member)
        omega = c.hgroup("sample", c.scalar_bytes(c.scalar()))
        Y = c.hgroup("HG", global_gid(self.gid), h, omega)
        uL, CL = gua.enc(self.local, omega)
        uG, CG = gua.enc(self.global_state, Y)
        v, ciphertext = ubkem.enc(self.ek)
        ad = (h, ciphertext)
        ek_next, kappa = ubkem.fin(v, ad)
        J = c.hgroup("HG", local_gid(self.gid, self.subgroup), kappa, ad)
        p = (h, CG)
        CT1 = c.seal(self.global_state.key, J, p)
        P = (p, CT1)
        aggregate = gua.combine(self.local, {self.member: (CL,)})
        rho = gua.dec(self.local, aggregate.ciphertext)
        local_nonce = gua.Nonce.prepare(("local", self.local.public_context(), h), self.member)
        delta, za = gua.ratchet(self.local, uL, rho, aggregate, (self.member,),
                              local_nonce.R, local_nonce, (self.subgroup, J))
        local_next = gua.confirm(self.local, delta, (za,))
        CT2 = c.seal(local_next.key, ciphertext, c.digest("WL", P, CL))
        ql = pack((P, CL, local_nonce.R, za, CT2))
        qg = pack((P, c.digest("QL", ql)))
        self.pending = Pending(ql, local_next, (ciphertext, kappa, J), self.member,
                               ek_next=ek_next, u_global=uG)
        return ql, qg

    def take_over(self, ql):
        """TL.TakeOver 1-14, including local/global contribution and tree checks."""
        if self.pending is not None:
            require(self.pending.ql == ql, "conflicting local package")
            return self.pending.theta
        P, h, CG, CT1, CL, R, za, CT2 = parse_local(ql)
        a = self._check_local_header(h)
        require(a != self.member and a in self.sources, "missing source-tree receiver state")
        J = c.point(c.open_seal(self.global_state.key, CT1, (h, CG)))
        omega = gua.dec(self.local, CL)
        require(gua.dec(self.global_state, CG) == c.hgroup("HG", global_gid(self.gid), h, omega),
                "local/global GUA contribution mismatch")
        aggregate = gua.combine(self.local, {a: (CL,)})
        delta, unused = gua.ratchet(self.local, None, gua.dec(self.local, aggregate.ciphertext),
                                  aggregate, (a,), R, None, (self.subgroup, J))
        require(unused is None, "unexpected local confirmer")
        local_next = gua.confirm(self.local, delta, (za,))
        ciphertext = c.open_seal(local_next.key, CT2, c.digest("WL", P, CL))
        dk_next, kappa = ubkem.dec(self.sources[a].path, (h, ciphertext), ciphertext)
        require(J == c.hgroup("HG", local_gid(self.gid, self.subgroup), kappa, (h, ciphertext)),
                "UB-KEM root does not match authenticated subgroup contribution")
        self.pending = Pending(ql, local_next, (ciphertext, kappa, J), a, dk_next=dk_next)
        return self.pending.theta

    def nonce_prepare(self):
        require(self.member in self.confirmers and self.nonce is None, "unexpected/repeated nonce preparation")
        self.nonce = gua.Nonce.prepare(self.nonce_context(), self.member)
        return pack(self.nonce.commitment())

    def nonce_context(self):
        return (self.global_state.public_context(), self.contributors, self.confirmers)

    def nonce_open(self):
        require(self.nonce is not None, "nonce was not committed")
        return pack(self.nonce.opening())

    def share(self, ql, qgs, R):
        """TL.Share 1-8; R arrives through the trusted nonce service channel."""
        self.take_over(ql)
        pending = self.pending
        if pending.global_candidate is not None:
            require(pending.qgs == tuple(qgs), "conflicting global transcript")
            require(pending.global_candidate.R == R, "conflicting aggregate nonce")
            # Never produce a second share with the same nonce.
            return pack(pending.share) if pending.share else None
        P, h, _, _, _, _, _, _ = parse_local(ql)
        received, contributions, subgroup_J = {}, {}, {}
        for qg in qgs:
            other_P, ql_hash = unpack(qg)
            (other_h, CG), CT1 = other_P
            (gid, epoch), subgroup, source = other_h
            require(gid == self.gid and epoch == self.epoch + 1, "global package group/epoch mismatch")
            require(subgroup not in received, "duplicate global subgroup package")
            require(dict(self.contributors).get(subgroup) == source, "global contributor mismatch")
            require(isinstance(ql_hash, bytes) and len(ql_hash) == 32, "invalid local package commitment")
            received[subgroup] = (other_P, ql_hash)
            contributions[source] = (CG,)
            subgroup_J[source] = c.point(c.open_seal(self.global_state.key, CT1, (other_h, CG)))
        require(set(received) == set(dict(self.contributors)), "missing subgroup contribution")
        require(received[self.subgroup] == (P, c.digest("QL", ql)), "QL/QG commitment mismatch")
        if self.member == pending.source:
            # Check that the source's own retained global ciphertext was not replaced.
            require(contributions[self.member][0] == P[0][1], "own contribution was substituted")
        aggregate = gua.combine(self.global_state, contributions)
        weights = dict(aggregate.weights)
        J = c.total(c.mul(weights[i], value) for i, value in subgroup_J.items())
        rho = gua.dec(self.global_state, aggregate.ciphertext)
        c.point(R, True)
        delta, share = gua.ratchet(self.global_state, pending.u_global, rho, aggregate,
                                  self.confirmers, R, self.nonce, J,
                                  strict_i_equals_f=self.strict_i_equals_f)
        pending.global_candidate, pending.J = delta, J
        pending.weights, pending.qgs = aggregate.weights, tuple(qgs)
        pending.share = (aggregate.tau, share[0], share[1]) if share else None
        return pack(pending.share) if pending.share else None

    def commit(self, shares, send=False):
        """TL.Commit 1-9. Authenticate final M_s with the OLD local signing key."""
        p = self.pending
        require(p is not None and p.global_candidate is not None, "Share must precede Commit")
        values = tuple(unpack(w) for w in shares)
        require(all(tau == p.global_candidate.tau for tau, _, _ in values), "confirmation transcript mismatch")
        global_next = gua.confirm(self.global_state, p.global_candidate, tuple((i, z) for _, i, z in values))
        key = c.kdf("group-key", p.J, self.gid, self.epoch + 1)
        history_next = c.digest("hist", self.gid, self.epoch + 1, self.history, p.J)
        message = None
        if send:
            ciphertext, kappa, Js = p.theta
            alpha = dict(p.weights)[p.source]
            complement = c.sub(p.J, c.mul(alpha, Js))
            h = self.header(p.source)
            e = (h, self.epoch + 1, ciphertext, c.scalar_bytes(alpha), dict(p.local_next.roster)[p.source])
            E = c.seal(c.kdf("subgroup-envelope", kappa, (h, ciphertext)), complement, e)
            signature = c.sign(self.local.sk, c.digest("M", self.member, e, E, self.history, history_next))
            message = pack((self.member, e, E, signature))
        # No committed state changes before all cryptographic checks and encoding succeed.
        self.global_state, self.local = global_next, p.local_next
        if p.ek_next is not None:
            self.ek = p.ek_next
        if p.dk_next is not None:
            self.sources[p.source] = Source(p.dk_next, dict(self.local.roster)[p.source])
        self.epoch += 1
        self.key = key
        self.history = history_next
        self.pending, self.nonce = None, None
        return message

    def abort(self):
        if self.nonce is not None:
            self.nonce.burn()
        self.pending, self.nonce = None, None
        self.contributors, self.confirmers = (), ()


@dataclass
class Ordinary:
    gid: bytes
    subgroup: int
    member: int
    sources: dict
    epoch: int = 0
    key: bytes | None = None
    history: bytes = bytes(32)

    def record(self):
        return (self.gid, self.subgroup, self.member, self.epoch,
                tuple((i, v.record()) for i, v in sorted(self.sources.items())), self.key, self.history)

    def receive(self, wire):
        """TL.Receive 1-7: ordinary clients only recover their own subgroup root."""
        x, e, E, signature = unpack(wire)
        h, epoch, ciphertext, alpha_bytes, next_pk = e
        (gid, h_epoch), subgroup, a = h
        require(gid == self.gid and subgroup == self.subgroup, "wrong group/subgroup")
        require(epoch == h_epoch == self.epoch + 1, "replayed/out-of-order epoch")
        require(a in self.sources and x in self.sources, "unknown source/broadcaster")
        alpha = c.scalar_read(alpha_bytes)
        require(alpha != 0, "zero contribution weight")
        c.point(next_pk, True)
        dk_next, kappa = ubkem.dec(self.sources[a].path, (h, ciphertext), ciphertext)
        complement = c.point(c.open_seal(c.kdf("subgroup-envelope", kappa, (h, ciphertext)), E, e))
        Js = c.hgroup("HG", local_gid(self.gid, self.subgroup), kappa, (h, ciphertext))
        J = c.add(c.mul(alpha, Js), complement)
        history_next = c.digest("hist", self.gid, epoch, self.history, J)
        require(c.verify(self.sources[x].verification_key,
                         c.digest("M", x, e, E, self.history, history_next), signature),
                "subgroup broadcast signature/history failed")
        key = c.kdf("group-key", J, self.gid, epoch)
        self.sources[a] = Source(dk_next, next_pk)
        self.epoch, self.key = epoch, key
        self.history = history_next
        return key


@dataclass
class Group:
    gid: bytes
    subgroups: tuple
    cores: dict
    ordinary: dict
    nonce_service: object = None

    @classmethod
    def init(cls, gid, roster, strict_i_equals_f=True, nonce_window=16):
        """TL.Init 1-7; roster is ((core_ids, ordinary_ids), ...) per subgroup."""
        all_ids = [i for cores, ordinary in roster for i in (*cores, *ordinary)]
        core_ids = tuple(i for cores, _ in roster for i in cores)
        require(all_ids and len(all_ids) == len(set(all_ids)), "duplicate member identity")
        require(all(cores and len(cores) + len(ordinary) >= 2 for cores, ordinary in roster), "invalid subgroup")
        global_states = gua.init(global_gid(gid), core_ids)
        cores_out, ordinary_out = {}, {}
        for s, (core_members, ordinary_members) in enumerate(roster):
            local_states = gua.init(local_gid(gid, s), core_members)
            paths = {i: {} for i in (*core_members, *ordinary_members)}
            trees = {}
            for a in core_members:
                receivers = [i for i in (*core_members, *ordinary_members) if i != a]
                trees[a], keys = ubkem.gen(receivers)
                for receiver, path in zip(receivers, keys):
                    paths[receiver][a] = Source(path, dict(local_states[a].roster)[a])
            for a in core_members:
                cores_out[a] = Core(gid, s, a, local_states[a], global_states[a], trees[a], paths[a],
                                    strict_i_equals_f=strict_i_equals_f)
            for u in ordinary_members:
                ordinary_out[u] = Ordinary(gid, s, u, paths[u])
        from .nonce_service import Session
        return cls(gid, tuple((tuple(a), tuple(b)) for a, b in roster), cores_out, ordinary_out,
                   Session(gid, core_ids, nonce_window))

    @classmethod
    def balanced(cls, n, subgroups, q=2, gid=b"tl-cgka-experiment", strict_i_equals_f=True):
        require(0 < n <= 65536 and subgroups > 0 and n % subgroups == 0 and n // subgroups > q >= 1,
                "invalid balanced partition")
        size = n // subgroups
        roster = []
        for s in range(subgroups):
            members = tuple(range(s * size, (s + 1) * size))
            roster.append((members[:q], members[q:]))
        return cls.init(gid, roster, strict_i_equals_f)
