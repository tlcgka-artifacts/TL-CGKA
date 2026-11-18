"""Group key encapsulation, contribution aggregation and confirmation.

Contributor and confirmer sets can differ. Set strict_i_equals_f to require identical sets."""
from dataclasses import dataclass
import os
from . import crypto as c
from .codec import pack, require


def keyagg(gid, roster):
    """Figure 1, GUA.KeyAgg 1-2."""
    require(len(roster) > 0, "empty signer roster")
    ids = tuple(i for i, _ in roster)
    require(ids == tuple(sorted(set(ids))), "noncanonical roster")
    h = c.digest("roster", roster)
    weights = {i: c.hscalar("agg", gid, h, pk) for i, pk in roster}
    return c.total(c.mul(weights[i], c.point(pk, True)) for i, pk in roster), weights


def challenge(m, R, pk):
    return c.hscalar("chal", m, R, pk)


@dataclass(frozen=True)
class State:
    gid: bytes
    member: int
    epoch: int
    sk: int
    m: bytes
    roster: tuple
    pk: bytes
    signature: tuple
    key: bytes

    def public_context(self):
        return (self.gid, self.epoch, self.roster, self.pk, self.signature)

    def record(self):
        return (self.member, c.scalar_bytes(self.sk), self.m, self.key, self.public_context())


def init(gid, members):
    """Figure 1 Init. Trusted experimental bootstrap, excluded from update timing."""
    ids = tuple(sorted(members))
    require(ids and len(ids) == len(set(ids)), "duplicate/empty initial roster")
    secrets = {i: c.scalar() for i in ids}
    roster = tuple((i, c.base(secrets[i])) for i in ids)
    pk, weights = keyagg(gid, roster)
    m = os.urandom(32)
    nonces = {i: c.scalar() for i in ids}
    R = c.total(c.base(r) for r in nonces.values())
    ch = challenge(m, R, pk)
    z = sum(nonces[i] + ch * weights[i] * secrets[i] for i in ids) % c.ORDER
    signature = (R, c.scalar_bytes(z))
    require(c.base(z) == c.add(R, c.mul(ch, pk)), "initial signature mismatch")
    return {i: State(gid, i, 0, secrets[i], m, roster, pk, signature, c.digest("key", m, pk))
            for i in ids}


def enc(state, rho):
    """Figure 1 Enc: (PK^u, g^u, R^u rho)."""
    c.point(rho)
    u = c.scalar()
    return u, (c.mul(u, state.pk), c.base(u), c.add(c.mul(u, state.signature[0]), rho))


@dataclass(frozen=True)
class Aggregate:
    ciphertext: tuple
    tau: bytes
    entries: tuple
    weights: tuple

    @property
    def contributors(self):
        return tuple(i for i, _ in self.entries)


def combine(state, bundles):
    """Figure 1 Combine 1-7. Caller inserts its locally retained bundle explicitly."""
    require(bool(bundles), "empty contributor set")
    known = dict(state.roster)
    entries = []
    for i in sorted(bundles):
        require(i in known, "unknown contributor")
        batch = bundles[i]
        for ciphertext in batch:
            require(len(ciphertext) == 3, "GUA ciphertext must contain three points")
            for p in ciphertext:
                c.point(p)
        entries.append((i, tuple(c.total(ct[k] for ct in batch) for k in range(3))))
    entries = tuple(entries)
    tau = c.digest("set", state.gid, state.epoch, entries)
    weights = tuple((i, c.hscalar("wt", tau, i, ct)) for i, ct in entries)
    w = dict(weights)
    combined = tuple(c.total(c.mul(w[i], ct[k]) for i, ct in entries) for k in range(3))
    return Aggregate(combined, tau, entries, weights)


def dec(state, ciphertext):
    """Figure 1 Dec 1-3: c*C1 + C3 - z*C2."""
    require(len(ciphertext) == 3, "invalid GUA ciphertext")
    C1, C2, C3 = ciphertext
    R, z = state.signature
    return c.sub(c.add(c.mul(challenge(state.m, R, state.pk), C1), c.point(C3)),
                 c.mul(c.scalar_read(z), C2))


@dataclass
class Nonce:
    """Appendix B.2 / Figure 4: one commitment/opening and one-use secret."""
    context: tuple
    member: int
    secret: int | None
    R: bytes
    salt: bytes

    @classmethod
    def prepare(cls, context, member):
        r = c.scalar()
        return cls(context, member, r, c.base(r), os.urandom(32))

    def commitment(self):
        return (self.member, c.digest("nonce-commit", self.context, self.member, self.R, self.salt))

    def opening(self):
        return (self.member, self.R, self.salt)

    def consume(self):
        require(self.secret is not None, "nonce already consumed")
        value, self.secret = self.secret, None
        return value

    def burn(self):
        self.secret = None


def nonce_aggregate(context, confirmers, commitments, openings):
    ids = tuple(sorted(confirmers))
    require(len(ids) == len(set(ids)) and ids, "invalid confirmer set")
    cm = dict(commitments)
    require(len(cm) == len(commitments) and set(cm) == set(ids), "nonce commitment set mismatch")
    require(tuple(sorted(x[0] for x in openings)) == ids, "nonce opening set mismatch")
    points = []
    for i, R, salt in openings:
        c.point(R, True)
        require(cm[i] == c.digest("nonce-commit", context, i, R, salt), "nonce commitment mismatch")
        points.append(R)
    R = c.total(points)
    require(R != c.IDENTITY, "identity aggregate nonce; retry with fresh commitments")
    return R


@dataclass(frozen=True)
class Candidate:
    parent: bytes
    state: State
    confirmers: tuple
    R: bytes
    tau: bytes


def ratchet(state, u, rho, aggregate, confirmers, R, nonce=None, ctx=None,
            strict_i_equals_f=False):
    """Figure 1 Ratchet 1-11. Returns an uncommitted candidate and optional share."""
    F = tuple(sorted(confirmers))
    require(F and len(F) == len(set(F)), "invalid confirmer set")
    I = aggregate.contributors
    if strict_i_equals_f:
        require(I == F, "Figure 1 restricted profile requires I=F")
    old = dict(state.roster)
    require(set(F) <= old.keys(), "unknown confirmer")
    c.point(R, True)
    m = c.digest("rat", state.epoch + 1, c.point(rho), aggregate.tau, ctx)
    updated, sk = dict(old), state.sk
    for j, ct in aggregate.entries:
        beta = c.hscalar("key-update", m, j, ct[1])
        updated[j] = c.add(old[j], c.mul(beta, ct[1]))
        if j == state.member:
            require(u is not None and c.base(u) == ct[1], "missing/mismatched local encapsulation randomness")
            sk = (sk + beta * u) % c.ORDER
    roster = tuple(sorted(updated.items()))
    signer_roster = tuple((i, updated[i]) for i in F)
    pk, weights = keyagg(state.gid, signer_roster)
    require(c.base(sk) == updated[state.member], "private/public ratchet mismatch")
    tentative = State(state.gid, state.member, state.epoch + 1, sk, m, roster, pk, (), b"")
    candidate = Candidate(c.digest("parent", state.record()), tentative, F, R, aggregate.tau)
    share = None
    if state.member in F:
        require(nonce is not None, "missing confirmation nonce")
        r = nonce.consume()
        share = (state.member, c.scalar_bytes(r + challenge(m, R, pk) * weights[state.member] * sk))
    return candidate, share


def confirm(state, candidate, shares):
    """Figure 1 Confirm 1-5; immutable input means rejection cannot commit state."""
    require(candidate.parent == c.digest("parent", state.record()), "stale candidate")
    ids = tuple(sorted(i for i, _ in shares))
    require(ids == candidate.confirmers, "missing/duplicate/unexpected confirmation share")
    z = sum(c.scalar_read(value) for _, value in shares) % c.ORDER
    ns = candidate.state
    require(c.base(z) == c.add(candidate.R, c.mul(challenge(ns.m, candidate.R, ns.pk), ns.pk)),
            "GUA aggregate confirmation failed")
    return State(ns.gid, ns.member, ns.epoch, ns.sk, ns.m, ns.roster, ns.pk,
                 (candidate.R, c.scalar_bytes(z)), c.digest("key", ns.m, ns.pk))
