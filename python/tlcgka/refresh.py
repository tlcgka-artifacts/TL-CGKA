"""Group refresh with a single public key in each control message.

Members reconstruct the temporary roster from the previous roster and the
issuer point. An authenticated digest binds the previous roster."""
import os
from . import crypto as c, gua
from .codec import pack, unpack, require


def anchor(state):
    return (state.gid, state.epoch, state.roster)


def anchor_tag(old_anchor):
    gid, epoch, roster = old_anchor
    return (gid, epoch, c.digest("refresh-parent-roster", roster))


def _refresh_roster(roster, eta):
    return tuple((i, c.mul(c.hscalar("refresh-ref", i, eta), pk)) for i, pk in roster)


def change(state, op, target, target_pk, context, *, outer_authenticated=False):
    roster = dict(state.roster)
    require(op in ("A", "R") and target != state.member, "invalid GUA membership operation")
    if op == "A":
        require(target not in roster, "duplicate GUA member")
        roster[target] = c.point(target_pk, True)
    else:
        require(roster.get(target) == target_pk, "GUA removal key mismatch")
        del roster[target]
    ephemeral_sk, eta = c.scalar(), os.urandom(32)
    ephemeral_pk = c.base(ephemeral_sk)
    roster[state.member] = ephemeral_pk
    roster = tuple(sorted(roster.items()))
    h = c.digest("refresh-roster", roster)
    masks = []
    for i, pk in roster:
        if i != state.member:
            mask = c.kdf("refresh-mask", h, c.mul(ephemeral_sk, pk))
            masks.append((i, bytes(a ^ b for a, b in zip(eta, mask))))
    m = c.digest("refresh-rat", state.epoch + 1, eta, h)
    factor = c.hscalar("refresh-ref", state.member, eta)
    new_sk = factor * ephemeral_sk % c.ORDER
    new_pk = c.mul(factor, ephemeral_pk)
    r = c.scalar()
    R = c.base(r)
    signature = (R, c.scalar_bytes(r + gua.challenge(m, R, new_pk) * new_sk))
    payload = (anchor_tag(anchor(state)), state.member, op, target, target_pk,
               ephemeral_pk, tuple(masks), signature, context)
    # Figure 3 calls only GUA.Change steps 1--3: its two outer signatures
    # authenticate both embedded payloads. Standalone Change retains step 4.
    wire = pack(payload) if outer_authenticated else pack((payload, c.sign(state.sk, c.digest("GUA.Change", payload))))
    roster = _refresh_roster(roster, eta)
    successor = gua.State(state.gid, state.member, state.epoch + 1, new_sk, m, roster, new_pk,
                          signature, c.digest("key", m, new_pk))
    return wire, successor


def recover(old_anchor, member, sk, wire, context, *, outer_authenticated=False):
    if outer_authenticated:
        payload = unpack(wire)
    else:
        payload, authentication = unpack(wire)
    prior, issuer, op, target, target_pk, ephemeral_pk, masks, signature, bound = payload
    require(prior == anchor_tag(old_anchor) and bound == context, "GUA membership context mismatch")
    gid, epoch, previous = old_anchor
    require(issuer in dict(previous) and target != issuer, "invalid GUA issuer/target")
    if not outer_authenticated:
        require(c.verify(dict(previous)[issuer], c.digest("GUA.Change", payload), authentication),
                "GUA membership signature failed")
    expected = dict(previous)
    if op == "A":
        require(target not in expected, "duplicate add")
        expected[target] = c.point(target_pk, True)
    else:
        require(op == "R" and expected.get(target) == target_pk, "invalid removal")
        del expected[target]
    expected[issuer] = c.point(ephemeral_pk, True)
    roster = tuple(sorted(expected.items()))
    require(member in expected and member != issuer, "recipient excluded or sponsor must commit staged state")
    require(c.base(sk) == expected[member], "private key does not match roster")
    require(tuple(i for i, _ in masks) == tuple(i for i, _ in roster if i != issuer), "wrong refresh recipient set")
    require(all(isinstance(value, bytes) and len(value) == 32 for _, value in masks),
            "invalid refresh mask length")
    h = c.digest("refresh-roster", roster)
    mask = c.kdf("refresh-mask", h, c.mul(sk, ephemeral_pk))
    eta = bytes(a ^ b for a, b in zip(dict(masks)[member], mask))
    m = c.digest("refresh-rat", epoch + 1, eta, h)
    new_pk = c.mul(c.hscalar("refresh-ref", issuer, eta), ephemeral_pk)
    R, z = signature
    require(c.base(c.scalar_read(z)) == c.add(R, c.mul(gua.challenge(m, R, new_pk), new_pk)),
            "refresh confirmation failed")
    next_sk = sk * c.hscalar("refresh-ref", member, eta) % c.ORDER
    roster = _refresh_roster(roster, eta)
    require(c.base(next_sk) == dict(roster)[member], "refresh private/public mismatch")
    return gua.State(gid, member, epoch + 1, next_sk, m, roster, new_pk, signature, c.digest("key", m, new_pk))
