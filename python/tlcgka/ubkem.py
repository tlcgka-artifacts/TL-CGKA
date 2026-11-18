"""Dynamic tree-based key encapsulation.

Joining splits the shallowest leaf. Removal contracts its sibling."""
from dataclasses import dataclass
import hashlib
import os
from . import crypto as c
from .codec import pack, unpack, require


def path(leaf):
    out = []
    while True:
        out.append(leaf)
        if leaf == 0:
            return tuple(reversed(out))
        leaf = (leaf - 1) // 2


def sibling(node):
    return node + 1 if node % 2 else node - 1


@dataclass(frozen=True)
class Sender:
    public: dict
    leaves: dict
    epoch: int = 0

    def record(self):
        return (self.epoch, tuple(sorted(self.public.items())), tuple(sorted(self.leaves.items())))


@dataclass(frozen=True)
class Receiver:
    leaf: int
    private: tuple
    epoch: int = 0

    def record(self):
        return (self.leaf, self.private, self.epoch)

    @classmethod
    def read(cls, value):
        leaf, private, epoch = value
        require(len(path(leaf)) == len(private), "bad private path")
        return cls(leaf, private, epoch)


def gen(members):
    ids = tuple(range(members)) if isinstance(members, int) else tuple(members)
    require(ids and len(ids) == len(set(ids)), "invalid receiver set")
    nodes, leaves = {0}, {0}
    while len(leaves) < len(ids):
        node = min(leaves)
        leaves.remove(node)
        children = (2 * node + 1, 2 * node + 2)
        leaves.update(children)
        nodes.update(children)
    pairs = {i: c.nike_gen() for i in sorted(nodes)}
    mapping = dict(zip(ids, sorted(leaves)))
    tree = Sender({i: pk for i, (_, pk) in pairs.items()}, mapping)
    return tree, [Receiver(mapping[i], tuple(pairs[j][0] for j in path(mapping[i]))) for i in ids]


def _h1(shared, ciphertext, ad):
    h = hashlib.sha512(pack(("TL-CGKA/UB/H1/v1", shared, ciphertext, ad))).digest()
    return h[:32], h[32:]


def _h2(shared, ciphertext):
    h = hashlib.sha512(pack(("TL-CGKA/UB/H2/v1", shared, ciphertext))).digest()
    return h[:32], h[32:]


def enc(sender):
    sk, pk = c.nike_gen()
    return (sender, sk, pk), pk


def fin(intermediate, ad):
    sender, sk, ct = intermediate
    pub, root = {}, None
    for node, pk in sender.public.items():
        secret, key = _h1(c.nike(sk, pk), ct, ad)
        pub[node] = c.nike_public(secret)
        if node == 0:
            root = key
    return Sender(pub, sender.leaves, sender.epoch + 1), root


def dec(receiver, ad, ciphertext):
    values = [_h1(c.nike(sk, ciphertext), ciphertext, ad) for sk in receiver.private]
    return Receiver(receiver.leaf, tuple(sk for sk, _ in values), receiver.epoch + 1), values[0][1]


def _refresh_path(public, leaf):
    ancestors = path(leaf)[:-1]
    copath = tuple(sibling(n) for n in path(leaf)[1:])
    pks = tuple(public[n] for n in copath)
    seed, secrets, ciphertexts = os.urandom(32), {}, {}
    for parent, pk in reversed(tuple(zip(ancestors, pks))):
        ct = c.nike_public(seed)
        secret, seed = _h2(c.nike(seed, pk), ct)
        secrets[parent], ciphertexts[parent] = secret, ct
        public[parent] = c.nike_public(secret)
    return secrets, pks, tuple(ciphertexts[n] for n in ancestors)


def add(sender, member):
    require(member not in sender.leaves, "duplicate receiver")
    pub, leaves = dict(sender.public), dict(sender.leaves)
    split = min(leaves.values())
    old_member = next(i for i, leaf in leaves.items() if leaf == split)
    left, right = split * 2 + 1, split * 2 + 2
    pub[right] = pub[split]
    sk, pub[left] = c.nike_gen()
    leaves[old_member], leaves[member] = right, left
    secrets, pks, cts = _refresh_path(pub, left)
    secrets[left] = sk
    msg = pack(("A", sender.epoch, member, left, split, pks, cts))
    new = Receiver(left, tuple(secrets[n] for n in path(left)), sender.epoch + 1)
    return Sender(pub, leaves, sender.epoch + 1), new, msg


def _relocate(node, old, new):
    bits = bin(node + 1)[2:]
    prefix = bin(old + 1)[2:]
    return int(bin(new + 1)[2:] + bits[len(prefix):], 2) - 1 if bits.startswith(prefix) else node


def rmv(sender, member):
    require(member in sender.leaves and len(sender.leaves) > 1, "invalid receiver removal")
    leaf = sender.leaves[member]
    parent, brother = (leaf - 1) // 2, sibling(leaf)
    pub = dict(sender.public)
    _, pks, cts = _refresh_path(pub, leaf)
    pub = {_relocate(n, brother, parent): pk for n, pk in pub.items() if n not in (leaf, parent)}
    leaves = {i: _relocate(n, brother, parent) for i, n in sender.leaves.items() if i != member}
    msg = pack(("R", sender.epoch, member, leaf, parent, pks, cts))
    return Sender(pub, leaves, sender.epoch + 1), msg


def proc(receiver, wire):
    op, epoch, member, target, split, pks, cts = unpack(wire)
    require(epoch == receiver.epoch and op in ("A", "R"), "stale/malformed membership update")
    leaf = receiver.leaf
    private = dict(zip(path(leaf), receiver.private))
    if op == "A" and leaf == split:
        leaf = split * 2 + 2
        private[leaf] = private[split]
    require(op != "R" or leaf != target, "removed receiver has no successor path")
    ancestors = path(target)[:-1]
    copath = tuple(sibling(n) for n in path(target)[1:])
    require(len(pks) == len(cts) == len(ancestors), "bad update path length")
    levels = [i for i, node in enumerate(copath) if node in private]
    require(len(levels) == 1, "receiver is outside update tree")
    level = levels[0]
    secret, seed = _h2(c.nike(private[copath[level]], cts[level]), cts[level])
    private[ancestors[level]] = secret
    for i in range(level - 1, -1, -1):
        ct = c.nike_public(seed)
        require(ct == cts[i], "inconsistent deterministic update chain")
        secret, seed = _h2(c.nike(seed, pks[i]), ct)
        private[ancestors[i]] = secret
    if op == "R":
        brother = sibling(target)
        private = {_relocate(n, brother, split): sk for n, sk in private.items() if n != split}
        leaf = _relocate(leaf, brother, split)
    return Receiver(leaf, tuple(private[n] for n in path(leaf)), epoch + 1)


def fork(sender):
    sk, pk = c.nike_gen()
    wire = pack(("F", sender.epoch, pk))
    branches = []
    for tag in (1, 2):
        public = {n: c.nike_public(_h1(c.nike(sk, v), wire, tag)[0]) for n, v in sender.public.items()}
        branches.append(Sender(public, dict(sender.leaves), sender.epoch + 1))
    return *branches, wire


def proc_fork(receiver, wire):
    tag, epoch, pk = unpack(wire)
    require(tag == "F" and epoch == receiver.epoch, "stale fork")
    return tuple(Receiver(receiver.leaf, tuple(_h1(c.nike(sk, pk), wire, side)[0]
                                             for sk in receiver.private), epoch + 1) for side in (1, 2))
