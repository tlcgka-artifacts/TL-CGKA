#include "internal.h"
V *path(V *leaf) {
    uint64_t n = integer(leaf);
    V *rev = E, *r = E;
    for (;;) {
        push(rev, N(n));
        if (!n)
            break;
        n = (n - 1) / 2;
    }
    for (size_t i = rev->n; i > 0; i--)
        push(r, A(rev, i - 1));
    return r;
}
static uint64_t sibling(uint64_t n) {
    REQUIRE(n > 0, "root has no sibling");
    return n % 2 ? n + 1 : n - 1;
}
static V *h1(V *shared, V *ct, V *ad) {
    V *h = hash(L(S("TL-CGKA/UB/H1/v1"), shared, ct, ad), 1);
    return L(bytes(h->b, 32), bytes(h->b + 32, 32));
}
static V *h2(V *shared, V *ct) {
    V *h = hash(L(S("TL-CGKA/UB/H2/v1"), shared, ct), 1);
    return L(bytes(h->b, 32), bytes(h->b + 32, 32));
}
V *ub_gen(V *members) {
    V *ids = members->t == 'i' ? range(0, integer(members)) : members;
    canonical_ids(sort(ids), 1);
    V *nodes = L(N(0)), *leaves = L(N(0));
    while (leaves->n < ids->n) {
        leaves = sort(leaves);
        uint64_t node = integer(A(leaves, 0));
        leaves = without(leaves, N(node));
        REQUIRE(node < (UINT64_MAX - 2) / 2, "tree depth overflow");
        push(leaves, N(2 * node + 1));
        push(leaves, N(2 * node + 2));
        push(nodes, N(2 * node + 1));
        push(nodes, N(2 * node + 2));
    }
    nodes = sort(nodes);
    leaves = sort(leaves);
    V *pairs = E, *public = E, *mapping = E, *receivers = E;
    EACH(j, nodes) {
        V *pair = nike_gen();
        set(pairs, A(nodes, j), pair);
        set(public, A(nodes, j), A(pair, 1));
    }
    EACH(j, ids) {
        V *leaf = A(leaves, j), *p = path(leaf), *priv = E;
        set(mapping, A(ids, j), leaf);
        EACH(k, p) push(priv, A(need(pairs, A(p, k)), 0));
        push(receivers, L(leaf, priv, N(0)));
    }
    return L(L(public, mapping, N(0)), receivers);
}
V *ub_enc(V *s) {
    V *pair = nike_gen();
    return L(L(s, A(pair, 0), A(pair, 1)), A(pair, 1));
}
V *ub_fin(V *u, V *ad) {
    shape(u, 3);
    V *s = A(u, 0), *pub = E, *root = Z;
    EACH(j, A(s, 0)) {
        V *entry = A(A(s, 0), j), *pair = h1(nike(A(u, 1), A(entry, 1)), A(u, 2), ad);
        set(pub, A(entry, 0), nike_public(A(pair, 0)));
        if (integer(A(entry, 0)) == 0)
            root = A(pair, 1);
    }
    REQUIRE(root->t != 'n', "missing tree root");
    return L(L(pub, A(s, 1), N(integer(A(s, 2)) + 1)), root);
}
V *ub_dec(V *r, V *ad, V *ct) {
    shape(r, 3);
    V *private = A(r, 1), *next = E, *root = Z;
    REQUIRE(private->t == 'l' && private->n, "empty private path");
    EACH(j, private) {
        V *pair = h1(nike(A(private, j), ct), ct, ad);
        push(next, A(pair, 0));
        if (!j)
            root = A(pair, 1);
    }
    return L(L(A(r, 0), next, N(integer(A(r, 2)) + 1)), root);
}
static V *refresh_path(V *pub, V *leaf) {
    V *p = path(leaf), *pks = E, *cts = E, *secrets = E, *seed = random_bytes(32);
    for (size_t j = 1; j < p->n; j++)
        push(pks, need(pub, N(sibling(integer(A(p, j))))));
    for (size_t j = pks->n; j > 0; j--) {
        V *ct = nike_public(seed), *pair = h2(nike(seed, A(pks, j - 1)), ct), *parent = A(p, j - 1);
        set(secrets, parent, A(pair, 0));
        set(cts, parent, ct);
        set(pub, parent, nike_public(A(pair, 0)));
        seed = A(pair, 1);
    }
    V *ordered = E;
    for (size_t j = 0; j + 1 < p->n; j++)
        push(ordered, need(cts, A(p, j)));
    return L(secrets, pks, ordered);
}
V *ub_add(V *s, V *member) {
    V *pub = clone(A(s, 0)), *leaves = clone(A(s, 1));
    REQUIRE(get(leaves, member)->t == 'n', "duplicate receiver");
    uint64_t split = UINT64_MAX;
    V *old = Z;
    EACH(j, leaves) {
        V *entry = A(leaves, j);
        uint64_t n = integer(A(entry, 1));
        if (n < split) {
            split = n;
            old = A(entry, 0);
        }
    }
    REQUIRE(split < (UINT64_MAX - 2) / 2, "tree overflow");
    V *left = N(2 * split + 1), *right = N(2 * split + 2), *pair = nike_gen();
    set(pub, right, need(pub, N(split)));
    set(pub, left, A(pair, 1));
    set(leaves, old, right);
    set(leaves, member, left);
    V *ref = refresh_path(pub, left), *secrets = A(ref, 0);
    set(secrets, left, A(pair, 0));
    V *p = path(left), *priv = E;
    EACH(j, p) push(priv, need(secrets, A(p, j)));
    V *epoch = N(integer(A(s, 2)) + 1),
      *wire = pack(L(S("A"), A(s, 2), member, left, N(split), A(ref, 1), A(ref, 2)));
    return L(L(pub, leaves, epoch), L(left, priv, epoch), wire);
}
static uint64_t relocate(uint64_t n, uint64_t old, uint64_t dest) {
    uint64_t cur = n;
    unsigned depth = 0;
    while (cur > old) {
        cur = (cur - 1) / 2;
        depth++;
    }
    if (cur != old)
        return n;
    REQUIRE(depth < 63 && dest + 1 <= UINT64_MAX >> depth, "relocation overflow");
    uint64_t suffix = (n + 1) & ((UINT64_C(1) << depth) - 1);
    return ((dest + 1) << depth) + suffix - 1;
}
V *ub_rmv(V *s, V *member) {
    V *leaves = A(s, 1);
    REQUIRE(leaves->n > 1, "cannot remove last receiver");
    uint64_t leaf = integer(need(leaves, member)), parent = (leaf - 1) / 2, brother = sibling(leaf);
    V *pub = clone(A(s, 0)), *ref = refresh_path(pub, N(leaf)), *next = E, *mapping = E;
    EACH(j, pub) {
        V *entry = A(pub, j);
        uint64_t n = integer(A(entry, 0));
        if (n != leaf && n != parent)
            set(next, N(relocate(n, brother, parent)), A(entry, 1));
    }
    EACH(j, leaves) {
        V *entry = A(leaves, j);
        if (!eq(A(entry, 0), member))
            set(mapping, A(entry, 0), N(relocate(integer(A(entry, 1)), brother, parent)));
    }
    return L(L(next, mapping, N(integer(A(s, 2)) + 1)),
             pack(L(S("R"), A(s, 2), member, N(leaf), N(parent), A(ref, 1), A(ref, 2))));
}
V *ub_proc(V *r, V *wire) {
    V *v = unpack(wire);
    shape(v, 7);
    V *op = A(v, 0), *epoch = A(v, 1), *target = A(v, 3), *split = A(v, 4), *pks = A(v, 5),
      *cts = A(v, 6);
    REQUIRE(eq(epoch, A(r, 2)) && (is(op, "A") || is(op, "R")),
            "stale/malformed membership update");
    V *leaf = A(r, 0), *p = path(leaf), *priv = E;
    REQUIRE(p->n == A(r, 1)->n, "bad private path");
    EACH(j, p) set(priv, A(p, j), A(A(r, 1), j));
    if (is(op, "A") && eq(leaf, split)) {
        leaf = N(integer(split) * 2 + 2);
        set(priv, leaf, need(priv, split));
    }
    REQUIRE(!is(op, "R") || !eq(leaf, target), "removed receiver has no successor path");
    V *anc = path(target);
    REQUIRE(anc->n > 1 && pks->n == anc->n - 1 && cts->n == pks->n, "bad update path length");
    size_t level = 0, found = 0;
    V *skey = Z;
    for (size_t j = 1; j < anc->n; j++) {
        V *k = get(priv, N(sibling(integer(A(anc, j)))));
        if (k->t != 'n') {
            level = j - 1;
            found++;
            skey = k;
        }
    }
    REQUIRE(found == 1, "receiver outside update tree");
    V *pair = h2(nike(skey, A(cts, level)), A(cts, level)), *seed = A(pair, 1);
    set(priv, A(anc, level), A(pair, 0));
    for (size_t j = level; j > 0; j--) {
        V *ct = nike_public(seed);
        REQUIRE(eq(ct, A(cts, j - 1)), "inconsistent deterministic update chain");
        pair = h2(nike(seed, A(pks, j - 1)), ct);
        set(priv, A(anc, j - 1), A(pair, 0));
        seed = A(pair, 1);
    }
    if (is(op, "R")) {
        uint64_t brother = sibling(integer(target)), dest = integer(split);
        V *next = E;
        EACH(j, priv) {
            V *entry = A(priv, j);
            if (!eq(A(entry, 0), split))
                set(next, N(relocate(integer(A(entry, 0)), brother, dest)), A(entry, 1));
        }
        priv = next;
        leaf = N(relocate(integer(leaf), brother, dest));
    }
    p = path(leaf);
    V *values = E;
    EACH(j, p) push(values, need(priv, A(p, j)));
    return L(leaf, values, N(integer(epoch) + 1));
}
V *ub_fork(V *s) {
    V *pair = nike_gen(), *wire = pack(L(S("F"), A(s, 2), A(pair, 1))), *branches = E;
    for (uint64_t tag = 1; tag <= 2; tag++) {
        V *pub = E;
        EACH(j, A(s, 0)) {
            V *entry = A(A(s, 0), j);
            set(pub, A(entry, 0),
                nike_public(A(h1(nike(A(pair, 0), A(entry, 1)), wire, N(tag)), 0)));
        }
        push(branches, L(pub, clone(A(s, 1)), N(integer(A(s, 2)) + 1)));
    }
    push(branches, wire);
    return branches;
}
V *ub_proc_fork(V *r, V *wire) {
    V *v = unpack(wire);
    shape(v, 3);
    REQUIRE(is(A(v, 0), "F") && eq(A(v, 1), A(r, 2)), "stale fork");
    V *out = E;
    for (uint64_t tag = 1; tag <= 2; tag++) {
        V *priv = E;
        EACH(j, A(r, 1)) push(priv, A(h1(nike(A(A(r, 1), j), A(v, 2)), wire, N(tag)), 0));
        push(out, L(A(r, 0), priv, N(integer(A(r, 2)) + 1)));
    }
    return out;
}
