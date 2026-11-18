#include "internal.h"
V *gua_context(V *s) {
    shape(s, 9);
    return L(A(s, GID), A(s, GEPOCH), A(s, ROSTER), A(s, PK), A(s, SIG));
}
V *gua_record(V *s) {
    return L(A(s, MEMBER), A(s, SK), A(s, M), A(s, KEY), gua_context(s));
}
V *keyagg(V *gid, V *roster) {
    canonical_ids(keys(roster), 1);
    V *h = D("roster", roster), *weights = E, *pk = identity();
    EACH(j, roster) {
        V *i = A(A(roster, j), 0), *p = A(A(roster, j), 1), *w = HS("agg", gid, h, p);
        point(p, 1);
        set(weights, i, w);
        pk = add(pk, mul(w, p));
    }
    return L(pk, weights);
}
V *challenge(V *m, V *r, V *pk) {
    return HS("chal", m, r, pk);
}
V *gua_init(V *gid, V *members) {
    V *ids = sort(members);
    canonical_ids(ids, 1);
    V *sk = E, *roster = E, *rs = E, *R = identity(), *states = E;
    EACH(j, ids) {
        V *i = A(ids, j), *s = scalar();
        set(sk, i, s);
        set(roster, i, base(s));
    }
    V *agg = keyagg(gid, roster), *pk = A(agg, 0), *weights = A(agg, 1), *m = random_bytes(32);
    EACH(j, ids) {
        V *r = scalar();
        set(rs, A(ids, j), r);
        R = add(R, base(r));
    }
    V *ch = challenge(m, R, pk), *z = identity();
    EACH(j, ids) {
        V *i = A(ids, j);
        z = sadd(z, sadd(need(rs, i), smul(ch, smul(need(weights, i), need(sk, i)))));
    }
    REQUIRE(eq(base(z), add(R, mul(ch, pk))), "initial signature mismatch");
    EACH(j, ids) {
        V *i = A(ids, j);
        set(states, i, L(gid, i, N(0), need(sk, i), m, roster, pk, L(R, z), D("key", m, pk)));
    }
    return states;
}
V *gua_enc(V *s, V *rho) {
    point(rho, 0);
    V *u = scalar();
    return L(u, L(mul(u, A(s, PK)), base(u), add(mul(u, A(A(s, SIG), 0)), rho)));
}
V *gua_combine(V *s, V *bundles) {
    canonical_ids(keys(bundles), 1);
    V *entries = E, *weights = E;
    EACH(j, bundles) {
        V *i = A(A(bundles, j), 0), *batch = A(A(bundles, j), 1),
          *ct = L(identity(), identity(), identity());
        need(A(s, ROSTER), i);
        EACH(k, batch) {
            V *v = A(batch, k);
            shape(v, 3);
            for (size_t q = 0; q < 3; q++)
                put(ct, q, add(A(ct, q), A(v, q)));
        }
        push(entries, L(i, ct));
    }
    V *tau = D("set", A(s, GID), A(s, GEPOCH), entries),
      *combined = L(identity(), identity(), identity());
    EACH(j, entries) {
        V *i = A(A(entries, j), 0), *ct = A(A(entries, j), 1), *w = HS("wt", tau, i, ct);
        set(weights, i, w);
        for (size_t q = 0; q < 3; q++)
            put(combined, q, add(A(combined, q), mul(w, A(ct, q))));
    }
    return L(combined, tau, entries, weights);
}
V *gua_dec(V *s, V *ct) {
    shape(ct, 3);
    V *sig = A(s, SIG);
    shape(sig, 2);
    return sub(add(mul(challenge(A(s, M), A(sig, 0), A(s, PK)), A(ct, 0)), point(A(ct, 2), 0)),
               mul(sread(A(sig, 1)), A(ct, 1)));
}
V *nonce_prepare(V *ctx, V *member) {
    V *r = scalar();
    return L(ctx, member, r, base(r), random_bytes(32));
}
V *nonce_commitment(V *n) {
    shape(n, 5);
    return L(A(n, 1), D("nonce-commit", A(n, 0), A(n, 1), A(n, 3), A(n, 4)));
}
V *nonce_opening(V *n) {
    return L(A(n, 1), A(n, 3), A(n, 4));
}
V *nonce_consume(V *n) {
    V *s = A(n, 2);
    REQUIRE(s->t != 'n', "nonce already consumed");
    put(n, 2, Z);
    return s;
}
void nonce_burn(V *n) {
    put(n, 2, Z);
}
V *nonce_aggregate(V *ctx, V *ids, V *commits, V *opens) {
    V *f = sort(ids);
    canonical_ids(f, 1);
    REQUIRE(eq(sort(keys(commits)), f), "nonce commitment set mismatch");
    V *oi = E, *R = identity();
    EACH(j, opens) {
        V *o = A(opens, j);
        shape(o, 3);
        push(oi, A(o, 0));
        point(A(o, 1), 1);
        REQUIRE(eq(need(commits, A(o, 0)), D("nonce-commit", ctx, A(o, 0), A(o, 1), A(o, 2))),
                "nonce commitment mismatch");
        R = add(R, A(o, 1));
    }
    REQUIRE(eq(sort(oi), f), "nonce opening set mismatch");
    point(R, 1);
    return R;
}
V *gua_ratchet(V *s, V *u, V *rho, V *agg, V *confirmers, V *R, V *nonce, V *ctx, int strict) {
    V *f = sort(confirmers);
    canonical_ids(f, 1);
    shape(agg, 4);
    V *entries = A(agg, 2), *old = A(s, ROSTER);
    if (strict)
        REQUIRE(eq(keys(entries), f), "restricted profile requires I=F");
    EACH(j, f) need(old, A(f, j));
    point(R, 1);
    V *m = D("rat", N(integer(A(s, GEPOCH)) + 1), point(rho, 0), A(agg, 1), ctx),
      *updated = clone(old), *sk = A(s, SK);
    EACH(j, entries) {
        V *i = A(A(entries, j), 0), *ct = A(A(entries, j), 1),
          *beta = HS("key-update", m, i, A(ct, 1));
        set(updated, i, add(need(old, i), mul(beta, A(ct, 1))));
        if (eq(i, A(s, MEMBER))) {
            REQUIRE(u->t != 'n' && eq(base(u), A(ct, 1)),
                    "missing/mismatched local encapsulation randomness");
            sk = sadd(sk, smul(beta, u));
        }
    }
    V *signers = E;
    EACH(j, f) set(signers, A(f, j), need(updated, A(f, j)));
    V *ka = keyagg(A(s, GID), signers), *pk = A(ka, 0);
    REQUIRE(eq(base(sk), need(updated, A(s, MEMBER))), "private/public ratchet mismatch");
    V *ns = L(A(s, GID), A(s, MEMBER), N(integer(A(s, GEPOCH)) + 1), sk, m, updated, pk, E,
              bytes(NULL, 0));
    V *cand = L(D("parent", gua_record(s)), ns, f, R, A(agg, 1)), *share = Z;
    if (contains(f, A(s, MEMBER))) {
        REQUIRE(nonce->t != 'n', "missing confirmation nonce");
        V *r = nonce_consume(nonce);
        share = L(A(s, MEMBER),
                  sadd(r, smul(challenge(m, R, pk), smul(need(A(ka, 1), A(s, MEMBER)), sk))));
    }
    return L(cand, share);
}
V *gua_confirm(V *s, V *cand, V *shares) {
    shape(cand, 5);
    REQUIRE(eq(A(cand, 0), D("parent", gua_record(s))), "stale candidate");
    REQUIRE(eq(sort(keys(shares)), A(cand, 2)), "missing/duplicate/unexpected confirmation share");
    V *z = identity();
    EACH(j, shares) z = sadd(z, sread(A(A(shares, j), 1)));
    V *ns = clone(A(cand, 1)), *R = A(cand, 3), *pk = A(ns, PK);
    REQUIRE(eq(base(z), add(R, mul(challenge(A(ns, M), R, pk), pk))),
            "GUA aggregate confirmation failed");
    put(ns, SIG, L(R, z));
    put(ns, KEY, D("key", A(ns, M), pk));
    return ns;
}
V *anchor(V *s) {
    return L(A(s, GID), A(s, GEPOCH), A(s, ROSTER));
}
V *anchor_tag(V *a) {
    shape(a, 3);
    return L(A(a, 0), A(a, 1), D("refresh-parent-roster", A(a, 2)));
}
V *refresh_change(V *s, V *op, V *target, V *target_pk, V *ctx, int outer, V *coins) {
    V *roster = clone(A(s, ROSTER)), *member = A(s, MEMBER);
    REQUIRE((is(op, "A") || is(op, "R")) && !eq(target, member),
            "invalid GUA membership operation");
    if (is(op, "A")) {
        REQUIRE(get(roster, target)->t == 'n', "duplicate GUA member");
        set(roster, target, point(target_pk, 1));
    } else {
        REQUIRE(eq(need(roster, target), target_pk), "GUA removal key mismatch");
        del(roster, target);
    }
    V *esk = coins->t == 'n' ? scalar() : A(coins, 0),
      *eta = coins->t == 'n' ? random_bytes(32) : A(coins, 1), *epk = base(esk);
    set(roster, member, epk);
    V *h = D("refresh-roster", roster), *masks = E;
    EACH(j, roster) {
        V *i = A(A(roster, j), 0);
        if (!eq(i, member))
            set(masks, i, xor32(eta, K("refresh-mask", h, mul(esk, A(A(roster, j), 1)))));
    }
    V *m = D("refresh-rat", N(integer(A(s, GEPOCH)) + 1), eta, h),
      *factor = HS("refresh-ref", member, eta), *sk = smul(factor, esk), *pk = mul(factor, epk),
      *r = coins->t == 'n' ? scalar() : A(coins, 2), *R = base(r),
      *signature = L(R, sadd(r, smul(challenge(m, R, pk), sk)));
    V *payload =
          L(anchor_tag(anchor(s)), member, op, target, target_pk, epk, masks, signature, ctx),
      *wire;
    if (outer)
        wire = pack(payload);
    else {
        V *auth;
        if (coins->t != 'n') {
            V *ar = A(coins, 3), *aR = base(ar), *oldpk = base(A(s, SK));
            auth = L(
                aR, sadd(ar, smul(HS("signature", aR, oldpk, D("GUA.Change", payload)), A(s, SK))));
        } else
            auth = sign(A(s, SK), D("GUA.Change", payload));
        wire = pack(L(payload, auth));
    }
    /* Figure 1, Refresh 6: ratchet EVERY surviving public key. The issuer's
     * entry in L' is P; other entries are their pre-refresh public keys. */
    EACH(j, roster) {
        V *entry = A(roster, j);
        put(entry, 1, mul(HS("refresh-ref", A(entry, 0), eta), A(entry, 1)));
    }
    return L(wire, L(A(s, GID), member, N(integer(A(s, GEPOCH)) + 1), sk, m, roster, pk, signature,
                     D("key", m, pk)));
}
V *refresh_recover(V *old, V *member, V *sk, V *wire, V *ctx, int outer) {
    V *v = unpack(wire), *p = outer ? v : A(v, 0);
    shape(p, 9);
    V *issuer = A(p, 1), *op = A(p, 2), *target = A(p, 3), *target_pk = A(p, 4), *epk = A(p, 5),
      *masks = A(p, 6), *sig = A(p, 7), *previous = A(old, 2);
    REQUIRE(eq(A(p, 0), anchor_tag(old)) && eq(A(p, 8), ctx), "GUA membership context mismatch");
    REQUIRE(!eq(target, issuer), "invalid GUA issuer/target");
    V *oldpk = need(previous, issuer);
    if (!outer)
        REQUIRE(verify(oldpk, D("GUA.Change", p), A(v, 1)), "GUA membership signature failed");
    V *roster = clone(previous);
    if (is(op, "A")) {
        REQUIRE(get(roster, target)->t == 'n', "duplicate add");
        set(roster, target, point(target_pk, 1));
    } else {
        REQUIRE(is(op, "R") && eq(need(roster, target), target_pk), "invalid removal");
        del(roster, target);
    }
    set(roster, issuer, point(epk, 1));
    REQUIRE(!eq(member, issuer) && eq(base(sk), need(roster, member)),
            "recipient excluded/private key mismatch");
    REQUIRE(eq(keys(masks), without(keys(roster), issuer)), "wrong refresh recipient set");
    EACH(j, masks) blob(A(A(masks, j), 1), 32);
    V *h = D("refresh-roster", roster),
      *eta = xor32(need(masks, member), K("refresh-mask", h, mul(sk, epk))),
      *m = D("refresh-rat", N(integer(A(old, 1)) + 1), eta, h),
      *pk = mul(HS("refresh-ref", issuer, eta), epk);
    shape(sig, 2);
    REQUIRE(eq(base(sread(A(sig, 1))), add(A(sig, 0), mul(challenge(m, A(sig, 0), pk), pk))),
            "refresh confirmation failed");
    /* Figure 5, ProcessChange 11: each receiver updates its own secret too. */
    V *next_sk = smul(HS("refresh-ref", member, eta), sk);
    EACH(j, roster) {
        V *entry = A(roster, j);
        put(entry, 1, mul(HS("refresh-ref", A(entry, 0), eta), A(entry, 1)));
    }
    REQUIRE(eq(base(next_sk), need(roster, member)), "refresh private/public mismatch");
    return L(A(old, 0), member, N(integer(A(old, 1)) + 1), next_sk, m, roster, pk, sig,
             D("key", m, pk));
}
