#include "internal.h"
V *local_gid(V *g, V *s) {
    return D("local-gid", g, s);
}
V *global_gid(V *g) {
    return D("global-gid", g);
}
static V *tree_record(V *s) {
    return L(A(s, 2), A(s, 0), A(s, 1));
}
V *core_record(V *c) {
    return L(A(c, C_GID), A(c, C_SUB), A(c, C_ID), A(c, C_EPOCH), gua_record(A(c, C_LOCAL)),
             gua_record(A(c, C_GLOBAL)), tree_record(A(c, C_TREE)), A(c, C_SOURCES), A(c, C_KEY),
             A(c, C_HISTORY));
}
V *ordinary_record(V *c) {
    return L(A(c, C_GID), A(c, C_SUB), A(c, C_ID), A(c, C_EPOCH), A(c, C_SOURCES), A(c, C_KEY),
             A(c, C_HISTORY));
}
V *header(V *c, V *source) {
    return L(L(A(c, C_GID), N(integer(A(c, C_EPOCH)) + 1)), A(c, C_SUB), source);
}
void configure(V *c, V *a, V *b) {
    REQUIRE(A(c, C_PENDING)->t == 'n' && A(c, C_NONCE)->t == 'n', "round already pending");
    canonical_ids(keys(a), 1);
    V *ids = E;
    EACH(j, a) {
        V *id = A(A(a, j), 1);
        REQUIRE(!contains(ids, id), "duplicate contributor");
        need(A(A(c, C_GLOBAL), ROSTER), id);
        push(ids, id);
    }
    V *f = sort(b);
    canonical_ids(f, 1);
    need(A(A(c, C_LOCAL), ROSTER), need(a, A(c, C_SUB)));
    EACH(j, f) need(A(A(c, C_GLOBAL), ROSTER), A(f, j));
    if (truth(A(c, C_STRICT)))
        REQUIRE(eq(sort(ids), f), "restricted profile requires A=B");
    put(c, C_A, a);
    put(c, C_B, f);
}
static V *pending(V *ql, V *local, V *theta, V *source) {
    return L(ql, local, theta, source, Z, Z, Z, Z, Z, E, E, Z);
}
V *core_prepare(V *c) {
    REQUIRE(A(c, C_PENDING)->t == 'n', "duplicate Prepare");
    V *member = A(c, C_ID), *local = A(c, C_LOCAL), *global = A(c, C_GLOBAL), *gid = A(c, C_GID),
      *s = A(c, C_SUB);
    REQUIRE(eq(need(A(c, C_A), s), member), "not nominated contributor");
    V *h = header(c, member), *omega = HG("sample", scalar()),
      *Y = HG("HG", global_gid(gid), h, omega), *l = gua_enc(local, omega), *g = gua_enc(global, Y),
      *CL = A(l, 1), *CG = A(g, 1), *enc = ub_enc(A(c, C_TREE)), *ct = A(enc, 1), *ad = L(h, ct),
      *fin = ub_fin(A(enc, 0), ad), *kappa = A(fin, 1), *J = HG("HG", local_gid(gid, s), kappa, ad),
      *p = L(h, CG), *CT1 = seal(A(global, KEY), J, p), *P = L(p, CT1),
      *agg = gua_combine(local, L(L(member, L(CL)))), *rho = gua_dec(local, A(agg, 0)),
      *nonce = nonce_prepare(L(S("local"), gua_context(local), h), member),
      *delta = gua_ratchet(local, A(l, 0), rho, agg, L(member), A(nonce, 3), nonce, L(s, J), 0),
      *za = A(delta, 1), *next = gua_confirm(local, A(delta, 0), L(za)),
      *CT2 = seal(A(next, KEY), ct, D("WL", P, CL)), *ql = pack(L(P, CL, A(nonce, 3), za, CT2)),
      *qg = pack(L(P, D("QL", ql))), *pn = pending(ql, next, L(ct, kappa, J), member);
    put(pn, P_EK, A(fin, 0));
    put(pn, P_U, A(g, 0));
    put(c, C_PENDING, pn);
    return L(ql, qg);
}
V *takeover(V *c, V *ql) {
    V *pn = A(c, C_PENDING);
    if (pn->t != 'n') {
        REQUIRE(eq(A(pn, P_QL), ql), "conflicting local package");
        return A(pn, P_THETA);
    }
    V *v = unpack(ql);
    shape(v, 5);
    V *P = A(v, 0);
    shape(P, 2);
    V *p = A(P, 0);
    shape(p, 2);
    V *h = A(p, 0), *CG = A(p, 1), *CL = A(v, 1), *R = A(v, 2), *za = A(v, 3),
      *local = A(c, C_LOCAL), *global = A(c, C_GLOBAL), *a = need(A(c, C_A), A(c, C_SUB));
    REQUIRE(eq(h, header(c, a)), "QL group/epoch/subgroup/source mismatch");
    REQUIRE(!eq(a, A(c, C_ID)), "own package missing");
    V *src = need(A(c, C_SOURCES), a), *J = point(open_seal(A(global, KEY), A(P, 1), p), 0),
      *omega = gua_dec(local, CL);
    REQUIRE(eq(gua_dec(global, CG), HG("HG", global_gid(A(c, C_GID)), h, omega)),
            "local/global GUA contribution mismatch");
    V *agg = gua_combine(local, L(L(a, L(CL)))),
      *delta =
          gua_ratchet(local, Z, gua_dec(local, A(agg, 0)), agg, L(a), R, Z, L(A(c, C_SUB), J), 0);
    REQUIRE(A(delta, 1)->t == 'n', "unexpected local confirmer");
    V *next = gua_confirm(local, A(delta, 0), L(za)),
      *ct = open_seal(A(next, KEY), A(v, 4), D("WL", P, CL)),
      *dec = ub_dec(A(src, 0), L(h, ct), ct), *kappa = A(dec, 1);
    REQUIRE(eq(J, HG("HG", local_gid(A(c, C_GID), A(c, C_SUB)), kappa, L(h, ct))),
            "UB-KEM root mismatch");
    pn = pending(ql, next, L(ct, kappa, J), a);
    put(pn, P_DK, A(dec, 0));
    put(c, C_PENDING, pn);
    return A(pn, P_THETA);
}
V *core_share(V *c, V *ql, V *qgs, V *R) {
    takeover(c, ql);
    V *pn = A(c, C_PENDING);
    if (A(pn, P_CAND)->t != 'n') {
        REQUIRE(eq(A(pn, P_QGS), qgs), "conflicting global transcript");
        REQUIRE(eq(A(A(pn, P_CAND), 3), R), "conflicting aggregate nonce");
        return A(pn, P_SHARE)->t == 'n' ? Z : pack(A(pn, P_SHARE));
    }
    V *v = unpack(ql), *P = A(v, 0), *received = E, *contributions = E, *js = E,
      *global = A(c, C_GLOBAL);
    EACH(j, qgs) {
        V *q = unpack(A(qgs, j));
        shape(q, 2);
        V *otherP = A(q, 0), *p = A(otherP, 0), *h = A(p, 0), *CG = A(p, 1);
        shape(h, 3);
        shape(A(h, 0), 2);
        V *s = A(h, 1), *source = A(h, 2);
        REQUIRE(eq(A(A(h, 0), 0), A(c, C_GID)) &&
                    integer(A(A(h, 0), 1)) == integer(A(c, C_EPOCH)) + 1,
                "global package group/epoch mismatch");
        REQUIRE(get(received, s)->t == 'n', "duplicate global subgroup package");
        REQUIRE(eq(need(A(c, C_A), s), source), "global contributor mismatch");
        blob(A(q, 1), 32);
        set(received, s, q);
        set(contributions, source, L(CG));
        set(js, source, point(open_seal(A(global, KEY), A(otherP, 1), p), 0));
    }
    REQUIRE(eq(keys(received), keys(A(c, C_A))), "missing subgroup contribution");
    REQUIRE(eq(need(received, A(c, C_SUB)), L(P, D("QL", ql))), "QL/QG commitment mismatch");
    if (eq(A(c, C_ID), A(pn, P_SOURCE)))
        REQUIRE(eq(A(need(contributions, A(c, C_ID)), 0), A(A(P, 0), 1)),
                "own contribution substituted");
    V *agg = gua_combine(global, contributions), *weights = A(agg, 3), *J = identity();
    EACH(j, js) {
        V *e = A(js, j);
        J = add(J, mul(need(weights, A(e, 0)), A(e, 1)));
    }
    V *rho = gua_dec(global, A(agg, 0));
    point(R, 1);
    V *delta = gua_ratchet(global, A(pn, P_U), rho, agg, A(c, C_B), R, A(c, C_NONCE), J,
                           truth(A(c, C_STRICT))),
      *share = A(delta, 1);
    put(pn, P_CAND, A(delta, 0));
    put(pn, P_J, J);
    put(pn, P_WEIGHTS, weights);
    put(pn, P_QGS, qgs);
    put(pn, P_SHARE, share->t == 'n' ? Z : L(A(agg, 1), A(share, 0), A(share, 1)));
    return A(pn, P_SHARE)->t == 'n' ? Z : pack(A(pn, P_SHARE));
}
V *core_commit(V *c, V *shares, int send) {
    V *p = A(c, C_PENDING);
    REQUIRE(p->t != 'n' && A(p, P_CAND)->t != 'n', "Share must precede Commit");
    V *values = E;
    EACH(j, shares) {
        V *v = unpack(A(shares, j));
        shape(v, 3);
        REQUIRE(eq(A(v, 0), A(A(p, P_CAND), 4)), "confirmation transcript mismatch");
        push(values, L(A(v, 1), A(v, 2)));
    }
    V *next = gua_confirm(A(c, C_GLOBAL), A(p, P_CAND), values),
      *epoch = N(integer(A(c, C_EPOCH)) + 1), *J = A(p, P_J),
      *key = K("group-key", J, A(c, C_GID), epoch),
      *hist = D("hist", A(c, C_GID), epoch, A(c, C_HISTORY), J), *message = Z;
    if (send) {
        V *ct = A(A(p, P_THETA), 0), *kappa = A(A(p, P_THETA), 1), *Js = A(A(p, P_THETA), 2),
          *alpha = need(A(p, P_WEIGHTS), A(p, P_SOURCE)), *complement = sub(J, mul(alpha, Js)),
          *h = header(c, A(p, P_SOURCE)),
          *e = L(h, epoch, ct, alpha, need(A(A(p, P_LOCAL), ROSTER), A(p, P_SOURCE))),
          *cipher = seal(K("subgroup-envelope", kappa, L(h, ct)), complement, e),
          *signature =
              sign(A(A(c, C_LOCAL), SK), D("M", A(c, C_ID), e, cipher, A(c, C_HISTORY), hist));
        message = pack(L(A(c, C_ID), e, cipher, signature));
    }
    put(c, C_GLOBAL, next);
    put(c, C_LOCAL, A(p, P_LOCAL));
    if (A(p, P_EK)->t != 'n')
        put(c, C_TREE, A(p, P_EK));
    if (A(p, P_DK)->t != 'n')
        set(A(c, C_SOURCES), A(p, P_SOURCE),
            L(A(p, P_DK), need(A(A(c, C_LOCAL), ROSTER), A(p, P_SOURCE))));
    put(c, C_EPOCH, epoch);
    put(c, C_KEY, key);
    put(c, C_HISTORY, hist);
    put(c, C_PENDING, Z);
    put(c, C_NONCE, Z);
    return message;
}
void core_abort(V *c) {
    if (A(c, C_NONCE)->t != 'n')
        nonce_burn(A(c, C_NONCE));
    put(c, C_PENDING, Z);
    put(c, C_NONCE, Z);
    put(c, C_A, E);
    put(c, C_B, E);
}
V *ordinary_receive(V *c, V *wire) {
    V *v = unpack(wire);
    shape(v, 4);
    V *x = A(v, 0), *e = A(v, 1), *cipher = A(v, 2), *signature = A(v, 3);
    shape(e, 5);
    V *h = A(e, 0), *epoch = A(e, 1), *ct = A(e, 2), *alpha = sread(A(e, 3)), *next_pk = A(e, 4);
    shape(h, 3);
    shape(A(h, 0), 2);
    V *source = A(h, 2);
    REQUIRE(eq(A(A(h, 0), 0), A(c, C_GID)) && eq(A(h, 1), A(c, C_SUB)), "wrong group/subgroup");
    REQUIRE(eq(epoch, A(A(h, 0), 1)) && integer(epoch) == integer(A(c, C_EPOCH)) + 1,
            "replayed/out-of-order epoch");
    V *src = need(A(c, C_SOURCES), source), *broadcaster = need(A(c, C_SOURCES), x);
    REQUIRE(!eq(alpha, identity()), "zero contribution weight");
    point(next_pk, 1);
    V *dec = ub_dec(A(src, 0), L(h, ct), ct), *kappa = A(dec, 1),
      *complement = point(open_seal(K("subgroup-envelope", kappa, L(h, ct)), cipher, e), 0),
      *Js = HG("HG", local_gid(A(c, C_GID), A(c, C_SUB)), kappa, L(h, ct)),
      *J = add(mul(alpha, Js), complement),
      *hist = D("hist", A(c, C_GID), epoch, A(c, C_HISTORY), J);
    REQUIRE(verify(A(broadcaster, 1), D("M", x, e, cipher, A(c, C_HISTORY), hist), signature),
            "subgroup broadcast signature/history failed");
    V *key = K("group-key", J, A(c, C_GID), epoch);
    set(A(c, C_SOURCES), source, L(A(dec, 0), next_pk));
    put(c, C_EPOCH, epoch);
    put(c, C_KEY, key);
    put(c, C_HISTORY, hist);
    return key;
}
V *group_init(V *gid, V *roster, int strict, uint64_t window) {
    V *all = E, *coreids = E;
    EACH(s, roster) {
        V *r = A(roster, s);
        shape(r, 2);
        REQUIRE(A(r, 0)->n && A(r, 0)->n + A(r, 1)->n >= 2, "invalid subgroup");
        all = cat(all, cat(A(r, 0), A(r, 1)));
        coreids = cat(coreids, A(r, 0));
    }
    canonical_ids(sort(all), 1);
    V *global = gua_init(global_gid(gid), coreids), *cores = E, *ordinary = E;
    EACH(s, roster) {
        V *r = A(roster, s), *ids = A(r, 0), *users = A(r, 1),
          *local = gua_init(local_gid(gid, N(s)), ids), *paths = E, *trees = E,
          *members = cat(ids, users);
        EACH(j, members) set(paths, A(members, j), E);
        EACH(j, ids) {
            V *a = A(ids, j), *recipients = without(members, a), *gen = ub_gen(recipients);
            set(trees, a, A(gen, 0));
            EACH(k, recipients)
            set(need(paths, A(recipients, k)), a,
                L(A(A(gen, 1), k), need(A(need(local, a), ROSTER), a)));
        }
        EACH(j, ids) {
            V *a = A(ids, j);
            set(cores, a,
                L(gid, N(s), a, need(local, a), need(global, a), need(trees, a), need(paths, a),
                  N(0), Z, Z, E, E, Z, boolean(strict), identity()));
        }
        EACH(j, users) {
            V *a = A(users, j);
            set(ordinary, a,
                L(gid, N(s), a, Z, Z, Z, need(paths, a), N(0), Z, Z, E, E, Z, boolean(strict),
                  identity()));
        }
    }
    return L(gid, roster, cores, ordinary, session_new(gid, coreids, window));
}
V *group_balanced(uint64_t n, uint64_t groups, uint64_t q, V *gid, int strict) {
    REQUIRE(groups && n % groups == 0 && q >= 1 && n / groups > q && n <= 65536,
            "invalid balanced partition");
    uint64_t size = n / groups;
    V *roster = E;
    for (uint64_t s = 0; s < groups; s++)
        push(roster, L(range(s * size, s * size + q), range(s * size + q, (s + 1) * size)));
    return group_init(gid, roster, strict, 16);
}
V *prepare_nonces(V *g) {
    V *core = A(A(A(g, 2), 0), 1), *s = A(g, 4);
    if (session_ready(s, N(integer(A(core, C_EPOCH)) + 1)))
        return Z;
    V *trace = E;
    session_preprocess(s, A(core, C_EPOCH), D("nonce-roster", A(A(core, C_GLOBAL), ROSTER)), trace);
    return trace;
}
V *group_round(V *g, int rotate, int handoff, int deliver, int check) {
    V *prep = prepare_nonces(g), *trace = E, *cores = A(g, 2), *ordinary = A(g, 3),
      *roster = A(g, 1), *epoch = A(A(A(cores, 0), 1), C_EPOCH), *a = E, *b = E, *broadcasters = E,
      *qls = E, *qgs = E;
    EACH(j, cores)
    REQUIRE(eq(A(A(A(cores, j), 1), C_EPOCH), epoch), "core epochs not synchronized");
    EACH(s, roster) {
        V *ids = A(A(roster, s), 0);
        size_t index = rotate ? (size_t)(integer(epoch) % ids->n) : 0;
        V *source = A(ids, index), *x = A(ids, handoff ? (index + 1) % ids->n : index);
        set(a, N(s), source);
        push(b, x);
        set(broadcasters, N(s), x);
    }
    b = sort(b);
    EACH(j, cores) configure(A(A(cores, j), 1), a, b);
    EACH(j, a) {
        V *s = A(A(a, j), 0), *source = A(A(a, j), 1), *p = core_prepare(need(cores, source));
        set(qls, s, A(p, 0));
        push(qgs, A(p, 1));
        sent(trace, "QL", source, A(p, 0), without(A(A(roster, integer(s)), 0), source));
        sent(trace, "QG", source, A(p, 1), without(keys(cores), source));
    }
    V *binding = L(A(g, 0), A(A(g, 4), 1), N(integer(epoch) + 1), a, b, D("nonce-round", qgs)),
      *prepared = session_aggregate(A(g, 4), binding, trace), *shares = E;
    EACH(j, cores) {
        V *i = A(A(cores, j), 0), *c = A(A(cores, j), 1);
        put(c, C_NONCE, A(need(prepared, i), 1));
        V *wire = core_share(c, need(qls, A(c, C_SUB)), qgs, A(need(prepared, i), 0));
        if (wire->t != 'n') {
            push(shares, wire);
            sent(trace, "confirmation_share", i, wire, without(keys(cores), i));
        }
    }
    V *messages = E;
    EACH(j, cores) {
        V *i = A(A(cores, j), 0), *c = A(A(cores, j), 1), *s = A(c, C_SUB),
          *wire = core_commit(c, shares, eq(need(broadcasters, s), i));
        if (wire->t != 'n') {
            set(messages, s, wire);
            sent(trace, "M", i, wire, A(A(roster, integer(s)), 1));
        }
    }
    if (deliver) {
        EACH(j, ordinary) {
            V *c = A(A(ordinary, j), 1);
            ordinary_receive(c, need(messages, A(c, C_SUB)));
        }
        if (check) {
            V *key = A(A(A(cores, 0), 1), C_KEY), *hist = A(A(A(cores, 0), 1), C_HISTORY),
              *all = cat(cores, ordinary);
            EACH(j, all) {
                V *c = A(A(all, j), 1);
                REQUIRE(eq(A(c, C_KEY), key) && eq(A(c, C_HISTORY), hist),
                        "global key/history agreement failed");
            }
        }
    }
    return L(messages, trace, prep);
}
