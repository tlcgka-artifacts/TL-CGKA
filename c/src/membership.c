#include "internal.h"
static V *client(V *g, V *i) {
    V *c = get(A(g, 2), i);
    return c->t == 'n' ? need(A(g, 3), i) : c;
}
static int queues_empty(V *m) {
    EACH(j, A(m, 3)) if (A(A(A(m, 3), j), 1)->n) return 0;
    return 1;
}
V *membership_new(V *g) {
    V *channels = E, *queues = E, *ids = cat(keys(A(g, 2)), keys(A(g, 3)));
    EACH(j, ids) set(channels, A(ids, j), nike_gen());
    EACH(j, A(g, 2)) set(queues, A(A(A(g, 2), j), 0), E);
    return L(g, channels, E, queues, N(0));
}
V *private_deliver(V *channels, V *source, V *recipient, V *value, V *ctx, V *trace) {
    V *ad = L(S("private"), source, recipient, ctx), *a = need(channels, source),
      *b = need(channels, recipient), *key = K("private-channel", nike(A(a, 0), A(b, 1)), ad),
      *wire = seal(key, pack(value), ad);
    sent(trace, "private", source, wire, L(recipient));
    return unpack(open_seal(K("private-channel", nike(A(b, 0), A(a, 1)), ad), wire, ad));
}
V *change_core(V *m, V *sponsor, V *op, V *target, V *pg, V *pl) {
    V *g = A(m, 0), *x = need(A(g, 2), sponsor);
    REQUIRE(!A(m, 2)->n && queues_empty(m), "operation/queue already pending");
    EACH(j, A(g, 2)) REQUIRE(A(A(A(A(g, 2), j), 1), C_PENDING)->t == 'n', "round already pending");
    REQUIRE((is(op, "A") || is(op, "R")) && !eq(target, sponsor), "invalid core operation");
    V *roster = A(A(g, 1), integer(A(x, C_SUB))), *ids = A(roster, 0);
    if (is(op, "A"))
        REQUIRE(get(A(g, 2), target)->t == 'n' && get(A(g, 3), target)->t == 'n',
                "identity already present");
    else
        REQUIRE(contains(ids, target), "target is not local core");
    V *h = L(A(g, 0), A(m, 4), A(x, C_EPOCH), A(x, C_SUB), sponsor, op, target, A(x, C_HISTORY)),
      *wg = refresh_change(A(x, C_GLOBAL), op, target, pg, h, 1, Z),
      *wl = refresh_change(A(x, C_LOCAL), op, target, pl, h, 1, Z),
      *tree = is(op, "A") ? ub_add(A(x, C_TREE), target) : ub_rmv(A(x, C_TREE), target),
      *dk = is(op, "A") ? A(tree, 1) : Z, *cm = A(tree, is(op, "A") ? 2 : 1),
      /* Revised Figure 4, ChangeCore 4: authenticate the complete L_s^{L+}. */
      *body = L(h, A(wg, 0), A(wl, 0), cm, A(A(wl, 1), ROSTER)),
      *wire = pack(L(body, sign(A(A(x, C_GLOBAL), SK), D("ChangeCore", body)),
                     sign(A(A(x, C_LOCAL), SK), D("ChangeCore", body))));
    V *candidate =
        L(L(A(x, C_GLOBAL), A(x, C_LOCAL), A(x, C_TREE)), wire, dk, A(wg, 1), A(wl, 1), A(tree, 0));
    set(A(m, 2), sponsor, candidate);
    return L(wire, dk);
}
V *process_change(V *m, V *member, V *wire, V *og, V *ol, V *secrets) {
    V *g = A(m, 0), *v = unpack(wire);
    shape(v, 3);
    V *body = A(v, 0);
    shape(body, 5);
    V *h = A(body, 0);
    shape(h, 8);
    V *gid = A(h, 0), *version = A(h, 1), *epoch = A(h, 2), *subgroup = A(h, 3), *sponsor = A(h, 4),
      *op = A(h, 5), *target = A(h, 6), *history = A(h, 7);
    REQUIRE(eq(gid, A(g, 0)) && eq(version, A(m, 4)), "membership replay/context mismatch");
    int joining = is(op, "A") && eq(member, target);
    if (!joining) {
        V *c = client(g, member);
        REQUIRE(eq(epoch, A(c, C_EPOCH)) && eq(history, A(c, C_HISTORY)),
                "membership predecessor/history mismatch");
    }
    V *roster = A(A(g, 1), integer(subgroup)), *ids = A(roster, 0), *users = A(roster, 1);
    REQUIRE(contains(ids, sponsor) && (is(op, "A") || is(op, "R")), "invalid sponsor/operation");
    REQUIRE(!is(op, "R") || !eq(member, target), "removed member has no next state");
    int local = contains(ids, member) || contains(users, member) || joining,
        core = get(A(g, 2), member)->t != 'n' || joining;
    if (core)
        REQUIRE(verify(need(A(og, 2), sponsor), D("ChangeCore", body), A(v, 1)),
                "global auth failed");
    if (local) {
        V *old_local_pk = core ? need(A(ol, 2), sponsor) :
            A(need(A(client(g, member), C_SOURCES), sponsor), 1);
        REQUIRE(verify(old_local_pk, D("ChangeCore", body), A(v, 2)),
                "local auth failed");
    }
    V *local_roster = A(body, 4), *sg = Z, *sl = Z, *p = Z;
    if (eq(member, sponsor)) {
        V *cand = need(A(m, 2), sponsor), *x = need(A(g, 2), sponsor);
        REQUIRE(eq(A(cand, 1), wire) &&
                    eq(A(cand, 0), L(A(x, C_GLOBAL), A(x, C_LOCAL), A(x, C_TREE))),
                "stale candidate");
        REQUIRE(eq(A(A(cand, 4), ROSTER), local_roster), "local refresh roster mismatch");
        return L(A(cand, 3), A(cand, 4), Z);
    }
    if (core) {
        V *sk = joining ? A(secrets, 0) : A(A(need(A(g, 2), member), C_GLOBAL), SK);
        sg = refresh_recover(og, member, sk, A(body, 1), h, 1);
    }
    if (local && core) {
        V *sk = joining ? A(secrets, 1) : A(A(need(A(g, 2), member), C_LOCAL), SK);
        sl = refresh_recover(ol, member, sk, A(body, 2), h, 1);
        /* Revised Process 6: check the authenticated table against GUA recovery. */
        REQUIRE(eq(A(sl, ROSTER), local_roster), "local refresh roster mismatch");
    }
    if (local && !eq(member, target)) {
        V *c = client(g, member);
        p = ub_proc(A(need(A(c, C_SOURCES), sponsor), 0), A(body, 3));
    }
    return L(sg, sl, p);
}
V *membership_change(V *m, V *sponsor, V *op, V *target) {
    V *g = A(m, 0), *trace = E, *x = need(A(g, 2), sponsor), *subgroup = A(x, C_SUB),
      *roster = A(A(g, 1), integer(subgroup)), *ids = A(roster, 0), *users = A(roster, 1),
      *og = anchor(A(x, C_GLOBAL)), *ol = anchor(A(x, C_LOCAL)), *secrets = Z, *pg, *pl;
    int adding = is(op, "A");
    if (adding) {
        secrets = L(scalar(), scalar());
        REQUIRE(get(A(m, 1), target)->t == 'n', "duplicate channel identity");
        set(A(m, 1), target, nike_gen());
        pg = base(A(secrets, 0));
        pl = base(A(secrets, 1));
    } else {
        pg = need(A(og, 2), target);
        pl = need(A(ol, 2), target);
    }
    V *change = change_core(m, sponsor, op, target, pg, pl), *wire = A(change, 0),
      *dk = A(change, 1), *body = A(unpack(wire), 0), *h = A(body, 0),
      *local_roster = A(body, 4),
      *active = cat(keys(A(g, 2)), keys(A(g, 3)));
    if (adding)
        push(active, target);
    else
        active = without(active, target);
    active = sort(active);
    sent(trace, "membership_control", sponsor, wire, without(active, sponsor));
    V *candidates = E;
    EACH(j, active) {
        V *i = A(active, j);
        set(candidates, i, process_change(m, i, wire, og, ol, eq(i, target) ? secrets : Z));
    }
    V *paths = E, *own_tree = Z, *delivered = E;
    if (adding) {
        sent(trace, "join_context", sponsor, pack(L(og, ol)), L(target));
        V *value = private_deliver(A(m, 1), sponsor, target, dk, h, trace),
          *vk = need(local_roster, sponsor);
        REQUIRE(path(A(value, 0))->n == A(value, 1)->n, "bad private path");
        set(paths, sponsor, L(value, vk));
        V *recipients = cat(ids, users), *gen = ub_gen(recipients);
        own_tree = A(gen, 0);
        V *ownvk = need(local_roster, target);
        EACH(j, recipients) {
            V *i = A(recipients, j),
              *record = private_deliver(A(m, 1), target, i, A(A(gen, 1), j), h, trace);
            set(delivered, i, L(record, ownvk));
        }
    }
    EACH(j, active) {
        V *i = A(active, j), *cand = need(candidates, i);
        if (adding && eq(i, target))
            continue;
        V *c = client(g, i);
        if (A(cand, 0)->t != 'n')
            put(c, C_GLOBAL, A(cand, 0));
        if (A(cand, 1)->t != 'n')
            put(c, C_LOCAL, A(cand, 1));
        if (eq(i, sponsor))
            put(c, C_TREE, A(need(A(m, 2), sponsor), 5));
        else if (A(cand, 2)->t != 'n')
            set(A(c, C_SOURCES), sponsor,
                L(A(cand, 2), need(local_roster, sponsor)));
        if (eq(A(c, C_SUB), subgroup)) {
            if (adding)
                set(A(c, C_SOURCES), target, need(delivered, i));
            else
                del(A(c, C_SOURCES), target);
        }
        put(c, C_EPOCH, N(integer(A(c, C_EPOCH)) + 1));
    }
    V *newids = adding ? sort(cat(ids, L(target))) : without(ids, target);
    if (adding) {
        V *cand = need(candidates, target);
        set(A(g, 2), target,
            L(A(g, 0), subgroup, target, A(cand, 1), A(cand, 0), own_tree, paths, A(x, C_EPOCH), Z,
              Z, E, E, Z, A(x, C_STRICT), A(x, C_HISTORY)));
        set(A(m, 3), target, E);
    } else {
        del(A(g, 2), target);
        del(A(m, 3), target);
    }
    put(A(g, 1), integer(subgroup), L(newids, users));
    /* Revised Process 11: use only the table carried by the verified message.
     * Update every existing local source record, preserving its receiver path. */
    V *local_members = cat(newids, users);
    EACH(j, local_members) {
        V *c = client(g, A(local_members, j)), *sources = A(c, C_SOURCES);
        EACH(k, newids) {
            V *id = A(newids, k), *src = get(sources, id);
            if (src->t != 'n')
                set(sources, id, L(A(src, 0), need(local_roster, id)));
        }
    }
    EACH(j, newids) {
        V *i = A(newids, j);
        if (!eq(i, sponsor) && !eq(i, target))
            push(need(A(m, 3), i), L(op, target, D("M_op", wire)));
    }
    put(m, 2, E);
    put(m, 4, N(integer(A(m, 4)) + 1));
    session_reconfigure(A(g, 4), keys(A(g, 2)), trace);
    return trace;
}
V *membership_drain(V *m) {
    V *g = A(m, 0), *trace = E;
    EACH(j, A(m, 3)) {
        V *source = A(A(A(m, 3), j), 0), *queue = A(A(A(m, 3), j), 1),
          *core = need(A(g, 2), source);
        while (queue->n) {
            V *op = A(A(queue, 0), 0), *target = A(A(queue, 0), 1), *op_hash = A(A(queue, 0), 2);
            int adding = is(op, "A");
            V *tree = adding ? ub_add(A(core, C_TREE), target) : ub_rmv(A(core, C_TREE), target),
              *dk = adding ? A(tree, 1) : Z, *cm = A(tree, adding ? 2 : 1),
              *body = L(A(g, 0), A(m, 4), source, op, target, op_hash, cm),
              *wire = pack(L(body, sign(A(A(core, C_LOCAL), SK), D("queued-source", body)))),
              *r = A(A(g, 1), integer(A(core, C_SUB))),
              *recipients = without(cat(A(r, 0), A(r, 1)), source);
            sent(trace, "queued_source_control", source, wire, recipients);
            EACH(k, recipients) {
                V *i = A(recipients, k), *c = client(g, i),
                  *vk = need(A(A(core, C_LOCAL), ROSTER), source);
                if (adding && eq(i, target)) {
                    V *value =
                        private_deliver(A(m, 1), source, i, L(dk, vk), L(op_hash, source), trace);
                    set(A(c, C_SOURCES), source, value);
                } else {
                    V *v = unpack(wire), *src = need(A(c, C_SOURCES), source);
                    REQUIRE(verify(A(src, 1), D("queued-source", A(v, 0)), A(v, 1)),
                            "queue signature failed");
                    set(A(c, C_SOURCES), source, L(ub_proc(A(src, 0), A(A(v, 0), 6)), A(src, 1)));
                }
            }
            put(core, C_TREE, A(tree, 0));
            memmove(queue->v, queue->v + 1, (queue->n - 1) * sizeof(V *));
            queue->n--;
        }
    }
    return trace;
}
V *membership_update(V *m, int check) {
    REQUIRE(queues_empty(m) && !A(m, 2)->n, "membership queues must be completed first");
    return group_round(A(m, 0), 1, 0, 1, check);
}

/* Parse/authenticate an ordinary-member control and stage the receiver path.
 * Installation is performed by membership_change_ordinary after all checks. */
V *process_ordinary(V *m, V *member, V *wire) {
    V *g = A(m, 0), *v = unpack(wire);
    shape(v, 3);
    V *body = A(v, 0); shape(body, 2);
    V *h = A(body, 0); shape(h, 9);
    REQUIRE(is(A(h, 0), "ordinary") && eq(A(h, 1), A(g, 0)) && eq(A(h, 2), A(m, 4)),
            "ordinary replay/context mismatch");
    V *c = client(g, member), *sub = A(h, 5), *sponsor = A(h, 6),
      *op = A(h, 7), *target = A(h, 8), *roster = A(A(g, 1), integer(sub)),
      *ids = A(roster, 0), *users = A(roster, 1);
    REQUIRE(eq(A(c, C_SUB), sub) && contains(ids, sponsor) && !eq(sponsor, target),
            "invalid ordinary sponsor/subgroup");
    REQUIRE(eq(A(c, C_EPOCH), A(h, 3)) && eq(A(c, C_HISTORY), A(h, 4)),
            "ordinary predecessor/context mismatch");
    if (is(op, "A")) {
        REQUIRE(get(A(g, 2), target)->t == 'n' && get(A(g, 3), target)->t == 'n',
                "identity already present");
    } else {
        REQUIRE(is(op, "R") && contains(users, target) && !eq(member, target),
                "invalid ordinary removal/recipient");
    }
    int core = get(A(g, 2), member)->t != 'n';
    if (core)
        REQUIRE(verify(need(A(A(c, C_GLOBAL), ROSTER), sponsor),
                       D("ChangeOrdinary", body), A(v, 1)), "ordinary global auth failed");
    V *vk = core ? need(A(A(c, C_LOCAL), ROSTER), sponsor) :
                  A(need(A(c, C_SOURCES), sponsor), 1);
    REQUIRE(verify(vk, D("ChangeOrdinary", body), A(v, 2)), "ordinary local auth failed");
    return eq(member, sponsor) ? Z :
        ub_proc(A(need(A(c, C_SOURCES), sponsor), 0), A(body, 1));
}

/* Receiver-only membership extension built from the existing authenticated
 * control and UB-KEM add/rmv/proc primitives. It does NOT change GUA membership,
 * signing keys, confirmer eligibility, or the nonce participant set. */
V *membership_change_ordinary(V *m, V *sponsor, V *op, V *target) {
    V *g = A(m, 0), *x = need(A(g, 2), sponsor), *sub = A(x, C_SUB),
      *roster = A(A(g, 1), integer(sub)), *ids = A(roster, 0), *users = A(roster, 1);
    REQUIRE(!A(m, 2)->n && queues_empty(m), "operation/queue already pending");
    EACH(j, A(g, 2)) {
        V *c = A(A(A(g, 2), j), 1);
        REQUIRE(A(c, C_PENDING)->t == 'n' && A(c, C_NONCE)->t == 'n', "round already pending");
    }
    REQUIRE((is(op, "A") || is(op, "R")) && !eq(sponsor, target), "invalid ordinary operation");
    int adding = is(op, "A");
    if (adding) {
        REQUIRE(get(A(g, 2), target)->t == 'n' && get(A(g, 3), target)->t == 'n',
                "identity already present");
        REQUIRE(get(A(m, 1), target)->t == 'n', "duplicate channel identity");
    } else {
        REQUIRE(contains(users, target), "target is not a local ordinary member");
        /* Existing UB-KEM requires at least one receiver after removal. */
        REQUIRE(ids->n + users->n > 2, "cannot remove the last source-tree receiver");
    }
    V *trace = E, *h = L(S("ordinary"), A(g, 0), A(m, 4), A(x, C_EPOCH),
                         A(x, C_HISTORY), sub, sponsor, op, target),
      *tree = adding ? ub_add(A(x, C_TREE), target) : ub_rmv(A(x, C_TREE), target),
      *dk = adding ? A(tree, 1) : Z, *cm = A(tree, adding ? 2 : 1),
      *body = L(h, cm), *tag = D("ChangeOrdinary", body),
      *wire = pack(L(body, sign(A(A(x, C_GLOBAL), SK), tag),
                     sign(A(A(x, C_LOCAL), SK), tag))),
      *active = sort(cat(ids, users));
    if (!adding)
        active = without(active, target);
    sent(trace, "ordinary_membership_control", sponsor, wire, without(active, sponsor));
    V *candidates = E;
    /* Decode and authenticate the actual wire separately at each recipient. */
    EACH(j, active) {
        V *i = A(active, j);
        set(candidates, i, process_ordinary(m, i, wire));
    }
    V *joined = Z;
    if (adding) {
        set(A(m, 1), target, nike_gen());
        /* The authenticated confidential channel supplies a public context and
         * the NEW receiver path, never an old group key or a core secret. */
        V *vk = need(A(A(x, C_LOCAL), ROSTER), sponsor),
          *received = private_deliver(A(m, 1), sponsor, target, L(h, wire, dk, vk), h, trace),
          *control = unpack(A(received, 1));
        REQUIRE(eq(A(received, 0), h) &&
                    verify(A(received, 3), D("ChangeOrdinary", A(control, 0)), A(control, 2)),
                "ordinary join context authentication failed");
        V *paths = E;
        set(paths, sponsor, L(A(received, 2), A(received, 3)));
        joined = L(A(g, 0), sub, target, Z, Z, Z, paths,
                   A(h, 3), Z, Z, E, E, Z, A(x, C_STRICT), A(h, 4));
    }
    EACH(j, active) {
        V *i = A(active, j), *c = client(g, i), *p = get(candidates, i);
        if (p->t != 'n') {
            V *old = need(A(c, C_SOURCES), sponsor);
            set(A(c, C_SOURCES), sponsor, L(p, A(old, 1)));
        }
    }
    put(x, C_TREE, A(tree, 0));
    if (adding)
        set(A(g, 3), target, joined);
    else {
        del(A(g, 3), target);
        del(A(m, 1), target);
    }
    put(roster, 1, adding ? sort(cat(users, L(target))) : without(users, target));
    EACH(j, ids) {
        V *i = A(ids, j);
        if (!eq(i, sponsor))
            push(need(A(m, 3), i), L(op, target, D("M_op", wire)));
    }
    put(m, 4, N(integer(A(m, 4)) + 1));
    return trace;
}
