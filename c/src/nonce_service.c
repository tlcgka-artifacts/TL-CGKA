#include "internal.h"
void sent(V *trace, const char *kind, V *source, V *wire, V *recipients) {
    push(trace, L(S(kind), source, wire, recipients));
}
V *endpoint(V *key, V *sid, V *owner, V *peer) {
    return L(key, sid, owner, peer, N(0), N(0));
}
V *endpoint_send(V *e, V *value) {
    shape(e, 6);
    V *seq = A(e, 4);
    REQUIRE(integer(seq) < UINT64_MAX, "channel sequence exhausted");
    V *wire = pack(L(seq, seal(A(e, 0), pack(value), L(A(e, 1), A(e, 2), A(e, 3), seq))));
    put(e, 4, N(integer(seq) + 1));
    return wire;
}
V *endpoint_receive(V *e, V *wire) {
    V *v = unpack(wire);
    shape(v, 2);
    V *seq = A(v, 0);
    REQUIRE(eq(seq, A(e, 5)), "nonce channel replay/out-of-order record");
    V *out = unpack(open_seal(A(e, 0), A(v, 1), L(A(e, 1), A(e, 3), A(e, 2), seq)));
    REQUIRE(integer(seq) < UINT64_MAX, "channel sequence exhausted");
    put(e, 5, N(integer(seq) + 1));
    return out;
}
void client_clear(V *c) {
    V *pool = A(c, 2);
    EACH(j, pool) nonce_burn(A(A(pool, j), 1));
    put(c, 2, E);
}
V *client_prepare(V *c, V *ctx) {
    shape(ctx, 6);
    client_clear(c);
    put(c, 3, ctx);
    uint64_t base_epoch = integer(A(ctx, 4)), window = integer(A(ctx, 5));
    REQUIRE(window > 0 && window <= 65536 && base_epoch <= UINT64_MAX - window,
            "invalid nonce window");
    V *entries = E;
    for (uint64_t e = base_epoch + 1; e <= base_epoch + window; e++) {
        V *n = nonce_prepare(L(ctx, N(e)), A(c, 0));
        set(A(c, 2), N(e), n);
        push(entries, L(N(e), A(nonce_commitment(n), 1)));
    }
    return endpoint_send(A(c, 1), L(S("commit"), ctx, entries));
}
V *client_open(V *c) {
    V *entries = E, *pool = A(c, 2);
    EACH(j, pool) {
        V *e = A(pool, j), *n = A(e, 1);
        push(entries, L(A(e, 0), A(n, 3), A(n, 4)));
    }
    return endpoint_send(A(c, 1), L(S("open"), A(c, 3), entries));
}
V *client_accept(V *c, V *wire, V *binding, int selected) {
    V *v = endpoint_receive(A(c, 1), wire);
    shape(v, 3);
    REQUIRE(eq(A(v, 0), A(c, 3)) && eq(A(v, 1), binding), "nonce response context mismatch");
    V *R = point(A(v, 2), 1), *epoch = A(binding, 2), *n = need(A(c, 2), epoch), *pool = E;
    EACH(j, A(c, 2)) {
        V *entry = A(A(c, 2), j);
        if (integer(A(entry, 0)) > integer(epoch))
            push(pool, entry);
        else if (!eq(A(entry, 0), epoch))
            nonce_burn(A(entry, 1));
    }
    put(c, 2, pool);
    if (!selected) {
        nonce_burn(n);
        n = Z;
    }
    return L(R, n);
}
V *server_new(void) {
    return L(E, E, Z, E, E, E, boolean(0), Z);
}
void server_begin(V *s, V *ctx, V *members) {
    shape(ctx, 6);
    canonical_ids(members, 1);
    put(s, 2, ctx);
    put(s, 1, members);
    put(s, 3, E);
    put(s, 4, E);
    put(s, 5, E);
    put(s, 6, boolean(0));
    put(s, 7, A(ctx, 4));
}
void server_commit(V *s, V *member, V *wire) {
    V *v = endpoint_receive(need(A(s, 0), member), wire);
    shape(v, 3);
    V *ctx = A(v, 1), *entries = A(v, 2);
    REQUIRE(is(A(v, 0), "commit") && eq(ctx, A(s, 2)) && contains(A(s, 1), member),
            "nonce commitment context mismatch");
    REQUIRE(!truth(A(s, 6)) && get(A(s, 3), member)->t == 'n', "duplicate/late commitment");
    uint64_t b = integer(A(ctx, 4)), w = integer(A(ctx, 5));
    REQUIRE(w > 0 && w <= 65536 && b <= UINT64_MAX - w, "invalid nonce window");
    REQUIRE(eq(keys(entries), range(b + 1, b + w + 1)), "wrong nonce window");
    EACH(j, entries) blob(A(A(entries, j), 1), 32);
    set(A(s, 3), member, entries);
}
void server_freeze(V *s) {
    REQUIRE(eq(keys(A(s, 3)), sort(A(s, 1))), "missing nonce commitments");
    put(s, 6, boolean(1));
}
void server_open(V *s, V *member, V *wire) {
    V *v = endpoint_receive(need(A(s, 0), member), wire);
    shape(v, 3);
    REQUIRE(truth(A(s, 6)) && is(A(v, 0), "open") && eq(A(v, 1), A(s, 2)),
            "opening before commit barrier");
    REQUIRE(contains(A(s, 1), member) && !contains(A(s, 5), member), "duplicate/unknown opening");
    V *entries = A(v, 2), *ids = E, *staged = E, *commits = need(A(s, 3), member);
    EACH(j, entries) {
        V *e = A(entries, j);
        shape(e, 3);
        push(ids, A(e, 0));
        point(A(e, 1), 1);
        blob(A(e, 2), 32);
        REQUIRE(eq(need(commits, A(e, 0)),
                   D("nonce-commit", L(A(s, 2), A(e, 0)), member, A(e, 1), A(e, 2))),
                "nonce commitment mismatch");
        set(staged, L(member, A(e, 0)), A(e, 1));
    }
    REQUIRE(eq(ids, keys(commits)), "wrong opening window");
    EACH(j, staged) set(A(s, 4), A(A(staged, j), 0), A(A(staged, j), 1));
    push(A(s, 5), member);
    put(s, 5, sort(A(s, 5)));
}
V *server_update(V *s, V *member, V *wire) {
    V *v = endpoint_receive(need(A(s, 0), member), wire);
    shape(v, 2);
    V *ctx = A(v, 0), *b = A(v, 1);
    shape(b, 6);
    REQUIRE(eq(ctx, A(s, 2)) && eq(A(b, 0), A(ctx, 0)) && eq(A(b, 1), A(ctx, 1)),
            "wrong server round context");
    REQUIRE(eq(sort(A(s, 5)), sort(A(s, 1))), "incomplete nonce preprocessing");
    V *f = A(b, 4), *epoch = A(b, 2);
    canonical_ids(f, 1);
    REQUIRE(contains(A(s, 1), member) && integer(epoch) > integer(A(s, 7)),
            "replayed nonce aggregation");
    V *R = identity();
    EACH(j, f) {
        REQUIRE(contains(A(s, 1), A(f, j)), "unknown confirmer");
        R = add(R, need(A(s, 4), L(A(f, j), epoch)));
    }
    point(R, 1);
    V *registry = E;
    EACH(j, A(s, 4)) {
        V *entry = A(A(s, 4), j);
        if (integer(A(A(entry, 0), 1)) > integer(epoch))
            push(registry, entry);
    }
    put(s, 7, epoch);
    put(s, 4, registry);
    return R;
}
V *session_new(V *gid, V *members, uint64_t window) {
    REQUIRE(window > 0 && window <= 65536, "invalid preprocessing window");
    V *s = L(gid, N(0), N(window), N(0), server_new(), E, Z);
    EACH(j, members) session_register(s, A(members, j));
    return s;
}
void session_register(V *s, V *member) {
    V *key = random_bytes(32), *sid = random_bytes(24);
    set(A(s, 5), member, L(member, endpoint(key, sid, member, S("nonce-server")), E, Z));
    set(A(A(s, 4), 0), member, endpoint(key, sid, S("nonce-server"), member));
}
void session_reconfigure(V *s, V *members, V *trace) {
    members = sort(members);
    canonical_ids(members, 1);
    V *clients = A(s, 5), *sponsor = Z;
    EACH(j, members) if (get(clients, A(members, j))->t != 'n') {
        sponsor = A(members, j);
        break;
    }
    REQUIRE(sponsor->t != 'n', "no continuing sponsor");
    V *version = N(integer(A(s, 1)) + 1), *value = L(S("roster"), A(s, 0), version, members),
      *wire = endpoint_send(A(need(clients, sponsor), 1), value);
    sent(trace, "nonce_roster", sponsor, wire, L(S("nonce-server")));
    V *server = A(s, 4);
    REQUIRE(eq(endpoint_receive(need(A(server, 0), sponsor), wire), value),
            "nonce roster mismatch");
    put(server, 2, Z);
    put(server, 3, E);
    put(server, 4, E);
    V *old = keys(clients);
    EACH(j, old) {
        V *i = A(old, j);
        client_clear(need(clients, i));
        if (!contains(members, i)) {
            del(clients, i);
            del(A(server, 0), i);
        }
    }
    EACH(j, members) if (get(clients, A(members, j))->t == 'n') session_register(s, A(members, j));
    put(s, 1, version);
    put(s, 6, Z);
}
int session_ready(V *s, V *epoch) {
    if (A(s, 6)->t == 'n')
        return 0;
    EACH(j, A(s, 5)) {
        V *client = A(A(A(s, 5), j), 1);
        if (get(A(client, 2), epoch)->t == 'n')
            return 0;
    }
    return 1;
}
void session_preprocess(V *s, V *start, V *roster, V *trace) {
    put(s, 3, N(integer(A(s, 3)) + 1));
    V *ctx = L(A(s, 0), A(s, 1), A(s, 3), roster, start, A(s, 2));
    put(s, 6, ctx);
    V *members = keys(A(s, 5)), *server = A(s, 4);
    server_begin(server, ctx, members);
    EACH(j, members) {
        V *i = A(members, j), *wire = client_prepare(need(A(s, 5), i), ctx);
        sent(trace, "nonce_commit_upload", i, wire, L(S("nonce-server")));
        server_commit(server, i, wire);
    }
    server_freeze(server);
    EACH(j, members) {
        V *i = A(members, j), *wire = client_open(need(A(s, 5), i));
        sent(trace, "nonce_open_upload", i, wire, L(S("nonce-server")));
        server_open(server, i, wire);
    }
}
V *session_aggregate(V *s, V *binding, V *trace) {
    V *requester = A(A(binding, 4), 0), *server = A(s, 4), *clients = A(s, 5),
      *wire = endpoint_send(A(need(clients, requester), 1), L(A(s, 6), binding));
    sent(trace, "nonce_request", requester, wire, L(S("nonce-server")));
    V *R = server_update(server, requester, wire), *out = E;
    EACH(j, clients) {
        V *i = A(A(clients, j), 0), *c = A(A(clients, j), 1);
        wire = endpoint_send(need(A(server, 0), i), L(A(s, 6), binding, R));
        sent(trace, "nonce_result", S("nonce-server"), wire, L(i));
        set(out, i, client_accept(c, wire, binding, contains(A(binding, 4), i)));
    }
    return out;
}
