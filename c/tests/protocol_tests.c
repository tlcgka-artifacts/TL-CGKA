#include "internal.h"
#include "sodium_abi.h"
#include "tlcgka.h"
#include <stdio.h>

static void release(Arena *a) {
    Allocation *p = a->alloc;
    while (p) { Allocation *next = p->next; sodium_memzero(p + 1, p->size); free(p); p = next; }
}
static void rejects(const char *op, V *args, const char *reason) {
    V *wire = pack(L(S(op), args)), *before = bytes(wire->b, wire->n);
    unsigned char *out = NULL; size_t size = 0;
    int status = tlcgka_call(wire->b, wire->n, &out, &size);
    int match = !reason || (size >= strlen(reason) &&
        memcmp(out, reason, strlen(reason)) == 0);
    tlcgka_free(out, size);
    REQUIRE(status == 1 && match, "expected API rejection");
    REQUIRE(eq(wire, before), "rejected API request modified caller input");
}
/* Verify the revised Refresh composes with the paper's next Ratchet/Confirm,
 * using different contributor and confirmer, including a newly joined signer. */
static void round_after_refresh(V *states) {
    V *ids = keys(states), *source = A(ids, 0), *signer = A(ids, ids->n - 1),
      *s = need(states, source), *rho = HG("after-refresh", A(s, GEPOCH)),
      *enc = gua_enc(s, rho), *agg = gua_combine(s, L(L(source, L(A(enc, 1))))),
      *ctx = S("post-refresh"), *nonce = nonce_prepare(ctx, signer),
      *candidates = E, *shares = E;
    EACH(j, states) {
        V *id = A(A(states, j), 0), *state = A(A(states, j), 1),
          *recovered = gua_dec(state, A(agg, 0)),
          *candidate = gua_ratchet(state, eq(id, source) ? A(enc, 0) : Z,
              recovered, agg, L(signer), A(nonce, 3), eq(id, signer) ? nonce : Z, ctx, 0);
        set(candidates, id, A(candidate, 0));
        if (A(candidate, 1)->t != 'n') push(shares, A(candidate, 1));
    }
    V *reference = Z;
    EACH(j, states) {
        V *id = A(A(states, j), 0),
          *next = gua_confirm(A(A(states, j), 1), need(candidates, id), shares);
        REQUIRE(eq(base(A(next, SK)), need(A(next, ROSTER), id)), "next-round secret mismatch");
        if (reference->t == 'n') reference = next;
        REQUIRE(eq(A(next, KEY), A(reference, KEY)) && eq(A(next, ROSTER), A(reference, ROSTER)),
                "post-refresh Ratchet/Confirm diverged");
    }
}
static int opens(V *c, V *wire) {
    Arena *outer = arena, *probe = calloc(1, sizeof(*probe));
    if (!probe) abort();
    arena = probe; volatile int opened = 0;
    if (!setjmp(probe->trap)) {
        V *v = unpack(wire), *e = A(v, 1), *h = A(e, 0), *ct = A(e, 2),
          *src = need(A(c, C_SOURCES), A(h, 2)),
          *root = A(ub_dec(A(src, 0), L(h, ct), ct), 1);
        (void)open_seal(K("subgroup-envelope", root, L(h, ct)), A(v, 2), e);
        opened = 1;
    }
    release(probe); free(probe); arena = outer;
    return opened;
}
static void refresh_case(int remove) {
    V *states = gua_init(S("refresh-v4"), range(0, 4)), *s = need(states, N(0)),
      *old = anchor(s), *target = N(remove ? 3 : 9),
      *secret = remove ? A(need(states, target), SK) : scalar(),
      *pk = base(secret), *eta = random_bytes(32), *e = scalar(),
      *coins = L(e, eta, scalar(), scalar()), *ctx = L(S("test"), N(remove)),
      *result = refresh_change(s, S(remove ? "R" : "A"), target, pk, ctx, 0, coins),
      *wire = A(result, 0), *next = A(result, 1), *payload = A(unpack(wire), 0),
      *roster = A(next, ROSTER), *successors = E;
    set(successors, N(0), next);
    shape(payload, 9); blob(A(payload, 5), 32);
    REQUIRE(eq(A(payload, 5), base(e)), "GUA wire is not the single ephemeral public key");
    EACH(j, roster) {
        V *id = A(A(roster, j), 0), *previous = eq(id, N(0)) ? e :
            (eq(id, target) ? secret : A(need(states, id), SK)),
          *expected = smul(HS("refresh-ref", id, eta), previous);
        REQUIRE(eq(base(expected), need(roster, id)), "not every surviving key was refreshed");
        if (eq(id, N(0))) { REQUIRE(eq(expected, A(next, SK)), "issuer secret mismatch"); continue; }
        V *r = refresh_recover(old, id, previous, wire, ctx, 0);
        set(successors, id, r);
        REQUIRE(eq(A(r, SK), expected) && eq(A(r, ROSTER), roster) &&
                eq(A(r, KEY), A(next, KEY)) && eq(A(r, M), A(next, M)), "refresh agreement failed");
        V *rho = HG("refresh-test", id), *enc = gua_enc(next, rho);
        REQUIRE(eq(gua_dec(r, A(enc, 1)), rho), "post-refresh decryption failed");
    }
    round_after_refresh(successors);
    REQUIRE(eq(A(s, GEPOCH), N(0)), "refresh mutated predecessor");
    V *bad = unpack(wire), *sig = clone(A(bad, 1));
    put(sig, 1, scalar()); put(bad, 1, sig);
    rejects("refresh.recover", L(old, N(1), A(need(states, N(1)), SK), pack(bad), ctx, boolean(0)), NULL);
    rejects("refresh.recover", L(old, N(1), A(need(states, N(1)), SK), wire, S("wrong"), boolean(0)), NULL);
    if (remove)
        rejects("refresh.recover", L(old, target, secret, wire, ctx, boolean(0)), NULL);
}
static void refresh_add(void) { refresh_case(0); }
static void refresh_remove(void) { refresh_case(1); }

static void group_handoff(void) {
    V *g = group_balanced(16, 2, 2, S("handoff"), 0);
    for (int i = 0; i < 18; ++i) group_round(g, 1, 1, 1, 1);
}
static void staged_core_format(void) {
    V *g = group_balanced(16, 2, 2, S("core-stage"), 1), *m = membership_new(g),
      *x = need(A(g, 2), N(0)), *og = anchor(A(x, C_GLOBAL)), *ol = anchor(A(x, C_LOCAL)),
      *secrets = L(scalar(), scalar()), *old_state = pack(core_record(x)),
      *changed = change_core(m, N(0), S("A"), N(99), base(A(secrets, 0)), base(A(secrets, 1))),
      *wire = A(changed, 0), *v = unpack(wire), *body = A(v, 0);
    shape(v, 3); shape(body, 5); shape(A(body, 0), 8);
    shape(unpack(A(body, 1)), 9); shape(unpack(A(body, 2)), 9);
    REQUIRE(eq(old_state, pack(core_record(x))), "staging installed a core successor");
    V *sponsor = process_change(m, N(0), wire, og, ol, Z);
    EACH(j, A(g, 2)) {
        V *id = A(A(A(g, 2), j), 0), *r = process_change(m, id, wire, og, ol, Z);
        REQUIRE(eq(A(A(r, 0), ROSTER), A(A(sponsor, 0), ROSTER)), "global staged roster differs");
        if (A(r, 1)->t != 'n')
            REQUIRE(eq(A(A(r, 1), ROSTER), A(A(sponsor, 1), ROSTER)), "local staged roster differs");
    }
    V *join = process_change(m, N(99), wire, og, ol, secrets);
    REQUIRE(eq(A(A(join, 0), ROSTER), A(A(sponsor, 0), ROSTER)) &&
            eq(A(A(join, 1), ROSTER), A(A(sponsor, 1), ROSTER)), "joining core staged key mismatch");
    V *bad = unpack(wire), *sig = clone(A(bad, 2));
    put(sig, 1, scalar()); put(bad, 2, sig);
    rejects("membership.process", L(m, N(2), pack(bad), og, ol, Z), "local auth failed");
    /* Changing the public table invalidates both outer signatures. */
    bad = unpack(wire);
    set(A(A(bad, 0), 4), N(1), base(scalar()));
    rejects("membership.process", L(m, N(1), pack(bad), og, ol, Z), "global auth failed");
    rejects("membership.process", L(m, N(2), pack(bad), og, ol, Z), "local auth failed");
    /* Even an authenticated table must equal the local GUA result (Process 6). */
    put(bad, 1, sign(A(A(x, C_GLOBAL), SK), D("ChangeCore", A(bad, 0))));
    put(bad, 2, sign(A(A(x, C_LOCAL), SK), D("ChangeCore", A(bad, 0))));
    rejects("membership.process", L(m, N(1), pack(bad), og, ol, Z), "local refresh roster mismatch");
    rejects("membership.process", L(m, N(99), pack(bad), og, ol, secrets), "local refresh roster mismatch");
}
static void source_keys_match(V *g) {
    V *clients = cat(A(g, 2), A(g, 3));
    EACH(j, clients) {
        V *c = A(A(clients, j), 1), *sources = A(c, C_SOURCES);
        EACH(k, sources) {
            V *entry = A(sources, k), *owner = need(A(g, 2), A(entry, 0));
            REQUIRE(eq(A(A(entry, 1), 1), base(A(A(owner, C_LOCAL), SK))),
                    "receiver verification key differs from source signing key");
        }
    }
}
static void core_lifecycle(void) {
    V *g = group_balanced(24, 2, 3, S("revised-figure4"), 0), *m = membership_new(g);
    membership_update(m, 1);
    for (int cycle = 0; cycle < 2; ++cycle) {
        V *sponsor = N(cycle ? 12 : 0), *target = N(99 + cycle),
          *ordinary = need(A(g, 3), N(cycle ? 15 : 3)),
          *old_sources = clone(A(ordinary, C_SOURCES));
        membership_change(m, sponsor, S("A"), target);
        source_keys_match(g);
        EACH(j, old_sources) {
            V *entry = A(old_sources, j), *id = A(entry, 0);
            REQUIRE(!eq(A(A(entry, 1), 1), A(need(A(ordinary, C_SOURCES), id), 1)),
                    "existing core verification key was not refreshed");
            if (!eq(id, sponsor))
                REQUIRE(eq(A(A(entry, 1), 0), A(need(A(ordinary, C_SOURCES), id), 0)),
                        "key sync changed an unrelated receiver path");
        }
        rejects("membership.update", L(m, boolean(1)), "membership queues must be completed first");
        membership_drain(m);
        source_keys_match(g);
        /* Rotate through all local sources, including the joining core, with handoff. */
        for (int k = 0; k < 8; ++k) { group_round(g, 1, 1, 1, 1); source_keys_match(g); }
        membership_change(m, sponsor, S("R"), target);
        REQUIRE(get(A(g, 2), target)->t == 'n' && get(A(ordinary, C_SOURCES), target)->t == 'n',
                "removed core/source retained");
        source_keys_match(g);
        membership_drain(m);
        for (int k = 0; k < 6; ++k) { group_round(g, 1, 1, 1, 1); source_keys_match(g); }
    }
}
static void nonce_rejections(void) {
    V *ctx = L(S("nonce-test"), N(3)), *n = nonce_prepare(ctx, N(0)),
      *commit = nonce_commitment(n), *opening = nonce_opening(n),
      *R = nonce_aggregate(ctx, L(N(0)), L(commit), L(opening));
    REQUIRE(eq(R, A(n, 3)), "nonce aggregate mismatch");
    rejects("nonce.aggregate", L(S("wrong-context"), L(N(0)), L(commit), L(opening)), NULL);
    nonce_consume(n);
    rejects("nonce.consume", L(n), NULL);
    V *a = endpoint(random_bytes(32), S("test-channel"), N(0), N(1)),
      *b = endpoint(A(a, 0), A(a, 1), N(1), N(0)), *wire = endpoint_send(a, ctx);
    REQUIRE(eq(endpoint_receive(b, wire), ctx), "channel positive control");
    rejects("endpoint.receive", L(b, wire), "nonce channel replay");
}
static void ordinary_lifecycle(void) {
    V *g = group_balanced(16, 2, 2, S("ordinary-lifecycle"), 0), *m = membership_new(g);
    V *old_round = membership_update(m, 1), *past = need(A(old_round, 0), N(0)),
      *cores_before = E;
    EACH(j, A(g, 2)) {
        V *c = A(A(A(g, 2), j), 1);
        push(cores_before, pack(L(A(c, C_LOCAL), A(c, C_GLOBAL))));
    }
    V *nonce_before = pack(A(g, 4)), *other_core = pack(need(A(g, 2), N(8))),
      *other_ordinary = pack(need(A(g, 3), N(10))), *epoch_before = A(need(A(g, 2), N(0)), C_EPOCH);
    membership_change_ordinary(m, N(0), S("A"), N(99));
    REQUIRE(A(g, 2)->n == 4 && A(g, 3)->n == 13, "ordinary join changed core count");
    REQUIRE(eq(nonce_before, pack(A(g, 4))), "ordinary change unnecessarily rebuilt core nonce pool");
    REQUIRE(eq(other_core, pack(need(A(g, 2), N(8)))) &&
            eq(other_ordinary, pack(need(A(g, 3), N(10)))) &&
            eq(epoch_before, A(need(A(g, 3), N(99)), C_EPOCH)),
            "ordinary change touched another subgroup or advanced group epoch");
    EACH(j, A(g, 2)) {
        V *c = A(A(A(g, 2), j), 1);
        REQUIRE(eq(A(cores_before, j), pack(L(A(c, C_LOCAL), A(c, C_GLOBAL)))), "ordinary change modified GUA");
    }
    rejects("membership.update", L(m, boolean(1)), "membership queues");
    rejects("membership.change_ordinary", L(m, N(0), S("A"), N(98)), "operation/queue");
    membership_drain(m);
    V *joined = need(A(g, 3), N(99));
    REQUIRE(A(joined, C_LOCAL)->t == 'n' && A(joined, C_GLOBAL)->t == 'n' &&
            A(joined, C_TREE)->t == 'n' && A(joined, C_SOURCES)->n == 2, "ordinary became a core");
    REQUIRE(!opens(joined, past), "joiner decrypted a past envelope");
    V *pre_receive = clone(joined), *round = group_round(g, 1, 1, 1, 1),
      *wire = need(A(round, 0), N(0));
    REQUIRE(opens(pre_receive, wire), "valid path positive control failed");
    rejects("ordinary.receive", L(joined, wire), "replayed/out-of-order");
    V *bad = unpack(wire), *sig = clone(A(bad, 3));
    put(sig, 1, scalar()); put(bad, 3, sig);
    rejects("ordinary.receive", L(pre_receive, pack(bad)), NULL);
    V *revoked = clone(joined);
    membership_change_ordinary(m, N(1), S("R"), N(99)); membership_drain(m);
    for (int k = 0; k < 4; ++k) {
        round = group_round(g, 1, 1, 1, 1);
        REQUIRE(!opens(revoked, need(A(round, 0), N(0))), "removed member decrypted successor envelope");
    }
    EACH(j, A(g, 2)) {
        V *c = A(A(A(g, 2), j), 1);
        if (eq(A(c, C_SUB), N(0)))
            REQUIRE(get(A(A(c, C_TREE), 1), N(99))->t == 'n', "removed leaf retained");
    }
    /* Rejoin with a fresh channel, then change a different subgroup. */
    membership_change_ordinary(m, N(0), S("A"), N(99)); membership_drain(m); membership_update(m, 1);
    membership_change_ordinary(m, N(8), S("R"), N(10)); membership_drain(m); membership_update(m, 1);
    rejects("membership.change_ordinary", L(m, N(0), S("R"), N(1)), "target is not");
    rejects("membership.change_ordinary", L(m, N(0), S("R"), N(11)), "target is not");
    rejects("membership.change_ordinary", L(m, N(0), S("A"), N(99)), "identity already");
}
static void ordinary_boundary(void) {
    V *g = group_balanced(4, 2, 1, S("boundary"), 1), *m = membership_new(g);
    rejects("membership.change_ordinary", L(m, N(0), S("R"), N(1)), "cannot remove the last");
    membership_change_ordinary(m, N(0), S("A"), N(20)); membership_drain(m); membership_update(m, 1);
    membership_change_ordinary(m, N(0), S("R"), N(1)); membership_drain(m); membership_update(m, 1);
}
static void ordinary_control_rejections(void) {
    V *m = membership_new(group_balanced(16, 2, 2, S("ordinary-control"), 0)),
      *before = clone(m), *trace = membership_change_ordinary(m, N(0), S("A"), N(99)),
      *wire = A(A(trace, 0), 2), *candidate = process_ordinary(before, N(2), wire);
    REQUIRE(candidate->t != 'n', "ordinary control positive case failed");
    rejects("membership.process_ordinary", L(m, N(2), wire), "ordinary replay/context mismatch");
    V *bad = unpack(wire), *sig = clone(A(bad, 2));
    put(sig, 1, scalar()); put(bad, 2, sig);
    rejects("membership.process_ordinary", L(before, N(2), pack(bad)), "ordinary local auth failed");
    bad = unpack(wire); sig = clone(A(bad, 1));
    put(sig, 1, scalar()); put(bad, 1, sig);
    rejects("membership.process_ordinary", L(before, N(1), pack(bad)), "ordinary global auth failed");
    rejects("membership.process_ordinary", L(before, N(10), wire), "invalid ordinary sponsor/subgroup");
    bad = unpack(wire); put(A(A(bad, 0), 0), 8, N(98));
    rejects("membership.process_ordinary", L(before, N(2), pack(bad)), "ordinary local auth failed");
}
static void mixed_membership(void) {
    V *g = group_balanced(16, 1, 2, S("mixed-membership"), 0), *m = membership_new(g);
    membership_update(m, 1);
    membership_change_ordinary(m, N(0), S("A"), N(99)); membership_drain(m);
    membership_update(m, 1);
    membership_change(m, N(0), S("A"), N(100)); membership_drain(m);
    for (int k = 0; k < 4; ++k) { group_round(g, 1, 1, 1, 1); source_keys_match(g); }
    membership_change_ordinary(m, N(100), S("R"), N(99)); membership_drain(m);
    membership_update(m, 1);
    membership_change(m, N(0), S("R"), N(100)); membership_drain(m);
    membership_update(m, 1);
    membership_change_ordinary(m, N(1), S("A"), N(99)); membership_drain(m);
    for (int k = 0; k < 4; ++k) { group_round(g, 1, 1, 1, 1); source_keys_match(g); }
}
static int run(const char *name, void (*fn)(void)) {
    Arena *a = calloc(1, sizeof(*a)); if (!a) abort(); arena = a;
    int ok = !setjmp(a->trap);
    if (ok) fn(); else fprintf(stderr, "FAIL %s: %s\n", name, a->error);
    release(a); free(a); arena = NULL;
    if (ok) printf("PASS %s\n", name);
    return !ok;
}
int main(void) {
    if (sodium_init() < 0) return 2;
    int failures = 0;
    failures += run("refresh_add_all_member_keys", refresh_add);
    failures += run("refresh_remove_all_member_keys", refresh_remove);
    failures += run("handoff_and_nonce_window_rollover", group_handoff);
    failures += run("core_staging_preserves_paper_wire_format", staged_core_format);
    failures += run("core_join_leave_key_sync_and_subsequent_handoff", core_lifecycle);
    failures += run("nonce_and_channel_rejections", nonce_rejections);
    failures += run("ordinary_join_leave_isolation_and_rejections", ordinary_lifecycle);
    failures += run("single_core_subgroup_boundary", ordinary_boundary);
    failures += run("ordinary_control_tamper_replay_and_scope_rejections", ordinary_control_rejections);
    failures += run("mixed_core_and_ordinary_membership", mixed_membership);
    return failures ? 1 : 0;
}
