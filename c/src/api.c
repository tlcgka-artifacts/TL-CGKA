#include "internal.h"
#include "sodium_abi.h"
static const char *label(V *v) {
    REQUIRE(v->t == 's' && v->n < 256, "invalid label");
    char *p = mem(v->n + 1);
    memcpy(p, v->b, v->n);
    return p;
}
static V *mut(V *state, V *result) {
    return L(state, result);
}
V *dispatch(V *request) {
    shape(request, 2);
    V *op = A(request, 0), *a = A(request, 1);
    REQUIRE(a->t == 'l', "invalid arguments");
#define OP(s) if (is(op, s))
#define X(i) A(a, i)
    OP("codec.pack") return pack(X(0));
    OP("codec.unpack") return unpack(X(0));
    OP("crypto.scalar") return scalar();
    OP("crypto.scalar_read") return sread(X(0));
    OP("crypto.base") return base(X(0));
    OP("crypto.mul") return mul(X(0), X(1));
    OP("crypto.add") return add(X(0), X(1));
    OP("crypto.sub") return sub(X(0), X(1));
    OP("crypto.point") return point(X(0), truth(X(1)));
    OP("crypto.total") return total(X(0));
    OP("crypto.digest") return digest(label(X(0)), X(1));
    OP("crypto.hscalar") return hs(label(X(0)), X(1));
    OP("crypto.hgroup") return hg(label(X(0)), X(1));
    OP("crypto.kdf") return kdf(label(X(0)), X(1));
    OP("crypto.sign") return sign(X(0), X(1));
    OP("crypto.verify") return boolean(verify(X(0), X(1), X(2)));
    OP("crypto.seal") return seal(X(0), X(1), X(2));
    OP("crypto.open_seal") return open_seal(X(0), X(1), X(2));
    OP("crypto.nike_gen") return nike_gen();
    OP("crypto.nike_public") return nike_public(X(0));
    OP("crypto.nike") return nike(X(0), X(1));
    OP("gua.init") return gua_init(X(0), X(1));
    OP("gua.keyagg") return keyagg(X(0), X(1));
    OP("gua.enc") return gua_enc(X(0), X(1));
    OP("gua.combine") return gua_combine(X(0), X(1));
    OP("gua.dec") return gua_dec(X(0), X(1));
    OP("gua.ratchet") {
        V *r = gua_ratchet(X(0), X(1), X(2), X(3), X(4), X(5), X(6), X(7), truth(X(8)));
        return L(r, X(6));
    }
    OP("gua.confirm") return gua_confirm(X(0), X(1), X(2));
    OP("nonce.prepare") return nonce_prepare(X(0), X(1));
    OP("nonce.commitment") return nonce_commitment(X(0));
    OP("nonce.opening") return nonce_opening(X(0));
    OP("nonce.consume") {
        V *r = nonce_consume(X(0));
        return mut(X(0), r);
    }
    OP("nonce.burn") {
        nonce_burn(X(0));
        return mut(X(0), Z);
    }
    OP("nonce.aggregate") return nonce_aggregate(X(0), X(1), X(2), X(3));
    OP("refresh.change") return refresh_change(X(0), X(1), X(2), X(3), X(4), truth(X(5)), X(6));
    OP("refresh.recover") return refresh_recover(X(0), X(1), X(2), X(3), X(4), truth(X(5)));
    OP("ub.gen") return ub_gen(X(0));
    OP("ub.enc") return ub_enc(X(0));
    OP("ub.fin") return ub_fin(X(0), X(1));
    OP("ub.dec") return ub_dec(X(0), X(1), X(2));
    OP("ub.add") return ub_add(X(0), X(1));
    OP("ub.rmv") return ub_rmv(X(0), X(1));
    OP("ub.proc") return ub_proc(X(0), X(1));
    OP("ub.fork") return ub_fork(X(0));
    OP("ub.proc_fork") return ub_proc_fork(X(0), X(1));
    OP("core.configure") {
        configure(X(0), X(1), X(2));
        return mut(X(0), Z);
    }
    OP("core.prepare") {
        V *r = core_prepare(X(0));
        return mut(X(0), r);
    }
    OP("core.takeover") {
        V *r = takeover(X(0), X(1));
        return mut(X(0), r);
    }
    OP("core.share") {
        V *r = core_share(X(0), X(1), X(2), X(3));
        return mut(X(0), r);
    }
    OP("core.commit") {
        V *r = core_commit(X(0), X(1), truth(X(2)));
        return mut(X(0), r);
    }
    OP("core.abort") {
        core_abort(X(0));
        return mut(X(0), Z);
    }
    OP("core.nonce_prepare") {
        V *c = X(0);
        REQUIRE(contains(A(c, C_B), A(c, C_ID)) && A(c, C_NONCE)->t == 'n',
                "unexpected/repeated nonce preparation");
        V *n = nonce_prepare(L(gua_context(A(c, C_GLOBAL)), A(c, C_A), A(c, C_B)), A(c, C_ID));
        put(c, C_NONCE, n);
        return mut(c, pack(nonce_commitment(n)));
    }
    OP("core.nonce_open") {
        REQUIRE(A(X(0), C_NONCE)->t != 'n', "nonce was not committed");
        return pack(nonce_opening(A(X(0), C_NONCE)));
    }
    OP("ordinary.receive") {
        V *r = ordinary_receive(X(0), X(1));
        return mut(X(0), r);
    }
    OP("group.init") return group_init(X(0), X(1), truth(X(2)), integer(X(3)));
    OP("group.balanced")
    return group_balanced(integer(X(0)), integer(X(1)), integer(X(2)), X(3), truth(X(4)));
    OP("group.round") {
        V *r = group_round(X(0), truth(X(1)), truth(X(2)), truth(X(3)), truth(X(4)));
        return mut(X(0), r);
    }
    OP("group.preprocess") {
        V *r = prepare_nonces(X(0));
        return mut(X(0), r);
    }
    OP("endpoint.send") {
        V *r = endpoint_send(X(0), X(1));
        return mut(X(0), r);
    }
    OP("endpoint.receive") {
        V *r = endpoint_receive(X(0), X(1));
        return mut(X(0), r);
    }
    OP("client.prepare") {
        V *r = client_prepare(X(0), X(1));
        return mut(X(0), r);
    }
    OP("client.open") {
        V *r = client_open(X(0));
        return mut(X(0), r);
    }
    OP("client.accept") {
        V *r = client_accept(X(0), X(1), X(2), truth(X(3)));
        return mut(X(0), r);
    }
    OP("client.clear") {
        client_clear(X(0));
        return mut(X(0), Z);
    }
    OP("server.begin") {
        server_begin(X(0), X(1), X(2));
        return mut(X(0), Z);
    }
    OP("server.commit") {
        server_commit(X(0), X(1), X(2));
        return mut(X(0), Z);
    }
    OP("server.freeze") {
        server_freeze(X(0));
        return mut(X(0), Z);
    }
    OP("server.open") {
        server_open(X(0), X(1), X(2));
        return mut(X(0), Z);
    }
    OP("server.update") {
        V *r = server_update(X(0), X(1), X(2));
        return mut(X(0), r);
    }
    OP("session.new") return session_new(X(0), X(1), integer(X(2)));
    OP("session.register") {
        session_register(X(0), X(1));
        return mut(X(0), Z);
    }
    OP("session.reconfigure") {
        V *trace = E;
        session_reconfigure(X(0), X(1), trace);
        return mut(X(0), trace);
    }
    OP("session.ready") return boolean(session_ready(X(0), X(1)));
    OP("session.preprocess") {
        V *trace = E;
        session_preprocess(X(0), X(1), X(2), trace);
        return mut(X(0), trace);
    }
    OP("session.aggregate") {
        V *trace = E, *r = session_aggregate(X(0), X(1), trace);
        return mut(X(0), L(r, trace));
    }
    OP("membership.new") return membership_new(X(0));
    OP("membership.change_core") {
        V *r = change_core(X(0), X(1), X(2), X(3), X(4), X(5));
        return mut(X(0), r);
    }
    OP("membership.process") return process_change(X(0), X(1), X(2), X(3), X(4), X(5));
    OP("membership.process_ordinary") return process_ordinary(X(0), X(1), X(2));
    OP("membership.change") {
        V *r = membership_change(X(0), X(1), X(2), X(3));
        return mut(X(0), r);
    }
    OP("membership.drain") {
        V *r = membership_drain(X(0));
        return mut(X(0), r);
    }
    OP("membership.change_ordinary") {
        V *r = membership_change_ordinary(X(0), X(1), X(2), X(3));
        return mut(X(0), r);
    }
    OP("membership.update") {
        V *r = membership_update(X(0), truth(X(1)));
        return mut(X(0), r);
    }
    OP("channels.deliver") {
        V *trace = E, *r = private_deliver(X(0), X(1), X(2), X(3), X(4), trace);
        return L(r, trace);
    }
    /* Standalone CLI keeps only serialized state between operations. */
    OP("demo.init")
    return membership_new(group_balanced(integer(X(0)), integer(X(1)), integer(X(2)),
                                         bytes("tl-cgka-experiment", 18), 1));
    OP("demo.round") {
        membership_update(X(0), 1);
        return X(0);
    }
    OP("demo.add") {
        V *g = A(X(0), 0), *ids = cat(keys(A(g, 2)), keys(A(g, 3)));
        ids = sort(ids);
        membership_change(X(0), A(A(A(g, 2), 0), 0), S("A"), N(integer(A(ids, ids->n - 1)) + 1));
        membership_drain(X(0));
        return X(0);
    }
    OP("demo.remove") {
        V *g = A(X(0), 0), *ids = A(A(A(g, 1), 0), 0);
        REQUIRE(ids->n > 1, "need two cores");
        membership_change(X(0), A(ids, 0), S("R"), A(ids, 1));
        membership_drain(X(0));
        return X(0);
    }
    OP("demo.add_ordinary") {
        V *g = A(X(0), 0), *ids = sort(cat(keys(A(g, 2)), keys(A(g, 3))));
        membership_change_ordinary(X(0), A(A(A(g, 2), 0), 0), S("A"),
                                   N(integer(A(ids, ids->n - 1)) + 1));
        membership_drain(X(0));
        return X(0);
    }
    OP("demo.remove_ordinary") {
        V *g = A(X(0), 0), *roster = A(A(g, 1), 0), *users = A(roster, 1);
        REQUIRE(users->n > 0, "need an ordinary member");
        membership_change_ordinary(X(0), A(A(roster, 0), 0), S("R"), A(users, users->n - 1));
        membership_drain(X(0));
        return X(0);
    }
    OP("demo.result") {
        V *g = A(X(0), 0), *c = A(A(A(g, 2), 0), 1);
        return L(A(c, C_EPOCH), A(c, C_HISTORY), N(A(g, 2)->n + A(g, 3)->n));
    }
    fail("unknown operation");
    return Z;
#undef X
#undef OP
}
const char *tlcgka_version(void) {
    return "TL-CGKA C 2.2";
}
void tlcgka_free(void *p, size_t n) {
    if (p) {
        sodium_memzero(p, n);
        free(p);
    }
}
int tlcgka_call(const unsigned char *input, size_t length, unsigned char **output, size_t *outlen) {
    if (!output || !outlen)
        return -1;
    *output = NULL;
    *outlen = 0;
    if (!input || length > 64 * 1024 * 1024 || sodium_init() < 0)
        return -1;
    Arena *previous = arena, *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return -1;
    arena = ctx;
    int status = 0;
    V *encoded = NULL;
    if (setjmp(ctx->trap)) {
        status = 1;
    } else
        encoded = pack(dispatch(unpack(bytes(input, length))));
    const unsigned char *data = status ? (const unsigned char *)ctx->error : encoded->b;
    size_t n = status ? strlen(ctx->error) : encoded->n;
    unsigned char *result = malloc(n ? n : 1);
    if (result) {
        memcpy(result, data, n);
        *output = result;
        *outlen = n;
    } else
        status = -1;
    Allocation *p = ctx->alloc;
    while (p) {
        Allocation *next = p->next;
        sodium_memzero(p + 1, p->size);
        free(p);
        p = next;
    }
    sodium_memzero(ctx, sizeof(*ctx));
    free(ctx);
    arena = previous;
    return status;
}
