#ifndef TL_INTERNAL_H
#define TL_INTERNAL_H
#include "tlcgka.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <setjmp.h>
#include <stdio.h>
#include <limits.h>
typedef struct V V;
struct V {
    char t;
    uint64_t u;
    size_t n, capacity;
    unsigned char *b;
    V **v;
};
typedef struct Allocation {
    struct Allocation *next;
    size_t size;
} Allocation;
typedef struct {
    jmp_buf trap;
    Allocation *alloc;
    size_t used;
    const char *error;
} Arena;
extern _Thread_local Arena *arena;
void fail(const char *message);
void *mem(size_t n);
V *nil(void);
V *num(uint64_t n);
V *boolean(int n);
V *bytes(const void *p, size_t n);
V *str(const char *p);
V *list(size_t n, ...);
V *empty(void);
void push(V *v, V *x);
V *at_checked(V *v, size_t i, const char *file, int line);
void put(V *v, size_t i, V *x);
#define at(v, i) at_checked(v, i, __FILE__, __LINE__)
uint64_t integer(V *v);
int truth(V *v);
int eq(V *a, V *b);
int is(V *a, const char *s);
V *clone(V *v);
V *sort(V *v);
V *keys(V *m);
V *get(V *m, V *k);
V *need(V *m, V *k);
void set(V *m, V *k, V *v);
void del(V *m, V *k);
int contains(V *v, V *x);
V *without(V *v, V *x);
V *range(uint64_t start, uint64_t end);
V *cat(V *a, V *b);
V *pack(V *v);
V *unpack(V *v);
void shape(V *v, size_t n);
void blob(V *v, size_t n);
void canonical_ids(V *v, int nonempty);
#define L(...) list(sizeof((V *[]){__VA_ARGS__}) / sizeof(V *), __VA_ARGS__)
#define A(v, i) at(v, i)
#define N(n) num(n)
#define S(s) str(s)
#define Z nil()
#define E empty()
#define REQUIRE(c, m)                                                                              \
    do {                                                                                           \
        if (!(c))                                                                                  \
            fail(m);                                                                               \
    } while (0)
#define EACH(i, v) for (size_t i = 0; i < (v)->n; i++)
V *random_bytes(size_t n);
V *scalar(void);
V *sread(V *v);
V *sadd(V *a, V *b);
V *smul(V *a, V *b);
V *identity(void);
V *point(V *v, int nonzero);
V *base(V *s);
V *mul(V *s, V *p);
V *add(V *a, V *b);
V *sub(V *a, V *b);
V *total(V *v);
V *hash(V *v, int wide);
V *digest(const char *label, V *parts);
V *hs(const char *label, V *parts);
V *hg(const char *label, V *parts);
V *kdf(const char *label, V *parts);
#define D(label, ...) digest(label, L(__VA_ARGS__))
#define HS(label, ...) hs(label, L(__VA_ARGS__))
#define HG(label, ...) hg(label, L(__VA_ARGS__))
#define K(label, ...) kdf(label, L(__VA_ARGS__))
V *seal(V *key, V *plain, V *ad);
V *open_seal(V *key, V *wire, V *ad);
V *sign(V *sk, V *message);
int verify(V *pk, V *message, V *sig);
V *nike_gen(void);
V *nike_public(V *sk);
V *nike(V *sk, V *pk);
V *xor32(V *a, V *b);
/* GUA state: gid,member,epoch,sk,m,roster,pk,signature,key. */
enum { GID, MEMBER, GEPOCH, SK, M, ROSTER, PK, SIG, KEY };
V *gua_context(V *s);
V *gua_record(V *s);
V *keyagg(V *gid, V *roster);
V *challenge(V *m, V *r, V *pk);
V *gua_init(V *gid, V *members);
V *gua_enc(V *s, V *rho);
V *gua_combine(V *s, V *bundles);
V *gua_dec(V *s, V *ct);
V *nonce_prepare(V *ctx, V *member);
V *nonce_commitment(V *n);
V *nonce_opening(V *n);
V *nonce_consume(V *n);
void nonce_burn(V *n);
V *nonce_aggregate(V *ctx, V *ids, V *commits, V *opens);
V *gua_ratchet(V *s, V *u, V *rho, V *agg, V *f, V *r, V *nonce, V *ctx, int strict);
V *gua_confirm(V *s, V *cand, V *shares);
V *anchor(V *s);
V *anchor_tag(V *s);
V *refresh_change(V *s, V *op, V *target, V *pk, V *ctx, int outer, V *coins);
V *refresh_recover(V *old, V *member, V *sk, V *wire, V *ctx, int outer);
/* UB sender: public map,leaves map,epoch; receiver: leaf,private,epoch. */
V *path(V *leaf);
V *ub_gen(V *members);
V *ub_enc(V *sender);
V *ub_fin(V *intermediate, V *ad);
V *ub_dec(V *receiver, V *ad, V *ct);
V *ub_add(V *s, V *member);
V *ub_rmv(V *s, V *member);
V *ub_proc(V *r, V *wire);
V *ub_fork(V *s);
V *ub_proc_fork(V *r, V *wire);
/* Core fields; ordinary shares gid/subgroup/member/sources/epoch/key/history
 * using same slots (unused slots null), which keeps client transitions uniform. */
enum {
    C_GID,
    C_SUB,
    C_ID,
    C_LOCAL,
    C_GLOBAL,
    C_TREE,
    C_SOURCES,
    C_EPOCH,
    C_KEY,
    C_PENDING,
    C_A,
    C_B,
    C_NONCE,
    C_STRICT,
    C_HISTORY
};
enum { P_QL, P_LOCAL, P_THETA, P_SOURCE, P_EK, P_DK, P_U, P_CAND, P_J, P_WEIGHTS, P_QGS, P_SHARE };
V *local_gid(V *g, V *s);
V *global_gid(V *g);
V *core_record(V *c);
V *ordinary_record(V *c);
void configure(V *c, V *a, V *b);
V *header(V *c, V *source);
V *core_prepare(V *c);
V *takeover(V *c, V *ql);
V *core_share(V *c, V *ql, V *qgs, V *r);
V *core_commit(V *c, V *shares, int send);
void core_abort(V *c);
V *ordinary_receive(V *c, V *wire);
V *group_init(V *gid, V *roster, int strict, uint64_t window);
V *group_balanced(uint64_t n, uint64_t groups, uint64_t q, V *gid, int strict);
V *group_round(V *g, int rotate, int handoff, int deliver, int check);
V *prepare_nonces(V *g);
/* endpoint key,sid,owner,peer,tx,rx; client member,endpoint,pool,context;
 * server endpoints,members,context,commits,registry,opened,frozen,last_epoch;
 * session gid,version,window,batch,server,clients,context. */
V *endpoint(V *key, V *sid, V *owner, V *peer);
V *endpoint_send(V *e, V *value);
V *endpoint_receive(V *e, V *wire);
void client_clear(V *c);
V *client_prepare(V *c, V *ctx);
V *client_open(V *c);
V *client_accept(V *c, V *wire, V *binding, int selected);
V *server_new(void);
void server_begin(V *s, V *ctx, V *members);
void server_commit(V *s, V *member, V *wire);
void server_freeze(V *s);
void server_open(V *s, V *member, V *wire);
V *server_update(V *s, V *member, V *wire);
V *session_new(V *gid, V *members, uint64_t window);
void session_register(V *s, V *member);
void session_reconfigure(V *s, V *members, V *trace);
int session_ready(V *s, V *epoch);
void session_preprocess(V *s, V *start, V *roster, V *trace);
V *session_aggregate(V *s, V *binding, V *trace);
void sent(V *trace, const char *kind, V *source, V *wire, V *recipients);
/* Membership: group,channel keys,pending map,queue map,version. */
V *membership_new(V *g);
V *change_core(V *m, V *sponsor, V *op, V *target, V *pg, V *pl);
V *process_change(V *m, V *member, V *wire, V *og, V *ol, V *secrets);
V *membership_change(V *m, V *sponsor, V *op, V *target);
V *membership_change_ordinary(V *m, V *sponsor, V *op, V *target);
V *process_ordinary(V *m, V *member, V *wire);
V *membership_drain(V *m);
V *membership_update(V *m, int check);
V *private_deliver(V *channels, V *source, V *recipient, V *value, V *ctx, V *trace);
V *dispatch(V *request);
#endif
