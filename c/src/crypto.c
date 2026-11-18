#include "internal.h"
#include "sodium_abi.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
static const unsigned char order[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0x10};
V *random_bytes(size_t n) {
    V *r = bytes(NULL, n);
    randombytes_buf(r->b, n);
    return r;
}
V *identity(void) {
    return bytes(NULL, 32);
}
V *scalar(void) {
    V *r = identity();
    crypto_core_ristretto255_scalar_random(r->b);
    return r;
}
V *sread(V *v) {
    blob(v, 32);
    int less = 0;
    for (int i = 31; i >= 0; i--)
        if (v->b[i] != order[i]) {
            less = v->b[i] < order[i];
            break;
        }
    REQUIRE(less, "noncanonical scalar");
    return v;
}
V *sadd(V *a, V *b) {
    sread(a);
    sread(b);
    V *r = identity();
    crypto_core_ristretto255_scalar_add(r->b, a->b, b->b);
    return r;
}
V *smul(V *a, V *b) {
    sread(a);
    sread(b);
    V *r = identity();
    crypto_core_ristretto255_scalar_mul(r->b, a->b, b->b);
    return r;
}
V *point(V *v, int nonzero) {
    blob(v, 32);
    REQUIRE(crypto_core_ristretto255_is_valid_point(v->b), "invalid Ristretto255 point");
    REQUIRE(!nonzero || !eq(v, identity()), "identity point");
    return v;
}
V *base(V *s) {
    sread(s);
    V *r = identity();
    if (!eq(s, r))
        REQUIRE(!crypto_scalarmult_ristretto255_base(r->b, s->b), "base multiplication failed");
    return r;
}
V *mul(V *s, V *p) {
    sread(s);
    point(p, 0);
    V *r = identity();
    if (!eq(s, r) && !eq(p, r))
        REQUIRE(!crypto_scalarmult_ristretto255(r->b, s->b, p->b), "point multiplication failed");
    return r;
}
V *add(V *a, V *b) {
    point(a, 0);
    point(b, 0);
    V *r = identity();
    REQUIRE(!crypto_core_ristretto255_add(r->b, a->b, b->b), "point addition failed");
    return r;
}
V *sub(V *a, V *b) {
    point(a, 0);
    point(b, 0);
    V *r = identity();
    REQUIRE(!crypto_core_ristretto255_sub(r->b, a->b, b->b), "point subtraction failed");
    return r;
}
V *total(V *v) {
    V *r = identity();
    EACH(i, v) r = add(r, A(v, i));
    return r;
}
V *hash(V *v, int wide) {
    V *p = pack(v), *r = bytes(NULL, wide ? 64 : 32);
    if (wide)
        SHA512(p->b, p->n, r->b);
    else
        SHA256(p->b, p->n, r->b);
    return r;
}
V *digest(const char *label, V *parts) {
    return hash(L(S("TL-CGKA/v1"), S(label), parts), 0);
}
V *hs(const char *label, V *parts) {
    for (uint64_t counter = 0;; counter++) {
        V *h = hash(L(S("TL-CGKA/v1"), S(label), parts, N(counter)), 1), *r = identity();
        crypto_core_ristretto255_scalar_reduce(r->b, h->b);
        if (!eq(r, identity()))
            return r;
    }
}
V *hg(const char *label, V *parts) {
    V *h = hash(L(S("TL-CGKA/v1"), S(label), parts), 1), *r = identity();
    REQUIRE(!crypto_core_ristretto255_from_hash(r->b, h->b), "hash-to-group failed");
    return r;
}
V *kdf(const char *label, V *parts) {
    V *ikm = pack(parts), *info = pack(L(S("TL-CGKA/v1"), S(label))), *prk = identity(),
      *r = identity();
    unsigned n = 0;
    unsigned char zero[32] = {0};
    REQUIRE(HMAC(EVP_sha256(), zero, 32, ikm->b, ikm->n, prk->b, &n) && n == 32,
            "HKDF extract failed");
    unsigned char *data = mem(info->n + 1);
    memcpy(data, info->b, info->n);
    data[info->n] = 1;
    REQUIRE(HMAC(EVP_sha256(), prk->b, 32, data, info->n + 1, r->b, &n) && n == 32,
            "HKDF expand failed");
    return r;
}
V *seal(V *key, V *plain, V *ad) {
    REQUIRE(key->t == 'b' && key->n >= 16 && plain->t == 'b' && plain->n <= INT_MAX - 28,
            "invalid AES input");
    V *aad = pack(ad), *r = bytes(NULL, 12 + plain->n + 16);
    randombytes_buf(r->b, 12);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    REQUIRE(ctx, "AES allocation failed");
    int l = 0, n = 0;
    int ok = EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key->b, r->b) &&
             EVP_EncryptUpdate(ctx, NULL, &l, aad->b, (int)aad->n) &&
             EVP_EncryptUpdate(ctx, r->b + 12, &n, plain->b, (int)plain->n) &&
             EVP_EncryptFinal_ex(ctx, r->b + 12 + n, &l) &&
             EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, r->b + 12 + plain->n);
    EVP_CIPHER_CTX_free(ctx);
    REQUIRE(ok, "AES encryption failed");
    return r;
}
V *open_seal(V *key, V *wire, V *ad) {
    REQUIRE(key->t == 'b' && key->n >= 16 && wire->t == 'b' && wire->n >= 28 && wire->n <= INT_MAX,
            "truncated AES ciphertext");
    V *aad = pack(ad), *r = bytes(NULL, wire->n - 28);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    REQUIRE(ctx, "AES allocation failed");
    int n = 0, l = 0;
    int ok = EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key->b, wire->b) &&
             EVP_DecryptUpdate(ctx, NULL, &l, aad->b, (int)aad->n) &&
             EVP_DecryptUpdate(ctx, r->b, &n, wire->b + 12, (int)r->n) &&
             EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, wire->b + wire->n - 16) &&
             EVP_DecryptFinal_ex(ctx, r->b + n, &l);
    EVP_CIPHER_CTX_free(ctx);
    REQUIRE(ok, "AEAD authentication failed");
    return r;
}
V *sign(V *sk, V *message) {
    V *r = scalar(), *R = base(r), *pk = base(sk);
    return L(R, sadd(r, smul(HS("signature", R, pk, message), sk)));
}
int verify(V *pk, V *message, V *sig) {
    if (!sig || sig->t != 'l' || sig->n != 2)
        return 0;
    V *r = A(sig, 0), *z = A(sig, 1);
    point(r, 1);
    sread(z);
    return eq(base(z), add(r, mul(HS("signature", r, pk, message), pk)));
}
V *nike_public(V *sk) {
    blob(sk, 32);
    V *r = identity();
    REQUIRE(!crypto_scalarmult_curve25519_base(r->b, sk->b), "X25519 public failed");
    return r;
}
V *nike_gen(void) {
    V *sk = random_bytes(32);
    sk->b[0] &= 248;
    sk->b[31] &= 127;
    sk->b[31] |= 64;
    return L(sk, nike_public(sk));
}
V *nike(V *sk, V *pk) {
    blob(sk, 32);
    blob(pk, 32);
    V *r = identity();
    REQUIRE(!crypto_scalarmult_curve25519(r->b, sk->b, pk->b), "invalid X25519 key/shared secret");
    return r;
}
V *xor32(V *a, V *b) {
    blob(a, 32);
    blob(b, 32);
    V *r = identity();
    for (size_t i = 0; i < 32; i++)
        r->b[i] = a->b[i] ^ b->b[i];
    return r;
}
