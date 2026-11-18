#ifndef TL_SODIUM_ABI_H
#define TL_SODIUM_ABI_H
/* Stable public libsodium ABI used by the Python reference too. Kept here
 * so systems with libsodium.so.23 but no development headers can build.
 * These are declarations only, not replacement cryptographic code. */
#include <stddef.h>
int sodium_init(void);
void sodium_memzero(void *, size_t);
int sodium_memcmp(const void *, const void *, size_t);
void randombytes_buf(void *, size_t);
int crypto_core_ristretto255_is_valid_point(const unsigned char *);
int crypto_core_ristretto255_add(unsigned char *, const unsigned char *, const unsigned char *);
int crypto_core_ristretto255_sub(unsigned char *, const unsigned char *, const unsigned char *);
int crypto_core_ristretto255_from_hash(unsigned char *, const unsigned char *);
void crypto_core_ristretto255_scalar_random(unsigned char *);
void crypto_core_ristretto255_scalar_reduce(unsigned char *, const unsigned char *);
void crypto_core_ristretto255_scalar_add(unsigned char *, const unsigned char *,
                                         const unsigned char *);
void crypto_core_ristretto255_scalar_mul(unsigned char *, const unsigned char *,
                                         const unsigned char *);
int crypto_scalarmult_ristretto255(unsigned char *, const unsigned char *, const unsigned char *);
int crypto_scalarmult_ristretto255_base(unsigned char *, const unsigned char *);
int crypto_scalarmult_curve25519(unsigned char *, const unsigned char *, const unsigned char *);
int crypto_scalarmult_curve25519_base(unsigned char *, const unsigned char *);
#endif
