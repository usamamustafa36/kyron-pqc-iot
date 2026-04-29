#ifndef PQCLEAN_MLDSA44_CLEAN_API_H
#define PQCLEAN_MLDSA44_CLEAN_API_H

#include <stddef.h>
#include <stdint.h>

/* Base constants */
#define CRYPTO_PUBLICKEYBYTES 1312
#define CRYPTO_SECRETKEYBYTES 2560
#define CRYPTO_BYTES          2420

/* PQClean-prefixed compatibility macros */
#define PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES  CRYPTO_PUBLICKEYBYTES
#define PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES  CRYPTO_SECRETKEYBYTES
#define PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES           CRYPTO_BYTES

/* Function prototypes */
int PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen,
                                                const uint8_t *m, size_t mlen,
                                                const uint8_t *sk);
int PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen,
                                             const uint8_t *m, size_t mlen,
                                             const uint8_t *pk);

#endif /* PQCLEAN_MLDSA44_CLEAN_API_H */

