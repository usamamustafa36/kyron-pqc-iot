#ifndef DILITHIUM_API_H
#define DILITHIUM_API_H

#include <stddef.h>
#include <stdint.h>
#include "PQCLEAN_MLDSA44_CLEAN_api.h"
void dilithium_test_randombytes(void);

/* Public macros from PQClean */
#define DILITHIUM_PUBLIC_KEY_BYTES  CRYPTO_PUBLICKEYBYTES
#define DILITHIUM_SECRET_KEY_BYTES  CRYPTO_SECRETKEYBYTES
#define DILITHIUM_SIGNATURE_BYTES   CRYPTO_BYTES

/* ====== SDK API ====== */
int dilithium_keygen(void);
int dilithium_sign(const uint8_t *message, size_t message_len);
int dilithium_verify(const uint8_t *message, size_t message_len);
int dilithium_verify_with_pk(const uint8_t *sig, size_t siglen, const uint8_t *msg, size_t mlen, const uint8_t *pk);

/* Clear session keys (DB + RAM) */
int dilithium_clear_session(void);

/* ====== Getters ====== */
const uint8_t *dilithium_get_pk(void);
const uint8_t *dilithium_get_sk(void);
const uint8_t *dilithium_get_sig(void);
size_t         dilithium_get_siglen(void);

#endif /* DILITHIUM_API_H */

