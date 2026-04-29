#ifndef PQC_TEST_WRAPPER_H
#define PQC_TEST_WRAPPER_H

#include <stdint.h>
#include <stddef.h>
#include "kyber_api.h"
#include "dilithium_api.h"
#include "ascon_api.h"

#define PQC_MAX_BUFFER 16384

// Wrapper init
int pqc_init_wrapper(void);

// Ciphertext access
const uint8_t* pqc_get_ciphertext(void);
unsigned long long pqc_get_ciphertext_len(void);
void pqc_load_ciphertext(const uint8_t *ct, unsigned long long ct_len);

// Kyber
int pqc_kyber_keypair(uint8_t *pk, uint8_t *sk);
int pqc_kyber_encapsulate(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqc_kyber_decapsulate(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

// Dilithium
int pqc_dilithium_keypair(void);
int pqc_dilithium_sign(const uint8_t *message, size_t message_len);
int pqc_dilithium_verify(const uint8_t *message, size_t message_len);
int pqc_dilithium_verify_with_pk(const uint8_t *sig, size_t siglen,
                                 const uint8_t *msg, size_t mlen,
                                 const uint8_t *pk);
const uint8_t *pqc_dilithium_get_pk(void);
const uint8_t *pqc_dilithium_get_sk(void);
const uint8_t *pqc_dilithium_get_sig(void);
size_t pqc_dilithium_get_siglen(void);

// Ascon
int pqc_ascon_encrypt(uint8_t *ciphertext, unsigned long long *ciphertext_len,
                      const uint8_t *plaintext, unsigned long long plaintext_len,
                      const uint8_t *ad, unsigned long long ad_len,
                      const uint8_t *nonce, const uint8_t *key);

int pqc_ascon_decrypt(uint8_t *plaintext, unsigned long long *plaintext_len,
                      const uint8_t *ciphertext, unsigned long long ciphertext_len,
                      const uint8_t *ad, unsigned long long ad_len,
                      const uint8_t *nonce, const uint8_t *key);

int pqc_ascon_encrypt_full_message(uint8_t *ciphertext, unsigned long long *ciphertext_len,
                                   const uint8_t *message, size_t msg_len,
                                   const uint8_t *signature, size_t sig_len,
                                   const uint8_t *nonce, const uint8_t *key);

int pqc_ascon_decrypt_full_message(uint8_t *message, unsigned long long *msg_len,
                                   uint8_t *signature, size_t sig_len,
                                   const uint8_t *ciphertext,
                                   unsigned long long ciphertext_len,
                                   const uint8_t *nonce,
                                   const uint8_t *key);
// Dilithium sign + verify helpers for chat
int pqc_sign_message(const uint8_t *msg, size_t msg_len,
                     uint8_t *signature, size_t *sig_len);

int pqc_verify_message(const uint8_t *msg, size_t msg_len,
                       const uint8_t *signature, size_t sig_len,
                       const uint8_t *pk);

#endif // PQC_TEST_WRAPPER_H

