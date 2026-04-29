#include "pqc_test_wrapper.h"
#include "randombytes.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// ===== Static buffers =====
static uint8_t pqc_send_buffer[PQC_MAX_BUFFER];
static uint8_t pqc_recv_buffer[PQC_MAX_BUFFER];

// ===== Ciphertext buffer (private) =====
static uint8_t g_ct_buf[PQC_MAX_BUFFER];
static unsigned long long g_ct_len = 0;

// Wrapper-managed key
static uint8_t g_ascon_key[ASCON_KEY_BYTES];

// ===== Init wrapper =====
int pqc_init_wrapper(void) {
    randombytes(g_ascon_key, ASCON_KEY_BYTES);
    return 0;
}

// ===== Ciphertext buffer access =====
const uint8_t* pqc_get_ciphertext(void) {
    return g_ct_buf;
}

unsigned long long pqc_get_ciphertext_len(void) {
    return g_ct_len;
}

void pqc_load_ciphertext(const uint8_t *ct, unsigned long long ct_len) {
    if (!ct) return;
    if (ct_len > PQC_MAX_BUFFER) ct_len = PQC_MAX_BUFFER;
    memcpy(g_ct_buf, ct, ct_len);
    g_ct_len = ct_len;
}

// ===== Kyber =====
int pqc_kyber_keypair(uint8_t *pk, uint8_t *sk) {
    int ret = kyber_generate_keypair(pqc_send_buffer, pqc_recv_buffer);
    if (ret == 0) {
        memcpy(pk, pqc_send_buffer, KYBER_PUBLIC_KEY_BYTES);
        memcpy(sk, pqc_recv_buffer, KYBER_SECRET_KEY_BYTES);
    }
    return ret;
}

int pqc_kyber_encapsulate(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    int ret = kyber_encapsulate(pqc_send_buffer, pqc_recv_buffer, pk);
    if (ret == 0) {
        memcpy(ct, pqc_send_buffer, KYBER_CIPHERTEXT_BYTES);
        memcpy(ss, pqc_recv_buffer, KYBER_SHARED_SECRET_BYTES);
    }
    return ret;
}

int pqc_kyber_decapsulate(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    int ret = kyber_decapsulate(pqc_recv_buffer, ct, sk);
    if (ret == 0) {
        memcpy(ss, pqc_recv_buffer, KYBER_SHARED_SECRET_BYTES);
    }
    return ret;
}

// ===== Dilithium =====
int pqc_dilithium_keypair(void) { return dilithium_keygen(); }
int pqc_dilithium_sign(const uint8_t *message, size_t message_len) { return dilithium_sign(message, message_len); }
int pqc_dilithium_verify(const uint8_t *message, size_t message_len) { return dilithium_verify(message, message_len); }
int pqc_dilithium_verify_with_pk(const uint8_t *sig, size_t siglen,
                                 const uint8_t *msg, size_t mlen,
                                 const uint8_t *pk) { return dilithium_verify_with_pk(sig, siglen, msg, mlen, pk); }

const uint8_t *pqc_dilithium_get_pk(void) { return dilithium_get_pk(); }
const uint8_t *pqc_dilithium_get_sk(void) { return dilithium_get_sk(); }
const uint8_t *pqc_dilithium_get_sig(void) { return dilithium_get_sig(); }
size_t pqc_dilithium_get_siglen(void) { return dilithium_get_siglen(); }

// ===== Ascon wrappers =====
int pqc_ascon_encrypt(uint8_t *ciphertext, unsigned long long *ciphertext_len,
                      const uint8_t *plaintext, unsigned long long plaintext_len,
                      const uint8_t *ad, unsigned long long ad_len,
                      const uint8_t *nonce, const uint8_t *key) {
    return ascon_encrypt(ciphertext, ciphertext_len, plaintext, plaintext_len,
                         ad, ad_len, nonce, key);
}

int pqc_ascon_decrypt(uint8_t *plaintext, unsigned long long *plaintext_len,
                      const uint8_t *ciphertext, unsigned long long ciphertext_len,
                      const uint8_t *ad, unsigned long long ad_len,
                      const uint8_t *nonce, const uint8_t *key) {
    return ascon_decrypt(plaintext, plaintext_len, ciphertext, ciphertext_len,
                         ad, ad_len, nonce, key);
}

// ===== Full message encryption (message + signature) =====
int pqc_ascon_encrypt_full_message(uint8_t *ciphertext, unsigned long long *ciphertext_len,
                                   const uint8_t *message, size_t msg_len,
                                   const uint8_t *signature, size_t sig_len,
                                   const uint8_t *nonce, const uint8_t *key)
{
    if (!ciphertext || !ciphertext_len || !message || !key || !nonce) return -1;

    uint8_t temp[PQC_MAX_BUFFER];
    if (msg_len + sig_len > PQC_MAX_BUFFER) return -1;

    memcpy(temp, message, msg_len);
    if (signature && sig_len > 0) memcpy(temp + msg_len, signature, sig_len);

    unsigned long long total_len = 0;
    int ret = pqc_ascon_encrypt(ciphertext, &total_len,
                                temp, msg_len + sig_len,
                                NULL, 0,
                                nonce, key);
    if (ret != 0) return -1;

    *ciphertext_len = total_len;
    return 0;
}

// ===== Full message decryption =====
int pqc_ascon_decrypt_full_message(uint8_t *message, unsigned long long *msg_len,
                                   uint8_t *signature, size_t sig_len,
                                   const uint8_t *ciphertext,
                                   unsigned long long ciphertext_len,
                                   const uint8_t *nonce,
                                   const uint8_t *key)
{
    if (!message || !ciphertext || !key || !nonce) return -1;

    uint8_t temp[PQC_MAX_BUFFER];
    unsigned long long decrypted_total = 0;

    int ret = pqc_ascon_decrypt(temp, &decrypted_total,
                                ciphertext, ciphertext_len,
                                NULL, 0,
                                nonce, key);
    if (ret != 0) return -1;

    if (decrypted_total < sig_len) return -1;

    memcpy(message, temp, decrypted_total - sig_len);
    *msg_len = decrypted_total - sig_len;

    if (signature && sig_len > 0) {
        memcpy(signature, temp + decrypted_total - sig_len, sig_len);
    }

    return 0;
}
int pqc_sign_message(const uint8_t *msg, size_t msg_len,
                     uint8_t *signature, size_t *sig_len)
{
    if (!msg || !signature || !sig_len) return -1;
    int ret = pqc_dilithium_sign(msg, msg_len);
    if (ret != 0) return ret;
    const uint8_t *sig = pqc_dilithium_get_sig();
    size_t len = pqc_dilithium_get_siglen();
    memcpy(signature, sig, len);
    *sig_len = len;
    return 0;
}

int pqc_verify_message(const uint8_t *msg, size_t msg_len,
                       const uint8_t *signature, size_t sig_len,
                       const uint8_t *pk)
{
    if (!msg || !signature || !pk) return -1;
    return pqc_dilithium_verify_with_pk(signature, sig_len, msg, msg_len, pk);
}

