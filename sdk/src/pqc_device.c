#include "pqc_device.h"
#include "pqc_test_wrapper.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "randombytes.h"

// Internal buffers for ciphertext and decrypted messages
static uint8_t g_ct_buf[PQC_MAX_BUFFER];
static unsigned long long g_ct_len = 0;
static uint8_t g_recv_buf[PQC_MAX_BUFFER];
static size_t decrypted_len = 0;
static uint8_t g_sig_buf[PQC_MAX_BUFFER];  // buffer to store signature separately
static size_t g_sig_len = 0;
// Ascon key (nonce now passed explicitly in API)
static uint8_t g_ascon_key[ASCON_KEY_BYTES];

// ===== Initialization =====
int pqc_init(void) {
    randombytes(g_ascon_key, ASCON_KEY_BYTES);
    g_ct_len = 0;
    decrypted_len = 0;
    return pqc_init_wrapper(); // initialize wrapper internal state
}
const uint8_t *pqc_get_ciphertext_buffer(void) {
    return g_ct_buf;
}

unsigned long long pqc_get_ciphertext_length(void) {
    return g_ct_len;
}

// ===== Encrypt a message =====
// Outputs:
// - g_ct_buf: stores ciphertext internally
// - g_ct_len: stores ciphertext length
// - nonce_out: must be provided by caller, filled with generated nonce
int pqc_encrypt_message(const uint8_t *msg, size_t msg_len,
                        uint8_t *nonce_out)
{
    if (!nonce_out) return -1;

    size_t sig_len = pqc_dilithium_get_siglen();
    const uint8_t *sig_ptr = pqc_dilithium_get_sig();

    // Generate a random nonce for this encryption
    randombytes(nonce_out, ASCON_NONCE_BYTES);

    int ret = pqc_ascon_encrypt_full_message(
        g_ct_buf,
        &g_ct_len,
        msg,
        msg_len,
        sig_ptr,
        sig_len,
        nonce_out,
        g_ascon_key
    );

    return ret;
}

// ===== Decrypt last message =====
int pqc_decrypt_message(const uint8_t *nonce)
{
    if (!nonce) return -1;

    size_t sig_len = pqc_dilithium_get_siglen();
    unsigned long long msg_len = 0;

    // Decrypt into separate buffers for message and signature
    int ret = pqc_ascon_decrypt_full_message(
        g_recv_buf,    // buffer for plaintext message
        &msg_len,      // decrypted message length
        g_sig_buf,     // buffer for signature
        sig_len,       // signature length
        g_ct_buf,      // ciphertext
        g_ct_len,      // ciphertext length
        nonce,
        g_ascon_key
    );

    if (ret != 0) return -1;

    // Store message length for pqc_get_decrypted_length()
    decrypted_len = (size_t)msg_len;
    g_sig_len = sig_len;

    return 0;
}


// ===== Get pointer to decrypted message =====
const uint8_t *pqc_get_decrypted_message(void) {
    return g_recv_buf;
}

size_t pqc_get_decrypted_length(void) {
    return decrypted_len;
}

