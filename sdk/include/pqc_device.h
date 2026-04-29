#ifndef PQC_DEVICE_H
#define PQC_DEVICE_H

#include <stdint.h>
#include <stddef.h>

#define PQC_MAX_BUFFER 16384
#define ASCON_KEY_BYTES 16
#define ASCON_NONCE_BYTES 16
const uint8_t *pqc_get_ciphertext_buffer(void);
unsigned long long pqc_get_ciphertext_length(void);

// ===== Initialization =====
int pqc_init(void);

// ===== Encrypt/Decrypt =====
// Encrypt: provide msg + msg_len, outputs nonce
int pqc_encrypt_message(const uint8_t *msg, size_t msg_len,
                        uint8_t *nonce_out);

// Decrypt: provide the nonce received alongside ciphertext
int pqc_decrypt_message(const uint8_t *nonce);

// Get decrypted message and length
const uint8_t *pqc_get_decrypted_message(void);
size_t pqc_get_decrypted_length(void);

#endif // PQC_DEVICE_H

