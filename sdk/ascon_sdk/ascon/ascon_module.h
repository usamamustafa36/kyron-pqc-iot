#ifndef ASCON_MODULE_H
#define ASCON_MODULE_H

#include <stdint.h>

void ascon_init_key_nonce(const uint8_t *key, const uint8_t *nonce);

int ascon_encrypt_message(const uint8_t *plaintext, unsigned long long plen,
                         uint8_t *ciphertext, unsigned long long *clen);

int ascon_decrypt_message(const uint8_t *ciphertext, unsigned long long clen,
                         uint8_t *plaintext, unsigned long long *plen);

#endif

