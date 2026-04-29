#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "ascon/api.h"
#include "ascon_hash.h"
#include "ascon/crypto_aead.h"  // provides crypto_aead_encrypt()

int ascon_hash(uint8_t *out, size_t outlen,
               const uint8_t *msg, size_t msglen)
{
    if (outlen < ASCON_HASH_OUT) return -1;

    uint8_t key[CRYPTO_KEYBYTES] = {0};
    uint8_t nonce[CRYPTO_NPUBBYTES] = {0};
    unsigned long long clen = 0;

    // deterministic AEAD-based hash
    if (crypto_aead_encrypt(out, &clen,
                            msg, msglen,
                            NULL, 0,
                            NULL, nonce, key) != 0)
        return -1;

    // truncate or pad to fixed output
    if (clen < ASCON_HASH_OUT)
        memset(out + clen, 0, ASCON_HASH_OUT - clen);

    return 0;
}

