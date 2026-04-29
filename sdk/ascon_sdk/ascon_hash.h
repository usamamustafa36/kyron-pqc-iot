#ifndef ASCON_HASH_H
#define ASCON_HASH_H

#include <stdint.h>
#include <stddef.h>

#ifndef ASCON_HASH_OUT
#define ASCON_HASH_OUT 32   // 256-bit output
#endif

// One-shot deterministic Ascon-based hash (no salt)
int ascon_hash(uint8_t *out, size_t outlen,
               const uint8_t *msg, size_t msglen);

#endif

