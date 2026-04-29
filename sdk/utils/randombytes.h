#ifndef UTILS_RANDOMBYTES_H
#define UTILS_RANDOMBYTES_H

#include <stddef.h>
#include <stdint.h>

// Primary RNG interface
void randombytes(uint8_t *buf, size_t len);

// PQClean naming variants
void PQCLEAN_randombytes(uint8_t *buf, size_t len);
void PQCLEAN_MLKEM512_CLEAN_randombytes(uint8_t *buf, size_t len);
void PQCLEAN_MLDSA44_CLEAN_randombytes(uint8_t *buf, size_t len);

#endif // UTILS_RANDOMBYTES_H

