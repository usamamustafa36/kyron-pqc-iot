#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "ascon_api.h"

static inline uint64_t now_us(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000ULL + (uint64_t)(t.tv_nsec / 1000ULL);
}

int main() {
    const uint8_t key[16]   = {0};
    const uint8_t nonce[16] = {1};
    const uint8_t ad[]      = "AD";

    uint8_t msg[4096];
    memset(msg, 'A', sizeof(msg));

    uint8_t ct[5000], pt[5000];
    unsigned long long ct_len, pt_len;

    size_t sizes[] = {16, 64, 256, 1024, 4096};
    int iterations = 500;

    for (int s = 0; s < 5; s++) {
        size_t len = sizes[s];
        printf("\n--- ASCON Test: %zu bytes ---\n", len);

        /* warm-up */
        for (int i=0;i<50;i++) {
            ct_len = sizeof(ct);
            ascon_encrypt(ct, &ct_len, msg, len, ad, strlen((char*)ad), nonce, key);
        }

        uint64_t start = now_us();
        for (int i=0;i<iterations;i++) {
            ct_len = sizeof(ct);
            ascon_encrypt(ct, &ct_len, msg, len, ad, strlen((char*)ad), nonce, key);
        }
        uint64_t end = now_us();

        double avg_us = (double)(end - start) / iterations;
        double throughput = (len / (avg_us / 1e6)) / (1024*1024); // MB/s

        printf("Average Encrypt Time: %.2f us\n", avg_us);
        printf("Throughput: %.3f MB/s\n", throughput);
    }
}
