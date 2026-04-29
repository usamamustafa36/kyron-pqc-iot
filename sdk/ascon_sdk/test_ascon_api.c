#include <stdio.h>
#include <string.h>        // ← required for strlen
#include "ascon_hash.h"

int main() {
    uint8_t out[32];
    char *msg = "Kyron Firmware v1.0";

    if(ascon_hash(out, 32, (uint8_t*)msg, strlen(msg)) != 0) {
        printf("Hash failed\n");
        return 1;
    }

    printf("ASCON Hash: ");
    for(int i=0;i<32;i++) printf("%02x", out[i]);
    printf("\n");

    return 0;
}

