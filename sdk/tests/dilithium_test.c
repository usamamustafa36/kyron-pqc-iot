#include <stdio.h>
#include <string.h>
#include "dilithium_api.h"

int main(void) {
    const char *msg = "Test message for Dilithium SDK";
    if (dilithium_keypair() != 0) {
        printf("Keypair generation failed\n");
        return 1;
    }
    if (dilithium_sign((const unsigned char*)msg, strlen(msg)) != 0) {
        printf("Signing failed\n");
        return 1;
    }
    if (dilithium_verify((const unsigned char*)msg, strlen(msg)) != 0) {
        printf("Signature verification failed\n");
        return 1;
    }
    printf("Dilithium SDK test passed!\n");
    return 0;
}

