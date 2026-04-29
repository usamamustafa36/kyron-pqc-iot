// sender.c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "dilithium_api.h"

#define PACKET_FILE "packet.bin"
#define MAX_MSG_LEN 1024

int main() {
    // Generate keypair
    if (dilithium_keygen() != 0) {
        printf("Keypair generation failed\n");
        return 1;
    }

    // Ask user for message
    char message[MAX_MSG_LEN];
    printf("Enter message to send: ");
    if (!fgets(message, sizeof(message), stdin)) {
        printf("Failed to read message\n");
        return 1;
    }

    // Remove newline if exists
    size_t msg_len = strlen(message);
    if (message[msg_len-1] == '\n') {
        message[msg_len-1] = '\0';
        msg_len--;
    }

    // Sign the message
    if (dilithium_sign((const uint8_t*)message, msg_len) != 0) {
        printf("Signing failed\n");
        return 1;
    }

    // Write to file: msg_len + message + sig_len + signature + public key
    FILE *f = fopen(PACKET_FILE, "wb");
    if (!f) { perror("open"); return 1; }

    uint16_t ml = msg_len;
    uint16_t slen = (uint16_t)dilithium_get_siglen();

    fwrite(&ml, sizeof(uint16_t), 1, f);
    fwrite(message, 1, msg_len, f);
    fwrite(&slen, sizeof(uint16_t), 1, f);           // store signature length
    fwrite(dilithium_get_sig(), 1, slen, f);
    fwrite(dilithium_get_pk(), 1, DILITHIUM_PUBLIC_KEY_BYTES, f);

    fclose(f);
    printf("Message signed and written to %s\n", PACKET_FILE);
    return 0;
}

