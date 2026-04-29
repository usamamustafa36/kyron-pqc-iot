#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "dilithium_api.h"

#define PACKET_FILE "fw_packet.bin"

int main() {
    FILE *pkt = fopen(PACKET_FILE, "rb");
    if (!pkt) { perror("open"); return 1; }

    // 1. Read firmware size
    uint32_t fw_len;
    fread(&fw_len, sizeof(uint32_t), 1, pkt);

    // 2. Read firmware data
    uint8_t *fw_data = malloc(fw_len);
    fread(fw_data, 1, fw_len, pkt);

    // 3. Read signature
    uint16_t sig_len;
    fread(&sig_len, sizeof(uint16_t), 1, pkt);

    uint8_t *sig = malloc(sig_len);
    fread(sig, 1, sig_len, pkt);

    // 4. Read public key
    uint8_t pk[DILITHIUM_PUBLIC_KEY_BYTES];
    fread(pk, 1, DILITHIUM_PUBLIC_KEY_BYTES, pkt);

    fclose(pkt);

    // 5. Verify signature
    if (dilithium_verify_with_pk(sig, sig_len, fw_data, fw_len, pk) == 0) {
        printf("Firmware signature VALID\n");
    } else {
        printf("Firmware signature INVALID\n");
    }

    free(fw_data);
    free(sig);
    return 0;
}
