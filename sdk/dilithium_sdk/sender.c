#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "dilithium_api.h"

#define PACKET_FILE "fw_packet.bin"

int main() {
    // 1. Generate keypair
    if (dilithium_keygen() != 0) { printf("Keygen failed\n"); return 1; }

    // 2. Dummy firmware
    uint8_t dummy_fw[256];
    for (int i=0; i<256; i++) dummy_fw[i] = i;

    size_t fw_len = sizeof(dummy_fw);

    // 3. Sign firmware
    if (dilithium_sign(dummy_fw, fw_len) != 0) { printf("Signing failed\n"); return 1; }

    // 4. Write packet: [fw_len][fw_data][sig_len][sig][pk]
    FILE *pkt = fopen(PACKET_FILE, "wb");
    uint16_t sig_len = (uint16_t)dilithium_get_siglen();
    uint32_t fw_size = (uint32_t)fw_len;

    fwrite(&fw_size, sizeof(uint32_t), 1, pkt);
    fwrite(dummy_fw, 1, fw_len, pkt);
    fwrite(&sig_len, sizeof(uint16_t), 1, pkt);
    fwrite(dilithium_get_sig(), 1, sig_len, pkt);
    fwrite(dilithium_get_pk(), 1, DILITHIUM_PUBLIC_KEY_BYTES, pkt);
    fclose(pkt);

    printf("Firmware signed and saved to %s\n", PACKET_FILE);
    return 0;
}
