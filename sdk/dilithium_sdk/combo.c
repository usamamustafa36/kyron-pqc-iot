#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "dilithium_api.h"

#define FW_SIZE 256 // dummy firmware size

int main() {
    printf("=== Dilithium Firmware Signing & Verification Demo ===\n");

    // -------------------------
    // Sender: Generate keypair
    // -------------------------
    if (dilithium_keygen() != 0) {
        printf("Key generation failed!\n");
        return 1;
    }
    printf("[Sender] Keypair generated.\n");

    // -------------------------
    // Sender: Prepare dummy firmware
    // -------------------------
    uint8_t firmware[FW_SIZE];
    for (int i=0; i<FW_SIZE; i++) firmware[i] = i;
    printf("[Sender] Dummy firmware prepared (%d bytes).\n", FW_SIZE);

    // -------------------------
    // Sender: Sign firmware
    // -------------------------
    if (dilithium_sign(firmware, FW_SIZE) != 0) {
        printf("Signing failed!\n");
        return 1;
    }
    size_t sig_len = dilithium_get_siglen();
    printf("[Sender] Firmware signed (siglen = %zu bytes).\n", sig_len);

    const uint8_t *pk = dilithium_get_pk();
    const uint8_t *sig = dilithium_get_sig();

    // -------------------------
    // Simulate "sending" the packet in memory
    // -------------------------
    size_t packet_size = sizeof(uint32_t) + FW_SIZE + sizeof(uint16_t) + sig_len + DILITHIUM_PUBLIC_KEY_BYTES;
    uint8_t *packet = malloc(packet_size);
    uint8_t *ptr = packet;

    // [firmware size]
    uint32_t fw_len_u32 = FW_SIZE;
    memcpy(ptr, &fw_len_u32, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    // [firmware data]
    memcpy(ptr, firmware, FW_SIZE);
    ptr += FW_SIZE;

    // [signature length]
    uint16_t sig_len_u16 = (uint16_t)sig_len;
    memcpy(ptr, &sig_len_u16, sizeof(uint16_t));
    ptr += sizeof(uint16_t);

    // [signature]
    memcpy(ptr, sig, sig_len);
    ptr += sig_len;

    // [public key]
    memcpy(ptr, pk, DILITHIUM_PUBLIC_KEY_BYTES);

    printf("[Sender] Packet created in memory.\n");

    // -------------------------
    // Receiver: Parse packet
    // -------------------------
    ptr = packet;

    // firmware size
    uint32_t recv_fw_len;
    memcpy(&recv_fw_len, ptr, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    // firmware data
    uint8_t *recv_fw = malloc(recv_fw_len);
    memcpy(recv_fw, ptr, recv_fw_len);
    ptr += recv_fw_len;

    // signature length
    uint16_t recv_sig_len;
    memcpy(&recv_sig_len, ptr, sizeof(uint16_t));
    ptr += sizeof(uint16_t);

    // signature
    uint8_t *recv_sig = malloc(recv_sig_len);
    memcpy(recv_sig, ptr, recv_sig_len);
    ptr += recv_sig_len;

    // public key
    uint8_t recv_pk[DILITHIUM_PUBLIC_KEY_BYTES];
    memcpy(recv_pk, ptr, DILITHIUM_PUBLIC_KEY_BYTES);

    // -------------------------
    // Receiver: Verify firmware
    // -------------------------
    int rc = dilithium_verify_with_pk(recv_sig, recv_sig_len, recv_fw, recv_fw_len, recv_pk);
    if (rc == 0) {
        printf("[Receiver] Firmware signature VALID ✅\n");
    } else {
        printf("[Receiver] Firmware signature INVALID ❌\n");
    }

    // Cleanup
    free(packet);
    free(recv_fw);
    free(recv_sig);

    printf("=== Demo Completed ===\n");
    return 0;
}
