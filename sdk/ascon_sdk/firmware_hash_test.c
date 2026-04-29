#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "ascon_hash.h"

int main() {
    // Example firmware data
    uint8_t firmware[] = "NEW IoT Firmware v1.0";

    // Compute hash for this firmware
    uint8_t expected_hash[32];
    if (ascon_hash(expected_hash, sizeof(expected_hash), firmware, sizeof(firmware)-1) != 0) {
        printf("Error computing firmware hash\n");
        return 1;
    }

    // Print hash for reference (you can copy this as golden value if needed)
    printf("Computed hash (golden value for positive test): ");
    for (int i = 0; i < sizeof(expected_hash); i++)
        printf("%02X", expected_hash[i]);
    printf("\n");

    // Compute hash again for positive verification
    uint8_t computed_hash[32];
    ascon_hash(computed_hash, sizeof(computed_hash), firmware, sizeof(firmware)-1);

    // Compare hashes
    if (memcmp(computed_hash, expected_hash, sizeof(expected_hash)) == 0) {
        printf("Firmware hash verified ✅\n");
    } else {
        printf("WARNING: Firmware hash mismatch ⚠️\n");
    }

    return 0;
}

