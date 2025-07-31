#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "api.h"
#include "crypto_aead.h"

// Function to enable the ARM cycle counter (PMCCNTR)
static inline void enable_cycle_counter() {
    // Enable user-mode access to the cycle counter
    asm volatile("mcr p15, 0, %0, c9, c14, 0" :: "r"(0x00000001));
    // Enable the cycle counter
    asm volatile("mcr p15, 0, %0, c9, c12, 0" :: "r"(0x8000000f));
    // Clear overflow flag
    asm volatile("mcr p15, 0, %0, c9, c12, 1" :: "r"(0x8000000f));
}

// Function to read the ARM cycle counter
static inline uint32_t read_cycle_counter() {
    uint32_t cycles;
    asm volatile("mrc p15, 0, %0, c9, c13, 0" : "=r"(cycles));
    return cycles;
}

int main() {
    uint8_t key[CRYPTO_KEYBYTES] = {0};
    uint8_t nonce[CRYPTO_NPUBBYTES] = {0};
    uint8_t ad[] = "MacBook";

    // Allocate 800 KB message and fill with random data
    size_t msg_len = 800 * 1024;
    uint8_t *msg = malloc(msg_len);
    if (!msg) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }
    for (size_t i = 0; i < msg_len; i++) {
        msg[i] = (uint8_t)(i % 256);
    }

    uint8_t *ct = malloc(msg_len + CRYPTO_ABYTES);
    uint8_t *decrypted = malloc(msg_len + CRYPTO_ABYTES);
    if (!ct || !decrypted) {
        fprintf(stderr, "Memory allocation failed\n");
        free(msg);
        return 1;
    }

    unsigned long long clen = 0, mlen = 0;
    uint32_t start_cycles, end_cycles;

    // Enable the ARM cycle counter
    enable_cycle_counter();

    // --- ENCRYPTION ---
    start_cycles = read_cycle_counter();
    crypto_aead_encrypt(ct, &clen, msg, msg_len, ad, sizeof(ad), NULL, nonce, key);
    end_cycles = read_cycle_counter();

    printf("Encryption cycles: %u\n", end_cycles - start_cycles);
    printf("Ciphertext length: %llu bytes\n", clen);

    // --- DECRYPTION ---
    start_cycles = read_cycle_counter();
    if (crypto_aead_decrypt(decrypted, &mlen, NULL, ct, clen, ad, sizeof(ad), nonce, key) != 0) {
        printf("Decryption failed!\n");
        free(msg);
        free(ct);
        free(decrypted);
        return 1;
    }
    end_cycles = read_cycle_counter();

    printf("Decryption cycles: %u\n", end_cycles - start_cycles);
    printf("Decrypted message length: %llu bytes\n", mlen);

    // Cleanup
    free(msg);
    free(ct);
    free(decrypted);

    return 0;
}