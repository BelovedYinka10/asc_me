#define _POSIX_C_SOURCE 199309L  // Enable POSIX.1b features for clock_gettime

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "api.h"            // For CRYPTO_* constants
#include "crypto_aead.h"    // For crypto_aead_encrypt/decrypt

// Helper function to compute elapsed milliseconds
double elapsed_ms(struct timespec start, struct timespec end) {
    double sec = end.tv_sec - start.tv_sec;
    double nsec = end.tv_nsec - start.tv_nsec;
    return sec * 1000.0 + nsec / 1e6;
}

int main() {
    uint8_t key[CRYPTO_KEYBYTES] = {0};
    uint8_t nonce[CRYPTO_NPUBBYTES] = {0};
    uint8_t msg[] = "Hello, Ascon on MacBook!";
    uint8_t ad[] = "MacBook";

    uint8_t ct[128] = {0};
    uint8_t decrypted[128] = {0};
    unsigned long long clen = 0, mlen = 0;

    struct timespec start, end;

    // --- ENCRYPTION ---
    clock_gettime(CLOCK_MONOTONIC, &start);
    crypto_aead_encrypt(ct, &clen, msg, sizeof(msg), ad, sizeof(ad), NULL, nonce, key);
    clock_gettime(CLOCK_MONOTONIC, &end);

    printf("Encryption time: %.3f ms\n", elapsed_ms(start, end));
    printf("Ciphertext: ");
    for (size_t i = 0; i < clen; ++i) {
        printf("%02x", ct[i]);
    }
    printf("\n");

    // --- DECRYPTION ---
    clock_gettime(CLOCK_MONOTONIC, &start);
    if (crypto_aead_decrypt(decrypted, &mlen, NULL, ct, clen, ad, sizeof(ad), nonce, key) != 0) {
        printf("Decryption failed!\n");
        return 1;
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    printf("Decryption time: %.3f ms\n", elapsed_ms(start, end));
    printf("Decrypted message: %s\n", decrypted);

    return 0;
}
