#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "api.h"
#include "crypto_aead.h"

// Time measurement
double elapsed_ms(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) * 1000.0 +
           (end.tv_nsec - start.tv_nsec) / 1e6;
}

int main() {
    // Inputs
    uint8_t key[CRYPTO_KEYBYTES] = {0};
    uint8_t nonce[CRYPTO_NPUBBYTES] = {0};
    uint8_t msg[] = "Hello, Ascon NEON on Pi!";
    uint8_t ad[] = "RaspberryPi";

    // Buffers
    uint8_t ct[128] = {0};
    uint8_t decrypted[128] = {0};
    unsigned long long clen = 0, mlen = 0;

    struct timespec start, end;

    // --- ENCRYPTION ---
    clock_gettime(CLOCK_MONOTONIC, &start);
    crypto_aead_encrypt(ct, &clen, msg, sizeof(msg), ad, sizeof(ad), NULL, nonce, key);
    clock_gettime(CLOCK_MONOTONIC, &end);
    printf("[ENCRYPTION] Time: %.3f ms\n", elapsed_ms(start, end));

    printf("[ENCRYPTION] Ciphertext: ");
    for (size_t i = 0; i < clen; ++i) printf("%02x", ct[i]);
    printf("\n");

    // --- DECRYPTION ---
    clock_gettime(CLOCK_MONOTONIC, &start);
    int result = crypto_aead_decrypt(decrypted, &mlen, NULL, ct, clen, ad, sizeof(ad), nonce, key);
    clock_gettime(CLOCK_MONOTONIC, &end);
    printf("[DECRYPTION] Time: %.3f ms\n", elapsed_ms(start, end));

    if (result != 0) {
        printf("[ERROR] Decryption failed!\n");
        return 1;
    }

    printf("[DECRYPTION] Message: %s\n", decrypted);
    return 0;
}
