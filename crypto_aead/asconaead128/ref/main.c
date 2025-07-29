#define _POSIX_C_SOURCE 199309L  // For clock_gettime

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#include "api.h"            // For CRYPTO_* constants
#include "crypto_aead.h"    // For crypto_aead_encrypt/decrypt

// Helper to compute elapsed milliseconds
double elapsed_ms(struct timespec start, struct timespec end) {
    double sec = end.tv_sec - start.tv_sec;
    double nsec = end.tv_nsec - start.tv_nsec;
    return sec * 1000.0 + nsec / 1e6;
}

// Get resident memory (VmRSS) in KB on Linux
size_t getCurrentRSS() {
    FILE* f = fopen("/proc/self/status", "r");
    if (!f) return 0;

    size_t rss = 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            char* p = line + 6;
            while (*p == ' ' || *p == '\t') p++;
            rss = strtoul(p, NULL, 10);  // in KB
            break;
        }
    }
    fclose(f);
    return rss;
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
    size_t mem_before, mem_after;

    // --- ENCRYPTION ---
    mem_before = getCurrentRSS();
    clock_gettime(CLOCK_MONOTONIC, &start);

    crypto_aead_encrypt(ct, &clen, msg, sizeof(msg), ad, sizeof(ad), NULL, nonce, key);

    clock_gettime(CLOCK_MONOTONIC, &end);
    mem_after = getCurrentRSS();

    printf("Encryption time: %.3f ms\n", elapsed_ms(start, end));
    printf("Memory used during encryption: %zu KB\n", mem_after - mem_before);
    printf("Ciphertext: ");
    for (size_t i = 0; i < clen; ++i) {
        printf("%02x", ct[i]);
    }
    printf("\n");

    // --- DECRYPTION ---
    mem_before = getCurrentRSS();
    clock_gettime(CLOCK_MONOTONIC, &start);

    if (crypto_aead_decrypt(decrypted, &mlen, NULL, ct, clen, ad, sizeof(ad), nonce, key) != 0) {
        printf("Decryption failed!\n");
        return 1;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    mem_after = getCurrentRSS();

    printf("Decryption time: %.3f ms\n", elapsed_ms(start, end));
    printf("Memory used during decryption: %zu KB\n", mem_after - mem_before);
    printf("Decrypted message: %s\n", decrypted);

    return 0;
}
