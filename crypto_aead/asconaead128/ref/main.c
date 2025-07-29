#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "api.h"            // For CRYPTO_* constants
#include "cpucycles.h"      // For measuring CPU cycles
#include "crypto_aead.h"    // For crypto_aead_encrypt/decrypt

int main() {
    // Inputs
    uint8_t key[CRYPTO_KEYBYTES] = {0};                     // 16 bytes
    uint8_t nonce[CRYPTO_NPUBBYTES] = {0};                  // 16 bytes
    uint8_t msg[] = "Hello, Ascon on MacBook!";
    uint8_t ad[] = "MacBook";                               // Associated data

    // Buffers
    uint8_t ct[128] = {0};                                  // Ciphertext buffer
    uint8_t decrypted[128] = {0};                           // Decryption output
    unsigned long long clen = 0, mlen = 0;

    // Initialize cycle counter
    cpucycles_init();

    // --- ENCRYPTION ---
    cpucycles_reset();
    cpucycles_start();
    crypto_aead_encrypt(ct, &clen, msg, sizeof(msg), ad, sizeof(ad), NULL, nonce, key);
    cpucycles_stop();

    printf("Encryption cycles: %llu\n", cpucycles_result());
    printf("Ciphertext: ");
    for (size_t i = 0; i < clen; ++i) {
        printf("%02x", ct[i]);
    }
    printf("\n");

    // --- DECRYPTION ---
    cpucycles_reset();
    cpucycles_start();
    if (crypto_aead_decrypt(decrypted, &mlen, NULL, ct, clen, ad, sizeof(ad), nonce, key) != 0) {
        printf("Decryption failed!\n");
        return 1;
    }
    cpucycles_stop();

    printf("Decryption cycles: %llu\n", cpucycles_result());
    printf("Decrypted message: %s\n", decrypted);

    return 0;
}
