#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "api.h"
#include "crypto_aead.h"
#include "cpucycles.h"

int main() {
    // Input data
    const uint8_t key[CRYPTO_KEYBYTES] = {0};
    const uint8_t nonce[CRYPTO_NPUBBYTES] = {0};
    const uint8_t message[] = "Hello, NEON on Raspberry Pi!";
    const uint8_t ad[] = "TestAD";

    // Buffers
    uint8_t ciphertext[128] = {0};
    uint8_t decrypted[128] = {0};
    unsigned long long clen = 0;
    unsigned long long mlen = 0;

    // --- ENCRYPTION ---
    cpucycles_reset();
    cpucycles_init();
    cpucycles_start();

    int enc = crypto_aead_encrypt(ciphertext, &clen, message, sizeof(message),
                                  ad, sizeof(ad), NULL, nonce, key);

    cpucycles_stop();
    printf("Encryption cycles: %llu\n", cpucycles_result());

    if (enc != 0) {
        printf("Encryption failed!\n");
        return 1;
    }

    printf("Ciphertext: ");
    for (size_t i = 0; i < clen; ++i)
        printf("%02x", ciphertext[i]);
    printf("\n");

    // --- DECRYPTION ---
    cpucycles_reset();
    cpucycles_start();

    int dec = crypto_aead_decrypt(decrypted, &mlen, NULL, ciphertext, clen,
                                  ad, sizeof(ad), nonce, key);

    cpucycles_stop();
    printf("Decryption cycles: %llu\n", cpucycles_result());

    if (dec != 0) {
        printf("Decryption failed!\n");
        return 1;
    }

    printf("Decrypted: %s\n", decrypted);
    return 0;
}
