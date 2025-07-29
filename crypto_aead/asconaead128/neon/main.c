#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "api.h"
#include "crypto_aead.h"

int main() {
    // Inputs
    uint8_t key[CRYPTO_KEYBYTES] = {0};
    uint8_t nonce[CRYPTO_NPUBBYTES] = {0};
    uint8_t msg[] = "Hello, NEON on Raspberry Pi!";
    uint8_t ad[] = "Raspberry";

    // Buffers
    uint8_t ct[128] = {0};
    uint8_t decrypted[128] = {0};
    unsigned long long clen = 0, mlen = 0;

    // --- ENCRYPTION ---
    crypto_aead_encrypt(ct, &clen, msg, sizeof(msg), ad, sizeof(ad), NULL, nonce, key);

    printf("Ciphertext: ");
    for (size_t i = 0; i < clen; ++i) printf("%02x", ct[i]);
    printf("\n");

    // --- DECRYPTION ---
    int result = crypto_aead_decrypt(decrypted, &mlen, NULL, ct, clen, ad, sizeof(ad), nonce, key);

    if (result != 0) {
        printf("Decryption failed!\n");
        return 1;
    }

    printf("Decrypted: %s\n", decrypted);
    return 0;
}
