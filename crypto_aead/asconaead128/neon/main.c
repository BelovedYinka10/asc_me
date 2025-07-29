#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "api.h"
#include "cpucycles.h"
#include "crypto_aead.h"

int main() {
    uint8_t key[CRYPTO_KEYBYTES] = {0};
    uint8_t nonce[CRYPTO_NPUBBYTES] = {0};
    uint8_t msg[] = "Hello, Pi!";
    uint8_t ad[] = "Raspberry";
    uint8_t ct[128] = {0};
    uint8_t decrypted[128] = {0};
    unsigned long long clen = 0, mlen = 0;

    cpucycles_init();

    // Encryption
    cpucycles_reset();
    cpucycles_start();
    crypto_aead_encrypt(ct, &clen, msg, sizeof(msg), ad, sizeof(ad), NULL, nonce, key);
    cpucycles_stop();
    printf("Encryption cycles: %llu\n", cpucycles_result());

    printf("Ciphertext: ");
    for (size_t i = 0; i < clen; ++i) printf("%02x", ct[i]);
    printf("\n");

    // Decryption
    cpucycles_reset();
    cpucycles_start();
    int result = crypto_aead_decrypt(decrypted, &mlen, NULL, ct, clen, ad, sizeof(ad), nonce, key);
    cpucycles_stop();
    printf("Decryption cycles: %llu\n", cpucycles_result());

    if (result != 0) {
        printf("Decryption failed!\n");
        return 1;
    }

    printf("Decrypted: %s\n", decrypted);
    return 0;
}
