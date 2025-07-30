#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "api.h"
#include "crypto_aead.h"

// Read CCNT register
static inline uint32_t read_ccnt(void) {
    uint32_t cc;
    asm volatile ("mrc p15, 0, %0, c9, c13, 0" : "=r"(cc));
    return cc;
}

int main() {
    uint8_t key[CRYPTO_KEYBYTES] = {0};
    uint8_t nonce[CRYPTO_NPUBBYTES] = {0};
    uint8_t msg[] = "Hello, Ascon on ARM!";
    uint8_t ad[] = "Benchmark";

    uint8_t ct[128] = {0};
    uint8_t decrypted[128] = {0};
    unsigned long long clen = 0, mlen = 0;

    uint32_t start, end;

    // --- ENCRYPTION ---
    start = read_ccnt();
    crypto_aead_encrypt(ct, &clen, msg, sizeof(msg), ad, sizeof(ad), NULL, nonce, key);
    end = read_ccnt();
    printf("Encryption cycles: %u\n", end - start);

    // --- DECRYPTION ---
    start = read_ccnt();
    if (crypto_aead_decrypt(decrypted, &mlen, NULL, ct, clen, ad, sizeof(ad), nonce, key) != 0) {
        printf("Decryption failed!\n");
        return 1;
    }
    end = read_ccnt();
    printf("Decryption cycles: %u\n", end - start);

    printf("Decrypted message: %s\n", decrypted);
    return 0;
}
