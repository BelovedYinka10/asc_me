#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <errno.h>
#include "api.h"
#include "crypto_aead.h"

static long
perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

int main() {
    // Inputs
    uint8_t key[CRYPTO_KEYBYTES] = {0};
    uint8_t nonce[CRYPTO_NPUBBYTES] = {0};
    uint8_t ad[] = "MacBook";

    size_t msg_len = 800 * 1024;
    uint8_t *msg = malloc(msg_len);
    uint8_t *ct = malloc(msg_len + CRYPTO_ABYTES);
    uint8_t *decrypted = malloc(msg_len + CRYPTO_ABYTES);
    unsigned long long clen = 0, mlen = 0;

    if (!msg || !ct || !decrypted) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    for (size_t i = 0; i < msg_len; i++) msg[i] = (uint8_t)(i % 256);

    // === ENCRYPTION Measurement ===
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(struct perf_event_attr));
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(struct perf_event_attr);
    pe.config = PERF_COUNT_HW_CPU_CYCLES;
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;

    int fd = perf_event_open(&pe, 0, 0, -1, 0);
    if (fd == -1) {
        perror("perf_event_open (encrypt)");
        return 1;
    }

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    crypto_aead_encrypt(ct, &clen, msg, msg_len, ad, sizeof(ad), NULL, nonce, key);

    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

    uint64_t enc_cycles = 0;
    if (read(fd, &enc_cycles, sizeof(enc_cycles)) != sizeof(enc_cycles)) {
        perror("read (encrypt)");
        close(fd);
        return 1;
    }
    close(fd);

    // Prevent optimization
    __asm__ volatile("" : : "r"(clen), "r"(ct) : "memory");

    uint32_t ct_checksum = 0;
    for (size_t i = 0; i < clen; i++) ct_checksum += ct[i];

    printf("Ciphertext checksum: %u\n", ct_checksum);
    printf("Encryption cycles: %lu\n", enc_cycles);
    printf("Ciphertext length: %llu bytes\n", clen);

    // === DECRYPTION Measurement ===
    fd = perf_event_open(&pe, 0, 0, -1, 0);
    if (fd == -1) {
        perror("perf_event_open (decrypt)");
        return 1;
    }

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    crypto_aead_decrypt(decrypted, &mlen, NULL, ct, clen, ad, sizeof(ad), nonce, key);

    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

    uint64_t dec_cycles = 0;
    if (read(fd, &dec_cycles, sizeof(dec_cycles)) != sizeof(dec_cycles)) {
        perror("read (decrypt)");
        close(fd);
        return 1;
    }
    close(fd);

    __asm__ volatile("" : : "r"(mlen), "r"(decrypted) : "memory");

    uint32_t pt_checksum = 0;
    for (size_t i = 0; i < mlen; i++) pt_checksum += decrypted[i];

    printf("Decrypted checksum: %u\n", pt_checksum);
    printf("Decryption cycles: %lu\n", dec_cycles);
    printf("Decrypted message length: %llu bytes\n", mlen);

    free(msg);
    free(ct);
    free(decrypted);
    return 0;
}
