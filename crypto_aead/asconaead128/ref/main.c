#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
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
    uint8_t key[CRYPTO_KEYBYTES] = {0};
    uint8_t nonce[CRYPTO_NPUBBYTES] = {0};
    uint8_t ad[] = "MacBook";

    size_t msg_len = 800 * 1024;
    uint8_t *msg = malloc(msg_len);
    uint8_t *ct = malloc(msg_len + CRYPTO_ABYTES);
    unsigned long long clen = 0;

    if (!msg || !ct) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    for (size_t i = 0; i < msg_len; i++) msg[i] = (uint8_t)(i % 256);

    // Setup PMU
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
        perror("perf_event_open");
        return 1;
    }

    // Start counting
    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    // --- Encryption ---
    crypto_aead_encrypt(ct, &clen, msg, msg_len, ad, sizeof(ad), NULL, nonce, key);

    // Stop counting
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

    uint64_t cycles = 0;
    if (read(fd, &cycles, sizeof(cycles)) != sizeof(cycles)) {
        perror("read");
        close(fd);
        return 1;
    }

    close(fd);

    // Force compiler to keep ciphertext
    uint32_t checksum = 0;
    for (size_t i = 0; i < clen; i++) checksum += ct[i];

    printf("Ciphertext checksum: %u\n", checksum);
    printf("Encryption cycles: %lu\n", cycles);
    printf("Ciphertext length: %llu bytes\n", clen);

    free(msg);
    free(ct);
    return 0;
}
