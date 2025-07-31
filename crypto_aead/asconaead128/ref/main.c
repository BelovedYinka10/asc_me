#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include "api.h"
#include "crypto_aead.h"

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                            int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

uint64_t measure_cycles(void (*func)(void*), void *arg) {
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
        exit(1);
    }

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    func(arg);  // execute measured function

    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

    uint64_t count = 0;
    if (read(fd, &count, sizeof(count)) != sizeof(count)) {
        perror("read");
        close(fd);
        exit(1);
    }

    close(fd);
    return count;
}

struct enc_args {
    uint8_t *ct;
    unsigned long long *clen;
    uint8_t *msg;
    size_t msg_len;
    uint8_t *ad;
    size_t ad_len;
    uint8_t *nonce;
    uint8_t *key;
};

struct dec_args {
    uint8_t *decrypted;
    unsigned long long *mlen;
    uint8_t *ct;
    unsigned long long clen;
    uint8_t *ad;
    size_t ad_len;
    uint8_t *nonce;
    uint8_t *key;
};

__attribute__((noinline))
void encrypt_func(void *arg) {
    struct enc_args *args = (struct enc_args *)arg;
    crypto_aead_encrypt(args->ct, args->clen, args->msg, args->msg_len,
                        args->ad, args->ad_len, NULL, args->nonce, args->key);
}

__attribute__((noinline))
void decrypt_func(void *arg) {
    struct dec_args *args = (struct dec_args *)arg;
    crypto_aead_decrypt(args->decrypted, args->mlen, NULL, args->ct, args->clen,
                        args->ad, args->ad_len, args->nonce, args->key);
}

int main() {
    uint8_t key[CRYPTO_KEYBYTES] = {0};
    uint8_t nonce[CRYPTO_NPUBBYTES] = {0};
    uint8_t ad[] = "MacBook";

    size_t msg_len = 800 * 1024;
    uint8_t *msg = malloc(msg_len);
    uint8_t *ct = malloc(msg_len + CRYPTO_ABYTES);
    uint8_t *decrypted = malloc(msg_len + CRYPTO_ABYTES);

    if (!msg || !ct || !decrypted) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    for (size_t i = 0; i < msg_len; i++) msg[i] = (uint8_t)(i % 256);

    unsigned long long clen = 0, mlen = 0;

    struct enc_args enc = {ct, &clen, msg, msg_len, ad, sizeof(ad), nonce, key};
    uint64_t enc_cycles = measure_cycles(encrypt_func, &enc);

    // Prevent optimization from removing output
    __asm__ volatile("" : : "r"(clen), "r"(ct) : "memory");

    printf("Encryption cycles: %lu\n", enc_cycles);
    printf("Ciphertext length: %llu bytes\n", clen);

    struct dec_args dec = {decrypted, &mlen, ct, clen, ad, sizeof(ad), nonce, key};
    uint64_t dec_cycles = measure_cycles(decrypt_func, &dec);

    __asm__ volatile("" : : "r"(mlen), "r"(decrypted) : "memory");

    printf("Decryption cycles: %lu\n", dec_cycles);
    printf("Decrypted message length: %llu bytes\n", mlen);

    free(msg);
    free(ct);
    free(decrypted);
    return 0;
}
