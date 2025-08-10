// ascon_mem_time_cycles.c — Per-operation Peak Memory + Avg Time + Avg Cycles
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <errno.h>
#include "api.h"
#include "crypto_aead.h"

#ifndef NUM_ITERATIONS
#define NUM_ITERATIONS 1000
#endif

static inline double tdiff_ns(struct timespec s, struct timespec e){
    return (e.tv_sec - s.tv_sec)*1e9 + (e.tv_nsec - s.tv_nsec);
}
static long perf_event_open(struct perf_event_attr *a, pid_t pid,int cpu,int g,unsigned long f){
    return syscall(__NR_perf_event_open, a, pid, cpu, g, f);
}
static long read_status_kb(const char *key){
    FILE *f = fopen("/proc/self/status","r");
    if(!f) return -1;
    char line[256]; long val=-1; size_t k=strlen(key);
    while(fgets(line,sizeof line,f)) if(strncmp(line,key,k)==0){ if(sscanf(line+k," %ld",&val)==1) break; }
    fclose(f); return val;
}
static void child_encrypt(int wfd, size_t msg_len){
    uint8_t *msg = malloc(msg_len);
    uint8_t *ct  = malloc(msg_len + CRYPTO_ABYTES);
    if(!msg || !ct) _exit(111);
    for(size_t i=0;i<msg_len;i++) msg[i]=(uint8_t)(i&0xFF);
    uint8_t key[CRYPTO_KEYBYTES]={0}, nonce[CRYPTO_NPUBBYTES]={0}, ad[]="MacBook";
    unsigned long long clen=0;

    // warm-up once
    crypto_aead_encrypt(ct,&clen,msg,msg_len,ad,sizeof ad,NULL,nonce,key);

    // perf setup
    struct perf_event_attr pe={0};
    pe.type=PERF_TYPE_HARDWARE; pe.size=sizeof(pe); pe.config=PERF_COUNT_HW_CPU_CYCLES;
    pe.disabled=1; pe.exclude_kernel=1; pe.exclude_hv=1;
    int perf_ok=1; int fd=perf_event_open(&pe,0,0,-1,0);
    if(fd==-1){ perf_ok=0; }

    struct timespec s,e;
    clock_gettime(CLOCK_MONOTONIC,&s);
    if(perf_ok){ ioctl(fd,PERF_EVENT_IOC_RESET,0); ioctl(fd,PERF_EVENT_IOC_ENABLE,0); }

    for(int i=0;i<NUM_ITERATIONS;i++)
        crypto_aead_encrypt(ct,&clen,msg,msg_len,ad,sizeof ad,NULL,nonce,key);

    if(perf_ok){ ioctl(fd,PERF_EVENT_IOC_DISABLE,0); }
    clock_gettime(CLOCK_MONOTONIC,&e);
    unsigned long long cycles=0ULL;
    if(perf_ok){ if(read(fd,&cycles,sizeof cycles)!=(ssize_t)sizeof cycles) cycles=0ULL; close(fd); }

    double avg_ms = (tdiff_ns(s,e)/1e6)/NUM_ITERATIONS;
    double avg_cycles = perf_ok? (double)cycles/NUM_ITERATIONS : 0.0;
    long peak_kb = read_status_kb("VmHWM:");

    dprintf(wfd, "ENC %.6f %.0f %ld\n", avg_ms, avg_cycles, peak_kb);
    free(msg); free(ct); _exit(0);
}
static void child_decrypt(int wfd, size_t msg_len){
    uint8_t *msg = malloc(msg_len);
    uint8_t *ct  = malloc(msg_len + CRYPTO_ABYTES);
    uint8_t *pt  = malloc(msg_len + CRYPTO_ABYTES);
    if(!msg || !ct || !pt) _exit(111);
    for(size_t i=0;i<msg_len;i++) msg[i]=(uint8_t)(i&0xFF);
    uint8_t key[CRYPTO_KEYBYTES]={0}, nonce[CRYPTO_NPUBBYTES]={0}, ad[]="MacBook";
    unsigned long long clen=0, mlen=0;

    // prepare ciphertext once (outside measured loop)
    crypto_aead_encrypt(ct,&clen,msg,msg_len,ad,sizeof ad,NULL,nonce,key);

    struct perf_event_attr pe={0};
    pe.type=PERF_TYPE_HARDWARE; pe.size=sizeof(pe); pe.config=PERF_COUNT_HW_CPU_CYCLES;
    pe.disabled=1; pe.exclude_kernel=1; pe.exclude_hv=1;
    int perf_ok=1; int fd=perf_event_open(&pe,0,0,-1,0);
    if(fd==-1){ perf_ok=0; }

    struct timespec s,e;
    clock_gettime(CLOCK_MONOTONIC,&s);
    if(perf_ok){ ioctl(fd,PERF_EVENT_IOC_RESET,0); ioctl(fd,PERF_EVENT_IOC_ENABLE,0); }

    for(int i=0;i<NUM_ITERATIONS;i++)
        crypto_aead_decrypt(pt,&mlen,NULL,ct,clen,ad,sizeof ad,nonce,key);

    if(perf_ok){ ioctl(fd,PERF_EVENT_IOC_DISABLE,0); }
    clock_gettime(CLOCK_MONOTONIC,&e);
    unsigned long long cycles=0ULL;
    if(perf_ok){ if(read(fd,&cycles,sizeof cycles)!=(ssize_t)sizeof cycles) cycles=0ULL; close(fd); }

    double avg_ms = (tdiff_ns(s,e)/1e6)/NUM_ITERATIONS;
    double avg_cycles = perf_ok? (double)cycles/NUM_ITERATIONS : 0.0;
    long peak_kb = read_status_kb("VmHWM:");

    dprintf(wfd, "DEC %.6f %.0f %ld\n", avg_ms, avg_cycles, peak_kb);
    free(msg); free(ct); free(pt); _exit(0);
}
int main(void){
    const size_t msg_len = 800*1024;

    // fork encrypt
    int p1[2]; pipe(p1);
    if(fork()==0){ close(p1[0]); child_encrypt(p1[1], msg_len); }
    close(p1[1]);
    char enc_buf[128]={0}; read(p1[0], enc_buf, sizeof enc_buf-1); close(p1[0]);
    int st1; wait(&st1);

    // fork decrypt
    int p2[2]; pipe(p2);
    if(fork()==0){ close(p2[0]); child_decrypt(p2[1], msg_len); }
    close(p2[1]);
    char dec_buf[128]={0}; read(p2[0], dec_buf, sizeof dec_buf-1); close(p2[0]);
    int st2; wait(&st2);

    // parse
    char tag1[4], tag2[4];
    double enc_ms=0, dec_ms=0, enc_cyc=0, dec_cyc=0;
    long enc_peak=0, dec_peak=0;
    sscanf(enc_buf, "%3s %lf %lf %ld", tag1, &enc_ms, &enc_cyc, &enc_peak);
    sscanf(dec_buf, "%3s %lf %lf %ld", tag2, &dec_ms, &dec_cyc, &dec_peak);

    // table
    printf("\n| Operation | Avg Time (ms) |   Avg Cycles | Peak Memory (KB) |\n");
    printf("|-----------|--------------:|-------------:|------------------:|\n");
    printf("| Encrypt   | %13.3f | %13.0f | %16ld |\n", enc_ms, enc_cyc, enc_peak);
    printf("| Decrypt   | %13.3f | %13.0f | %16ld |\n\n", dec_ms, dec_cyc, dec_peak);
    return 0;
}
