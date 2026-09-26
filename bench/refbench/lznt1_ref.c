/*
 * LZNT1 reference harness: ntfs-3g, libfwnt (libyal) and Wine decoders, ntfs-3g compressor.
 * Built by lznt1_ref.sh, which downloads the (GPL/LGPL, not vendored) sources and extracts
 * the LZNT1 functions into ntfs3g_lznt1.inc / wine_lznt1.inc next to the binary.
 *
 *   lznt1_ref compress IN OUT              ntfs-3g's compressor (4096-byte blocks, as NTFS)
 *   lznt1_ref DECODER FILE RUNS [EXPECTED] decode throughput, DECODER: ntfs3g | libfwnt | wine
 *
 * Methodology as codecs_refbench.c: the compressed file is loaded once; each timed run allocates a
 * fresh output buffer of the exact uncompressed size (like the Rust API, which returns a new
 * Vec) and decodes the whole stream; the buffer is freed outside the timed region.
 * Prints "c lznt1-<decoder> <file> <out_bytes> <best_ms> <MB/s> <cycles> <instructions>
 * <branch_misses>" (user-mode perf counters of the run with the fewest cycles, 0 if
 * perf_event_open is unavailable).
 */
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

/* ---- ntfs-3g shims (libntfs-3g/compress.c: ntfs_compress_block, ntfs_decompress) ---- */
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef int16_t s16;
typedef uint16_t le16;
#define ntfs_malloc malloc
#define ntfs_log_trace(...) ((void)0)
#define ntfs_log_debug(...) ((void)0)
#define ntfs_log_perror(...) ((void)0)
#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif
#include "ntfs3g_lznt1.inc"
#undef min

/* ---- Wine shims (dlls/ntdll/rtl.c: lznt1_decompress_chunk, lznt1_decompress) ---- */
typedef unsigned char UCHAR;
typedef unsigned int ULONG;
typedef unsigned short WORD;
typedef int NTSTATUS;
#define STATUS_SUCCESS 0
#define STATUS_ACCESS_VIOLATION ((NTSTATUS)0xC0000005)
#define STATUS_BAD_COMPRESSION_BUFFER ((NTSTATUS)0xC0000242)
#define min(a, b) ((a) < (b) ? (a) : (b))
#include "wine_lznt1.inc"
#undef min

/* ---- libfwnt (libfwnt/libfwnt_lznt1.c, compiled separately with shim headers) ---- */
int libfwnt_lznt1_decompress(const uint8_t *compressed_data, size_t compressed_data_size,
                             uint8_t *uncompressed_data, size_t *uncompressed_data_size, void **error);

static int perf_fds[3] = {-1, -1, -1};

static void perf_open(void) {
    static const unsigned long long cfg[3] = {PERF_COUNT_HW_CPU_CYCLES, PERF_COUNT_HW_INSTRUCTIONS,
                                              PERF_COUNT_HW_BRANCH_MISSES};
    unsigned long long pmu = 0;
    FILE *f = fopen("/sys/bus/event_source/devices/cpu_core/type", "r");
    if (f) {
        if (fscanf(f, "%llu", &pmu) != 1) pmu = 0;
        fclose(f);
    }
    for (int i = 0; i < 3; i++) {
        struct perf_event_attr a;
        memset(&a, 0, sizeof a);
        a.type = PERF_TYPE_HARDWARE;
        a.size = sizeof a;
        a.config = cfg[i] | (pmu << 32);
        a.disabled = 1;
        a.exclude_kernel = 1;
        a.exclude_hv = 1;
        perf_fds[i] = syscall(__NR_perf_event_open, &a, 0, -1, -1, 0);
    }
}

static void perf_start(void) {
    for (int i = 0; i < 3; i++)
        if (perf_fds[i] >= 0) {
            ioctl(perf_fds[i], PERF_EVENT_IOC_RESET, 0);
            ioctl(perf_fds[i], PERF_EVENT_IOC_ENABLE, 0);
        }
}

static void perf_stop(unsigned long long v[3]) {
    for (int i = 0; i < 3; i++) {
        v[i] = 0;
        if (perf_fds[i] >= 0) {
            ioctl(perf_fds[i], PERF_EVENT_IOC_DISABLE, 0);
            if (read(perf_fds[i], &v[i], 8) != 8) v[i] = 0;
        }
    }
}

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static unsigned char *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(2); }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *buf = malloc(n ? n : 1);
    if (n && fread(buf, 1, n, f) != (size_t)n) { perror("read"); exit(2); }
    fclose(f);
    *len = n;
    return buf;
}

/* Output size without padding (headers only; every chunk of the benchmark files is full). */
static size_t stream_size(const unsigned char *in, size_t n) {
    size_t ip = 0, out = 0;
    while (n - ip >= 2) {
        unsigned h = in[ip] | in[ip + 1] << 8;
        if (!h) break;
        unsigned size = (h & 0xFFF) + 1;
        ip += 2 + size;
        if (ip > n) return (size_t)-1;
        out += (h & 0x8000) ? 4096 : size;
    }
    return out;
}

/* Returns bytes produced, (size_t)-1 on error. */
static size_t decode(const char *dec, unsigned char *in, size_t in_len, unsigned char *out, size_t cap) {
    if (!strcmp(dec, "ntfs3g")) {
        /* Designed for one compression unit; handles any number of full 4 KiB sub-blocks. */
        return ntfs_decompress(out, cap, in, in_len) ? (size_t)-1 : cap;
    }
    if (!strcmp(dec, "libfwnt")) {
        size_t n = cap;
        return libfwnt_lznt1_decompress(in, in_len, out, &n, NULL) == 1 ? n : (size_t)-1;
    }
    if (!strcmp(dec, "wine")) {
        ULONG n = 0;
        return lznt1_decompress(out, cap, in, in_len, 0, &n, NULL) ? (size_t)-1 : n;
    }
    fprintf(stderr, "unknown decoder %s\n", dec);
    exit(2);
}

static int compress_file(const char *inp, const char *outp) {
    size_t n;
    unsigned char *in = read_file(inp, &n);
    unsigned char *out = malloc(n / 4096 * 4100 + 4100 + 2);
    size_t o = 0;
    for (size_t i = 0; i < n; i += 4096) {
        int bs = n - i < 4096 ? (int)(n - i) : 4096;
        unsigned x = ntfs_compress_block((const char *)in + i, bs, (char *)out + o);
        if (!x) { fprintf(stderr, "compress failed\n"); return 1; }
        if (x == 4098 && bs < 4096) {
            /* ntfs-3g stores an incompressible partial block padded to 4096: store it exact. */
            out[o] = (bs - 1) & 0xFF;
            out[o + 1] = 0x30 | ((bs - 1) >> 8);
            x = bs + 2;
        }
        o += x;
    }
    FILE *f = fopen(outp, "wb");
    if (!f || fwrite(out, 1, o, f) != o || fclose(f)) { perror(outp); return 1; }
    fprintf(stderr, "%s: %zu -> %zu bytes (%.1f%%)\n", inp, n, o, 100.0 * o / (n ? n : 1));
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 4 && !strcmp(argv[1], "compress")) return compress_file(argv[2], argv[3]);
    if (argc < 4) {
        fprintf(stderr, "usage: %s compress IN OUT | %s ntfs3g|libfwnt|wine FILE RUNS [EXPECTED]\n", argv[0],
                argv[0]);
        return 2;
    }
    const char *dec = argv[1];
    size_t in_len;
    unsigned char *in = read_file(argv[2], &in_len);
    int runs = atoi(argv[3]);
    size_t n = stream_size(in, in_len);
    if (n == (size_t)-1) { fprintf(stderr, "%s: truncated stream\n", argv[2]); return 1; }
    unsigned char *probe = malloc(n ? n : 1);
    if (decode(dec, in, in_len, probe, n) != n) { fprintf(stderr, "%s: %s decode error\n", argv[2], dec); return 1; }
    if (argc > 4) {
        size_t elen;
        unsigned char *exp = read_file(argv[4], &elen);
        if (elen != n || memcmp(exp, probe, n)) {
            fprintf(stderr, "%s: %s output differs from %s\n", argv[2], dec, argv[4]);
            return 1;
        }
        free(exp);
    }
    free(probe);
    double best = 1e30;
    unsigned sink = 0;
    unsigned long long best_c[3] = {0, 0, 0}, c[3];
    perf_open();
    for (int i = 0; i < runs; i++) {
        perf_start();
        double t = now();
        unsigned char *out = malloc(n ? n : 1);
        size_t m = decode(dec, in, in_len, out, n);
        double dt = now() - t;
        perf_stop(c);
        if (best_c[0] == 0 || c[0] < best_c[0]) memcpy(best_c, c, sizeof c);
        if (m != n) { fprintf(stderr, "decode failed\n"); return 1; }
        sink += n ? out[n / 2] : 0;
        free(out);
        if (dt < best) best = dt;
    }
    printf("c lznt1-%s %s %zu %.3f %.1f %llu %llu %llu\n", dec, argv[2], n, best * 1e3, n / best / 1e6, best_c[0],
           best_c[1], best_c[2]);
    return sink == 0xFFFFFFFF;
}
