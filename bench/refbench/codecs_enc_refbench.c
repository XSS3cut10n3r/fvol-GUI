/*
 * Reference COMPRESSION throughput harness (zlib, libbz2, liblzma; libdeflate for context).
 *
 *   gcc -O3 -march=native -o codecs_enc_refbench codecs_enc_refbench.c -llzma -lz -lbz2 -ldeflate -lpthread
 *   codecs_enc_refbench CODEC LEVEL FILE RUNS [THREADS]
 *
 * CODEC: deflate | zlib | gzip | bz2 | xz | xz-mt | libdeflate
 *   xz      = lzma_easy_buffer_encode(preset, CRC64)            (python lzma.compress / LZMAFile)
 *   xz-mt   = lzma_stream_encoder_mt(preset, CRC64, THREADS)     (xz -T)
 *   bz2     = BZ2_bzBuffToBuffCompress(blockSize100k = LEVEL)   (python bz2)
 *   zlib    = compress2 / deflateInit2 (window 15, memLevel 8)  (python zlib / gzip)
 *   libdeflate = libdeflate_deflate_compress (raw deflate)
 * The input file is loaded into memory once. Each timed run compresses the whole input into
 * a preallocated worst-case buffer; best of RUNS. Every result is decompressed once and
 * compared with the input.
 * Prints: "c <codec> <level> <file> <in_bytes> <out_bytes> <best_ms> <MB/s> <cycles>"
 * (MB/s = 1e6 bytes of INPUT per second; cycles = user-mode cycles of the calling thread in
 * the fastest run, 0 if unavailable; set FASTVOL_PERF_PMU=cpu_atom when pinned to an E-core).
 */
#include <bzlib.h>
#include <libdeflate.h>
#include <lzma.h>
#include <zlib.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

/* User-mode cycles of this thread (FASTVOL_PERF_PMU=cpu_atom when pinned to an E-core). */
static int perf_fd = -1;
static void perf_open(void) {
    const char *pmu_name = getenv("FASTVOL_PERF_PMU");
    if (!pmu_name) pmu_name = getenv("RSVOL_PERF_PMU"); /* pre-rename name */
    char path[256];
    snprintf(path, sizeof path, "/sys/bus/event_source/devices/%s/type", pmu_name ? pmu_name : "cpu_core");
    unsigned long long pmu = 0;
    FILE *f = fopen(path, "r");
    if (f) {
        if (fscanf(f, "%llu", &pmu) != 1) pmu = 0;
        fclose(f);
    }
    struct perf_event_attr a;
    memset(&a, 0, sizeof a);
    a.type = PERF_TYPE_HARDWARE;
    a.size = sizeof a;
    a.config = PERF_COUNT_HW_CPU_CYCLES | (pmu << 32);
    a.disabled = 1;
    a.exclude_kernel = 1;
    a.exclude_hv = 1;
    perf_fd = syscall(__NR_perf_event_open, &a, 0, -1, -1, 0);
}
static void perf_start(void) {
    if (perf_fd >= 0) {
        ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0);
        ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
    }
}
static unsigned long long perf_stop(void) {
    unsigned long long v = 0;
    if (perf_fd >= 0) {
        ioctl(perf_fd, PERF_EVENT_IOC_DISABLE, 0);
        if (read(perf_fd, &v, 8) != 8) v = 0;
    }
    return v;
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

static int threads = 1;

/* Returns the compressed size or (size_t)-1. */
static size_t compress_buf(const char *codec, int level, const unsigned char *in, size_t n, unsigned char *out,
                           size_t cap) {
    if (!strcmp(codec, "deflate") || !strcmp(codec, "zlib") || !strcmp(codec, "gzip")) {
        int wbits = !strcmp(codec, "gzip") ? 31 : !strcmp(codec, "zlib") ? 15 : -15;
        z_stream z;
        memset(&z, 0, sizeof z);
        if (deflateInit2(&z, level, Z_DEFLATED, wbits, 8, Z_DEFAULT_STRATEGY) != Z_OK) return (size_t)-1;
        z.next_in = (unsigned char *)in;
        z.next_out = out;
        size_t left = n;
        int r;
        do {
            unsigned chunk = left > (1u << 30) ? (1u << 30) : (unsigned)left;
            z.avail_in = chunk;
            left -= chunk;
            z.avail_out = (unsigned)((cap - z.total_out) > (1u << 31) ? (1u << 31) : (cap - z.total_out));
            r = deflate(&z, left ? Z_NO_FLUSH : Z_FINISH);
        } while (left || r == Z_OK);
        size_t m = z.total_out;
        deflateEnd(&z);
        return r == Z_STREAM_END ? m : (size_t)-1;
    }
    if (!strcmp(codec, "libdeflate")) {
        struct libdeflate_compressor *c = libdeflate_alloc_compressor(level);
        size_t m = libdeflate_deflate_compress(c, in, n, out, cap);
        libdeflate_free_compressor(c);
        return m ? m : (size_t)-1;
    }
    if (!strcmp(codec, "bz2")) {
        unsigned int m = (unsigned int)cap;
        int r = BZ2_bzBuffToBuffCompress((char *)out, &m, (char *)in, (unsigned)n, level, 0, 0);
        return r == BZ_OK ? m : (size_t)-1;
    }
    if (!strcmp(codec, "xz")) {
        size_t pos = 0;
        lzma_ret r = lzma_easy_buffer_encode(level, LZMA_CHECK_CRC64, NULL, in, n, out, &pos, cap);
        return r == LZMA_OK ? pos : (size_t)-1;
    }
    if (!strcmp(codec, "xz-mt")) {
        lzma_mt mt;
        memset(&mt, 0, sizeof mt);
        mt.threads = threads;
        mt.preset = level;
        mt.check = LZMA_CHECK_CRC64;
        lzma_stream s = LZMA_STREAM_INIT;
        if (lzma_stream_encoder_mt(&s, &mt) != LZMA_OK) return (size_t)-1;
        s.next_in = in;
        s.avail_in = n;
        s.next_out = out;
        s.avail_out = cap;
        lzma_ret r = lzma_code(&s, LZMA_FINISH);
        size_t m = cap - s.avail_out;
        lzma_end(&s);
        return r == LZMA_STREAM_END ? m : (size_t)-1;
    }
    fprintf(stderr, "unknown codec %s\n", codec);
    exit(2);
}

static int verify(const char *codec, const unsigned char *in, size_t n, const unsigned char *c, size_t m) {
    unsigned char *d = malloc(n + 1);
    size_t got = (size_t)-1;
    if (!strcmp(codec, "deflate") || !strcmp(codec, "zlib") || !strcmp(codec, "gzip") ||
        !strcmp(codec, "libdeflate")) {
        int wbits = !strcmp(codec, "gzip") ? 31 : !strcmp(codec, "zlib") ? 15 : -15;
        z_stream z;
        memset(&z, 0, sizeof z);
        inflateInit2(&z, wbits);
        z.next_in = (unsigned char *)c;
        z.avail_in = (unsigned)m;
        z.next_out = d;
        z.avail_out = (unsigned)(n + 1);
        if (inflate(&z, Z_FINISH) == Z_STREAM_END) got = z.total_out;
        inflateEnd(&z);
    } else if (!strcmp(codec, "bz2")) {
        unsigned int dl = (unsigned)(n + 1);
        if (BZ2_bzBuffToBuffDecompress((char *)d, &dl, (char *)c, (unsigned)m, 0, 0) == BZ_OK) got = dl;
    } else {
        uint64_t memlimit = UINT64_MAX;
        size_t ip = 0, op = 0;
        if (lzma_stream_buffer_decode(&memlimit, 0, NULL, c, &ip, m, d, &op, n + 1) == LZMA_OK) got = op;
    }
    int ok = got == n && !memcmp(d, in, n);
    free(d);
    return ok;
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: %s CODEC LEVEL FILE RUNS [THREADS]\n", argv[0]);
        return 2;
    }
    const char *codec = argv[1];
    int level = atoi(argv[2]);
    size_t n;
    unsigned char *in = read_file(argv[3], &n);
    int runs = atoi(argv[4]);
    if (argc > 5) threads = atoi(argv[5]);
    size_t cap = n + n / 8 + (1 << 20);
    unsigned char *out = malloc(cap);
    memset(out, 0, cap); /* prefault */
    double best = 1e30;
    size_t m = 0;
    unsigned long long best_cyc = 0;
    perf_open();
    for (int i = 0; i < runs; i++) {
        perf_start();
        double t = now();
        m = compress_buf(codec, level, in, n, out, cap);
        double dt = now() - t;
        unsigned long long cyc = perf_stop();
        if (best_cyc == 0 || cyc < best_cyc) best_cyc = cyc;
        if (m == (size_t)-1) { fprintf(stderr, "compress failed\n"); return 1; }
        if (dt < best) best = dt;
    }
    if (!verify(codec, in, n, out, m)) { fprintf(stderr, "%s: roundtrip failed\n", argv[3]); return 1; }
    printf("c %s %d %s %zu %zu %.3f %.1f %llu\n", codec, level, argv[3], n, m, best * 1e3, n / best / 1e6, best_cyc);
    return 0;
}
