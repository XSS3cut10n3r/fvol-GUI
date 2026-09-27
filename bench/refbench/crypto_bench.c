/* Reference benchmark harness for fastvol's src/crypto/ primitives, measured
 * in-process against OpenSSL's EVP API (the "beat the reference library" bar).
 *
 * Two workloads per primitive, matching src/crypto/bench.rs on the Rust side
 * exactly (same buffer sizes / iteration counts / repetition scheme):
 *   - bulk:  1 MiB buffer, processed BULK_REP_ITERS times per repetition with ONE
 *            context set up up front (raw sustained throughput; key/context setup
 *            amortized away).
 *   - small: SMALL_REP_ITERS independent calls per repetition over a 32-byte buffer,
 *            each one paying full context/key setup and teardown (this is the shape
 *            of the actual plugin workloads: hashdump/lsadump/cachedump process a
 *            handful of 16-56 byte values per registry key, never megabytes).
 *
 * Each workload is repeated REPS times (default 10, env CRYPTO_BENCH_REPS) and the
 * best repetition is reported, both as wall-clock throughput and as user-space core
 * cycles per byte / per op (perf_event_open cycle counter; "-" if unavailable).
 * Cycles are the number to compare on a shared, frequency-scaling machine.
 * CRYPTO_BENCH_ONLY=name1,name2 restricts the run to primitives whose name contains
 * one of the given substrings (e.g. CRYPTO_BENCH_ONLY=AES128,SHA1).
 *
 * Build: gcc -O3 -march=native -o refbench crypto_bench.c -lcrypto
 * Run pinned to one P-core, e.g.: taskset -c 4 ./refbench
 * (DES and RC4 live in OpenSSL 3's "legacy" provider, loaded explicitly below.)
 */
#define _GNU_SOURCE
#include <linux/perf_event.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#pragma GCC diagnostic ignored "-Wdeprecated-declarations" /* HMAC_CTX: same API python uses */

#define BULK_SIZE (1 * 1024 * 1024)
#define BULK_REP_ITERS 20
#define SMALL_SIZE 32
#define SMALL_REP_ITERS 50000

static int REPS = 10;
static const char *ONLY = NULL;
static int perf_fd = -1;

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void cycles_init(void) {
    struct perf_event_attr a;
    memset(&a, 0, sizeof a);
    a.type = PERF_TYPE_HARDWARE;
    a.size = sizeof a;
    a.config = PERF_COUNT_HW_CPU_CYCLES;
    a.exclude_kernel = 1;
    a.exclude_hv = 1;
    perf_fd = (int)syscall(SYS_perf_event_open, &a, 0, -1, -1, 0);
}

static double cycles(void) {
    long long v = 0;
    if (perf_fd < 0 || read(perf_fd, &v, sizeof v) != sizeof v) return 0;
    return (double)v;
}

static int wanted(const char *name) {
    if (!ONLY || !*ONLY) return 1;
    char buf[256];
    snprintf(buf, sizeof buf, "%s", ONLY);
    for (char *tok = strtok(buf, ","); tok; tok = strtok(NULL, ","))
        if (strstr(name, tok)) return 1;
    return 0;
}

/* Runs BODY REPS times; leaves the best wall time in best_s and the best cycle
 * count in best_c. */
#define BEST_OF(BODY)                                                              \
    do {                                                                           \
        best_s = 1e30;                                                             \
        best_c = 1e30;                                                             \
        for (int rep_ = 0; rep_ < REPS; rep_++) {                                  \
            double c0_ = cycles(), t0_ = now_s();                                  \
            BODY;                                                                  \
            double t_ = now_s() - t0_, c_ = cycles() - c0_;                        \
            if (t_ < best_s) best_s = t_;                                          \
            if (c_ < best_c) best_c = c_;                                          \
        }                                                                          \
    } while (0)

static void report_bulk(const char *name, double s, double c) {
    double mbps = ((double)BULK_SIZE * BULK_REP_ITERS / 1e6) / s;
    double cpb = c / ((double)BULK_SIZE * BULK_REP_ITERS);
    if (perf_fd >= 0)
        printf("%-16s bulk  %10.1f MB/s   %8.3f c/B\n", name, mbps, cpb);
    else
        printf("%-16s bulk  %10.1f MB/s   %8s c/B\n", name, mbps, "-");
    fflush(stdout);
}

static void report_small(const char *name, double s, double c, const char *note) {
    double opsps = SMALL_REP_ITERS / s;
    double cpo = c / SMALL_REP_ITERS;
    if (perf_fd >= 0)
        printf("%-16s small %10.0f ops/s  %8.1f c/op  (%s)\n", name, opsps, cpo, note);
    else
        printf("%-16s small %10.0f ops/s  %8s c/op  (%s)\n", name, opsps, "-", note);
    fflush(stdout);
}

static void fill(unsigned char *buf, size_t n, unsigned seed) {
    unsigned x = seed;
    for (size_t i = 0; i < n; i++) {
        x = x * 1103515245u + 12345u;
        buf[i] = (unsigned char)(x >> 16);
    }
}

/* --- digest (MD5/SHA1/SHA256) --- */

static void bench_digest(const char *name, const EVP_MD *md) {
    if (!wanted(name)) return;
    double best_s, best_c;
    unsigned char *buf = malloc(BULK_SIZE);
    fill(buf, BULK_SIZE, 1);
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outl;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    BEST_OF(for (int i = 0; i < BULK_REP_ITERS; i++) {
        EVP_DigestInit_ex(ctx, md, NULL);
        EVP_DigestUpdate(ctx, buf, BULK_SIZE);
        EVP_DigestFinal_ex(ctx, out, &outl);
    });
    report_bulk(name, best_s, best_c);
    EVP_MD_CTX_free(ctx);

    unsigned char small[SMALL_SIZE];
    fill(small, SMALL_SIZE, 2);
    BEST_OF(for (int i = 0; i < SMALL_REP_ITERS; i++) {
        EVP_MD_CTX *c = EVP_MD_CTX_new();
        EVP_DigestInit_ex(c, md, NULL);
        EVP_DigestUpdate(c, small, SMALL_SIZE);
        EVP_DigestFinal_ex(c, out, &outl);
        EVP_MD_CTX_free(c);
    });
    report_small(name, best_s, best_c, "incl. ctx new/free each call");
    free(buf);
}

/* --- HMAC --- */

static void bench_hmac(const char *name, const EVP_MD *md) {
    if (!wanted(name)) return;
    double best_s, best_c;
    unsigned char key[32];
    fill(key, sizeof(key), 3);
    unsigned char *buf = malloc(BULK_SIZE);
    fill(buf, BULK_SIZE, 4);
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outl;

    HMAC_CTX *ctx = HMAC_CTX_new();
    BEST_OF(for (int i = 0; i < BULK_REP_ITERS; i++) {
        HMAC_Init_ex(ctx, key, sizeof(key), md, NULL);
        HMAC_Update(ctx, buf, BULK_SIZE);
        HMAC_Final(ctx, out, &outl);
    });
    report_bulk(name, best_s, best_c);
    HMAC_CTX_free(ctx);

    unsigned char small[SMALL_SIZE];
    fill(small, SMALL_SIZE, 5);
    BEST_OF(for (int i = 0; i < SMALL_REP_ITERS; i++) {
        HMAC_CTX *c = HMAC_CTX_new();
        HMAC_Init_ex(c, key, sizeof(key), md, NULL);
        HMAC_Update(c, small, SMALL_SIZE);
        HMAC_Final(c, out, &outl);
        HMAC_CTX_free(c);
    });
    report_small(name, best_s, best_c, "incl. ctx new/free each call");
    free(buf);
}

/* --- ciphers (RC4 / DES-ECB / AES ECB+CBC) --- */

static void bench_cipher(const char *name, const EVP_CIPHER *cipher, int is_cbc, int decrypt) {
    if (!wanted(name)) return;
    double best_s, best_c;
    unsigned char key[32];
    fill(key, sizeof(key), 6);
    unsigned char iv[16] = {0};

    unsigned char *in = malloc(BULK_SIZE);
    unsigned char *out = malloc(BULK_SIZE + 32);
    fill(in, BULK_SIZE, 7);
    int outl;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (decrypt)
        EVP_DecryptInit_ex(ctx, cipher, NULL, key, is_cbc ? iv : NULL);
    else
        EVP_EncryptInit_ex(ctx, cipher, NULL, key, is_cbc ? iv : NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    BEST_OF(for (int i = 0; i < BULK_REP_ITERS; i++) {
        if (decrypt)
            EVP_DecryptUpdate(ctx, out, &outl, in, BULK_SIZE);
        else
            EVP_EncryptUpdate(ctx, out, &outl, in, BULK_SIZE);
    });
    report_bulk(name, best_s, best_c);
    EVP_CIPHER_CTX_free(ctx);

    unsigned char small_in[SMALL_SIZE], small_out[SMALL_SIZE + 32];
    fill(small_in, SMALL_SIZE, 8);
    BEST_OF(for (int i = 0; i < SMALL_REP_ITERS; i++) {
        EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
        if (decrypt) {
            EVP_DecryptInit_ex(c, cipher, NULL, key, is_cbc ? iv : NULL);
            EVP_CIPHER_CTX_set_padding(c, 0);
            EVP_DecryptUpdate(c, small_out, &outl, small_in, SMALL_SIZE);
        } else {
            EVP_EncryptInit_ex(c, cipher, NULL, key, is_cbc ? iv : NULL);
            EVP_CIPHER_CTX_set_padding(c, 0);
            EVP_EncryptUpdate(c, small_out, &outl, small_in, SMALL_SIZE);
        }
        EVP_CIPHER_CTX_free(c);
    });
    report_small(name, best_s, best_c, "incl. ctx new/free + key setup each call");
    free(in);
    free(out);
}

int main(void) {
    const char *reps = getenv("CRYPTO_BENCH_REPS");
    if (reps && atoi(reps) > 0) REPS = atoi(reps);
    ONLY = getenv("CRYPTO_BENCH_ONLY");
    cycles_init();

    /* RC4 and DES-ECB live in the "legacy" provider under OpenSSL 3.x. */
    OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER *legacy = OSSL_PROVIDER_load(NULL, "legacy");
    if (!legacy) {
        fprintf(stderr, "warning: could not load legacy provider; RC4/DES skipped\n");
    }

    bench_digest("MD5", EVP_md5());
    bench_digest("SHA1", EVP_sha1());
    bench_digest("SHA256", EVP_sha256());

    bench_hmac("HMAC-MD5", EVP_md5());
    bench_hmac("HMAC-SHA1", EVP_sha1());
    bench_hmac("HMAC-SHA256", EVP_sha256());

    if (legacy) {
        bench_cipher("RC4", EVP_rc4(), 0, 1);
        bench_cipher("DES-ECB", EVP_des_ecb(), 0, 1);
    }

    bench_cipher("AES128-ECB-dec", EVP_aes_128_ecb(), 0, 1);
    bench_cipher("AES128-CBC-dec", EVP_aes_128_cbc(), 1, 1);
    bench_cipher("AES256-ECB-dec", EVP_aes_256_ecb(), 0, 1);
    bench_cipher("AES256-CBC-dec", EVP_aes_256_cbc(), 1, 1);

    return 0;
}
