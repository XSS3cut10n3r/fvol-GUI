/* Reference benchmark harness for rsvol's src/crypto/ primitives, measured
 * in-process against OpenSSL's EVP API (the "beat the reference library" bar).
 *
 * Two workloads per primitive, matching src/crypto/bench_ref.rs on the Rust side
 * exactly (same buffer sizes / iteration counts):
 *   - bulk:  1 MiB buffer, processed BULK_ITERS times with ONE context set up
 *            up front (raw sustained throughput; key/context setup amortized away).
 *   - small: SMALL_ITERS independent calls over a 32-byte buffer, each one paying
 *            full context/key setup and teardown (this is the shape of the actual
 *            plugin workloads: hashdump/lsadump/cachedump process a handful of
 *            16-56 byte values per registry key, never megabytes).
 *
 * Build: gcc -O3 -march=native -o refbench bench.c -lcrypto
 * (DES and RC4 live in OpenSSL 3's "legacy" provider, loaded explicitly below.)
 */
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BULK_SIZE (1 * 1024 * 1024)
#define BULK_ITERS 200
#define SMALL_SIZE 32
#define SMALL_ITERS 500000

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
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
    unsigned char *buf = malloc(BULK_SIZE);
    fill(buf, BULK_SIZE, 1);
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outl;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    double t0 = now_s();
    for (int i = 0; i < BULK_ITERS; i++) {
        EVP_DigestInit_ex(ctx, md, NULL);
        EVP_DigestUpdate(ctx, buf, BULK_SIZE);
        EVP_DigestFinal_ex(ctx, out, &outl);
    }
    double t1 = now_s();
    double mbps = ((double)BULK_SIZE * BULK_ITERS / 1e6) / (t1 - t0);
    printf("%-12s bulk  %10.1f MB/s\n", name, mbps);
    EVP_MD_CTX_free(ctx);

    unsigned char small[SMALL_SIZE];
    fill(small, SMALL_SIZE, 2);
    t0 = now_s();
    for (int i = 0; i < SMALL_ITERS; i++) {
        EVP_MD_CTX *c = EVP_MD_CTX_new();
        EVP_DigestInit_ex(c, md, NULL);
        EVP_DigestUpdate(c, small, SMALL_SIZE);
        EVP_DigestFinal_ex(c, out, &outl);
        EVP_MD_CTX_free(c);
    }
    t1 = now_s();
    double opsps = SMALL_ITERS / (t1 - t0);
    printf("%-12s small %10.0f ops/s (incl. ctx new/free each call)\n", name, opsps);
    free(buf);
}

/* --- HMAC --- */

static void bench_hmac(const char *name, const EVP_MD *md) {
    unsigned char key[32];
    fill(key, sizeof(key), 3);
    unsigned char *buf = malloc(BULK_SIZE);
    fill(buf, BULK_SIZE, 4);
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outl;

    HMAC_CTX *ctx = HMAC_CTX_new();
    double t0 = now_s();
    for (int i = 0; i < BULK_ITERS; i++) {
        HMAC_Init_ex(ctx, key, sizeof(key), md, NULL);
        HMAC_Update(ctx, buf, BULK_SIZE);
        HMAC_Final(ctx, out, &outl);
    }
    double t1 = now_s();
    double mbps = ((double)BULK_SIZE * BULK_ITERS / 1e6) / (t1 - t0);
    printf("%-12s bulk  %10.1f MB/s\n", name, mbps);
    HMAC_CTX_free(ctx);

    unsigned char small[SMALL_SIZE];
    fill(small, SMALL_SIZE, 5);
    t0 = now_s();
    for (int i = 0; i < SMALL_ITERS; i++) {
        HMAC_CTX *c = HMAC_CTX_new();
        HMAC_Init_ex(c, key, sizeof(key), md, NULL);
        HMAC_Update(c, small, SMALL_SIZE);
        HMAC_Final(c, out, &outl);
        HMAC_CTX_free(c);
    }
    t1 = now_s();
    double opsps = SMALL_ITERS / (t1 - t0);
    printf("%-12s small %10.0f ops/s (incl. ctx new/free each call)\n", name, opsps);
    free(buf);
}

/* --- ciphers (RC4 / DES-ECB / AES ECB+CBC) --- */

static void bench_cipher(const char *name, const EVP_CIPHER *cipher, int keylen,
                          int is_cbc, int decrypt) {
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

    double t0 = now_s();
    for (int i = 0; i < BULK_ITERS; i++) {
        if (decrypt)
            EVP_DecryptUpdate(ctx, out, &outl, in, BULK_SIZE);
        else
            EVP_EncryptUpdate(ctx, out, &outl, in, BULK_SIZE);
    }
    double t1 = now_s();
    double mbps = ((double)BULK_SIZE * BULK_ITERS / 1e6) / (t1 - t0);
    printf("%-12s bulk  %10.1f MB/s\n", name, mbps);
    EVP_CIPHER_CTX_free(ctx);

    unsigned char small_in[SMALL_SIZE], small_out[SMALL_SIZE + 32];
    fill(small_in, SMALL_SIZE, 8);
    t0 = now_s();
    for (int i = 0; i < SMALL_ITERS; i++) {
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
    }
    t1 = now_s();
    double opsps = SMALL_ITERS / (t1 - t0);
    printf("%-12s small %10.0f ops/s (incl. ctx new/free + key setup each call)\n", name,
           opsps);
    free(in);
    free(out);
}

int main(void) {
    /* RC4 and DES-ECB live in the "legacy" provider under OpenSSL 3.x. */
    OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER *legacy = OSSL_PROVIDER_load(NULL, "legacy");
    if (!legacy) {
        fprintf(stderr, "warning: could not load legacy provider; RC4/DES skipped\n");
    }

    printf("--- digests ---\n");
    bench_digest("MD5", EVP_md5());
    bench_digest("SHA1", EVP_sha1());
    bench_digest("SHA256", EVP_sha256());

    printf("--- hmac ---\n");
    bench_hmac("HMAC-MD5", EVP_md5());
    bench_hmac("HMAC-SHA1", EVP_sha1());
    bench_hmac("HMAC-SHA256", EVP_sha256());

    if (legacy) {
        printf("--- rc4/des (legacy provider) ---\n");
        bench_cipher("RC4", EVP_rc4(), 16, 0, 1);
        bench_cipher("DES-ECB", EVP_des_ecb(), 8, 0, 1);
    }

    printf("--- aes ---\n");
    bench_cipher("AES128-ECB-dec", EVP_aes_128_ecb(), 16, 0, 1);
    bench_cipher("AES128-CBC-dec", EVP_aes_128_cbc(), 16, 1, 1);
    bench_cipher("AES256-ECB-dec", EVP_aes_256_ecb(), 32, 0, 1);
    bench_cipher("AES256-CBC-dec", EVP_aes_256_cbc(), 32, 1, 1);

    return 0;
}
