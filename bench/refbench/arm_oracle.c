// capstone oracle for the ARM / AArch64 differential harness (bench only, not part of the build).
//
//   gcc -O2 -o arm_oracle arm_oracle.c -lcapstone -lpthread
//
//   arm_oracle blocks ARCH START END BLOCKBITS [THREADS]
//        exhaustive: for every word in [START, END) (hex) print one line per block of
//        2^BLOCKBITS words: "block_index fnv64 valid_count" (see word_addr / fnv below)
//   arm_oracle dump  ARCH START COUNT            text of COUNT consecutive words
//   arm_oracle words ARCH FILE                   text of the hex words listed in FILE
//   arm_oracle rand  ARCH N SEED                 text of N pseudo-random words
//
// ARCH: arm64 | arm.  Each word is disassembled at address word_addr(word) (a 64-bit mix of
// the word, so pc-relative operands are exercised everywhere).  Text lines:
//   "%08x\t%016llx\t<mnemonic>\t<op_str>" or "%08x\t%016llx\t!" for invalid words.
#include <capstone/capstone.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t word_addr(uint32_t w) {
    uint64_t z = (uint64_t)w + 0x9E3779B97F4A7C15ull;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    z ^= z >> 31;
    return z & ~3ull;
}

static cs_arch g_arch;
static cs_mode g_mode;

static csh open_handle(void) {
    csh h;
    if (cs_open(g_arch, g_mode, &h) != CS_ERR_OK) {
        fprintf(stderr, "cs_open failed\n");
        exit(1);
    }
    return h;
}

// text of one word: "mnem\top" or "!" ; returns length written into buf
static int word_text(csh h, cs_insn *insn, uint32_t w, char *buf, size_t cap) {
    uint8_t b[4] = {w & 0xff, (w >> 8) & 0xff, (w >> 16) & 0xff, w >> 24};
    const uint8_t *code = b;
    size_t size = 4;
    uint64_t addr = word_addr(w);
    if (cs_disasm_iter(h, &code, &size, &addr, insn))
        return snprintf(buf, cap, "%s\t%s", insn->mnemonic, insn->op_str);
    buf[0] = '!';
    buf[1] = 0;
    return 1;
}

#define FNV_OFF 0xcbf29ce484222325ull
#define FNV_PRIME 0x100000001b3ull

static uint64_t fnv(uint64_t h, const char *s, int n) {
    for (int i = 0; i < n; i++) {
        h ^= (uint8_t)s[i];
        h *= FNV_PRIME;
    }
    h ^= '\n';
    h *= FNV_PRIME;
    return h;
}

struct job {
    uint64_t start, end;
    int bits;
    uint64_t next_block;
    uint64_t nblocks;
    uint64_t *hashes;
    uint64_t *valid;
    pthread_mutex_t mu;
};

static void *worker(void *arg) {
    struct job *j = arg;
    csh h = open_handle();
    cs_insn *insn = cs_malloc(h);
    char buf[512];
    for (;;) {
        pthread_mutex_lock(&j->mu);
        uint64_t bi = j->next_block++;
        pthread_mutex_unlock(&j->mu);
        if (bi >= j->nblocks)
            break;
        uint64_t s = j->start + (bi << j->bits);
        uint64_t e = s + (1ull << j->bits);
        if (e > j->end)
            e = j->end;
        uint64_t hv = FNV_OFF, nv = 0;
        for (uint64_t w = s; w < e; w++) {
            int n = word_text(h, insn, (uint32_t)w, buf, sizeof buf);
            if (buf[0] != '!')
                nv++;
            hv = fnv(hv, buf, n);
        }
        j->hashes[bi] = hv;
        j->valid[bi] = nv;
    }
    cs_free(insn, 1);
    cs_close(&h);
    return NULL;
}

static void set_arch(const char *a) {
    if (!strcmp(a, "arm64")) {
        g_arch = CS_ARCH_ARM64;
        g_mode = CS_MODE_ARM;
    } else if (!strcmp(a, "arm")) {
        g_arch = CS_ARCH_ARM;
        g_mode = CS_MODE_ARM;
    } else {
        fprintf(stderr, "bad arch %s\n", a);
        exit(2);
    }
}

static void print_word(csh h, cs_insn *insn, uint32_t w) {
    char buf[512];
    word_text(h, insn, w, buf, sizeof buf);
    printf("%08x\t%016llx\t%s\n", w, (unsigned long long)word_addr(w), buf);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: see source\n");
        return 2;
    }
    set_arch(argv[2]);
    if (!strcmp(argv[1], "blocks") && argc >= 6) {
        struct job j;
        memset(&j, 0, sizeof j);
        j.start = strtoull(argv[3], 0, 16);
        j.end = strtoull(argv[4], 0, 16);
        j.bits = atoi(argv[5]);
        int nt = argc > 6 ? atoi(argv[6]) : 16;
        j.nblocks = (j.end - j.start + (1ull << j.bits) - 1) >> j.bits;
        j.hashes = calloc(j.nblocks, 8);
        j.valid = calloc(j.nblocks, 8);
        pthread_mutex_init(&j.mu, 0);
        pthread_t th[256];
        if (nt > 256)
            nt = 256;
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (int i = 0; i < nt; i++)
            pthread_create(&th[i], 0, worker, &j);
        for (int i = 0; i < nt; i++)
            pthread_join(th[i], 0);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        fprintf(stderr, "oracle: %llu words in %.2fs\n", (unsigned long long)(j.end - j.start),
                (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) * 1e-9);
        for (uint64_t i = 0; i < j.nblocks; i++)
            printf("%llu %016llx %llu\n", (unsigned long long)((j.start >> j.bits) + i),
                   (unsigned long long)j.hashes[i], (unsigned long long)j.valid[i]);
        return 0;
    }
    csh h = open_handle();
    cs_insn *insn = cs_malloc(h);
    if (!strcmp(argv[1], "dump") && argc >= 5) {
        uint64_t s = strtoull(argv[3], 0, 16), n = strtoull(argv[4], 0, 0);
        for (uint64_t i = 0; i < n; i++)
            print_word(h, insn, (uint32_t)(s + i));
    } else if (!strcmp(argv[1], "words") && argc >= 4) {
        FILE *f = fopen(argv[3], "r");
        char line[256];
        while (f && fgets(line, sizeof line, f))
            print_word(h, insn, (uint32_t)strtoul(line, 0, 16));
    } else if (!strcmp(argv[1], "rand") && argc >= 5) {
        uint64_t n = strtoull(argv[3], 0, 0), x = strtoull(argv[4], 0, 0) | 1;
        for (uint64_t i = 0; i < n; i++) {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            print_word(h, insn, (uint32_t)(x >> 16));
        }
    }
    cs_free(insn, 1);
    cs_close(&h);
    return 0;
}
