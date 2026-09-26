/* Reference benchmark for rsvol's x86 disassembler (src/disasm/x86), measured in-process
 * against libcapstone 5 (the "beat the reference library" bar). Rust side: examples/disasm_bench.rs
 * (identical corpus, methodology and output format).
 *
 * Corpus: flat files from bench/scripts/disasm_bench_corpus.py: DIR/real{32,64}.bin (section
 * bytes concatenated) + DIR/real{32,64}.idx (`vaddr_hex<TAB>len` per section). Each section is
 * swept linearly; after an undecodable instruction the sweep skips one byte and continues.
 *
 * Workloads (best of N passes over the whole corpus, per mode):
 *   text    cs_disasm_iter, detail off: mnemonic + op_str text (lengths summed as a checksum)
 *   line    text + the volatility renderer line "\n{addr:#x}:\t{mnemonic}\t{op_str}" appended to
 *           a reused buffer (format_capstone equivalent)
 *   detail  cs_disasm_iter with CS_OPT_DETAIL on (structured operands with access flags,
 *           implicit registers); compare with the Rust "detail" (native structured operands)
 *   cdetail detail + cs_regs_access(); the Rust "cdetail" (decode + detail_operands +
 *           implicit_regs + regs_access) computes the same view and has the same check
 *   len     cheapest capstone path: detail off, only insn->size used
 *
 * Build/run: bench/refbench/capstone_bench.sh  (gcc -O3 -march=native ... -lcapstone)
 */
#include <capstone/capstone.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    uint64_t addr;
    size_t off, len;
} chunk_t;

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static uint8_t *load_file(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc(sz > 0 ? (size_t)sz : 1);
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) { fclose(f); free(buf); return NULL; }
    fclose(f);
    *n = (size_t)sz;
    return buf;
}

static chunk_t *load_idx(const char *path, size_t total, size_t *nch) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    size_t cap = 64, n = 0, off = 0;
    chunk_t *c = malloc(cap * sizeof *c);
    unsigned long long a;
    unsigned long long l;
    while (fscanf(f, "%llx %llu", &a, &l) == 2) {
        if (n == cap) { cap *= 2; c = realloc(c, cap * sizeof *c); }
        if (off + l > total) break;
        c[n].addr = a; c[n].off = off; c[n].len = (size_t)l;
        off += l;
        n++;
    }
    fclose(f);
    *nch = n;
    return c;
}

/* "0x..." lowercase hex, returns bytes written */
static inline size_t put_hex(char *p, uint64_t v) {
    static const char H[] = "0123456789abcdef";
    char tmp[16];
    int i = 16;
    do { tmp[--i] = H[v & 15]; v >>= 4; } while (v);
    p[0] = '0'; p[1] = 'x';
    memcpy(p + 2, tmp + i, 16 - i);
    return 2 + 16 - i;
}

enum { W_TEXT, W_LINE, W_DETAIL, W_CDETAIL, W_LEN, W_N };
static const char *WNAME[] = {"text", "line", "detail", "cdetail", "len"};

/* exact token match in a comma separated list */
static int has_work(const char *only, const char *name) {
    size_t n = strlen(name);
    for (const char *p = only; p && *p;) {
        const char *e = strchr(p, ',');
        size_t k = e ? (size_t)(e - p) : strlen(p);
        if (k == n && strncmp(p, name, n) == 0) return 1;
        p = e ? e + 1 : NULL;
    }
    return 0;
}

typedef struct {
    uint64_t insns, bad, bytes, check;
} result_t;

static result_t run(csh h, int w, const uint8_t *data, const chunk_t *ch, size_t nch, char *line, size_t line_cap) {
    result_t r = {0, 0, 0, 0};
    cs_insn *insn = cs_malloc(h);
    for (size_t c = 0; c < nch; c++) {
        const uint8_t *code = data + ch[c].off;
        size_t size = ch[c].len;
        uint64_t addr = ch[c].addr;
        size_t lp = 0;
        r.bytes += size;
        while (size > 0) {
            if (cs_disasm_iter(h, &code, &size, &addr, insn)) {
                r.insns++;
                switch (w) {
                case W_TEXT:
                    r.check += strlen(insn->mnemonic) + strlen(insn->op_str);
                    break;
                case W_LINE: {
                    if (lp + 512 > line_cap) { r.check += lp; lp = 0; }
                    char *p = line + lp;
                    *p++ = '\n';
                    p += put_hex(p, insn->address);
                    *p++ = ':'; *p++ = '\t';
                    size_t k = strlen(insn->mnemonic);
                    memcpy(p, insn->mnemonic, k); p += k;
                    *p++ = '\t';
                    k = strlen(insn->op_str);
                    memcpy(p, insn->op_str, k); p += k;
                    lp = (size_t)(p - line);
                    break;
                }
                case W_DETAIL:
                    /* operands + implicit registers */
                    r.check += insn->detail->x86.op_count + insn->detail->regs_read_count +
                               insn->detail->regs_write_count;
                    break;
                case W_CDETAIL: {
                    cs_regs rr, ww;
                    uint8_t nr = 0, nw = 0;
                    cs_regs_access(h, insn, rr, &nr, ww, &nw);
                    /* operands + implicit registers + regs_access: equals the Rust check */
                    r.check += insn->detail->x86.op_count + insn->detail->regs_read_count +
                               insn->detail->regs_write_count + nr + nw;
                    break;
                }
                default:
                    r.check += insn->size;
                    break;
                }
            } else {
                code++; size--; addr++;
                r.bad++;
            }
        }
        r.check += lp;
    }
    cs_free(insn, 1);
    return r;
}

int main(int argc, char **argv) {
    const char *dir = argc > 1 ? argv[1] : "/home/user/rs-vol/testdata/scratch/disasm/ref/bin";
    int passes = argc > 2 ? atoi(argv[2]) : 5;
    const char *only = argc > 3 ? argv[3] : NULL; /* e.g. "text,len" */
    size_t line_cap = 1 << 20;
    char *line = malloc(line_cap);
    printf("# capstone %d.%d  passes=%d  corpus=%s\n", CS_API_MAJOR, CS_API_MINOR, passes, dir);
    printf("%-6s %-7s %10s %10s %10s %9s %12s %9s %s\n", "side", "work", "mode", "insns", "bytes", "best_s",
           "insn/s", "MB/s", "check");
    for (int bits = 32; bits <= 64; bits += 32) {
        char p1[4096], p2[4096];
        snprintf(p1, sizeof p1, "%s/real%d.bin", dir, bits);
        snprintf(p2, sizeof p2, "%s/real%d.idx", dir, bits);
        size_t n = 0, nch = 0;
        uint8_t *data = load_file(p1, &n);
        if (!data) { fprintf(stderr, "cannot read %s\n", p1); return 1; }
        chunk_t *ch = load_idx(p2, n, &nch);
        if (!ch) { fprintf(stderr, "cannot read %s\n", p2); return 1; }
        csh h;
        if (cs_open(CS_ARCH_X86, bits == 64 ? CS_MODE_64 : CS_MODE_32, &h) != CS_ERR_OK) return 1;
        for (int w = 0; w < W_N; w++) {
            if (only && !has_work(only, WNAME[w])) continue;
            cs_option(h, CS_OPT_DETAIL, (w == W_DETAIL || w == W_CDETAIL) ? CS_OPT_ON : CS_OPT_OFF);
            double best = 1e30;
            result_t r = {0};
            for (int p = 0; p < passes; p++) {
                double t0 = now_s();
                r = run(h, w, data, ch, nch, line, line_cap);
                double t = now_s() - t0;
                if (t < best) best = t;
            }
            printf("%-6s %-7s %10s %10llu %10llu %9.4f %12.0f %9.1f %llu\n", "cs", WNAME[w],
                   bits == 64 ? "x86-64" : "x86-32", (unsigned long long)r.insns,
                   (unsigned long long)r.bytes, best, r.insns / best, r.bytes / best / 1e6,
                   (unsigned long long)r.check);
            fflush(stdout);
        }
        cs_close(&h);
        free(ch);
        free(data);
    }
    free(line);
    return 0;
}
