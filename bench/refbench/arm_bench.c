// libcapstone reference benchmark for the ARM / AArch64 disassemblers (bench only).
//
//   gcc -O3 -march=native -o arm_bench arm_bench.c -lcapstone
//   arm_bench ARCH N [FILE]
//
// Decodes + formats N pseudo-random words (same xorshift generator as
// examples/disasm_diff_arm.rs `bench`) one instruction at a time with cs_disasm_iter (detail off),
// or the 4-byte words of FILE (a raw code blob, linear sweep restarting after invalid words).
// Reports the best of 3 rounds in words/s and valid instructions/s.
#include <capstone/capstone.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec * 1e-9;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: arm_bench arm64|arm N [FILE]\n");
        return 2;
    }
    cs_arch arch = !strcmp(argv[1], "arm64") ? CS_ARCH_ARM64 : CS_ARCH_ARM;
    size_t n = strtoull(argv[2], 0, 0);
    uint32_t *words = malloc(n * 4);
    if (argc > 3) {
        // real code: the file's words, repeated cyclically up to N words
        FILE *f = fopen(argv[3], "rb");
        size_t got = f ? fread(words, 4, n, f) : 0;
        if (f)
            fclose(f);
        if (got == 0)
            return 1;
        for (size_t i = got; i < n; i++)
            words[i] = words[i % got];
    } else {
        uint64_t x = 1;
        for (size_t i = 0; i < n; i++) {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            words[i] = (uint32_t)(x >> 16);
        }
    }
    csh h;
    if (cs_open(arch, CS_MODE_ARM, &h) != CS_ERR_OK)
        return 1;
    cs_insn *insn = cs_malloc(h);
    double best = 1e30;
    size_t valid = 0, bytes = 0;
    for (int round = 0; round < 3; round++) {
        double t0 = now();
        valid = 0;
        bytes = 0;
        for (size_t i = 0; i < n; i++) {
            const uint8_t *code = (const uint8_t *)&words[i];
            size_t size = 4;
            uint64_t addr = 0x10000;
            if (cs_disasm_iter(h, &code, &size, &addr, insn)) {
                valid++;
                bytes += strlen(insn->mnemonic) + strlen(insn->op_str) + 1;
            }
        }
        double dt = now() - t0;
        if (dt < best)
            best = dt;
    }
    printf("capstone %s: %zu words (%zu valid) best %.3fs = %.2f M words/s, %.2f M valid insn/s (%zu bytes)\n",
           argv[1], n, valid, best, n / best / 1e6, valid / best / 1e6, bytes);
    cs_free(insn, 1);
    cs_close(&h);
    return 0;
}
