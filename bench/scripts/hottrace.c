// hottrace: single-step a command (all of its threads) with ptrace and report which code of the
// executable ran. Used by gen-symbol-order.sh to build the hot-text ordering (.cargo/symbol-order.txt).
//
// Output (to -o FILE, default stdout), one line per distinct instruction address inside the
// executable's own mappings:  <file offset, hex> <first-execution index> <execution count>
// The command's stdout/stderr go to /dev/null. Summary on stderr.
//
// Usage: hottrace [-o OUT] -- cmd args...        (build: cc -O2 -o hottrace hottrace.c)
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

#define HB (1u << 23)
static uint64_t *hk;   // rip
static uint64_t *hfirst;
static uint32_t *hn;

static void add(uint64_t k, uint64_t seq) {
    uint64_t h = (k * 0x9E3779B97F4A7C15ull) >> 41;
    while (hk[h] && hk[h] != k) h = (h + 1) & (HB - 1);
    if (!hk[h]) { hk[h] = k; hfirst[h] = seq; }
    hn[h]++;
}

struct map { uint64_t lo, hi, off; char name[512]; };
static struct map maps[1024];
static int nmaps;

static void read_maps(pid_t pid) {
    char p[64]; snprintf(p, sizeof p, "/proc/%d/maps", pid);
    FILE *f = fopen(p, "r"); char line[1200];
    nmaps = 0;
    while (f && fgets(line, sizeof line, f) && nmaps < 1024) {
        struct map *m = &maps[nmaps]; char perm[8], dev[32]; unsigned long ino; m->name[0] = 0;
        if (sscanf(line, "%lx-%lx %7s %lx %31s %lu %511[^\n]", &m->lo, &m->hi, perm, &m->off, dev, &ino, m->name) >= 6) {
            char *s = m->name; while (*s == ' ') s++; memmove(m->name, s, strlen(s) + 1); nmaps++;
        }
    }
    if (f) fclose(f);
}

int main(int argc, char **argv) {
    const char *out = NULL; int i = 1;
    for (; i < argc; i++) {
        if (!strcmp(argv[i], "--")) { i++; break; }
        if (!strcmp(argv[i], "-o") && i + 1 < argc) out = argv[++i];
    }
    if (i >= argc) { fprintf(stderr, "usage: hottrace [-o OUT] -- cmd args...\n"); return 2; }
    char **cmd = argv + i;
    hk = calloc(HB, 8); hfirst = calloc(HB, 8); hn = calloc(HB, 4);
    if (!hk || !hfirst || !hn) { perror("calloc"); return 1; }
    char exe[4096];
    if (!realpath(cmd[0], exe)) { perror(cmd[0]); return 1; }
    pid_t pid = fork();
    if (pid == 0) {
        int nul = open("/dev/null", O_RDWR);
        dup2(nul, 1); dup2(nul, 2);
        personality(ADDR_NO_RANDOMIZE);
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        raise(SIGSTOP);
        execve(cmd[0], cmd, environ);
        _exit(127);
    }
    int st;
    waitpid(pid, &st, 0);
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEEXIT | PTRACE_O_EXITKILL | PTRACE_O_TRACEEXEC | PTRACE_O_TRACECLONE);
    ptrace(PTRACE_CONT, pid, 0, 0);
    waitpid(pid, &st, 0); // exec stop
    uint64_t seq = 0; int have_maps = 0, threads = 1, exitcode = -1;
    ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
    for (;;) {
        pid_t t = waitpid(-1, &st, __WALL);
        if (t < 0) { if (errno == EINTR) continue; break; }
        if (WIFEXITED(st) || WIFSIGNALED(st)) {
            if (t == pid) exitcode = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
            continue;
        }
        if (!WIFSTOPPED(st)) continue;
        int sig = WSTOPSIG(st), ev = st >> 16, inject = 0;
        if (ev == PTRACE_EVENT_EXIT) {
            if (!have_maps) { read_maps(pid); have_maps = 1; }
            ptrace(PTRACE_CONT, t, 0, 0);
            continue;
        }
        if (ev == PTRACE_EVENT_CLONE) threads++;
        else if (sig == SIGTRAP && ev == 0) {
            long rip = ptrace(PTRACE_PEEKUSER, t, offsetof(struct user_regs_struct, rip), 0);
            add((uint64_t)rip, seq++);
        } else if (sig != SIGSTOP && sig != SIGTRAP) inject = sig;
        ptrace(PTRACE_SINGLESTEP, t, 0, inject);
    }
    FILE *o = out ? fopen(out, "w") : stdout;
    if (!o) { perror(out); return 1; }
    uint64_t inexe = 0, other = 0, distinct = 0;
    for (uint64_t h = 0; h < HB; h++) {
        if (!hk[h]) continue;
        int m;
        for (m = 0; m < nmaps; m++) if (hk[h] >= maps[m].lo && hk[h] < maps[m].hi) break;
        if (m < nmaps && !strcmp(maps[m].name, exe)) {
            fprintf(o, "%lx %lu %u\n", hk[h] - maps[m].lo + maps[m].off, hfirst[h], hn[h]);
            inexe += hn[h]; distinct++;
        } else other += hn[h];
    }
    if (o != stdout) fclose(o);
    fprintf(stderr, "hottrace: %lu instructions (%lu outside the executable), %lu distinct addresses, %d threads, exit %d\n",
            inexe + other, other, distinct, threads, exitcode);
    return 0;
}
