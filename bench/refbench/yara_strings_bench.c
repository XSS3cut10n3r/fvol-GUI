// libyara reference for the rsvol string matcher benchmark (src/yara/scan/bench.rs).
//
//   gcc -O3 -march=native -o yara_strings_bench yara_strings_bench.c -lyara
//   ./yara_strings_bench RULES.yar IMAGE [OFF LEN CHUNK]
//
// Maps IMAGE, scans [OFF, OFF+LEN) in CHUNK+4096-byte windows advancing by CHUNK (like
// volatility's scanner; CHUNK=0 scans the range in one call), best of 6 passes (thread
// CPU time, robust on a busy machine), and
// prints MB/s plus the number of matches per string (offset < CHUNK within a window).
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <yara.h>

static size_t counts[4096];
static size_t limit;

static int cb(YR_SCAN_CONTEXT* ctx, int msg, void* msg_data, void* user)
{
  (void) user;
  if (msg == CALLBACK_MSG_RULE_MATCHING || msg == CALLBACK_MSG_RULE_NOT_MATCHING)
  {
    YR_RULE* rule = (YR_RULE*) msg_data;
    YR_STRING* s;
    int i = 0;
    yr_rule_strings_foreach(rule, s)
    {
      YR_MATCH* m;
      yr_string_matches_foreach(ctx, s, m)
      {
        if ((size_t) m->offset < limit && i < 4096)
          counts[i]++;
      }
      i++;
    }
  }
  return CALLBACK_CONTINUE;
}

static void compile_cb(int level, const char* file, int line, const YR_RULE* rule, const char* msg, void* user)
{
  (void) file; (void) rule; (void) user;
  fprintf(stderr, "%s line %d: %s\n", level == YARA_ERROR_LEVEL_ERROR ? "error" : "warning", line, msg);
}

int main(int argc, char** argv)
{
  if (argc < 3)
  {
    fprintf(stderr, "usage: %s RULES IMAGE [OFF LEN CHUNK]\n", argv[0]);
    return 2;
  }
  size_t off = argc > 3 ? strtoull(argv[3], 0, 0) : (1ull << 30);
  size_t len = argc > 4 ? strtoull(argv[4], 0, 0) : (1ull << 30);
  size_t chunk = argc > 5 ? strtoull(argv[5], 0, 0) : (16ull << 20);
  yr_initialize();
  YR_COMPILER* c;
  yr_compiler_create(&c);
  yr_compiler_set_callback(c, compile_cb, NULL);
  FILE* rf = fopen(argv[1], "r");
  if (!rf || yr_compiler_add_file(c, rf, NULL, argv[1]) != 0)
    return 1;
  YR_RULES* rules;
  yr_compiler_get_rules(c, &rules);
  int fd = open(argv[2], O_RDONLY);
  struct stat st;
  fstat(fd, &st);
  const uint8_t* map = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
  if (off > (size_t) st.st_size)
    off = st.st_size;
  if (off + len > (size_t) st.st_size)
    len = st.st_size - off;
  const uint8_t* data = map + off;
  YR_SCANNER* sc;
  yr_scanner_create(rules, &sc);
  yr_scanner_set_callback(sc, cb, NULL);
  yr_scanner_set_flags(sc, SCAN_FLAGS_REPORT_RULES_MATCHING | SCAN_FLAGS_REPORT_RULES_NOT_MATCHING);
  double best = 1e30;
  for (int pass = 0; pass < 6; pass++)
  {
    for (int i = 0; i < 4096; i++) counts[i] = 0;
    struct timespec t0, t1, w0, w1;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t0);
    clock_gettime(CLOCK_MONOTONIC, &w0);
    size_t p = 0;
    for (;;)
    {
      size_t e = chunk == 0 ? len : (p + chunk + 4096 < len ? p + chunk + 4096 : len);
      limit = chunk == 0 ? (size_t) -1 : chunk;
      yr_scanner_scan_mem(sc, data + p, e - p);
      if (chunk == 0 || e == len)
        break;
      p += chunk;
    }
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t1);
    clock_gettime(CLOCK_MONOTONIC, &w1);
    double dt = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    double wall = (w1.tv_sec - w0.tv_sec) + (w1.tv_nsec - w0.tv_nsec) / 1e9;
    fprintf(stderr, "pass %d: cpu %.3f s (wall %.3f)  %.0f MB/s\n", pass, dt, wall, len / dt / 1e6);
    if (dt < best)
      best = dt;
  }
  size_t total = 0;
  printf("libyara %s bytes=%zu best=%.3fs  %.0f MB/s\nmatches per string: [", YR_VERSION, len, best, len / best / 1e6);
  YR_RULE* r;
  int n = 0;
  yr_rules_foreach(rules, r)
  {
    YR_STRING* s;
    yr_rule_strings_foreach(r, s) { n++; }
  }
  for (int i = 0; i < n && i < 4096; i++)
  {
    printf("%s%zu", i ? ", " : "", counts[i]);
    total += counts[i];
  }
  printf("]  total %zu\n", total);
  return 0;
}
