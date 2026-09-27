# Further optimizations (not yet implemented)

Collected from the hardware-floor reviews (`bench/reviews/*.md`) and the optimization agents' final
reports. Each item: estimated gain, effort/risk, source. Items are removed from here when implemented.

## Startup / fixed per-run cost
Status after the optimization pass: warm windows.pslist 1005 -> 710 us locally (floor ~424 us, 1.7x),
3.7 -> 2.4 ms median on the VM (VM floor: /bin/true alone takes 621 us).

- **Non-PIE static link**: -100..190 us on the VM (48 CoW faults + 131k instructions of self-relocation,
  mostly ~3,700 panic-location constants). Costs ASLR for a tool that parses untrusted images; the
  compiler flag that drops panic locations is nightly-only. *Deferred on security grounds.*
- **Skip glibc's environment scan** (75k instructions with ~218 env vars; ~0 with a normal environment):
  needs a custom process entry point. Low value, some risk.
- **pread instead of mmap for image reads** (~190 us per the floor experiment): removes image-page faults;
  a 3-5 day redesign of the read paths. Overlaps the scanning agent's dual-mapping work.
- **Warm-path memory touched every run**: a 128 KB table cache and a 268 KB output buffer; size them to
  the run (lazy growth).
- **stat() calls on the warm path**: ~28 for the ISF-choice cache checks, ~16 for the volatility3 install
  search; batch or cache the directory fingerprints.
- **`vol -h`**: ~6.1M instructions of help formatting (not on the warm path).
- **Huge pages for the text on the VM**: the benchmark VM's kernel lacks CONFIG_READ_ONLY_THP_FOR_FS, so
  that step is a no-op there (works locally).
