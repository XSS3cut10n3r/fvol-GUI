# Building fastvol

How to build the `fvol` binary, what the repository's compiler flags do, and how to build a binary
for machines other than the build machine. For the quick version, see the
[README](../README.md#install).

Applies to fastvol 0.1.0.

## Requirements

You need a Rust toolchain of version 1.95 or newer, the `rust-version` in `Cargo.toml`: the
project uses edition 2024 and `std::hint::cold_path`, which was stabilized in 1.95. Stable 1.95.0
builds it and passes the tests and parity gates. The published benchmark was built with rustc
1.100.0-nightly (2026-09-21), the earlier runs with 1.98.1.

Platforms: Linux on x86-64 and on arm64 (aarch64). Both run the unit tests in CI and ship as
release binaries. The parity gates run natively on x86-64; the arm64 binary was checked against
them under qemu (see [arm64](#arm64)).

## Build profiles

```bash
cargo build --release          # target/release/fvol, for benchmarks and daily use
cargo build --profile fast     # target/fast/fvol, optimized without LTO, quick to rebuild
cargo test --profile fast      # unit and differential tests
```

The release profile uses fat LTO and a single codegen unit. The binary is self-contained, so you
can copy `target/release/fvol` anywhere on your `PATH`.

## Compiler flags

The repository's [.cargo/config.toml](../.cargo/config.toml) adds these flags to every build:

- `-C target-cpu=native` compiles for the CPU of the build machine. The binary may use
  instructions such as AVX2 or BMI2 without checking for them, so it can crash with an illegal
  instruction on an older or different CPU.
- `-C target-feature=+crt-static` links a static-pie binary, which skips the dynamic loader and
  runs on any Linux of its architecture with no shared library requirements.
- `-z max-page-size=0x200000 -z separate-code` (linker) align the segments to 2 MB and start the
  code on a 2 MB boundary, so the kernel can map the code and read-only data with huge pages
  (see [Startup](#startup)). The file gets up to ~4 MB of sparse padding, and the randomized load
  address has 9 fewer bits of entropy; the binary stays position-independent.
- `-z pack-relative-relocs` (linker) stores the ~10,500 relocations the static-pie applies to
  itself at startup as a 3 KB bitmap (RELR, glibc 2.36 or newer) instead of 250 KB of entries.

The same file limits a build to 6 parallel jobs; pass `-j <N>` to cargo to use more.

## Startup

A warm run of a small plugin takes well under a millisecond, so the fixed cost of starting and
ending the process matters as much as the plugin. Three measures cut it by about a third; none of
them changes any output.

**Hot-text ordering.** The release link goes through
[.cargo/linker.sh](../.cargo/linker.sh), which passes the functions listed in
[.cargo/symbol-order.txt](../.cargo/symbol-order.txt) to lld's `--symbol-ordering-file`. The
~1,200 functions that typical runs execute then sit together at the start of the code (~850 KB)
instead of being spread over 10 MB, so a run takes a dozen page faults on its code instead of
~90. The list holds demangled names, so crate-hash changes do not invalidate it, and the wrapper
translates them to the symbols of the object being linked. A stale list only costs speed: names
that no longer exist are ignored, and a missing list or `nm` links without ordering.
`FASTVOL_SYMBOL_ORDER=0` turns it off. Regenerate the list after larger code changes:

```bash
bench/scripts/gen-symbol-order.sh      # a few minutes: builds, traces 9 typical runs, writes the list
cargo build --release
```

**Teardown after the exit.** When a process exits, the kernel unmaps its address space before
the parent learns about the exit: 0.1 to 0.7 ms for a run that maps a multi-GB image. After its
output is flushed and every descriptor closed, a one-shot `fvol` run hands its address space to a
small helper process that shares it (`clone(CLONE_VM)`), waits for `fvol` to exit and then exits
itself, so the unmapping happens after the caller's `wait` has returned. The exit status, the
output and pipes behave exactly as before. Caveat: the teardown's CPU time is charged to the
helper, which init reaps, so `time`, `wait4` and `getrusage(RUSAGE_CHILDREN)` in the caller no
longer include it (the cgroup's accounting still does). `fvol serve`, the test suite and code
embedding fastvol never use the helper. `FASTVOL_EXIT_HELPER=0` turns it off.

**Huge pages for the code.** With `CONFIG_READ_ONLY_THP_FOR_FS` (Linux 6.1 or newer for
`MADV_COLLAPSE`), the helper above checks whether the run's code was mapped with 2 MB pages and,
if not, asks the kernel to collapse the executable's code and read-only data into 2 MB page-cache
folios. That takes a few milliseconds once, off everyone's clock; later runs then map the hot code
with a single TLB entry and almost no page faults. Memory pressure may split the folios again, in
which case the next run collapses them again. Where the kernel does not support it (Ubuntu's
kernels, for example, do not enable `CONFIG_READ_ONLY_THP_FOR_FS`), nothing happens.
`FASTVOL_EXIT_HELPER=nothp` keeps the helper and skips the collapse.

## Build for other machines

To build a binary for other machines, override the flags with `RUSTFLAGS`, which replaces the
`rustflags` of the config file (keep the linker flags, they only affect the layout):

```bash
L="-C link-arg=-Wl,-z,max-page-size=0x200000 -C link-arg=-Wl,-z,separate-code -C link-arg=-Wl,-z,pack-relative-relocs"

# generic x86-64, still static
RUSTFLAGS="-C target-feature=+crt-static $L" cargo build --release

# CPUs with AVX2, such as Intel Haswell and AMD Zen or newer
RUSTFLAGS="-C target-cpu=x86-64-v3 -C target-feature=+crt-static $L" cargo build --release
```

The SIMD code paths, which cover scanning, JSON parsing, crypto, the snappy, Xpress and bzip2
decoders and the Linux kernel searches, detect CPU features at run time, so a generic build still
uses AVX2, SSSE3, BMI2, AES-NI and SHA-NI where they exist. Two small helpers, the match length of
the zlib-exact compressor and the hex digits of the disassembler, use AVX2 or BMI2 only when the
build enables them, because a run-time check there would cost more than it saves. Output is
identical either way.

## arm64

On an arm64 machine the same commands build a native binary (`target-cpu=native` then means that
machine's CPU). For a binary that runs on any 64-bit ARM CPU:

```bash
RUSTFLAGS="-C target-cpu=generic -C target-feature=+crt-static $L" cargo build --release
```

The SIMD fast paths (AVX2, SSE, SHA-NI, AES-NI) are x86-only; arm64 runs the portable versions of
the same code, which give the same output but scan and decode more slowly. Memory mappings use
the kernel's page size, so kernels with 16 KiB or 64 KiB pages work too.

To test arm64 code on an x86-64 machine without an ARM toolchain, build the tests for musl, which
brings its own C library and links with the toolchain's `rust-lld`, and run them with
qemu-user (binfmt makes the arm64 binaries runnable directly):

```bash
rustup target add aarch64-unknown-linux-musl
RUSTFLAGS="" CARGO_TARGET_DIR=target/arm64 CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld \
  cargo test --target aarch64-unknown-linux-musl --profile fast
# the parity gates with the arm64 binary
bench/scripts/check_all.sh -b $PWD/target/arm64/aarch64-unknown-linux-musl/fast/fvol
```
