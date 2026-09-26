# Building rsvol

How to build the `vol` binary, what the repository's compiler flags do, and how to build a binary
for machines other than the build machine. For the quick version, see the
[README](../README.md#install).

Applies to rsvol 0.1.0.

## Requirements

You need a Rust toolchain of version 1.95 or newer, the `rust-version` in `Cargo.toml`: the
project uses edition 2024 and `std::hint::cold_path`, which was stabilized in 1.95. Stable 1.95.0
builds it and passes the tests and parity gates. The published benchmarks were built with rustc
1.98.1. Linux on x86-64 is the tested platform.

## Build profiles

```bash
cargo build --release          # target/release/vol, for benchmarks and daily use
cargo build --profile fast     # target/fast/vol, optimized without LTO, quick to rebuild
cargo test --profile fast      # unit and differential tests
```

The release profile uses fat LTO and a single codegen unit. The binary is self-contained, so you
can copy `target/release/vol` anywhere on your `PATH`.

## Compiler flags

The repository's [.cargo/config.toml](../.cargo/config.toml) adds two compiler flags to every
build:

- `-C target-cpu=native` compiles for the CPU of the build machine. The binary may use
  instructions such as AVX2 or BMI2 without checking for them, so it can crash with an illegal
  instruction on an older or different CPU.
- `-C target-feature=+crt-static` links a static-pie binary, which skips the dynamic loader and
  runs on any x86-64 Linux with no shared library requirements.

The same file limits a build to 6 parallel jobs; pass `-j <N>` to cargo to use more.

## Build for other machines

To build a binary for other machines, override the flags with `RUSTFLAGS`, which replaces the
`rustflags` of the config file:

```bash
# generic x86-64, still static
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release

# CPUs with AVX2, such as Intel Haswell and AMD Zen or newer
RUSTFLAGS="-C target-cpu=x86-64-v3 -C target-feature=+crt-static" cargo build --release
```

The SIMD code paths, which cover scanning, JSON parsing, crypto, the snappy, Xpress and bzip2
decoders and the Linux kernel searches, detect CPU features at run time, so a generic build still
uses AVX2, SSSE3, BMI2, AES-NI and SHA-NI where they exist. Two small helpers, the match length of
the zlib-exact compressor and the hex digits of the disassembler, use AVX2 or BMI2 only when the
build enables them, because a run-time check there would cost more than it saves. Output is
identical either way.
