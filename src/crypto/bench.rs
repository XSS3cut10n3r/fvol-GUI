//! Throughput measurements for the primitives in this module, matched
//! methodology-for-methodology against `bench/refbench/crypto_bench.c` (OpenSSL EVP) so
//! the two are directly comparable -- same buffer sizes, same iteration counts, same
//! "bulk vs. small+setup" workload split. Not part of `cargo test crypto` (ignored
//! by default): run explicitly with
//!
//!   cargo test --profile fast crypto::bench -- --ignored --nocapture
//!
//! No bench-harness crate is available (zero dependencies, see `DESIGN.md`), so this
//! is a plain wall-clock loop. Every measured result is passed through
//! `std::hint::black_box` -- without it, a result bound to `_` is exactly the kind of
//! provably-unobserved pure computation LLVM is entitled to delete outright, which
//! silently turns "how fast is this" into "how fast is nothing" (caught during
//! development: an early version of this file reported AES-CBC at ~8 GB/s, ~3.5x the
//! real rate, purely from a discarded `Vec` letting the optimizer skip most of the
//! work).
//!
//! Two workloads, matching bench.c:
//!   - bulk:  BULK_SIZE (1 MiB) buffer, processed BULK_ITERS (200) times reusing one
//!            key schedule / context set up before the loop -- raw sustained
//!            throughput, and small enough to mostly stay in L2 across iterations
//!            (this is deliberate: bench.c's OpenSSL loop gets the same cache
//!            residency, so it's a fair comparison, not an inflated one).
//!   - small: SMALL_ITERS (500,000) independent calls over a SMALL_SIZE (32) byte
//!            buffer, each one paying full key-setup cost fresh (`Aes::new` /
//!            `Des::new` / `Rc4::new` inside the loop) -- this is the shape of the
//!            actual plugin workloads (hashdump/lsadump/cachedump process a handful
//!            of 16-56 byte values per registry key, never megabytes), and it's
//!            where having no context-allocation overhead should show up as a win.

use super::{aes::Aes, des::Des, hmac, md5, rc4, sha1, sha256};
use std::hint::black_box;
use std::time::Instant;

const BULK_SIZE: usize = 1024 * 1024;
const BULK_ITERS: usize = 200;
const SMALL_SIZE: usize = 32;
const SMALL_ITERS: usize = 500_000;

fn fill(n: usize, seed: u32) -> Vec<u8> {
    let mut x = seed;
    (0..n)
        .map(|_| {
            x = x.wrapping_mul(1103515245).wrapping_add(12345);
            (x >> 16) as u8
        })
        .collect()
}

fn report_bulk(name: &str, bytes_per_iter: usize, iters: usize, secs: f64) {
    let mbps = (bytes_per_iter as f64 * iters as f64 / 1e6) / secs;
    println!("{name:16} bulk  {mbps:10.1} MB/s");
}
fn report_small(name: &str, iters: usize, secs: f64, note: &str) {
    let opsps = iters as f64 / secs;
    println!("{name:16} small {opsps:10.0} ops/s  ({note})");
}

#[test]
#[ignore]
fn bench_all() {
    let bulk = black_box(fill(BULK_SIZE, 1));
    let small = black_box(fill(SMALL_SIZE, 2));

    // --- digests ---
    for (name, f) in [
        ("MD5", (|d: &[u8]| md5::digest(d).to_vec()) as fn(&[u8]) -> Vec<u8>),
        ("SHA1", |d: &[u8]| sha1::digest(d).to_vec()),
        ("SHA256", |d: &[u8]| sha256::digest(d).to_vec()),
    ] {
        let start = Instant::now();
        for _ in 0..BULK_ITERS {
            black_box(f(black_box(&bulk)));
        }
        report_bulk(name, BULK_SIZE, BULK_ITERS, start.elapsed().as_secs_f64());

        let start = Instant::now();
        for _ in 0..SMALL_ITERS {
            black_box(f(black_box(&small)));
        }
        report_small(name, SMALL_ITERS, start.elapsed().as_secs_f64(), "no setup cost to pay");
    }

    // --- HMAC ---
    let key32 = black_box(fill(32, 3));
    for (name, f) in [
        (
            "HMAC-MD5",
            (|k: &[u8], d: &[u8]| hmac::hmac_md5(k, d).to_vec()) as fn(&[u8], &[u8]) -> Vec<u8>,
        ),
        ("HMAC-SHA1", |k, d| hmac::hmac_sha1(k, d).to_vec()),
        ("HMAC-SHA256", |k, d| hmac::hmac_sha256(k, d).to_vec()),
    ] {
        let start = Instant::now();
        for _ in 0..BULK_ITERS {
            black_box(f(black_box(&key32), black_box(&bulk)));
        }
        report_bulk(name, BULK_SIZE, BULK_ITERS, start.elapsed().as_secs_f64());

        let start = Instant::now();
        for _ in 0..SMALL_ITERS {
            black_box(f(black_box(&key32), black_box(&small)));
        }
        report_small(name, SMALL_ITERS, start.elapsed().as_secs_f64(), "no separate setup step");
    }

    // --- RC4 (key schedule set up once for bulk; fresh Rc4::new per call for small) ---
    {
        let key = black_box(fill(16, 6));
        let cipher = rc4::Rc4::new(&key);
        let _ = cipher; // KSA cost paid once, like bench.c's EVP_EncryptInit outside the loop
        let mut buf = bulk.clone();
        let start = Instant::now();
        for _ in 0..BULK_ITERS {
            let mut c = rc4::Rc4::new(&key);
            c.apply(black_box(&mut buf));
        }
        report_bulk("RC4", BULK_SIZE, BULK_ITERS, start.elapsed().as_secs_f64());

        let start = Instant::now();
        for _ in 0..SMALL_ITERS {
            let mut c = rc4::Rc4::new(black_box(&key));
            let mut s = small.clone();
            c.apply(&mut s);
            black_box(&s);
        }
        report_small("RC4", SMALL_ITERS, start.elapsed().as_secs_f64(), "incl. KSA each call");
    }

    // --- DES-ECB decrypt ---
    {
        let key: [u8; 8] = fill(8, 7).try_into().unwrap();
        let des = Des::new(&key);
        let start = Instant::now();
        for _ in 0..BULK_ITERS {
            black_box(des.ecb_decrypt(black_box(&bulk)).unwrap());
        }
        report_bulk("DES-ECB", BULK_SIZE, BULK_ITERS, start.elapsed().as_secs_f64());

        let start = Instant::now();
        for _ in 0..SMALL_ITERS {
            let d = Des::new(black_box(&key));
            black_box(d.ecb_decrypt(&small).unwrap());
        }
        report_small(
            "DES-ECB",
            SMALL_ITERS,
            start.elapsed().as_secs_f64(),
            "incl. key schedule each call",
        );
    }

    // --- AES ECB/CBC decrypt, 128 and 256 bit ---
    for klen in [16usize, 32] {
        let key = fill(klen, 8);
        let iv: [u8; 16] = fill(16, 9).try_into().unwrap();
        let aes = Aes::new(&key).unwrap();
        let tag = if klen == 16 { "AES128" } else { "AES256" };

        let start = Instant::now();
        for _ in 0..BULK_ITERS {
            black_box(aes.ecb_decrypt(black_box(&bulk)));
        }
        report_bulk(&format!("{tag}-ECB-dec"), BULK_SIZE, BULK_ITERS, start.elapsed().as_secs_f64());

        let start = Instant::now();
        for _ in 0..BULK_ITERS {
            black_box(aes.cbc_decrypt(&iv, black_box(&bulk)).unwrap());
        }
        report_bulk(&format!("{tag}-CBC-dec"), BULK_SIZE, BULK_ITERS, start.elapsed().as_secs_f64());

        let start = Instant::now();
        for _ in 0..SMALL_ITERS {
            let a = Aes::new(black_box(&key)).unwrap();
            black_box(a.ecb_decrypt(&small));
        }
        report_small(
            &format!("{tag}-ECB-dec"),
            SMALL_ITERS,
            start.elapsed().as_secs_f64(),
            "incl. key schedule each call",
        );

        let start = Instant::now();
        for _ in 0..SMALL_ITERS {
            let a = Aes::new(black_box(&key)).unwrap();
            black_box(a.cbc_decrypt(&iv, &small).unwrap());
        }
        report_small(
            &format!("{tag}-CBC-dec"),
            SMALL_ITERS,
            start.elapsed().as_secs_f64(),
            "incl. key schedule each call",
        );
    }

    // --- Diagnostic: raw VAES 8-block throughput on a single hot 128-byte buffer
    // (no Vec, no allocation, no XOR pass) -- shows the hardware loop's ceiling
    // versus the wrapped ecb_decrypt/cbc_decrypt numbers above, which additionally
    // pay for a full-buffer allocation and (for CBC) a scalar XOR pass across
    // real, cold, 1 MiB of memory -- not code-path overhead, but genuine memory
    // traffic that OpenSSL's EVP path pays too.
    #[cfg(target_arch = "x86_64")]
    {
        let key = black_box(fill(16, 44));
        let aes = Aes::new(&key).unwrap();
        if aes.has_vaes() {
            let mut buf = black_box([7u8; 128]);
            const ITERS: usize = 2_000_000;
            let start = Instant::now();
            for _ in 0..ITERS {
                aes.decrypt8_raw_for_bench(&mut buf);
            }
            let secs = start.elapsed().as_secs_f64();
            black_box(&buf);
            println!(
                "{:16} raw   {:10.1} MB/s  (hot 128B buffer, no alloc/XOR -- hardware ceiling)",
                "AES128-VAES8",
                (ITERS as f64 * 128.0 / 1e6) / secs
            );
        }
    }
}
