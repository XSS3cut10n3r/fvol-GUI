//! Throughput measurements for the primitives in this module, matched
//! methodology-for-methodology against `bench/refbench/crypto_bench.c` (OpenSSL EVP) so
//! the two are directly comparable -- same buffer sizes, same iteration counts, same
//! "bulk vs. small+setup" workload split, same best-of-N repetition scheme. Not part
//! of `cargo test crypto` (ignored by default): run explicitly, pinned to one P-core,
//! with
//!
//!   cargo test --profile fast crypto::bench -- --ignored --nocapture
//!   (or run the built test binary directly under `taskset -c 4 ... crypto::bench
//!   --ignored --nocapture`)
//!
//! No bench-harness crate is available (zero dependencies), so this
//! is a plain wall-clock loop. Every measured result is passed through
//! `std::hint::black_box` -- without it, a result bound to `_` is exactly the kind of
//! provably-unobserved pure computation LLVM is entitled to delete outright, which
//! silently turns "how fast is this" into "how fast is nothing" (caught during
//! development: an early version of this file reported AES-CBC at ~8 GB/s, ~3.5x the
//! real rate, purely from a discarded `Vec` letting the optimizer skip most of the
//! work).
//!
//! Two workloads, matching crypto_bench.c:
//! - bulk: BULK_SIZE (1 MiB) buffer, processed BULK_REP_ITERS (20) times per
//!   repetition reusing one key schedule / context set up before the loop -- raw
//!   sustained throughput.
//! - small: SMALL_REP_ITERS (50,000) independent calls per repetition over a
//!   SMALL_SIZE (32) byte buffer, each one paying full key-setup cost fresh
//!   (`Aes::new` / `Des::new` / `Rc4::new` inside the loop) -- this is the shape of
//!   the actual plugin workloads (hashdump/lsadump/cachedump process a handful of
//!   16-56 byte values per registry key, never megabytes).
//!
//! Each workload is repeated REPS times (env `CRYPTO_BENCH_REPS`, default 10) and the
//! best repetition is reported as MB/s (ops/s) and as user-space core cycles per
//! byte (per op) from a `perf_event_open` cycle counter -- the machine this runs on
//! is shared and frequency-scaling, so cycles are the robust comparison.
//! `CRYPTO_BENCH_ONLY=AES128,SHA1` restricts the run to matching primitives.
//!
//! Rows named `...*` measure the allocation-free in-place APIs
//! (`Aes::cbc_decrypt_in_place`, `Des::ecb_decrypt_in_place`); the unstarred rows
//! measure the `Vec`-returning APIs the plugins use, which is what the OpenSSL rows
//! are compared against.

use super::{aes::Aes, des::Des, hmac, md5, rc4, sha1, sha256};
use std::hint::black_box;
use std::time::Instant;

const BULK_SIZE: usize = 1024 * 1024;
const BULK_REP_ITERS: usize = 20;
const SMALL_SIZE: usize = 32;
const SMALL_REP_ITERS: usize = 50_000;

// --- user-space cycle counter via perf_event_open(2) (std only: raw libc calls) ---
unsafe extern "C" {
    fn syscall(num: i64, ...) -> i64;
    fn read(fd: i32, buf: *mut std::ffi::c_void, count: usize) -> isize;
}

struct Cycles(i32);

impl Cycles {
    fn open() -> Cycles {
        #[cfg(target_os = "linux")]
        {
            // struct perf_event_attr (PERF_ATTR_SIZE_VER8 = 136 bytes): type=HARDWARE(0),
            // size, config=CPU_CYCLES(0), flags: exclude_kernel(bit 5) | exclude_hv(bit 6).
            let mut attr = [0u64; 17];
            attr[0] = 136u64 << 32;
            attr[5] = (1 << 5) | (1 << 6);
            const SYS_PERF_EVENT_OPEN: i64 = if cfg!(target_arch = "aarch64") { 241 } else { 298 };
            let fd =
                unsafe { syscall(SYS_PERF_EVENT_OPEN, attr.as_ptr(), 0i32, -1i32, -1i32, 0u64) };
            Cycles(fd as i32)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Cycles(-1)
        }
    }
    fn now(&self) -> f64 {
        if self.0 < 0 {
            return 0.0;
        }
        let mut v = 0u64;
        let n = unsafe { read(self.0, (&mut v as *mut u64).cast(), 8) };
        if n == 8 { v as f64 } else { 0.0 }
    }
}

struct Bench {
    reps: usize,
    only: Vec<String>,
    cyc: Cycles,
}

impl Bench {
    fn new() -> Bench {
        let reps = std::env::var("CRYPTO_BENCH_REPS")
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|&n: &usize| n > 0)
            .unwrap_or(10);
        let only = std::env::var("CRYPTO_BENCH_ONLY")
            .map(|s| {
                s.split(',')
                    .filter(|t| !t.is_empty())
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();
        Bench {
            reps,
            only,
            cyc: Cycles::open(),
        }
    }

    fn wanted(&self, name: &str) -> bool {
        self.only.is_empty() || self.only.iter().any(|t| name.contains(t.as_str()))
    }

    /// Best-of-`reps` (wall seconds, cycles) for one repetition of `f`.
    fn best(&self, mut f: impl FnMut()) -> (f64, f64) {
        let (mut bs, mut bc) = (f64::MAX, f64::MAX);
        for _ in 0..self.reps {
            let c0 = self.cyc.now();
            let t0 = Instant::now();
            f();
            let s = t0.elapsed().as_secs_f64();
            let c = self.cyc.now() - c0;
            bs = bs.min(s);
            bc = bc.min(c);
        }
        (bs, bc)
    }

    fn bulk(&self, name: &str, f: impl FnMut()) {
        let (s, c) = self.best(f);
        let bytes = (BULK_SIZE * BULK_REP_ITERS) as f64;
        let cpb = if self.cyc.0 >= 0 {
            format!("{:8.3}", c / bytes)
        } else {
            format!("{:>8}", "-")
        };
        println!("{name:16} bulk  {:10.1} MB/s   {cpb} c/B", bytes / 1e6 / s);
    }

    fn small(&self, name: &str, note: &str, f: impl FnMut()) {
        let (s, c) = self.best(f);
        let n = SMALL_REP_ITERS as f64;
        let cpo = if self.cyc.0 >= 0 {
            format!("{:8.1}", c / n)
        } else {
            format!("{:>8}", "-")
        };
        println!("{name:16} small {:10.0} ops/s  {cpo} c/op  ({note})", n / s);
    }
}

fn fill(n: usize, seed: u32) -> Vec<u8> {
    let mut x = seed;
    (0..n)
        .map(|_| {
            x = x.wrapping_mul(1103515245).wrapping_add(12345);
            (x >> 16) as u8
        })
        .collect()
}

#[test]
#[ignore]
fn bench_all() {
    let b = Bench::new();
    let bulk = black_box(fill(BULK_SIZE, 1));
    let small = black_box(fill(SMALL_SIZE, 2));

    // --- digests ---
    for (name, f) in [
        (
            "MD5",
            (|d: &[u8]| md5::digest(d).to_vec()) as fn(&[u8]) -> Vec<u8>,
        ),
        ("SHA1", |d: &[u8]| sha1::digest(d).to_vec()),
        ("SHA256", |d: &[u8]| sha256::digest(d).to_vec()),
    ] {
        if !b.wanted(name) {
            continue;
        }
        b.bulk(name, || {
            for _ in 0..BULK_REP_ITERS {
                black_box(f(black_box(&bulk)));
            }
        });
        b.small(name, "no setup cost to pay", || {
            for _ in 0..SMALL_REP_ITERS {
                black_box(f(black_box(&small)));
            }
        });
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
        if !b.wanted(name) {
            continue;
        }
        b.bulk(name, || {
            for _ in 0..BULK_REP_ITERS {
                black_box(f(black_box(&key32), black_box(&bulk)));
            }
        });
        b.small(name, "no separate setup step", || {
            for _ in 0..SMALL_REP_ITERS {
                black_box(f(black_box(&key32), black_box(&small)));
            }
        });
    }

    // --- RC4 (fresh Rc4::new per 1 MiB pass for bulk -- KSA cost is noise there;
    // fresh Rc4::new per call for small) ---
    if b.wanted("RC4") {
        let key = black_box(fill(16, 6));
        let mut buf = bulk.clone();
        b.bulk("RC4", || {
            for _ in 0..BULK_REP_ITERS {
                let mut c = rc4::Rc4::new(&key);
                c.apply(black_box(&mut buf));
            }
        });
        b.small("RC4", "incl. KSA each call", || {
            for _ in 0..SMALL_REP_ITERS {
                black_box(rc4::rc4(black_box(&key), black_box(&small)));
            }
        });
    }

    // --- DES-ECB decrypt ---
    if b.wanted("DES-ECB") {
        let key: [u8; 8] = fill(8, 7).try_into().unwrap();
        let des = Des::new(&key);
        b.bulk("DES-ECB", || {
            for _ in 0..BULK_REP_ITERS {
                black_box(des.ecb_decrypt(black_box(&bulk)).unwrap());
            }
        });
        b.small("DES-ECB", "incl. key schedule each call", || {
            for _ in 0..SMALL_REP_ITERS {
                let d = Des::new(black_box(&key));
                black_box(d.ecb_decrypt(black_box(&small)).unwrap());
            }
        });
        let mut buf = bulk.clone();
        b.bulk("DES-ECB*", || {
            for _ in 0..BULK_REP_ITERS {
                des.ecb_decrypt_in_place(black_box(&mut buf)).unwrap();
            }
        });
        b.small("DES-ECB*", "in place, incl. key schedule", || {
            for _ in 0..SMALL_REP_ITERS {
                let d = Des::new(black_box(&key));
                let mut s: [u8; SMALL_SIZE] = black_box(&small[..]).try_into().unwrap();
                d.ecb_decrypt_in_place(&mut s).unwrap();
                black_box(&s);
            }
        });
    }

    // --- AES ECB/CBC decrypt, 128 and 256 bit ---
    for klen in [16usize, 32] {
        let key = fill(klen, 8);
        let iv: [u8; 16] = fill(16, 9).try_into().unwrap();
        let aes = Aes::new(&key).unwrap();
        let tag = if klen == 16 { "AES128" } else { "AES256" };

        let name = format!("{tag}-ECB-dec");
        if b.wanted(&name) {
            b.bulk(&name, || {
                for _ in 0..BULK_REP_ITERS {
                    black_box(aes.ecb_decrypt(black_box(&bulk)));
                }
            });
            b.small(&name, "incl. key schedule each call", || {
                for _ in 0..SMALL_REP_ITERS {
                    let a = Aes::new(black_box(&key)).unwrap();
                    black_box(a.ecb_decrypt(black_box(&small)));
                }
            });
        }
        let name = format!("{tag}-CBC-dec");
        if b.wanted(&name) {
            b.bulk(&name, || {
                for _ in 0..BULK_REP_ITERS {
                    black_box(aes.cbc_decrypt(&iv, black_box(&bulk)).unwrap());
                }
            });
            b.small(&name, "incl. key schedule each call", || {
                for _ in 0..SMALL_REP_ITERS {
                    let a = Aes::new(black_box(&key)).unwrap();
                    black_box(a.cbc_decrypt(&iv, black_box(&small)).unwrap());
                }
            });
            // Allocation-free in-place API (same work, caller-owned buffer).
            let mut buf = bulk.clone();
            b.bulk(&format!("{name}*"), || {
                for _ in 0..BULK_REP_ITERS {
                    aes.cbc_decrypt_in_place(&iv, black_box(&mut buf)).unwrap();
                }
            });
            b.small(&format!("{name}*"), "in place, incl. key schedule", || {
                for _ in 0..SMALL_REP_ITERS {
                    let a = Aes::new(black_box(&key)).unwrap();
                    let mut s: [u8; SMALL_SIZE] = black_box(&small[..]).try_into().unwrap();
                    a.cbc_decrypt_in_place(&iv, &mut s).unwrap();
                    black_box(&s);
                }
            });
        }
    }
}
