//! Standalone xz decoder micro-benchmark: compiles src/codecs/{crc,lzma,xz}.rs directly with
//! rustc (seconds instead of a crate build) and measures best-of-N user-mode cycles,
//! instructions and branch misses per file, pinned to one CPU. Built and run by
//! codec_xz_micro.sh, which interleaves it with the liblzma harness (codecs_refbench.c).
//!
//!   codec_xz_micro bench RUNS FILE...    -> "rust <file> <out_bytes> <best_ms> <MB/s> <cyc> <ins> <brmiss>"
//!   codec_xz_micro verify FILE...        -> decodes and compares with FILE minus ".xz" if present
//!   codec_xz_micro loop SECONDS FILE     -> decodes FILE repeatedly (for perf record)
//!
//! With `--cfg old_lzma` and OLD_LZMA=<path to a previous lzma.rs>, `bench` also runs the old
//! decoder interleaved (label "old") so A/B runs share the machine state.
#![allow(dead_code, unexpected_cfgs)]

mod error {
    #[derive(Debug)]
    pub enum Error {
        Msg(String),
    }
    impl std::fmt::Display for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let Error::Msg(m) = self;
            f.write_str(m)
        }
    }
    pub type Result<T> = std::result::Result<T, Error>;
}

// The codec files use `super::` for their siblings and `crate::error`, so they sit at the
// crate root here.
#[path = "../../src/codecs/crc.rs"]
pub mod crc;
#[path = "../../src/codecs/lzma.rs"]
pub mod lzma;
#[path = "../../src/codecs/xz.rs"]
pub mod xz;

pub(crate) fn try_zeroed(n: usize) -> crate::error::Result<Vec<u8>> {
    if n == 0 {
        return Ok(Vec::new());
    }
    let layout = std::alloc::Layout::array::<u8>(n).map_err(|_| crate::error::Error::Msg("alloc".into()))?;
    // SAFETY: non-zero layout; calloc'ed bytes are initialised.
    unsafe {
        let p = std::alloc::alloc_zeroed(layout);
        if p.is_null() {
            return Err(crate::error::Error::Msg("alloc".into()));
        }
        Ok(Vec::from_raw_parts(p, n, n))
    }
}

/// Previous decoder for A/B runs: $WORK/old/mod.rs holds `pub mod lzma; pub mod xz; pub use
/// crate::{crc, try_zeroed};` next to copies of the old lzma.rs and xz.rs.
#[cfg(old_lzma)]
#[path = "/home/user/rs-vol/testdata/scratch/xzperf/old/mod.rs"]
mod old;

fn pin(cpu: usize) {
    unsafe extern "C" {
        fn sched_setaffinity(pid: i32, size: usize, mask: *const u64) -> i32;
    }
    let mut mask = [0u64; 16];
    mask[cpu / 64] = 1 << (cpu % 64);
    // SAFETY: plain syscall wrapper with a valid mask buffer
    unsafe { sched_setaffinity(0, 128, mask.as_ptr()) };
}

/// User-space hardware counters of this thread (P-core PMU on hybrid Intel parts).
struct Counters {
    fds: Vec<i32>,
}

impl Counters {
    fn open() -> Counters {
        unsafe extern "C" {
            fn syscall(n: i64, ...) -> i64;
        }
        let ext: u64 = std::fs::read_to_string("/sys/bus/event_source/devices/cpu_core/type")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        let mut fds = Vec::new();
        for ev in [0u64, 1, 5] {
            let mut attr = [0u64; 8];
            attr[0] = 64 << 32;
            attr[1] = (ext << 32) | ev;
            attr[5] = (1 << 0) | (1 << 5) | (1 << 6);
            // SAFETY: perf_event_open(attr, pid 0, cpu -1, group -1, flags 0)
            let fd = unsafe { syscall(298, attr.as_ptr(), 0i32, -1i32, -1i32, 0u64) };
            if fd < 0 {
                return Counters { fds: Vec::new() };
            }
            fds.push(fd as i32);
        }
        Counters { fds }
    }
    fn start(&self) {
        unsafe extern "C" {
            fn ioctl(fd: i32, req: u64, ...) -> i32;
        }
        for &fd in &self.fds {
            // SAFETY: PERF_EVENT_IOC_RESET / ENABLE on our own fds
            unsafe {
                ioctl(fd, 0x2403, 0);
                ioctl(fd, 0x2400, 0);
            }
        }
    }
    fn stop(&self) -> [u64; 3] {
        unsafe extern "C" {
            fn ioctl(fd: i32, req: u64, ...) -> i32;
            fn read(fd: i32, buf: *mut std::ffi::c_void, n: usize) -> isize;
        }
        let mut v = [0u64; 3];
        for (i, &fd) in self.fds.iter().enumerate() {
            // SAFETY: PERF_EVENT_IOC_DISABLE, then an 8-byte counter read
            unsafe {
                ioctl(fd, 0x2401, 0);
                read(fd, &mut v[i] as *mut u64 as *mut std::ffi::c_void, 8);
            }
        }
        v
    }
}

/// IP sampler on the perf ring buffer ("perf record" without perf): every `period` events of
/// hardware event `event` (0 cycles, 1 instructions, 5 branch misses) of this thread.
struct Sampler {
    fd: i32,
    ring: *mut u8,
}

const RING_PAGES: usize = 1 << 11;

impl Sampler {
    fn open(event: u64, period: u64) -> Sampler {
        unsafe extern "C" {
            fn syscall(n: i64, ...) -> i64;
            fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut u8;
        }
        let ext: u64 = std::fs::read_to_string("/sys/bus/event_source/devices/cpu_core/type")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        let mut fd = -1;
        for precise in [2u64, 1, 0] {
            let mut attr = [0u64; 8];
            attr[0] = 64 << 32;
            attr[1] = (ext << 32) | event;
            attr[2] = period;
            attr[3] = 1; // PERF_SAMPLE_IP
            attr[5] = 1 | (1 << 5) | (1 << 6) | (precise << 15);
            // SAFETY: valid perf_event_attr
            fd = unsafe { syscall(298, attr.as_ptr(), 0i32, -1i32, -1i32, 0u64) } as i32;
            if fd >= 0 {
                break;
            }
        }
        assert!(fd >= 0, "perf_event_open (sampling) failed");
        // SAFETY: mapping our own perf fd's ring buffer
        let ring = unsafe { mmap(std::ptr::null_mut(), (1 + RING_PAGES) * 4096, 3, 1, fd, 0) };
        assert!(ring as isize != -1);
        Sampler { fd, ring }
    }
    fn set(&self, on: bool) {
        unsafe extern "C" {
            fn ioctl(fd: i32, req: u64, ...) -> i32;
        }
        // SAFETY: valid perf fd
        unsafe { ioctl(self.fd, if on { 0x2400 } else { 0x2401 }, 0) };
    }
    fn drain(&mut self, hist: &mut std::collections::HashMap<u64, u64>) {
        use std::sync::atomic::{AtomicU64, Ordering};
        // SAFETY: perf_event_mmap_page (data_head at 1024, data_tail at 1032), data at page 1
        unsafe {
            let head = (*(self.ring.add(1024) as *const AtomicU64)).load(Ordering::Acquire);
            let tail_p = &*(self.ring.add(1032) as *const AtomicU64);
            let mut tail = tail_p.load(Ordering::Relaxed);
            let data = self.ring.add(4096);
            let size = (RING_PAGES * 4096) as u64;
            let rd = |off: u64| -> u64 {
                let mut b = [0u8; 8];
                for (i, x) in b.iter_mut().enumerate() {
                    *x = *data.add(((off + i as u64) % size) as usize);
                }
                u64::from_le_bytes(b)
            };
            while tail < head {
                let h = rd(tail);
                let sz = (h >> 48) & 0xFFFF;
                if sz == 0 {
                    break;
                }
                if h as u32 == 9 {
                    *hist.entry(rd(tail + 8)).or_insert(0) += 1;
                }
                tail += sz;
            }
            tail_p.store(head, Ordering::Release);
        }
    }
}

type Dec = fn(&[u8]) -> Vec<u8>;

fn dec_new(d: &[u8]) -> Vec<u8> {
    xz::decompress(d).unwrap()
}

#[cfg(old_lzma)]
fn dec_old(d: &[u8]) -> Vec<u8> {
    old::xz::decompress(d).unwrap()
}

fn measure(pmu: &Counters, dec: Dec, data: &[u8], runs: usize) -> (usize, f64, [u64; 3]) {
    let mut best = f64::MAX;
    let mut best_c = [u64::MAX; 3];
    let mut n = 0;
    for _ in 0..runs {
        pmu.start();
        let t = std::time::Instant::now();
        let out = dec(data);
        let dt = t.elapsed().as_secs_f64();
        let c = pmu.stop();
        n = out.len();
        std::hint::black_box(&out);
        drop(out);
        best = best.min(dt);
        if c[0] < best_c[0] {
            best_c = c;
        }
    }
    (n, best, best_c)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Some(cpu) = std::env::var("RSVOL_BENCH_CPU").ok().and_then(|v| v.parse().ok()) {
        pin(cpu);
    }
    match args.get(1).map(String::as_str) {
        Some("bench") => {
            let runs: usize = args[2].parse().unwrap();
            let pmu = Counters::open();
            for f in &args[3..] {
                let data = std::fs::read(f).unwrap();
                #[allow(unused_mut)]
                let mut decs: Vec<(&str, Dec)> = vec![("rust", dec_new)];
                #[cfg(old_lzma)]
                decs.insert(0, ("old", dec_old));
                for (label, dec) in decs {
                    let (n, best, c) = measure(&pmu, dec, &data, runs);
                    println!(
                        "{label} {f} {n} {:.3} {:.1} {} {} {}",
                        best * 1e3,
                        n as f64 / best / 1e6,
                        c[0],
                        c[1],
                        c[2]
                    );
                }
            }
        }
        Some("verify") => {
            for f in &args[2..] {
                let data = std::fs::read(f).unwrap();
                let out = xz::decompress(&data).unwrap_or_else(|e| panic!("{f}: {e}"));
                let want_path = f.strip_suffix(".xz").unwrap_or(f);
                match std::fs::read(want_path) {
                    Ok(want) if want_path != f => {
                        assert!(out == want, "{f}: output differs from {want_path}");
                        println!("ok {f} {}", out.len());
                    }
                    _ => println!("decoded {f} {} crc32 {:08x}", out.len(), crc::crc32(&out)),
                }
            }
        }
        Some("loop") => {
            let secs: f64 = args[2].parse().unwrap();
            let data = std::fs::read(&args[3]).unwrap();
            let t = std::time::Instant::now();
            let mut n = 0usize;
            while t.elapsed().as_secs_f64() < secs {
                n += std::hint::black_box(xz::decompress(&data).unwrap()).len();
            }
            println!("{n}");
        }
        Some("events") => {
            // events RUNS FILE CONFIG... : raw P-core events (PERF_TYPE_RAW configs, hex, e.g.
            // 0x01ad INT_MISC.RECOVERY_CYCLES), counted over the best (fewest cycles) run
            unsafe extern "C" {
                fn syscall(n: i64, ...) -> i64;
                fn ioctl(fd: i32, req: u64, ...) -> i32;
                fn read(fd: i32, buf: *mut std::ffi::c_void, n: usize) -> isize;
            }
            let runs: usize = args[2].parse().unwrap();
            let data = std::fs::read(&args[3]).unwrap();
            let mut cfgs = vec![0x3cu64]; // cycles (core, unhalted)
            for a in &args[4..] {
                cfgs.push(u64::from_str_radix(a.trim_start_matches("0x"), 16).unwrap());
            }
            let fds: Vec<i32> = cfgs
                .iter()
                .map(|&c| {
                    let mut attr = [0u64; 8];
                    attr[0] = (64 << 32) | 4; // PERF_TYPE_RAW (= cpu_core PMU type on this box)
                    attr[1] = c;
                    attr[5] = 1 | (1 << 5) | (1 << 6);
                    // SAFETY: valid perf_event_attr
                    let fd = unsafe { syscall(298, attr.as_ptr(), 0i32, -1i32, -1i32, 0u64) } as i32;
                    assert!(fd >= 0, "event {c:#x} refused");
                    fd
                })
                .collect();
            let mut best: Vec<u64> = vec![u64::MAX; cfgs.len()];
            for _ in 0..runs {
                for &fd in &fds {
                    // SAFETY: own fds
                    unsafe {
                        ioctl(fd, 0x2403, 0);
                        ioctl(fd, 0x2400, 0);
                    }
                }
                let out = xz::decompress(&data).unwrap();
                let mut v = vec![0u64; fds.len()];
                for (i, &fd) in fds.iter().enumerate() {
                    // SAFETY: own fds, 8-byte read
                    unsafe {
                        ioctl(fd, 0x2401, 0);
                        read(fd, &mut v[i] as *mut u64 as *mut std::ffi::c_void, 8);
                    }
                }
                drop(out);
                if v[0] < best[0] {
                    best = v;
                }
            }
            for (c, v) in cfgs.iter().zip(&best) {
                println!("{c:#010x} {v:>12} {:6.3}", *v as f64 / best[0] as f64);
            }
        }
        Some("profile") => {
            // profile EVENT PERIOD RUNS FILE -> "offset count" lines (offsets relative to the
            // executable's load base, for objdump), hottest first
            let (event, period, runs): (u64, u64, usize) =
                (args[2].parse().unwrap(), args[3].parse().unwrap(), args[4].parse().unwrap());
            let data = std::fs::read(&args[5]).unwrap();
            let mut s = Sampler::open(event, period);
            let mut hist = std::collections::HashMap::new();
            for _ in 0..runs {
                s.set(true);
                let out = xz::decompress(&data).unwrap();
                s.set(false);
                s.drain(&mut hist);
                drop(out);
            }
            let exe = std::fs::read_link("/proc/self/exe").unwrap();
            let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
            let base = maps
                .lines()
                .filter(|l| l.ends_with(&*exe.to_string_lossy()))
                .filter_map(|l| u64::from_str_radix(l.split('-').next()?, 16).ok())
                .min()
                .unwrap();
            let mut v: Vec<(u64, u64)> = hist.into_iter().map(|(ip, n)| (ip.wrapping_sub(base), n)).collect();
            v.sort_by(|a, b| b.1.cmp(&a.1));
            for (a, n) in v {
                println!("{a:x} {n}");
            }
        }
        #[cfg(lzma_stats)]
        Some("stats") => {
            // Symbol statistics (build with RUSTFLAGS_EXTRA="--cfg lzma_stats").
            for f in &args[2..] {
                for a in &lzma::STATS {
                    a.store(0, std::sync::atomic::Ordering::Relaxed);
                }
                let out = xz::decompress(&std::fs::read(f).unwrap()).unwrap();
                let s: Vec<u64> = lzma::STATS.iter().map(|a| a.load(std::sync::atomic::Ordering::Relaxed)).collect();
                println!("{f}: {} bytes", out.len());
                println!("  stats {s:?}");
            }
        }
        _ => {
            eprintln!("usage: codec_xz_micro bench RUNS FILE... | verify FILE... | loop SECONDS FILE");
            std::process::exit(2);
        }
    }
}
