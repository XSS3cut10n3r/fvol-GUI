//! Corpus verification + throughput harness (ignored by default).
//!
//! ```text
//! CODECS_CORPUS=/path/to/dir cargo test --profile fast codecs_corpus -- --ignored --nocapture
//! ```
//! Every `NAME[.VARIANT].{xz,lzma,gz,zz,bz2,lznt1}` file in the directory is decoded with the
//! matching codec and compared against `NAME` (when it exists; VARIANT is `lN`, `mt`, `x86`...);
//! the best of a few runs is reported.
//!
//! `codecs_bench_file` benches a single file the same way the C reference harness in
//! `bench/refbench/codecs_refbench.c` does (fresh output per run, best of N) and prints
//! `rust <codec> <file> <out_bytes> <best_ms> <MB/s>`.

use std::path::{Path, PathBuf};
use std::time::Instant;

/// `big.json.l9.gz` -> `big.json`, `isf.json.xz` -> `isf.json`.
fn reference_path(p: &Path) -> PathBuf {
    let base = p.with_extension("");
    let last = base.extension().map(|e| e.to_string_lossy().to_string()).unwrap_or_default();
    let variant = last.starts_with("mt")
        || last == "x86"
        || last == "delta"
        || (last.len() >= 2 && last.starts_with('l') && last.as_bytes()[1].is_ascii_digit());
    if variant { base.with_extension("") } else { base }
}

fn codec_of(ext: &str) -> &str {
    match ext {
        "gz" => "gzip",
        "zz" => "zlib",
        other => other,
    }
}

fn decode(codec: &str, data: &[u8]) -> Option<crate::error::Result<Vec<u8>>> {
    Some(match codec {
        "xz" => super::xz::decompress(data),
        "lzma" => super::lzma::decompress(data),
        "gzip" => super::gzip::decompress(data),
        "zlib" => super::zlib::decompress(data),
        "deflate" => super::inflate::decompress(data),
        "bz2" => super::bzip2::decompress(data),
        "lznt1" => super::lznt1::decompress(data),
        _ => return None,
    })
}

#[test]
#[ignore]
fn codecs_corpus() {
    let Ok(dir) = std::env::var("CODECS_CORPUS") else {
        eprintln!("set CODECS_CORPUS");
        return;
    };
    let runs: usize = std::env::var("CODECS_RUNS").ok().and_then(|s| s.parse().ok()).unwrap_or(3);
    let filter = std::env::var("CODECS_FILTER").unwrap_or_default();
    let mut paths: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.path()).collect();
    paths.sort();
    let mut failures = 0;
    for path in paths {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if !name.contains(&filter) {
            continue;
        }
        let Some(ext) = path.extension().map(|e| e.to_string_lossy().to_string()) else { continue };
        let data = std::fs::read(&path).unwrap();
        let ext = codec_of(&ext);
        let Some(first) = decode(ext, &data) else { continue };
        let reference = std::fs::read(reference_path(&path)).ok();
        let status = match (&first, &reference) {
            (Err(e), _) => format!("ERROR {e}"),
            (Ok(out), Some(r)) if out != r => format!("MISMATCH (got {} bytes, want {})", out.len(), r.len()),
            (Ok(_), Some(_)) => "ok".to_string(),
            (Ok(_), None) => "ok (no reference)".to_string(),
        };
        if !status.starts_with("ok") {
            failures += 1;
            println!("{name:40} {status}");
            continue;
        }
        let out_len = first.as_ref().map(|v| v.len()).unwrap_or(0);
        drop(first);
        let mut best = f64::MAX;
        for _ in 0..runs {
            let t = Instant::now();
            let r = decode(ext, &data).unwrap();
            let dt = t.elapsed().as_secs_f64();
            drop(r);
            best = best.min(dt);
        }
        println!(
            "{name:40} {status:18} {:>11} -> {:>11} bytes  {:8.2} ms  {:8.1} MB/s",
            data.len(),
            out_len,
            best * 1e3,
            out_len as f64 / best / 1e6
        );
    }
    assert_eq!(failures, 0, "{failures} corpus failures");
}

#[test]
#[ignore]
fn codecs_bench_file() {
    let (Ok(file), Ok(codec)) = (std::env::var("CODECS_BENCH_FILE"), std::env::var("CODECS_BENCH_CODEC")) else {
        eprintln!("set CODECS_BENCH_FILE and CODECS_BENCH_CODEC");
        return;
    };
    let runs: usize = std::env::var("CODECS_RUNS").ok().and_then(|s| s.parse().ok()).unwrap_or(10);
    let data = std::fs::read(&file).unwrap();
    let codec = if codec == "xz-mt" { "xz" } else { codec.as_str() };
    let out = decode(codec, &data).expect("unknown codec").expect("decode failed");
    if let Ok(reference) = std::fs::read(reference_path(Path::new(&file))) {
        assert!(out == reference, "{file}: output differs from reference");
    }
    let n = out.len();
    drop(out);
    let mut best = f64::MAX;
    let mut best_counts = [0u64; 3];
    let counters = perf::Counters::open();
    for _ in 0..runs {
        if let Some(c) = counters.as_ref() {
            c.start();
        }
        let t = Instant::now();
        let r = decode(codec, &data).unwrap().unwrap();
        let dt = t.elapsed().as_secs_f64();
        if let Some(c) = counters.as_ref() {
            let v = c.stop();
            if best_counts[0] == 0 || v[0] < best_counts[0] {
                best_counts = v;
            }
        }
        assert_eq!(r.len(), n);
        drop(r);
        best = best.min(dt);
    }
    // Fields 7..9: user-mode cycles, instructions, branch misses of the run with the fewest
    // cycles (0 when perf counters are unavailable).
    println!(
        "rust {codec} {file} {n} {:.3} {:.1} {} {} {}",
        best * 1e3,
        n as f64 / best / 1e6,
        best_counts[0],
        best_counts[1],
        best_counts[2]
    );
}

/// Sampling profile ("perf record" without perf): decodes CODECS_BENCH_FILE CODECS_RUNS times
/// (or encodes it with CODECS_BENCH_CODEC at level CODECS_ENC_LEVEL when that is set)
/// while sampling the instruction pointer every CODECS_PROFILE_PERIOD events of
/// CODECS_PROFILE_EVENT (0 = cycles, 5 = branch misses) and writes "vaddr count" lines
/// (addresses relative to the executable's load base, for addr2line) to CODECS_PROFILE_OUT.
#[test]
#[ignore]
fn codecs_profile_file() {
    let (Ok(file), Ok(codec), Ok(outp)) = (
        std::env::var("CODECS_BENCH_FILE"),
        std::env::var("CODECS_BENCH_CODEC"),
        std::env::var("CODECS_PROFILE_OUT"),
    ) else {
        eprintln!("set CODECS_BENCH_FILE, CODECS_BENCH_CODEC and CODECS_PROFILE_OUT");
        return;
    };
    let env = |k: &str, d: u64| std::env::var(k).ok().and_then(|s| s.parse().ok()).unwrap_or(d);
    let runs = env("CODECS_RUNS", 3);
    let event = env("CODECS_PROFILE_EVENT", 0);
    let period = env("CODECS_PROFILE_PERIOD", if event == 0 { 20011 } else { 211 });
    let data = std::fs::read(&file).unwrap();
    let mut s = perf::Sampler::open(event, period).expect("perf_event_open (sampling) failed");
    let mut hist: std::collections::HashMap<u64, u64> = std::collections::HashMap::new();
    for _ in 0..runs {
        s.start();
        let r = match std::env::var("CODECS_ENC_LEVEL").ok().and_then(|s| s.parse::<u32>().ok()) {
            Some(level) => encode(&codec, level, &data).expect("unknown codec"),
            None => decode(&codec, &data).unwrap().unwrap(),
        };
        s.stop();
        s.drain(&mut hist);
        drop(r);
    }
    // Load base of the executable = start of its mapping at file offset 0.
    let exe = std::fs::read_link("/proc/self/exe").unwrap();
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    let base = maps
        .lines()
        .filter(|l| l.ends_with(&*exe.to_string_lossy()))
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let range = it.next()?;
            let _perms = it.next()?;
            let off = u64::from_str_radix(it.next()?, 16).ok()?;
            let start = u64::from_str_radix(range.split('-').next()?, 16).ok()?;
            (off == 0).then_some(start)
        })
        .min()
        .unwrap();
    let mut v: Vec<(u64, u64)> = hist.into_iter().map(|(ip, n)| (ip.wrapping_sub(base), n)).collect();
    v.sort_by(|a, b| b.1.cmp(&a.1));
    let text: String = v.iter().map(|(a, n)| format!("{a:#x} {n}\n")).collect();
    std::fs::write(&outp, text).unwrap();
    println!("profile: {} samples at {} distinct addresses -> {outp} (exe {})", v.iter().map(|x| x.1).sum::<u64>(), v.len(), exe.display());
}

/// Minimal perf_event_open(2) wrapper (user-mode cycles / instructions / branch misses of
/// the calling thread), used only by the benchmarks. Unavailable counters yield None.
mod perf {
    use std::os::raw::{c_int, c_long, c_ulong};
    unsafe extern "C" {
        fn syscall(num: c_long, ...) -> c_long;
        fn ioctl(fd: c_int, req: c_ulong, ...) -> c_int;
        fn close(fd: c_int) -> c_int;
    }
    const SYS_PERF_EVENT_OPEN: c_long = 298;
    const IOC_ENABLE: c_ulong = 0x2400;
    const IOC_DISABLE: c_ulong = 0x2401;
    const IOC_RESET: c_ulong = 0x2403;

    pub struct Counters {
        fds: [c_int; 3],
    }

    fn open_one(config: u64) -> Option<c_int> {
        // perf_event_attr, PERF_ATTR_SIZE_VER0 (64 bytes).
        let mut attr = [0u64; 8];
        // Hybrid CPUs: PERF_TYPE_HARDWARE with the P-core PMU type in config bits 32..63.
        // RSVOL_PERF_PMU=cpu_atom when pinned to an E-core of a hybrid CPU.
        let pmu_name = std::env::var("RSVOL_PERF_PMU").unwrap_or_else(|_| "cpu_core".into());
        let pmu = std::fs::read_to_string(format!("/sys/bus/event_source/devices/{pmu_name}/type"))
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);
        attr[0] = 64u64 << 32; // type = PERF_TYPE_HARDWARE (0), size = 64
        attr[1] = config | (pmu << 32);
        attr[5] = 1 | (1 << 5) | (1 << 6); // disabled, exclude_kernel, exclude_hv
        // SAFETY: attr is a valid perf_event_attr of the declared size.
        let fd = unsafe {
            syscall(SYS_PERF_EVENT_OPEN, attr.as_ptr(), 0 as c_int, -1 as c_int, -1 as c_int, 0 as c_ulong)
        };
        if fd < 0 { None } else { Some(fd as c_int) }
    }

    impl Counters {
        pub fn open() -> Option<Counters> {
            // cycles, instructions, branch-misses
            Some(Counters { fds: [open_one(0)?, open_one(1)?, open_one(5)?] })
        }
        pub fn start(&self) {
            for &fd in &self.fds {
                // SAFETY: valid perf fds.
                unsafe {
                    ioctl(fd, IOC_RESET, 0 as c_ulong);
                    ioctl(fd, IOC_ENABLE, 0 as c_ulong);
                }
            }
        }
        pub fn stop(&self) -> [u64; 3] {
            let mut v = [0u64; 3];
            for (i, &fd) in self.fds.iter().enumerate() {
                // SAFETY: valid perf fds; reading one u64 counter value.
                unsafe {
                    ioctl(fd, IOC_DISABLE, 0 as c_ulong);
                    use std::io::Read;
                    use std::os::fd::FromRawFd;
                    let mut f = std::mem::ManuallyDrop::new(std::fs::File::from_raw_fd(fd));
                    let mut b = [0u8; 8];
                    if f.read_exact(&mut b).is_ok() {
                        v[i] = u64::from_ne_bytes(b);
                    }
                }
            }
            v
        }
    }

    impl Drop for Counters {
        fn drop(&mut self) {
            for &fd in &self.fds {
                // SAFETY: closing our own fds.
                unsafe { close(fd) };
            }
        }
    }

    unsafe extern "C" {
        fn mmap(addr: *mut u8, len: usize, prot: c_int, flags: c_int, fd: c_int, off: i64) -> *mut u8;
        fn munmap(addr: *mut u8, len: usize) -> c_int;
    }

    /// IP sampler backed by the perf ring buffer.
    pub struct Sampler {
        fd: c_int,
        ring: *mut u8,
        len: usize,
    }

    const DATA_PAGES: usize = 1 << 11; // 8 MiB of 16-byte samples

    impl Sampler {
        pub fn open(event: u64, period: u64) -> Option<Sampler> {
            let pmu = std::fs::read_to_string("/sys/bus/event_source/devices/cpu_core/type")
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .unwrap_or(0);
            let mut fd = -1;
            for precise in [2u64, 1, 0] {
                let mut attr = [0u64; 8];
                attr[0] = 64u64 << 32; // PERF_TYPE_HARDWARE, size 64
                attr[1] = event | (pmu << 32);
                attr[2] = period; // sample_period
                attr[3] = 1; // sample_type = PERF_SAMPLE_IP
                attr[5] = 1 | (1 << 5) | (1 << 6) | (precise << 15); // disabled, excl kernel/hv
                // SAFETY: valid perf_event_attr.
                fd = unsafe {
                    syscall(SYS_PERF_EVENT_OPEN, attr.as_ptr(), 0 as c_int, -1 as c_int, -1 as c_int, 0 as c_ulong)
                } as c_int;
                if fd >= 0 {
                    break;
                }
            }
            if fd < 0 {
                return None;
            }
            let len = (1 + DATA_PAGES) * 4096;
            // SAFETY: mapping the perf ring buffer of our own fd (PROT_READ|PROT_WRITE, MAP_SHARED).
            let ring = unsafe { mmap(std::ptr::null_mut(), len, 3, 1, fd, 0) };
            if ring as isize == -1 {
                return None;
            }
            Some(Sampler { fd, ring, len })
        }
        pub fn start(&self) {
            // SAFETY: valid perf fd.
            unsafe { ioctl(self.fd, IOC_ENABLE, 0 as c_ulong) };
        }
        pub fn stop(&self) {
            // SAFETY: valid perf fd.
            unsafe { ioctl(self.fd, IOC_DISABLE, 0 as c_ulong) };
        }
        /// Moves all buffered PERF_RECORD_SAMPLE IPs into `hist`.
        pub fn drain(&mut self, hist: &mut std::collections::HashMap<u64, u64>) {
            use std::sync::atomic::{AtomicU64, Ordering, fence};
            // SAFETY: perf_event_mmap_page: data_head at 1024, data_tail at 1032; data at page 1.
            unsafe {
                let head_p = &*(self.ring.add(1024) as *const AtomicU64);
                let tail_p = &*(self.ring.add(1032) as *const AtomicU64);
                let head = head_p.load(Ordering::Acquire);
                fence(Ordering::Acquire);
                let mut tail = tail_p.load(Ordering::Relaxed);
                let data = self.ring.add(4096);
                let size = (DATA_PAGES * 4096) as u64;
                let rd = |off: u64, n: usize| -> [u8; 16] {
                    let mut b = [0u8; 16];
                    for (i, x) in b.iter_mut().enumerate().take(n) {
                        *x = *data.add(((off + i as u64) % size) as usize);
                    }
                    b
                };
                while tail < head {
                    let h = rd(tail, 8);
                    let typ = u32::from_le_bytes(h[0..4].try_into().unwrap());
                    let sz = u16::from_le_bytes(h[6..8].try_into().unwrap()) as u64;
                    if sz == 0 {
                        break;
                    }
                    if typ == 9 && sz >= 16 {
                        let b = rd(tail + 8, 8);
                        let ip = u64::from_le_bytes(b[0..8].try_into().unwrap());
                        *hist.entry(ip).or_insert(0) += 1;
                    }
                    tail += sz;
                }
                fence(Ordering::Release);
                tail_p.store(head, Ordering::Release);
            }
        }
    }

    impl Drop for Sampler {
        fn drop(&mut self) {
            // SAFETY: our own mapping / fd.
            unsafe {
                munmap(self.ring, self.len);
                close(self.fd);
            }
        }
    }
}

/// Symbol statistics (build with RUSTFLAGS="--cfg lzma_stats").
#[cfg(lzma_stats)]
#[test]
#[ignore]
fn codecs_lzma_stats() {
    let Ok(dir) = std::env::var("CODECS_CORPUS") else { return };
    let filter = std::env::var("CODECS_FILTER").unwrap_or_else(|_| "big.json.xz".into());
    let data = std::fs::read(format!("{dir}/{filter}")).unwrap();
    let out = super::xz::decompress(&data).unwrap();
    let s: Vec<u64> = super::lzma::STATS.iter().map(|a| a.load(std::sync::atomic::Ordering::Relaxed)).collect();
    let syms = s[0] + s[1] + s[2] + s[3] + s[4];
    println!(
        "out {} syms {} lit {} mlit {} match {} (far {}) rep {} shortrep {} matchbytes {} avg_len {:.1} small_dist {} len>=18 {} bytes/sym {:.1}",
        out.len(), syms, s[0], s[1], s[2], s[10], s[3], s[4], s[8],
        s[8] as f64 / (s[2] + s[3]) as f64, s[9], s[11], out.len() as f64 / syms as f64
    );
    println!("decisions (normalize checks) {} normalizations {}", s[12], s[13]);
}

/// Where does the time go when decoding big.json.xz?
#[test]
#[ignore]
fn codecs_breakdown() {
    let Ok(dir) = std::env::var("CODECS_CORPUS") else { return };
    let data = std::fs::read(format!("{dir}/big.json.xz")).unwrap();
    let n = 49595956usize;
    for _ in 0..3 {
        let t = Instant::now();
        let mut v = vec![0u8; n];
        for i in (0..n).step_by(4096) {
            v[i] = 1;
        }
        let touch = t.elapsed();
        let t = Instant::now();
        let c = super::crc::crc64(&v);
        let crc = t.elapsed();
        let t = Instant::now();
        let mut w = vec![0u8; n];
        let off = 12 + 12; // stream header + block header of this file
        let (clen, _) = super::lzma::lzma2_scan(&data[off..]).unwrap();
        let scan = t.elapsed();
        let t = Instant::now();
        super::lzma::lzma2_decode_into(&data[off..off + clen], &mut w).unwrap();
        let dec = t.elapsed();
        let t = Instant::now();
        super::lzma::lzma2_decode_into(&data[off..off + clen], &mut w).unwrap();
        let dec2 = t.elapsed();
        println!(
            "alloc+touch {touch:?} crc64 {crc:?} ({c:x}) scan {scan:?} decode(fresh) {dec:?} decode(prefaulted) {dec2:?}"
        );
    }
}

/// Streams a file through a streaming encoder into another file (bounded memory: the input
/// is read in `CODECS_ENC_WRITE`-byte pieces, default 64 KiB) and prints wall time,
/// throughput and the process's peak RSS:
///
/// ```text
/// CODECS_ENC_FILE=in CODECS_ENC_OUT=out.gz CODECS_ENC_CODEC=gzip [CODECS_ENC_LEVEL=9] \
///   cargo test --release codecs_enc_stream_file -- --ignored --nocapture
/// ```
#[test]
#[ignore]
fn codecs_enc_stream_file() {
    use std::io::{Read, Write};
    let (Ok(file), Ok(outp), Ok(codec)) =
        (std::env::var("CODECS_ENC_FILE"), std::env::var("CODECS_ENC_OUT"), std::env::var("CODECS_ENC_CODEC"))
    else {
        eprintln!("set CODECS_ENC_FILE, CODECS_ENC_OUT and CODECS_ENC_CODEC");
        return;
    };
    let level: u32 = std::env::var("CODECS_ENC_LEVEL").ok().and_then(|s| s.parse().ok()).unwrap_or(9);
    let ws: usize = std::env::var("CODECS_ENC_WRITE").ok().and_then(|s| s.parse().ok()).unwrap_or(65536);
    let mut inp = std::fs::File::open(&file).unwrap();
    let out = std::io::BufWriter::with_capacity(1 << 20, std::fs::File::create(&outp).unwrap());
    let mut buf = vec![0u8; ws];
    let t = Instant::now();
    let mut total = 0u64;
    let mut feed = |w: &mut dyn Write| loop {
        let n = inp.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        total += n as u64;
        w.write_all(&buf[..n]).unwrap();
    };
    match codec.as_str() {
        "gzip" => {
            let mut e = super::gzip_enc::GzipEncoder::new(out, super::gzip_enc::GzipOptions::python(level, 0));
            feed(&mut e);
            e.finish().unwrap().flush().unwrap();
        }
        "bz2" => {
            let mut e = super::bzip2_enc::Bzip2Encoder::new(out, level);
            feed(&mut e);
            e.finish().unwrap().flush().unwrap();
        }
        _ => panic!("unknown streaming codec {codec}"),
    }
    let dt = t.elapsed().as_secs_f64();
    let hwm = std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find(|l| l.starts_with("VmHWM"))
        .map(|l| l.split_whitespace().nth(1).unwrap_or("0").to_string())
        .unwrap_or_default();
    let osz = std::fs::metadata(&outp).map(|m| m.len()).unwrap_or(0);
    println!(
        "rust-stream {codec} {level} {file} {total} {osz} {:.3} {:.1} threads={} peak_rss_kb={hwm}",
        dt * 1e3,
        total as f64 / dt / 1e6,
        crate::util::par::threads()
    );
}

/// Encoder under test: `codec` is deflate | zlib | gzip | bz2 | xz.
fn encode(codec: &str, level: u32, data: &[u8]) -> Option<Vec<u8>> {
    Some(match codec {
        "deflate" => super::deflate_enc::deflate_compress(data, level),
        "zlib" => super::deflate_enc::zlib_compress(data, level),
        "gzip" => super::gzip_enc::gzip_compress(data, &super::gzip_enc::GzipOptions::python(level, 0)),
        "bz2" => super::bzip2_enc::bzip2_compress(data, level),
        _ => return None,
    })
}

/// Compression throughput of one file (the Rust side of `bench/refbench/codecs_enc_run.sh`):
///
/// ```text
/// CODECS_ENC_FILE=f CODECS_ENC_CODEC=deflate CODECS_ENC_LEVEL=6 [CODECS_RUNS=3] [RSVOL_THREADS=1] \
///   cargo test --release codecs_enc_bench_file -- --ignored --nocapture
/// ```
/// Prints `rust <codec> <level> <file> <in_bytes> <out_bytes> <best_ms> <MB/s> <threads>` (MB/s
/// of input). The first result is round-tripped through our decoder.
#[test]
#[ignore]
fn codecs_enc_bench_file() {
    let (Ok(file), Ok(codec)) = (std::env::var("CODECS_ENC_FILE"), std::env::var("CODECS_ENC_CODEC")) else {
        eprintln!("set CODECS_ENC_FILE and CODECS_ENC_CODEC");
        return;
    };
    let level: u32 = std::env::var("CODECS_ENC_LEVEL").ok().and_then(|s| s.parse().ok()).unwrap_or(6);
    let runs: usize = std::env::var("CODECS_RUNS").ok().and_then(|s| s.parse().ok()).unwrap_or(3);
    let data = std::fs::read(&file).unwrap();
    let mut best = f64::MAX;
    let mut out_len = 0;
    let counters = perf::Counters::open();
    let mut best_cyc = 0u64;
    let mut best_counts = [0u64; 3];
    for r in 0..runs {
        if let Some(c) = counters.as_ref() {
            c.start();
        }
        let t = Instant::now();
        let c = encode(&codec, level, &data).expect("unknown codec");
        let dt = t.elapsed().as_secs_f64();
        if let Some(c) = counters.as_ref() {
            let v = c.stop();
            if best_cyc == 0 || v[0] < best_cyc {
                best_cyc = v[0];
                best_counts = v;
            }
        }
        best = best.min(dt);
        out_len = c.len();
        if r == 0 {
            let dec_codec = match codec.as_str() {
                "bz2" | "xz" | "gzip" | "zlib" => codec.as_str(),
                _ => "deflate",
            };
            let d = decode(dec_codec, &c).unwrap().expect("our decoder rejected the output");
            assert!(d == data, "{file}: roundtrip mismatch");
        }
    }
    #[cfg(deflate_stats)]
    {
        let v: Vec<u64> = super::deflate_enc::STATS.iter().map(|a| a.load(std::sync::atomic::Ordering::Relaxed)).collect();
        let n = data.len() as f64 * runs as f64;
        eprintln!(
            "stats per byte: finds {:.3} cands {:.3} (per find {:.2}) inserts {:.3} lits {:.3} matches {:.3} avg_len {:.1} blocks {}",
            v[0] as f64 / n, v[1] as f64 / n, v[1] as f64 / v[0].max(1) as f64, v[2] as f64 / n, v[3] as f64 / n,
            v[4] as f64 / n, v[5] as f64 / v[4].max(1) as f64, v[6] / runs as u64
        );
    }
    // Last fields: user-mode cycles, instructions and branch misses of the calling thread in
    // the fastest run (single-thread runs only; 0 without perf counters).
    println!(
        "rust {codec} {level} {file} {} {out_len} {:.3} {:.1} {} {best_cyc} {} {}",
        data.len(),
        best * 1e3,
        data.len() as f64 / best / 1e6,
        crate::util::par::threads(),
        best_counts[1],
        best_counts[2]
    );
}
