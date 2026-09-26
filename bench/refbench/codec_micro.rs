//! Standalone codec micro-benchmark: compiles src/codecs/{snappy,xpress}.rs directly with
//! rustc (seconds instead of a crate build), checks every chunk against the snappy output and
//! prints best-of-N throughput on the refbench vectors. Built and run by codec_micro.sh.
#![allow(dead_code)]
mod error {
    #[derive(Debug)]
    pub enum Error {
        Msg(String),
    }
}
#[path = "../../src/codecs/snappy.rs"]
mod snappy;
#[path = "../../src/codecs/xpress.rs"]
mod xpress;

fn pin(cpu: usize) {
    unsafe extern "C" {
        fn sched_setaffinity(pid: i32, size: usize, mask: *const u64) -> i32;
    }
    let mut mask = [0u64; 16];
    mask[cpu / 64] = 1 << (cpu % 64);
    // SAFETY: plain syscall wrapper with a valid mask buffer
    unsafe { sched_setaffinity(0, 128, mask.as_ptr()) };
}

/// User-space hardware counters of this thread (perf_event_open; P-core PMU on hybrid
/// Intel parts). Silently absent when the kernel refuses.
struct Counters {
    fds: Vec<i32>,
}

impl Counters {
    const EVENTS: [(u64, &'static str); 3] = [(0, "cycles"), (1, "instructions"), (5, "branch-misses")];

    fn open() -> Counters {
        unsafe extern "C" {
            fn syscall(n: i64, ...) -> i64;
        }
        // cpu_core PMU type on hybrid parts (extended hardware event type), else plain
        let ext: u64 = std::fs::read_to_string("/sys/bus/event_source/devices/cpu_core/type")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        let mut fds = Vec::new();
        for (ev, _) in Self::EVENTS {
            // perf_event_attr, PERF_ATTR_SIZE_VER0 (64 bytes)
            let mut attr = [0u64; 8];
            attr[0] = 64 << 32; // type = PERF_TYPE_HARDWARE (0), size = 64
            attr[1] = (ext << 32) | ev;
            attr[5] = (1 << 0) | (1 << 5) | (1 << 6); // flags: disabled, exclude_kernel, exclude_hv
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

    fn stop(&self) -> Vec<u64> {
        unsafe extern "C" {
            fn ioctl(fd: i32, req: u64, ...) -> i32;
            fn read(fd: i32, buf: *mut std::ffi::c_void, n: usize) -> isize;
        }
        self.fds
            .iter()
            .map(|&fd| {
                let mut v = 0u64;
                // SAFETY: PERF_EVENT_IOC_DISABLE, then an 8-byte counter read
                unsafe {
                    ioctl(fd, 0x2401, 0);
                    read(fd, &mut v as *mut u64 as *mut std::ffi::c_void, 8);
                }
                v
            })
            .collect()
    }
}

fn load(dir: &str, name: &str) -> Vec<(usize, Vec<u8>)> {
    let d = std::fs::read(format!("{dir}/{name}")).unwrap();
    let mut v = Vec::new();
    let mut i = 0;
    while i + 8 <= d.len() {
        let ul = u32::from_le_bytes(d[i..i + 4].try_into().unwrap()) as usize;
        let cl = u32::from_le_bytes(d[i + 4..i + 8].try_into().unwrap()) as usize;
        v.push((ul, d[i + 8..i + 8 + cl].to_vec()));
        i += 8 + cl;
    }
    v
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = args.get(1).cloned().expect("usage: codec_micro VECDIR [REPS] [FILTER]");
    let reps: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(9);
    let only: String = args.get(3).cloned().unwrap_or_default();
    if let Some(cpu) = std::env::var("RSVOL_BENCH_CPU").ok().and_then(|v| v.parse().ok()) {
        pin(cpu);
    }
    type Dec = fn(&[u8], &mut [u8]) -> bool;
    let sets: [(&str, Vec<(usize, Vec<u8>)>, Dec); 3] = [
        ("snappy", load(&dir, "snappy.vec"), |c, o| snappy::decompress_into(c, o).is_ok()),
        ("xpress_huff", load(&dir, "xpress_huff.vec"), |c, o| xpress::huffman_decompress_into(c, o) == Ok(o.len())),
        ("xpress_lz77", load(&dir, "xpress_lz77.vec"), |c, o| xpress::lz77_decompress_into(c, o) == Ok(o.len())),
    ];
    // correctness: identical outputs across formats (poisoned buffer before every decode)
    let mut out = vec![0u8; 65536];
    let mut reference: Vec<Vec<u8>> = Vec::new();
    for (k, (name, v, dec)) in sets.iter().enumerate() {
        for (i, (ul, c)) in v.iter().enumerate() {
            out.fill(0xcc);
            assert!(dec(c, &mut out[..*ul]), "{name}: chunk {i} failed to decode");
            if k == 0 {
                reference.push(out[..*ul].to_vec());
            } else {
                assert_eq!(&out[..*ul], &reference[i][..], "{name}: chunk {i} differs");
            }
        }
    }
    let pmu = Counters::open();
    for (name, v, dec) in &sets {
        if !only.is_empty() && !name.contains(only.as_str()) {
            continue;
        }
        let mut best = f64::MAX;
        let mut best_counts = Vec::new();
        let mut total = 0usize;
        for _ in 0..reps {
            total = 0;
            pmu.start();
            let t = std::time::Instant::now();
            for (ul, c) in v {
                std::hint::black_box(dec(c, &mut out[..*ul]));
                total += ul;
            }
            let dt = t.elapsed().as_secs_f64();
            let counts = pmu.stop();
            if dt < best {
                best = dt;
                best_counts = counts;
            }
        }
        let mut extra = String::new();
        if let [cyc, ins, bm] = best_counts[..] {
            let n = v.len() as f64;
            extra = format!(
                "  {:.3} cyc/B  IPC {:.2}  {:.0} cyc/chunk  {:.0} br-miss/chunk  ({:.2} GHz)",
                cyc as f64 / total as f64,
                ins as f64 / cyc as f64,
                cyc as f64 / n,
                bm as f64 / n,
                cyc as f64 / best / 1e9
            );
        }
        println!("{name:<12} rsvol {:8.1} MB/s  ({} chunks, best of {reps}){extra}", total as f64 / best / 1e6, v.len());
    }
}
