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
    for (name, v, dec) in &sets {
        if !only.is_empty() && !name.contains(only.as_str()) {
            continue;
        }
        let mut best = f64::MAX;
        let mut total = 0usize;
        for _ in 0..reps {
            total = 0;
            let t = std::time::Instant::now();
            for (ul, c) in v {
                std::hint::black_box(dec(c, &mut out[..*ul]));
                total += ul;
            }
            best = best.min(t.elapsed().as_secs_f64());
        }
        println!("{name:<12} rsvol {:8.1} MB/s  ({} chunks, best of {reps})", total as f64 / best / 1e6, v.len());
    }
}
