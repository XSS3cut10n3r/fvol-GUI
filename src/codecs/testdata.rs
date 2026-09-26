//! Shared deterministic test data for the codec tests (mirrors gen_xpress.py:gen_data).
#![cfg(test)]

pub(crate) fn fixture(name: &str) -> Vec<u8> {
    let p = format!("{}/tests/fixtures/codecs/{}", env!("CARGO_MANIFEST_DIR"), name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

/// Mirror of gen_data() in gen_xpress.py.
pub(crate) fn gen_data(seed: u64, n: usize) -> Vec<u8> {
    const WORDS: [&[u8]; 9] = [
        b"volatility",
        b"memory",
        b"kernel",
        b"\0\0\0\0\0\0\0\0",
        b"process",
        b"handle",
        b"\\Device\\HarddiskVolume3\\Windows",
        b"ntoskrnl.exe",
        b"\xff\xff",
    ];
    let mut x = seed;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let mut out: Vec<u8> = Vec::new();
    while out.len() < n {
        let r = next() % 100;
        if r < 30 {
            out.extend_from_slice(WORDS[(next() % WORDS.len() as u64) as usize]);
        } else if r < 40 {
            let k = (next() % 700) as usize;
            out.resize(out.len() + k, 0);
        } else if r < 55 && !out.is_empty() {
            let start = (next() % out.len() as u64) as usize;
            let ln = (next() % 300) as usize;
            let end = (start + ln).min(out.len());
            let piece = out[start..end].to_vec();
            out.extend_from_slice(&piece);
        } else {
            let k = 1 + next() % 16;
            for _ in 0..k {
                out.push(next() as u8);
            }
        }
    }
    out.truncate(n);
    out
}


/// Codec throughput on the vectors written by bench/refbench (`refbench mkvec`): 64 KiB chunks
/// of real memory as [u32 ulen][u32 clen][data]. All three files hold the same chunks, so the
/// decoded outputs must be identical (cross-checks the xpress decoders against libsnappy's
/// output). Run through bench/refbench/run.sh.
#[test]
#[ignore]
fn codec_bench() {
    use crate::codecs::{snappy, xpress};
    let Ok(dir) = std::env::var("RSVOL_CODEC_BENCH") else { return };
    let reps: usize = std::env::var("RSVOL_BENCH_REPS").ok().and_then(|v| v.parse().ok()).unwrap_or(7);
    let load = |name: &str| -> Vec<(usize, Vec<u8>)> {
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
    };
    type Dec = fn(&[u8], &mut [u8]) -> bool;
    let sets: [(&str, Vec<(usize, Vec<u8>)>, Dec); 3] = [
        ("snappy", load("snappy.vec"), |c, o| snappy::decompress_into(c, o).is_ok()),
        ("xpress_huff", load("xpress_huff.vec"), |c, o| xpress::huffman_decompress_into(c, o) == Ok(o.len())),
        ("xpress_lz77", load("xpress_lz77.vec"), |c, o| xpress::lz77_decompress_into(c, o) == Ok(o.len())),
    ];
    // correctness: identical outputs across formats
    let mut out = vec![0u8; 65536];
    let mut reference: Vec<Vec<u8>> = Vec::new();
    for (k, (name, v, dec)) in sets.iter().enumerate() {
        for (i, (ul, c)) in v.iter().enumerate() {
            assert!(dec(c, &mut out[..*ul]), "{name}: chunk {i} failed to decode");
            if k == 0 {
                reference.push(out[..*ul].to_vec());
            } else {
                assert_eq!(&out[..*ul], &reference[i][..], "{name}: chunk {i} differs from snappy");
            }
        }
    }
    for (name, v, dec) in &sets {
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
