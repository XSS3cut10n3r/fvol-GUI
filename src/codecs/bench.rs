//! Corpus verification + throughput harness (ignored by default).
//!
//! ```text
//! CODECS_CORPUS=/path/to/dir cargo test --profile fast codecs_corpus -- --ignored --nocapture
//! ```
//! Every `NAME.{xz,lzma,gz,zz,bz2,lznt1}` file in the directory is decoded with the matching
//! codec and compared against `NAME` (when it exists); the best of a few runs is reported.

use std::time::Instant;

fn decode(ext: &str, data: &[u8]) -> Option<crate::error::Result<Vec<u8>>> {
    Some(match ext {
        "xz" => super::xz::decompress(data),
        "lzma" => super::lzma::decompress(data),
        // "gz" => super::gzip::decompress(data),
        // "zz" => super::zlib::decompress(data),
        // "bz2" => super::bzip2::decompress(data),
        // "lznt1" => super::lznt1::decompress(data),
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
        let Some(first) = decode(&ext, &data) else { continue };
        let reference = std::fs::read(path.with_extension("")).ok();
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
            let r = decode(&ext, &data).unwrap();
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
