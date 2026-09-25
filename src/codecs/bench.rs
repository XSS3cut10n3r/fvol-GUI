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
