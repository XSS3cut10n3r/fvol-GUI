//! Developer throughput check over the real memory image (ignored test):
//!   RSVOL_PERF_LEN=1073741824 cargo test --profile fast yara_regex_perf -- --ignored --nocapture
//! Optional RSVOL_PERF_PAT=<pattern> (python bytes-pattern syntax) to time one pattern.

use super::Regex;
use crate::util::mmap::Mmap;
use std::time::Instant;

#[test]
#[ignore]
fn yara_regex_perf() {
    let path = std::env::var("RSVOL_IMAGE").unwrap_or_else(|_| "/home/user/cbc2/task2/memory-dirty.raw".into());
    let Ok(f) = std::fs::File::open(&path) else { return };
    let Ok(m) = Mmap::map(&f) else { return };
    let len: usize = std::env::var("RSVOL_PERF_LEN").ok().and_then(|s| s.parse().ok()).unwrap_or(256 << 20);
    let off = (1usize << 30).min(m.len().saturating_sub(len));
    let hay = &m.as_slice()[off..off + len.min(m.len())];
    // warm the page cache
    let mut x = 0u64;
    for i in (0..hay.len()).step_by(4096) {
        x = x.wrapping_add(hay[i] as u64);
    }
    eprintln!("window {} MiB (checksum {x})", hay.len() >> 20);
    let default: Vec<(&str, u32)> = vec![
        ("Microsoft", 0),
        (r"\\Device\\HarddiskVolume\d+", 0),
        (r"[a-z]{5,}\.exe", 0),
        ("kernel32|ntdll|svchost|explorer|lsass|winlogon|csrss|services|smss|wininit|spoolsv|taskhost|dwm|conhost|rundll32|regsvr32|powershell|cmd\\.exe|userinit|mstsc", 0),
        ("(?i)password", 0),
        (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", 0),
        (r"https?://[a-zA-Z0-9./?=_%:-]+", 0),
        (r"\x0f\x05[^\xc3]{,24}\xc3", 16),
    ];
    let pats: Vec<(String, u32)> = match std::env::var("RSVOL_PERF_PAT") {
        Ok(p) => vec![(p, 16)],
        Err(_) => default.into_iter().map(|(p, f)| (p.to_string(), f)).collect(),
    };
    for (p, flags) in pats {
        let t0 = Instant::now();
        let re = match Regex::new(p.as_bytes(), flags) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("{p}: compile error {e}");
                continue;
            }
        };
        let ct = t0.elapsed();
        let mut best = f64::MAX;
        let mut n = 0;
        for _ in 0..3 {
            let t = Instant::now();
            n = re.find_iter(hay).count();
            best = best.min(t.elapsed().as_secs_f64());
        }
        eprintln!(
            "{:>10.1} MB/s  {:>8} matches  compile {:>7.1}us  engine={:<11} {}",
            hay.len() as f64 / best / 1e6,
            n,
            ct.as_secs_f64() * 1e6,
            re.engine_name(),
            p
        );
    }
}
