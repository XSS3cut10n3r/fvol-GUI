//! Tests of the PDB -> ISF converter.
//!
//! Heavy comparisons against python output live in ignored tests driven by environment
//! variables (see `compare_with_python_reference`).

use super::*;
use std::path::Path;

const NT_PDB: &str = "/.cache/vol-rs/pdb/ntkrnlmp.pdb/8E3373D6124E747F0E72EF8E02E676B31/ntkrnlmp.pdb";

fn home_file(rel: &str) -> Option<Vec<u8>> {
    let home = std::env::var("HOME").ok()?;
    std::fs::read(Path::new(&(home + rel))).ok()
}

/// Replaces the value of the `"datetime"` key so outputs can be compared byte for byte.
fn normalize(json: &[u8]) -> Vec<u8> {
    let key = b"\"datetime\": \"";
    let Some(p) = json.windows(key.len()).position(|w| w == key) else { return json.to_vec() };
    let start = p + key.len();
    let end = start + json[start..].iter().position(|&c| c == b'"').unwrap_or(0);
    let mut out = json[..start].to_vec();
    out.extend_from_slice(b"X");
    out.extend_from_slice(&json[end..]);
    out
}

#[test]
fn datetime_format() {
    let s = python_now_isoformat();
    assert!(s.len() == 19 || s.len() == 26, "{s}");
    assert_eq!(&s[4..5], "-");
    assert_eq!(&s[10..11], "T");
    assert_eq!(utc_time(0), (1970, 1, 1, 0, 0, 0));
    assert_eq!(utc_time(951782400), (2000, 2, 29, 0, 0, 0));
    assert_eq!(utc_time(4102444799), (2099, 12, 31, 23, 59, 59));
}

#[test]
fn garbage_never_panics() {
    let mut rng = 0x1234_5678_9abc_def0u64;
    let mut next = || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    for len in [0usize, 1, 10, 60, 100, 4096, 8192] {
        let mut v: Vec<u8> = (0..len).map(|_| next() as u8).collect();
        assert!(pdb_to_isf_json(&v).is_err());
        if v.len() > 64 {
            v[..32].copy_from_slice(b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0");
            let _ = pdb_to_isf_json(&v);
        }
    }
}

#[test]
fn ntkrnlmp_if_present() {
    let Some(pdb) = home_file(NT_PDB) else { return };
    let out = pdb_to_isf_bytes(&pdb, Some("ntkrnlmp.pdb"), "2026-01-01T00:00:00").unwrap();
    let s = std::str::from_utf8(&out).unwrap();
    assert!(s.starts_with("{\n  \"base_types\": {\n    \"HRESULT\": {"));
    assert!(s.contains("\"GUID\": \"8E3373D6124E747F0E72EF8E02E676B3\""));
    assert!(s.contains("\"database\": \"ntkrnlmp.pdb\""));
    assert!(s.contains("    \"_EPROCESS\": {\n      \"fields\": {"));
    assert!(s.ends_with("\n}"));
    // -f style naming comes from the IPI stream
    let out2 = pdb_to_isf_bytes(&pdb, None, "2026-01-01T00:00:00").unwrap();
    assert_eq!(out, out2);
}

/// `RSVOL_PDB=<file.pdb> RSVOL_REF=<python json> [RSVOL_DB=<name>] cargo test ... -- --ignored`
#[test]
#[ignore]
fn compare_with_python_reference() {
    let pdb = std::fs::read(std::env::var("RSVOL_PDB").expect("RSVOL_PDB")).unwrap();
    let reference = std::fs::read(std::env::var("RSVOL_REF").expect("RSVOL_REF")).unwrap();
    let db = std::env::var("RSVOL_DB").ok();
    let t = std::time::Instant::now();
    let ours = pdb_to_isf_bytes(&pdb, db.as_deref(), "X").unwrap();
    eprintln!("converted in {:?}", t.elapsed());
    if let Ok(out) = std::env::var("RSVOL_OUT") {
        std::fs::write(out, &ours).unwrap();
    }
    assert!(normalize(&ours) == normalize(&reference), "output differs from the python reference");
}

/// `RSVOL_PDB=<file.pdb> [RSVOL_ITERS=n] cargo test --profile fast ... bench_convert -- --ignored --nocapture`
#[test]
#[ignore]
fn bench_convert() {
    let pdb = std::fs::read(std::env::var("RSVOL_PDB").expect("RSVOL_PDB")).unwrap();
    let iters: usize = std::env::var("RSVOL_ITERS").ok().and_then(|s| s.parse().ok()).unwrap_or(20);
    let mut best = std::time::Duration::MAX;
    let mut len = 0;
    for _ in 0..iters {
        let t = std::time::Instant::now();
        let out = pdb_to_isf_bytes(&pdb, Some("x.pdb"), "X").unwrap();
        best = best.min(t.elapsed());
        len = out.len();
    }
    eprintln!("best of {iters}: {:?} ({} bytes out)", best, len);
}

/// Random byte mutations of a real PDB must never panic.
/// `RSVOL_PDB=<file.pdb> [RSVOL_ITERS=n] cargo test ... fuzz_mutations -- --ignored`
#[test]
#[ignore]
fn fuzz_mutations() {
    let pdb = std::fs::read(std::env::var("RSVOL_PDB").expect("RSVOL_PDB")).unwrap();
    let iters: usize = std::env::var("RSVOL_ITERS").ok().and_then(|s| s.parse().ok()).unwrap_or(200);
    let mut rng = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    let (mut ok, mut err) = (0, 0);
    for _ in 0..iters {
        let mut m = pdb.clone();
        let n = 1 + next() % 16;
        for _ in 0..n {
            let pos = (next() % m.len() as u64) as usize;
            m[pos] = next() as u8;
        }
        if next() % 8 == 0 {
            m.truncate((next() % m.len() as u64) as usize);
        }
        match pdb_to_isf_bytes(&m, None, "X") {
            Ok(_) => ok += 1,
            Err(_) => err += 1,
        }
    }
    eprintln!("fuzz: {ok} ok, {err} errors");
}

/// Machine calibration for the benchmark numbers (raw sort / write throughput).
#[test]
#[ignore]
fn calibrate() {
    let mut rng = 0x9e37_79b9_7f4a_7c15u64;
    let orig: Vec<u128> = (0..43000u128)
        .map(|i| {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            ((rng as u128) << 64) | i
        })
        .collect();
    let mut v = orig.clone();
    let mut best = std::time::Duration::MAX;
    for _ in 0..20 {
        v.copy_from_slice(&orig);
        let t = std::time::Instant::now();
        v.sort_unstable();
        best = best.min(t.elapsed());
    }
    eprintln!("sort 43k u128: {best:?}");
    let mut best = std::time::Duration::MAX;
    for _ in 0..20 {
        let t = std::time::Instant::now();
        let mut b: Vec<u8> = Vec::with_capacity(4 << 20);
        for i in 0..43000u32 {
            b.extend_from_slice(b",\n    \"SomeSymbolName\": {\n      \"address\": ");
            b.extend_from_slice(i.to_string().as_bytes());
            b.extend_from_slice(b"\n    }");
        }
        best = best.min(t.elapsed());
        std::hint::black_box(&b);
    }
    eprintln!("write 43k entries: {best:?}");
}
