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

const SYNTH: &[u8] = include_bytes!("testdata/synth.pdb");

/// A synthetic PDB (testdata/mksynth.py) covering OMAP, pascal leaves/symbols, extended
/// numeric leaves, forward-referenced arrays, pointer32/pointer64 bases, renamed anonymous
/// tags, the LF_UNION size quirk, IPI naming, name_strip...: byte-identical to python.
#[test]
fn synthetic_matches_python() {
    let ours = pdb_to_isf_bytes(SYNTH, None, "X").unwrap();
    let golden = include_bytes!("testdata/synth.py.json");
    if normalize(&ours) != normalize(golden) {
        let (o, g) = (String::from_utf8_lossy(&ours), String::from_utf8_lossy(golden));
        let line = o.lines().zip(g.lines()).position(|(a, b)| a != b && !a.contains("datetime"));
        panic!("differs from python at line {line:?}");
    }
    // pdbutil-style naming
    let named = pdb_to_isf_bytes(SYNTH, Some("synth.pdb"), "X").unwrap();
    assert!(std::str::from_utf8(&named).unwrap().contains("\"database\": \"synth.pdb\""));
}

/// Inputs on which python raises must fail here too.
#[test]
fn synthetic_error_parity() {
    let cases: [(&str, &[u8]); 7] = [
        // stream directory claiming 0xfd000008 streams: python wraps around the directory
        // forever; we refuse it (this input used to exhaust memory)
        ("dir_wrap", include_bytes!("testdata/err_dir_wrap.pdb")),
        ("zero_elem", include_bytes!("testdata/err_zero_elem.pdb")),
        ("ptrmix", include_bytes!("testdata/err_ptrmix.pdb")),
        ("unhandled", include_bytes!("testdata/err_unhandled.pdb")),
        ("quad_enum", include_bytes!("testdata/err_quad_enum.pdb")),
        ("strip_idx", include_bytes!("testdata/err_strip_idx.pdb")),
        ("omap_high", include_bytes!("testdata/err_omap_high.pdb")),
    ];
    for (name, pdb) in cases {
        assert!(pdb_to_isf_bytes(pdb, None, "X").is_err(), "{name} should fail like python");
    }
}

/// Mutations of the synthetic PDB (small, so most mutations land in parsed structures)
/// must never panic.
#[test]
fn synthetic_mutations_never_panic() {
    let mut rng = 0x243f_6a88_85a3_08d3u64;
    let mut next = move || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    const INTERESTING: [u8; 10] = [0, 1, 0x7f, 0x80, 0xff, 0x10, 0x15, 0xf1, 0x03, 0x12];
    let iters: usize = std::env::var("RSVOL_MUT_ITERS").ok().and_then(|s| s.parse().ok()).unwrap_or(3000);
    for _it in 0..iters {
        let mut m = SYNTH.to_vec();
        for _ in 0..1 + next() % 8 {
            let pos = (next() % m.len() as u64) as usize;
            m[pos] = if next() % 2 == 0 { INTERESTING[(next() % 10) as usize] } else { next() as u8 };
        }
        if next() % 16 == 0 {
            m.truncate((next() % m.len() as u64) as usize);
        }
        // RSVOL_MUT_TRACE=<file>: keep the input being converted (to reproduce a crash / OOM)
        if let Some(path) = std::env::var_os("RSVOL_MUT_TRACE") {
            eprintln!("mutation {_it}");
            std::fs::write(path, &m).unwrap();
        }
        let _ = pdb_to_isf_bytes(&m, None, "X");
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

/// Batch comparison: every `RSVOL_PDB_DIR/<name>/<GUIDage>/<name>.pdb` is converted
/// (`pdbconv.py -f` semantics) and compared byte for byte with
/// `RSVOL_REF_DIR/<name>.<GUIDage>.f.json`; a missing reference means python failed, in
/// which case the conversion must fail too.
#[test]
#[ignore]
fn compare_dir() {
    let dir = std::path::PathBuf::from(std::env::var("RSVOL_PDB_DIR").expect("RSVOL_PDB_DIR"));
    let refs = std::path::PathBuf::from(std::env::var("RSVOL_REF_DIR").expect("RSVOL_REF_DIR"));
    let mut bad = 0;
    let mut entries = Vec::new();
    for n in std::fs::read_dir(&dir).unwrap() {
        let n = n.unwrap().path();
        for g in std::fs::read_dir(&n).unwrap() {
            let g = g.unwrap().path();
            let name = n.file_name().unwrap().to_string_lossy().to_string();
            entries.push((name.clone(), g.file_name().unwrap().to_string_lossy().to_string(), g.join(&name)));
        }
    }
    entries.sort();
    for (name, guid, pdb_path) in entries {
        let pdb = std::fs::read(&pdb_path).unwrap();
        let stem = name.trim_end_matches(".pdb");
        let reference = std::fs::read(refs.join(format!("{stem}.{guid}.f.json"))).ok();
        let t = std::time::Instant::now();
        let ours = pdb_to_isf_bytes(&pdb, None, "X");
        let dt = t.elapsed();
        let verdict = match (&ours, &reference) {
            (Ok(o), Some(r)) if normalize(o) == normalize(r) => "IDENTICAL".to_string(),
            (Ok(_), Some(_)) => {
                bad += 1;
                "DIFFERENT".to_string()
            }
            (Err(e), None) => format!("both fail ({e})"),
            (Ok(_), None) => {
                bad += 1;
                "python failed, ours succeeded".to_string()
            }
            (Err(e), Some(_)) => {
                bad += 1;
                format!("OURS FAILED: {e}")
            }
        };
        eprintln!("{name:<16} {guid:<34} {:>9} bytes {dt:>12?}  {verdict}", pdb.len());
        if let (Ok(o), Ok(dirout)) = (&ours, std::env::var("RSVOL_OUT_DIR")) {
            std::fs::write(std::path::Path::new(&dirout).join(format!("{stem}.{guid}.json")), o).unwrap();
        }
    }
    assert_eq!(bad, 0);
}

/// Differential test of [`pe_codeview_info`] against volatility3's
/// `PDBUtility.get_guid_from_mz` (pefile): `RSVOL_PE_REF` is a TSV of
/// `path<TAB>None` / `path<TAB>GUID<TAB>age<TAB>name` lines produced by python over the
/// same files (zero padded to SizeOfImage).
#[test]
#[ignore]
fn pe_codeview_matches_python() {
    let reference = std::fs::read_to_string(std::env::var("RSVOL_PE_REF").expect("RSVOL_PE_REF")).unwrap();
    let (mut same, mut found, mut diff) = (0, 0, 0);
    let t_all = std::time::Instant::now();
    for line in reference.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        let mut data = std::fs::read(f[0]).unwrap();
        if let Some(n) = pe_image_size(&data)
            && (n as usize) > data.len()
            && n < (256 << 20)
        {
            data.resize(n as usize, 0);
        }
        let ours = match pe_codeview_info(&data) {
            None => "None".to_string(),
            Some(cv) => format!("{}\t{}\t{}", cv.guid, cv.age, cv.pdb_name),
        };
        let want = f[1..].join("\t");
        if ours == want {
            same += 1;
            found += (want != "None") as usize;
        } else {
            diff += 1;
            eprintln!("DIFF {}\n  python: {want}\n  rsvol:  {ours}", f[0]);
        }
    }
    eprintln!("{same} identical ({found} with CodeView info), {diff} different, in {:?}", t_all.elapsed());
    assert_eq!(diff, 0);
}

/// Downloads every `name<TAB>GUID<TAB>age` line of `RSVOL_DL_LIST` into
/// `RSVOL_DL_DIR/<name>/<GUID><age>/<name>` with [`download_pdb`].
#[test]
#[ignore]
fn download_list() {
    let list = std::fs::read_to_string(std::env::var("RSVOL_DL_LIST").expect("RSVOL_DL_LIST")).unwrap();
    let dir = std::path::PathBuf::from(std::env::var("RSVOL_DL_DIR").expect("RSVOL_DL_DIR"));
    for line in list.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 3 {
            continue;
        }
        let (name, guid, age) = (f[0], f[1], f[2].parse::<u32>().unwrap());
        let out = dir.join(name).join(format!("{guid}{age}")).join(name);
        if out.exists() {
            continue;
        }
        let t = std::time::Instant::now();
        match download_pdb(name, guid, age, false) {
            Ok(data) => {
                std::fs::create_dir_all(out.parent().unwrap()).unwrap();
                std::fs::write(&out, &data).unwrap();
                eprintln!("ok   {name} {guid} {age}: {} bytes in {:?}", data.len(), t.elapsed());
            }
            Err(e) => eprintln!("FAIL {name} {guid} {age}: {e}"),
        }
    }
}

/// `download_and_convert` end to end into `RSVOL_DL_DIR`.
#[test]
#[ignore]
fn download_and_convert_ntkrnlmp() {
    let dir = std::path::PathBuf::from(std::env::var("RSVOL_DL_DIR").expect("RSVOL_DL_DIR"));
    let t = std::time::Instant::now();
    let (p, json) = download_and_convert("ntkrnlmp.pdb", "8e3373d6124e747f0e72ef8e02e676b3", 1, std::slice::from_ref(&dir), false).unwrap();
    eprintln!("{} in {:?}", p.display(), t.elapsed());
    assert!(p.ends_with("windows/ntkrnlmp.pdb/8E3373D6124E747F0E72EF8E02E676B3-1.json.xz"));
    assert_eq!(crate::codecs::xz::decompress(&std::fs::read(&p).unwrap()).unwrap(), json);
    assert!(download_and_convert("ntkrnlmp.pdb", "8e3373d6124e747f0e72ef8e02e676b3", 1, &[dir], true).is_err());
}
