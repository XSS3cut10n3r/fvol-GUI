//! Developer throughput check over the real memory image (ignored test):
//!   FASTVOL_PERF_LEN=1073741824 cargo test --profile fast yara_regex_perf -- --ignored --nocapture
//! Optional FASTVOL_PERF_PAT=<pattern> (python bytes-pattern syntax) to time one pattern.

use super::Regex;
use crate::util::mmap::Mmap;
use std::time::Instant;

#[test]
#[ignore]
fn yara_regex_perf() {
    let path = crate::util::env::var("IMAGE").unwrap_or_else(|_| "/home/user/cbc2/task2/memory-dirty.raw".into());
    let Ok(f) = std::fs::File::open(&path) else { return };
    let Ok(m) = Mmap::map(&f) else { return };
    let len: usize = crate::util::env::var("PERF_LEN").ok().and_then(|s| s.parse().ok()).unwrap_or(256 << 20);
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
    let pats: Vec<(String, u32)> = match crate::util::env::var("PERF_PAT") {
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

/// Interleaved A/B timing of several patterns (developer probe, ignored test):
///   FASTVOL_AB_PATS='p1<TAB>p2...' FASTVOL_AB_ROUNDS=15 FASTVOL_AB_LEN=1073741824 \
///   cargo test --profile release yara_regex_ab -- --ignored --nocapture
/// A pattern prefixed with `mm:` times `memchr::Memmem::find_iter` of the raw bytes instead.
/// Prints best / median / lower-quartile MB/s per pattern (window: 1 GiB at 1 GiB, like
/// refbench). Interleaving makes the comparison robust on a busy machine.
#[test]
#[ignore]
fn yara_regex_ab() {
    let Ok(pats) = crate::util::env::var("AB_PATS") else { return };
    let path = crate::util::env::var("IMAGE").unwrap_or_else(|_| "/home/user/cbc2/task2/memory-dirty.raw".into());
    let Ok(f) = std::fs::File::open(&path) else { return };
    let Ok(m) = Mmap::map(&f) else { return };
    let len: usize = crate::util::env::var("AB_LEN").ok().and_then(|s| s.parse().ok()).unwrap_or(1 << 30);
    let rounds: usize = crate::util::env::var("AB_ROUNDS").ok().and_then(|s| s.parse().ok()).unwrap_or(10);
    let off = (1usize << 30).min(m.len().saturating_sub(len));
    let hay = &m.as_slice()[off..off + len.min(m.len() - off)];
    let mut x = 0u64;
    for i in (0..hay.len()).step_by(4096) {
        x = x.wrapping_add(hay[i] as u64);
    }
    std::hint::black_box(x);
    enum V {
        Re(Regex),
        Mm(crate::yara::memchr::Memmem),
    }
    let vs: Vec<(String, V)> = pats
        .split('\t')
        .filter(|p| !p.is_empty())
        .map(|p| match p.strip_prefix("mm:") {
            Some(l) => (p.to_string(), V::Mm(crate::yara::memchr::Memmem::new(l.as_bytes()))),
            None => (p.to_string(), V::Re(Regex::new(p.as_bytes(), 0).expect("pattern"))),
        })
        .collect();
    let mut t: Vec<Vec<f64>> = vec![Vec::new(); vs.len()];
    let mut n = vec![0usize; vs.len()];
    for _ in 0..rounds.max(1) {
        for (i, (_, v)) in vs.iter().enumerate() {
            let t0 = Instant::now();
            n[i] = match v {
                V::Re(r) => r.find_iter(std::hint::black_box(hay)).count(),
                V::Mm(mm) => mm.find_iter(std::hint::black_box(hay)).count(),
            };
            t[i].push(hay.len() as f64 / 1e6 / t0.elapsed().as_secs_f64());
        }
    }
    for (i, (p, _)) in vs.iter().enumerate() {
        let mut v = t[i].clone();
        v.sort_by(|a, b| a.total_cmp(b));
        eprintln!(
            "{:>8.0} best {:>8.0} median {:>8.0} q25  {:>7} matches  {p}",
            v[v.len() - 1],
            v[v.len() / 2],
            v[v.len() / 4],
            n[i]
        );
    }
}

/// Compile-time breakdown per pipeline stage (developer probe, ignored test):
///   cargo test --profile release yara_regex_compile_stages -- --ignored --nocapture
/// Patterns: bench/refbench/regex_cases.tsv (or FASTVOL_AB_PATS, tab separated).
#[test]
#[ignore]
fn yara_regex_compile_stages() {
    let pats: Vec<Vec<u8>> = match crate::util::env::var("AB_PATS") {
        Ok(p) => p.split('\t').filter(|s| !s.is_empty()).map(|s| s.as_bytes().to_vec()).collect(),
        Err(_) => {
            let data = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/bench/refbench/regex_cases.tsv")).unwrap_or_default();
            data.split(|&b| b == b'\n')
                .filter(|l| !l.is_empty() && l[0] != b'#')
                .filter_map(|l| l.iter().position(|&b| b == b'\t').map(|t| l[t + 1..].to_vec()))
                .collect()
        }
    };
    fn best<T>(f: &mut dyn FnMut() -> T) -> f64 {
        let mut b = f64::MAX;
        for _ in 0..200 {
            let t = Instant::now();
            let v = std::hint::black_box(f());
            b = b.min(t.elapsed().as_secs_f64());
            drop(v); // not timed (the refbench driver does not time drops either)
        }
        b * 1e6
    }
    for p in pats {
        let total = best(&mut || Regex::new(&p, 0));
        let t_parse = best(&mut || super::parse::parse(&p, 0).map(|x| x.nodes.len()));
        let lowered = || super::hir::lower(super::parse::parse(&p, 0).unwrap()).unwrap();
        let t_lower = best(&mut || lowered().groups) - t_parse;
        let l = lowered();
        let t_props = best(&mut || super::hir::props(&l.hir, &l.group_widths).nfa_size);
        let t_bt = best(&mut || super::backtrack::Prog::new(&l.hir, l.groups, &l.group_widths).map(|x| x.nslots));
        let t_pre = best(&mut || super::literal::Prefilter::for_hir(&l.hir).map(|x| x.1));
        let t_fixed = best(&mut || super::fixed_sequence(&l.hir).map(|s| s.len()));
        let t_dfa = best(&mut || super::dfa::Searcher::new(&l.hir).map(|s| s.strategy_name()));
        let t_nfa = best(&mut || super::nfa::Nfa::new(&l.hir, false).map(|n| n.states.len()));
        if let Some(alts) = super::literal::alt_seqs(&l.hir) {
            let t_pos = best(&mut || super::literal::positions(&l.hir).0.len());
            let t_alts = best(&mut || super::literal::alt_seqs(&l.hir).map(|a| a.len()));
            let t_teddy = best(&mut || crate::yara::teddy::Teddy::new(&alts).is_some());
            let t_seqf = best(&mut || super::literal::SeqFinder::new(&super::literal::positions(&l.hir).0).is_some());
            eprintln!("   prefilter parts: positions {t_pos:.2} alt_seqs {t_alts:.2} teddy {t_teddy:.2} seqfinder(+positions) {t_seqf:.2}");
        }
        let re = Regex::new(&p, 0).unwrap();
        let t_first = best(&mut || {
            let r = Regex::new(&p, 0).unwrap();
            r.search(b"x", 0)
        }) - total;
        eprintln!(
            "total {total:>6.1}us  parse {t_parse:>5.1} lower {t_lower:>5.1} props {t_props:>5.1} bt {t_bt:>5.1} prefilter {t_pre:>5.1} \
             fixed {t_fixed:>5.1} dfa {t_dfa:>5.1} (nfa {t_nfa:>4.1})  +first-search {t_first:>5.1}  {} {}",
            re.engine_name(),
            String::from_utf8_lossy(&p)
        );
    }
}
