//! Developer micro-benchmark of ReString::verify over real memory (ignored test):
//!   RSVOL_YRE_SRC='{ FF 15 ?? ?? ?? ?? ( 85 C0 | 48 85 C0 | 3B C3 ) 7? }' cargo test --profile fast yara_yre_verify_perf -- --ignored --nocapture

use crate::util::mmap::Mmap;
use crate::yara::memchr::Memmem;
use crate::yara::scan::re_string::ReString;
use crate::yara::scan::Modifiers;
use std::time::Instant;

#[test]
#[ignore]
fn yara_yre_verify_perf() {
    let src = std::env::var("RSVOL_YRE_SRC").unwrap_or_else(|_| "{ FF 15 ?? ?? ?? ?? ( 85 C0 | 48 85 C0 | 3B C3 ) 7? }".into());
    let Ok(f) = std::fs::File::open("/home/user/cbc2/task2/memory-dirty.raw") else { return };
    let Ok(m) = Mmap::map(&f) else { return };
    let len: usize = 256 << 20;
    let hay = &m.as_slice()[1 << 30..(1 << 30) + len];
    let rs = if src.starts_with('{') {
        ReString::new_hex(&src, &Modifiers::default(), None)
    } else {
        ReString::new_regex(src.as_bytes(), false, false, &Modifiers::default(), None)
    }
    .expect("compile");
    // collect atom hits
    let t = Instant::now();
    let mut hits: Vec<(usize, usize)> = Vec::new();
    for (k, a) in rs.atoms().iter().enumerate() {
        if a.bytes.is_empty() {
            continue;
        }
        let mm = Memmem::new(&a.bytes);
        let mut p = 0;
        while let Some(q) = mm.find_at(hay, p) {
            hits.push((q, k));
            p = q + 1;
        }
    }
    hits.sort_unstable();
    eprintln!("atoms={} hits={} (search {:.3}s)", rs.atoms().len(), hits.len(), t.elapsed().as_secs_f64());
    let mut st = rs.new_state();
    let mut out = Vec::new();
    let mut n = 0usize;
    let t = Instant::now();
    for &(p, k) in &hits {
        out.clear();
        rs.verify(&mut st, hay, k, p, &mut out);
        n += out.len();
    }
    let dt = t.elapsed().as_secs_f64();
    eprintln!("verify: {:.3}s, {:.1} ns/hit, {} matches", dt, dt * 1e9 / hits.len().max(1) as f64, n);
    // Split: hits producing no output vs with output, timed separately (warm cache).
    let (empty, full): (Vec<_>, Vec<_>) = hits.iter().partition(|&&(p, k)| {
        out.clear();
        rs.verify(&mut st, hay, k, p, &mut out);
        out.is_empty()
    });
    for (name, set) in [("no-match", &empty), ("match", &full)] {
        let t = Instant::now();
        for &(p, k) in set.iter() {
            out.clear();
            rs.verify(&mut st, hay, k, p, &mut out);
        }
        let dt = t.elapsed().as_secs_f64();
        eprintln!("  {name}: {} hits, {:.1} ns/hit", set.len(), dt * 1e9 / set.len().max(1) as f64);
    }
    let t = Instant::now();
    let mut rej = 0usize;
    for &(p, k) in &hits {
        if rs.debug_quick_reject(hay, k, p) {
            rej += 1;
        }
    }
    eprintln!("  quick_reject alone: {} of {} rejected, {:.1} ns/hit", rej, hits.len(), t.elapsed().as_secs_f64() * 1e9 / hits.len().max(1) as f64);
    let t = Instant::now();
    let mut rej = 0usize;
    for &(p, k) in &hits {
        if rs.debug_filter_reject(hay, k, p) {
            rej += 1;
        }
    }
    eprintln!("  prefix filter alone: {} of {} rejected, {:.1} ns/hit", rej, hits.len(), t.elapsed().as_secs_f64() * 1e9 / hits.len().max(1) as f64);
}
