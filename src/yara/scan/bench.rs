//! Throughput benchmark of the string matcher on real memory (ignored test):
//!
//! ```text
//! bench/scripts/limit.sh -m 4G cargo test --profile fast yara_scan_bench -- --ignored --nocapture
//! ```
//!
//! Env: `RSVOL_YARA_IMG` (default the Windows 10 image), `RSVOL_YARA_OFF` / `RSVOL_YARA_LEN`
//! (default 1 GiB at 1 GiB), `RSVOL_YARA_RULE` (`text` | `xor` | `many`), `RSVOL_YARA_CHUNK`
//! (default 16 MiB + 4 KiB overlap, like volatility's scanner; 0 = one call),
//! `RSVOL_YARA_PRINT=1` prints the equivalent yara rule source.

use super::*;
use crate::util::mmap::Mmap;

unsafe extern "C" {
    fn clock_gettime(clk: i32, ts: *mut [i64; 2]) -> i32;
}

/// CLOCK_THREAD_CPUTIME_ID in seconds.
fn thread_cpu() -> f64 {
    let mut ts = [0i64; 2];
    // SAFETY: valid pointer to a timespec-sized buffer.
    unsafe { clock_gettime(3, &mut ts) };
    ts[0] as f64 + ts[1] as f64 * 1e-9
}

/// (text, modifiers) of the benchmark rule sets.
pub(crate) fn bench_rule(name: &str) -> Vec<(Vec<u8>, Modifiers)> {
    let m = Modifiers::default;
    let aw = || Modifiers { ascii: true, wide: true, ..m() };
    let awn = || Modifiers { ascii: true, wide: true, nocase: true, ..m() };
    let n = || Modifiers { nocase: true, ..m() };
    let text: Vec<(&[u8], Modifiers)> = vec![
        (b"mimikatz", awn()),
        (b"sekurlsa::logonpasswords", aw()),
        (b"This program cannot be run in DOS mode", m()),
        (b"cmd.exe /c", n()),
        (b"powershell", awn()),
        (b"http://", aw()),
        (b"VirtualAllocEx", m()),
        (b"LoadLibraryA", m()),
        (b"GetProcAddress", m()),
        (b"WriteProcessMemory", m()),
        (b"CreateRemoteThread", m()),
        (b"\\Windows\\System32\\", Modifiers { wide: true, nocase: true, ..m() }),
        (b"password", Modifiers { nocase: true, fullword: true, ..m() }),
        (b"Invoke-Expression", awn()),
        (b"HKEY_LOCAL_MACHINE", aw()),
        (b"kernel32.dll", n()),
        (b"DownloadString", aw()),
        (b"svchost.exe", Modifiers { wide: true, nocase: true, ..m() }),
        (b"ntdll.dll", awn()),
        (b"Mozilla/5.0", m()),
    ];
    let v: Vec<(&[u8], Modifiers)> = match name {
        "xor" => {
            let mut v = text[..14].to_vec();
            v.push((b"This program cannot be run", Modifiers { xor: Some((1, 255)), ..m() }));
            v.push((b"http://", Modifiers { ascii: true, wide: true, xor: Some((0, 255)), ..m() }));
            v.push((b"GetProcAddress", Modifiers { xor: Some((0x20, 0x21)), ..m() }));
            v.push((b"powershell", Modifiers { base64: Some(None), base64wide: Some(None), ..m() }));
            v.push((b"IEX (New-Object", Modifiers { base64: Some(None), ..m() }));
            v.push((b"cmd.exe", Modifiers { ascii: true, wide: true, xor: Some((1, 255)), ..m() }));
            v
        }
        "rare" => vec![(b"\xf1\xf2\xf3\xf4zq" as &[u8], m())],
        "rare8" => (0..8u8)
            .map(|k| (Box::leak(vec![0xf1, 0xf2, 0xe0 + k, 0xf4, b'z'].into_boxed_slice()) as &[u8], m()))
            .collect(),
        "many" => {
            // 20 * 8 = 160 strings: the Aho-Corasick engine.
            let mut v = Vec::new();
            for (t, mo) in &text {
                for k in 0..8u8 {
                    let mut s = t.to_vec();
                    s.push(b'0' + k);
                    v.push((Box::leak(s.into_boxed_slice()) as &[u8], mo.clone()));
                }
            }
            v
        }
        _ => text,
    };
    v.into_iter().map(|(t, mo)| (t.to_vec(), mo)).collect()
}

pub(crate) fn rule_source(strings: &[(Vec<u8>, Modifiers)]) -> String {
    let mut s = String::from("rule bench {\n  strings:\n");
    for (i, (t, mo)) in strings.iter().enumerate() {
        let mut lit = String::new();
        for &b in t {
            if b.is_ascii_alphanumeric() || b" .:/-()!_,".contains(&b) {
                lit.push(b as char);
            } else {
                lit.push_str(&format!("\\x{b:02x}"));
            }
        }
        let mut mods = String::new();
        if mo.ascii {
            mods += " ascii";
        }
        if mo.wide {
            mods += " wide";
        }
        if mo.nocase {
            mods += " nocase";
        }
        if mo.fullword {
            mods += " fullword";
        }
        if let Some((a, b)) = mo.xor {
            mods += &format!(" xor({a}-{b})");
        }
        if mo.base64.is_some() {
            mods += " base64";
        }
        if mo.base64wide.is_some() {
            mods += " base64wide";
        }
        s += &format!("    $s{i} = \"{lit}\"{mods}\n");
    }
    s += "  condition:\n    any of them\n}\n";
    s
}

#[test]
#[ignore]
fn yara_scan_bench() {
    let img = std::env::var("RSVOL_YARA_IMG").unwrap_or_else(|_| "/home/user/cbc2/task2/memory-dirty.raw".into());
    let env = |k: &str, d: usize| std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d);
    let off = env("RSVOL_YARA_OFF", 1 << 30);
    let len = env("RSVOL_YARA_LEN", 1 << 30);
    let chunk = env("RSVOL_YARA_CHUNK", 16 << 20);
    let rule = std::env::var("RSVOL_YARA_RULE").unwrap_or_else(|_| "text".into());
    let strings = bench_rule(&rule);
    if std::env::var("RSVOL_YARA_PRINT").is_ok() {
        println!("{}", rule_source(&strings));
    }
    let defs: Vec<StringDef> = strings
        .iter()
        .enumerate()
        .map(|(i, (t, mo))| StringDef {
            id: format!("$s{i}"),
            kind: StringKind::Text(t.clone()),
            mods: mo.clone(),
            fixed_offset: None,
        })
        .collect();
    let t0 = std::time::Instant::now();
    let mt = Matcher::new(&defs).expect("compile");
    let compile = t0.elapsed();
    let f = std::fs::File::open(&img).expect("open image");
    let map = Mmap::map(&f).expect("mmap");
    let all = map.as_slice();
    let end = (off + len).min(all.len());
    let data = &all[off.min(end)..end];
    if std::env::var("RSVOL_YARA_STATS").is_ok() {
        eprintln!("{}", mt.candidate_stats(data));
    }
    if std::env::var("RSVOL_YARA_FLOOR").is_ok() {
        // Bandwidth floor: one pass of SIMD memchr for an absent byte pattern.
        for _ in 0..3 {
            let t = std::time::Instant::now();
            let mut n = 0usize;
            for c in data.chunks(16 << 20) {
                n += crate::yara::memchr::memchr(0xf7, c).is_some() as usize;
                n += crate::yara::memchr::memchr2(0xf7, 0xf6, c).map_or(0, |_| 1);
            }
            let dt = t.elapsed().as_secs_f64();
            eprintln!("floor (memchr+memchr2 to first hit per chunk): {:.3}s {n}", dt);
        }
        for _ in 0..3 {
            let t = std::time::Instant::now();
            let mut x = 0u64;
            for c in data.chunks_exact(8) {
                x ^= u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]);
            }
            eprintln!("floor (xor all words): {:.3}s {x}", t.elapsed().as_secs_f64());
        }
    }
    let mut sc = Scratch::new();
    let mut out = Vec::new();
    let mut best = f64::MAX;
    let mut counts = vec![0usize; defs.len()];
    for pass in 0..6 {
        let t = std::time::Instant::now();
        let c0 = thread_cpu();
        counts.iter_mut().for_each(|c| *c = 0);
        let mut p = 0;
        loop {
            let e = if chunk == 0 { data.len() } else { (p + chunk + 4096).min(data.len()) };
            mt.scan_with(&mut sc, &data[p..e], &mut out);
            let limit = if chunk == 0 { usize::MAX } else { chunk };
            for (c, v) in counts.iter_mut().zip(&out) {
                *c += v.iter().filter(|m| m.offset < limit).count();
            }
            if chunk == 0 || e == data.len() {
                break;
            }
            p += chunk;
        }
        let wall = t.elapsed().as_secs_f64();
        // Thread CPU time: robust against being descheduled on a busy machine.
        let dt = thread_cpu() - c0;
        eprintln!("pass {pass}: cpu {:.3} s (wall {:.3})  {:.0} MB/s", dt, wall, data.len() as f64 / dt / 1e6);
        best = best.min(dt);
    }
    eprintln!(
        "rule={rule} strings={} compile={:?} bytes={} best={:.3}s  {:.0} MB/s",
        defs.len(),
        compile,
        data.len(),
        best,
        data.len() as f64 / best / 1e6
    );
    eprintln!("matches per string: {:?}  total {}", counts, counts.iter().sum::<usize>());
}

/// Window-model check: for every 4-byte window of the benchmark patterns, the true
/// count in 256 MiB of the image vs the independent-byte and pair-Markov estimates.
#[test]
#[ignore]
fn yara_scan_window_model() {
    let img = std::env::var("RSVOL_YARA_IMG").unwrap_or_else(|_| "/home/user/cbc2/task2/memory-dirty.raw".into());
    let f = std::fs::File::open(&img).expect("open image");
    let map = Mmap::map(&f).expect("mmap");
    let data = &map.as_slice()[1 << 30..(1 << 30) + (256 << 20)];
    let mut wins: Vec<Vec<u8>> = Vec::new();
    for (t, mo) in bench_rule("text") {
        let mut vs = Vec::new();
        if mo.ascii || !mo.wide {
            vs.push(t.clone());
        }
        if mo.wide {
            vs.push(t.iter().flat_map(|&b| [b, 0]).collect::<Vec<u8>>());
        }
        for v in vs {
            for w in v.windows(4) {
                wins.push(w.to_vec());
            }
        }
    }
    wins.sort();
    wins.dedup();
    let mut idx = std::collections::HashMap::new();
    for (i, w) in wins.iter().enumerate() {
        idx.insert(u32::from_le_bytes([w[0], w[1], w[2], w[3]]), i);
    }
    let mut counts = vec![0usize; wins.len()];
    for w in data.windows(4) {
        if let Some(&i) = idx.get(&u32::from_le_bytes([w[0], w[1], w[2], w[3]])) {
            counts[i] += 1;
        }
    }
    let n = data.len() as f64;
    let (mut e_ind, mut e_mk) = (0.0, 0.0);
    for (i, w) in wins.iter().enumerate() {
        let ind: f64 = w.iter().map(|&b| (-super::freq::byte_bits(b)).exp2()).product();
        let mk = super::freq::seq_prob(w);
        let t = (counts[i] as f64 + 0.5) / n;
        e_ind += (ind / t).log2().abs();
        e_mk += (mk / t).log2().abs();
        if counts[i] > 1000 {
            eprintln!("{:?} true {:.2e} ind {:.2e} markov {:.2e}", String::from_utf8_lossy(w), t, ind, mk);
        }
    }
    eprintln!("mean |log2 error|: independent {:.2}  markov {:.2}", e_ind / wins.len() as f64, e_mk / wins.len() as f64);
}

/// Measures byte-pair frequencies over a memory image and writes the quantized tables
/// used for window selection (`bigram_freq.bin`: 65536 bytes, entry `b0 | b1 << 8` =
/// round(-8 * log2(P(b0 b1))), capped at 255; `<out>.wide`: the same for the 4-grams
/// `b0 00 b1 00`).
///
/// `RSVOL_YARA_BIGRAM_OUT=path cargo test --profile fast yara_scan_measure_bigrams -- --ignored`
#[test]
#[ignore]
fn yara_scan_measure_bigrams() {
    let Ok(outp) = std::env::var("RSVOL_YARA_BIGRAM_OUT") else { return };
    let img = std::env::var("RSVOL_YARA_IMG").unwrap_or_else(|_| "/home/user/cbc2/task2/memory-dirty.raw".into());
    let f = std::fs::File::open(&img).expect("open image");
    let map = Mmap::map(&f).expect("mmap");
    let data = map.as_slice();
    let mut counts = vec![0u64; 1 << 16];
    let mut wide = vec![0u64; 1 << 16];
    for w in data.windows(4) {
        counts[w[0] as usize | (w[1] as usize) << 8] += 1;
        if w[1] == 0 && w[3] == 0 {
            wide[w[0] as usize | (w[2] as usize) << 8] += 1;
        }
    }
    let total = data.len().max(1) as f64;
    let quant = |c: &u64| if *c == 0 { 255 } else { (-8.0 * (*c as f64 / total).log2()).round().min(255.0) as u8 };
    std::fs::write(&outp, counts.iter().map(quant).collect::<Vec<u8>>()).expect("write table");
    // `a\0b\0` frequencies: entry `a | b << 8`.
    std::fs::write(format!("{outp}.wide"), wide.iter().map(quant).collect::<Vec<u8>>()).expect("write table");
}
