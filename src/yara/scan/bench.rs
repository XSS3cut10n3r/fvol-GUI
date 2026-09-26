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
    let mut sc = Scratch::new();
    let mut out = Vec::new();
    let mut best = f64::MAX;
    let mut counts = vec![0usize; defs.len()];
    for pass in 0..4 {
        let t = std::time::Instant::now();
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
        let dt = t.elapsed().as_secs_f64();
        eprintln!("pass {pass}: {:.3} s  {:.0} MB/s", dt, data.len() as f64 / dt / 1e6);
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
