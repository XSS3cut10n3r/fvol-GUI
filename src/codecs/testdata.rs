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

