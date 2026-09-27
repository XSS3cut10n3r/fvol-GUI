//! Robustness fuzzing: arbitrary pattern bytes / haystacks must never panic.
//! Quick version runs in `cargo test yara`; `FASTVOL_FUZZ_ITERS=1000000 cargo test
//! --profile fast yara_fuzz -- --ignored` runs a long campaign.

use super::regex::Regex;
use super::scan::re_string::{scan_reference, ReString};
use super::scan::Modifiers;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

const RE_ALPHA: &[u8] = b"ab()[]{}|*+?.^$\\-,0123456789:=!<>#PdDwWsSbBAZzxuU ?iLmsxa\n\xff\xc3\xa9";
const HEX_ALPHA: &[u8] = b"{} 0123456789abcdefABCDEF??~[]-|()\n/*";

fn one(r: &mut Rng) {
    let plen = r.below(24);
    let pat: Vec<u8> = (0..plen).map(|_| RE_ALPHA[r.below(RE_ALPHA.len())]).collect();
    let hlen = r.below(64);
    let hay: Vec<u8> = (0..hlen).map(|_| b"ab\n _\xc3\xa9x"[r.below(8)]).collect();
    let flags = [0u32, 2, 8, 16, 64, 256, 2 | 16][r.below(7)];
    if let Ok(re) = Regex::new(&pat, flags) {
        let _ = re.find_iter(&hay).take(100).count();
        let _ = re.captures_at(&hay, 0);
        let _ = re.match_at(&hay, r.below(hay.len() + 2));
    }
    if let Ok(s) = std::str::from_utf8(&pat) {
        if let Ok(re) = Regex::new_str(s, flags) {
            let h = String::from_utf8_lossy(&hay).into_owned();
            let _ = re.find_iter(h.as_bytes()).take(100).count();
        }
    }
    let m = Modifiers { wide: r.below(3) == 0, ascii: r.below(2) == 0, fullword: r.below(4) == 0, ..Default::default() };
    if let Ok(rs) = ReString::new_regex(&pat, r.below(2) == 0, r.below(2) == 0, &m, None) {
        let _ = scan_reference(&rs, &hay);
    }
    let hlen2 = r.below(30);
    let mut hex: Vec<u8> = vec![b'{'];
    hex.extend((0..hlen2).map(|_| HEX_ALPHA[r.below(HEX_ALPHA.len())]));
    if r.below(4) != 0 {
        hex.push(b'}');
    }
    if let Ok(rs) = ReString::new_hex(&String::from_utf8_lossy(&hex), &Modifiers::default(), None) {
        let _ = scan_reference(&rs, &hay);
    }
}

#[test]
fn yara_fuzz_quick() {
    let mut r = Rng(0xdead_beef_1234_5678);
    for _ in 0..20_000 {
        one(&mut r);
    }
}

#[test]
#[ignore]
fn yara_fuzz_long() {
    let iters: usize = crate::util::env::var("FUZZ_ITERS").ok().and_then(|s| s.parse().ok()).unwrap_or(1_000_000);
    let seed: u64 = crate::util::env::var("FUZZ_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(0x5eed);
    let mut r = Rng(seed | 1);
    for i in 0..iters {
        if i % 100_000 == 0 {
            eprintln!("fuzz {i}");
        }
        one(&mut r);
    }
}
