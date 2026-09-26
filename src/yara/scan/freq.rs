//! Byte and byte-pair statistics of real memory, used to pick the rarest windows of
//! the patterns (performance only — never affects results).
//!
//! `bigram_freq.bin` (65536 bytes) was measured over a 5 GiB Windows 10 memory image
//! by the ignored test `yara_scan_measure_bigrams`: entry `b0 | b1 << 8` is
//! `round(-8 * log2 P(b0 b1))`. Single bytes use `regex::literal::BYTE_FREQ` (same
//! image). Pairs capture what single bytes cannot: `o\0w\0` is common (UTF-16 text)
//! although `o` and `w` are rare bytes.

use crate::yara::regex::literal::BYTE_FREQ;

static BIGRAM: &[u8; 65536] = include_bytes!("bigram_freq.bin");
/// `a 00 b 00` (UTF-16 text) frequencies, same encoding, entry `a | b << 8`.
static WIDE: &[u8; 65536] = include_bytes!("wide_bigram_freq.bin");

/// -log2 P(a b) (adjacent bytes).
#[inline]
pub fn pair_bits(a: u8, b: u8) -> f64 {
    BIGRAM[a as usize | (b as usize) << 8] as f64 / 8.0
}

/// -log2 P(b).
#[inline]
pub fn byte_bits(b: u8) -> f64 {
    let f = BYTE_FREQ[b as usize].max(1) as f64 / (1u64 << 20) as f64;
    -f.log2()
}

/// Estimated probability of an exact byte string at a random memory position:
/// measured UTF-16 character pairs for `a 00 b 00` / `00 a 00 b` windows, otherwise a
/// first-order Markov chain over the measured byte pairs.
pub fn seq_prob(s: &[u8]) -> f64 {
    if s.len() == 4 {
        let wide = |a: u8, b: u8| (-(WIDE[a as usize | (b as usize) << 8] as f64 / 8.0)).exp2();
        if s[1] == 0 && s[3] == 0 && s[0] != 0 && s[2] != 0 {
            return wide(s[0], s[2]);
        }
        if s[0] == 0 && s[2] == 0 && s[1] != 0 && s[3] != 0 {
            return wide(s[1], s[3]);
        }
    }
    match s.len() {
        0 => 1.0,
        1 => (-byte_bits(s[0])).exp2(),
        _ => {
            let mut bits = pair_bits(s[0], s[1]);
            for i in 1..s.len() - 1 {
                bits += pair_bits(s[i], s[i + 1]) - byte_bits(s[i]);
            }
            (-bits.max(0.0)).exp2()
        }
    }
}

/// Estimated probability of a window where positions with `fold[i] != 0` also accept
/// `bytes[i] ^ 0x20` (sums over case combinations, at most 16 for 4-byte windows).
pub fn window_prob(bytes: &[u8], fold: &[u8]) -> f64 {
    let folded: Vec<usize> = (0..bytes.len()).filter(|&i| fold.get(i).is_some_and(|&f| f != 0)).collect();
    let mut total = 0.0;
    let mut v = bytes.to_vec();
    for combo in 0..(1usize << folded.len().min(8)) {
        for (bit, &j) in folded.iter().enumerate().take(8) {
            v[j] = if combo >> bit & 1 != 0 { bytes[j] ^ 0x20 } else { bytes[j] };
        }
        total += seq_prob(&v);
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yara_freq_utf16_common() {
        // "o\0w\0" is far more common than its single-byte estimate suggests.
        let indep = (-(byte_bits(b'o') + byte_bits(0) + byte_bits(b'w') + byte_bits(0))).exp2();
        assert!(seq_prob(b"o\x00w\x00") > 10.0 * indep);
        assert!(seq_prob(b"o\x00w\x00") > seq_prob(b"s\x00h\x00"));
        assert!(seq_prob(b"\x00\x00\x00\x00") > 0.3);
        assert!(window_prob(b"ab", &[0x20, 0]) > seq_prob(b"ab"));
    }
}
