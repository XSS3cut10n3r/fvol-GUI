//! Checksums shared by the codecs.
//!
//! * [`crc32`] — CRC-32/ISO-HDLC (zlib, gzip, zip, xz). Reflected polynomial 0xEDB88320.
//! * [`crc64`] — CRC-64/XZ (ECMA-182, reflected polynomial 0xC96C5795D7870F42).
//! * [`crc32_bzip2`] — CRC-32/BZIP2 (MSB-first polynomial 0x04C11DB7).
//!
//! Small inputs use slicing-by-8 tables (generated at compile time). On x86-64 CPUs with
//! PCLMULQDQ the reflected CRCs fold 64 bytes per iteration with carry-less multiplication,
//! reducing the final 128-bit remainder with the tables.

/// CRC-32 (IEEE) of `data`.
#[inline]
pub fn crc32(data: &[u8]) -> u32 {
    crc32_update(0, data)
}

/// Continue a CRC-32 (IEEE): `crc32_update(crc32(a), b) == crc32(a ++ b)`.
pub fn crc32_update(crc: u32, data: &[u8]) -> u32 {
    !crc32_raw(!crc, data)
}

/// CRC-64/XZ of `data`.
#[inline]
pub fn crc64(data: &[u8]) -> u64 {
    crc64_update(0, data)
}

/// Continue a CRC-64/XZ: `crc64_update(crc64(a), b) == crc64(a ++ b)`.
pub fn crc64_update(crc: u64, data: &[u8]) -> u64 {
    !crc64_raw(!crc, data)
}

/// CRC-32/BZIP2 of `data`.
#[inline]
pub fn crc32_bzip2(data: &[u8]) -> u32 {
    crc32_bzip2_update(0, data)
}

/// Continue a CRC-32/BZIP2.
pub fn crc32_bzip2_update(crc: u32, data: &[u8]) -> u32 {
    !crc32_msb_tables(!crc, data)
}

// ---------------------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------------------

const CRC32_POLY_REFLECTED: u32 = 0xEDB8_8320;
const CRC32_POLY_NORMAL: u32 = 0x04C1_1DB7;
const CRC64_POLY_REFLECTED: u64 = 0xC96C_5795_D787_0F42;
const CRC64_POLY_NORMAL: u64 = 0x42F0_E1EB_A9EA_3693;

const fn make_crc32_tables() -> [[u32; 256]; 8] {
    let mut t = [[0u32; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ CRC32_POLY_REFLECTED } else { c >> 1 };
            k += 1;
        }
        t[0][i] = c;
        i += 1;
    }
    let mut s = 1;
    while s < 8 {
        let mut i = 0;
        while i < 256 {
            let prev = t[s - 1][i];
            t[s][i] = (prev >> 8) ^ t[0][(prev & 0xff) as usize];
            i += 1;
        }
        s += 1;
    }
    t
}

const fn make_crc64_tables() -> [[u64; 256]; 8] {
    let mut t = [[0u64; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u64;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ CRC64_POLY_REFLECTED } else { c >> 1 };
            k += 1;
        }
        t[0][i] = c;
        i += 1;
    }
    let mut s = 1;
    while s < 8 {
        let mut i = 0;
        while i < 256 {
            let prev = t[s - 1][i];
            t[s][i] = (prev >> 8) ^ t[0][(prev & 0xff) as usize];
            i += 1;
        }
        s += 1;
    }
    t
}

const fn make_crc32_msb_tables() -> [[u32; 256]; 8] {
    let mut t = [[0u32; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let mut c = (i as u32) << 24;
        let mut k = 0;
        while k < 8 {
            c = if c & 0x8000_0000 != 0 { (c << 1) ^ CRC32_POLY_NORMAL } else { c << 1 };
            k += 1;
        }
        t[0][i] = c;
        i += 1;
    }
    let mut s = 1;
    while s < 8 {
        let mut i = 0;
        while i < 256 {
            let prev = t[s - 1][i];
            t[s][i] = (prev << 8) ^ t[0][(prev >> 24) as usize];
            i += 1;
        }
        s += 1;
    }
    t
}

static CRC32_TABLES: [[u32; 256]; 8] = make_crc32_tables();
static CRC64_TABLES: [[u64; 256]; 8] = make_crc64_tables();
static CRC32_MSB_TABLES: [[u32; 256]; 8] = make_crc32_msb_tables();

/// The single-byte CRC-32/BZIP2 table (bzip2 updates its block CRC byte-at-a-time in places).
#[inline(always)]
pub(crate) fn crc32_msb_table() -> &'static [u32; 256] {
    &CRC32_MSB_TABLES[0]
}

/// Raw reflected CRC-32 register update (no pre/post inversion), slicing-by-8.
fn crc32_tables(mut crc: u32, data: &[u8]) -> u32 {
    let t = &CRC32_TABLES;
    let mut chunks = data.chunks_exact(8);
    for c in &mut chunks {
        let v = u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]) ^ crc as u64;
        crc = t[7][(v & 0xff) as usize]
            ^ t[6][((v >> 8) & 0xff) as usize]
            ^ t[5][((v >> 16) & 0xff) as usize]
            ^ t[4][((v >> 24) & 0xff) as usize]
            ^ t[3][((v >> 32) & 0xff) as usize]
            ^ t[2][((v >> 40) & 0xff) as usize]
            ^ t[1][((v >> 48) & 0xff) as usize]
            ^ t[0][(v >> 56) as usize];
    }
    for &b in chunks.remainder() {
        crc = (crc >> 8) ^ t[0][((crc ^ b as u32) & 0xff) as usize];
    }
    crc
}

/// Raw reflected CRC-64 register update (no pre/post inversion), slicing-by-8.
fn crc64_tables(mut crc: u64, data: &[u8]) -> u64 {
    let t = &CRC64_TABLES;
    let mut chunks = data.chunks_exact(8);
    for c in &mut chunks {
        let v = u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]) ^ crc;
        crc = t[7][(v & 0xff) as usize]
            ^ t[6][((v >> 8) & 0xff) as usize]
            ^ t[5][((v >> 16) & 0xff) as usize]
            ^ t[4][((v >> 24) & 0xff) as usize]
            ^ t[3][((v >> 32) & 0xff) as usize]
            ^ t[2][((v >> 40) & 0xff) as usize]
            ^ t[1][((v >> 48) & 0xff) as usize]
            ^ t[0][(v >> 56) as usize];
    }
    for &b in chunks.remainder() {
        crc = (crc >> 8) ^ t[0][((crc ^ b as u64) & 0xff) as usize];
    }
    crc
}

/// Raw MSB-first CRC-32 register update, slicing-by-8.
fn crc32_msb_tables(mut crc: u32, data: &[u8]) -> u32 {
    let t = &CRC32_MSB_TABLES;
    let mut chunks = data.chunks_exact(8);
    for c in &mut chunks {
        let a = u32::from_be_bytes([c[0], c[1], c[2], c[3]]) ^ crc;
        let b = u32::from_be_bytes([c[4], c[5], c[6], c[7]]);
        crc = t[7][(a >> 24) as usize]
            ^ t[6][((a >> 16) & 0xff) as usize]
            ^ t[5][((a >> 8) & 0xff) as usize]
            ^ t[4][(a & 0xff) as usize]
            ^ t[3][(b >> 24) as usize]
            ^ t[2][((b >> 16) & 0xff) as usize]
            ^ t[1][((b >> 8) & 0xff) as usize]
            ^ t[0][(b & 0xff) as usize];
    }
    for &b in chunks.remainder() {
        crc = (crc << 8) ^ t[0][((crc >> 24) ^ b as u32) as usize];
    }
    crc
}

// ---------------------------------------------------------------------------------------
// Carry-less multiplication folding (x86-64 PCLMULQDQ)
// ---------------------------------------------------------------------------------------
//
// Bit-reflected convention: a 128-bit lane value `v` loaded little-endian from the message
// represents the polynomial sum(v_k * x^(127-k)).  Folding a block A forward by D bits means
// computing F == A * x^D (mod P) with deg F < 128, then XOR-ing F into the block D bits later.
// With A = L0 * x^64 + L1 (L0 = low 64-bit lane), `clmul(L0, reflect64(Q))` interpreted in
// the same convention equals x * L0 * Q, so the constants are
//     k_lo = reflect64(x^(63+D) mod P),   k_hi = reflect64(x^(D-1) mod P).
// Once everything is folded into one 128-bit value V (plus < 16 tail bytes), the CRC register
// equals the table CRC (initial register 0) of V's 16 bytes followed by the tail.

/// x^n mod P for the CRC-32 generator (normal bit order, bit d = coefficient of x^d).
const fn xpow_mod_crc32(n: u32) -> u64 {
    let mut r: u64 = 1;
    let mut i = 0;
    while i < n {
        r <<= 1;
        if r & (1 << 32) != 0 {
            r ^= (1u64 << 32) | CRC32_POLY_NORMAL as u64;
        }
        i += 1;
    }
    r
}

/// x^n mod P for the CRC-64/XZ generator (normal bit order).
const fn xpow_mod_crc64(n: u32) -> u64 {
    let mut r: u64 = 1;
    let mut i = 0;
    while i < n {
        let carry = r >> 63;
        r <<= 1;
        if carry != 0 {
            r ^= CRC64_POLY_NORMAL;
        }
        i += 1;
    }
    r
}

#[allow(dead_code)]
const CRC32_K512: (u64, u64) = (
    xpow_mod_crc32(63 + 512).reverse_bits(),
    xpow_mod_crc32(512 - 1).reverse_bits(),
);
#[allow(dead_code)]
const CRC32_K128: (u64, u64) = (
    xpow_mod_crc32(63 + 128).reverse_bits(),
    xpow_mod_crc32(128 - 1).reverse_bits(),
);
#[allow(dead_code)]
const CRC64_K512: (u64, u64) = (
    xpow_mod_crc64(63 + 512).reverse_bits(),
    xpow_mod_crc64(512 - 1).reverse_bits(),
);
#[allow(dead_code)]
const CRC64_K128: (u64, u64) = (
    xpow_mod_crc64(63 + 128).reverse_bits(),
    xpow_mod_crc64(128 - 1).reverse_bits(),
);

/// Inputs shorter than this use the tables only.
const CLMUL_MIN_LEN: usize = 128;

#[cfg(target_arch = "x86_64")]
#[inline]
fn have_clmul() -> bool {
    std::arch::is_x86_feature_detected!("pclmulqdq") && std::arch::is_x86_feature_detected!("sse2")
}

/// Folds `data` (len >= 64) into a 128-bit remainder; `init` is XOR-ed into the low 64 bits
/// of the first block. Returns (remainder bytes, bytes consumed (multiple of 16)).
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn clmul_fold(init: u64, data: &[u8], k512: (u64, u64), k128: (u64, u64)) -> ([u8; 16], usize) {
    use std::arch::x86_64::*;
    debug_assert!(data.len() >= 64);
    // SAFETY (whole fn): every load reads 16 bytes at an offset `o` with o + 16 <= data.len().
    unsafe {
        let p = data.as_ptr();
        let load = |o: usize| _mm_loadu_si128(p.add(o) as *const __m128i);
        let kf4 = _mm_set_epi64x(k512.1 as i64, k512.0 as i64);
        let kf1 = _mm_set_epi64x(k128.1 as i64, k128.0 as i64);
        macro_rules! fold {
            ($x:expr, $k:expr) => {
                _mm_xor_si128(_mm_clmulepi64_si128($x, $k, 0x00), _mm_clmulepi64_si128($x, $k, 0x11))
            };
        }
        let mut x0 = _mm_xor_si128(load(0), _mm_set_epi64x(0, init as i64));
        let mut x1 = load(16);
        let mut x2 = load(32);
        let mut x3 = load(48);
        let mut off = 64;
        let n = data.len();
        while off + 64 <= n {
            x0 = _mm_xor_si128(fold!(x0, kf4), load(off));
            x1 = _mm_xor_si128(fold!(x1, kf4), load(off + 16));
            x2 = _mm_xor_si128(fold!(x2, kf4), load(off + 32));
            x3 = _mm_xor_si128(fold!(x3, kf4), load(off + 48));
            off += 64;
        }
        let mut x = _mm_xor_si128(fold!(x0, kf1), x1);
        x = _mm_xor_si128(fold!(x, kf1), x2);
        x = _mm_xor_si128(fold!(x, kf1), x3);
        while off + 16 <= n {
            x = _mm_xor_si128(fold!(x, kf1), load(off));
            off += 16;
        }
        let mut out = [0u8; 16];
        _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, x);
        (out, off)
    }
}

fn crc32_raw(crc: u32, data: &[u8]) -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        if data.len() >= CLMUL_MIN_LEN && have_clmul() {
            // SAFETY: CPU support checked above; len >= 64.
            let (rem, used) = unsafe { clmul_fold(crc as u64, data, CRC32_K512, CRC32_K128) };
            let r = crc32_tables(0, &rem);
            return crc32_tables(r, &data[used..]);
        }
    }
    crc32_tables(crc, data)
}

fn crc64_raw(crc: u64, data: &[u8]) -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        if data.len() >= CLMUL_MIN_LEN && have_clmul() {
            // SAFETY: CPU support checked above; len >= 64.
            let (rem, used) = unsafe { clmul_fold(crc, data, CRC64_K512, CRC64_K128) };
            let r = crc64_tables(0, &rem);
            return crc64_tables(r, &data[used..]);
        }
    }
    crc64_tables(crc, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn crc32_bitwise(data: &[u8]) -> u32 {
        let mut c = !0u32;
        for &b in data {
            c ^= b as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { (c >> 1) ^ CRC32_POLY_REFLECTED } else { c >> 1 };
            }
        }
        !c
    }

    fn crc64_bitwise(data: &[u8]) -> u64 {
        let mut c = !0u64;
        for &b in data {
            c ^= b as u64;
            for _ in 0..8 {
                c = if c & 1 != 0 { (c >> 1) ^ CRC64_POLY_REFLECTED } else { c >> 1 };
            }
        }
        !c
    }

    fn pseudo_random(n: usize, seed: u64) -> Vec<u8> {
        let mut s = seed;
        (0..n)
            .map(|_| {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                (s >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn codecs_crc_check_values() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc64(b"123456789"), 0x995D_C9BB_DF19_39FA);
        assert_eq!(crc32_bzip2(b"123456789"), 0xFC89_1918);
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc64(b""), 0);
    }

    #[test]
    fn codecs_crc_matches_bitwise_all_lengths() {
        let data = pseudo_random(4096 + 77, 0x1234_5678_9abc_def1);
        for len in (0..300).chain([511, 512, 513, 1000, 4096, 4096 + 77]) {
            let d = &data[..len];
            assert_eq!(crc32(d), crc32_bitwise(d), "crc32 len {len}");
            assert_eq!(crc64(d), crc64_bitwise(d), "crc64 len {len}");
            assert_eq!(crc32_tables(!0, d), !crc32_bitwise(d));
            assert_eq!(crc64_tables(!0, d), !crc64_bitwise(d));
        }
        // Streaming updates with odd split points.
        for split in [0usize, 1, 7, 63, 64, 65, 200, 1000] {
            let (a, b) = data.split_at(split);
            assert_eq!(crc32_update(crc32(a), b), crc32(&data));
            assert_eq!(crc64_update(crc64(a), b), crc64(&data));
            assert_eq!(crc32_bzip2_update(crc32_bzip2(a), b), crc32_bzip2(&data));
        }
    }
}
