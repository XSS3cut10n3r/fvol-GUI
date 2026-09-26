//! gzip (RFC 1952) decoder: multiple members, zero padding between members (like python's
//! `gzip.decompress`), CRC-32 and ISIZE verification.

use super::crc::crc32;
use super::inflate::inflate_into;
use crate::error::{Error, Result};

fn err(what: &str) -> Error {
    Error::Msg(format!("gzip: {what}"))
}

/// Returns true if `data` starts with the gzip magic.
pub fn is_gzip(data: &[u8]) -> bool {
    data.starts_with(&[0x1F, 0x8B])
}

/// Parses a member header at `off`; returns the offset of the DEFLATE data.
fn parse_header(data: &[u8], off: usize) -> Result<usize> {
    let h = data.get(off..off + 10).ok_or_else(|| err("truncated header"))?;
    if h[0] != 0x1F || h[1] != 0x8B {
        return Err(err("not a gzipped file"));
    }
    if h[2] != 8 {
        return Err(err("unknown compression method"));
    }
    let flags = h[3];
    let mut p = off + 10;
    if flags & 0x04 != 0 {
        let x = data.get(p..p + 2).ok_or_else(|| err("truncated header"))?;
        p += 2 + u16::from_le_bytes([x[0], x[1]]) as usize;
    }
    for flag in [0x08u8, 0x10] {
        if flags & flag != 0 {
            let rest = data.get(p..).ok_or_else(|| err("truncated header"))?;
            let nul = rest.iter().position(|&b| b == 0).ok_or_else(|| err("truncated header"))?;
            p += nul + 1;
        }
    }
    if flags & 0x02 != 0 {
        p += 2; // header CRC16 (not verified, like python)
    }
    if p > data.len() {
        return Err(err("truncated header"));
    }
    Ok(p)
}

/// Decompresses all members of a gzip file.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    // ISIZE of the last member is an exact size hint for single-member files.
    let hint = if data.len() >= 18 {
        let isize = u32::from_le_bytes(data[data.len() - 4..].try_into().unwrap()) as usize;
        if isize <= data.len().saturating_mul(1032) { isize } else { data.len().saturating_mul(4) }
    } else {
        0
    };
    let mut out = Vec::with_capacity(hint.saturating_add(512));
    let mut off = 0usize;
    loop {
        let start = parse_header(data, off)?;
        let member_start = out.len();
        let used = inflate_into(&data[start..], &mut out)?;
        let t = data.get(start + used..start + used + 8).ok_or_else(|| err("truncated trailer"))?;
        let crc = u32::from_le_bytes([t[0], t[1], t[2], t[3]]);
        let isize = u32::from_le_bytes([t[4], t[5], t[6], t[7]]);
        let member = &out[member_start..];
        if crc32(member) != crc {
            return Err(err("CRC check failed"));
        }
        if member.len() as u32 != isize {
            return Err(err("incorrect length of data produced"));
        }
        off = start + used + 8;
        while off < data.len() && data[off] == 0 {
            off += 1;
        }
        if off >= data.len() {
            break;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // printf 'hello hello hello hello\n' | gzip -n -9
    const GZ: &[u8] = &[
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0xc8, 0x40,
        0x27, 0xb9, 0x00, 0x00, 0x88, 0x59, 0x0b, 0x18, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn codecs_gzip_members_and_padding() {
        assert_eq!(decompress(GZ).unwrap(), b"hello hello hello hello\n");
        let mut two = GZ.to_vec();
        two.extend_from_slice(&[0, 0, 0]);
        two.extend_from_slice(GZ);
        two.extend_from_slice(&[0, 0]);
        assert_eq!(decompress(&two).unwrap(), b"hello hello hello hello\nhello hello hello hello\n");
        let mut garbage = GZ.to_vec();
        garbage.push(b'x');
        assert!(decompress(&garbage).is_err());
        let mut badcrc = GZ.to_vec();
        badcrc[GZ.len() - 8] ^= 1;
        assert!(decompress(&badcrc).is_err());
        for n in 0..GZ.len() {
            assert!(decompress(&GZ[..n]).is_err());
        }
    }
}
