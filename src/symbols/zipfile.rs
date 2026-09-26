//! Minimal zip reader for symbol packs (python `zipfile`): list members, read a member
//! (stored or deflated; inflate provided by `crate::codecs::zip`).

use crate::error::{Error, Result};
use std::path::Path;

struct Entry {
    name: String,
    method: u16,
    crc: u32,
    csize: u64,
    usize_: u64,
    local_off: u64,
}

fn rd16(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?))
}
fn rd32(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}
fn rd64(b: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(o..o + 8)?.try_into().ok()?))
}

fn entries(b: &[u8]) -> Option<Vec<Entry>> {
    // find end of central directory
    let min = b.len().saturating_sub(22 + 65535);
    let mut eocd = None;
    let mut i = b.len().checked_sub(22)?;
    loop {
        if rd32(b, i)? == 0x0605_4b50 {
            eocd = Some(i);
            break;
        }
        if i == min || i == 0 {
            break;
        }
        i -= 1;
    }
    let e = eocd?;
    let mut count = rd16(b, e + 10)? as u64;
    let mut cd_off = rd32(b, e + 16)? as u64;
    // zip64
    if (count == 0xffff || cd_off == 0xffff_ffff) && e >= 20 && rd32(b, e - 20)? == 0x0706_4b50 {
        let z64 = rd64(b, e - 20 + 8)? as usize;
        if rd32(b, z64)? == 0x0606_4b50 {
            count = rd64(b, z64 + 32)?;
            cd_off = rd64(b, z64 + 48)?;
        }
    }
    let mut out = Vec::new();
    let mut p = cd_off as usize;
    for _ in 0..count {
        if rd32(b, p)? != 0x0201_4b50 {
            break;
        }
        let method = rd16(b, p + 10)?;
        let crc = rd32(b, p + 16)?;
        let mut csize = rd32(b, p + 20)? as u64;
        let mut usize_ = rd32(b, p + 24)? as u64;
        let nlen = rd16(b, p + 28)? as usize;
        let xlen = rd16(b, p + 30)? as usize;
        let clen = rd16(b, p + 32)? as usize;
        let mut local_off = rd32(b, p + 42)? as u64;
        let name = String::from_utf8_lossy(b.get(p + 46..p + 46 + nlen)?).into_owned();
        // zip64 extra field
        let mut x = p + 46 + nlen;
        let xend = x + xlen;
        while x + 4 <= xend {
            let id = rd16(b, x)?;
            let sz = rd16(b, x + 2)? as usize;
            if id == 1 {
                let mut q = x + 4;
                if usize_ == 0xffff_ffff {
                    usize_ = rd64(b, q)?;
                    q += 8;
                }
                if csize == 0xffff_ffff {
                    csize = rd64(b, q)?;
                    q += 8;
                }
                if local_off == 0xffff_ffff {
                    local_off = rd64(b, q)?;
                }
            }
            x += 4 + sz;
        }
        out.push(Entry { name, method, crc, csize, usize_, local_off });
        p += 46 + nlen + xlen + clen;
    }
    Some(out)
}

/// Member names of a zip file.
pub fn list(path: &Path) -> Result<Vec<String>> {
    let b = std::fs::read(path)?;
    Ok(entries(&b).ok_or_else(|| Error::msg("bad zip file"))?.into_iter().map(|e| e.name).collect())
}

/// Read (and inflate) one member.
pub fn read_member(path: &Path, member: &str) -> Result<Vec<u8>> {
    let b = std::fs::read(path)?;
    let es = entries(&b).ok_or_else(|| Error::msg("bad zip file"))?;
    let e = es.iter().find(|e| e.name == member).ok_or_else(|| Error::msg(format!("{member} not in zip")))?;
    let lo = e.local_off as usize;
    if rd32(&b, lo) != Some(0x0403_4b50) {
        return Err(Error::msg("bad zip local header"));
    }
    let nlen = rd16(&b, lo + 26).unwrap_or(0) as usize;
    let xlen = rd16(&b, lo + 28).unwrap_or(0) as usize;
    let start = lo + 30 + nlen + xlen;
    let data = b.get(start..start + e.csize as usize).ok_or_else(|| Error::msg("truncated zip member"))?;
    match e.method {
        0 => Ok(data.to_vec()),
        8 => crate::codecs::zip::inflate(data, e.crc, e.usize_ as u32),
        m => Err(Error::msg(format!("unsupported zip method {m}"))),
    }
}
