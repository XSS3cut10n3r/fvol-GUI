//! `entrypoint` for plain data scans: libyara 4.5 exefiles.c
//! `yr_get_entry_point_offset` (PE / ELF headers at the start of the scanned
//! buffer), bit-for-bit including its unsigned wrap-arounds. Returns the raw
//! 64-bit value libyara stores in `context->entry_point` (which may be the
//! YR_UNDEFINED marker).

use super::eval::UNDEF;

#[inline]
fn u16le(d: &[u8], o: usize) -> Option<u16> {
    let b = d.get(o..o.checked_add(2)?)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

#[inline]
fn u32le(d: &[u8], o: usize) -> Option<u32> {
    let b = d.get(o..o.checked_add(4)?)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

#[inline]
fn u64le(d: &[u8], o: usize) -> Option<u64> {
    let b = d.get(o..o.checked_add(8)?)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(b);
    Some(u64::from_le_bytes(a))
}

const DOS_HEADER: usize = 64;
const FILE_HEADER: usize = 20;
const OPTIONAL_HEADER32: usize = 224;
const SECTION_HEADER: usize = 40;

/// yr_get_pe_header: offset of the NT headers or None.
fn pe_header(d: &[u8]) -> Option<usize> {
    if d.len() < DOS_HEADER || u16le(d, 0)? != 0x5A4D {
        return None;
    }
    let lfanew = u32le(d, 0x3c)?;
    if (lfanew as i32) < 0 {
        return None;
    }
    let lfanew = lfanew as usize;
    let mut headers = lfanew + 4 + FILE_HEADER;
    if d.len() < headers {
        return None;
    }
    headers += OPTIONAL_HEADER32;
    let machine = u16le(d, lfanew + 4)?;
    if u32le(d, lfanew)? == 0x0000_4550 && (machine == 0x14c || machine == 0x8664) && d.len() > headers {
        Some(lfanew)
    } else {
        None
    }
}

/// yr_pe_rva_to_offset (`buffer_length` is counted from the NT headers).
fn pe_rva_to_offset(d: &[u8], pe: usize, rva: u64, buffer_length: usize) -> u64 {
    let nsections = u16le(d, pe + 6).unwrap_or(0).min(60) as usize;
    let opt_size = u16le(d, pe + 20).unwrap_or(0) as usize;
    let first = 24 + opt_size; // relative to the NT headers
    let mut section_rva: u32 = 0;
    let mut section_offset: u32 = 0;
    for i in 0..nsections {
        let rel = first + i * SECTION_HEADER;
        if rel + SECTION_HEADER < buffer_length {
            let va = u32le(d, pe + rel + 12).unwrap_or(0);
            let raw = u32le(d, pe + rel + 20).unwrap_or(0);
            if rva >= va as u64 && section_rva <= va {
                section_rva = va;
                section_offset = raw;
            }
        } else {
            return 0;
        }
    }
    (section_offset as u64).wrapping_add(rva.wrapping_sub(section_rva as u64))
}

fn elf32_rva_to_offset(d: &[u8], rva: u64) -> u64 {
    let len = d.len() as u64;
    let ty = u16le(d, 16).unwrap_or(0);
    let ph_offset = u32le(d, 28).unwrap_or(0) as u64;
    let sh_offset = u32le(d, 32).unwrap_or(0) as u64;
    let ph_count = u16le(d, 44).unwrap_or(0) as u64;
    let sh_count = u16le(d, 48).unwrap_or(0) as u64;
    if ty == 2 {
        if ph_offset == 0 || ph_count == 0 {
            return 0;
        }
        if ph_offset + 32 * ph_count > len {
            return 0;
        }
        for i in 0..ph_count {
            let p = (ph_offset + i * 32) as usize;
            let off = u32le(d, p + 4).unwrap_or(0);
            let va = u32le(d, p + 8).unwrap_or(0);
            let msz = u32le(d, p + 20).unwrap_or(0);
            if rva >= va as u64 && rva < va.wrapping_add(msz) as u64 {
                return (off as u64).wrapping_add(rva.wrapping_sub(va as u64));
            }
        }
    } else {
        if sh_offset == 0 || sh_count == 0 {
            return 0;
        }
        if sh_offset + 40 * sh_count > len {
            return 0;
        }
        for i in 0..sh_count {
            let s = (sh_offset + i * 40) as usize;
            let sty = u32le(d, s + 4).unwrap_or(0);
            let addr = u32le(d, s + 12).unwrap_or(0);
            let off = u32le(d, s + 16).unwrap_or(0);
            let size = u32le(d, s + 20).unwrap_or(0);
            if sty != 0 && sty != 8 && rva >= addr as u64 && rva < addr.wrapping_add(size) as u64 {
                return (off as u64).wrapping_add(rva.wrapping_sub(addr as u64));
            }
        }
    }
    0
}

fn elf64_rva_to_offset(d: &[u8], rva: u64) -> u64 {
    let len = d.len() as u64;
    let ty = u16le(d, 16).unwrap_or(0);
    let ph_offset = u64le(d, 32).unwrap_or(0);
    let sh_offset = u64le(d, 40).unwrap_or(0);
    let ph_count = u16le(d, 56).unwrap_or(0) as u64;
    let sh_count = u16le(d, 60).unwrap_or(0) as u64;
    if ty == 2 {
        if ph_offset == 0 || ph_count == 0 {
            return 0;
        }
        if u64::MAX - ph_offset < 56 * ph_count || ph_offset + 56 * ph_count > len {
            return 0;
        }
        for i in 0..ph_count {
            let p = (ph_offset + i * 56) as usize;
            let off = u64le(d, p + 8).unwrap_or(0);
            let va = u64le(d, p + 16).unwrap_or(0);
            let msz = u64le(d, p + 40).unwrap_or(0);
            if rva >= va && rva < va.wrapping_add(msz) {
                return off.wrapping_add(rva.wrapping_sub(va));
            }
        }
    } else {
        if sh_offset == 0 || sh_count == 0 {
            return 0;
        }
        if u64::MAX - sh_offset < 64 * sh_count || sh_offset + 64 * sh_count > len {
            return 0;
        }
        for i in 0..sh_count {
            let s = (sh_offset + i * 64) as usize;
            let sty = u32le(d, s + 4).unwrap_or(0);
            let addr = u64le(d, s + 16).unwrap_or(0);
            let off = u64le(d, s + 24).unwrap_or(0);
            let size = u64le(d, s + 32).unwrap_or(0);
            if sty != 0 && sty != 8 && rva >= addr && rva < addr.wrapping_add(size) {
                return off.wrapping_add(rva.wrapping_sub(addr));
            }
        }
    }
    0
}

/// yr_get_entry_point_offset(data, len) as an i64 VM word.
pub fn entry_point_offset(d: &[u8]) -> i64 {
    if let Some(pe) = pe_header(d) {
        let rva = u32le(d, pe + 40).unwrap_or(0) as u64;
        return pe_rva_to_offset(d, pe, rva, d.len() - pe) as i64;
    }
    if d.len() >= 16 && u32le(d, 0) == Some(0x464C_457F) {
        match d[4] {
            1 if d.len() >= 52 => {
                let entry = u32le(d, 24).unwrap_or(0) as u64;
                return elf32_rva_to_offset(d, entry) as i64;
            }
            2 if d.len() >= 64 => {
                let entry = u64le(d, 24).unwrap_or(0);
                return elf64_rva_to_offset(d, entry) as i64;
            }
            _ => {}
        }
    }
    UNDEF
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pe(ep: u32, sections: &[(u32, u32)]) -> Vec<u8> {
        let mut d = vec![0u8; 0x400];
        d[0] = b'M';
        d[1] = b'Z';
        d[0x3c] = 0x80;
        d[0x80..0x84].copy_from_slice(b"PE\0\0");
        d[0x84..0x86].copy_from_slice(&0x14cu16.to_le_bytes());
        d[0x86..0x88].copy_from_slice(&(sections.len() as u16).to_le_bytes());
        d[0x94..0x96].copy_from_slice(&224u16.to_le_bytes());
        d[0x80 + 40..0x80 + 44].copy_from_slice(&ep.to_le_bytes());
        let first = 0x80 + 24 + 224;
        for (i, (va, raw)) in sections.iter().enumerate() {
            let s = first + i * 40;
            d[s + 12..s + 16].copy_from_slice(&va.to_le_bytes());
            d[s + 20..s + 24].copy_from_slice(&raw.to_le_bytes());
        }
        d
    }

    #[test]
    fn yara_entrypoint_pe() {
        let d = pe(0x1010, &[(0x1000, 0x200), (0x2000, 0x300)]);
        assert_eq!(entry_point_offset(&d), 0x210);
        let d = pe(0x500, &[(0x1000, 0x200)]);
        assert_eq!(entry_point_offset(&d), 0x500);
        assert_eq!(entry_point_offset(b"hello"), UNDEF);
        assert_eq!(entry_point_offset(b"MZ"), UNDEF);
    }

    #[test]
    fn yara_entrypoint_elf_and_garbage() {
        let mut d = vec![0u8; 64];
        d[0..4].copy_from_slice(b"\x7fELF");
        d[4] = 2;
        // no sections / program headers -> 0
        assert_eq!(entry_point_offset(&d), 0);
        let mut seed = 7u32;
        for n in 0..3000usize {
            let mut buf = vec![0u8; n % 700];
            for b in buf.iter_mut() {
                seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
                *b = (seed >> 16) as u8;
            }
            if buf.len() > 4 {
                if n % 3 == 0 {
                    buf[0] = b'M';
                    buf[1] = b'Z';
                } else if n % 3 == 1 {
                    buf[0..4].copy_from_slice(b"\x7fELF");
                }
            }
            let _ = entry_point_offset(&buf);
        }
    }
}
