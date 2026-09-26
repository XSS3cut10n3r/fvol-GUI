//! python `symbols/windows/extensions/pe.py`: `_IMAGE_DOS_HEADER.get_nt_header()`,
//! `reconstruct()` and `_IMAGE_NT_HEADERS.get_sections()` (objects from the `windows/pe`
//! table).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::error::{Error, Result};
use crate::layers::LayerExt;
use crate::objects::Obj;

/// python `constants.windows.PE_MAX_EXTRACTION_SIZE`.
pub const PE_MAX_EXTRACTION_SIZE: u64 = 1024 * 1024 * 256;

/// python `IMAGE_DOS_HEADER.get_nt_header()`: `_IMAGE_NT_HEADERS` or `_IMAGE_NT_HEADERS64`.
pub fn get_nt_header(dos: &Obj) -> Result<Obj> {
    let magic = dos.m("e_magic")?.u64()?;
    if magic != 0x5A4D {
        return Err(Error::msg(format!("e_magic {magic:04X} is not a valid DOS signature.")));
    }
    let lfanew = dos.m("e_lfanew")?.int()?;
    let nt = Obj::named(dos.sp, "_IMAGE_NT_HEADERS", (dos.addr as i128 + lfanew) as u64)?;
    let sig = nt.m("Signature")?.u64()?;
    if sig != 0x4550 {
        return Err(Error::msg(format!("NT header signature {sig:04X} is not a valid")));
    }
    if nt.path("FileHeader.Machine")?.u64()? == 34404 {
        return nt.cast("_IMAGE_NT_HEADERS64");
    }
    Ok(nt)
}

/// python `IMAGE_NT_HEADERS.get_sections()`.
pub fn get_sections(nt: &Obj) -> Result<Vec<Obj>> {
    let sect_size = nt.table().size_of(nt.table().get_type("_IMAGE_SECTION_HEADER")?);
    let opt = nt.m("OptionalHeader")?;
    let start = nt.path("FileHeader.SizeOfOptionalHeader")?.u64()?.wrapping_add(opt.addr);
    let n = nt.path("FileHeader.NumberOfSections")?.u64()?;
    (0..n).map(|i| Obj::named(nt.sp, "_IMAGE_SECTION_HEADER", start.wrapping_add(i * sect_size))).collect()
}

/// python `int.to_bytes(length, byteorder, signed)` for a primitive member object; None on
/// OverflowError.
fn value_bytes(member: &Obj, value: i128) -> Option<Vec<u8>> {
    let (size, signed, big) = match member.ty {
        crate::symbols::Ty::Int(p) => (p.size as usize, p.signed, p.big_endian),
        crate::symbols::Ty::Pointer { prim, .. } => (prim.size as usize, false, prim.big_endian),
        _ => return None,
    };
    let bits = size * 8;
    let fits = if signed {
        bits >= 128 || (value >= -(1i128 << (bits - 1)) && value < (1i128 << (bits - 1)))
    } else {
        value >= 0 && (bits >= 128 || value < (1i128 << bits))
    };
    if !fits {
        return None;
    }
    let le = (value as u128).to_le_bytes();
    let mut v = le[..size].to_vec();
    if big {
        v.reverse();
    }
    Some(v)
}

/// python `conversion.round(addr, align, up=True)`.
fn round_up(addr: u64, align: u64) -> Result<u64> {
    if align == 0 {
        return Err(Error::msg("ZeroDivisionError: integer modulo by zero"));
    }
    Ok(if addr % align == 0 { addr } else { addr + (align - addr % align) })
}

/// python `IMAGE_DOS_HEADER.reconstruct()`: `(file offset, data)` pieces to write, in order.
/// Python is a generator: when it raises midway, the pieces yielded so far have already been
/// written -- callers get them in `.0` and the error in `.1`.
pub fn reconstruct(dos: &Obj) -> (Vec<(u64, Vec<u8>)>, Option<Error>) {
    let mut out = Vec::new();
    let r = (|| -> Result<()> {
        let nt = get_nt_header(dos)?;
        let opt = nt.m("OptionalHeader")?;
        let section_alignment = opt.m("SectionAlignment")?.u64()?;
        let sect_header_size = dos.table().size_of(dos.table().get_type("_IMAGE_SECTION_HEADER")?);
        let size_of_image = opt.m("SizeOfImage")?.u64()?;
        if size_of_image > PE_MAX_EXTRACTION_SIZE {
            return Err(Error::msg(format!("The claimed SizeOfImage is too large: {size_of_image}")));
        }
        let layer = dos.layer();
        let mut raw = layer.read_vec_padded(dos.addr, size_of_image as usize);
        // fix_image_base
        let ib = opt.m("ImageBase")?;
        let ib_off = ib.addr.wrapping_sub(dos.addr) as usize;
        if let Some(nv) = value_bytes(&ib, dos.addr as i128) {
            // python slicing: raw[:off] + new + raw[off + size:] (clamped)
            let a = ib_off.min(raw.len());
            let b = ib_off.saturating_add(nv.len()).min(raw.len());
            let mut fixed = raw[..a].to_vec();
            fixed.extend_from_slice(&nv);
            fixed.extend_from_slice(&raw[b..]);
            raw = fixed;
        }
        out.push((0u64, raw));
        let start_addr = nt.path("FileHeader.SizeOfOptionalHeader")?.u64()?.wrapping_add(opt.addr.wrapping_sub(dos.addr));
        for (counter, sect) in get_sections(&nt)?.into_iter().enumerate() {
            let va = sect.m("VirtualAddress")?.u64()?;
            if va > size_of_image {
                return Err(Error::msg(format!("Section VirtualAddress is too large: {va}")));
            }
            let vs = sect.path("Misc.VirtualSize")?.u64()?;
            if vs > size_of_image {
                return Err(Error::msg(format!("Section VirtualSize is too large: {vs}")));
            }
            let srd = sect.m("SizeOfRawData")?.u64()?;
            if srd > size_of_image {
                return Err(Error::msg(format!("Section SizeOfRawData is too large: {srd}")));
            }
            let sect_size = round_up(vs, section_alignment)?;
            let mut header = layer.read_vec(sect.addr, sect_header_size as usize)?;
            for (item, value) in [(sect.m("PointerToRawData")?, va), (sect.m("SizeOfRawData")?, sect_size), (sect.path("Misc.VirtualSize")?, sect_size)] {
                let msize = item.size() as usize;
                let start = item.addr.wrapping_sub(sect.addr) as usize;
                let nv = value_bytes(&item, value as i128).ok_or_else(|| Error::msg("OverflowError: int too big to convert"))?;
                let end = (start + msize).min(header.len());
                let mut h = header[..start.min(header.len())].to_vec();
                h.extend_from_slice(&nv);
                h.extend_from_slice(&header[end..]);
                header = h;
            }
            out.push((start_addr.wrapping_add(counter as u64 * sect_header_size), header));
        }
        Ok(())
    })();
    (out, r.err())
}

/// Write reconstruct() pieces into a file like python (`seek(offset); write(data)`).
pub fn write_pieces(f: &mut std::fs::File, pieces: &[(u64, Vec<u8>)]) -> std::io::Result<()> {
    use std::io::{Seek, SeekFrom, Write};
    for (off, data) in pieces {
        f.seek(SeekFrom::Start(*off))?;
        f.write_all(data)?;
    }
    Ok(())
}
