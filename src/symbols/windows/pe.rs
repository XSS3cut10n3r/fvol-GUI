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

/// Why python's `reconstruct()` (and the `BytesIO` writes of its pieces) stopped early. The
/// plugins catch different python exception types, so the kind matters.
#[derive(Debug)]
pub enum ReconError {
    /// `InvalidAddressException` (a header could not be read).
    Invalid(Error),
    /// `ValueError` (bad signature, oversized SizeOfImage / section, negative seek).
    Value(String),
    /// `OverflowError` (a fixed section field does not fit its type).
    Overflow(String),
    /// `ZeroDivisionError` (SectionAlignment 0 in `conversion.round`).
    ZeroDivision,
}

impl ReconError {
    /// Caught by `except (InvalidAddressException, ValueError)` (pe_symbols, iat, verinfo).
    pub fn is_invalid_or_value(&self) -> bool {
        matches!(self, ReconError::Invalid(_) | ReconError::Value(_))
    }
    fn from_error(e: Error) -> ReconError {
        if e.is_invalid_address() { ReconError::Invalid(e) } else { ReconError::Value(e.to_string()) }
    }
}

impl std::fmt::Display for ReconError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReconError::Invalid(e) => write!(f, "{e}"),
            ReconError::Value(m) => write!(f, "ValueError: {m}"),
            ReconError::Overflow(m) => write!(f, "OverflowError: {m}"),
            ReconError::ZeroDivision => write!(f, "ZeroDivisionError: integer modulo by zero"),
        }
    }
}

enum ViewPage {
    Borrowed(&'static [u8]),
    Owned(Box<[u8]>),
}

/// The bytes python builds with `for offset, data in dos_header.reconstruct(): pe_data.seek(offset);
/// pe_data.write(data)` (a `BytesIO`), materialized lazily page by page: pefile usually touches a
/// handful of pages of a module, so nothing else is read. Pages come zero-copy from the mmapped
/// image when possible. Feed it to [`super::pefile::PeFile::parse`].
pub struct PeView {
    layer: Option<crate::objects::LayerRef>,
    base: u64,
    /// bytes of the padded `read(base, SizeOfImage)` (0 when reconstruct failed before the
    /// first yield)
    raw_len: usize,
    /// `len(pe_data.getvalue())`
    len: usize,
    /// later writes over the raw image, in write order
    patches: Vec<(usize, Vec<u8>)>,
    pages: Vec<std::cell::OnceCell<ViewPage>>,
}

impl PeView {
    fn empty() -> PeView {
        PeView { layer: None, base: 0, raw_len: 0, len: 0, patches: Vec::new(), pages: Vec::new() }
    }

    /// `pe_data.seek(off); pe_data.write(data)`.
    fn write(&mut self, off: usize, data: Vec<u8>) {
        self.len = self.len.max(off + data.len());
        self.patches.push((off, data));
    }

    fn finish(mut self) -> PeView {
        let n = self.len.div_ceil(0x1000);
        self.pages = (0..n).map(|_| std::cell::OnceCell::new()).collect();
        self
    }

    /// Base address the image was read from.
    pub fn base(&self) -> u64 {
        self.base
    }

    fn page(&self, p: usize) -> &[u8] {
        let v = self.pages[p].get_or_init(|| {
            let start = p * 0x1000;
            let end = (start + 0x1000).min(self.len);
            let touched = self.patches.iter().any(|(o, d)| *o < end && o + d.len() > start);
            if let Some(l) = self.layer {
                if !touched && end - start == 0x1000 && end <= self.raw_len {
                    if let Some(s) = l.slice(self.base.wrapping_add(start as u64), 0x1000) {
                        return ViewPage::Borrowed(s);
                    }
                }
            }
            let mut buf = vec![0u8; end - start].into_boxed_slice();
            if let Some(l) = self.layer {
                let raw_end = end.min(self.raw_len);
                if raw_end > start {
                    l.read_padded(self.base.wrapping_add(start as u64), &mut buf[..raw_end - start]);
                }
            }
            for (o, d) in &self.patches {
                let (o, e) = (*o, o + d.len());
                if o < end && e > start {
                    let a = o.max(start);
                    let b = e.min(end);
                    buf[a - start..b - start].copy_from_slice(&d[a - o..b - o]);
                }
            }
            ViewPage::Owned(buf)
        });
        match v {
            ViewPage::Borrowed(s) => s,
            ViewPage::Owned(b) => b,
        }
    }
}

impl super::pefile::PeData for PeView {
    fn len(&self) -> usize {
        self.len
    }
    fn bytes(&self, a: usize, b: usize) -> std::borrow::Cow<'_, [u8]> {
        if a >= b {
            return std::borrow::Cow::Borrowed(&[]);
        }
        let (pa, pb) = (a >> 12, (b - 1) >> 12);
        if pa == pb {
            let pg = self.page(pa);
            return std::borrow::Cow::Borrowed(&pg[a & 0xFFF..((b - 1) & 0xFFF) + 1]);
        }
        let mut out = Vec::with_capacity(b - a);
        let mut pos = a;
        while pos < b {
            let p = pos >> 12;
            let stop = ((p + 1) << 12).min(b);
            out.extend_from_slice(&self.page(p)[pos & 0xFFF..(pos & 0xFFF) + (stop - pos)]);
            pos = stop;
        }
        std::borrow::Cow::Owned(out)
    }
}

/// python `IMAGE_DOS_HEADER.reconstruct()` + the `BytesIO` its caller writes the pieces into,
/// as a lazy [`PeView`] (see [`reconstruct`] for the eager form used for dumping). On error the
/// view holds what python had written before the exception (what `pe_data` holds after a
/// caught exception).
pub fn reconstruct_view(dos: &Obj) -> (PeView, Option<ReconError>) {
    let mut view = PeView::empty();
    let r = (|| -> std::result::Result<(), ReconError> {
        let e = ReconError::from_error;
        let nt = get_nt_header(dos).map_err(e)?;
        let opt = nt.m("OptionalHeader").map_err(e)?;
        let section_alignment = opt.m("SectionAlignment").and_then(|o| o.u64()).map_err(e)?;
        let sect_header_size = dos.table().size_of(dos.table().get_type("_IMAGE_SECTION_HEADER").map_err(e)?);
        let size_of_image = opt.m("SizeOfImage").and_then(|o| o.u64()).map_err(e)?;
        if size_of_image > PE_MAX_EXTRACTION_SIZE {
            return Err(ReconError::Value(format!("The claimed SizeOfImage is too large: {size_of_image}")));
        }
        let layer = dos.layer();
        view.layer = Some(layer);
        view.base = dos.addr;
        view.raw_len = size_of_image as usize;
        view.len = size_of_image as usize;
        // fix_image_base: raw[:off] + new + raw[off + size:] (python slices clamp at the end)
        let ib = opt.m("ImageBase").map_err(e)?;
        let ib_off = ib.addr.wrapping_sub(dos.addr) as usize;
        if let Some(nv) = value_bytes(&ib, dos.addr as i128) {
            let pos = ib_off.min(view.raw_len);
            view.len = view.len.max(pos + nv.len());
            view.patches.push((pos, nv));
        }
        let start_addr = nt.path("FileHeader.SizeOfOptionalHeader").and_then(|o| o.u64()).map_err(e)? as i128 + (opt.addr as i128 - dos.addr as i128);
        let sections = get_sections(&nt).map_err(e)?;
        for (counter, sect) in sections.into_iter().enumerate() {
            let rd = |p: &str| sect.path(p).and_then(|o| o.u64()).map_err(ReconError::from_error);
            let va = rd("VirtualAddress")?;
            if va > size_of_image {
                return Err(ReconError::Value(format!("Section VirtualAddress is too large: {va}")));
            }
            let vs = rd("Misc.VirtualSize")?;
            if vs > size_of_image {
                return Err(ReconError::Value(format!("Section VirtualSize is too large: {vs}")));
            }
            let srd = rd("SizeOfRawData")?;
            if srd > size_of_image {
                return Err(ReconError::Value(format!("Section SizeOfRawData is too large: {srd}")));
            }
            if section_alignment == 0 {
                return Err(ReconError::ZeroDivision);
            }
            let sect_size = if vs % section_alignment == 0 { vs } else { vs + (section_alignment - vs % section_alignment) };
            let mut header = layer.read_vec(sect.addr, sect_header_size as usize).map_err(e)?;
            for (item, value) in [("PointerToRawData", va), ("SizeOfRawData", sect_size), ("Misc.VirtualSize", sect_size)] {
                let item = sect.path(item).map_err(e)?;
                let msize = item.size() as usize;
                let start = item.addr.wrapping_sub(sect.addr) as usize;
                let nv = value_bytes(&item, value as i128).ok_or_else(|| ReconError::Overflow("int too big to convert".into()))?;
                let end = (start + msize).min(header.len());
                let mut h = header[..start.min(header.len())].to_vec();
                h.extend_from_slice(&nv);
                h.extend_from_slice(&header[end..]);
                header = h;
            }
            let offset = start_addr + counter as i128 * sect_header_size as i128;
            if offset < 0 {
                return Err(ReconError::Value(format!("negative seek value {offset}")));
            }
            view.write(offset as usize, header);
        }
        Ok(())
    })();
    (view.finish(), r.err())
}
