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
    let (raw, headers, err) = reconstruct_parts(dos);
    let mut out = Vec::with_capacity(headers.len() + 1);
    if let Some(r) = raw {
        out.push((0u64, r.materialize()));
    }
    out.extend(headers);
    (out, err)
}

/// The first piece `reconstruct()` yields, described instead of read: python's
/// `layer.read(base, SizeOfImage, pad=True)` with `fix_image_base` applied
/// (`raw[:off] + new + raw[off + size:]`).
pub struct RawPiece {
    pub layer: crate::objects::LayerRef,
    pub addr: u64,
    pub size: usize,
    /// (offset, the new ImageBase bytes) when python patches it
    pub image_base: Option<(usize, Vec<u8>)>,
}

impl RawPiece {
    /// The piece's bytes (one padded read, like python).
    pub fn materialize(&self) -> Vec<u8> {
        let mut raw = self.layer.read_vec_padded(self.addr, self.size);
        if let Some((ib_off, nv)) = &self.image_base {
            // python slicing: raw[:off] + new + raw[off + size:] (clamped)
            let a = (*ib_off).min(raw.len());
            let b = ib_off.saturating_add(nv.len()).min(raw.len());
            if b - a == nv.len() {
                raw[a..b].copy_from_slice(nv);
            } else {
                let mut fixed = raw[..a].to_vec();
                fixed.extend_from_slice(nv);
                fixed.extend_from_slice(&raw[b..]);
                raw = fixed;
            }
        }
        raw
    }

    /// Whether the ImageBase patch (if any) lies inside the image: the piece is then exactly
    /// the padded read with the patch written over it.
    fn patch_inside(&self) -> bool {
        self.image_base.as_ref().is_none_or(|(o, nv)| o.saturating_add(nv.len()) <= self.size)
    }
}

/// [`reconstruct`] with its first piece described instead of read: (raw piece, the section
/// header pieces after it, python's error).
pub fn reconstruct_parts(dos: &Obj) -> (Option<RawPiece>, Vec<(u64, Vec<u8>)>, Option<Error>) {
    let mut raw_piece = None;
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
        // fix_image_base
        let ib = opt.m("ImageBase")?;
        let ib_off = ib.addr.wrapping_sub(dos.addr) as usize;
        let image_base = value_bytes(&ib, dos.addr as i128).map(|nv| (ib_off, nv));
        raw_piece = Some(RawPiece { layer, addr: dos.addr, size: size_of_image as usize, image_base });
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
    (raw_piece, out, r.err())
}

/// python's `for offset, data in dos_header.reconstruct(): f.seek(offset); f.write(data)` into
/// the fresh (empty) file `f`, with the same resulting bytes. The image is written straight
/// from the chunks python's single padded read copies (zero-copy from the mapped image, see
/// [`crate::layers::intel::IntelLayer::padded_read_chunks`]; reading it page by page is NOT
/// the same) and its all-zero pages stay holes: a module image is mostly pages that were
/// never paged in. The ImageBase patch and the section headers are then written over it with
/// positional writes, like python's seek + write. Returns the first write error (later pieces
/// are not written) and python's error (the pieces before it are written, like python's
/// generator).
pub fn write_reconstructed(f: &std::fs::File, dos: &Obj) -> (std::io::Result<()>, Option<Error>) {
    use std::os::unix::fs::FileExt;
    let (raw, headers, err) = reconstruct_parts(dos);
    let io = (|| -> std::io::Result<()> {
        if let Some(r) = &raw {
            match r.layer.as_intel() {
                Some(il) if r.patch_inside() => {
                    let mut w = crate::cli::files::SparseDump::new(f);
                    let mut res = Ok(());
                    il.padded_read_chunks(r.addr, r.size as u64, &mut |off, size, mapped, tl| {
                        res = w.range(tl, mapped, size, off.wrapping_sub(r.addr));
                        res.is_ok()
                    });
                    res?;
                    w.set_size(r.size as u64);
                    w.finish()?;
                    if let Some((o, nv)) = &r.image_base {
                        f.write_all_at(nv, *o as u64)?;
                    }
                }
                _ => crate::cli::files::write_sparse(f, &r.materialize(), 0)?,
            }
        }
        for (off, data) in &headers {
            // python's seek(offset) raises for these (a wrapped negative offset): stop there
            if *off > i64::MAX as u64 {
                return Err(std::io::ErrorKind::InvalidInput.into());
            }
            f.write_all_at(data, *off)?;
        }
        Ok(())
    })();
    (io, err)
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
    /// the chunks of the padded read, for the pages a read of their own could get wrong
    long: std::cell::OnceCell<LongRead>,
}

/// The chunks python's single padded `read(base, SizeOfImage)` copies
/// ([`crate::layers::intel::IntelLayer::padded_read_chunks`]). A page read on its own differs
/// from the same page inside that read where a large page's physical range is only partly
/// valid (the long read skips the whole large page, or steps through it with python's skip
/// arithmetic when the read ends inside it), and for an unaligned base.
struct LongRead {
    /// the translation layer's targets (`dependencies()`: physical, then swap layers)
    deps: Vec<std::sync::Arc<dyn crate::layers::Layer>>,
    /// (offset from base, size, mapped, target index), in order, adjacent ones merged
    chunks: Vec<(u64, u64, u64, u8)>,
}

impl LongRead {
    fn new(il: &crate::layers::IntelLayer, base: u64, len: u64) -> LongRead {
        let deps = crate::layers::Layer::dependencies(il);
        let mut chunks: Vec<(u64, u64, u64, u8)> = Vec::new();
        il.padded_read_chunks(base, len, &mut |off, size, mapped, tl| {
            let tl = tl as *const dyn crate::layers::Layer;
            let Some(t) = deps.iter().position(|d| std::ptr::addr_eq(d.as_ref() as *const dyn crate::layers::Layer, tl)) else {
                return true;
            };
            let rel = off.wrapping_sub(base);
            match chunks.last_mut() {
                Some(c) if c.0 + c.1 == rel && c.2.wrapping_add(c.1) == mapped && c.3 == t as u8 => c.1 += size,
                _ => chunks.push((rel, size, mapped, t as u8)),
            }
            true
        });
        LongRead { deps, chunks }
    }

    /// Copy the read's bytes `[a, a + buf.len())` (offsets from base) into the zeroed `buf`.
    fn copy(&self, a: u64, buf: &mut [u8]) {
        let b = a + buf.len() as u64;
        let first = self.chunks.partition_point(|c| c.0 + c.1 <= a);
        for &(off, size, mapped, t) in &self.chunks[first..] {
            if off >= b {
                break;
            }
            let (x, y) = (off.max(a), (off + size).min(b));
            self.deps[t as usize].read_padded(mapped + (x - off), &mut buf[(x - a) as usize..(y - a) as usize]);
        }
    }
}

impl PeView {
    fn empty() -> PeView {
        PeView { layer: None, base: 0, raw_len: 0, len: 0, patches: Vec::new(), pages: Vec::new(), long: std::cell::OnceCell::new() }
    }

    /// The padded read's chunks when the raw image's page at `start` (offset from base) must be
    /// taken from them instead of from a read of its own (see [`LongRead`]): it lies in a large
    /// page, or the base is not page aligned.
    fn long_read(&self, l: crate::objects::LayerRef, start: usize) -> Option<&LongRead> {
        let il = l.as_intel()?;
        let large = || matches!(il.translate_raw(self.base.wrapping_add(start as u64)), Ok((_, bits, _)) if bits > 12);
        if self.base & 0xfff != 0 || large() {
            return Some(self.long.get_or_init(|| LongRead::new(il, self.base, self.raw_len as u64)));
        }
        None
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
            let raw_end = end.min(self.raw_len);
            let long = match self.layer {
                Some(l) if raw_end > start => self.long_read(l, start),
                _ => None,
            };
            if let (Some(l), None) = (self.layer, long) {
                if !touched && end - start == 0x1000 && end <= self.raw_len {
                    if let Some(s) = l.slice(self.base.wrapping_add(start as u64), 0x1000) {
                        return ViewPage::Borrowed(s);
                    }
                }
            }
            let mut buf = vec![0u8; end - start].into_boxed_slice();
            if let Some(l) = self.layer {
                if raw_end > start {
                    match long {
                        Some(lr) => lr.copy(start as u64, &mut buf[..raw_end - start]),
                        None => l.read_padded(self.base.wrapping_add(start as u64), &mut buf[..raw_end - start]),
                    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layers::{IntelLayer, Layer, LayerExt, Mapping, PagingMode, PteFlavor};
    use crate::symbols::windows::pefile::PeData;
    use std::sync::Arc;

    /// A physical layer backed by a Vec.
    struct Buf(Vec<u8>);
    impl Layer for Buf {
        fn name(&self) -> &str {
            "buf"
        }
        fn max_address(&self) -> u64 {
            self.0.len() as u64 - 1
        }
        fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
            let a = addr as usize;
            match self.0.get(a..a + buf.len()) {
                Some(s) => {
                    buf.copy_from_slice(s);
                    Ok(())
                }
                None => Err(Error::invalid(addr)),
            }
        }
        fn is_valid(&self, addr: u64, len: u64) -> bool {
            addr + len <= self.0.len() as u64
        }
        fn mapping(&self, addr: u64, len: u64, f: &mut dyn FnMut(Mapping) -> bool) {
            f(Mapping { offset: addr, len, mapped: addr });
        }
    }

    fn put(v: &mut [u8], at: usize, x: &[u8]) {
        v[at..at + x.len()].copy_from_slice(x);
    }

    /// A PE32 at VA 0x3fe000 of a 32-bit (non-PAE) address space: two 4 KiB pages (headers,
    /// then 0x5a bytes), then a 4 MiB page whose physical range (0x400000..0x800000) is only
    /// half inside the 6 MiB physical layer. SizeOfImage ends the image at VA 0x700000.
    fn large_page_pe() -> (crate::objects::LayerRef, Obj) {
        let mut m = vec![0u8; 0x600000];
        put(&mut m, 0x1000, &(0x2000u32 | 1).to_le_bytes()); // PDE[0] -> page table at 0x2000
        put(&mut m, 0x1004, &(0x400000u32 | 0x81).to_le_bytes()); // PDE[1]: 4 MiB page at 0x400000
        put(&mut m, 0x2000 + 0x3fe * 4, &(0x3000u32 | 1).to_le_bytes()); // VA 0x3fe000 -> 0x3000
        put(&mut m, 0x2000 + 0x3ff * 4, &(0x5000u32 | 1).to_le_bytes()); // VA 0x3ff000 -> 0x5000
        let h = 0x3000;
        put(&mut m, h, b"MZ");
        put(&mut m, h + 0x3c, &0x80u32.to_le_bytes()); // e_lfanew
        let nt = h + 0x80;
        put(&mut m, nt, b"PE\0\0");
        put(&mut m, nt + 4, &0x14cu16.to_le_bytes()); // Machine: i386
        put(&mut m, nt + 6, &1u16.to_le_bytes()); // NumberOfSections
        put(&mut m, nt + 20, &0xe0u16.to_le_bytes()); // SizeOfOptionalHeader
        let opt = nt + 24;
        put(&mut m, opt, &0x10bu16.to_le_bytes());
        put(&mut m, opt + 28, &0x1000_0000u32.to_le_bytes()); // ImageBase (patched: 0x3fe000)
        put(&mut m, opt + 32, &0x1000u32.to_le_bytes()); // SectionAlignment
        put(&mut m, opt + 36, &0x200u32.to_le_bytes()); // FileAlignment
        put(&mut m, opt + 56, &0x302000u32.to_le_bytes()); // SizeOfImage
        let sh = opt + 0xe0;
        put(&mut m, sh, b".text");
        put(&mut m, sh + 8, &0x1234u32.to_le_bytes()); // VirtualSize
        put(&mut m, sh + 12, &0x1000u32.to_le_bytes()); // VirtualAddress
        put(&mut m, sh + 16, &0x400u32.to_le_bytes()); // SizeOfRawData
        put(&mut m, sh + 20, &0x400u32.to_le_bytes()); // PointerToRawData
        m[0x5000..0x6000].fill(0x5a);
        for (i, b) in m[0x400000..].iter_mut().enumerate() {
            *b = (i % 251) as u8 | 1;
        }
        let phys: Arc<dyn Layer> = Arc::new(Buf(m));
        let l = crate::objects::leak_layer(Arc::new(IntelLayer::new("t", phys, 0x1000, PagingMode::Intel32, PteFlavor::Windows)));
        let pe = crate::symbols::load_isf("windows", "pe", None, &[]).unwrap();
        let dos = Obj::named(crate::objects::Space::on(l, pe), "_IMAGE_DOS_HEADER", 0x3fe000).unwrap();
        (l, dos)
    }

    /// python: the reconstruct() pieces written into a BytesIO at their offsets.
    fn python_bytes(dos: &Obj) -> Vec<u8> {
        let (pieces, err) = reconstruct(dos);
        assert!(err.is_none(), "{err:?}");
        let mut v = Vec::new();
        for (off, d) in pieces {
            let off = off as usize;
            if v.len() < off + d.len() {
                v.resize(off + d.len(), 0);
            }
            v[off..off + d.len()].copy_from_slice(&d);
        }
        v
    }

    /// The dump writer and the lazy view give python's bytes: one long padded read, which
    /// skips a large page whose physical range is only partly valid as a whole (reading its
    /// pages one by one would return their data).
    #[test]
    fn large_page_long_read() {
        let (l, dos) = large_page_pe();
        let want = python_bytes(&dos);
        assert_eq!(want.len(), 0x302000);
        assert_eq!(&want[..2], b"MZ");
        assert_eq!(&want[0x80 + 24 + 28..0x80 + 24 + 32], &0x3fe000u32.to_le_bytes()); // ImageBase fixed
        assert_eq!(&want[0x80 + 24 + 0xe0 + 8..0x80 + 24 + 0xe0 + 12], &0x2000u32.to_le_bytes()); // VirtualSize rounded
        assert!(want[0x1000..0x2000].iter().all(|&b| b == 0x5a));
        assert!(want[0x2000..].iter().all(|&b| b == 0));
        // what a page-by-page read would have produced instead
        assert!(l.read_vec_padded(0x400000, 0x1000).iter().all(|&b| b != 0));

        let dir = std::env::temp_dir().join(format!("rsvol-pe-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("x.dmp");
        let f = crate::cli::files::open_new(&path).unwrap();
        let (io, err) = write_reconstructed(&f, &dos);
        io.unwrap();
        assert!(err.is_none());
        drop(f);
        assert!(std::fs::read(&path).unwrap() == want, "dump differs from python's bytes");

        // the lazy view, pages materialized in order and out of order
        let (view, err) = reconstruct_view(&dos);
        assert!(err.is_none());
        assert_eq!(view.len(), want.len());
        assert!(view.bytes(0, want.len()).as_ref() == &want[..]);
        let (view, _) = reconstruct_view(&dos);
        for p in (0..want.len()).step_by(0x1000).rev() {
            let e = (p + 0x1000).min(want.len());
            assert!(view.bytes(p, e).as_ref() == &want[p..e], "page {p:#x}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// vad / vma dumps (`cli::files::dump_padded_reads`): python's 10 MiB padded reads, each
    /// one long read, from a start inside the large page too.
    #[test]
    fn padded_reads_dump() {
        let (l, _) = large_page_pe();
        let dir = std::env::temp_dir().join(format!("rsvol-pe-vad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cases = [(0x3fe000u64, 0x302000u128), (0x3ff000, 0x1234), (0x401000, 0x2ff000), (0x3fe800, 0x1800), (0x0, 0x0), (0x3fd000, 0x503000)];
        for (i, (start, size)) in cases.into_iter().enumerate() {
            for chunk in [10u128 << 20, 0x100000, 0x3000] {
                let path = dir.join(format!("v{i}-{chunk}"));
                let f = crate::cli::files::open_new(&path).unwrap();
                crate::cli::files::dump_padded_reads_at(&f, l, start, size, chunk, 0).unwrap();
                drop(f);
                // python: the padded reads of each chunk, one after the other
                let mut want = Vec::new();
                let mut off = 0;
                while off < size {
                    let n = chunk.min(size - off);
                    want.extend_from_slice(&l.read_vec_padded(start + off as u64, n as usize));
                    off += n;
                }
                assert!(std::fs::read(&path).unwrap() == want, "{start:#x}+{size:#x} chunks of {chunk:#x}");
            }
        }
        // ELF-style: sections concatenated, one read each (the last ones all zeros)
        let path = dir.join("elf");
        let f = crate::cli::files::open_new(&path).unwrap();
        let (mut off, mut want) = (0u64, Vec::new());
        for (s, n) in [(0x3fe000u64, 0x2000u128), (0x400000, 0x1000), (0x3ff000, 0x3000), (0x500000, 0x2000)] {
            crate::cli::files::dump_padded_reads_at(&f, l, s, n, n, off).unwrap();
            want.extend_from_slice(&l.read_vec_padded(s, n as usize));
            off += n as u64;
        }
        drop(f);
        assert!(std::fs::read(&path).unwrap() == want);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
