// Derived from Volatility 3 (Volatility Software License 1.0): framework/layers/msf.py
//! MSF ("Multi-Stream Format") container used by PDB files.
//!
//! Mirrors volatility3's `PdbMultiStreamFormat` / `PdbMSFStream` layers, including their
//! quirks:
//!   * both the 2.00 and the 7.00 header are recognised, but the stream directory is always
//!     decoded the 7.00 way (u32 page numbers behind a root index), exactly like python;
//!   * a stream's "maximum address" is its declared size, yet reads may run into the slack of
//!     its last page (they only fail past the last listed page or past the end of the file);
//!   * structure members are located through the layer's `address_mask`
//!     (`(1 << ceil(log2(size))) - 1`), see [`Stream::m`].

use super::{PErr, PResult};
use std::borrow::Cow;

const MSF_HDR_MAGIC: &[u8] = b"Microsoft C/C++ program database 2.00\r\n\x1a\x4a\x47";
const BIG_MSF_HDR_MAGIC: &[u8] = b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53";

/// Parsed MSF directory: the page list of every stream.
pub(crate) struct Msf<'a> {
    file: &'a [u8],
    page_size: u64,
    streams: Vec<Option<StreamDesc>>,
}

struct StreamDesc {
    size: u64,
    pages: Vec<u32>,
}

/// A materialised MSF stream (python `PdbMSFStream`).
pub(crate) struct Stream<'a> {
    /// `pages.len() * page_size` bytes; bytes not backed by the file are zero and listed in
    /// `holes`.
    data: Cow<'a, [u8]>,
    /// `[start, end)` ranges of `data` that are not backed by the file (reads fail there).
    holes: Vec<(u64, u64)>,
    /// Declared stream size (python `maximum_address`).
    pub size: u64,
    /// python `address_mask` of the layer, applied to structure member offsets.
    mask: u64,
}

/// python `LayerInterface.address_mask`: `(1 << ceil(log2(maximum_address))) - 1`.
fn address_mask(max_address: u64) -> u64 {
    if max_address <= 1 {
        // log2(1) == 0 -> mask 0 (log2(0) raises in python; streams of size 0 do not exist).
        return 0;
    }
    let bits = 64 - (max_address - 1).leading_zeros();
    if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 }
}

/// python `math.ceil(a / b)` for the small non-negative values used here.
#[inline]
fn ceil_div(a: i64, b: i64) -> i64 {
    // b > 0 always (page size is validated to be >= 0x100)
    if a >= 0 { (a + b - 1) / b } else { -((-a) / b) }
}

/// `bytes_to_decoded_string` termination test: the character after the magic must be a NUL
/// or an invalid UTF-8 sequence (which decodes to U+FFFD), or the data must end there.
fn string_terminates(rest: &[u8]) -> bool {
    match rest.first() {
        None => true,
        Some(0) => true,
        Some(&b) if b < 0x80 => false,
        Some(_) => match std::str::from_utf8(rest) {
            Ok(_) => false,
            Err(e) => e.valid_up_to() == 0,
        },
    }
}

impl<'a> Msf<'a> {
    /// python `PdbMultiStreamFormat.__init__` + `read_streams`.
    pub(crate) fn open(file: &'a [u8]) -> PResult<Msf<'a>> {
        let file_mask = address_mask((file.len() as u64).saturating_sub(1));
        let fread = |off: u64, len: usize| -> PResult<&'a [u8]> {
            let off = off as usize;
            match off.checked_add(len) {
                Some(end) if end <= file.len() => Ok(&file[off..end]),
                _ => Err(PErr::Invalid(off as u64)),
            }
        };
        let fi32 = |off: u64| -> PResult<i64> {
            let b = fread(off & file_mask, 4)?;
            Ok(i32::from_le_bytes([b[0], b[1], b[2], b[3]]) as i64)
        };
        let fu32 = |off: u64| -> PResult<u32> {
            let b = fread(off & file_mask, 4)?;
            Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        };

        // _check_header: (magic, magic array length, PageSize, StreamInfoSize, header size)
        let mut found = None;
        for &(magic, count, ps_off, sis_off, hdr_size) in
            &[(MSF_HDR_MAGIC, 44u64, 44u64, 52u64, 60u64), (BIG_MSF_HDR_MAGIC, 30, 32, 44, 52)]
        {
            // address_to_string on a non-translation layer: needs start + count < maximum_address
            let max_addr = (file.len() as i64) - 1;
            if (count as i64) >= max_addr {
                return Err(PErr::Invalid(0));
            }
            let data = &file[..count as usize];
            let ok = data.starts_with(magic) && string_terminates(&data[magic.len()..]);
            if ok {
                let ps = fi32(ps_off)?;
                if (0x100..=128 * 0x10000).contains(&ps) {
                    found = Some((ps, sis_off, hdr_size));
                    break;
                }
            }
        }
        let (page_size, sis_off, hdr_size) = match found {
            Some(f) => f,
            None => return Err(PErr::Other("Could not find a suitable header".into())),
        };
        let stream_info_size = fi32(sis_off)?;

        let mut msf = Msf { file, page_size: page_size as u64, streams: Vec::new() };

        let root_table_num_pages = ceil_div(stream_info_size, page_size);
        let root_index_size = ceil_div(root_table_num_pages * 4, page_size);
        let mut root_index = Vec::new();
        for i in 0..root_index_size.max(0) as u64 {
            root_index.push(fu32(hdr_size + 4 * i)?);
        }
        let root_index_layer = msf.stream_from_pages(stream_info_size, root_index)?;
        let mut root_pages = Vec::new();
        for i in 0..root_table_num_pages.max(0) as u64 {
            root_pages.push(root_index_layer.u32(root_index_layer.m(4 * i))?);
        }
        let root = msf.stream_from_pages(stream_info_size, root_pages)?;

        let num_streams = root.u32(0)? as u64;
        // Python locates the directory arrays through the root layer's address mask, so a
        // corrupt directory whose arrays run past `mask + 1` wraps around and is read forever
        // (billions of streams). A directory is only meaningful while it does not wrap: refuse
        // those instead of looping / exhausting memory.
        let span = root.mask + 1;
        let wrap_err = || PErr::Other("corrupt MSF stream directory (wraps around)".into());
        let mut current_offset = (num_streams + 1) * 4;
        if current_offset > span {
            return Err(wrap_err());
        }
        let mut streams = Vec::with_capacity(num_streams.min(root.bytes().len() as u64 / 4) as usize);
        for stream in 0..num_streams {
            let size = root.u32(4 + 4 * stream)?;
            let list_size = ceil_div(size as i64, page_size) as u64;
            if list_size == 0 || size == 0xFFFF_FFFF {
                streams.push(None);
                continue;
            }
            let end = current_offset + list_size * 4;
            if end > span {
                return Err(wrap_err());
            }
            // every page number must be readable from the root stream
            let bytes = root.read(current_offset, list_size * 4)?;
            let pages =
                bytes.as_chunks::<4>().0.iter().map(|c| u32::from_le_bytes(*c)).collect();
            current_offset = end;
            streams.push(Some(StreamDesc { size: size as u64, pages }));
        }
        msf.streams = streams;
        Ok(msf)
    }

    /// Number of entries in the stream directory.
    #[allow(dead_code)]
    pub(crate) fn num_streams(&self) -> usize {
        self.streams.len()
    }

    /// Returns stream `index` (None when it does not exist or is empty/nil, i.e. when python
    /// has no `<msf>_stream<index>` layer).
    pub(crate) fn stream(&self, index: i64) -> PResult<Option<Stream<'a>>> {
        if index < 0 {
            return Ok(None);
        }
        match self.streams.get(index as usize) {
            Some(Some(desc)) => Ok(Some(self.materialize(desc.size, &desc.pages)?)),
            _ => Ok(None),
        }
    }

    /// Declared size of stream `index` (None when python has no layer for it).
    pub(crate) fn stream_size(&self, index: i64) -> Option<u64> {
        match self.streams.get(usize::try_from(index).ok()?) {
            Some(Some(d)) => Some(d.size),
            _ => None,
        }
    }

    /// Like [`Msf::stream`] but without materialising the stream: for streams of which only a
    /// few fields are read (DBI header, section headers).
    pub(crate) fn paged(&self, index: i64) -> Option<Paged<'a>> {
        if index < 0 {
            return None;
        }
        match self.streams.get(index as usize) {
            Some(Some(desc)) => Some(Paged {
                file: self.file,
                ps: self.page_size,
                pages: desc.pages.clone(),
                size: desc.size,
                mask: address_mask(desc.size),
            }),
            _ => None,
        }
    }

    /// python `create_stream_from_pages` (the stream must have at least one page).
    fn stream_from_pages(&self, maximum_size: i64, pages: Vec<u32>) -> PResult<Stream<'a>> {
        if pages.is_empty() {
            return Err(PErr::Other("Invalid/no pages specified".into()));
        }
        // A negative maximum_size cannot happen here: pages is non-empty only if size > 0.
        self.materialize(maximum_size.max(0) as u64, &pages)
    }

    fn materialize(&self, size: u64, pages: &[u32]) -> PResult<Stream<'a>> {
        let ps = self.page_size;
        let flen = self.file.len() as u64;
        let total = (pages.len() as u64).saturating_mul(ps);
        let mask = address_mask(size);
        // Fast path: pages are consecutive and fully inside the file -> borrow.
        let first = pages[0] as u64;
        let consecutive = pages.iter().enumerate().all(|(i, &p)| p as u64 == first + i as u64);
        if consecutive && first * ps + total <= flen && total <= u32::MAX as u64 {
            let start = (first * ps) as usize;
            return Ok(Stream {
                data: Cow::Borrowed(&self.file[start..start + total as usize]),
                holes: Vec::new(),
                size,
                mask,
            });
        }
        // In a well-formed MSF every stream page is a distinct page of the file, so no stream
        // is larger than the file. Refuse more (repeated pages let a tiny file describe a
        // gigantic stream; python would crawl through it, we would just burn memory).
        let limit = flen.saturating_add(ps).min(u32::MAX as u64);
        if total > limit {
            return Err(PErr::Other(format!("MSF stream too large ({total} bytes)")));
        }
        let mut data = Vec::new();
        if data.try_reserve_exact(total as usize).is_err() {
            return Err(PErr::Other("out of memory materialising MSF stream".into()));
        }
        let mut holes: Vec<(u64, u64)> = Vec::new();
        for &p in pages {
            let off = p as u64 * ps;
            let avail = flen.saturating_sub(off).min(ps);
            if avail > 0 {
                data.extend_from_slice(&self.file[off as usize..(off + avail) as usize]);
            }
            if avail < ps {
                let base = data.len() as u64;
                data.resize(data.len() + (ps - avail) as usize, 0);
                let end = data.len() as u64;
                match holes.last_mut() {
                    Some(h) if h.1 == base => h.1 = end,
                    _ => holes.push((base, end)),
                }
            }
        }
        Ok(Stream { data: Cow::Owned(data), holes, size, mask })
    }
}

/// An MSF stream accessed page by page (no copy), for sparse small reads.
pub(crate) struct Paged<'a> {
    file: &'a [u8],
    ps: u64,
    pages: Vec<u32>,
    pub size: u64,
    mask: u64,
}

impl<'a> Paged<'a> {
    #[cfg(test)]
    pub(crate) fn test_new() -> Paged<'static> {
        Paged { file: &[], ps: 4096, pages: Vec::new(), size: 0, mask: 0 }
    }

    #[inline(always)]
    pub(crate) fn m(&self, off: u64) -> u64 {
        off & self.mask
    }

    /// python `layer.read(off, len)` into `buf`.
    pub(crate) fn read_into(&self, off: u64, buf: &mut [u8]) -> PResult<()> {
        let mut done = 0usize;
        while done < buf.len() {
            let pos = off + done as u64;
            let page = pos / self.ps;
            let in_page = pos % self.ps;
            let Some(&p) = self.pages.get(page as usize) else { return Err(PErr::Invalid(pos)) };
            let chunk = ((self.ps - in_page) as usize).min(buf.len() - done);
            let foff = p as u64 * self.ps + in_page;
            match self.file.get(foff as usize..foff as usize + chunk) {
                Some(src) => buf[done..done + chunk].copy_from_slice(src),
                None => return Err(PErr::Invalid(pos)),
            }
            done += chunk;
        }
        Ok(())
    }

    #[inline]
    pub(crate) fn u8(&self, off: u64) -> PResult<u8> {
        let mut b = [0u8; 1];
        self.read_into(off, &mut b)?;
        Ok(b[0])
    }
    #[inline]
    pub(crate) fn u16(&self, off: u64) -> PResult<u16> {
        let mut b = [0u8; 2];
        self.read_into(off, &mut b)?;
        Ok(u16::from_le_bytes(b))
    }
    #[inline]
    pub(crate) fn i16(&self, off: u64) -> PResult<i16> {
        Ok(self.u16(off)? as i16)
    }
    #[inline]
    pub(crate) fn u32(&self, off: u64) -> PResult<u32> {
        let mut b = [0u8; 4];
        self.read_into(off, &mut b)?;
        Ok(u32::from_le_bytes(b))
    }
}

impl<'a> Stream<'a> {
    /// The whole materialised stream (including last-page slack). Only for slicing ranges
    /// that were already validated with [`Stream::read`].
    #[inline(always)]
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.data
    }

    /// Masked structure member offset (python `AggregateType.__getattr__`).
    #[inline(always)]
    pub(crate) fn m(&self, off: u64) -> u64 {
        off & self.mask
    }

    /// Reads `len` bytes at `off` (python `layer.read(off, len)` without padding).
    #[inline]
    pub(crate) fn read(&self, off: u64, len: u64) -> PResult<&[u8]> {
        let end = match off.checked_add(len) {
            Some(e) if e <= self.data.len() as u64 => e,
            _ => return Err(PErr::Invalid(off.max(self.data.len() as u64))),
        };
        if !self.holes.is_empty() {
            for &(hs, he) in &self.holes {
                if off < he && end > hs && len > 0 {
                    return Err(PErr::Invalid(off.max(hs)));
                }
            }
        }
        Ok(&self.data[off as usize..end as usize])
    }

    #[inline]
    pub(crate) fn u8(&self, off: u64) -> PResult<u8> {
        Ok(self.read(off, 1)?[0])
    }
    #[inline]
    pub(crate) fn u16(&self, off: u64) -> PResult<u16> {
        let b = self.read(off, 2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    #[inline]
    pub(crate) fn u32(&self, off: u64) -> PResult<u32> {
        let b = self.read(off, 4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    #[inline]
    pub(crate) fn i16(&self, off: u64) -> PResult<i16> {
        Ok(self.u16(off)? as i16)
    }
    #[inline]
    pub(crate) fn i8(&self, off: u64) -> PResult<i8> {
        Ok(self.u8(off)? as i8)
    }
    #[inline]
    pub(crate) fn i32(&self, off: u64) -> PResult<i32> {
        Ok(self.u32(off)? as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks() {
        assert_eq!(address_mask(1), 0);
        assert_eq!(address_mask(2), 1);
        assert_eq!(address_mask(3), 3);
        assert_eq!(address_mask(4), 3);
        assert_eq!(address_mask(5), 7);
        assert_eq!(address_mask(4096), 0xfff);
        assert_eq!(address_mask(4097), 0x1fff);
        assert_eq!(address_mask(u32::MAX as u64), u32::MAX as u64);
    }

    #[test]
    fn ceil() {
        assert_eq!(ceil_div(0, 4096), 0);
        assert_eq!(ceil_div(1, 4096), 1);
        assert_eq!(ceil_div(4096, 4096), 1);
        assert_eq!(ceil_div(4097, 4096), 2);
        assert_eq!(ceil_div(-1, 4096), 0);
        assert_eq!(ceil_div(-4097, 4096), -1);
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(Msf::open(b"").is_err());
        assert!(Msf::open(&[0u8; 100]).is_err());
        let mut hdr = BIG_MSF_HDR_MAGIC.to_vec();
        hdr.resize(4096, 0);
        assert!(Msf::open(&hdr).is_err());
    }
}
