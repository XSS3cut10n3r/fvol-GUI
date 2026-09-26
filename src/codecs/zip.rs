//! ZIP archive reader (central directory, zip64, stored / deflate / bzip2 / lzma).
//!
//! Mirrors python's `zipfile` (3.14) wherever the result is observable: the end record is
//! located the same way (last 22 bytes, else the last signature in the final 64 KiB), zip64
//! records are found through the locator (with the same fallback for prepended data), names
//! are UTF-8 when flag bit 11 is set and cp437 otherwise (invalid UTF-8 is an error), cut at
//! the first NUL, and replaced by a matching Info-ZIP Unicode Path extra field (0x7075); a
//! later duplicate name wins on lookup; data prepended to the archive (self-extractors) is
//! tolerated; a read checks the local header (signature, same name), rejects overlapping
//! entries, encrypted entries and unsupported methods, and verifies the CRC-32 of the data
//! (cut at the declared size, as python does). Malformed archives yield errors, never panics
//! or absurd allocations.
//!
//! ```ignore
//! let zip = ZipArchive::parse(&bytes)?;
//! let e = zip.find("windows/ntkrnlmp.pdb/GUID-1.json.xz").unwrap();
//! let data = zip.read(e)?;
//! ```

use super::crc::crc32;
use crate::error::{Error, Result};
use std::collections::HashMap;
use std::sync::OnceLock;

fn err(what: &str) -> Error {
    Error::Msg(format!("zip: {what}"))
}

pub const METHOD_STORED: u16 = 0;
pub const METHOD_DEFLATED: u16 = 8;
pub const METHOD_BZIP2: u16 = 12;
pub const METHOD_LZMA: u16 = 14;

const FLAG_ENCRYPTED: u16 = 1 << 0;
const FLAG_LZMA_EOS: u16 = 1 << 1;
const FLAG_COMPRESSED_PATCH: u16 = 1 << 5;
const FLAG_STRONG_ENCRYPTION: u16 = 1 << 6;
const FLAG_UTF8: u16 = 1 << 11;

/// python's `MAX_EXTRACT_VERSION`: newer "version needed to extract" values are refused.
const MAX_EXTRACT_VERSION: u8 = 63;

const SIG_LOCAL: [u8; 4] = *b"PK\x03\x04";
const SIG_CENTRAL: [u8; 4] = *b"PK\x01\x02";
const SIG_END: [u8; 4] = *b"PK\x05\x06";
const SIG_END64: [u8; 4] = *b"PK\x06\x06";
const SIG_END64_LOCATOR: [u8; 4] = *b"PK\x06\x07";

/// One central directory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZipEntry {
    /// Entry name as python's `ZipInfo.filename` (decoded, cut at the first NUL, or taken from
    /// the Unicode Path extra field).
    pub name: String,
    pub method: u16,
    pub flags: u16,
    pub crc32: u32,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    /// Offset of the local file header, adjusted for prepended data (`u64::MAX` when the
    /// directory points before the start of the file).
    pub header_offset: u64,
    /// DOS date and time fields (as stored).
    pub dos_date: u16,
    pub dos_time: u16,
    /// Local header offset as python computes it (may be negative for a corrupt directory).
    hdr: i128,
    /// Where the next local header (or the central directory) starts: python's `_end_offset`.
    end_offset: i128,
    /// The raw central directory name (start, length) in the archive bytes.
    raw_name: (usize, usize),
}

impl ZipEntry {
    /// python's `ZipInfo.is_dir()` (on POSIX): the name ends with '/'.
    pub fn is_dir(&self) -> bool {
        self.name.ends_with('/')
    }
}

/// A parsed archive borrowing the archive bytes (typically an mmap).
pub struct ZipArchive<'a> {
    data: &'a [u8],
    entries: Vec<ZipEntry>,
    comment: &'a [u8],
    index: OnceLock<HashMap<String, usize>>,
}

#[inline]
fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
#[inline]
fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
#[inline]
fn u64le(b: &[u8], o: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(v)
}

/// cp437 code points for bytes 0x80..=0xFF.
const CP437_HIGH: [char; 128] = [
    'Ç', 'ü', 'é', 'â', 'ä', 'à', 'å', 'ç', 'ê', 'ë', 'è', 'ï', 'î', 'ì', 'Ä', 'Å', 'É', 'æ', 'Æ', 'ô', 'ö', 'ò', 'û', 'ù',
    'ÿ', 'Ö', 'Ü', '¢', '£', '¥', '₧', 'ƒ', 'á', 'í', 'ó', 'ú', 'ñ', 'Ñ', 'ª', 'º', '¿', '⌐', '¬', '½', '¼', '¡', '«', '»',
    '░', '▒', '▓', '│', '┤', '╡', '╢', '╖', '╕', '╣', '║', '╗', '╝', '╜', '╛', '┐', '└', '┴', '┬', '├', '─', '┼', '╞', '╟',
    '╚', '╔', '╩', '╦', '╠', '═', '╬', '╧', '╨', '╤', '╥', '╙', '╘', '╒', '╓', '╫', '╪', '┘', '┌', '█', '▄', '▌', '▐', '▀',
    'α', 'ß', 'Γ', 'π', 'Σ', 'σ', 'µ', 'τ', 'Φ', 'Θ', 'Ω', 'δ', '∞', 'φ', 'ε', '∩', '≡', '±', '≥', '≤', '⌠', '⌡', '÷', '≈',
    '°', '∙', '·', '√', 'ⁿ', '²', '■', '\u{a0}',
];

/// Decodes a stored name like python: strict UTF-8 with flag bit 11, cp437 otherwise.
fn decode_name(raw: &[u8], utf8: bool) -> Result<String> {
    if utf8 || raw.is_ascii() {
        String::from_utf8(raw.to_vec()).map_err(|_| err("file name is not valid UTF-8"))
    } else {
        Ok(raw.iter().map(|&b| if b < 0x80 { b as char } else { CP437_HIGH[(b - 0x80) as usize] }).collect())
    }
}

/// python's `_sanitize_filename` on POSIX: cut at the first NUL.
fn sanitize(mut name: String) -> String {
    if let Some(n) = name.find('\0') {
        name.truncate(n);
    }
    name
}

/// Takes up to `n` bytes at `*p` (fewer at the end, like a short file read).
fn take<'b>(b: &'b [u8], p: &mut usize, n: usize) -> &'b [u8] {
    let start = (*p).min(b.len());
    let end = start.saturating_add(n).min(b.len());
    *p = end;
    &b[start..end]
}

/// End of central directory record, as python's `_EndRecData` returns it.
struct EndRecord<'a> {
    /// Archive position of the end record (of the zip64 record when there is one).
    location: u64,
    cd_size: u64,
    cd_offset: u64,
    comment: &'a [u8],
}

/// python's `_EndRecData` + `_EndRecData64`.
fn end_record(data: &[u8]) -> Result<EndRecord<'_>> {
    const MAX_COMMENT: usize = (1 << 16) - 1;
    let not_zip = || err("file is not a zip file");
    let n = data.len();
    if n < 22 {
        return Err(not_zip());
    }
    // No archive comment: the record is the last 22 bytes.
    let (at, comment) = if data[n - 22..n - 18] == SIG_END && data[n - 2..] == [0, 0] {
        (n - 22, &data[n..])
    } else {
        // Else the last signature in the final 64 KiB + 22 bytes, whatever its comment length.
        let lo = n.saturating_sub(MAX_COMMENT + 22);
        let tail = &data[lo..];
        let start = tail.windows(4).rposition(|w| w == SIG_END).ok_or_else(not_zip)?;
        if tail.len() - start < 22 {
            return Err(not_zip());
        }
        let clen = u16le(tail, start + 20) as usize;
        let c = &tail[start + 22..(start + 22 + clen).min(tail.len())];
        (lo + start, c)
    };
    let rec = &data[at..at + 22];
    let mut end = EndRecord {
        location: at as u64,
        cd_size: u32le(rec, 12) as u64,
        cd_offset: u32le(rec, 16) as u64,
        comment,
    };
    // zip64 end of central directory locator right before the end record.
    let Some(loc_at) = at.checked_sub(20) else { return Ok(end) };
    let loc = &data[loc_at..at];
    if loc[..4] != SIG_END64_LOCATOR {
        return Ok(end);
    }
    let (disk, reloff, disks) = (u32le(loc, 4), u64le(loc, 8), u32le(loc, 16));
    if disk != 0 || disks > 1 {
        return Err(err("zipfiles that span multiple disks are not supported"));
    }
    // The zip64 record normally sits right before the locator.
    let offset = loc_at as i128 - 56;
    if reloff as i128 > offset {
        return Err(err("corrupt zip64 end of central directory locator"));
    }
    // First assume no prepended data (the record at `reloff`, maybe followed by an extensible
    // data sector), else the record right before the locator.
    let (mut rec_at, mut extra) = (reloff as usize, offset - reloff as i128);
    if data[rec_at..rec_at + 4] != SIG_END64 && reloff as i128 != offset {
        rec_at = offset as usize;
        extra = 0;
    }
    let r = &data[rec_at..rec_at + 56];
    if r[..4] != SIG_END64 {
        return Err(err("zip64 end of central directory record not found"));
    }
    let (size, cd_size, cd_offset) = (u64le(r, 4), u64le(r, 40), u64le(r, 48));
    if cd_offset as u128 + cd_size as u128 != reloff as u128 || size as i128 + 12 != 56 + extra {
        return Err(err("corrupt zip64 end of central directory record"));
    }
    end.cd_size = cd_size;
    end.cd_offset = cd_offset;
    end.location = (offset - extra) as u64;
    Ok(end)
}

/// python's `ZipInfo._decodeExtra`: zip64 sizes / offset and the Unicode Path field.
fn decode_extra(
    mut x: &[u8],
    usize_: &mut u64,
    csize: &mut u64,
    offset: &mut u64,
    raw_name: &[u8],
    name: &mut String,
) -> Result<()> {
    while x.len() >= 4 {
        let (tp, ln) = (u16le(x, 0), u16le(x, 2) as usize);
        if ln + 4 > x.len() {
            return Err(err(&format!("corrupt extra field {tp:04x} (size={ln})")));
        }
        let d = &x[4..4 + ln];
        if tp == 0x0001 {
            let mut rest = d;
            let mut next = |what: &str| {
                if rest.len() < 8 {
                    return Err(err(&format!("corrupt zip64 extra field. {what} not found.")));
                }
                let v = u64le(rest, 0);
                rest = &rest[8..];
                Ok(v)
            };
            if *usize_ == u64::MAX || *usize_ == 0xFFFF_FFFF {
                *usize_ = next("File size")?;
            }
            if *csize == 0xFFFF_FFFF {
                *csize = next("Compress size")?;
            }
            if *offset == 0xFFFF_FFFF {
                *offset = next("Header offset")?;
            }
        } else if tp == 0x7075 {
            if d.len() < 5 {
                return Err(err("corrupt unicode path extra field (0x7075)"));
            }
            if d[0] == 1 && u32le(d, 1) == crc32(raw_name) {
                let s = std::str::from_utf8(&d[5..])
                    .map_err(|_| err("corrupt unicode path extra field (0x7075): invalid utf-8 bytes"))?;
                if !s.is_empty() {
                    *name = sanitize(s.to_string());
                }
            }
        }
        x = &x[4 + ln..];
    }
    Ok(())
}

impl<'a> ZipArchive<'a> {
    /// Parses the end-of-central-directory record(s) and the central directory
    /// (python's `ZipFile._RealGetContents`).
    pub fn parse(data: &'a [u8]) -> Result<ZipArchive<'a>> {
        let end = end_record(data)?;
        // "concat" is the size of data prepended to the archive (python's arithmetic, which
        // may go negative for a corrupt directory).
        let concat = end.location as i128 - end.cd_size as i128 - end.cd_offset as i128;
        let start_dir = end.cd_offset as i128 + concat;
        if start_dir < 0 {
            return Err(err("bad offset for central directory"));
        }
        // start_dir <= end.location <= data.len().
        let start = start_dir as usize;
        let cd_end = start.saturating_add(usize::try_from(end.cd_size).unwrap_or(usize::MAX)).min(data.len());
        let cd = &data[start..cd_end];
        let mut entries = Vec::with_capacity(cd.len() / 46);
        let mut total: u128 = 0;
        let mut p = 0usize;
        while total < end.cd_size as u128 {
            if cd.len() - p < 46 {
                return Err(err("truncated central directory"));
            }
            let h = &cd[p..p + 46];
            if h[..4] != SIG_CENTRAL {
                return Err(err("bad magic number for central directory"));
            }
            let flags = u16le(h, 8);
            let (nlen, xlen, clen) = (u16le(h, 28) as usize, u16le(h, 30) as usize, u16le(h, 32) as usize);
            p += 46;
            let name_at = start + p;
            let raw_name = take(cd, &mut p, nlen);
            let orig = decode_name(raw_name, flags & FLAG_UTF8 != 0)?;
            let mut name = sanitize(orig);
            let extra = take(cd, &mut p, xlen);
            take(cd, &mut p, clen);
            if h[6] > MAX_EXTRACT_VERSION {
                return Err(err(&format!("zip file version {:.1}", h[6] as f64 / 10.0)));
            }
            let mut csize = u32le(h, 20) as u64;
            let mut usize_ = u32le(h, 24) as u64;
            let mut offset = u32le(h, 42) as u64;
            decode_extra(extra, &mut usize_, &mut csize, &mut offset, raw_name, &mut name)?;
            let hdr = offset as i128 + concat;
            entries.push(ZipEntry {
                name,
                method: u16le(h, 10),
                flags,
                crc32: u32le(h, 16),
                compressed_size: csize,
                uncompressed_size: usize_,
                header_offset: u64::try_from(hdr).unwrap_or(u64::MAX),
                dos_date: u16le(h, 14),
                dos_time: u16le(h, 12),
                hdr,
                end_offset: 0,
                raw_name: (name_at, raw_name.len()),
            });
            total += (46 + nlen + xlen + clen) as u128;
        }
        // python's `_end_offset`: each entry ends where the next local header (in offset order,
        // stable for ties) or the central directory starts.
        let mut order: Vec<usize> = (0..entries.len()).collect();
        order.sort_by_key(|&i| entries[i].hdr);
        let mut end_offset = start_dir;
        for &i in order.iter().rev() {
            entries[i].end_offset = end_offset;
            end_offset = entries[i].hdr;
        }
        Ok(ZipArchive { data, entries, comment: end.comment, index: OnceLock::new() })
    }

    /// All entries in central directory order (python's `infolist()`).
    pub fn entries(&self) -> &[ZipEntry] {
        &self.entries
    }

    /// Entry names in central directory order (python's `namelist()`).
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|e| e.name.as_str())
    }

    /// The archive comment (python's `ZipFile.comment`).
    pub fn comment(&self) -> &'a [u8] {
        self.comment
    }

    /// Looks an entry up by exact name (python's `getinfo`: the last one wins for duplicates).
    pub fn find(&self, name: &str) -> Option<&ZipEntry> {
        let idx = self.index.get_or_init(|| {
            let mut m = HashMap::with_capacity(self.entries.len());
            for (i, e) in self.entries.iter().enumerate() {
                m.insert(e.name.clone(), i);
            }
            m
        });
        idx.get(name).map(|&i| &self.entries[i])
    }

    /// python's `ZipFile.open()` checks; returns the entry's compressed bytes that are present
    /// in the archive (at most `compressed_size`, fewer when the archive is truncated).
    fn open(&self, e: &ZipEntry) -> Result<&'a [u8]> {
        let d = self.data;
        let h = usize::try_from(e.hdr).map_err(|_| err("bad local header offset"))?;
        let lh = d.get(h..h.saturating_add(30)).ok_or_else(|| err("truncated file header"))?;
        if lh[..4] != SIG_LOCAL {
            return Err(err("bad magic number for file header"));
        }
        let (lflags, nlen, xlen) = (u16le(lh, 6), u16le(lh, 26) as usize, u16le(lh, 28) as usize);
        let fname = &d[h + 30..(h + 30 + nlen).min(d.len())];
        if e.flags & FLAG_COMPRESSED_PATCH != 0 {
            return Err(err("compressed patched data (flag bit 5) is not supported"));
        }
        if e.flags & FLAG_STRONG_ENCRYPTION != 0 {
            return Err(err("strong encryption (flag bit 6) is not supported"));
        }
        // The local name must decode (with the local flags) to the directory's original name.
        let (ns, nl) = e.raw_name;
        let cd_name = d.get(ns..ns.saturating_add(nl)).ok_or_else(|| err("entry not from this archive"))?;
        if fname != cd_name || (lflags ^ e.flags) & FLAG_UTF8 != 0 {
            let local = decode_name(fname, lflags & FLAG_UTF8 != 0)?;
            let orig = decode_name(cd_name, e.flags & FLAG_UTF8 != 0)?;
            if local != orig {
                return Err(err(&format!("file name in directory {orig:?} and header {local:?} differ")));
            }
        }
        let data_pos = h + 30 + fname.len() + xlen;
        if data_pos as i128 + e.compressed_size as i128 > e.end_offset && e.end_offset != e.hdr {
            return Err(err(&format!("overlapped entries: {:?} (possible zip bomb)", e.name)));
        }
        if e.flags & FLAG_ENCRYPTED != 0 {
            return Err(err(&format!("file {:?} is encrypted, password required for extraction", e.name)));
        }
        match e.method {
            METHOD_STORED | METHOD_DEFLATED | METHOD_BZIP2 | METHOD_LZMA => {}
            m => {
                let what = match m {
                    1 => " (shrink)",
                    2..=5 => " (reduce)",
                    6 => " (implode)",
                    9 => " (deflate64)",
                    10 => " (implode)",
                    18 => " (terse)",
                    19 => " (lz77)",
                    93 => " (zstd)",
                    97 => " (wavpack)",
                    98 => " (ppmd)",
                    _ => "",
                };
                return Err(err(&format!("compression type {m}{what} is not supported")));
            }
        }
        let start = data_pos.min(d.len());
        let stop = (data_pos as u128 + e.compressed_size as u128).min(d.len() as u128) as usize;
        Ok(&d[start..stop])
    }

    /// The entry's stored (possibly compressed) bytes, borrowed from the archive, after the
    /// same checks as [`ZipArchive::read`] minus decompression.
    pub fn raw_data(&self, e: &ZipEntry) -> Result<&'a [u8]> {
        let raw = self.open(e)?;
        if (raw.len() as u64) < e.compressed_size {
            return Err(err("truncated file data"));
        }
        Ok(raw)
    }

    /// Reads and decompresses an entry, verifying its CRC-32 (python's `ZipFile.read`).
    pub fn read(&self, e: &ZipEntry) -> Result<Vec<u8>> {
        let raw = self.open(e)?;
        // Output beyond the declared size is cut, as python does (never allocated up front:
        // the declared size is untrusted).
        let size = usize::try_from(e.uncompressed_size).unwrap_or(usize::MAX);
        let eof = || err(&format!("truncated data for file {:?}", e.name));
        let out = if e.compressed_size == 0 {
            Vec::new()
        } else if raw.is_empty() {
            return Err(eof());
        } else {
            match e.method {
                METHOD_STORED => {
                    if (raw.len() as u64) < e.compressed_size && (raw.len() as u64) < e.uncompressed_size {
                        return Err(eof());
                    }
                    raw[..raw.len().min(size)].to_vec()
                }
                METHOD_DEFLATED => {
                    // DEFLATE expands at most 1032:1.
                    let cap = size.min(raw.len().saturating_mul(1032)).saturating_add(1 << 10);
                    let mut out = Vec::new();
                    out.try_reserve(cap).map_err(|_| err("out of memory"))?;
                    super::inflate::inflate_into(raw, &mut out)?;
                    out.truncate(size);
                    out
                }
                METHOD_BZIP2 => {
                    let mut out = super::bzip2::decompress(raw)?;
                    out.truncate(size);
                    out
                }
                _ => {
                    // LZMA: 2 bytes version, 2 bytes properties size, properties, LZMA1 data.
                    if raw.len() < 4 {
                        return Err(err("truncated lzma header"));
                    }
                    let psize = u16le(raw, 2) as usize;
                    if psize != 5 || raw.len() < 4 + psize {
                        return Err(err("bad lzma properties"));
                    }
                    // Flag bit 1: the stream ends with an end marker. python decodes up to it
                    // whatever the declared size, so only an unterminated stream is bounded
                    // by that size.
                    let bound = if e.flags & FLAG_LZMA_EOS != 0 { None } else { Some(size as u64) };
                    let mut out = super::lzma::decompress_lzma1_raw(&raw[4 + psize..], raw[4], bound)?;
                    out.truncate(size);
                    out
                }
            }
        };
        if crc32(&out) != e.crc32 {
            return Err(err(&format!("bad CRC-32 for file {:?}", e.name)));
        }
        Ok(out)
    }

    /// Reads an entry by name.
    pub fn read_by_name(&self, name: &str) -> Result<Vec<u8>> {
        let e = self.find(name).ok_or_else(|| err(&format!("there is no item named {name:?} in the archive")))?;
        self.read(e)
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        let s: Vec<u8> = s.bytes().filter(|b| b.is_ascii_hexdigit()).collect();
        s.chunks(2).map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap()).collect()
    }

    /// What python's zipfile does with an archive: `namelist()`, the `infolist()` index
    /// `getinfo(name)` returns for each name, `comment`, and `read()` of every entry
    /// (length and CRC-32 of the data, or the exception type).
    struct Py {
        names: &'static [&'static str],
        find: &'static [usize],
        comment: &'static [u8],
        reads: &'static [std::result::Result<(usize, u32), &'static str>],
    }

    fn archive(key: &str) -> Vec<u8> {
        unhex(PYTHON.iter().find(|c| c.0 == key).unwrap().1)
    }

    // Archives made by Info-ZIP zip 3.0 (-X, -0 / -9 / -Z bzip2 / -P), 7-Zip (-tzip -mm=LZMA /
    // Deflate64) and python 3.14 zipfile (comments, names, duplicates, zip64 forced by lowering
    // ZIP64_LIMIT, data descriptors via an unseekable stream), plus hand-patched variants; the
    // expectations were recorded by running python's zipfile on each.
    const Z_STORED: &str = "\
        504b03040a0000000000aa816e572d3b08af0c0000000c0000000900000068656c6c6f2e74787468656c6c6f20776f726c64\
        0a504b03040a000000000091a4395d000000000000000000000000040000006469722f504b03040a000000000091a4395d00\
        00000000000000000000000a0000006469722f656d7074792f504b03040a0000000000aa816e57f8e1f8e6d6000000d60000\
        00090000006469722f612e747874766f6c6174696c6974792073796d626f6c207461626c653a206e746b726e6c6d702e7064\
        6220384533333733443631323445373437463045373245463845303245363736423320766f6c6174696c6974792073796d62\
        6f6c207461626c653a206e746b726e6c6d702e70646220384533333733443631323445373437463045373245463845303245\
        363736423320766f6c6174696c6974792073796d626f6c207461626c653a206e746b726e6c6d702e70646220384533333733\
        4436313234453734374630453732454638453032453637364233200a504b01021e030a0000000000aa816e572d3b08af0c00\
        00000c000000090000000000000000000000a4810000000068656c6c6f2e747874504b01021e030a000000000091a4395d00\
        0000000000000000000000040000000000000000001000ed41330000006469722f504b01021e030a000000000091a4395d00\
        00000000000000000000000a0000000000000000001000ed41550000006469722f656d7074792f504b01021e030a00000000\
        00aa816e57f8e1f8e6d6000000d6000000090000000000000000000000a4817d0000006469722f612e747874504b05060000\
        000004000400d80000007a0100000000";
    const Z_DEFLATED: &str = "\
        504b03040a0002000000aa816e572d3b08af0c0000000c0000000900000068656c6c6f2e74787468656c6c6f20776f726c64\
        0a504b0304140002000800aa816e57f8e1f8e64e000000d6000000090000006469722f612e7478742bcbcf492cc9ccc92ca9\
        5428aecc4dcacf5128494cca49b552c82bc92ecacbc92dd02b484952b0703536363776313334327135373177337035377275\
        b370353072353337733256281b54c6700100504b01021e030a0002000000aa816e572d3b08af0c0000000c00000009000000\
        0000000001000000a4810000000068656c6c6f2e747874504b01021e03140002000800aa816e57f8e1f8e64e000000d60000\
        00090000000000000001000000a481330000006469722f612e747874504b050600000000020002006e000000a80000000000";
    const Z_BZIP2: &str = "\
        504b03042e0000000c00aa816e57f8e1f8e67f000000d6000000090000006469722f612e747874425a683631415926535986\
        2f9569000067dd80001040017dd01700362fdd20200060aff5529b4d4d3d04d321a34c218c001300013233f0b9cb44a1f993\
        3775ebd8b24d62a8316692a45245632518bda49bcc145cb1d1451c3168d1ab3495a28b68346ad9f136ef49b95addc2b83051\
        6aa8718397f177245385090862f95690504b01021e032e0000000c00aa816e57f8e1f8e67f000000d6000000090000000000\
        000000000000a481000000006469722f612e747874504b0506000000000100010037000000a60000000000";
    const Z_LZMA: &str = "\
        504b03043f0002000e00aa896e57f8e1f8e65d000000d6000000090000006469722f612e7478741a0205005d00100000003b\
        1bc9cd48ee12c00ad503033438b8a942d4dde9c90bfff674d6c93c043932bfc7f4b46226fee12e65b126356dedbe3b3cbf12\
        49777a44ad11a826aec73840d25167309945622c74db04b706a0ffffd96f2000504b01023f033f0002000e00aa896e57f8e1\
        f8e65d000000d6000000090024000000000000002080a481000000006469722f612e7478740a002000000000000100180000\
        006dc64717da0100000000000000000000000000000000504b050600000000010001005b000000840000000000";
    const Z_DEFLATE64: &str = "\
        504b0304150000000900aa896e57f8e1f8e650000000d6000000090000006469722f612e747874cdcccb0d80200c00d0bb53\
        7402834028f1682c7b40f4402c9f6863c2f6aee11be0bd8da364ce32e0192535068989cf15aa5c77e5d2e77e24f0640c9add\
        2dda125a0c8a5053f0a43439749b817f35d307504b01023f03150000000900aa896e57f8e1f8e650000000d6000000090024\
        000000000000002080a481000000006469722f612e7478740a002000000000000100180000006dc64717da01000000000000\
        00000000000000000000504b050600000000010001005b000000770000000000";
    const Z_ENCRYPTED: &str = "\
        504b03040a0009000000aa816e572d3b08af180000000c0000000900000068656c6c6f2e74787491ee0337fd4e13f708493a\
        07d948c705e5e78f8012abe071504b07082d3b08af180000000c000000504b01021e030a0009000000aa816e572d3b08af18\
        0000000c000000090000000000000001000000a4810000000068656c6c6f2e747874504b0506000000000100010037000000\
        4f0000000000";
    const Z_PY_LZMA_BZ2: &str = "\
        504b03043f0002000e0083182258f8e1f8e65d000000d600000005000000612e747874090405005d00008000003b1bc9cd48\
        ee12c00ad503033438b8a942d4dde9c90bfff674d6c93c043932bfc7f4b46226fee12e65b126356dedbe3b3cbf1249777a44\
        ad11a826aec73840d25167309945622c74db04b706a0ffffd96f2000504b03042e0000000c0083182258f8e1f8e67f000000\
        d600000005000000622e747874425a6839314159265359862f9569000067dd80001040017dd01700362fdd20200060aff552\
        9b4d4d3d04d321a34c218c001300013233f0b9cb44a1f9933775ebd8b24d62a8316692a45245632518bda49bcc145cb1d145\
        1c3168d1ab3495a28b68346ad9f136ef49b95addc2b830516aa8718397f177245385090862f95690504b01023f033f000200\
        0e0083182258f8e1f8e65d000000d6000000050000000000000000000000a40100000000612e747874504b01022e032e0000\
        000c0083182258f8e1f8e67f000000d6000000050000000000000000000000a40180000000622e747874504b050600000000\
        0200020066000000220100000000";
    const Z_NAMES: &str = "\
        504b0304140000000000831822588d41c6ef060000000600000008000000636166822e74787463703433370a504b03041400\
        00080000831822581e4d5da805000000050000000e000000e697a5e69cac2fe8aa9e2e747874757466380a504b0304140000\
        00000083182258000000000000000000000000040000006469722f504b030414000000080083182258f8e1f8e64e000000d6\
        00000009000000706c61696e2e7478742bcbcf492cc9ccc92ca95428aecc4dcacf5128494cca49b552c82bc92ecacbc92dd0\
        2b484952b0703536363776313334327135373177337035377275b370353072353337733256281b54c6700100504b01021403\
        140000000000831822588d41c6ef0600000006000000080000000000000000000000a40100000000636166822e747874504b\
        01021403140000080000831822581e4d5da805000000050000000e0000000000000000000000a4012c000000e697a5e69cac\
        2fe8aa9e2e747874504b0102140314000000000083182258000000000000000000000000040000000000000000000000a401\
        5d0000006469722f504b0102140314000000080083182258f8e1f8e64e000000d6000000090000000000000000000000a401\
        7f000000706c61696e2e747874504b05060000000004000400db000000f40000000000";
    const Z_COMMENT: &str = "\
        504b0304140000000000831822582d3b08af0c0000000c000000010000007868656c6c6f20776f726c640a504b0102140314\
        0000000000831822582d3b08af0c0000000c000000010000000000000000000000a4010000000078504b0506000000000100\
        01002f0000002b00000023006172636869766520636f6d6d656e7420504b05206e6f742061207369676e6174757265";
    const Z_DUPLICATES: &str = "\
        504b0304140000000000831822582ab34ac70600000006000000070000006475702e74787466697273740a504b0304140000\
        000000831822586e7e60090600000006000000090000006f746865722e7478746f746865720a504b03041400000000008318\
        22587ec00f060700000007000000070000006475702e7478747365636f6e640a504b01021403140000000000831822582ab3\
        4ac70600000006000000070000000000000000000000a401000000006475702e747874504b01021403140000000000831822\
        586e7e60090600000006000000090000000000000000000000a4012b0000006f746865722e747874504b0102140314000000\
        0000831822587ec00f060700000007000000070000000000000000000000a401580000006475702e747874504b0506000000\
        0003000300a1000000840000000000";
    const Z_EMPTY: &str = "\
        504b0506000000000000000000000000000000000000";
    const Z_ZIP64: &str = "\
        504b03042d000000000083182258f8e1f8e6ffffffffffffffff070014006269672e62696e01001000d600000000000000d6\
        00000000000000766f6c6174696c6974792073796d626f6c207461626c653a206e746b726e6c6d702e706462203845333337\
        33443631323445373437463045373245463845303245363736423320766f6c6174696c6974792073796d626f6c207461626c\
        653a206e746b726e6c6d702e7064622038453333373344363132344537343746304537324546384530324536373642332076\
        6f6c6174696c6974792073796d626f6c207461626c653a206e746b726e6c6d702e7064622038453333373344363132344537\
        34374630453732454638453032453637364233200a504b03042d000000080083182258f8e1f8e6ffffffffffffffff080014\
        00626967322e62696e01001000d6000000000000004e000000000000002bcbcf492cc9ccc92ca95428aecc4dcacf5128494c\
        ca49b552c82bc92ecacbc92dd02b484952b0703536363776313334327135373177337035377275b370353072353337733256\
        281b54c6700100504b01022d032d000000000083182258f8e1f8e6ffffffffffffffff070014000000000000000000a40100\
        0000006269672e62696e01001000d600000000000000d600000000000000504b01022d032d000000080083182258f8e1f8e6\
        ffffffffffffffff08001c000000000000000000a401ffffffff626967322e62696e01001800d6000000000000004e000000\
        000000000f01000000000000504b06062c000000000000002d002d0000000000000000000200000000000000020000000000\
        00009b000000000000009701000000000000504b060700000000320200000000000001000000504b05060000000002000200\
        9b000000970100000000";
    const Z_SFX: &str = "\
        4d5a90002073656c662d657874726163746f72207374756220000102030405060708090a0b0c0d0e0f101112131415161718\
        191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f504b03040a0002000000aa\
        816e572d3b08af0c0000000c0000000900000068656c6c6f2e74787468656c6c6f20776f726c640a504b0304140002000800\
        aa816e57f8e1f8e64e000000d6000000090000006469722f612e7478742bcbcf492cc9ccc92ca95428aecc4dcacf5128494c\
        ca49b552c82bc92ecacbc92dd02b484952b0703536363776313334327135373177337035377275b370353072353337733256\
        281b54c6700100504b01021e030a0002000000aa816e572d3b08af0c0000000c000000090000000000000001000000a48100\
        00000068656c6c6f2e747874504b01021e03140002000800aa816e57f8e1f8e64e000000d600000009000000000000000100\
        0000a481330000006469722f612e747874504b050600000000020002006e000000a80000000000";
    const Z_ZIP64_SFX: &str = "\
        4d5a90002073656c662d657874726163746f72207374756220000102030405060708090a0b0c0d0e0f101112131415161718\
        191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f504b03042d000000000083\
        182258f8e1f8e6ffffffffffffffff070014006269672e62696e01001000d600000000000000d600000000000000766f6c61\
        74696c6974792073796d626f6c207461626c653a206e746b726e6c6d702e7064622038453333373344363132344537343746\
        3045373245463845303245363736423320766f6c6174696c6974792073796d626f6c207461626c653a206e746b726e6c6d70\
        2e70646220384533333733443631323445373437463045373245463845303245363736423320766f6c6174696c6974792073\
        796d626f6c207461626c653a206e746b726e6c6d702e70646220384533333733443631323445373437463045373245463845\
        3032453637364233200a504b03042d000000080083182258f8e1f8e6ffffffffffffffff08001400626967322e62696e0100\
        1000d6000000000000004e000000000000002bcbcf492cc9ccc92ca95428aecc4dcacf5128494cca49b552c82bc92ecacbc9\
        2dd02b484952b0703536363776313334327135373177337035377275b370353072353337733256281b54c6700100504b0102\
        2d032d000000000083182258f8e1f8e6ffffffffffffffff070014000000000000000000a401000000006269672e62696e01\
        001000d600000000000000d600000000000000504b01022d032d000000080083182258f8e1f8e6ffffffffffffffff08001c\
        000000000000000000a401ffffffff626967322e62696e01001800d6000000000000004e000000000000000f010000000000\
        00504b06062c000000000000002d002d000000000000000000020000000000000002000000000000009b0000000000000097\
        01000000000000504b060700000000320200000000000001000000504b050600000000020002009b000000970100000000";
    const Z_DESCRIPTOR: &str = "\
        504b0304140008000800000021000000000000000000000000000a00000073747265616d2e7478742bcbcf492cc9ccc92ca9\
        5428aecc4dcacf5128494cca49b552c82bc92ecacbc92dd02b484952b0703536363776313334327135373177337035377275\
        b370353072353337733256281b54c6700100504b0708f8e1f8e64e000000d6000000504b0102140314000800080000002100\
        f8e1f8e64e000000d60000000a000000000000000000000080010000000073747265616d2e747874504b0506000000000100\
        010038000000860000000000";
    const Z_BAD_CRC: &str = "\
        504b03040a0000000000aa816e572d3b08af0c0000000c0000000900000068656c6c6f2e74787468656c6c6f20776f726c64\
        0a504b03040a000000000091a4395d000000000000000000000000040000006469722f504b03040a000000000091a4395d00\
        00000000000000000000000a0000006469722f656d7074792f504b03040a0000000000aa816e57f8e1f8e6d6000000d60000\
        00090000006469722f612e747874766f6c6174696c6974792073796d626f6c207461626c653a206e746b726e6c6d702e7064\
        6220384533333733443631323445373437463045373245463845303245363736423320766f6c6174696c6974792073796d62\
        6f6c207461626c653a206e746b726e6c6d702e70646220384533333733443631323445373437463045373245463845303245\
        363736423320766f6c6174696c6974792073796d626f6c207461626c653a206e746b726e6c6d702e70646220384533333733\
        4436313234453734374630453732454638453032453637364233200a504b01021e030a0000000000aa816e572c3b08af0c00\
        00000c000000090000000000000000000000a4810000000068656c6c6f2e747874504b01021e030a000000000091a4395d00\
        0000000000000000000000040000000000000000001000ed41330000006469722f504b01021e030a000000000091a4395d00\
        00000000000000000000000a0000000000000000001000ed41550000006469722f656d7074792f504b01021e030a00000000\
        00aa816e57f8e1f8e6d6000000d6000000090000000000000000000000a4817d0000006469722f612e747874504b05060000\
        000004000400d80000007a0100000000";
    const Z_NAME_MISMATCH: &str = "\
        504b03040a0000000000aa816e572d3b08af0c0000000c0000000900000058656c6c6f2e74787468656c6c6f20776f726c64\
        0a504b03040a000000000091a4395d000000000000000000000000040000006469722f504b03040a000000000091a4395d00\
        00000000000000000000000a0000006469722f656d7074792f504b03040a0000000000aa816e57f8e1f8e6d6000000d60000\
        00090000006469722f612e747874766f6c6174696c6974792073796d626f6c207461626c653a206e746b726e6c6d702e7064\
        6220384533333733443631323445373437463045373245463845303245363736423320766f6c6174696c6974792073796d62\
        6f6c207461626c653a206e746b726e6c6d702e70646220384533333733443631323445373437463045373245463845303245\
        363736423320766f6c6174696c6974792073796d626f6c207461626c653a206e746b726e6c6d702e70646220384533333733\
        4436313234453734374630453732454638453032453637364233200a504b01021e030a0000000000aa816e572d3b08af0c00\
        00000c000000090000000000000000000000a4810000000068656c6c6f2e747874504b01021e030a000000000091a4395d00\
        0000000000000000000000040000000000000000001000ed41330000006469722f504b01021e030a000000000091a4395d00\
        00000000000000000000000a0000000000000000001000ed41550000006469722f656d7074792f504b01021e030a00000000\
        00aa816e57f8e1f8e6d6000000d6000000090000000000000000000000a4817d0000006469722f612e747874504b05060000\
        000004000400d80000007a0100000000";
    const Z_BAD_LOCAL_SIG: &str = "\
        504b03050a0000000000aa816e572d3b08af0c0000000c0000000900000068656c6c6f2e74787468656c6c6f20776f726c64\
        0a504b03040a000000000091a4395d000000000000000000000000040000006469722f504b03040a000000000091a4395d00\
        00000000000000000000000a0000006469722f656d7074792f504b03040a0000000000aa816e57f8e1f8e6d6000000d60000\
        00090000006469722f612e747874766f6c6174696c6974792073796d626f6c207461626c653a206e746b726e6c6d702e7064\
        6220384533333733443631323445373437463045373245463845303245363736423320766f6c6174696c6974792073796d62\
        6f6c207461626c653a206e746b726e6c6d702e70646220384533333733443631323445373437463045373245463845303245\
        363736423320766f6c6174696c6974792073796d626f6c207461626c653a206e746b726e6c6d702e70646220384533333733\
        4436313234453734374630453732454638453032453637364233200a504b01021e030a0000000000aa816e572d3b08af0c00\
        00000c000000090000000000000000000000a4810000000068656c6c6f2e747874504b01021e030a000000000091a4395d00\
        0000000000000000000000040000000000000000001000ed41330000006469722f504b01021e030a000000000091a4395d00\
        00000000000000000000000a0000000000000000001000ed41550000006469722f656d7074792f504b01021e030a00000000\
        00aa816e57f8e1f8e6d6000000d6000000090000000000000000000000a4817d0000006469722f612e747874504b05060000\
        000004000400d80000007a0100000000";
    const Z_BAD_VERSION: &str = "\
        504b03040a0000000000aa816e572d3b08af0c0000000c0000000900000068656c6c6f2e74787468656c6c6f20776f726c64\
        0a504b03040a000000000091a4395d000000000000000000000000040000006469722f504b03040a000000000091a4395d00\
        00000000000000000000000a0000006469722f656d7074792f504b03040a0000000000aa816e57f8e1f8e6d6000000d60000\
        00090000006469722f612e747874766f6c6174696c6974792073796d626f6c207461626c653a206e746b726e6c6d702e7064\
        6220384533333733443631323445373437463045373245463845303245363736423320766f6c6174696c6974792073796d62\
        6f6c207461626c653a206e746b726e6c6d702e70646220384533333733443631323445373437463045373245463845303245\
        363736423320766f6c6174696c6974792073796d626f6c207461626c653a206e746b726e6c6d702e70646220384533333733\
        4436313234453734374630453732454638453032453637364233200a504b01021e03400000000000aa816e572d3b08af0c00\
        00000c000000090000000000000000000000a4810000000068656c6c6f2e747874504b01021e030a000000000091a4395d00\
        0000000000000000000000040000000000000000001000ed41330000006469722f504b01021e030a000000000091a4395d00\
        00000000000000000000000a0000000000000000001000ed41550000006469722f656d7074792f504b01021e030a00000000\
        00aa816e57f8e1f8e6d6000000d6000000090000000000000000000000a4817d0000006469722f612e747874504b05060000\
        000004000400d80000007a0100000000";
    const Z_BAD_UTF8: &str = "\
        504b0304140000000000831822588d41c6ef060000000600000008000000636166822e74787463703433370a504b03041400\
        00080000831822581e4d5da805000000050000000e000000e697a5e69cac2fe8aa9e2e747874757466380a504b0304140000\
        00000083182258000000000000000000000000040000006469722f504b030414000000080083182258f8e1f8e64e000000d6\
        00000009000000706c61696e2e7478742bcbcf492cc9ccc92ca95428aecc4dcacf5128494cca49b552c82bc92ecacbc92dd0\
        2b484952b0703536363776313334327135373177337035377275b370353072353337733256281b54c6700100504b01021403\
        140000000000831822588d41c6ef0600000006000000080000000000000000000000a40100000000636166822e747874504b\
        01021403140000080000831822581e4d5da805000000050000000e0000000000000000000000a4012c000000ff97a5e69cac\
        2fe8aa9e2e747874504b0102140314000000000083182258000000000000000000000000040000000000000000000000a401\
        5d0000006469722f504b0102140314000000080083182258f8e1f8e64e000000d6000000090000000000000000000000a401\
        7f000000706c61696e2e747874504b05060000000004000400db000000f40000000000";
    const Z_NUL_NAME: &str = "\
        504b0304140000000000831822582d3b08af0c0000000c000000070000006100622e74787468656c6c6f20776f726c640a50\
        4b01021403140000000000831822582d3b08af0c0000000c000000070000000000000000000000a401000000006100622e74\
        7874504b0506000000000100010035000000310000000000";
    const Z_HUGE_DEFLATE: &str = "\
        504b03040a0002000000aa816e572d3b08af0c0000000c0000000900000068656c6c6f2e74787468656c6c6f20776f726c64\
        0a504b0304140002000800aa816e57f8e1f8e64e000000d6000000090000006469722f612e7478742bcbcf492cc9ccc92ca9\
        5428aecc4dcacf5128494cca49b552c82bc92ecacbc92dd02b484952b0703536363776313334327135373177337035377275\
        b370353072353337733256281b54c6700100504b01021e030a0002000000aa816e572d3b08af0c0000000c00000009000000\
        0000000001000000a4810000000068656c6c6f2e747874504b01021e03140002000800aa816e57f8e1f8e64e000000feffff\
        ff090000000000000001000000a481330000006469722f612e747874504b050600000000020002006e000000a80000000000";
    const Z_HUGE_ZIP64: &str = "\
        504b03042d000000000083182258f8e1f8e6ffffffffffffffff070014006269672e62696e01001000d600000000000000d6\
        00000000000000766f6c6174696c6974792073796d626f6c207461626c653a206e746b726e6c6d702e706462203845333337\
        33443631323445373437463045373245463845303245363736423320766f6c6174696c6974792073796d626f6c207461626c\
        653a206e746b726e6c6d702e7064622038453333373344363132344537343746304537324546384530324536373642332076\
        6f6c6174696c6974792073796d626f6c207461626c653a206e746b726e6c6d702e7064622038453333373344363132344537\
        34374630453732454638453032453637364233200a504b03042d000000080083182258f8e1f8e6ffffffffffffffff080014\
        00626967322e62696e01001000d6000000000000004e000000000000002bcbcf492cc9ccc92ca95428aecc4dcacf5128494c\
        ca49b552c82bc92ecacbc92dd02b484952b0703536363776313334327135373177337035377275b370353072353337733256\
        281b54c6700100504b01022d032d000000000083182258f8e1f8e6ffffffffffffffff070014000000000000000000a40100\
        0000006269672e62696e010010000000000000000040d600000000000000504b01022d032d000000080083182258f8e1f8e6\
        ffffffffffffffff08001c000000000000000000a401ffffffff626967322e62696e01001800d6000000000000004e000000\
        000000000f01000000000000504b06062c000000000000002d002d0000000000000000000200000000000000020000000000\
        00009b000000000000009701000000000000504b060700000000320200000000000001000000504b05060000000002000200\
        9b000000970100000000";
    const Z_HUGE_LZMA: &str = "\
        504b03043f0002000e00aa896e57f8e1f8e65d000000d6000000090000006469722f612e7478741a0205005d00100000003b\
        1bc9cd48ee12c00ad503033438b8a942d4dde9c90bfff674d6c93c043932bfc7f4b46226fee12e65b126356dedbe3b3cbf12\
        49777a44ad11a826aec73840d25167309945622c74db04b706a0ffffd96f2000504b01023f033f0002000e00aa896e57f8e1\
        f8e65d000000f0ffffff090024000000000000002080a481000000006469722f612e7478740a002000000000000100180000\
        006dc64717da0100000000000000000000000000000000504b050600000000010001005b000000840000000000";
    const Z_OVERLAP: &str = "\
        504b03041400000000008318225864002f492800000028000000030000006f6e653131313131313131313131313131313131\
        3131313131313131313131313131313131313131313131504b0304140000000000831822581bca6ff3280000002800000003\
        00000074776f32323232323232323232323232323232323232323232323232323232323232323232323232323232504b0102\
        14031400000000008318225864002f493c00000028000000030000000000000000000000a401000000006f6e65504b010214\
        03140000000000831822581bca6ff32800000028000000030000000000000000000000a4014900000074776f504b05060000\
        00000200020062000000920000000000";
    const Z_SHARED_HEADER: &str = "\
        504b03041400000000008318225864002f492800000028000000030000006f6e653131313131313131313131313131313131\
        3131313131313131313131313131313131313131313131504b0304140000000000831822581bca6ff3280000002800000003\
        00000074776f32323232323232323232323232323232323232323232323232323232323232323232323232323232504b0102\
        14031400000000008318225864002f492800000028000000030000000000000000000000a401000000006f6e65504b010214\
        031400000000008318225864002f492800000028000000030000000000000000000000a401000000006f6e65504b05060000\
        00000200020062000000920000000000";
    const Z_UNICODE_PATH: &str = "\
        504b030414000000000083182258191f9d150d0000000d00000008001500636166822e74787475701100018f6e97a072c3a9\
        73756dc3a92e747874756e69636f646520706174680a504b0102140314000000000083182258191f9d150d0000000d000000\
        080015000000000000000000a40100000000636166822e74787475701100018f6e97a072c3a973756dc3a92e747874504b05\
        0600000000010001004b000000480000000000";
    const Z_UNICODE_PATH_STALE: &str = "\
        504b030414000000000083182258191f9d150d0000000d00000008001500636166822e74787475701100018e6e97a072c3a9\
        73756dc3a92e747874756e69636f646520706174680a504b0102140314000000000083182258191f9d150d0000000d000000\
        080015000000000000000000a40100000000636166822e74787475701100018e6e97a072c3a973756dc3a92e747874504b05\
        0600000000010001004b000000480000000000";
    const Z_COMMENT_LEN_TOO_BIG: &str = "\
        504b0304140000000000831822582d3b08af0c0000000c000000010000007868656c6c6f20776f726c640a504b0102140314\
        0000000000831822582d3b08af0c0000000c000000010000000000000000000000a4010000000078504b0506000000000100\
        01002f0000002b000000f4016172636869766520636f6d6d656e7420504b05206e6f742061207369676e6174757265";
    const Z_SIG_IN_COMMENT_END: &str = "\
        504b0304140000000000831822582d3b08af0c0000000c000000010000007868656c6c6f20776f726c640a504b0102140314\
        0000000000831822582d3b08af0c0000000c000000010000000000000000000000a4010000000078504b0506000000000100\
        01002f0000002b0000000700787820504b0506";
    const Z_PACK: &str = "\
        504b0304140000000800831822583bcf63c727000000660000003f00000077696e646f77732f6e746b726e6c6d702e706462\
        2f38453333373344363132344537343746304537324546384530324536373642332d312e6a736f6e2e787ab3703536363776\
        313334327135373177337035377275b3703530723533377332d635b4a0820a00504b030414000000080083182258b0fa6e41\
        27000000660000003f00000077696e646f77732f6e746b726e6c6d702e7064622f3242324131354641314645323132324242\
        3141333945443335373237343144322d312e6a736f6e2e787a3372327234347573347473353234327272327434b674753136\
        35373237317431d23534a2820a00504b030414000000000083182258000000000000000000000000060000006c696e75782f\
        504b01021403140000000800831822583bcf63c727000000660000003f0000000000000000000000a4010000000077696e64\
        6f77732f6e746b726e6c6d702e7064622f38453333373344363132344537343746304537324546384530324536373642332d\
        312e6a736f6e2e787a504b0102140314000000080083182258b0fa6e4127000000660000003f0000000000000000000000a4\
        018400000077696e646f77732f6e746b726e6c6d702e7064622f324232413135464131464532313232424231413339454433\
        35373237343144322d312e6a736f6e2e787a504b010214031400000000008318225800000000000000000000000006000000\
        0000000000000000a401080100006c696e75782f504b050600000000030003000e0100002c0100000000";
    const Z_BAD_EXTRA: &str = "\
        504b0304140000000000831822582d3b08af0c0000000c00000005000600652e74787499991000616268656c6c6f20776f72\
        6c640a504b01021403140000000000831822582d3b08af0c0000000c000000050006000000000000000000a4010000000065\
        2e747874999910006162504b0506000000000100010039000000350000000000";
    const Z_ZIP64_SHORT: &str = "\
        504b03042d000000000083182258f8e1f8e6ffffffffffffffff070014006269672e62696e01001000d600000000000000d6\
        00000000000000766f6c6174696c6974792073796d626f6c207461626c653a206e746b726e6c6d702e706462203845333337\
        33443631323445373437463045373245463845303245363736423320766f6c6174696c6974792073796d626f6c207461626c\
        653a206e746b726e6c6d702e7064622038453333373344363132344537343746304537324546384530324536373642332076\
        6f6c6174696c6974792073796d626f6c207461626c653a206e746b726e6c6d702e7064622038453333373344363132344537\
        34374630453732454638453032453637364233200a504b03042d000000080083182258f8e1f8e6ffffffffffffffff080014\
        00626967322e62696e01001000d6000000000000004e000000000000002bcbcf492cc9ccc92ca95428aecc4dcacf5128494c\
        ca49b552c82bc92ecacbc92dd02b484952b0703536363776313334327135373177337035377275b370353072353337733256\
        281b54c6700100504b01022d032d000000000083182258f8e1f8e6ffffffffffffffff070014000000000000000000a40100\
        0000006269672e62696e01000400d600000000000000d600000000000000504b01022d032d000000080083182258f8e1f8e6\
        ffffffffffffffff08001c000000000000000000a401ffffffff626967322e62696e01001800d6000000000000004e000000\
        000000000f01000000000000504b06062c000000000000002d002d0000000000000000000200000000000000020000000000\
        00009b000000000000009701000000000000504b060700000000320200000000000001000000504b05060000000002000200\
        9b000000970100000000";
    const Z_CORRUPT_DEFLATE: &str = "\
        504b03040a0002000000aa816e572d3b08af0c0000000c0000000900000068656c6c6f2e74787468656c6c6f20776f726c64\
        0a504b0304140002000800aa816e57f8e1f8e64e000000d6000000090000006469722f612e7478742bcbcf492c9cccc92ca9\
        5428aecc4dcacf5128494cca49b552c82bc92ecacbc92dd02b484952b0703536363776313334327135373177337035377275\
        b370353072353337733256281b54c6700100504b01021e030a0002000000aa816e572d3b08af0c0000000c00000009000000\
        0000000001000000a4810000000068656c6c6f2e747874504b01021e03140002000800aa816e57f8e1f8e64e000000d60000\
        00090000000000000001000000a481330000006469722f612e747874504b050600000000020002006e000000a80000000000";
    const Z_STORED_SHORT_SIZE: &str = "\
        504b03040a0000000000aa816e572d3b08af0c0000000c0000000900000068656c6c6f2e74787468656c6c6f20776f726c64\
        0a504b03040a000000000091a4395d000000000000000000000000040000006469722f504b03040a000000000091a4395d00\
        00000000000000000000000a0000006469722f656d7074792f504b03040a0000000000aa816e57f8e1f8e6d6000000d60000\
        00090000006469722f612e747874766f6c6174696c6974792073796d626f6c207461626c653a206e746b726e6c6d702e7064\
        6220384533333733443631323445373437463045373245463845303245363736423320766f6c6174696c6974792073796d62\
        6f6c207461626c653a206e746b726e6c6d702e70646220384533333733443631323445373437463045373245463845303245\
        363736423320766f6c6174696c6974792073796d626f6c207461626c653a206e746b726e6c6d702e70646220384533333733\
        4436313234453734374630453732454638453032453637364233200a504b01021e030a0000000000aa816e5786a610360c00\
        000005000000090000000000000000000000a4810000000068656c6c6f2e747874504b01021e030a000000000091a4395d00\
        0000000000000000000000040000000000000000001000ed41330000006469722f504b01021e030a000000000091a4395d00\
        00000000000000000000000a0000000000000000001000ed41550000006469722f656d7074792f504b01021e030a00000000\
        00aa816e57f8e1f8e6d6000000d6000000090000000000000000000000a4817d0000006469722f612e747874504b05060000\
        000004000400d80000007a0100000000";
    const Z_TRUNCATED: &str = "\
        504b03040a0002000000aa816e572d3b08af0c0000000c0000000900000068656c6c6f2e74787468656c6c6f20776f726c64\
        0a504b0304140002000800aa816e57f8e1f8e64e000000d6000000090000006469722f612e7478742bcbcf492cc9ccc92ca9\
        5428aecc4dcacf5128494cca49b552c82bc92ecacbc92dd02b484952b0703536363776313334327135373177337035377275\
        b370353072353337733256281b54c6700100504b01021e030a0002000000aa816e572d3b08af0c0000000c00000009000000\
        0000000001000000a4810000000068656c6c6f2e747874504b01021e03140002000800aa816e57f8e1f8e64e000000d60000\
        00090000000000000001000000a4813300000064";
    const Z_GARBAGE: &str = "\
        504b0304000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d\
        2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f\
        606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f9091\
        92939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3\
        c4c5c6c7";
    /// python 3.14 zipfile behaviour on each archive (None: ZipFile() raises).
    const PYTHON: &[(&str, &str, Option<Py>)] = &[
        ("STORED", Z_STORED, Some(Py { names: &["hello.txt", "dir/", "dir/empty/", "dir/a.txt"], find: &[0, 1, 2, 3], comment: &[], reads: &[Ok((12, 0xaf083b2d)), Ok((0, 0x00000000)), Ok((0, 0x00000000)), Ok((214, 0xe6f8e1f8))] })),
        ("DEFLATED", Z_DEFLATED, Some(Py { names: &["hello.txt", "dir/a.txt"], find: &[0, 1], comment: &[], reads: &[Ok((12, 0xaf083b2d)), Ok((214, 0xe6f8e1f8))] })),
        ("BZIP2", Z_BZIP2, Some(Py { names: &["dir/a.txt"], find: &[0], comment: &[], reads: &[Ok((214, 0xe6f8e1f8))] })),
        ("LZMA", Z_LZMA, Some(Py { names: &["dir/a.txt"], find: &[0], comment: &[], reads: &[Ok((214, 0xe6f8e1f8))] })),
        ("DEFLATE64", Z_DEFLATE64, Some(Py { names: &["dir/a.txt"], find: &[0], comment: &[], reads: &[Err("NotImplementedError")] })),
        ("ENCRYPTED", Z_ENCRYPTED, Some(Py { names: &["hello.txt"], find: &[0], comment: &[], reads: &[Err("RuntimeError")] })),
        ("PY_LZMA_BZ2", Z_PY_LZMA_BZ2, Some(Py { names: &["a.txt", "b.txt"], find: &[0, 1], comment: &[], reads: &[Ok((214, 0xe6f8e1f8)), Ok((214, 0xe6f8e1f8))] })),
        ("NAMES", Z_NAMES, Some(Py { names: &["café.txt", "日本/語.txt", "dir/", "plain.txt"], find: &[0, 1, 2, 3], comment: &[], reads: &[Ok((6, 0xefc6418d)), Ok((5, 0xa85d4d1e)), Ok((0, 0x00000000)), Ok((214, 0xe6f8e1f8))] })),
        ("COMMENT", Z_COMMENT, Some(Py { names: &["x"], find: &[0], comment: &[97, 114, 99, 104, 105, 118, 101, 32, 99, 111, 109, 109, 101, 110, 116, 32, 80, 75, 5, 32, 110, 111, 116, 32, 97, 32, 115, 105, 103, 110, 97, 116, 117, 114, 101], reads: &[Ok((12, 0xaf083b2d))] })),
        ("DUPLICATES", Z_DUPLICATES, Some(Py { names: &["dup.txt", "other.txt", "dup.txt"], find: &[2, 1, 2], comment: &[], reads: &[Ok((6, 0xc74ab32a)), Ok((6, 0x09607e6e)), Ok((7, 0x060fc07e))] })),
        ("EMPTY", Z_EMPTY, Some(Py { names: &[], find: &[], comment: &[], reads: &[] })),
        ("ZIP64", Z_ZIP64, Some(Py { names: &["big.bin", "big2.bin"], find: &[0, 1], comment: &[], reads: &[Ok((214, 0xe6f8e1f8)), Ok((214, 0xe6f8e1f8))] })),
        ("SFX", Z_SFX, Some(Py { names: &["hello.txt", "dir/a.txt"], find: &[0, 1], comment: &[], reads: &[Ok((12, 0xaf083b2d)), Ok((214, 0xe6f8e1f8))] })),
        ("ZIP64_SFX", Z_ZIP64_SFX, Some(Py { names: &["big.bin", "big2.bin"], find: &[0, 1], comment: &[], reads: &[Ok((214, 0xe6f8e1f8)), Ok((214, 0xe6f8e1f8))] })),
        ("DESCRIPTOR", Z_DESCRIPTOR, Some(Py { names: &["stream.txt"], find: &[0], comment: &[], reads: &[Ok((214, 0xe6f8e1f8))] })),
        ("BAD_CRC", Z_BAD_CRC, Some(Py { names: &["hello.txt", "dir/", "dir/empty/", "dir/a.txt"], find: &[0, 1, 2, 3], comment: &[], reads: &[Err("BadZipFile"), Ok((0, 0x00000000)), Ok((0, 0x00000000)), Ok((214, 0xe6f8e1f8))] })),
        ("NAME_MISMATCH", Z_NAME_MISMATCH, Some(Py { names: &["hello.txt", "dir/", "dir/empty/", "dir/a.txt"], find: &[0, 1, 2, 3], comment: &[], reads: &[Err("BadZipFile"), Ok((0, 0x00000000)), Ok((0, 0x00000000)), Ok((214, 0xe6f8e1f8))] })),
        ("BAD_LOCAL_SIG", Z_BAD_LOCAL_SIG, Some(Py { names: &["hello.txt", "dir/", "dir/empty/", "dir/a.txt"], find: &[0, 1, 2, 3], comment: &[], reads: &[Err("BadZipFile"), Ok((0, 0x00000000)), Ok((0, 0x00000000)), Ok((214, 0xe6f8e1f8))] })),
        ("BAD_VERSION", Z_BAD_VERSION, None),
        ("BAD_UTF8", Z_BAD_UTF8, None),
        ("NUL_NAME", Z_NUL_NAME, Some(Py { names: &["a"], find: &[0], comment: &[], reads: &[Ok((12, 0xaf083b2d))] })),
        ("HUGE_DEFLATE", Z_HUGE_DEFLATE, Some(Py { names: &["hello.txt", "dir/a.txt"], find: &[0, 1], comment: &[], reads: &[Ok((12, 0xaf083b2d)), Ok((214, 0xe6f8e1f8))] })),
        ("HUGE_ZIP64", Z_HUGE_ZIP64, Some(Py { names: &["big.bin", "big2.bin"], find: &[0, 1], comment: &[], reads: &[Ok((214, 0xe6f8e1f8)), Ok((214, 0xe6f8e1f8))] })),
        ("HUGE_LZMA", Z_HUGE_LZMA, Some(Py { names: &["dir/a.txt"], find: &[0], comment: &[], reads: &[Ok((214, 0xe6f8e1f8))] })),
        ("OVERLAP", Z_OVERLAP, Some(Py { names: &["one", "two"], find: &[0, 1], comment: &[], reads: &[Err("BadZipFile"), Ok((40, 0xf36fca1b))] })),
        ("SHARED_HEADER", Z_SHARED_HEADER, Some(Py { names: &["one", "one"], find: &[1, 1], comment: &[], reads: &[Ok((40, 0x492f0064)), Ok((40, 0x492f0064))] })),
        ("UNICODE_PATH", Z_UNICODE_PATH, Some(Py { names: &["résumé.txt"], find: &[0], comment: &[], reads: &[Ok((13, 0x159d1f19))] })),
        ("UNICODE_PATH_STALE", Z_UNICODE_PATH_STALE, Some(Py { names: &["café.txt"], find: &[0], comment: &[], reads: &[Ok((13, 0x159d1f19))] })),
        ("COMMENT_LEN_TOO_BIG", Z_COMMENT_LEN_TOO_BIG, Some(Py { names: &["x"], find: &[0], comment: &[97, 114, 99, 104, 105, 118, 101, 32, 99, 111, 109, 109, 101, 110, 116, 32, 80, 75, 5, 32, 110, 111, 116, 32, 97, 32, 115, 105, 103, 110, 97, 116, 117, 114, 101], reads: &[Ok((12, 0xaf083b2d))] })),
        ("SIG_IN_COMMENT_END", Z_SIG_IN_COMMENT_END, None),
        ("PACK", Z_PACK, Some(Py { names: &["windows/ntkrnlmp.pdb/8E3373D6124E747F0E72EF8E02E676B3-1.json.xz", "windows/ntkrnlmp.pdb/2B2A15FA1FE2122BB1A39ED3572741D2-1.json.xz", "linux/"], find: &[0, 1, 2], comment: &[], reads: &[Ok((102, 0xc763cf3b)), Ok((102, 0x416efab0)), Ok((0, 0x00000000))] })),
        ("BAD_EXTRA", Z_BAD_EXTRA, None),
        ("ZIP64_SHORT", Z_ZIP64_SHORT, None),
        ("CORRUPT_DEFLATE", Z_CORRUPT_DEFLATE, Some(Py { names: &["hello.txt", "dir/a.txt"], find: &[0, 1], comment: &[], reads: &[Ok((12, 0xaf083b2d)), Err("error")] })),
        ("STORED_SHORT_SIZE", Z_STORED_SHORT_SIZE, Some(Py { names: &["hello.txt", "dir/", "dir/empty/", "dir/a.txt"], find: &[0, 1, 2, 3], comment: &[], reads: &[Ok((5, 0x3610a686)), Ok((0, 0x00000000)), Ok((0, 0x00000000)), Ok((214, 0xe6f8e1f8))] })),
        ("TRUNCATED", Z_TRUNCATED, None),
        ("GARBAGE", Z_GARBAGE, None),
    ];

    #[test]
    fn codecs_zip_matches_python() {
        for (key, hex, py) in PYTHON {
            let data = unhex(hex);
            let z = ZipArchive::parse(&data);
            let (z, py) = match (z, py) {
                (Err(_), None) => continue,
                (Ok(z), Some(py)) => (z, py),
                (Ok(_), None) => panic!("{key}: python refuses the archive, we accept it"),
                (Err(e), Some(_)) => panic!("{key}: python opens the archive, we fail: {e}"),
            };
            assert_eq!(z.names().collect::<Vec<_>>(), py.names, "{key}: names");
            assert_eq!(z.comment(), py.comment, "{key}: comment");
            for (name, &want) in py.names.iter().zip(py.find) {
                let got = z.find(name).unwrap();
                assert!(std::ptr::eq(got, &z.entries()[want]), "{key}: find({name:?}) is not entry {want}");
            }
            for (i, (e, want)) in z.entries().iter().zip(py.reads).enumerate() {
                match (z.read(e), want) {
                    (Ok(d), Ok((len, crc))) => {
                        assert_eq!((d.len(), crc32(&d)), (*len, *crc), "{key}: read entry {i} ({:?})", e.name)
                    }
                    (Err(_), Err(_)) => {}
                    (got, want) => panic!("{key}: read entry {i} ({:?}): got {:?}, python {want:?}", e.name, got.map(|d| d.len())),
                }
            }
            assert_eq!(z.entries().len(), py.reads.len());
        }
    }

    #[test]
    fn codecs_zip_entry_fields() {
        let data = archive("STORED");
        let z = ZipArchive::parse(&data).unwrap();
        let dirs: Vec<bool> = z.entries().iter().map(|e| e.is_dir()).collect();
        assert_eq!(dirs, [false, true, true, false]);
        let e = z.find("hello.txt").unwrap();
        assert_eq!((e.method, e.compressed_size, e.uncompressed_size), (METHOD_STORED, 12, 12));
        assert_eq!(z.raw_data(e).unwrap(), b"hello world\n");
        assert_eq!(z.read_by_name("hello.txt").unwrap(), b"hello world\n");
        assert!(z.read_by_name("missing.txt").unwrap_err().to_string().contains("no item named"));
        assert!(z.find("HELLO.TXT").is_none() && z.find("dir").is_none() && z.find("/hello.txt").is_none());
        // DOS timestamp fields as stored (python: date_time == (2023, 11, 14, 22, 13, 20)).
        let (d, t) = (e.dos_date, e.dos_time);
        let local = ((d >> 9) + 1980, (d >> 5) & 15, d & 31, t >> 11, (t >> 5) & 63, (t & 31) * 2);
        assert_eq!((local.0, local.1), (2023, 11));

        let deflated = archive("DEFLATED");
        let sfx = archive("SFX");
        let (a, b) = (ZipArchive::parse(&deflated).unwrap(), ZipArchive::parse(&sfx).unwrap());
        let stub = sfx.len() - deflated.len();
        // zip -9 keeps the 12-byte file stored (deflate would not shrink it).
        assert_eq!(a.entries().iter().map(|e| e.method).collect::<Vec<_>>(), [METHOD_STORED, METHOD_DEFLATED]);
        for (x, y) in a.entries().iter().zip(b.entries()) {
            assert_eq!(y.header_offset, x.header_offset + stub as u64);
            assert_eq!(a.read(x).unwrap(), b.read(y).unwrap());
        }

        let z64 = archive("ZIP64");
        let z = ZipArchive::parse(&z64).unwrap();
        assert_eq!(z.entries()[0].uncompressed_size, 214);
        assert_eq!(z.entries()[1].method, METHOD_DEFLATED);

        let pack = archive("PACK");
        let z = ZipArchive::parse(&pack).unwrap();
        let d = z.read_by_name("windows/ntkrnlmp.pdb/8E3373D6124E747F0E72EF8E02E676B3-1.json.xz").unwrap();
        assert_eq!(d, b"8E3373D6124E747F0E72EF8E02E676B3-1".repeat(3));
    }

    #[test]
    fn codecs_zip_errors() {
        let msg = |key: &str, entry: usize| {
            let data = archive(key);
            let z = ZipArchive::parse(&data).unwrap();
            z.read(&z.entries()[entry]).unwrap_err().to_string()
        };
        assert!(msg("ENCRYPTED", 0).contains("encrypted"));
        assert!(msg("DEFLATE64", 0).contains("compression type 9 (deflate64)"));
        assert!(msg("BAD_CRC", 0).contains("bad CRC-32"));
        assert!(msg("NAME_MISMATCH", 0).contains("differ"));
        assert!(msg("BAD_LOCAL_SIG", 0).contains("bad magic number for file header"));
        assert!(msg("OVERLAP", 0).contains("overlapped entries"));
        let parse = |key: &str| ZipArchive::parse(&archive(key)).err().unwrap().to_string();
        assert!(parse("BAD_VERSION").contains("zip file version 6.4"));
        assert!(parse("BAD_UTF8").contains("UTF-8"));
        assert!(parse("BAD_EXTRA").contains("corrupt extra field 9999"));
        assert!(parse("GARBAGE").contains("not a zip file"));
        assert!(parse("SIG_IN_COMMENT_END").contains("not a zip file"));
        for n in 0..22 {
            assert!(ZipArchive::parse(&vec![0u8; n]).is_err());
        }
        // Encrypted entries still list, and their raw bytes are refused like python's open().
        let data = archive("ENCRYPTED");
        let z = ZipArchive::parse(&data).unwrap();
        assert!(z.raw_data(&z.entries()[0]).is_err());
    }

    #[test]
    fn codecs_zip_names() {
        let data = archive("NAMES");
        let z = ZipArchive::parse(&data).unwrap();
        let flags: Vec<u16> = z.entries().iter().map(|e| e.flags & FLAG_UTF8).collect();
        assert_eq!(flags, [0, FLAG_UTF8, 0, 0], "cp437 name without, UTF-8 name with flag bit 11");
        assert_eq!(z.read_by_name("café.txt").unwrap(), b"cp437\n");
        assert_eq!(z.read_by_name("日本/語.txt").unwrap(), b"utf8\n");
        // Every cp437 byte decodes like python's codec (the low half is ASCII).
        let py = "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■\u{a0}";
        let all: Vec<u8> = (0..=255).collect();
        let want: String = (0..128u8).map(|b| b as char).chain(py.chars()).collect();
        assert_eq!(decode_name(&all, false).unwrap(), want);
        // Unicode Path extra field: used when its CRC matches the stored name.
        let up = archive("UNICODE_PATH");
        let z = ZipArchive::parse(&up).unwrap();
        assert_eq!(z.names().collect::<Vec<_>>(), ["résumé.txt"]);
        assert_eq!(z.read_by_name("résumé.txt").unwrap(), b"unicode path\n");
        assert!(z.find("café.txt").is_none());
        // NUL cuts the name; the local header check uses the full stored name.
        let nul = archive("NUL_NAME");
        let z = ZipArchive::parse(&nul).unwrap();
        assert_eq!(z.read_by_name("a").unwrap(), b"hello world\n");
        // Duplicates: listed twice, the last one wins on lookup.
        let dup = archive("DUPLICATES");
        let z = ZipArchive::parse(&dup).unwrap();
        assert_eq!(z.names().filter(|n| *n == "dup.txt").count(), 2);
        assert_eq!(z.read_by_name("dup.txt").unwrap(), b"second\n");
    }

    /// Declared sizes are untrusted: absurd ones never reach an allocation, and python cuts
    /// the data at the declared size rather than failing, so reads still succeed.
    #[test]
    fn codecs_zip_huge_declared_sizes() {
        for key in ["HUGE_DEFLATE", "HUGE_ZIP64", "HUGE_LZMA"] {
            let data = archive(key);
            let z = ZipArchive::parse(&data).unwrap();
            let e = &z.entries()[0];
            assert!(e.uncompressed_size >= 0xFFFF_FFF0 || key == "HUGE_DEFLATE");
            for e in z.entries() {
                assert!(z.read(e).unwrap().len() < 1000, "{key}");
            }
        }
        // A zip64 entry claiming 2^62 compressed bytes: truncated data, no allocation.
        let mut data = archive("ZIP64");
        let z = ZipArchive::parse(&data).unwrap();
        let cd = z.entries()[0].raw_name.0 - 46;
        let x0 = cd + 46 + u16le(&data, cd + 28) as usize;
        data[x0 + 12..x0 + 20].copy_from_slice(&(1u64 << 62).to_le_bytes());
        let z = ZipArchive::parse(&data).unwrap();
        assert_eq!(z.entries()[0].compressed_size, 1 << 62);
        assert!(z.read(&z.entries()[0]).is_err());
        assert!(z.raw_data(&z.entries()[0]).is_err());
    }

    /// Truncated, mutated and random archives: errors, never panics.
    #[test]
    fn codecs_zip_fuzz_never_panics() {
        let mut s = 0x9E37_79B9_7F4A_7C15u64;
        let mut rnd = move || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        let reads = std::cell::Cell::new(0usize);
        let exercise = |data: &[u8]| {
            if let Ok(z) = ZipArchive::parse(data) {
                for e in z.entries() {
                    reads.set(reads.get() + z.read(e).is_ok() as usize);
                    let _ = z.raw_data(e);
                    let _ = z.find(&e.name);
                    let _ = e.is_dir();
                }
                let _ = z.comment();
            }
        };
        for (_, hex, _) in PYTHON {
            let data = unhex(hex);
            for n in 0..data.len() {
                exercise(&data[..n]);
                exercise(&data[n..]);
            }
            for _ in 0..300 {
                let mut d = data.clone();
                for _ in 0..1 + rnd() % 4 {
                    let i = (rnd() % d.len().max(1) as u64) as usize;
                    if i < d.len() {
                        d[i] = match rnd() % 3 {
                            0 => d[i] ^ (1 << (rnd() % 8)),
                            1 => 0xFF,
                            _ => rnd() as u8,
                        };
                    }
                }
                exercise(&d);
            }
        }
        for n in 0..2000 {
            let mut d: Vec<u8> = (0..n % 300).map(|_| rnd() as u8).collect();
            if d.len() >= 22 && n % 2 == 0 {
                let at = d.len() - 22;
                d[at..at + 4].copy_from_slice(&SIG_END);
            }
            exercise(&d);
        }
        assert!(reads.get() > 5000, "the mutations rarely reach read() ({})", reads.get());
    }
}
