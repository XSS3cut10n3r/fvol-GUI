//! Minimal ZIP archive reader (central directory, zip64, stored / deflate / bzip2 / lzma).
//!
//! Mirrors python's `zipfile` where it matters for symbol packs: names are UTF-8 when flag
//! bit 11 is set and cp437 otherwise (truncated at a NUL), a later duplicate name wins on
//! lookup, data prepended to the archive is tolerated, and CRC-32 is verified on read.
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

/// One central directory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZipEntry {
    pub name: String,
    pub method: u16,
    pub flags: u16,
    pub crc32: u32,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    /// Offset of the local file header (already adjusted for prepended data).
    pub header_offset: u64,
    /// DOS date and time fields (as stored).
    pub dos_date: u16,
    pub dos_time: u16,
}

impl ZipEntry {
    pub fn is_dir(&self) -> bool {
        self.name.ends_with('/')
    }
}

/// A parsed archive borrowing the archive bytes (typically an mmap).
pub struct ZipArchive<'a> {
    data: &'a [u8],
    entries: Vec<ZipEntry>,
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
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
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

fn decode_name(raw: &[u8], utf8: bool) -> String {
    let raw = match raw.iter().position(|&b| b == 0) {
        Some(n) => &raw[..n],
        None => raw,
    };
    if utf8 {
        String::from_utf8_lossy(raw).into_owned()
    } else if raw.is_ascii() {
        // SAFETY-free fast path: ASCII is valid UTF-8.
        String::from_utf8_lossy(raw).into_owned()
    } else {
        raw.iter().map(|&b| if b < 0x80 { b as char } else { CP437_HIGH[(b - 0x80) as usize] }).collect()
    }
}

impl<'a> ZipArchive<'a> {
    /// Parses the end-of-central-directory record(s) and the central directory.
    pub fn parse(data: &'a [u8]) -> Result<ZipArchive<'a>> {
        const EOCD_SIG: [u8; 4] = [b'P', b'K', 5, 6];
        if data.len() < 22 {
            return Err(err("file too small"));
        }
        // The EOCD is the last 22 bytes plus a comment of up to 65535 bytes.
        let lo = data.len().saturating_sub(22 + 65535);
        let eocd = (lo..=data.len() - 22)
            .rev()
            .find(|&i| data[i..i + 4] == EOCD_SIG && i + 22 + u16le(data, i + 20) as usize <= data.len())
            .ok_or_else(|| err("end of central directory not found"))?;
        let mut count = u16le(data, eocd + 10) as u64;
        let mut cd_size = u32le(data, eocd + 12) as u64;
        let mut cd_offset = u32le(data, eocd + 16) as u64;
        let mut concat = eocd as i64 - cd_size as i64 - cd_offset as i64;
        // zip64 locator immediately precedes the EOCD.
        if eocd >= 20 && data[eocd - 20..eocd - 16] == [b'P', b'K', 6, 7] {
            // Like python, locate the zip64 record right before the locator.
            let rec_pos = eocd.checked_sub(20 + 56).ok_or_else(|| err("bad zip64 locator"))?;
            let r = &data[rec_pos..rec_pos + 56];
            if r[..4] != [b'P', b'K', 6, 6] {
                return Err(err("zip64 end of central directory record not found"));
            }
            count = u64le(r, 32);
            cd_size = u64le(r, 40);
            cd_offset = u64le(r, 48);
            concat = rec_pos as i64 - cd_size as i64 - cd_offset as i64;
        }
        if concat < 0 {
            return Err(err("bad central directory offset"));
        }
        let cd_start = (cd_offset as i64 + concat) as usize;
        let cd = data.get(cd_start..cd_start.saturating_add(cd_size as usize)).ok_or_else(|| err("truncated central directory"))?;
        let mut entries = Vec::with_capacity(count.min(1 << 20) as usize);
        let mut p = 0usize;
        while p + 46 <= cd.len() {
            if cd[p..p + 4] != [b'P', b'K', 1, 2] {
                return Err(err("bad central directory entry"));
            }
            let flags = u16le(cd, p + 8);
            let method = u16le(cd, p + 10);
            let dos_time = u16le(cd, p + 12);
            let dos_date = u16le(cd, p + 14);
            let crc = u32le(cd, p + 16);
            let mut csize = u32le(cd, p + 20) as u64;
            let mut usize_ = u32le(cd, p + 24) as u64;
            let nlen = u16le(cd, p + 28) as usize;
            let xlen = u16le(cd, p + 30) as usize;
            let clen = u16le(cd, p + 32) as usize;
            let mut offset = u32le(cd, p + 42) as u64;
            let end = p + 46 + nlen + xlen + clen;
            if end > cd.len() {
                return Err(err("truncated central directory entry"));
            }
            let name = decode_name(&cd[p + 46..p + 46 + nlen], flags & 0x800 != 0);
            // zip64 extended information extra field.
            let mut x = &cd[p + 46 + nlen..p + 46 + nlen + xlen];
            while x.len() >= 4 {
                let id = u16le(x, 0);
                let sz = (u16le(x, 2) as usize).min(x.len() - 4);
                if id == 1 {
                    let mut f = &x[4..4 + sz];
                    for v in [&mut usize_, &mut csize, &mut offset] {
                        if *v == 0xFFFF_FFFF {
                            if f.len() < 8 {
                                return Err(err("corrupt zip64 extra field"));
                            }
                            *v = u64le(f, 0);
                            f = &f[8..];
                        }
                    }
                }
                x = &x[4 + sz..];
            }
            entries.push(ZipEntry {
                name,
                method,
                flags,
                crc32: crc,
                compressed_size: csize,
                uncompressed_size: usize_,
                header_offset: (offset as i64 + concat) as u64,
                dos_date,
                dos_time,
            });
            p = end;
        }
        Ok(ZipArchive { data, entries, index: OnceLock::new() })
    }

    /// All entries in central directory order.
    pub fn entries(&self) -> &[ZipEntry] {
        &self.entries
    }

    /// Entry names in central directory order (python's `namelist()`).
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|e| e.name.as_str())
    }

    /// Looks an entry up by exact name (the last one wins for duplicates).
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

    /// The entry's stored (possibly compressed) bytes, borrowed from the archive.
    pub fn raw_data(&self, e: &ZipEntry) -> Result<&'a [u8]> {
        let h = e.header_offset as usize;
        let lh = self.data.get(h..h.saturating_add(30)).ok_or_else(|| err("bad local header offset"))?;
        if lh[..4] != [b'P', b'K', 3, 4] {
            return Err(err("bad magic number for file header"));
        }
        let nlen = u16le(lh, 26) as usize;
        let xlen = u16le(lh, 28) as usize;
        let name = self.data.get(h + 30..h + 30 + nlen).ok_or_else(|| err("truncated local header"))?;
        if decode_name(name, e.flags & 0x800 != 0) != e.name {
            return Err(err(&format!("file name in directory {:?} and header differ", e.name)));
        }
        let start = h + 30 + nlen + xlen;
        self.data
            .get(start..start.saturating_add(e.compressed_size as usize))
            .ok_or_else(|| err("truncated file data"))
    }

    /// Reads and decompresses an entry, verifying its CRC-32.
    pub fn read(&self, e: &ZipEntry) -> Result<Vec<u8>> {
        if e.flags & 1 != 0 {
            return Err(err(&format!("file {:?} is encrypted", e.name)));
        }
        let raw = self.raw_data(e)?;
        let size = usize::try_from(e.uncompressed_size).map_err(|_| err("entry too large"))?;
        let out = match e.method {
            METHOD_STORED => {
                if raw.len() != size {
                    return Err(err("stored entry size mismatch"));
                }
                raw.to_vec()
            }
            METHOD_DEFLATED => super::inflate::decompress_sized(raw, size)?,
            METHOD_BZIP2 => super::bzip2::decompress(raw)?,
            METHOD_LZMA => {
                // 2 bytes version, 2 bytes properties size, properties (5 bytes), LZMA1 data.
                if raw.len() < 4 {
                    return Err(err("truncated lzma header"));
                }
                let psize = u16le(raw, 2) as usize;
                if psize != 5 || raw.len() < 4 + psize {
                    return Err(err("bad lzma properties"));
                }
                super::lzma::decompress_lzma1_raw(&raw[4 + psize..], raw[4], Some(size as u64))?
            }
            m => return Err(err(&format!("compression method {m} not supported"))),
        };
        if out.len() != size {
            return Err(err("uncompressed size mismatch"));
        }
        if crc32(&out) != e.crc32 {
            return Err(err(&format!("bad CRC-32 for file {:?}", e.name)));
        }
        Ok(out)
    }

    /// Reads an entry by name.
    pub fn read_by_name(&self, name: &str) -> Result<Vec<u8>> {
        let e = self.find(name).ok_or_else(|| err(&format!("no item named {name:?} in the archive")))?;
        self.read(e)
    }
}
