//! python `symbols/windows/extensions/mft.py`: the NTFS MFT record classes `MFTEntry`,
//! `MFTFileName` and `MFTAttribute` over the bundled `windows/mft` ISF, as zero-allocation views
//! over a layer.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! The `windows/mft` table is fixed (it ships with volatility), so member offsets and the enum
//! tables are constants here (checked against the ISF by a unit test) -- the record parsers run
//! for hundreds of thousands of scan hits and read raw little-endian fields straight from the
//! layer. Every accessor reads exactly where python reads (python primitives read on attribute
//! access) and returns `Err` (an invalid-address error) where python raises
//! `InvalidAddressException`; the iterators swallow errors exactly where python's generators do.
//!
//! ```ignore
//! use crate::symbols::windows::mft::MftEntry;
//! let rec = MftEntry::new(layer, offset);
//! for si in rec.standard_information_entries()? { let t = si.creation_time()?; }
//! for name in rec.filename_entries()? { let s = name.get_full_name()?; }
//! let longest = rec.longest_filename()?;              // Option<String>
//! for ads in rec.alternate_data_streams() { let attr = ads?; attr.get_resident_filename()?; }
//! ```
//!
//! Layout notes (from `mft.json`, python reads the enums with their 1-byte base type):
//! `MFT_ENTRY` (1024 bytes): Signature @0 (read as a 4-byte latin-1 string), LinkCount @18 u16,
//! FirstAttrOffset @20 u16, Flags @22 `MFTFlagsEnum` (u8), RecordNumber @44 u32.
//! `ATTRIBUTE`: `Attr_Header` @0 (`ATTR_HEADER`: AttrType @0 `AttrTypeEnum` (u8), Length @4 u32,
//! NonResidentFlag @8 u8, NameLength @9 u8, NameOffset @10 u16, ContentLength @16 u32,
//! ContentOffset @20 u16), `Attr_Data` @24 (cast to `STANDARD_INFORMATION_ENTRY` /
//! `FILE_NAME_ENTRY`). `STANDARD_INFORMATION_ENTRY`: Creation/Modified/Updated/AccessedTime @0/8/
//! 16/24 u64. `FILE_NAME_ENTRY`: Creation/Modified/Updated/AccessedTime @8/16/24/32 u64, Flags @56
//! `PermissionFlagEnum` (u8), NameLength @64 u8, Name @66 (UTF-16).

use crate::error::{Error, Result};
use crate::layers::{Layer, LayerExt};
use crate::objects::strings::decode_cstring;
use crate::symbols::{StrEnc, StrErrors};

/// Member offsets of the `windows/mft` ISF types.
pub mod off {
    /// `MFT_ENTRY.Signature`
    pub const SIGNATURE: u64 = 0;
    /// `MFT_ENTRY.LinkCount` (u16)
    pub const LINK_COUNT: u64 = 18;
    /// `MFT_ENTRY.FirstAttrOffset` (u16)
    pub const FIRST_ATTR_OFFSET: u64 = 20;
    /// `MFT_ENTRY.Flags` (`MFTFlagsEnum`, u8)
    pub const FLAGS: u64 = 22;
    /// `MFT_ENTRY.RecordNumber` (u32)
    pub const RECORD_NUMBER: u64 = 44;

    /// `ATTR_HEADER.AttrType` (`AttrTypeEnum`, u8)
    pub const ATTR_TYPE: u64 = 0;
    /// `ATTR_HEADER.Length` (u32)
    pub const ATTR_LENGTH: u64 = 4;
    /// `ATTR_HEADER.NonResidentFlag` (u8)
    pub const NON_RESIDENT_FLAG: u64 = 8;
    /// `ATTR_HEADER.NameLength` (u8)
    pub const NAME_LENGTH: u64 = 9;
    /// `ATTR_HEADER.NameOffset` (u16)
    pub const NAME_OFFSET: u64 = 10;
    /// `ATTR_HEADER.ContentLength` (u32)
    pub const CONTENT_LENGTH: u64 = 16;
    /// `ATTR_HEADER.ContentOffset` (u16)
    pub const CONTENT_OFFSET: u64 = 20;
    /// `ATTRIBUTE.Attr_Data`
    pub const ATTR_DATA: u64 = 24;

    /// `STANDARD_INFORMATION_ENTRY.CreationTime` (then Modified/Updated/Accessed, u64 each)
    pub const SI_CREATION_TIME: u64 = 0;

    /// `FILE_NAME_ENTRY.CreationTime` (then Modified/Updated/Accessed, u64 each)
    pub const FN_CREATION_TIME: u64 = 8;
    /// `FILE_NAME_ENTRY.Flags` (`PermissionFlagEnum`, u8)
    pub const FN_FLAGS: u64 = 56;
    /// `FILE_NAME_ENTRY.NameLength` (u8)
    pub const FN_NAME_LENGTH: u64 = 64;
    /// `FILE_NAME_ENTRY.Name` (wchar[])
    pub const FN_NAME: u64 = 66;
}

/// `AttrTypeEnum` value of `STANDARD_INFORMATION`.
pub const ATTR_STANDARD_INFORMATION: u8 = 16;
/// `AttrTypeEnum` value of `FILE_NAME`.
pub const ATTR_FILE_NAME: u8 = 48;
/// `AttrTypeEnum` value of `DATA`.
pub const ATTR_DATA: u8 = 128;

/// python `AttrTypeEnum.lookup(v)` for the 1-byte value python reads (`LOGGED_UTILITY_STREAM` =
/// 256 can never match); `None` = not a valid choice.
pub fn attr_type_name(v: u8) -> Option<&'static str> {
    Some(match v {
        16 => "STANDARD_INFORMATION",
        32 => "ATTRIBUTE_LIST",
        48 => "FILE_NAME",
        64 => "OBJECT_ID",
        80 => "SECURITY_DESCRIPTOR",
        96 => "VOLUME_NAME",
        112 => "VOLUME_INFORMATION",
        114 => "INDEX_ROOT",
        128 => "DATA",
        160 => "INDEX_ALLOCATION",
        176 => "BITMAP",
        192 => "REPARSE_POINT",
        208 => "EA_INFORMATION",
        224 => "EA",
        240 => "PROPERTY_SET",
        _ => return None,
    })
}

/// python `MFTFlagsEnum.lookup(v)`.
pub fn mft_flags_name(v: u8) -> Option<&'static str> {
    Some(match v {
        0 => "Removed",
        1 => "File",
        2 => "Directory",
        3 => "DirInUse",
        _ => return None,
    })
}

/// python `PermissionFlagEnum.lookup(v)` for the 1-byte value python reads.
pub fn permission_flags_name(v: u8) -> Option<&'static str> {
    Some(match v {
        1 => "ReadOnly",
        2 => "Hidden",
        4 => "System",
        32 => "Archive",
        34 => "ArchiveHidden",
        36 => "ArchiveSystem",
        38 => "ArchiveHiddenSystem",
        60 => "Device",
        128 => "Normal",
        _ => return None,
    })
}

/// python `str(MFTEntry.get_signature())` of raw signature bytes (latin-1, cut at NUL) without
/// allocating for the signatures the MFT scan finds: `Ok("FILE")` / `Ok("BAAD")`, `Err(string)`
/// for anything else.
pub fn signature_str(raw: [u8; 4]) -> std::result::Result<&'static str, String> {
    match &raw {
        b"FILE" => Ok("FILE"),
        b"BAAD" => Ok("BAAD"),
        _ => Err(raw.iter().take_while(|&&b| b != 0).map(|&b| b as char).collect()),
    }
}

/// python `MFTAttribute` resident-content cutoff (4 MiB, "format /L" volumes).
pub const RESIDENT_CUTOFF: u64 = 0x400000;

#[inline]
fn at(base: u64, rel: u64) -> Result<u64> {
    base.checked_add(rel).ok_or(Error::invalid(base))
}

/// python `MFTEntry` (`windows/mft!MFT_ENTRY`) at `offset` of `layer`.
#[derive(Clone, Copy)]
pub struct MftEntry<'a> {
    pub layer: &'a dyn Layer,
    pub offset: u64,
}

impl<'a> MftEntry<'a> {
    #[inline]
    pub fn new(layer: &'a dyn Layer, offset: u64) -> Self {
        MftEntry { layer, offset }
    }

    #[inline]
    fn u8_at(&self, rel: u64) -> Result<u8> {
        self.layer.read_u8(at(self.offset, rel)?)
    }

    #[inline]
    fn u16_at(&self, rel: u64) -> Result<u16> {
        self.layer.read_u16(at(self.offset, rel)?)
    }

    /// python `get_signature()` + `str()`: the 4 signature bytes as latin-1, cut at NUL.
    pub fn get_signature(&self) -> Result<String> {
        let b: [u8; 4] = self.layer.read_array(at(self.offset, off::SIGNATURE)?)?;
        decode_cstring(&b, StrEnc::Latin1, StrErrors::Strict)
    }

    /// The 4 raw signature bytes [`MftEntry::get_signature`] decodes (see [`signature_str`]).
    pub fn signature_raw(&self) -> Result<[u8; 4]> {
        self.layer.read_array(at(self.offset, off::SIGNATURE)?)
    }

    /// `MFT_ENTRY.Flags` (raw 1-byte `MFTFlagsEnum` value).
    #[inline]
    pub fn flags(&self) -> Result<u8> {
        self.u8_at(off::FLAGS)
    }

    /// `MFT_ENTRY.LinkCount`.
    #[inline]
    pub fn link_count(&self) -> Result<u16> {
        self.u16_at(off::LINK_COUNT)
    }

    /// `MFT_ENTRY.RecordNumber`.
    #[inline]
    pub fn record_number(&self) -> Result<u32> {
        self.layer.read_u32(at(self.offset, off::RECORD_NUMBER)?)
    }

    /// `MFT_ENTRY.FirstAttrOffset`.
    #[inline]
    pub fn first_attr_offset(&self) -> Result<u16> {
        self.u16_at(off::FIRST_ATTR_OFFSET)
    }

    /// python `MFTEntry.attributes` (`_attributes()`): attributes from `FirstAttrOffset` on,
    /// while `AttrType` is a valid `AttrTypeEnum` choice, advancing by `Length` (stopping after an
    /// attribute of length 0); an unreadable attribute ends the walk silently. `Err` only when
    /// `FirstAttrOffset` itself cannot be read (python raises out of `attributes` then).
    /// Python caches the list; re-walking reads the same bytes, so this is lazy instead.
    pub fn attributes(&self) -> Result<Attributes<'a>> {
        let first = self.first_attr_offset()?;
        Ok(Attributes { layer: self.layer, record: self.offset, rel: first as u64, done: false })
    }

    /// python `standard_information_entries()`: the `STANDARD_INFORMATION_ENTRY` of every
    /// `STANDARD_INFORMATION` attribute.
    pub fn standard_information_entries(&self) -> Result<impl Iterator<Item = StandardInformation<'a>> + use<'a>> {
        Ok(self.attributes()?.filter(|a| a.attr_type == ATTR_STANDARD_INFORMATION).map(|a| StandardInformation { layer: a.layer, offset: a.attr_data_offset() }))
    }

    /// python `filename_entries()`: the `FILE_NAME_ENTRY` of every `FILE_NAME` attribute.
    pub fn filename_entries(&self) -> Result<impl Iterator<Item = MftFileName<'a>> + use<'a>> {
        Ok(self.attributes()?.filter(|a| a.attr_type == ATTR_FILE_NAME).map(|a| MftFileName { layer: a.layer, offset: a.attr_data_offset() }))
    }

    /// python `longest_filename()`: the longest (in characters; the first of equals) of the
    /// FILE_NAME names, `None` without FILE_NAME attributes. Errors propagate (python does not
    /// catch them here).
    pub fn longest_filename(&self) -> Result<Option<String>> {
        let mut best: Option<(usize, String)> = None;
        for f in self.filename_entries()? {
            let name = f.get_full_name()?;
            let n = name.chars().count();
            if best.as_ref().is_none_or(|(bn, _)| n > *bn) {
                best = Some((n, name));
            }
        }
        Ok(best.map(|(_, s)| s))
    }

    /// python `_data_attributes()` filtered on `NameLength == 0` (`named == false`, python
    /// `resident_data_attributes()`) or `!= 0` (`named == true`, `alternate_data_streams()`).
    /// Lazy like python's generator: an `Err` item is python raising at that point (reading
    /// `NonResidentFlag` / `NameLength`); nothing follows it.
    pub fn data_attributes(&self, named: bool) -> DataAttributes<'a> {
        match self.attributes() {
            Ok(a) => DataAttributes { attrs: Some(a), err: None, named },
            Err(e) => DataAttributes { attrs: None, err: Some(e), named },
        }
    }

    /// python `resident_data_attributes()`: resident unnamed DATA attributes (primary stream).
    pub fn resident_data_attributes(&self) -> DataAttributes<'a> {
        self.data_attributes(false)
    }

    /// python `alternate_data_streams()`: resident named DATA attributes (ADS).
    pub fn alternate_data_streams(&self) -> DataAttributes<'a> {
        self.data_attributes(true)
    }
}

/// Iterator of [`MftEntry::attributes`].
pub struct Attributes<'a> {
    layer: &'a dyn Layer,
    record: u64,
    /// python `attr_base_offset`
    rel: u64,
    done: bool,
}

impl<'a> Iterator for Attributes<'a> {
    type Item = MftAttribute<'a>;
    #[inline]
    fn next(&mut self) -> Option<MftAttribute<'a>> {
        if self.done {
            return None;
        }
        let Some(addr) = self.record.checked_add(self.rel) else {
            self.done = true;
            return None;
        };
        let t = match self.layer.read_u8(addr) {
            Ok(t) if attr_type_name(t).is_some() => t,
            _ => {
                self.done = true;
                return None;
            }
        };
        // python yields the attribute, then reads Length (an error there ends the walk)
        match addr.checked_add(off::ATTR_LENGTH).map(|a| self.layer.read_u32(a)) {
            Some(Ok(0)) | Some(Err(_)) | None => self.done = true,
            Some(Ok(len)) => self.rel += len as u64,
        }
        Some(MftAttribute { layer: self.layer, offset: addr, attr_type: t })
    }
}

/// Iterator of [`MftEntry::data_attributes`].
pub struct DataAttributes<'a> {
    attrs: Option<Attributes<'a>>,
    /// python raised reading `FirstAttrOffset`
    err: Option<Error>,
    named: bool,
}

impl<'a> Iterator for DataAttributes<'a> {
    type Item = Result<MftAttribute<'a>>;
    fn next(&mut self) -> Option<Result<MftAttribute<'a>>> {
        if let Some(e) = self.err.take() {
            return Some(Err(e));
        }
        let attrs = self.attrs.as_mut()?;
        for a in attrs.by_ref() {
            if a.attr_type != ATTR_DATA {
                continue;
            }
            let r = a.non_resident_flag().and_then(|nr| if nr == 0 { a.name_length().map(Some) } else { Ok(None) });
            match r {
                Err(e) => {
                    self.attrs = None;
                    return Some(Err(e));
                }
                Ok(Some(nl)) if (nl != 0) == self.named => return Some(Ok(a)),
                Ok(_) => {}
            }
        }
        self.attrs = None;
        None
    }
}

/// python `MFTAttribute` (`windows/mft!ATTRIBUTE`) at `offset`; `attr_type` is the
/// `Attr_Header.AttrType` value read by the attribute walk (always a valid choice).
#[derive(Clone, Copy)]
pub struct MftAttribute<'a> {
    pub layer: &'a dyn Layer,
    pub offset: u64,
    pub attr_type: u8,
}

impl<'a> MftAttribute<'a> {
    /// python `Attr_Header.AttrType.lookup()`.
    #[inline]
    pub fn attr_type_name(&self) -> &'static str {
        attr_type_name(self.attr_type).unwrap_or("")
    }

    /// python `Attr_Data.vol.offset`.
    #[inline]
    pub fn attr_data_offset(&self) -> u64 {
        self.offset.wrapping_add(off::ATTR_DATA)
    }

    /// `Attr_Header.Length`.
    #[inline]
    pub fn length(&self) -> Result<u32> {
        self.layer.read_u32(at(self.offset, off::ATTR_LENGTH)?)
    }

    /// `Attr_Header.NonResidentFlag`.
    #[inline]
    pub fn non_resident_flag(&self) -> Result<u8> {
        self.layer.read_u8(at(self.offset, off::NON_RESIDENT_FLAG)?)
    }

    /// `Attr_Header.NameLength`.
    #[inline]
    pub fn name_length(&self) -> Result<u8> {
        self.layer.read_u8(at(self.offset, off::NAME_LENGTH)?)
    }

    /// `Attr_Header.NameOffset`.
    #[inline]
    pub fn name_offset(&self) -> Result<u16> {
        self.layer.read_u16(at(self.offset, off::NAME_OFFSET)?)
    }

    /// `Attr_Header.ContentLength`.
    #[inline]
    pub fn content_length(&self) -> Result<u32> {
        self.layer.read_u32(at(self.offset, off::CONTENT_LENGTH)?)
    }

    /// `Attr_Header.ContentOffset`.
    #[inline]
    pub fn content_offset(&self) -> Result<u16> {
        self.layer.read_u16(at(self.offset, off::CONTENT_OFFSET)?)
    }

    /// python `get_resident_filename()`: the attribute name (UTF-16, errors replaced, cut at
    /// NUL) at `NameOffset`; `Ok(None)` when unreadable (python catches that). The size checks
    /// read `ContentOffset` / `NameLength` outside python's `try` (errors propagate).
    pub fn get_resident_filename(&self) -> Result<Option<String>> {
        let co = self.content_offset()? as u64;
        if co > RESIDENT_CUTOFF {
            return Ok(None);
        }
        let nl = self.name_length()? as u64;
        if nl > 512 {
            return Ok(None);
        }
        let r = (|| -> Result<String> {
            let addr = at(self.offset, self.name_offset()? as u64)?;
            read_utf16_name(self.layer, addr, nl * 2)
        })();
        match r {
            Ok(s) => Ok(Some(s)),
            Err(e) if e.is_invalid_address() => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Where [`MftAttribute::get_resident_filecontent`] reads: `(offset + ContentOffset,
    /// ContentLength)`, `None` past the 4 MiB cutoffs. Errors reading the header propagate.
    pub fn resident_content_range(&self) -> Result<Option<(u64, u64)>> {
        let co = self.content_offset()? as u64;
        if co > RESIDENT_CUTOFF {
            return Ok(None);
        }
        let cl = self.content_length()? as u64;
        if cl > RESIDENT_CUTOFF {
            return Ok(None);
        }
        Ok(Some((self.offset.wrapping_add(co), cl)))
    }

    /// python `get_resident_filecontent()`: the resident content bytes (`ContentLength` bytes at
    /// `ContentOffset`) with their layer offset; `Ok(None)` past the cutoffs or when unreadable
    /// (python catches that). An empty result is python's falsy `b""`.
    pub fn get_resident_filecontent(&self) -> Result<Option<(u64, Vec<u8>)>> {
        let Some((addr, len)) = self.resident_content_range()? else { return Ok(None) };
        if len == 0 {
            // python: a 0-length Bytes object reads nothing
            return Ok(Some((addr, Vec::new())));
        }
        match self.layer.read_vec(addr, len as usize) {
            Ok(v) => Ok(Some((addr, v))),
            Err(e) if e.is_invalid_address() => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// `max_length`-byte python `objects.String` with encoding "utf16", errors "replace".
#[inline]
fn read_utf16_name(layer: &dyn Layer, addr: u64, max_len: u64) -> Result<String> {
    if max_len == 0 {
        return Ok(String::new());
    }
    let mut buf = [0u8; 512];
    let b = &mut buf[..max_len as usize];
    layer.read(addr, b)?;
    decode_cstring(b, StrEnc::Utf16, StrErrors::Replace)
}

/// `windows/mft!STANDARD_INFORMATION_ENTRY` (python `attr.Attr_Data.cast(...)`).
#[derive(Clone, Copy)]
pub struct StandardInformation<'a> {
    pub layer: &'a dyn Layer,
    pub offset: u64,
}

impl StandardInformation<'_> {
    #[inline]
    fn time(&self, i: u64) -> Result<u64> {
        self.layer.read_u64(at(self.offset, off::SI_CREATION_TIME + 8 * i)?)
    }
    /// `CreationTime`
    pub fn creation_time(&self) -> Result<u64> {
        self.time(0)
    }
    /// `ModifiedTime`
    pub fn modified_time(&self) -> Result<u64> {
        self.time(1)
    }
    /// `UpdatedTime`
    pub fn updated_time(&self) -> Result<u64> {
        self.time(2)
    }
    /// `AccessedTime`
    pub fn accessed_time(&self) -> Result<u64> {
        self.time(3)
    }
    /// All four times (Creation, Modified, Updated, Accessed) with one read.
    pub fn times(&self) -> Result<[u64; 4]> {
        read_times(self.layer, at(self.offset, off::SI_CREATION_TIME)?)
    }
}

#[inline]
fn read_times(layer: &dyn Layer, addr: u64) -> Result<[u64; 4]> {
    let b: [u8; 32] = layer.read_array(addr)?;
    let t = |i: usize| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
    Ok([t(0), t(1), t(2), t(3)])
}

/// python `MFTFileName` (`windows/mft!FILE_NAME_ENTRY`).
#[derive(Clone, Copy)]
pub struct MftFileName<'a> {
    pub layer: &'a dyn Layer,
    pub offset: u64,
}

impl MftFileName<'_> {
    /// `Flags` (raw 1-byte `PermissionFlagEnum` value).
    #[inline]
    pub fn flags(&self) -> Result<u8> {
        self.layer.read_u8(at(self.offset, off::FN_FLAGS)?)
    }
    /// `NameLength` (characters).
    #[inline]
    pub fn name_length(&self) -> Result<u8> {
        self.layer.read_u8(at(self.offset, off::FN_NAME_LENGTH)?)
    }
    /// `CreationTime`, `ModifiedTime`, `UpdatedTime`, `AccessedTime`.
    pub fn times(&self) -> Result<[u64; 4]> {
        read_times(self.layer, at(self.offset, off::FN_CREATION_TIME)?)
    }
    /// python `get_full_name()`: `NameLength` UTF-16 characters (errors replaced, cut at NUL).
    pub fn get_full_name(&self) -> Result<String> {
        let mut s = String::new();
        self.get_full_name_into(&mut s)?;
        Ok(s)
    }

    /// [`MftFileName::get_full_name`] appended to `out` (plain ASCII names are copied without
    /// allocating); nothing is appended on error.
    pub fn get_full_name_into(&self, out: &mut String) -> Result<()> {
        let n = self.name_length()? as usize;
        if n == 0 {
            return Ok(());
        }
        let mut buf = [0u8; 512];
        let b = &mut buf[..2 * n];
        self.layer.read(at(self.offset, off::FN_NAME)?, b)?;
        let units = b.as_chunks::<2>().0;
        if units.iter().all(|u| u[1] == 0 && u[0] < 0x80) {
            // ASCII code units (no BOM, no surrogates): the same characters, cut at NUL
            for u in units {
                if u[0] == 0 {
                    break;
                }
                out.push(u[0] as char);
            }
            return Ok(());
        }
        out.push_str(&decode_cstring(b, StrEnc::Utf16, StrErrors::Replace)?);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layers::Mapping;

    /// A flat in-memory layer for tests.
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
        fn mapping(&self, _addr: u64, _len: u64, _f: &mut dyn FnMut(Mapping) -> bool) {}
    }

    fn put(b: &mut [u8], at: usize, v: &[u8]) {
        b[at..at + v.len()].copy_from_slice(v);
    }

    fn attr(b: &mut [u8], at: usize, ty: u8, len: u32) {
        b[at] = ty;
        put(b, at + 4, &len.to_le_bytes());
    }

    #[test]
    fn isf_layout_matches() {
        let t = crate::symbols::load_isf("windows", "mft", None, &[]).unwrap();
        let o = |ty: &str, m: &str| t.offset_of(ty, m).unwrap();
        assert_eq!(o("MFT_ENTRY", "Signature"), off::SIGNATURE);
        assert_eq!(o("MFT_ENTRY", "LinkCount"), off::LINK_COUNT);
        assert_eq!(o("MFT_ENTRY", "FirstAttrOffset"), off::FIRST_ATTR_OFFSET);
        assert_eq!(o("MFT_ENTRY", "Flags"), off::FLAGS);
        assert_eq!(o("MFT_ENTRY", "RecordNumber"), off::RECORD_NUMBER);
        assert_eq!(o("ATTRIBUTE", "Attr_Data"), off::ATTR_DATA);
        assert_eq!(o("ATTR_HEADER", "AttrType"), off::ATTR_TYPE);
        assert_eq!(o("ATTR_HEADER", "Length"), off::ATTR_LENGTH);
        assert_eq!(o("ATTR_HEADER", "NonResidentFlag"), off::NON_RESIDENT_FLAG);
        assert_eq!(o("ATTR_HEADER", "NameLength"), off::NAME_LENGTH);
        assert_eq!(o("ATTR_HEADER", "NameOffset"), off::NAME_OFFSET);
        assert_eq!(o("ATTR_HEADER", "ContentLength"), off::CONTENT_LENGTH);
        assert_eq!(o("ATTR_HEADER", "ContentOffset"), off::CONTENT_OFFSET);
        assert_eq!(o("STANDARD_INFORMATION_ENTRY", "CreationTime"), off::SI_CREATION_TIME);
        assert_eq!(o("STANDARD_INFORMATION_ENTRY", "AccessedTime"), off::SI_CREATION_TIME + 24);
        assert_eq!(o("FILE_NAME_ENTRY", "CreationTime"), off::FN_CREATION_TIME);
        assert_eq!(o("FILE_NAME_ENTRY", "AccessedTime"), off::FN_CREATION_TIME + 24);
        assert_eq!(o("FILE_NAME_ENTRY", "Flags"), off::FN_FLAGS);
        assert_eq!(o("FILE_NAME_ENTRY", "NameLength"), off::FN_NAME_LENGTH);
        assert_eq!(o("FILE_NAME_ENTRY", "Name"), off::FN_NAME);
        // enums: every constant representable in the 1-byte base maps back
        for (en, f) in [
            ("AttrTypeEnum", attr_type_name as fn(u8) -> Option<&'static str>),
            ("MFTFlagsEnum", mft_flags_name),
            ("PermissionFlagEnum", permission_flags_name),
        ] {
            let e = t.enumeration(en).unwrap();
            let mut n = 0;
            for (name, v) in t.enum_constants(e) {
                if v < 256 {
                    assert_eq!(f(v as u8), Some(name), "{en} {v}");
                    n += 1;
                }
            }
            assert_eq!((0..=255u8).filter(|&v| f(v).is_some()).count(), n, "{en}");
        }
    }

    #[test]
    fn attribute_walk() {
        let mut b = vec![0u8; 0x800];
        put(&mut b, 0, b"FILE0");
        put(&mut b, 20, &0x38u16.to_le_bytes());
        b[22] = 1;
        put(&mut b, 44, &77u32.to_le_bytes());
        // SI @0x38 len 0x60, FN @0x98 len 0x68, DATA named @0x100 len 0x50, DATA unnamed @0x150
        attr(&mut b, 0x38, 0x10, 0x60);
        put(&mut b, 0x38 + 24, &0x01d4_0000_0000_0000u64.to_le_bytes());
        attr(&mut b, 0x98, 0x30, 0x68);
        let fname = 0x98 + 24;
        b[fname + 56] = 0x20;
        b[fname + 64] = 3;
        put(&mut b, fname + 66, &[b'a', 0, b'b', 0, b'c', 0]);
        attr(&mut b, 0x100, 0x80, 0x50);
        b[0x100 + 9] = 2;
        put(&mut b, 0x100 + 10, &0x40u16.to_le_bytes());
        put(&mut b, 0x100 + 0x40, &[b'x', 0, b'y', 0]);
        put(&mut b, 0x100 + 16, &4u32.to_le_bytes());
        put(&mut b, 0x100 + 20, &0x48u16.to_le_bytes());
        put(&mut b, 0x100 + 0x48, b"DATA");
        attr(&mut b, 0x150, 0x80, 0);
        put(&mut b, 0x150 + 16, &0u32.to_le_bytes());
        b[0x150 + 0x60] = 0xff; // never reached: Length 0 ends the walk
        let l = Buf(b);
        let e = MftEntry::new(&l, 0);
        assert_eq!(e.get_signature().unwrap(), "FILE");
        assert_eq!(e.record_number().unwrap(), 77);
        let types: Vec<u8> = e.attributes().unwrap().map(|a| a.attr_type).collect();
        assert_eq!(types, vec![0x10, 0x30, 0x80, 0x80]);
        assert_eq!(e.longest_filename().unwrap().as_deref(), Some("abc"));
        let ads: Vec<_> = e.alternate_data_streams().map(|a| a.unwrap().offset).collect();
        assert_eq!(ads, vec![0x100]);
        let a = MftAttribute { layer: &l, offset: 0x100, attr_type: 0x80 };
        assert_eq!(a.get_resident_filename().unwrap().as_deref(), Some("xy"));
        assert_eq!(a.get_resident_filecontent().unwrap().unwrap(), (0x148, b"DATA".to_vec()));
        let res: Vec<_> = e.resident_data_attributes().map(|a| a.unwrap().offset).collect();
        assert_eq!(res, vec![0x150]);
    }
}
