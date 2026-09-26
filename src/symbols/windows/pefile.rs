//! A faithful port of the parts of the python `pefile` module (version 2024.8.26) that
//! volatility3 plugins use: `pefile.PE(data=..., fast_load=True)` (DOS / NT / file / optional
//! headers, data directories, sections) followed by `parse_data_directories([...])` for the
//! export, import and resource directories (plus `VS_FIXEDFILEINFO` from the version
//! resource).
//!
//! Byte-identical plugin output depends on pefile's exact behaviour on smeared or partial
//! images (which entries it keeps, where it gives up, which errors escape), so the control flow
//! below mirrors pefile line by line, including its section lookup cache, its python slice
//! semantics and its global limits. Pure warnings are not reproduced.
//!
//! The data is accessed through [`PeData`], so a PE carved from memory can be parsed lazily:
//! [`crate::symbols::windows::pe::reconstruct_view`] gives a view that only reads the pages
//! pefile actually touches (a few pages per module instead of the whole image).
//!
//! ```ignore
//! let (view, err) = pe::reconstruct_view(&dos);
//! let pe = PeFile::parse(&view)?;                    // pefile.PE(data=..., fast_load=True)
//! if let Some(exports) = pe.parse_exports()? { for e in &exports.symbols { .. } }
//! for desc in pe.parse_imports()?.unwrap_or_default() { .. }
//! let fixed = pe.parse_version_info()?;              // VS_FIXEDFILEINFO list
//! ```
//!
//! Derived from pefile (MIT license, Copyright (c) 2005-2024 Ero Carrera) as used by
//! Volatility 3 (Volatility Software License 1.0).

use std::borrow::Cow;
use std::cell::Cell;

use super::pefile_ord;

/// pefile limits.
pub const MAX_STRING_LENGTH: i64 = 0x100000;
pub const MAX_IMPORT_SYMBOLS: u32 = 0x2000;
pub const MAX_IMPORT_NAME_LENGTH: i64 = 0x200;
pub const MAX_DLL_LENGTH: i64 = 0x200;
pub const MAX_SYMBOL_NAME_LENGTH: i64 = 0x200;
pub const MAX_SECTIONS: u32 = 0x800;
pub const MAX_RESOURCE_ENTRIES: u64 = 0x8000;
pub const MAX_RESOURCE_DEPTH: u32 = 32;
pub const MAX_SYMBOL_EXPORT_COUNT: usize = 0x2000;
pub const MAX_REPEATED_SYMBOL: u32 = 120;

pub const OPTIONAL_HEADER_MAGIC_PE: u16 = 0x10B;
pub const OPTIONAL_HEADER_MAGIC_PE_PLUS: u16 = 0x20B;
const IMAGE_ORDINAL_FLAG: u64 = 0x8000_0000;
const IMAGE_ORDINAL_FLAG64: u64 = 0x8000_0000_0000_0000;

/// `pefile.DIRECTORY_ENTRY` indices used here.
pub const DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const DIRECTORY_ENTRY_RESOURCE: usize = 2;

const RT_VERSION: u32 = 16;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

/// Errors that escape pefile calls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeError {
    /// `pefile.PEFormatError` (message as python formats it).
    Format(String),
    /// A python `AttributeError` raised inside pefile (e.g. `is_driver()` called while the
    /// sections are still being parsed).
    Attribute(String),
}

impl std::fmt::Display for PeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeError::Format(m) => write!(f, "PEFormatError: {m}"),
            PeError::Attribute(m) => write!(f, "AttributeError: {m}"),
        }
    }
}

type PeResult<T> = std::result::Result<T, PeError>;

fn fmt_err<T>(m: impl Into<String>) -> PeResult<T> {
    Err(PeError::Format(m.into()))
}

/// The bytes pefile parses (python's `__data__`).
pub trait PeData {
    /// `len(__data__)`.
    fn len(&self) -> usize;
    /// `__data__[a:b]` for `0 <= a <= b <= len()`.
    fn bytes(&self, a: usize, b: usize) -> Cow<'_, [u8]>;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl PeData for [u8] {
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }
    fn bytes(&self, a: usize, b: usize) -> Cow<'_, [u8]> {
        Cow::Borrowed(&self[a..b])
    }
}

impl PeData for Vec<u8> {
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }
    fn bytes(&self, a: usize, b: usize) -> Cow<'_, [u8]> {
        Cow::Borrowed(&self[a..b])
    }
}

/// python slice bounds `x[start:end]` for a sequence of length `n`.
#[inline]
pub fn py_range(n: usize, start: i64, end: Option<i64>) -> (usize, usize) {
    let n = n as i64;
    let clamp = |v: i64| -> i64 {
        if v < 0 {
            (v + n).max(0)
        } else {
            v.min(n)
        }
    };
    let s = clamp(start);
    let e = end.map(clamp).unwrap_or(n);
    if e <= s { (s as usize, s as usize) } else { (s as usize, e as usize) }
}

#[inline]
fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
#[inline]
fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
#[inline]
fn le64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// `get_word_from_data(data, offset)`.
#[inline]
fn word_from_data(d: &[u8], i: i64) -> Option<u16> {
    if i < 0 || (i + 1) * 2 > d.len() as i64 {
        return None;
    }
    Some(le16(d, i as usize * 2))
}

/// `get_dword_from_data(data, offset)`.
#[inline]
fn dword_from_data(d: &[u8], i: i64) -> Option<u32> {
    if i < 0 || (i + 1) * 4 > d.len() as i64 {
        return None;
    }
    Some(le32(d, i as usize * 4))
}

/// `Structure.all_zeroes()` of the unpacked bytes.
#[inline]
fn all_zero(b: &[u8]) -> bool {
    b.iter().all(|&c| c == 0)
}

/// `is_valid_function_name(s, relax_allowed_characters)`.
pub fn is_valid_function_name(s: Option<&[u8]>, relax: bool) -> bool {
    let Some(s) = s else { return false };
    let extra: &[u8] = if relax { b"!\"#$%&'()*+,-./:<>?[\\]^_`{|}~@" } else { b"._?@$()<>" };
    s.iter().all(|c| c.is_ascii_alphanumeric() || extra.contains(c))
}

/// `is_valid_dos_filename(s)`.
pub fn is_valid_dos_filename(s: Option<&[u8]>) -> bool {
    let Some(s) = s else { return false };
    s.iter().all(|c| c.is_ascii_alphanumeric() || b"!#$%&'()-@^_`{}~+,.;=[]:\\/".contains(c))
}

/// `ordlookup.ordLookup(libname, ord_val)` (make_name=False).
pub fn ord_lookup(libname_lower: &[u8], ord_val: u64) -> Option<Vec<u8>> {
    let table: &[(u16, &str)] = match libname_lower {
        b"oleaut32.dll" => pefile_ord::OLEAUT32,
        b"ws2_32.dll" => pefile_ord::WS2_32,
        b"wsock32.dll" => pefile_ord::WSOCK32,
        _ => return None,
    };
    if ord_val <= u16::MAX as u64 {
        if let Ok(i) = table.binary_search_by_key(&(ord_val as u16), |e| e.0) {
            return Some(table[i].1.as_bytes().to_vec());
        }
    }
    Some(format!("ord{ord_val}").into_bytes())
}

/// `IMAGE_FILE_HEADER`.
#[derive(Clone, Copy, Debug, Default)]
pub struct FileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

/// `IMAGE_OPTIONAL_HEADER` / `IMAGE_OPTIONAL_HEADER64` (fields used here).
#[derive(Clone, Copy, Debug, Default)]
pub struct OptionalHeader {
    pub magic: u16,
    pub address_of_entry_point: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub number_of_rva_and_sizes: u32,
    /// `OPTIONAL_HEADER.sizeof()` (96 or 112).
    pub struct_size: u32,
}

/// `IMAGE_SECTION_HEADER` (a `SectionStructure`), with pefile's derived values.
#[derive(Clone, Debug)]
pub struct Section {
    pub name: [u8; 8],
    pub misc_virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub characteristics: u32,
    /// `get_PointerToRawData_adj()`
    ptrd_adj: i64,
    /// `get_VirtualAddress_adj()`
    va_adj: i64,
    /// `contains_rva` bounds (`section_min_addr`, `section_max_addr`)
    min_addr: i64,
    max_addr: i64,
}

impl Section {
    #[inline]
    fn contains_rva(&self, rva: i64) -> bool {
        self.min_addr <= rva && rva < self.max_addr
    }
}

/// One export (`pefile.ExportData`), as far as the plugins look at it.
#[derive(Clone, Debug)]
pub struct Export {
    pub ordinal: i64,
    /// RVA of the symbol (`None` when pefile stored `None`, see the ordinal-only loop).
    pub address: Option<u32>,
    /// Symbol name (`None` for ordinal-only exports).
    pub name: Option<Vec<u8>>,
    pub forwarder: Option<Vec<u8>>,
}

/// `pefile.ExportDirData`.
#[derive(Clone, Debug, Default)]
pub struct ExportDir {
    pub symbols: Vec<Export>,
}

/// One imported symbol (`pefile.ImportData`).
#[derive(Clone, Debug)]
pub struct Import {
    /// Ordinal when imported by ordinal.
    pub ordinal: Option<u64>,
    /// Name (python bytes); for imports by ordinal pefile may fill in an `ordlookup` name.
    pub name: Option<Vec<u8>>,
    /// `first_thunk + ImageBase + idx * thunk_size` (python int).
    pub address: u128,
    pub hint: Option<u16>,
}

/// `pefile.ImportDescData`.
#[derive(Clone, Debug)]
pub struct ImportDesc {
    pub dll: Vec<u8>,
    pub time_date_stamp: u32,
    pub original_first_thunk: u32,
    pub first_thunk: u32,
    pub imports: Vec<Import>,
}

/// `VS_FIXEDFILEINFO`.
#[derive(Clone, Copy, Debug, Default)]
pub struct FixedFileInfo {
    pub signature: u32,
    pub struc_version: u32,
    pub file_version_ms: u32,
    pub file_version_ls: u32,
    pub product_version_ms: u32,
    pub product_version_ls: u32,
    pub file_flags_mask: u32,
    pub file_flags: u32,
    pub file_os: u32,
    pub file_type: u32,
    pub file_subtype: u32,
    pub file_date_ms: u32,
    pub file_date_ls: u32,
}

/// A resource directory entry recorded while parsing the RT_VERSION subtree.
enum ResEntry {
    /// `entry.directory.entries`
    Dir(Vec<ResEntry>),
    /// `entry.data.struct` (OffsetToData, Size)
    Leaf(i64, i64),
}

/// A parsed PE (`pefile.PE(data=..., fast_load=True)`).
pub struct PeFile<'a, D: PeData + ?Sized> {
    data: &'a D,
    len: i64,
    /// `PE_TYPE` (None for an invalid optional header magic).
    pub pe_type: Option<u16>,
    pub e_lfanew: u32,
    pub file_header: FileHeader,
    pub optional_header: OptionalHeader,
    /// `OPTIONAL_HEADER.DATA_DIRECTORY` as (VirtualAddress, Size).
    pub data_directories: Vec<(u32, u32)>,
    /// Sections sorted by VirtualAddress (like pefile).
    pub sections: Vec<Section>,
    /// `len(self.header)`
    header_len: i64,
    /// `_get_section_by_rva_last_used`
    last_used: Cell<Option<usize>>,
    /// `__total_import_symbols`
    total_import_symbols: Cell<u32>,
    /// `__total_resource_entries_count`
    total_resource_entries: Cell<u64>,
    /// `hasattr(self, "DIRECTORY_ENTRY_IMPORT")` set by an earlier parse
    import_parsed: Cell<bool>,
}

/// `cache_adjust_SectionAlignment(val, section_alignment, file_alignment)`.
#[inline]
fn adjust_section_alignment(val: i64, section_alignment: u32, file_alignment: u32) -> i64 {
    let sa = if section_alignment < 0x1000 { file_alignment } else { section_alignment } as i64;
    if sa != 0 && val % sa != 0 {
        return sa * (val / sa);
    }
    val
}

/// `adjust_PointerToRawData(val)`.
#[inline]
fn adjust_pointer_to_raw_data(val: i64) -> i64 {
    val & !0x1FF
}

/// `dword_align(offset, base)`.
#[inline]
fn dword_align(offset: i64, base: i64) -> i64 {
    ((offset + base + 3) & 0xFFFF_FFFC) - (base & 0xFFFF_FFFC)
}

impl<'a, D: PeData + ?Sized> PeFile<'a, D> {
    /// `__data__[a:b]` with python slice semantics.
    #[inline]
    fn slice(&self, start: i64, end: Option<i64>) -> Cow<'a, [u8]> {
        let (a, b) = py_range(self.data.len(), start, end);
        self.data.bytes(a, b)
    }

    /// `pefile.PE(data=data, fast_load=True)`.
    pub fn parse(data: &'a D) -> PeResult<PeFile<'a, D>> {
        let len = data.len() as i64;
        let mut pe = PeFile {
            data,
            len,
            pe_type: None,
            e_lfanew: 0,
            file_header: FileHeader::default(),
            optional_header: OptionalHeader::default(),
            data_directories: Vec::new(),
            sections: Vec::new(),
            header_len: 0,
            last_used: Cell::new(None),
            total_import_symbols: Cell::new(0),
            total_resource_entries: Cell::new(0),
            import_parsed: Cell::new(false),
        };
        let dos = pe.slice(0, Some(64));
        if dos.len() != 64 {
            return fmt_err("Unable to read the DOS Header, possibly a truncated file.");
        }
        let e_magic = le16(&dos, 0);
        if e_magic == 0x4D5A {
            return fmt_err("Probably a ZM Executable (not a PE file).");
        }
        if e_magic != 0x5A4D {
            return fmt_err("DOS Header magic not found.");
        }
        let e_lfanew = le32(&dos, 60);
        pe.e_lfanew = e_lfanew;
        if e_lfanew as i64 > len {
            return fmt_err("Invalid e_lfanew value, probably not a PE file");
        }
        let nt = e_lfanew as i64;
        let nt_data = pe.slice(nt, Some(nt + 8));
        let sig = if nt_data.len() >= 4 { le32(&nt_data, 0) } else { 0 };
        if sig == 0 {
            return fmt_err("NT Headers not found.");
        }
        match sig & 0xFFFF {
            0x454E => return fmt_err("Invalid NT Headers signature. Probably a NE file"),
            0x454C => return fmt_err("Invalid NT Headers signature. Probably a LE file"),
            0x584C => return fmt_err("Invalid NT Headers signature. Probably a LX file"),
            0x5A56 => return fmt_err("Invalid NT Headers signature. Probably a TE file"),
            _ => {}
        }
        if sig != 0x4550 {
            return fmt_err("Invalid NT Headers signature.");
        }
        let fh = pe.slice(nt + 4, Some(nt + 4 + 32));
        if fh.len() < 20 {
            return fmt_err("File Header missing");
        }
        pe.file_header = FileHeader {
            machine: le16(&fh, 0),
            number_of_sections: le16(&fh, 2),
            time_date_stamp: le32(&fh, 4),
            size_of_optional_header: le16(&fh, 16),
            characteristics: le16(&fh, 18),
        };
        let opt_off = nt + 4 + 20;
        let sections_offset = opt_off + pe.file_header.size_of_optional_header as i64;

        // the 32-bit optional header (padded with zeros when at least 69 bytes are there)
        let parse_opt = |b: &[u8], is64: bool| -> OptionalHeader {
            if is64 {
                OptionalHeader {
                    magic: le16(b, 0),
                    address_of_entry_point: le32(b, 16),
                    image_base: le64(b, 24),
                    section_alignment: le32(b, 32),
                    file_alignment: le32(b, 36),
                    size_of_image: le32(b, 56),
                    size_of_headers: le32(b, 60),
                    number_of_rva_and_sizes: le32(b, 108),
                    struct_size: 112,
                }
            } else {
                OptionalHeader {
                    magic: le16(b, 0),
                    address_of_entry_point: le32(b, 16),
                    image_base: le32(b, 28) as u64,
                    section_alignment: le32(b, 32),
                    file_alignment: le32(b, 36),
                    size_of_image: le32(b, 56),
                    size_of_headers: le32(b, 60),
                    number_of_rva_and_sizes: le32(b, 92),
                    struct_size: 96,
                }
            }
        };
        let unpack_opt = |pe: &PeFile<'a, D>, primary: Cow<'a, [u8]>, is64: bool, min_raw: usize| -> Option<OptionalHeader> {
            let need = if is64 { 112 } else { 96 };
            if primary.len() >= need {
                return Some(parse_opt(&primary, is64));
            }
            let raw = pe.slice(opt_off, Some(opt_off + 0x200));
            if raw.len() >= min_raw {
                let mut padded = raw.into_owned();
                padded.extend_from_slice(&[0u8; 128]);
                if padded.len() >= need {
                    return Some(parse_opt(&padded, is64));
                }
            }
            None
        };
        let mut opt = unpack_opt(&pe, pe.slice(opt_off, Some(opt_off + 256)), false, 69);
        if let Some(o) = opt {
            if o.magic == OPTIONAL_HEADER_MAGIC_PE {
                pe.pe_type = Some(OPTIONAL_HEADER_MAGIC_PE);
            } else if o.magic == OPTIONAL_HEADER_MAGIC_PE_PLUS {
                pe.pe_type = Some(OPTIONAL_HEADER_MAGIC_PE_PLUS);
                opt = unpack_opt(&pe, pe.slice(opt_off, Some(opt_off + 0x200)), true, 73);
            }
        }
        let Some(opt) = opt else {
            return fmt_err("No Optional Header found, invalid PE32 or PE32+ file.");
        };
        pe.optional_header = opt;

        // data directories
        let mut offset = opt_off + opt.struct_size as i64;
        let nrva = (opt.number_of_rva_and_sizes & 0x7FFF_FFFF) as i64;
        let mut i = 0i64;
        while i < nrva {
            if len - offset == 0 {
                break;
            }
            let entry: Vec<u8> = if len - offset < 8 {
                let mut d = pe.slice(offset, None).into_owned();
                d.extend_from_slice(&[0u8; 8]);
                d
            } else {
                pe.slice(offset, Some(offset + 0x100)).into_owned()
            };
            if entry.len() < 8 {
                break;
            }
            if i >= 16 {
                break; // DIRECTORY_ENTRY[i] KeyError
            }
            pe.data_directories.push((le32(&entry, 0), le32(&entry, 4)));
            offset += 8;
            if offset >= opt_off + opt.struct_size as i64 + 8 * 16 {
                break;
            }
            i += 1;
        }

        let offset = pe.parse_sections(sections_offset)?;

        let lowest = pe
            .sections
            .iter()
            .filter(|s| s.pointer_to_raw_data > 0)
            .map(|s| adjust_pointer_to_raw_data(s.pointer_to_raw_data as i64))
            .min();
        let hdr_end = match lowest {
            Some(l) if l != 0 && l >= offset => l,
            _ => offset,
        };
        pe.header_len = py_range(pe.data.len(), 0, Some(hdr_end)).1 as i64;
        Ok(pe)
    }

    /// `parse_sections(offset)`; returns the offset after the section table.
    fn parse_sections(&mut self, offset: i64) -> PeResult<i64> {
        let opt = self.optional_header;
        for i in 0..self.file_header.number_of_sections as u32 {
            if i >= MAX_SECTIONS {
                break;
            }
            let so = offset + 40 * i as i64;
            let sd = self.slice(so, Some(so + 40));
            if sd.len() == 40 && all_zero(&sd) {
                break;
            }
            if sd.is_empty() {
                break;
            }
            if sd.len() < 40 {
                return fmt_err("Data length less than expected header length.");
            }
            let mut name = [0u8; 8];
            name.copy_from_slice(&sd[..8]);
            let vs = le32(&sd, 8);
            let va = le32(&sd, 12);
            let srd = le32(&sd, 16);
            let ptrd = le32(&sd, 20);
            let ch = le32(&sd, 36);
            let mut errors = 0;
            if srd as i64 + ptrd as i64 > self.len {
                errors += 1;
            }
            if adjust_pointer_to_raw_data(ptrd as i64) > self.len {
                errors += 1;
            }
            if vs > 0x1000_0000 {
                errors += 1;
            }
            if adjust_section_alignment(va as i64, opt.section_alignment, opt.file_alignment) > 0x1000_0000 {
                errors += 1;
            }
            if opt.file_alignment != 0 && ptrd % opt.file_alignment != 0 {
                errors += 1;
            }
            if errors >= 3 {
                break;
            }
            if ch & IMAGE_SCN_MEM_WRITE != 0 && ch & IMAGE_SCN_MEM_EXECUTE != 0 {
                let trimmed: &[u8] = {
                    let mut e = 8;
                    while e > 0 && name[e - 1] == 0 {
                        e -= 1;
                    }
                    &name[..e]
                };
                if trimmed == b"PAGE" {
                    // `self.is_driver()` runs parse_data_directories(IMPORT) while the section
                    // list is incomplete: python raises AttributeError (the sections lack
                    // `next_section_virtual_address`, or `self.header` does not exist yet)
                    // whenever the import directory has a non-zero RVA.
                    if let Some(&(iva, _)) = self.data_directories.get(DIRECTORY_ENTRY_IMPORT) {
                        if iva != 0 {
                            return Err(PeError::Attribute("'SectionStructure' object has no attribute 'next_section_virtual_address'".into()));
                        }
                    }
                }
            }
            let mut ptrd_adj = adjust_pointer_to_raw_data(ptrd as i64);
            if opt.section_alignment < 0x1000 && ptrd == va {
                ptrd_adj = va as i64;
            }
            let va_adj = adjust_section_alignment(va as i64, opt.section_alignment, opt.file_alignment);
            self.sections.push(Section {
                name,
                misc_virtual_size: vs,
                virtual_address: va,
                size_of_raw_data: srd,
                pointer_to_raw_data: ptrd,
                characteristics: ch,
                ptrd_adj,
                va_adj,
                min_addr: 0,
                max_addr: 0,
            });
        }
        // stable sort by VirtualAddress, then the contains_rva bounds
        self.sections.sort_by_key(|s| s.virtual_address);
        let n = self.sections.len();
        for idx in 0..n {
            let next = if idx + 1 < n { Some(self.sections[idx + 1].virtual_address as i64) } else { None };
            let s = &mut self.sections[idx];
            let mut size = if self.len - s.ptrd_adj < s.size_of_raw_data as i64 {
                s.misc_virtual_size as i64
            } else {
                (s.size_of_raw_data as i64).max(s.misc_virtual_size as i64)
            };
            if let Some(nv) = next {
                if nv > s.virtual_address as i64 && s.va_adj + size > nv {
                    size = nv - s.va_adj;
                }
            }
            s.min_addr = s.va_adj;
            s.max_addr = s.va_adj + size;
        }
        if self.file_header.number_of_sections > 0 && !self.sections.is_empty() {
            Ok(offset + 40 * self.file_header.number_of_sections as i64)
        } else {
            Ok(offset)
        }
    }

    /// `get_section_by_rva(rva)` (with pefile's last-used cache).
    fn section_by_rva(&self, rva: i64) -> Option<usize> {
        if let Some(i) = self.last_used.get() {
            if self.sections[i].contains_rva(rva) {
                return Some(i);
            }
        }
        for (i, s) in self.sections.iter().enumerate() {
            if s.contains_rva(rva) {
                self.last_used.set(Some(i));
                return Some(i);
            }
        }
        None
    }

    /// `SectionStructure.get_data(start, length)`.
    fn section_data(&self, s: &Section, start: Option<i64>, length: Option<i64>) -> Cow<'a, [u8]> {
        let offset = match start {
            None => s.ptrd_adj,
            Some(st) => (st - s.va_adj) + s.ptrd_adj,
        };
        let mut end = match length {
            Some(l) => offset + l,
            None => offset + s.size_of_raw_data as i64,
        };
        let lim = s.pointer_to_raw_data as i64 + s.size_of_raw_data as i64;
        if end > lim {
            end = lim;
        }
        self.slice(offset, Some(end))
    }

    /// `get_data(rva, length)`.
    pub fn get_data(&self, rva: i64, length: Option<i64>) -> PeResult<Cow<'a, [u8]>> {
        let end = length.map(|l| rva + l);
        match self.section_by_rva(rva) {
            Some(i) => Ok(self.section_data(&self.sections[i], Some(rva), length)),
            None => {
                if rva < self.header_len {
                    // self.header[rva:end] (header = data[:header_len])
                    let (a, b) = py_range(self.header_len as usize, rva, end);
                    return Ok(self.data.bytes(a, b));
                }
                if rva < self.len {
                    return Ok(self.slice(rva, end));
                }
                fmt_err("data at RVA can't be fetched. Corrupt header?")
            }
        }
    }

    /// `get_offset_from_rva(rva)`.
    pub fn get_offset_from_rva(&self, rva: i64) -> PeResult<i64> {
        match self.section_by_rva(rva) {
            Some(i) => {
                let s = &self.sections[i];
                Ok(rva - s.va_adj + s.ptrd_adj)
            }
            None => {
                if rva < self.len {
                    Ok(rva)
                } else {
                    fmt_err(format!("data at RVA 0x{rva:x} can't be fetched"))
                }
            }
        }
    }

    /// Bytes of `__data__[a:b]` (python slice) up to the first NUL.
    fn cstr_in(&self, start: i64, end: Option<i64>) -> Vec<u8> {
        let (a, b) = py_range(self.data.len(), start, end);
        let mut out = Vec::new();
        let mut pos = a;
        while pos < b {
            // read in page-sized pieces: most strings are short
            let stop = ((pos & !0xFFF) + 0x1000).min(b);
            let chunk = self.data.bytes(pos, stop);
            if let Some(z) = chunk.iter().position(|&c| c == 0) {
                out.extend_from_slice(&chunk[..z]);
                return out;
            }
            out.extend_from_slice(&chunk);
            pos = stop;
        }
        out
    }

    /// `get_string_at_rva(rva, max_length)`.
    pub fn get_string_at_rva(&self, rva: Option<i64>, max_length: i64) -> Option<Vec<u8>> {
        let rva = rva?;
        Some(match self.section_by_rva(rva) {
            None => self.cstr_in(rva, Some(rva + max_length)),
            Some(i) => {
                let s = &self.sections[i];
                // s.get_data(rva, length=max_length), then up to the first NUL
                let offset = (rva - s.va_adj) + s.ptrd_adj;
                let mut end = offset + max_length;
                let lim = s.pointer_to_raw_data as i64 + s.size_of_raw_data as i64;
                if end > lim {
                    end = lim;
                }
                self.cstr_in(offset, Some(end))
            }
        })
    }

    /// `get_string_u_at_rva(rva, max_length)` as UTF-16 code units (before python's
    /// `encode(..., "backslashreplace_")`).
    pub fn get_string_u_at_rva(&self, rva: i64, max_length: i64) -> PeResult<Vec<u16>> {
        if max_length == 0 {
            return Ok(Vec::new());
        }
        self.get_data(rva, Some(2))?;
        let max_length = max_length << 1;
        let mut requested = max_length.min(256);
        let mut data = self.get_data(rva, Some(requested))?.into_owned();
        let mut null_index: i64 = -1;
        loop {
            let from = (null_index + 1).max(0) as usize;
            let found = if from <= data.len() { data[from..].windows(2).position(|w| w == [0, 0]).map(|p| (p + from) as i64) } else { None };
            match found {
                None => {
                    let dl = data.len() as i64;
                    if dl < requested || dl == max_length {
                        null_index = dl >> 1;
                        break;
                    }
                    let more = self.get_data(rva + dl, Some(max_length - dl))?;
                    data.extend_from_slice(&more);
                    null_index = requested - 1;
                    requested = max_length;
                }
                Some(ni) => {
                    null_index = ni;
                    if ni % 2 == 0 {
                        null_index >>= 1;
                        break;
                    }
                }
            }
        }
        let n = (null_index.max(0) as usize).min(data.len() / 2);
        Ok((0..n).map(|i| le16(&data, i * 2)).collect())
    }

    /// python `parse_data_directories(directories=[index])` for the export directory:
    /// `DIRECTORY_ENTRY_EXPORT` (None when pefile did not set the attribute).
    pub fn parse_exports(&self) -> Option<ExportDir> {
        // directory_parsing order: IMPORT, EXPORT, ...: an IndexError on IMPORT stops everything
        if self.data_directories.len() <= DIRECTORY_ENTRY_EXPORT.max(DIRECTORY_ENTRY_IMPORT) {
            return None;
        }
        let (va, size) = self.data_directories[DIRECTORY_ENTRY_EXPORT];
        if va == 0 {
            return None;
        }
        match self.parse_export_directory(va as i64, size as i64) {
            Ok(v) => v,
            Err(_) => None, // PEFormatError -> warning
        }
    }

    /// python `parse_data_directories(directories=[IMPORT])`: `DIRECTORY_ENTRY_IMPORT` if it
    /// was set (a non-empty list).
    pub fn parse_imports(&self) -> Option<Vec<ImportDesc>> {
        let &(va, size) = self.data_directories.get(DIRECTORY_ENTRY_IMPORT)?;
        if va == 0 {
            return None;
        }
        match self.parse_import_directory(va as i64, size as i64) {
            Ok(v) if !v.is_empty() => {
                self.import_parsed.set(true);
                Some(v)
            }
            _ => None,
        }
    }

    /// python `parse_data_directories(directories=[RESOURCE])` followed by
    /// `pe.VS_FIXEDFILEINFO`: the fixed version infos found (empty = AttributeError).
    pub fn parse_version_info(&self) -> Vec<FixedFileInfo> {
        let mut out = Vec::new();
        if self.data_directories.len() <= DIRECTORY_ENTRY_RESOURCE {
            return out;
        }
        let (va, size) = self.data_directories[DIRECTORY_ENTRY_RESOURCE];
        if va == 0 {
            return out;
        }
        let mut dirs = vec![va as i64];
        // PEFormatError from inside the resource parse -> warning (VS_FIXEDFILEINFO found so
        // far stays set)
        let _ = self.parse_resources_directory(va as i64, size as i64, va as i64, 0, &mut dirs, &mut out, false);
        out
    }

    fn parse_export_directory(&self, rva: i64, size: i64) -> PeResult<Option<ExportDir>> {
        let hdr = match self.get_data(rva, Some(40)).and_then(|d| self.get_offset_from_rva(rva).map(|_| d)) {
            Ok(d) => d,
            Err(_) => return Ok(None),
        };
        if hdr.len() < 40 {
            return Ok(None);
        }
        let hdr_zero = all_zero(&hdr[..40]);
        let name_rva = le32(&hdr, 12) as i64;
        let base = le32(&hdr, 16) as i64;
        let number_of_functions = le32(&hdr, 20) as i64;
        let number_of_names = le32(&hdr, 24) as i64;
        let address_of_functions = le32(&hdr, 28) as i64;
        let address_of_names = le32(&hdr, 32) as i64;
        let address_of_name_ordinals = le32(&hdr, 36) as i64;
        let _ = name_rva;

        let length_until_eof = |r: i64| -> PeResult<i64> { Ok(self.len - self.get_offset_from_rva(r)?) };
        let arrays = (|| -> PeResult<(Cow<'a, [u8]>, Cow<'a, [u8]>, Cow<'a, [u8]>)> {
            let names = self.get_data(address_of_names, Some(length_until_eof(address_of_names)?.min(number_of_names * 4)))?;
            let ords = self.get_data(address_of_name_ordinals, Some(length_until_eof(address_of_name_ordinals)?.min(number_of_names * 4)))?;
            let funcs = self.get_data(address_of_functions, Some(length_until_eof(address_of_functions)?.min(number_of_functions * 4)))?;
            Ok((names, ords, funcs))
        })();
        let Ok((names, ords, funcs)) = arrays else { return Ok(None) };

        let mut exports: Vec<Export> = Vec::new();
        let mut max_failed = 10i32;
        let safety = |at: i64| -> i64 {
            match self.section_by_rva(at) {
                Some(i) => {
                    let s = &self.sections[i];
                    s.virtual_address as i64 + self.section_data(s, None, None).len() as i64 - at
                }
                None => self.len,
            }
        };
        // int(safety_boundary / 4): truncation toward zero
        let trunc4 = |v: i64| -> i64 { v / 4 };

        let safety_boundary = safety(address_of_names);
        let mut counts: crate::util::FxHashMap<(Vec<u8>, u32), u32> = Default::default();
        let mut completed = true;
        let n1 = number_of_names.min(trunc4(safety_boundary));
        let mut i = 0i64;
        while i < n1 {
            let symbol_ordinal = word_from_data(&ords, i);
            let symbol_address = match symbol_ordinal {
                Some(o) if (o as i64) * 4 < funcs.len() as i64 => dword_from_data(&funcs, o as i64),
                _ => return Ok(None),
            };
            let symbol_ordinal = symbol_ordinal.unwrap() as i64;
            let symbol_address = match symbol_address {
                None | Some(0) => {
                    i += 1;
                    continue;
                }
                Some(a) => a,
            };
            let forwarder = if (symbol_address as i64) >= rva && (symbol_address as i64) < rva + size {
                let f = self.get_string_at_rva(Some(symbol_address as i64), MAX_STRING_LENGTH);
                if self.get_offset_from_rva(symbol_address as i64).is_err() {
                    i += 1;
                    continue;
                }
                f
            } else {
                None
            };
            let name_addr = dword_from_data(&names, i);
            if name_addr.is_none() {
                max_failed -= 1;
                if max_failed <= 0 {
                    completed = false;
                    break;
                }
            }
            let symbol_name = self.get_string_at_rva(name_addr.map(|a| a as i64), MAX_SYMBOL_NAME_LENGTH);
            if !is_valid_function_name(symbol_name.as_deref(), true) {
                completed = false;
                break;
            }
            let symbol_name = symbol_name.unwrap();
            let name_addr = name_addr.unwrap() as i64;
            if self.get_offset_from_rva(name_addr).is_err() {
                max_failed -= 1;
                if max_failed <= 0 {
                    completed = false;
                    break;
                }
                // python retries the same lookup, which fails again
                max_failed -= 1;
                if max_failed <= 0 {
                    completed = false;
                    break;
                }
                i += 1;
                continue;
            }
            let key = (symbol_name.clone(), symbol_address);
            let c = counts.entry(key).or_insert(0);
            *c += 1;
            if *c > 10 {
                break;
            } else if counts.len() > MAX_SYMBOL_EXPORT_COUNT {
                break;
            }
            // ExportData(ordinal_offset=..., address_offset=...) may raise PEFormatError
            self.get_offset_from_rva(address_of_name_ordinals + 2 * i)?;
            self.get_offset_from_rva(address_of_functions + 4 * symbol_ordinal)?;
            exports.push(Export { ordinal: base + symbol_ordinal, address: Some(symbol_address), name: Some(symbol_name), forwarder });
            i += 1;
        }
        let _ = completed;

        let ordinals: crate::util::FxHashSet<i64> = exports.iter().map(|e| e.ordinal).collect();
        let mut max_failed = 10i32;
        let safety_boundary = safety(address_of_functions);
        let mut counts2: crate::util::FxHashMap<Option<u32>, u32> = Default::default();
        let mut completed = true;
        let n2 = number_of_functions.min(trunc4(safety_boundary));
        for idx in 0..n2.max(0) {
            if ordinals.contains(&(idx + base)) {
                continue;
            }
            let symbol_address = dword_from_data(&funcs, idx);
            if symbol_address.is_none() {
                max_failed -= 1;
                if max_failed <= 0 {
                    completed = false;
                    break;
                }
            }
            if symbol_address == Some(0) {
                continue;
            }
            let forwarder = match symbol_address {
                Some(a) if (a as i64) >= rva && (a as i64) < rva + size => self.get_string_at_rva(Some(a as i64), MAX_STRING_LENGTH),
                _ => None,
            };
            let c = counts2.entry(symbol_address).or_insert(0);
            *c += 1;
            if *c > MAX_REPEATED_SYMBOL {
                break;
            } else if counts2.len() > MAX_SYMBOL_EXPORT_COUNT {
                break;
            }
            exports.push(Export { ordinal: base + idx, address: symbol_address, name: None, forwarder });
        }
        if !completed {
            return Ok(None);
        }
        if exports.is_empty() && hdr_zero {
            return Ok(None);
        }
        // ExportDirData(name=self.get_string_at_rva(export_dir.Name)) cannot raise
        Ok(Some(ExportDir { symbols: exports }))
    }

    /// `parse_import_directory(rva, size)`.
    fn parse_import_directory(&self, mut rva: i64, _size: i64) -> PeResult<Vec<ImportDesc>> {
        let mut descs = Vec::new();
        let mut error_count = 0;
        loop {
            let data = match self.get_data(rva, Some(20)) {
                Ok(d) => d,
                Err(_) => break,
            };
            let file_offset = self.get_offset_from_rva(rva)?;
            if data.len() < 20 || all_zero(&data[..20]) {
                break;
            }
            let oft = le32(&data, 0) as i64;
            let tds = le32(&data, 4);
            let fc = le32(&data, 8);
            let name = le32(&data, 12) as i64;
            let ft = le32(&data, 16) as i64;
            rva += 20;
            let mut max_len = self.len - file_offset;
            if rva > oft || rva > ft {
                max_len = (rva - oft).max(rva - ft);
            }
            let import_data = self.parse_imports_of(oft, ft, fc, Some(max_len)).unwrap_or_default();
            if error_count > 5 {
                break;
            }
            if import_data.is_empty() {
                error_count += 1;
                continue;
            }
            let mut dll = self.get_string_at_rva(Some(name), MAX_DLL_LENGTH);
            if !is_valid_dos_filename(dll.as_deref()) {
                dll = Some(b"*invalid*".to_vec());
            }
            let dll = dll.unwrap_or_default();
            if !dll.is_empty() {
                let lower = dll.to_ascii_lowercase();
                let mut imports = import_data;
                for sym in imports.iter_mut() {
                    if sym.name.is_none() {
                        if let Some(n) = ord_lookup(&lower, sym.ordinal.unwrap_or(0)) {
                            sym.name = Some(n);
                        }
                    }
                }
                descs.push(ImportDesc { dll, time_date_stamp: tds, original_first_thunk: oft as u32, first_thunk: ft as u32, imports });
            }
        }
        Ok(descs)
    }

    /// `get_import_table(rva, max_length)`: `Ok(None)` is python's `return None`.
    fn get_import_table(&self, mut rva: i64, max_length: Option<i64>) -> PeResult<Option<Vec<u64>>> {
        let (ordinal_flag, esize) = if self.pe_type == Some(OPTIONAL_HEADER_MAGIC_PE_PLUS) { (IMAGE_ORDINAL_FLAG64, 8i64) } else { (IMAGE_ORDINAL_FLAG, 4i64) };
        const MAX_ADDRESS_SPREAD: u64 = 128 << 20;
        let mut table = Vec::new();
        let mut repeated = 0u32;
        let mut set32: crate::util::FxHashSet<u64> = Default::default();
        let mut set64: crate::util::FxHashSet<u64> = Default::default();
        let (mut min32, mut max32, mut min64, mut max64) = (u64::MAX, 0u64, u64::MAX, 0u64);
        let start_rva = rva;
        while rva != 0 {
            if let Some(m) = max_length {
                if rva >= start_rva + m {
                    break;
                }
            }
            if self.total_import_symbols.get() > MAX_IMPORT_SYMBOLS {
                break;
            }
            self.total_import_symbols.set(self.total_import_symbols.get() + 1);
            if repeated >= 15 {
                return Ok(Some(Vec::new()));
            }
            if !set32.is_empty() && max32 - min32 > MAX_ADDRESS_SPREAD {
                return Ok(Some(Vec::new()));
            }
            if !set64.is_empty() && max64 - min64 > MAX_ADDRESS_SPREAD {
                return Ok(Some(Vec::new()));
            }
            let data = match self.get_data(rva, Some(esize)) {
                Ok(d) if d.len() as i64 == esize => d,
                _ => return Ok(None),
            };
            self.get_offset_from_rva(rva)?;
            let aod = if esize == 8 { le64(&data, 0) } else { le32(&data, 0) as u64 };
            if (aod as i128) >= start_rva as i128 && (aod as i128) <= rva as i128 {
                break;
            }
            if aod != 0 {
                if aod & ordinal_flag != 0 {
                    if aod & 0x7FFF_FFFF > 0xFFFF {
                        return Ok(Some(Vec::new()));
                    }
                } else if aod >= 1 << 32 {
                    if !set64.insert(aod) {
                        repeated += 1;
                    }
                    min64 = min64.min(aod);
                    max64 = max64.max(aod);
                } else {
                    if !set32.insert(aod) {
                        repeated += 1;
                    }
                    min32 = min32.min(aod);
                    max32 = max32.max(aod);
                }
            }
            if aod == 0 {
                break;
            }
            rva += esize;
            table.push(aod);
        }
        Ok(Some(table))
    }

    /// `parse_imports(original_first_thunk, first_thunk, forwarder_chain, max_length)`:
    /// `Err` is a PEFormatError (the caller then keeps an empty list).
    fn parse_imports_of(&self, oft: i64, ft: i64, _fc: u32, max_length: Option<i64>) -> PeResult<Vec<Import>> {
        let ilt = self.get_import_table(oft, max_length)?;
        let iat = self.get_import_table(ft, max_length)?;
        let ilt_empty = ilt.as_ref().map(|v| v.is_empty()).unwrap_or(true);
        let iat_empty = iat.as_ref().map(|v| v.is_empty()).unwrap_or(true);
        if iat_empty && ilt_empty {
            return Ok(Vec::new());
        }
        let table = if !ilt_empty { ilt.as_ref().unwrap() } else { iat.as_ref().unwrap() };
        let (ordinal_flag, imp_offset, address_mask) = match self.pe_type {
            Some(OPTIONAL_HEADER_MAGIC_PE_PLUS) => (IMAGE_ORDINAL_FLAG64, 8u128, 0x7FFF_FFFF_FFFF_FFFFu64),
            _ => (IMAGE_ORDINAL_FLAG, 4u128, 0x7FFF_FFFFu64),
        };
        let image_base = self.optional_header.image_base as u128;
        let mut out = Vec::new();
        let mut num_invalid = 0usize;
        for (idx, &aod) in table.iter().enumerate() {
            let mut imp_ord: Option<u64> = None;
            let mut imp_hint: Option<u16> = None;
            let mut imp_name: Option<Vec<u8>> = None;
            if aod != 0 {
                if aod & ordinal_flag != 0 {
                    imp_ord = Some(aod & 0xFFFF);
                } else {
                    let r = (|| -> PeResult<()> {
                        let hint_rva = (aod & address_mask) as i64;
                        let data = self.get_data(hint_rva, Some(2))?;
                        imp_hint = word_from_data(&data, 0);
                        let name_rva = (aod as i64).wrapping_add(2);
                        let mut n = self.get_string_at_rva(Some(name_rva), MAX_IMPORT_NAME_LENGTH);
                        if !is_valid_function_name(n.as_deref(), false) {
                            n = Some(b"*invalid*".to_vec());
                        }
                        imp_name = n;
                        self.get_offset_from_rva(name_rva)?;
                        Ok(())
                    })();
                    let _ = r;
                }
            }
            let imp_address = ft as u128 + image_base + idx as u128 * imp_offset;
            if imp_ord.is_none() && imp_name.is_none() {
                return fmt_err("Invalid entries, aborting parsing.");
            }
            if imp_name.as_deref() == Some(b"*invalid*".as_slice()) {
                if num_invalid > 1000 && num_invalid == idx {
                    return fmt_err("Too many invalid names, aborting parsing.");
                }
                num_invalid += 1;
                continue;
            }
            let ord_truthy = imp_ord.map(|o| o != 0).unwrap_or(false);
            let name_truthy = imp_name.as_ref().map(|n| !n.is_empty()).unwrap_or(false);
            if ord_truthy || name_truthy {
                out.push(Import { ordinal: imp_ord, name: imp_name, address: imp_address, hint: imp_hint });
            }
        }
        Ok(out)
    }

    /// `parse_resources_directory(rva, size, base_rva, level, dirs)`. `Ok(None)` is python's
    /// `None`, `Ok(Some(entries))` a `ResourceDirData`; the entries are only recorded when
    /// `collect` is set (the subtree below a level-0 RT_VERSION entry), everything else is
    /// walked for its side effects (global entry count, version info, errors) only.
    #[allow(clippy::too_many_arguments)]
    fn parse_resources_directory(
        &self,
        rva: i64,
        size: i64,
        base_rva: i64,
        level: u32,
        dirs: &mut Vec<i64>,
        fixed: &mut Vec<FixedFileInfo>,
        collect: bool,
    ) -> PeResult<Option<Vec<ResEntry>>> {
        if level > MAX_RESOURCE_DEPTH {
            return Ok(None);
        }
        let data = match self.get_data(rva, Some(16)) {
            Ok(d) => d,
            Err(_) => return Ok(None),
        };
        self.get_offset_from_rva(rva)?;
        if data.len() < 16 {
            return Ok(None);
        }
        let number_of_entries = le16(&data, 12) as u64 + le16(&data, 14) as u64;
        let mut rva = rva + 16;
        if number_of_entries > 4096 {
            return Ok(None);
        }
        self.total_resource_entries.set(self.total_resource_entries.get() + number_of_entries);
        if self.total_resource_entries.get() > MAX_RESOURCE_ENTRIES {
            return Ok(None);
        }
        let mut entries: Vec<ResEntry> = Vec::new();
        let mut last_name: Option<(i64, i64)> = None;
        for _ in 0..number_of_entries {
            // parse_resource_entry(rva)
            let e = match self.get_data(rva, Some(8)) {
                Ok(d) => d,
                Err(_) => break,
            };
            self.get_offset_from_rva(rva)?;
            if e.len() < 8 {
                break;
            }
            let name = le32(&e, 0);
            let otd = le32(&e, 4);
            let id = name & 0xFFFF;
            let data_is_directory = otd & 0x8000_0000 != 0;
            let target = base_rva + (otd & 0x7FFF_FFFF) as i64;
            if name & 0x8000_0000 != 0 {
                let ustr_offset = base_rva + (name & 0x7FFF_FFFF) as i64;
                // UnicodeStringWrapperPostProcessor.get_pascal_16_length(): the word at the
                // name, False (0) when unreadable
                let plen = match self.get_data(ustr_offset, Some(2)) {
                    Ok(d) if d.len() >= 2 => le16(&d, 0) as i64,
                    _ => 0,
                };
                if let Some((b, en)) = last_name {
                    if b < ustr_offset && en >= ustr_offset {
                        break;
                    }
                }
                last_name = Some((ustr_offset, ustr_offset + plen));
            }
            let is_version = level == 0 && id == RT_VERSION;
            if data_is_directory {
                if dirs.contains(&target) {
                    break;
                }
                dirs.push(target);
                let sub = self.parse_resources_directory(target, size - (rva - base_rva), base_rva, level + 1, dirs, fixed, collect || is_version);
                dirs.pop();
                let Some(children) = sub? else { break };
                if is_version {
                    // last_entry.directory.entries[0].directory.entries -> .data.struct
                    if let Some(ResEntry::Dir(first)) = children.first() {
                        for leaf in first {
                            if let ResEntry::Leaf(off, sz) = *leaf {
                                self.parse_version_information((off, sz), fixed);
                            }
                        }
                    }
                }
                if collect {
                    entries.push(ResEntry::Dir(children));
                }
            } else {
                // parse_resource_data_entry(target)
                let d = match self.get_data(target, Some(16)) {
                    Ok(d) => d,
                    Err(_) => break,
                };
                self.get_offset_from_rva(target)?;
                if d.len() < 16 {
                    break;
                }
                if collect {
                    entries.push(ResEntry::Leaf(le32(&d, 0) as i64, le32(&d, 4) as i64));
                }
            }
            rva += 8;
        }
        Ok(Some(entries))
    }

    /// `parse_version_information(version_struct)` up to `VS_FIXEDFILEINFO` (the string
    /// tables that follow cannot fail in a way that affects it).
    fn parse_version_information(&self, (offset_to_data, size): (i64, i64), fixed: &mut Vec<FixedFileInfo>) {
        let Ok(start) = self.get_offset_from_rva(offset_to_data) else { return };
        let raw = self.slice(start, Some(start + size));
        if raw.len() < 6 {
            return;
        }
        let ustr_offset = offset_to_data + 6;
        let section_end = self.section_by_rva(ustr_offset).map(|i| {
            let s = &self.sections[i];
            s.virtual_address as i64 + (s.size_of_raw_data as i64).max(s.misc_virtual_size as i64)
        });
        let r = match section_end {
            None => self.get_string_u_at_rva(ustr_offset, 1 << 16),
            Some(e) => self.get_string_u_at_rva(ustr_offset, (e - ustr_offset) >> 1),
        };
        let Ok(s) = r else { return };
        let key: Vec<u16> = "VS_VERSION_INFO".encode_utf16().collect();
        if s != key {
            return;
        }
        let ffi_off = dword_align(6 + 2 * (s.len() as i64 + 1), offset_to_data);
        let (a, b) = py_range(raw.len(), ffi_off, None);
        let f = &raw[a..b];
        if f.len() < 52 {
            return;
        }
        let v = |i: usize| le32(f, i * 4);
        fixed.push(FixedFileInfo {
            signature: v(0),
            struc_version: v(1),
            file_version_ms: v(2),
            file_version_ls: v(3),
            product_version_ms: v(4),
            product_version_ls: v(5),
            file_flags_mask: v(6),
            file_flags: v(7),
            file_os: v(8),
            file_type: v(9),
            file_subtype: v(10),
            file_date_ms: v(11),
            file_date_ls: v(12),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slices() {
        assert_eq!(py_range(10, 2, Some(5)), (2, 5));
        assert_eq!(py_range(10, 2, Some(-3)), (2, 7));
        assert_eq!(py_range(10, -3, None), (7, 10));
        assert_eq!(py_range(10, 12, Some(20)), (10, 10));
        assert_eq!(py_range(10, 5, Some(2)), (5, 5));
        assert_eq!(py_range(10, -20, Some(-15)), (0, 0));
    }

    #[test]
    fn names() {
        assert!(is_valid_function_name(Some(b"NtCreateFile"), false));
        assert!(is_valid_function_name(Some(b""), false));
        assert!(!is_valid_function_name(Some(b"a b"), false));
        assert!(!is_valid_function_name(None, false));
        assert!(is_valid_function_name(Some(b"??0x@@QEAA`"), true));
        assert!(is_valid_dos_filename(Some(b"KERNEL32.dll")));
        assert!(!is_valid_dos_filename(Some(b"a*b")));
        assert_eq!(ord_lookup(b"ws2_32.dll", 1).unwrap(), b"accept");
        assert_eq!(ord_lookup(b"ws2_32.dll", 60000).unwrap(), b"ord60000");
        assert_eq!(ord_lookup(b"kernel32.dll", 1), None);
    }

    fn hexs(b: &Option<Vec<u8>>) -> String {
        match b {
            None => "-".into(),
            Some(v) => v.iter().map(|c| format!("{c:02x}")).collect(),
        }
    }

    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else {
                out.push(p);
            }
        }
    }

    /// Differential test against python pefile: `W2B_PE_DIRS=dir1:dir2 W2B_PE_OUT=file cargo
    /// test --profile fast differential_dump -- --ignored`, then diff with the output of the
    /// python oracle (`pefile.PE(fast_load=True)` + one directory per fresh object) over the
    /// same dirs.
    #[test]
    #[ignore]
    fn differential_dump() {
        use std::fmt::Write as _;
        let (Ok(dirs), Ok(outp)) = (std::env::var("W2B_PE_DIRS"), std::env::var("W2B_PE_OUT")) else { return };
        let mut files = Vec::new();
        for d in dirs.split(':') {
            walk(std::path::Path::new(d), &mut files);
        }
        files.sort_by(|a, b| a.as_os_str().as_encoded_bytes().cmp(b.as_os_str().as_encoded_bytes()));
        let mut out = String::new();
        for path in files {
            let data = std::fs::read(&path).unwrap();
            if !data.starts_with(b"MZ") {
                continue;
            }
            let _ = writeln!(out, "FILE {} {}", path.file_name().unwrap().to_string_lossy(), data.len());
            let pe = match PeFile::parse(&data) {
                Ok(p) => p,
                Err(PeError::Format(_)) => {
                    out.push_str("ERR PEFormatError\n");
                    continue;
                }
                Err(PeError::Attribute(_)) => {
                    out.push_str("ERR AttributeError\n");
                    continue;
                }
            };
            let pt = pe.pe_type.map(|t| t.to_string()).unwrap_or_else(|| "None".into());
            let _ = writeln!(out, "HDR {pt} {:x} {} {}", pe.optional_header.image_base, pe.sections.len(), pe.data_directories.len());
            match pe.parse_exports() {
                Some(d) => {
                    let _ = writeln!(out, "EXP {}", d.symbols.len());
                    for s in &d.symbols {
                        let a = s.address.map(|a| format!("{a:x}")).unwrap_or_else(|| "-".into());
                        let _ = writeln!(out, " E {} {a} {} {}", s.ordinal, hexs(&s.name), hexs(&s.forwarder));
                    }
                }
                None => out.push_str("EXP none\n"),
            }
            let pe = PeFile::parse(&data).unwrap();
            match pe.parse_imports() {
                Some(v) => {
                    let _ = writeln!(out, "IMP {}", v.len());
                    for d in &v {
                        let _ = writeln!(out, " D {} {} {}", hexs(&Some(d.dll.clone())), d.time_date_stamp, d.imports.len());
                        for i in &d.imports {
                            let o = i.ordinal.map(|o| o.to_string()).unwrap_or_else(|| "-".into());
                            let _ = writeln!(out, "  I {} {o} {:x}", hexs(&i.name), i.address);
                        }
                    }
                }
                None => out.push_str("IMP none\n"),
            }
            let pe = PeFile::parse(&data).unwrap();
            let v = pe.parse_version_info();
            if v.is_empty() {
                out.push_str("VER none\n");
            }
            for f in v {
                let _ = writeln!(out, "VER {:x} {:x} {:x} {:x}", f.file_version_ms, f.file_version_ls, f.product_version_ms, f.product_version_ls);
            }
        }
        std::fs::write(outp, out).unwrap();
    }

    #[test]
    fn align() {
        assert_eq!(dword_align(38, 0x1000), 40);
        assert_eq!(dword_align(38, 0x1002), 40);
        assert_eq!(dword_align(36, 0x1000), 36);
        assert_eq!(adjust_section_alignment(0x1234, 0x1000, 0x200), 0x1000);
        assert_eq!(adjust_section_alignment(0x1234, 0x200, 0x200), 0x1200);
        assert_eq!(adjust_section_alignment(0x1234, 0x100, 0), 0x1234);
    }
}
