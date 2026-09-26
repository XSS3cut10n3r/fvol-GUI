//! QEMU savevm / migration streams ("QEVM" v3).
//! Derived from Volatility 3's layers/qemu.py (Volatility Software License 1.0); the section
//! fields are big-endian as declared in symbols/generic/qemu.json.
//!
//! Only pages of the "pc.ram" RAM block are mapped. "Compressed" pages (a single fill byte)
//! become FILL runs; everything else is a raw 4K (config `page_size`) run. Addresses above
//! the PCI hole start are shifted by the hole size chosen from the machine type.

use super::json::{self, Value};
use super::segmented::{Seg, SegmentedLayer, Src};
use super::{py_string, Base};
use crate::error::{Error, Result};
use std::collections::HashMap;

const QEVM_EOF: u8 = 0x00;
const QEVM_SECTION_START: u8 = 0x01;
const QEVM_SECTION_PART: u8 = 0x02;
const QEVM_SECTION_END: u8 = 0x03;
const QEVM_SECTION_FULL: u8 = 0x04;
const QEVM_CONFIGURATION: u8 = 0x07;
const QEVM_SECTION_FOOTER: u8 = 0x7e;

const FLAG_COMPRESS: u64 = 0x02;
const FLAG_MEM_SIZE: u64 = 0x04;
const FLAG_PAGE: u64 = 0x08;
const FLAG_EOS: u64 = 0x10;
const FLAG_CONTINUE: u64 = 0x20;
const FLAG_XBZRLE: u64 = 0x40;

fn err(msg: &str) -> Error {
    Error::Layer(format!("QEMU: {msg}"))
}

/// qemu "string" object of `max_length` n (no read at all for n == 0, as in python).
fn string_at(base: &Base, off: u64, n: u64) -> Result<String> {
    if n == 0 {
        return Ok(String::new());
    }
    py_string(&base.bytes(off, usize::try_from(n).map_err(|_| Error::invalid(off))?)?)
}

/// python `QemuSuspendLayer._check_header`.
fn check_header(base: &Base) -> Result<()> {
    let h = base.bytes(0, 8)?;
    if &h[..4] != b"QEVM" {
        return Err(err("no magic bytes"));
    }
    if h[4..8] != [0, 0, 0, 3] {
        return Err(err("unsupported version"));
    }
    Ok(())
}

/// `(pci_hole_minimum, pci_hole_start, pci_hole_end)` for a machine type, in the order of
/// python's `pci_hole_table` (regexes re-implemented; `$` also matches before a final "\n").
fn pci_hole(arch: &str) -> Option<(u64, u64, u64)> {
    let a = arch.strip_suffix('\n').unwrap_or(arch);
    let digit = |c: char| c.is_ascii_digit();
    // \w+[\d{1,2}\.]*  (anchored, whole remainder)
    let distro = |r: &str| -> bool {
        let first_non_word = r.char_indices().find(|&(_, c)| !(c.is_alphanumeric() || c == '_')).map_or(r.len(), |(i, _)| i);
        first_non_word > 0 && r[first_non_word..].chars().all(|c| c.is_ascii_digit() || matches!(c, '{' | '}' | ',' | '.'))
    };
    // digits "." digit
    let ver = |r: &str| -> Option<(usize, bool)> {
        let (major, minor) = r.split_once('.')?;
        let ok = !major.is_empty() && major.chars().all(digit) && minor.len() == 1 && minor.chars().all(digit);
        ok.then(|| (major.len(), major.starts_with(['0', '1'])))
    };
    if let Some(r) = a.strip_prefix("pc-i440fx-") {
        if let Some((n, low)) = ver(r) {
            if n >= 2 || !low {
                return Some((0xE000_0000, 0xC000_0000, 0x1_0000_0000));
            }
            return Some((0xE000_0000, 0xE000_0000, 0x1_0000_0000));
        }
    }
    if let Some(r) = a.strip_prefix("pc-q35-")
        && let Some((1, _)) = ver(r)
    {
        return Some((0xB000_0000, 0x8000_0000, 0x1_0000_0000));
    }
    if a == "microvm" {
        return Some((0xC000_0000, 0xC000_0000, 0x1_0000_0000));
    }
    if a == "xen" {
        return Some((0xF000_0000, 0xF000_0000, 0x1_0000_0000));
    }
    if let Some(r) = a.strip_prefix("pc-i440fx-")
        && distro(r)
    {
        return Some((0xE000_0000, 0xC000_0000, 0x1_0000_0000));
    }
    if let Some(r) = a.strip_prefix("pc-q35-")
        && distro(r)
    {
        return Some((0xB000_0000, 0x8000_0000, 0x1_0000_0000));
    }
    None
}

/// python `_read_configuration`: the JSON vmdescription at the end of the stream (after the
/// last NUL of the aligned 4K chunks read backwards from the end).
fn read_configuration(base: &Base) -> Result<Value> {
    let len = base.len();
    if len <= 4096 {
        return Err(err("invalid JSON configuration at the end of the file"));
    }
    // python reads chunks [len - k*4096, +4096) for k = 1.. while the start is > 0
    let k_max = (len - 1) / 4096;
    let lo = len - k_max * 4096;
    let region: Vec<u8>;
    let data: &[u8] = match &base.file {
        Some(f) => &f.data()[lo as usize..len as usize],
        None => {
            // generic lower layer: gather chunks backwards until a NUL shows up
            let mut chunks: Vec<u8> = Vec::new();
            let mut k = 1;
            loop {
                if k > k_max {
                    return Err(err("invalid JSON configuration at the end of the file"));
                }
                let c = base.bytes(len - k * 4096, 4096)?;
                let mut v = c.into_owned();
                v.extend_from_slice(&chunks);
                chunks = v;
                let end = chunks.iter().rposition(|&b| b != 0).map_or(0, |p| p + 1);
                if chunks[..end].contains(&0) {
                    break;
                }
                k += 1;
            }
            region = chunks;
            &region
        }
    };
    let end = data.iter().rposition(|&b| b != 0).map_or(0, |p| p + 1);
    let Some(last_nul) = data[..end].iter().rposition(|&b| b == 0) else {
        return Err(err("invalid JSON configuration at the end of the file"));
    };
    match data[last_nul..end].iter().position(|&b| b == b'{') {
        Some(s) => json::parse(&data[last_nul + s..end]).map_err(|_| err("bad JSON configuration")),
        None => Ok(Value::Obj(Vec::new())),
    }
}

struct Parser<'a> {
    base: &'a Base,
    config: Value,
    page_size: Option<u64>,
    architecture: Option<String>,
    current_segment_name: Vec<u8>,
    hole_start: u64,
    hole_end: u64,
    hole_min: u64,
    segs: Vec<Seg>,
}

pub(crate) fn stack(base: &Base) -> Result<SegmentedLayer> {
    check_header(base)?;
    let config = read_configuration(base)?;
    let mut p = Parser {
        base,
        config,
        page_size: None,
        architecture: None,
        current_segment_name: Vec::new(),
        hole_start: 0,
        hole_end: 0,
        hole_min: 0,
        segs: Vec::new(),
    };
    p.load_segments()?;
    SegmentedLayer::new_nonlinear_allow_empty("QemuSuspendLayer", base, p.segs)
}

impl Parser<'_> {
    fn load_segments(&mut self) -> Result<()> {
        let base = self.base;
        let len = base.len();
        let mut section_byte: Option<u8> = None;
        let mut index = 8u64;
        let mut section_info: HashMap<u32, (String, u32)> = HashMap::new();
        let mut current_section_id: i64 = -1;
        let mut arch_detected = false;
        while section_byte != Some(QEVM_EOF) && index < len {
            if index > 20 && !arch_detected {
                if self.architecture.is_none() {
                    self.architecture = self.fallback_architecture()?;
                }
                // python: regex.match(None) raises TypeError
                let arch = self.architecture.as_deref().ok_or_else(|| err("architecture could not be determined"))?;
                if let Some((min, start, end)) = pci_hole(arch) {
                    self.hole_min = min;
                    self.hole_start = start;
                    self.hole_end = end;
                }
                arch_detected = true;
            }
            let sb = base.u8(index)?;
            section_byte = Some(sb);
            index += 1;
            match sb {
                QEVM_CONFIGURATION => {
                    let n = base.u32be(index)? as u64;
                    self.architecture = Some(string_at(base, index + 4, n)?);
                    index += 4 + n;
                }
                QEVM_SECTION_START | QEVM_SECTION_FULL => {
                    let id = base.u32be(index)?;
                    current_section_id = id as i64;
                    index += 4;
                    let name_len = base.u8(index)? as u64;
                    index += 1;
                    let name = string_at(base, index, name_len)?;
                    index += name_len;
                    index += 4; // instance id
                    let version_id = base.u32be(index)?;
                    index += 4;
                    section_info.insert(id, (name.clone(), version_id));
                    index = self.extract_data(index, &name, version_id)?;
                }
                QEVM_SECTION_PART | QEVM_SECTION_END => {
                    let id = base.u32be(index)?;
                    current_section_id = id as i64;
                    index += 4;
                    let (name, version_id) = section_info.get(&id).cloned().ok_or_else(|| err("unknown section id"))?;
                    index = self.extract_data(index, &name, version_id)?;
                }
                QEVM_SECTION_FOOTER => {
                    let id = base.u32be(index)?;
                    index += 4;
                    if id as i64 != current_section_id {
                        return Err(err("section footer mismatch"));
                    }
                }
                QEVM_EOF => {}
                _ => return Err(err(&format!("unknown section encountered: {sb}"))),
            }
        }
        Ok(())
    }

    fn page_size(&mut self) -> Result<u64> {
        if let Some(p) = self.page_size {
            return Ok(p);
        }
        let v = match self.config.get("page_size").map_err(|_| err("configuration is not a dict"))? {
            None => 4096,
            Some(Value::Int(i)) if *i > 0 && (*i as u128).is_power_of_two() && *i <= 1 << 40 => *i as u64,
            Some(Value::Bool(true)) => 1,
            _ => return Err(err("unsupported page_size")),
        };
        self.page_size = Some(v);
        Ok(v)
    }

    fn extract_data(&mut self, mut index: u64, name: &str, version_id: u32) -> Result<u64> {
        let base = self.base;
        match name {
            "ram" => {
                if version_id != 4 {
                    return Err(err("unknown RAM version_id"));
                }
                let ps = self.page_size()?;
                index = self.ram_segments(index, ps)?;
            }
            "spapr/htab" => {
                if version_id != 1 {
                    return Err(err("unknown HTAB version_id"));
                }
                base.u32be(index)?;
                index += 4;
            }
            "dirty-bitmap" => index += 1,
            "pbs-state" => {
                let n = base.u64be(index)?;
                index = index.checked_add(8).and_then(|i| i.checked_add(n)).ok_or_else(|| err("bad pbs-state length"))?;
            }
            _ => {}
        }
        Ok(index)
    }

    /// python `_get_ram_segments`.
    fn ram_segments(&mut self, mut index: u64, page_size: u64) -> Result<u64> {
        let base = self.base;
        let mask = page_size - 1;
        let data = base.file.as_ref().map(|f| f.data());
        let be64 = |at: u64| -> Result<u64> {
            match data {
                Some(d) => match d.get(at as usize..(at as usize).wrapping_add(8)) {
                    Some(b) => Ok(u64::from_be_bytes(b.try_into().unwrap())),
                    None => Err(Error::invalid(at)),
                },
                None => base.u64be(at),
            }
        };
        let byte = |at: u64| -> Result<u8> {
            match data {
                Some(d) => d.get(at as usize).copied().ok_or(Error::invalid(at)),
                None => base.u8(at),
            }
        };
        loop {
            let raw = be64(index)?;
            let flags = raw & mask;
            let mut addr = raw ^ flags;
            index += 8;
            let mut addr_ok = true;
            if addr >= self.hole_start {
                match addr.checked_add(self.hole_end - self.hole_start) {
                    Some(a) => addr = a,
                    None => addr_ok = false,
                }
            }
            if flags & FLAG_MEM_SIZE != 0 {
                let mut sizes: HashMap<Vec<u8>, u64> = HashMap::new();
                let mut namelen = byte(index)? as u64;
                while namelen != 0 {
                    let total = be64(index + 1 + namelen)?;
                    sizes.insert(base.bytes(index + 1, namelen as usize)?.into_owned(), total);
                    index += 1 + namelen + 8;
                    namelen = byte(index)? as u64;
                }
                let highest = 0xF000_0000u64 + 1;
                if sizes.get(b"pc.ram".as_slice()).copied().unwrap_or(highest) < self.hole_min {
                    self.hole_start = 0;
                    self.hole_end = 0;
                }
            }
            if flags & (FLAG_COMPRESS | FLAG_PAGE) != 0 {
                if flags & FLAG_CONTINUE == 0 {
                    let namelen = byte(index)? as u64;
                    if namelen == 0 {
                        // python FileLayer.read(.., 0) raises ValueError
                        return Err(err("empty RAM block name"));
                    }
                    self.current_segment_name = base.bytes(index + 1, namelen as usize)?.into_owned();
                    index += 1 + namelen;
                }
                let is_ram = self.current_segment_name == b"pc.ram";
                if flags & FLAG_COMPRESS != 0 {
                    if is_ram && addr_ok {
                        let b = byte(index).unwrap_or(0);
                        self.segs.push(Seg { start: addr, len: page_size, src: Src::Fill { at: index, byte: b } });
                    }
                    index += 1;
                } else {
                    if is_ram && addr_ok {
                        self.segs.push(Seg { start: addr, len: page_size, src: Src::Raw(index) });
                    }
                    index += page_size;
                }
            }
            if flags & FLAG_XBZRLE != 0 {
                return Err(err("XBZRLE compression not supported"));
            }
            if flags & FLAG_EOS != 0 {
                return Ok(index);
            }
        }
    }

    /// python `_fallback_determine_architecture`.
    fn fallback_architecture(&self) -> Result<Option<String>> {
        let base = self.base;
        if let Some(pos) = scan(base, find_machine_type) {
            let w = base.bytes(pos, 64)?;
            return Ok(Some(machine_type_match(&w)));
        }
        let devices = match self.config.get("devices").map_err(|_| err("configuration is not a dict"))? {
            None => None,
            Some(Value::Arr(a)) => Some(a),
            Some(_) => return Err(err("devices is not a list")),
        };
        for d in devices.into_iter().flatten() {
            let name = match d.get("vmsd_name").map_err(|_| err("device is not a dict"))? {
                None => String::new(),
                Some(Value::Str(s)) => s.to_lowercase(),
                Some(_) => return Err(err("vmsd_name is not a string")),
            };
            if name.contains("i440fx") || name.contains("piix") {
                return Ok(Some("pc-i440fx-2.0".into()));
            } else if name.contains("ich9") {
                return Ok(Some("pc-q35-2.0".into()));
            }
        }
        if let Some(pos) = scan(base, find_standard_pc) {
            let w = base.bytes(pos, 64)?;
            let chip = if w[13..].starts_with(b"i440FX") { "i440fx" } else { "q35" };
            return Ok(Some(format!("pc-{chip}-2.0")));
        }
        Ok(None)
    }
}

/// Leftmost match of `pc-(i440fx|q35)-(\d{1,2}\.\d{1,2}|\w+[\d{1,2}\.]*)` (bytes regex).
fn find_machine_type(d: &[u8]) -> Option<usize> {
    let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut i = 0;
    while i + 3 <= d.len() {
        let p = i + d[i..].iter().position(|&c| c == b'p')?;
        i = p + 1;
        let r = &d[p..];
        let tail = if r.starts_with(b"pc-i440fx-") {
            10
        } else if r.starts_with(b"pc-q35-") {
            7
        } else {
            continue;
        };
        if r.get(tail).is_some_and(|&c| word(c)) {
            return Some(p);
        }
    }
    None
}

/// Leftmost match of `Standard PC \((i440FX|Q35)`.
fn find_standard_pc(d: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i < d.len() {
        let p = i + d[i..].iter().position(|&c| c == b'S')?;
        i = p + 1;
        let r = &d[p..];
        if r.starts_with(b"Standard PC (i440FX") || r.starts_with(b"Standard PC (Q35") {
            return Some(p);
        }
    }
    None
}

/// python `re.search(pattern, window).group()` for the machine type regex, where the window
/// starts with a match.
fn machine_type_match(w: &[u8]) -> String {
    let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let class = |c: u8| c.is_ascii_digit() || matches!(c, b'{' | b'}' | b',' | b'.');
    let pre = if w.starts_with(b"pc-i440fx-") { 10 } else { 7 };
    let t = &w[pre..];
    let nd = |s: &[u8], max: usize| s.iter().take(max).take_while(|c| c.is_ascii_digit()).count();
    // alternative 1: \d{1,2}\.\d{1,2} (greedy, backtracking the first group)
    let d1 = nd(t, 2);
    for l1 in (1..=d1).rev() {
        if t.get(l1) == Some(&b'.') {
            let l2 = nd(&t[l1 + 1..], 2);
            if l2 > 0 {
                return String::from_utf8_lossy(&w[..pre + l1 + 1 + l2]).into_owned();
            }
        }
    }
    // alternative 2: \w+[\d{1,2}\.]*
    let a = t.iter().take_while(|&&c| word(c)).count();
    let b = t[a..].iter().take_while(|&&c| class(c)).count();
    String::from_utf8_lossy(&w[..pre + a + b]).into_owned()
}

/// Run a leftmost-match finder over the base layer (python `base_layer.scan` with a
/// RegExScanner: first hit in address order).
fn scan(base: &Base, find: fn(&[u8]) -> Option<usize>) -> Option<u64> {
    if let Some(f) = &base.file {
        return find(f.data()).map(|p| p as u64);
    }
    const CHUNK: u64 = 1 << 20;
    const OVERLAP: u64 = 64;
    let len = base.len();
    let mut at = 0u64;
    let mut buf = vec![0u8; (CHUNK + OVERLAP) as usize];
    while at < len {
        let n = (len - at).min(CHUNK + OVERLAP) as usize;
        base.layer.read_padded(at, &mut buf[..n]);
        if let Some(p) = find(&buf[..n])
            && (p as u64) < CHUNK
        {
            return Some(at + p as u64);
        }
        at += CHUNK;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pci_hole_table() {
        let i440 = Some((0xE000_0000, 0xC000_0000, 0x1_0000_0000));
        assert_eq!(pci_hole("pc-i440fx-6.2"), i440);
        assert_eq!(pci_hole("pc-i440fx-10.1"), i440);
        assert_eq!(pci_hole("pc-i440fx-1.7"), Some((0xE000_0000, 0xE000_0000, 0x1_0000_0000)));
        assert_eq!(pci_hole("pc-i440fx-01.7"), i440); // \d\d+
        assert_eq!(pci_hole("pc-q35-7.2"), Some((0xB000_0000, 0x8000_0000, 0x1_0000_0000)));
        assert_eq!(pci_hole("pc-q35-7.2\n"), Some((0xB000_0000, 0x8000_0000, 0x1_0000_0000)));
        assert_eq!(pci_hole("pc-q35-10.1"), Some((0xB000_0000, 0x8000_0000, 0x1_0000_0000))); // distro rule
        assert_eq!(pci_hole("pc-i440fx-rhel7.6.0"), i440);
        assert_eq!(pci_hole("pc-i440fx-bionic-hpb"), None);
        assert_eq!(pci_hole("microvm"), Some((0xC000_0000, 0xC000_0000, 0x1_0000_0000)));
        assert_eq!(pci_hole("xen"), Some((0xF000_0000, 0xF000_0000, 0x1_0000_0000)));
        assert_eq!(pci_hole("pc"), None);
        assert_eq!(pci_hole("pc-i440fx-"), None);
    }

    #[test]
    fn machine_type_regex() {
        assert_eq!(machine_type_match(b"pc-i440fx-2.12xyz"), "pc-i440fx-2.12");
        assert_eq!(machine_type_match(b"pc-i440fx-123.4 "), "pc-i440fx-123.4");
        assert_eq!(machine_type_match(b"pc-q35-focal-hpb"), "pc-q35-focal");
        assert_eq!(machine_type_match(b"pc-i440fx-rhel7.6.0\0"), "pc-i440fx-rhel7.6.0");
        assert_eq!(find_machine_type(b"xx pc-q35- pc-q35-5.1"), Some(11));
        assert_eq!(find_standard_pc(b"..Standard PC (Q35 + ICH9"), Some(2));
    }
}
