//! VMware memory: a flat `.vmem` split into regions described by the `memory` group of the
//! checkpoint metadata in the `.vmss` (suspend) or `.vmsn` (snapshot) file next to it.
//! Derived from Volatility 3's layers/vmware.py (Volatility Software License 1.0).

use super::segmented::{Seg, SegmentedLayer, Src};
use super::{py_string, Base};
use crate::error::{Error, Result};
use crate::layers::file::FileLayer;
use std::collections::HashMap;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const MAGICS: [[u8; 4]; 4] = [[0xd0, 0xbe, 0xd2, 0xbe], [0xd1, 0xba, 0xd1, 0xba], [0xd2, 0xbe, 0xd2, 0xbe], [0xd3, 0xbe, 0xd3, 0xbe]];
const PAGE: u64 = 0x1000;
const HEADER: u64 = 12; // "<4sII"
const GROUP: u64 = 80; // "64sQQ"

/// python `VmwareStacker.stack`: `<name>.vmem` + `<name>.vmss`, else `<name>.vmsn`.
/// `location` is the local file of the `.vmem`, `url` python's location of it (tested for
/// the `.vmem` suffix, as python does; when remote, the metadata file next to it is
/// downloaded into the rsvol cache like the image). Returns the layer and python's location
/// of the metadata file (the meta_layer's `location` in configurations). `native_table` is set
/// once the metadata file is open: python then constructs the `VmwareLayer`, whose
/// `_read_header` first appends a native `vmware` symbol table to the symbol space (it stays
/// there even when the header turns out to be invalid).
pub(crate) fn stack(base: &Base, location: &Path, url: Option<&str>, offline: bool, native_table: &mut bool) -> Result<(SegmentedLayer, String)> {
    let not_vmem = || Error::Layer("vmware: not a .vmem file".into());
    let url_stem = match url {
        Some(u) => Some(u.strip_suffix(".vmem").ok_or_else(not_vmem)?),
        None => None,
    };
    let stem = location.as_os_str().as_bytes().strip_suffix(b".vmem");
    let open_meta = |ext: &str| -> Result<(FileLayer, String)> {
        if let Some(us) = url_stem.filter(|u| crate::util::download::is_remote(u)) {
            let meta_url = format!("{us}{ext}");
            let p = crate::util::download::fetch(&meta_url, offline)?;
            return Ok((FileLayer::open(&p)?, meta_url));
        }
        let mut v = stem.ok_or_else(not_vmem)?.to_vec();
        v.extend_from_slice(ext.as_bytes());
        let p = PathBuf::from(std::ffi::OsString::from_vec(v));
        let meta_loc = match url_stem {
            Some(us) => format!("{us}{ext}"),
            None => crate::util::paths::path_to_file_uri(&p),
        };
        Ok((FileLayer::open(&p)?, meta_loc))
    };
    // python opens the file and reads 10 bytes; any IOError moves on to the .vmsn
    let (meta, meta_loc) = open_meta(".vmss")
        .or_else(|_| open_meta(".vmsn"))
        .map_err(|_| Error::Layer("vmware: no .vmss/.vmsn metadata next to the .vmem".into()))?;
    *native_table = true;
    let meta = Arc::new(meta);
    let segs = read_regions(&Base::from_file(&meta))?;
    Ok((SegmentedLayer::new("VmwareLayer", base, segs)?, meta_loc))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TagValue {
    Int(u64),
    Bytes,
}

/// python `VmwareLayer._read_header`.
pub(crate) fn read_regions(meta: &Base) -> Result<Vec<Seg>> {
    let h = meta.bytes(0, HEADER as usize)?;
    let magic: [u8; 4] = h[0..4].try_into().unwrap();
    let group_count = u32::from_le_bytes(h[8..12].try_into().unwrap()) as u64;
    if !MAGICS.contains(&magic) {
        return Err(Error::Layer(format!("vmware: wrong magic bytes {magic:02x?}")));
    }
    let version = magic[0] & 0xf;
    let mut memory: Option<u64> = None;
    for g in 0..group_count {
        let rec = meta.bytes(HEADER + g * GROUP, GROUP as usize)?;
        let name = &rec[..64];
        let end = name.iter().rposition(|&b| b != 0).map_or(0, |p| p + 1);
        if &name[..end] == b"memory" {
            memory = Some(u64::from_le_bytes(rec[64..72].try_into().unwrap()));
        }
    }
    let mut offset = memory.ok_or_else(|| Error::Layer("vmware: no memory group".into()))?;
    let index_len = 4u64;
    // only the region tags matter, but every tag name must decode like python's String
    let mut tags: HashMap<(String, Vec<u32>), TagValue> = HashMap::new();
    loop {
        let flags = meta.u8(offset)?;
        let name_len = meta.u8(offset.checked_add(1).ok_or_else(ovf)?)? as u64;
        if flags == 0 && name_len == 0 {
            break;
        }
        let name = if name_len > 0 { py_string(&meta.bytes(offset + 2, name_len as usize)?)? } else { String::new() };
        let indices_len = ((flags >> 6) & 3) as u64;
        let mut indices = Vec::with_capacity(indices_len as usize);
        for i in 0..indices_len {
            indices.push(meta.u32le(offset + name_len + 2 + i * index_len)?);
        }
        let data_len = (flags & 0x3f) as u64;
        let at = offset + 2 + name_len + indices_len * index_len;
        let value;
        if data_len == 62 || data_len == 63 {
            let dl = if version == 0 { 4 } else { 8 };
            let data_size = if dl == 4 { meta.u32le(at)? as u64 } else { meta.u64le(at)? };
            let data_at = at + 2 * dl + 2;
            if data_size > 0 {
                // python reads the whole blob (vmware!bytes); it must be present
                let end = data_at.checked_add(data_size).ok_or_else(ovf)?;
                if end > meta.len() {
                    return Err(Error::invalid(data_at));
                }
            }
            value = TagValue::Bytes;
            offset = data_at.checked_add(data_size).ok_or_else(ovf)?;
        } else {
            value = TagValue::Int(if data_len == 4 { meta.u32le(at)? as u64 } else { meta.u64le(at)? });
            offset = at + data_len;
        }
        if matches!(name.as_str(), "regionsCount" | "regionPPN" | "regionPageNum" | "regionSize") {
            tags.insert((name, indices), value);
        }
    }
    let get = |name: &str, idx: &[u32]| -> Result<u64> {
        match tags.get(&(name.to_string(), idx.to_vec())) {
            Some(TagValue::Int(v)) => Ok(*v),
            Some(TagValue::Bytes) => Err(Error::Layer(format!("vmware: tag {name} is not an integer"))),
            None => Err(Error::Layer(format!("vmware: missing tag {name}{idx:?}"))),
        }
    };
    let count = get("regionsCount", &[])?;
    if count == 0 {
        return Err(Error::Layer("VMware VMEM is not split into regions".into()));
    }
    let mut segs = Vec::new();
    for region in 0..count {
        // indices are u32 in the file: larger region numbers can never match (KeyError)
        let r = u32::try_from(region).map_err(|_| Error::Layer("vmware: missing region tag".into()))?;
        let ppn = get("regionPPN", &[r])?;
        let page_num = get("regionPageNum", &[r])?;
        let size = get("regionSize", &[r])?;
        if let (Some(start), Some(src), Some(len)) = (ppn.checked_mul(PAGE), page_num.checked_mul(PAGE), size.checked_mul(PAGE)) {
            segs.push(Seg { start, len, src: Src::Raw(src) });
        }
    }
    Ok(segs)
}

fn ovf() -> Error {
    Error::Layer("vmware: offset overflow".into())
}
