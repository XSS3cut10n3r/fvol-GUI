//! vmscan.Vmscan (python `plugins/vmscan.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! python's `PageStartScanner` only looks at the first 4 bytes of every page of every scan
//! chunk (`range(data_offset % 0x1000, len(data), 0x1000)`, no `chunk_size` filter, so the
//! page in a chunk's overlap is reported by both chunks). We replay python's chunk list and
//! read just those 4 bytes per page (in parallel), instead of streaming the whole image.
//!
//! The checks of a hit read the 4 bytes after the revision id and six `_VMCS` members: those
//! bytes (a "record") are cached next to the raw hits ([`scancache::page_start_records`]) and
//! the shipped structure layouts are compiled in ([`SHIPPED`]), so a repeated run reads neither
//! the image nor an ISF: the checks run on the cached bytes.

use crate::context::Context;
use crate::error::Result;
use crate::layers::scan::chunk_layout;
use crate::layers::{FileLayer, Layer, LayerExt, scancache};
use crate::objects::{LayerRef, Obj, Space};
use crate::plugins::{Config, ConfigValue, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::store::IsfLocation;
use crate::symbols::{Prim, PrimKind, TableRef, Ty};

pub struct Vmscan;

const PAGE: u64 = 0x1000;

/// The `_VMCS` members python's checks read (indices below).
const MEMBERS: [&str; 6] = ["vmcs_link_ptr", "host_cr4", "guest_cr3", "host_cr3", "guest_cr4", "ept"];
const LINK: usize = 0;
const HOST_CR4: usize = 1;
const GUEST_CR3: usize = 2;
const HOST_CR3: usize = 3;
const GUEST_CR4: usize = 4;
const EPT: usize = 5;

/// The shipped `generic/vmcs` ISFs (embedded; python's install has the same files): file name,
/// revision id and the offsets of [`MEMBERS`] in `_VMCS`, all `unsigned long long` (8 bytes,
/// little endian, unsigned). A location byte-identical to a shipped file uses this layout
/// instead of loading the ISF; `tests::shipped_layouts_match_isf` checks it against the ISFs.
const SHIPPED: [(&str, u32, [u64; 6]); 5] = [
    ("haswell-architecture.json", 18, [248, 824, 528, 816, 536, 320]),
    ("nehalem-architecture.json", 14, [248, 840, 736, 832, 744, 232]),
    ("sandybridge-architecture.json", 16, [248, 840, 736, 832, 744, 232]),
    ("skylake-architecture.json", 4, [248, 824, 528, 816, 536, 320]),
    ("westmere-architecture.json", 15, [248, 840, 736, 832, 744, 320]),
];

/// An integer member (`Ty::Int`): its offset from the structure start (masked with the layer's
/// address mask, like python's member offsets) and format.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Field {
    off: u64,
    size: u8,
    signed: bool,
    big_endian: bool,
}

impl Field {
    /// Bytes read (python reads the whole primitive; we decode at most 16).
    fn len(&self) -> usize {
        (self.size as usize).min(16)
    }

    /// python `int(member)` from its bytes.
    fn value(&self, b: &[u8]) -> i128 {
        Prim { size: self.size, signed: self.signed, big_endian: self.big_endian, kind: PrimKind::Int, name: Prim::NO_NAME }.decode_int(b)
    }
}

/// How the pages of one structure table are checked.
enum Checks {
    /// no `_VMCS` type or a member is missing: python raises on every page (skipped)
    Never,
    /// every member is an integer: checked from its bytes (records, cached)
    Fields([Field; 6]),
    /// other member types (pointers, enums, bit fields, floats): checked through the objects,
    /// resolved once (python looks them up on every page; `m()` on a probe at 0, rebased per
    /// page, gives the same objects)
    Objects([Obj; 6]),
}

/// One structure table: revision id signature, python table name, checks.
struct Vmcs {
    sig: [u8; 4],
    name: String,
    checks: Checks,
}

/// python `Vmscan._gather_vmcs_structures`: one entry per revision id (a later table with the
/// same revision id wins, like python's dict).
fn gather_vmcs_structures(layer: LayerRef) -> Vec<Vmcs> {
    // the embedded ISFs stand in for python's install dirs only when those are absent
    let have_py = crate::symbols::store::python_install_cached().is_some();
    let locs: Vec<IsfLocation> = crate::symbols::symbol_path()
        .all_under("generic/vmcs")
        .into_iter()
        .filter(|l| !(have_py && matches!(l, IsfLocation::Embedded { .. })))
        .collect();
    let base_of = |l: &IsfLocation| -> String { l.url().rsplit('/').next().unwrap_or("").split('.').next().unwrap_or("").to_string() };
    let bases: Vec<String> = locs.iter().map(base_of).collect();
    let mask = layer.address_mask();
    let mut out: Vec<Vmcs> = Vec::new();
    for (i, base) in bases.iter().enumerate() {
        // IntermediateSymbolTable.create(filename=base): the first file with that name, table
        // name free_table_name(base)
        let n = bases[..i].iter().filter(|b| *b == base).count() + 1;
        let Some(first) = bases.iter().position(|b| b == base).map(|j| &locs[j]) else { continue };
        let (rev, checks) = match shipped(first) {
            Some((rev, offs)) => (rev, Checks::Fields(offs.map(|o| Field { off: o & mask, size: 8, signed: false, big_endian: false }))),
            None => {
                let Ok(t) = crate::symbols::load_location(first, base, None, 0) else { continue };
                let Some(rev) = revision_id(t) else { continue };
                (rev, table_checks(layer, t))
            }
        };
        let sig = rev.to_le_bytes();
        let name = format!("{base}{n}");
        match out.iter_mut().find(|e| e.sig == sig) {
            Some(e) => {
                e.name = name;
                e.checks = checks;
            }
            None => out.push(Vmcs { sig, name, checks }),
        }
    }
    out
}

/// The compiled-in revision id and member offsets of `loc` when it is a shipped ISF (embedded,
/// or a file byte-identical to it).
fn shipped(loc: &IsfLocation) -> Option<(u32, [u64; 6])> {
    let name = match loc {
        IsfLocation::Embedded { rel, .. } => rel.strip_prefix("generic/vmcs/")?,
        IsfLocation::File(p) => p.file_name()?.to_str()?,
        _ => return None,
    };
    let &(_, rev, offs) = SHIPPED.iter().find(|s| s.0 == name)?;
    if let IsfLocation::File(p) = loc {
        let want = crate::symbols::store::embedded_file(&format!("generic/vmcs/{name}"))?;
        if std::fs::read(p).ok()? != want {
            return None;
        }
    }
    Some((rev, offs))
}

/// python `int(symbol_table.get_symbol("revision_id").constant_data)`.
fn revision_id(t: TableRef) -> Option<u32> {
    t.get_symbol("revision_id").ok().and_then(|s| s.constant_data).and_then(|cd| std::str::from_utf8(cd).ok()).and_then(|s| s.trim().parse::<u32>().ok())
}

/// The checks of a loaded structure table.
fn table_checks(layer: LayerRef, t: TableRef) -> Checks {
    let Ok(probe) = Obj::named(Space::on(layer, t), "_VMCS", 0) else { return Checks::Never };
    let mut objs = [probe; 6];
    for (o, n) in objs.iter_mut().zip(MEMBERS) {
        match probe.m(n) {
            Ok(m) => *o = m,
            Err(_) => return Checks::Never,
        }
    }
    let mut fields = [Field::default(); 6];
    for (f, o) in fields.iter_mut().zip(&objs) {
        match o.ty {
            Ty::Int(p) => *f = Field { off: o.addr, size: p.size, signed: p.signed, big_endian: p.big_endian },
            _ => return Checks::Objects(objs),
        }
    }
    Checks::Fields(fields)
}

/// python `_verify_vmcs_page` and the row's reads: `Some((ept, guest_cr3))` for a VMCS page.
/// Any failed test (python 3.11+: every non-empty `VMCSTest` flag combination has a `name`) or
/// failed read (InvalidAddressException / AttributeError) skips the page, so the tests stop at
/// the first failure. `abort` = the 4 bytes after the revision id, `v(i)` = member `i`'s value.
fn verdict(abort: Result<[u8; 4]>, v: impl Fn(usize) -> Result<i128>) -> Option<(u64, u64)> {
    let r = (|| -> Result<Option<(u64, u64)>> {
        let failed = abort? != [0, 0, 0, 0]
            || v(LINK)? != 0xFFFF_FFFF_FFFF_FFFF
            || v(HOST_CR4)? & (1 << 13) == 0
            || v(GUEST_CR3)? == 0
            || v(HOST_CR3)? == 0
            || v(GUEST_CR4)? & 0xFFFF_FFFF_FF88_9000 != 0;
        if failed {
            return Ok(None);
        }
        Ok(Some((v(EPT)? as u64, v(GUEST_CR3)? as u64)))
    })();
    r.ok().flatten()
}

/// [`verdict`] of the page at `page` through the member objects.
fn check_objects(layer: &dyn Layer, objs: &[Obj; 6], page: u64) -> Option<(u64, u64)> {
    let at = |o: &Obj| Obj { sp: o.sp, ty: o.ty, addr: page.wrapping_add(o.addr) & o.sp.layer_mask };
    verdict(layer.read_array::<4>(page.wrapping_add(4)), |i| at(&objs[i]).int())
}

// ---------------------------------------------------------------------------------------------
// Records: `[1 if every read succeeded][4 bytes at page + 4][each member's bytes, MEMBERS order]`
// ---------------------------------------------------------------------------------------------

/// Record size for `fields`.
fn rec_len(fields: &[Field; 6]) -> usize {
    5 + fields.iter().map(|f| f.len()).sum::<usize>()
}

/// Reads of the physical layer: from the image file when the layer is the file or a linear
/// container over it, the layer otherwise.
struct Reader<'a> {
    layer: &'a dyn Layer,
    file: Option<&'a FileLayer>,
    is_file: bool,
}

impl<'a> Reader<'a> {
    fn new(layer: &'a dyn Layer) -> Reader<'a> {
        let direct = layer.as_file().is_some() || layer.lower().is_some_and(|l| l.as_file().is_some());
        Reader { layer, file: crate::layers::base_file(layer).filter(|_| direct), is_file: layer.as_file().is_some() }
    }

    /// The image file and the offset of `[addr, addr + len)` in it, when that is one run of
    /// the file.
    fn file_at(&self, addr: u64, len: usize) -> Option<(&'a FileLayer, u64)> {
        let f = self.file?;
        if self.is_file {
            return Some((f, addr));
        }
        match self.layer.translate(addr) {
            Some((o, rem)) if rem >= len as u64 => Some((f, o)),
            _ => None,
        }
    }

    /// python `layer.read(addr, len(buf))` succeeds. File runs are read with `pread`: no page
    /// tables are built for scattered hit pages (on a VM, mapping a page and tearing it down at
    /// exit cost ~10 us each).
    fn read(&self, addr: u64, buf: &mut [u8]) -> bool {
        use std::os::unix::fs::FileExt;
        match self.file_at(addr, buf.len()) {
            Some((f, o)) => f.file().read_exact_at(buf, o).is_ok(),
            None => self.layer.read(addr, buf).is_ok(),
        }
    }
}

/// Fill the record of the page at `page` (every read python's checks and row may do).
fn fill_record(rd: &Reader, page: u64, fields: &[Field; 6], mask: u64, rec: &mut [u8]) {
    rec.fill(0);
    // the span of all reads (bytes 4..848 for the shipped layouts): one read when every member
    // address is page + offset (no masking) and the span is short, else a read per member
    let (mut lo, mut hi) = (4u64, 8u64);
    for f in fields.iter().filter(|f| f.len() > 0) {
        lo = lo.min(f.off);
        hi = hi.max(f.off.saturating_add(f.len() as u64));
    }
    let mut span = [0u8; 4096];
    let n = (hi - lo) as usize;
    let one = hi - lo <= span.len() as u64 && page.checked_add(hi).is_some_and(|end| end - 1 <= mask);
    let ok = if one && rd.read(page + lo, &mut span[..n]) {
        rec[1..5].copy_from_slice(&span[(4 - lo) as usize..][..4]);
        let mut pos = 5;
        for f in fields {
            let l = f.len();
            if l > 0 {
                rec[pos..pos + l].copy_from_slice(&span[(f.off - lo) as usize..][..l]);
            }
            pos += l;
        }
        true
    } else {
        let mut ok = rd.read(page.wrapping_add(4), &mut rec[1..5]);
        let mut pos = 5;
        for f in fields {
            let l = f.len();
            if l > 0 {
                ok &= rd.read(page.wrapping_add(f.off) & mask, &mut rec[pos..pos + l]);
            }
            pos += l;
        }
        ok
    };
    rec[0] = ok as u8;
}

/// [`verdict`] of a record filled by [`fill_record`] (a failed read skips the page).
fn check_record(fields: &[Field; 6], rec: &[u8]) -> Option<(u64, u64)> {
    if rec.first() != Some(&1) || rec.len() < rec_len(fields) {
        return None;
    }
    let mut at = [0usize; 6];
    let mut pos = 5;
    for (a, f) in at.iter_mut().zip(fields) {
        *a = pos;
        pos += f.len();
    }
    verdict(Ok([rec[1], rec[2], rec[3], rec[4]]), |i| Ok(fields[i].value(&rec[at[i]..at[i] + fields[i].len()])))
}

/// python's hits `(chunk start, offset in chunk, structure)` in chunk order: the first 4 bytes
/// of every page of every chunk. A file-backed layer is read through the image mapping: a
/// fault maps 16 pages at once, far cheaper than a `pread` per page start (5 GiB image on a
/// 32-vCPU VM: 44 ms vs 295 ms; locally 28 vs 105 ms). Each chunk's page-table entries are
/// dropped right after it (`MADV_DONTNEED`, in parallel) instead of by the exit teardown of the
/// whole mapping (serial: ~250 ms on that VM).
fn page_starts(layer: &dyn Layer, structures: &[Vmcs]) -> Vec<(u64, u64, u32)> {
    let rd = Reader::new(layer);
    let chunks = chunk_layout(layer, 0x1000000, 0x1000, None);
    let per_chunk: Vec<Vec<(u64, u64, u32)>> = crate::util::par::par_map(chunks.len(), |ci| {
        let (start, len) = chunks[ci];
        let mut hits = Vec::new();
        // python: a data-layer chunk that cannot be read entirely has no hits
        if layer.lower().is_none() && !layer.is_valid(start, len) {
            return hits;
        }
        let (mut lo, mut hi) = (u64::MAX, 0u64);
        let mut ps = start % PAGE;
        while ps + 4 <= len {
            let addr = start + ps;
            let sig = match rd.file_at(addr, 4) {
                Some((f, o)) => f.data().get(o as usize..).and_then(|d| d.first_chunk::<4>()).map(|b| {
                    lo = lo.min(o);
                    hi = hi.max(o + 4);
                    *b
                }),
                None => layer.read_array::<4>(addr).ok(),
            };
            if let Some(sig) = sig
                && let Some(si) = structures.iter().position(|s| s.sig == sig)
            {
                hits.push((start, ps, si as u32));
            }
            ps += PAGE;
        }
        if let Some(f) = rd.file
            && hi > lo
        {
            f.mmap().advise(lo as usize, (hi - lo) as usize, crate::util::mmap::MADV_DONTNEED);
        }
        hits
    });
    per_chunk.concat()
}

impl Plugin for Vmscan {
    fn name(&self) -> &'static str {
        "vmscan.Vmscan"
    }
    fn description(&self) -> &'static str {
        "Scans for Intel VT-d structures and generates VM volatility configs for them"
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::new("log-threshold", "Number of criteria failed to log to debug output", ReqKind::Int)
            .optional()
            .default(ConfigValue::Int(2))]
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        // python: the primary layer, moved down to its memory_layer when it has one
        let layer = super::primary::physical(ctx, "Physical base memory layer")?;
        let structures = {
            let _t = crate::util::trace::span("vmscan: vmcs tables");
            gather_vmcs_structures(layer)
        };
        out.begin(vec![
            Column::new("Architecture", ColType::Str),
            Column::new("VMCS Physical offset", ColType::Hex),
            Column::new("EPT", ColType::Hex),
            Column::new("Guest CR3", ColType::Hex),
        ])?;
        if structures.is_empty() {
            // python: PageStartScanner([]) raises ValueError("No signatures passed to constructor")
            panic!("ValueError: No signatures passed to constructor");
        }
        let _t = crate::util::trace::span("vmscan: page starts + checks");
        // the raw hits come from the scan cache when an earlier run (or another physical scan's
        // sweep) recorded them; the checks run every time
        let sigs: Vec<u32> = structures.iter().map(|s| u32::from_le_bytes(s.sig)).collect();
        let rd = Reader::new(layer);
        let mask = layer.address_mask();
        let compute = || page_starts(layer, &structures);
        let mut rows: Vec<(u64, usize, (u64, u64))> = Vec::new();
        if structures.iter().any(|s| matches!(s.checks, Checks::Objects(_))) {
            // non-integer members: no records, every hit is checked by reading the layer
            let raw = scancache::page_start_hits(layer, &sigs, compute);
            let check_one = |i: usize| {
                let (start, ps, si) = raw[i];
                let page = start + ps;
                match &structures[si as usize].checks {
                    Checks::Never => None,
                    Checks::Fields(f) => {
                        let mut rec = vec![0u8; rec_len(f)];
                        fill_record(&rd, page, f, mask, &mut rec);
                        check_record(f, &rec)
                    }
                    Checks::Objects(o) => check_objects(layer, o, page),
                }
            };
            let checked: Vec<Option<(u64, u64)>> =
                if raw.len() < 256 { (0..raw.len()).map(check_one).collect() } else { crate::util::par::par_map(raw.len(), check_one) };
            rows.extend(raw.iter().zip(checked).filter_map(|(&(start, ps, si), c)| Some((start + ps, si as usize, c?))));
        } else {
            // the record of every hit: its check reads, cached with the hits (a warm run reads
            // nothing but one cache file); `spec` = everything that determines the records
            let rl = structures.iter().map(|s| if let Checks::Fields(f) = &s.checks { rec_len(f) } else { 0 }).max().unwrap_or(0).max(1);
            let mut spec = b"vmscan records/1: ok, page+4 (4), members".to_vec();
            spec.extend_from_slice(&mask.to_le_bytes());
            for s in &structures {
                match &s.checks {
                    Checks::Fields(f) => {
                        spec.push(1);
                        for x in f {
                            spec.extend_from_slice(&x.off.to_le_bytes());
                            spec.push(x.len() as u8);
                        }
                    }
                    _ => spec.push(0),
                }
            }
            let (raw, recs) = scancache::page_start_records(layer, &sigs, &spec, rl, compute, |page, si, rec| {
                if let Some(Checks::Fields(f)) = structures.get(si as usize).map(|s| &s.checks) {
                    fill_record(&rd, page, f, mask, rec);
                }
            });
            for (&(start, ps, si), rec) in raw.iter().zip(recs.chunks_exact(rl)) {
                if let Checks::Fields(f) = &structures[si as usize].checks
                    && let Some(c) = check_record(f, rec)
                {
                    rows.push((start + ps, si as usize, c));
                }
            }
        }
        for (off, si, (ept, cr3)) in rows {
            out.row(0, vec![Value::Str(structures[si].name.clone()), Value::Int(off as i128), Value::Int(ept as i128), Value::Int(cr3 as i128)])?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::layers::Mapping;

    /// A memory buffer layer with a 33-bit address space (like a 5 GiB image).
    struct Mem(Vec<u8>);
    impl Layer for Mem {
        fn name(&self) -> &str {
            "mem"
        }
        fn max_address(&self) -> u64 {
            (5 << 30) - 1
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
            addr.checked_add(len).is_some_and(|e| e <= self.0.len() as u64)
        }
        fn mapping(&self, addr: u64, len: u64, f: &mut dyn FnMut(Mapping) -> bool) {
            f(Mapping { offset: addr, len, mapped: addr });
        }
    }

    fn shipped_table(name: &str) -> TableRef {
        let rel = format!("generic/vmcs/{name}");
        let data = crate::symbols::store::embedded_file(&rel).expect("embedded");
        let rel: &'static str = Box::leak(rel.into_boxed_str());
        let base = name.split('.').next().unwrap();
        crate::symbols::load_location(&IsfLocation::Embedded { rel, top: true, data }, base, None, 0).unwrap()
    }

    /// The compiled-in layouts are exactly what loading the shipped ISFs gives, and every
    /// shipped VMCS ISF has one.
    #[test]
    fn shipped_layouts_match_isf() {
        let layer = crate::objects::leak_layer(std::sync::Arc::new(Mem(vec![0; 16])));
        let mask = layer.address_mask();
        for (name, rev, offs) in SHIPPED {
            let t = shipped_table(name);
            assert_eq!(revision_id(t), Some(rev), "{name}");
            match table_checks(layer, t) {
                Checks::Fields(f) => assert_eq!(f, offs.map(|o| Field { off: o & mask, size: 8, signed: false, big_endian: false }), "{name}"),
                _ => panic!("{name}: not integer members"),
            }
            let loc = IsfLocation::Embedded { rel: Box::leak(format!("generic/vmcs/{name}").into_boxed_str()), top: true, data: &[] };
            assert_eq!(shipped(&loc), Some((rev, offs)));
        }
        let all = crate::symbols::SymbolPath { roots: vec![crate::symbols::store::Root::Embedded { top: true }], download_dir: Default::default() }.all_under("generic/vmcs");
        assert_eq!(all.len(), SHIPPED.len());
        for l in &all {
            assert!(shipped(l).is_some(), "{l:?}");
        }
    }

    /// Checks from records (the cached path) agree with checks through the objects (python's
    /// member reads) on pages near and far from a valid VMCS, for every shipped layout.
    #[test]
    fn records_match_objects() {
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut rnd = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for (name, _, offs) in SHIPPED {
            // pages: a valid VMCS, then mutations of one field each, random junk, and a page
            // cut short by the end of the layer
            let mut pages: Vec<Vec<u8>> = Vec::new();
            let mut good = vec![0u8; 4096];
            let put = |p: &mut Vec<u8>, off: u64, v: u64| p[off as usize..off as usize + 8].copy_from_slice(&v.to_le_bytes());
            put(&mut good, offs[LINK], u64::MAX);
            put(&mut good, offs[HOST_CR4], 1 << 13);
            put(&mut good, offs[GUEST_CR3], 0x1234000);
            put(&mut good, offs[HOST_CR3], 0x5678000);
            put(&mut good, offs[GUEST_CR4], 0x20);
            put(&mut good, offs[EPT], 0xabc000);
            pages.push(good.clone());
            for i in 0..40 {
                let mut p = good.clone();
                match i % 8 {
                    0 => p[4 + (rnd() % 4) as usize] = 1,
                    1..=6 => {
                        let f = offs[(i % 8 - 1) as usize] as usize;
                        p[f + (rnd() % 8) as usize] ^= 1 << (rnd() % 8);
                    }
                    _ => p.iter_mut().for_each(|b| *b = rnd() as u8),
                }
                pages.push(p);
            }
            let n = pages.len();
            let mut img: Vec<u8> = pages.concat();
            img.extend_from_slice(&good[..600]); // the last page ends before the members
            let layer = crate::objects::leak_layer(std::sync::Arc::new(Mem(img)));
            let t = shipped_table(name);
            let probe = Obj::named(Space::on(layer, t), "_VMCS", 0).unwrap();
            let mut objs = [probe; 6];
            for (o, m) in objs.iter_mut().zip(MEMBERS) {
                *o = probe.m(m).unwrap();
            }
            let Checks::Fields(fields) = table_checks(layer, t) else { panic!("{name}: not integer members") };
            let rd = Reader::new(layer);
            let mut valid = 0;
            for k in 0..=n {
                let page = k as u64 * PAGE;
                let mut rec = vec![0u8; rec_len(&fields)];
                fill_record(&rd, page, &fields, layer.address_mask(), &mut rec);
                let want = check_objects(layer, &objs, page);
                assert_eq!(check_record(&fields, &rec), want, "{name} page {k}");
                valid += want.is_some() as usize;
            }
            assert!(valid >= 1, "{name}");
            assert_eq!(check_objects(layer, &objs, 0), Some((0xabc000, 0x1234000)));
        }
    }
}
