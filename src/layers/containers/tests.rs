//! Tests for the container layers.
//!
//! * `python_differential_fixtures`: synthetic containers built from real memory by
//!   tests/fixtures/containers/gen_containers.py, with the results python volatility3's own
//!   layer classes produced for the stacking decision, maximum_address and ~120 strict and
//!   padded reads each. Every answer must match exactly.
//! * `python_differential_large` (ignored): same against a bigger generated set, e.g.
//!   `gen_containers.py RAW /tmp/fx --scale 64 --queries 2000` then
//!   `RSVOL_CONTAINER_FIXTURES=/tmp/fx cargo test --release python_differential_large -- --ignored`.
//! * model tests of the segment semantics, malformed-input fuzzing (no panics).

use super::segmented::{Seg, SegmentedLayer, Src};
use super::*;
use crate::layers::LayerExt;
use std::path::Path;

fn fnv64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/containers")
}

fn temp_file(tag: &str, data: &[u8]) -> PathBuf {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static N: AtomicUsize = AtomicUsize::new(0);
    let p = std::env::temp_dir().join(format!("rsvol-ctest-{}-{}-{tag}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
    std::fs::write(&p, data).unwrap();
    p
}

fn open(p: &Path) -> Arc<FileLayer> {
    Arc::new(FileLayer::open(p).unwrap())
}

/// Class names of a physical stack, top first (as python's `stack_layer` result).
fn chain(l: &Arc<dyn Layer>) -> Vec<String> {
    let mut v = vec![l.name().to_string()];
    let mut cur = l.lower();
    while let Some(c) = cur {
        v.push(c.name().to_string());
        cur = c.lower();
    }
    v
}

/// Check one container against its `.expect` file; returns the number of checked queries.
fn check_expect(expect: &Path) -> usize {
    let dir = expect.parent().unwrap();
    let stem = expect.file_stem().unwrap().to_str().unwrap();
    let main = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.file_stem().and_then(|s| s.to_str()) == Some(stem)
                && !matches!(p.extension().and_then(|e| e.to_str()), Some("expect" | "vmss" | "vmsn" | "py"))
        })
        .unwrap_or_else(|| panic!("no container for {}", expect.display()));
    let file = open(&main);
    let st = stack_with(file, &StackOptions { location: Some(&main), stackers: None }).unwrap();
    let layer = st.layer;
    let text = std::fs::read_to_string(expect).unwrap();
    let mut n = 0;
    for line in text.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "STACK" => assert_eq!(chain(&layer), f[1..].to_vec(), "{stem}: stack"),
            "MAX" => assert_eq!(layer.max_address(), u64::from_str_radix(f[1], 16).unwrap(), "{stem}: maximum_address"),
            "R" | "P" => {
                let a = u64::from_str_radix(f[1], 16).unwrap();
                let len = usize::from_str_radix(f[2], 16).unwrap();
                let mut buf = vec![0xAAu8; len];
                let got = if f[0] == "R" {
                    match layer.read(a, &mut buf) {
                        Ok(()) => format!("{:016x}", fnv64(&buf)),
                        Err(_) => "X".to_string(),
                    }
                } else {
                    layer.read_padded(a, &mut buf);
                    format!("{:016x}", fnv64(&buf))
                };
                assert_eq!(got, f[3], "{stem}: {line}");
                // the other access paths must agree with read()
                if f[0] == "R" {
                    let valid = f[3] != "X";
                    assert_eq!(layer.is_valid(a, len as u64), valid, "{stem}: is_valid {line}");
                    if let Some(s) = layer.slice(a, len) {
                        assert!(valid, "{stem}: slice of invalid range {line}");
                        assert_eq!(format!("{:016x}", fnv64(s)), f[3], "{stem}: slice {line}");
                    }
                    let mut covered = 0u64;
                    layer.mapping(a, len as u64, &mut |m| {
                        assert!(m.offset >= a && m.offset + m.len <= a + len as u64);
                        covered += m.len;
                        true
                    });
                    if valid {
                        assert_eq!(covered, len as u64, "{stem}: mapping coverage {line}");
                    }
                }
                n += 1;
            }
            "" => {}
            other => panic!("unknown expect line {other}"),
        }
    }
    n
}

fn check_dir(dir: &Path) -> (usize, usize) {
    let mut files = 0;
    let mut queries = 0;
    let mut entries: Vec<_> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()).collect();
    entries.sort();
    for p in entries {
        if p.extension().and_then(|e| e.to_str()) == Some("expect") {
            queries += check_expect(&p);
            files += 1;
        }
    }
    (files, queries)
}

#[test]
fn python_differential_fixtures() {
    let (files, queries) = check_dir(&fixtures_dir());
    assert!(files >= 14, "fixtures missing ({files})");
    assert!(queries > 1000);
}

#[test]
#[ignore]
fn python_differential_large() {
    let Ok(dir) = std::env::var("RSVOL_CONTAINER_FIXTURES") else { return };
    let (files, queries) = check_dir(Path::new(&dir));
    println!("{files} containers, {queries} queries match python");
}

#[test]
fn stack_listing_names() {
    let dir = fixtures_dir();
    let p = dir.join("nested_elf_lime.elf");
    let st = stack_with(open(&p), &StackOptions { location: Some(&p), stackers: None }).unwrap();
    assert_eq!(st.stackers, vec![Stacker::Elf64, Stacker::Lime]);
    let got: Vec<(usize, &str, &str)> = st.layers.iter().map(|e| (e.depth, e.name.as_str(), e.class)).collect();
    assert_eq!(got, vec![(0, "memory_layer", "LimeLayer"), (1, "base_layer2", "Elf64Layer"), (2, "base_layer", "FileLayer")]);

    let p = dir.join("vmware.vmem");
    let st = stack_with(open(&p), &StackOptions { location: Some(&p), stackers: None }).unwrap();
    let got: Vec<(usize, &str, &str)> = st.layers.iter().map(|e| (e.depth, e.name.as_str(), e.class)).collect();
    assert_eq!(got, vec![(0, "memory_layer", "VmwareLayer"), (1, "base_layer", "FileLayer"), (1, "meta_layer", "FileLayer")]);

    // a raw file stays raw
    let raw = temp_file("raw", &vec![0x11u8; 3 * 4096]);
    let st = stack_with(open(&raw), &StackOptions::default()).unwrap();
    assert_eq!(st.layer.name(), "FileLayer");
    assert_eq!(st.layers, vec![StackEntry { depth: 0, name: "memory_layer".into(), class: "FileLayer" }]);
    std::fs::remove_file(raw).unwrap();

    // stacker filter (python automagic.LayerStacker.stackers)
    let p = dir.join("lime.lime");
    let only_elf = vec!["Elf64Stacker".to_string()];
    let st = stack_with(open(&p), &StackOptions { location: Some(&p), stackers: Some(&only_elf) }).unwrap();
    assert_eq!(st.layer.name(), "FileLayer");
    assert_eq!(stack(open(&p)).unwrap().name(), "LimeLayer");
}

#[test]
fn vmem_location_from_proc_maps() {
    // stack() without a location must still pair the .vmem with its .vmss
    let p = fixtures_dir().join("vmware.vmem");
    let file = open(&p);
    assert_eq!(file_location(&file).as_deref(), Some(p.as_path()));
    assert_eq!(stack(file).unwrap().name(), "VmwareLayer");
}

#[test]
fn crash_header_for_crashinfo() {
    let p = fixtures_dir().join("crash64_bitmap.dmp");
    let l = stack(open(&p)).unwrap();
    let h = crash::find_header(&l).unwrap();
    assert!(h.is64);
    assert_eq!(&h.signature, b"PAGE");
    assert_eq!(&h.valid_dump, b"DU64");
    assert_eq!(h.directory_table_base, 0x1ae000);
    assert_eq!(h.dump_type, 5);
    assert_eq!(h.system_up_time, 12345678);
    assert_eq!(&h.comment[..8], b"rsvol64\0");
    let s = h.summary.unwrap();
    assert_eq!(&s.signature, b"SDMP");
    assert_eq!(s.bitmap_size, 4 * 32 - 5);
    let p = fixtures_dir().join("crash32_full.dmp");
    let h = crash::find_header(&stack(open(&p)).unwrap()).unwrap();
    assert!(!h.is64);
    assert_eq!(h.directory_table_base, 0x185000);
    assert_eq!(h.dump_type, 1);
    assert!(h.summary.is_none());
    assert!(crash::find_header(&stack(open(&fixtures_dir().join("lime.lime"))).unwrap()).is_none());
}

/// Literal port of python's segmented.py (`_find_segment`, `mapping`) and linear.py `read`
/// over a list of (start, length, mapped) in python order, reading from `data` like
/// physical.FileLayer (which raises unless the whole range is inside the file, even with pad).
struct PyModel<'a> {
    segs: Vec<(u64, u64, u64)>,
    data: &'a [u8],
}

impl PyModel<'_> {
    fn find(&self, off: i128, next: bool) -> Option<(i128, i128, i128)> {
        let base_max = self.data.len() as i128 - 1;
        // bisect_right(segments, (off, base_max)) with python tuple ordering
        let (mut lo, mut hi) = (0usize, self.segs.len());
        while lo < hi {
            let mid = (lo + hi) / 2;
            let (s, _, m) = self.segs[mid];
            // (off, base_max) < (s, m, l, l): a strict prefix compares smaller
            let x_lt_item = (off, base_max) <= (s as i128, m as i128);
            if x_lt_item {
                hi = mid
            } else {
                lo = mid + 1
            }
        }
        if lo > 0 && !next {
            let (s, l, m) = self.segs[lo - 1];
            if (s as i128) <= off && off < s as i128 + l as i128 {
                return Some((s as i128, m as i128, l as i128));
            }
        }
        if next && lo < self.segs.len() {
            let (s, l, m) = self.segs[lo];
            return Some((s as i128, m as i128, l as i128));
        }
        None
    }

    /// Some(chunks) or None for InvalidAddressException.
    fn mapping(&self, offset: i128, length: i128, ignore: bool) -> Option<Vec<(i128, i128, i128)>> {
        let mut out = Vec::new();
        let mut cur = offset;
        loop {
            let (mut lo, mut mo, mut size);
            match self.find(cur, false) {
                Some((l, m, sz)) => {
                    (lo, mo, size) = (l, m, sz);
                    if cur > lo {
                        let d = cur - lo;
                        lo += d;
                        mo += d;
                        size -= d;
                    }
                }
                None => {
                    if !ignore {
                        return None;
                    }
                    match self.find(cur, true) {
                        Some((l, m, sz)) => {
                            (lo, mo, size) = (l, m, sz);
                            cur = lo;
                            if lo > offset + length {
                                return Some(out);
                            }
                        }
                        None => return Some(out),
                    }
                }
            }
            let chunk = size.min(length + offset - lo);
            out.push((lo, chunk, mo));
            if chunk == 0 && ignore {
                return Some(out); // python would spin on a zero-length segment
            }
            cur += chunk;
            if cur >= offset + length {
                return Some(out);
            }
        }
    }

    fn read(&self, offset: u64, length: u64, pad: bool) -> Option<Vec<u8>> {
        let (offset, length) = (offset as i128, length as i128);
        let mut cur = offset;
        let mut out: Vec<u8> = Vec::new();
        for (off, len, mapped) in self.mapping(offset, length, pad)? {
            if !pad && off > cur {
                return None;
            } else if off > cur {
                out.resize(out.len() + (off - cur) as usize, 0);
                cur = off;
            } else if off < cur {
                return None; // LayerException: overlapping mapping
            }
            if len > 0 {
                let d = self.data.get(mapped as usize..(mapped + len) as usize)?;
                out.extend_from_slice(d);
            }
            cur += len;
        }
        out.resize(length as usize, 0);
        Some(out)
    }
}

#[test]
fn segment_semantics_match_python_model() {
    let data: Vec<u8> = (0..65536u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8).collect();
    let p = temp_file("model", &data);
    let file = open(&p);
    let base = Base::from_file(&file);
    let mut x: u64 = 0x2545_f491_4f6c_dd1d;
    let mut rnd = move |n: u64| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x % n
    };
    let (mut fast, mut exact) = (0, 0);
    for round in 0..600 {
        let n = 1 + rnd(8) as usize;
        let mut segs: Vec<(u64, u64, u64)> = (0..n).map(|_| (rnd(300), rnd(120), rnd(66000))).collect();
        if round % 2 == 0 {
            // mostly well-formed lists: sorted, touching or disjoint
            segs.sort_by_key(|s| s.0);
            for k in 1..n {
                if segs[k].0 < segs[k - 1].0 + segs[k - 1].1 && rnd(3) != 0 {
                    segs[k].0 = segs[k - 1].0 + segs[k - 1].1 + rnd(3);
                }
            }
            for s in segs.iter_mut() {
                s.2 %= 60000;
            }
        }
        let model = PyModel { segs: segs.clone(), data: &data };
        let layer = SegmentedLayer::new(
            "T",
            &base,
            segs.iter().map(|&(s, l, o)| Seg { start: s, len: l, src: Src::Raw(o) }).collect(),
        )
        .unwrap();
        if layer.is_exact_mode() {
            exact += 1;
        } else {
            fast += 1;
        }
        let top = segs.iter().map(|s| s.0 + s.1).max().unwrap() + 20;
        for a in 0..top {
            for len in [1u64, 2, 1 + rnd(40), 1 + rnd(300)] {
                let want = model.read(a, len, false);
                let mut buf = vec![0u8; len as usize];
                match (layer.read(a, &mut buf), &want) {
                    (Ok(()), Some(v)) => assert_eq!(&buf, v, "segs {segs:?} addr {a} len {len}"),
                    (Err(_), None) => {}
                    (r, v) => panic!("segs {segs:?} addr {a} len {len}: {r:?} vs {v:?}"),
                }
                if len == 1 {
                    assert_eq!(layer.is_valid(a, 1), want.is_some(), "segs {segs:?} addr {a}");
                }
                if let Some(v) = model.read(a, len, true) {
                    let mut padded = vec![0x55u8; len as usize];
                    layer.read_padded(a, &mut padded);
                    assert_eq!(padded, v, "padded: segs {segs:?} addr {a} len {len}");
                }
            }
        }
        let last = segs[n - 1];
        assert_eq!(layer.max_address(), (last.0 + last.1).saturating_sub(1));
    }
    assert!(fast > 100 && exact > 100, "fast {fast} exact {exact}");
    std::fs::remove_file(p).unwrap();
}

#[test]
fn adjacent_runs_merge_and_fill_pages() {
    let data = vec![7u8; 5 * 4096];
    let p = temp_file("merge", &data);
    let file = open(&p);
    let base = Base::from_file(&file);
    // file-contiguous and address-contiguous raw segments collapse into one run
    let segs = (0..4).map(|i| Seg { start: i * 4096, len: 4096, src: Src::Raw(i * 4096) }).collect();
    let l = SegmentedLayer::new("T", &base, segs).unwrap();
    assert_eq!(l.run_count(), 1);
    assert_eq!(l.slice(100, 3 * 4096).map(|s| s.len()), Some(3 * 4096));
    assert_eq!(l.translate(4097), Some((4097, 4 * 4096 - 4097)));
    // zero fill pages merge and slice to a static zero page; fill byte beyond EOF is unreadable
    let mut segs = vec![
        Seg { start: 0, len: 4096, src: Src::Fill { at: 1, byte: 0 } },
        Seg { start: 4096, len: 4096, src: Src::Fill { at: 2, byte: 0 } },
        Seg { start: 8192, len: 4096, src: Src::Fill { at: 3, byte: 0xab } },
    ];
    let l = SegmentedLayer::new("T", &base, segs.clone()).unwrap();
    assert!(!l.is_exact_mode());
    assert_eq!(l.run_count(), 2);
    assert_eq!(l.slice(10, 8000), Some(&[0u8; 8000][..]));
    assert_eq!(l.read_vec(8190, 4).unwrap(), vec![0, 0, 0xab, 0xab]);
    assert_eq!(l.translate(0), None);
    let mut runs = Vec::new();
    l.mapping(0, 1 << 20, &mut |m| {
        runs.push((m.offset, m.len));
        true
    });
    assert_eq!(runs, vec![(0, 8192), (8192, 4096)]);
    // a fill byte beyond the end of the file (python bisect ties change: exact mode)
    segs.push(Seg { start: 12288, len: 4096, src: Src::Fill { at: 1 << 40, byte: 1 } });
    let l = SegmentedLayer::new("T", &base, segs).unwrap();
    assert!(l.is_exact_mode());
    assert_eq!(l.read_vec(8190, 4).unwrap(), vec![0, 0, 0xab, 0xab]);
    assert!(l.read_vec(12287, 2).is_err());
    assert!(!l.is_valid(12288, 1));
    let mut runs = Vec::new();
    l.mapping(0, 1 << 20, &mut |m| {
        runs.push((m.offset, m.len));
        true
    });
    assert_eq!(runs, vec![(0, 4096), (4096, 4096), (8192, 4096)]);
    std::fs::remove_file(p).unwrap();
}

#[test]
fn truncated_file_reads() {
    // LiME segment claims 3 pages but the file stops after 1.5 pages
    let mut img = Vec::new();
    img.extend_from_slice(&lime::MAGIC.to_le_bytes());
    img.extend_from_slice(&1u32.to_le_bytes());
    img.extend_from_slice(&0x1000u64.to_le_bytes());
    img.extend_from_slice(&(0x1000u64 + 3 * 4096 - 1).to_le_bytes());
    img.extend_from_slice(&0u64.to_le_bytes());
    img.extend((0..6144u32).map(|i| (i % 251) as u8));
    let p = temp_file("trunc", &img);
    let l = stack(open(&p)).unwrap();
    assert_eq!(l.name(), "LimeLayer");
    assert_eq!(l.max_address(), 0x1000 + 3 * 4096 - 1);
    assert_eq!(l.read_vec(0x1000, 16).unwrap(), (0..16).collect::<Vec<u8>>());
    match l.read(0x1000 + 6000, &mut [0u8; 400]) {
        Err(Error::InvalidAddress { addr }) => assert_eq!(addr, 0x1000 + 6144),
        r => panic!("{r:?}"),
    }
    let mut buf = [0xffu8; 400];
    l.read_padded(0x1000 + 6000, &mut buf);
    assert_eq!(buf[..144], img[32 + 6000..32 + 6144]);
    assert!(buf[144..].iter().all(|&b| b == 0));
    let mut runs = Vec::new();
    l.mapping(0, u64::MAX, &mut |m| {
        runs.push((m.offset, m.len, m.mapped));
        true
    });
    assert_eq!(runs, vec![(0x1000, 6144, 32)]);
    std::fs::remove_file(p).unwrap();
}

/// Corrupt headers / metadata / truncate every fixture in many ways: stacking and reading must
/// never panic.
#[test]
fn malformed_containers_never_panic() {
    let dir = fixtures_dir();
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut rnd = move |n: u64| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x % n.max(1)
    };
    let mut paths: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().path()).collect();
    paths.sort();
    for p in paths {
        let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
        if matches!(ext, "expect" | "py" | "vmss" | "vmsn") {
            continue;
        }
        let orig = std::fs::read(&p).unwrap();
        for round in 0..40 {
            let mut d = orig.clone();
            match round % 4 {
                0 => {
                    // flip bytes in the first 8K (headers, tables)
                    for _ in 0..1 + rnd(8) {
                        let i = rnd(d.len().min(8192) as u64) as usize;
                        d[i] = rnd(256) as u8;
                    }
                }
                1 => d.truncate(rnd(d.len() as u64) as usize),
                2 => {
                    // overwrite a random 8-byte field anywhere with an extreme value
                    let i = rnd(d.len().saturating_sub(8) as u64) as usize;
                    let v = [0u64, u64::MAX, 0x8000_0000_0000_0000, 0xFFFF_FFFF, 1 << 40][rnd(5) as usize];
                    d[i..i + 8].copy_from_slice(&v.to_le_bytes());
                }
                _ => {
                    for _ in 0..1 + rnd(64) {
                        let i = rnd(d.len() as u64) as usize;
                        d[i] ^= 1 << rnd(8);
                    }
                }
            }
            let tp = temp_file(&format!("fuzz.{ext}"), &d);
            if ext == "vmem" {
                // corrupt the metadata instead of the flat vmem
                let meta = std::fs::read(p.with_extension("vmss")).or_else(|_| std::fs::read(p.with_extension("vmsn"))).unwrap();
                let mut m = meta.clone();
                for _ in 0..1 + rnd(4) {
                    let i = rnd(m.len() as u64) as usize;
                    m[i] = rnd(256) as u8;
                }
                if round % 5 == 0 {
                    m.truncate(rnd(m.len() as u64) as usize);
                }
                std::fs::write(tp.with_extension("vmss"), &m).unwrap();
            }
            if let Ok(l) = stack(open(&tp)) {
                let max = l.max_address();
                for _ in 0..50 {
                    let a = if rnd(2) == 0 { rnd(max.saturating_add(1).max(1)) } else { rnd(u64::MAX) };
                    let n = 1 + rnd(70000) as usize;
                    let mut buf = vec![0u8; n];
                    let _ = l.read(a, &mut buf);
                    l.read_padded(a, &mut buf);
                    let _ = l.is_valid(a, n as u64);
                    let _ = l.slice(a, n);
                    let _ = l.translate(a);
                    l.mapping(a, n as u64, &mut |_| true);
                }
                let _ = l.read(u64::MAX - 3, &mut [0u8; 16]);
                l.read_padded(u64::MAX - 3, &mut [0u8; 16]);
            }
            let _ = std::fs::remove_file(tp.with_extension("vmss"));
            std::fs::remove_file(&tp).unwrap();
        }
    }
}
