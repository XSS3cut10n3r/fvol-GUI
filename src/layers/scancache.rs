//! Per-image scan-result cache: repeat runs of scanning plugins replay the raw pattern hits of an
//! earlier full scan instead of reading gigabytes again. The cache must never change output,
//! only speed.
//!
//! What is cached: the **raw byte-level matches per scan chunk** -- the `prescan` output of a
//! two-phase [`Scanner`] (see [`Scanner::cache_query`]) -- never the plugin's validated results.
//! A cached scan replays them through the scanner's own `finish` (pool header checks, object
//! carving, MFT parsing ...) in python's chunk order, exactly as the executor calls it, so all
//! python-equivalent validation still runs and the correctness risk stays in this module.
//!
//! Atoms: a scan cache entry is one **atom** of one scan configuration:
//!   * `Lit(p)`: every occurrence (overlapping, anywhere in the chunk data) of the literal `p`,
//!     per chunk. [`CacheQuery::Greedy`] (python `MultiStringScanner`: leftmost-longest,
//!     non-overlapping, restarting in every chunk, only starts before `chunk_size`) and
//!     [`CacheQuery::Every`] (python `BytesScanner`) are derived exactly from the atoms of their
//!     literals, so ANY query over known literals is answered, not only the one that was run;
//!   * `Page(v)`: python `vmscan.PageStartScanner` hits of the 4-byte value `v` ([`page_start_hits`]);
//!   * `Opaque(key)`: a scanner's own `prescan` output, keyed by the scanner ([`CacheQuery::Opaque`]).
//!
//! The scan configuration (key material, stored in full in every file and compared on load):
//! [`CACHE_VERSION`], the layer's identity -- its class/name, bounds, translation parameters
//! (DTB, paging mode, PTE flavor) and dependencies down to the files, each identified by
//! canonical path + size + mtime + inode ([`layer_identity`]) -- the exact coalesced sections,
//! `chunk_size` and `overlap` (everything that shapes python's chunk list), plus the atom.
//!
//! Batching: a full scan (python default sections and chunking) that misses searches, in the
//! same sweep over memory, for a family of well-known literals besides its own (every built-in
//! pool tag on translation layers; MFT / MBR signatures and vmscan's VMCS page starts on
//! physical layers, plus the pool tags when the scan itself is a pool scan). The extra literals
//! ride the same Teddy prefilter pass over cache-resident data (measured: the sweep stays memory
//! bound), so the next DIFFERENT scanner of the family is answered from the cache too.
//!
//! Storage: `~/.cache/rsvol/scan/<image key>/<atom key>.hits` (image key = image file identity
//! and this executable's identity: a rebuilt binary never trusts an older binary's scans), written
//! atomically (unique temp file + rename, so concurrent processes are safe); a missing, stale or
//! corrupt file (bad magic / version / key / length / checksum / encoding) is a miss and is
//! rewritten. Format: 64-byte header, the key material, then per chunk with hits
//! `varint(chunk start delta) varint(count) count * varint(rel delta) [varint(tag)]`. The cache
//! directory is capped ([`MAX_TOTAL_BYTES`], oldest image directories are pruned first),
//! `--clear-cache` wipes it and `RSVOL_NO_SCAN_CACHE=1` disables it.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use super::Layer;
use super::scan::{self, DEFAULT_CHUNK_SIZE, DEFAULT_OVERLAP, MultiStringScanner, Scanner};
use crate::util::{par, paths};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Bump whenever the meaning of an atom changes (search semantics, chunking rules, encoding).
pub const CACHE_VERSION: u32 = 1;
/// On-disk format version (header layout).
const FORMAT_VERSION: u32 = 1;
const MAGIC: &[u8; 8] = b"RSVSCAN\x01";
const HEADER: usize = 64;
/// Cap of the whole scan cache; older image directories are removed first.
pub const MAX_TOTAL_BYTES: u64 = 256 << 20;
/// Atoms bigger than this are not written (not worth caching).
const MAX_ATOM_BYTES: usize = 64 << 20;
/// A sweep stops recording (the scan goes on, uncached) beyond this many matches: bounds the
/// memory of pathological queries (a very common needle over a huge layer).
const MAX_RECORDS: usize = 16 << 20;
/// Scans of fewer section bytes are not cached: they read at most this much (~1 ms), a cache
/// file costs about as much (e.g. linux.bash's heap scans).
const MIN_CACHED_SPAN: u128 = 16 << 20;
/// Greedy queries over more distinct literals (e.g. linux.bash's pointer needles, one per heap
/// hit) are cached whole (one atom keyed by the full query) instead of per literal.
const MAX_LITERAL_ATOMS: usize = 64;

/// What a scanner's `prescan` computes (see [`Scanner::cache_query`]). The description must be
/// exact: the cache answers a scan with matches derived from it, and the scanner's `finish`
/// turns them into hits.
pub enum CacheQuery<'a> {
    /// python `MultiStringScanner` over `patterns`: per chunk the leftmost-longest
    /// non-overlapping matches `(offset in chunk, index of the first pattern with those bytes)`
    /// starting before `limit` (empty patterns never match), at most `cap` of them.
    Greedy { patterns: &'a [Vec<u8>], limit: u64, cap: usize },
    /// python `BytesScanner(needle)`: per chunk every (overlapping) occurrence starting before
    /// `limit`, tag 0.
    Every { needle: &'a [u8], limit: u64 },
    /// Any other two-phase scanner: its `prescan` output is cached as is. `key` must identify
    /// the prescan function completely (name, version, every parameter).
    Opaque { key: Vec<u8> },
}

/// Whether the scan cache is enabled (`RSVOL_NO_SCAN_CACHE=1` disables it; unit tests never
/// touch the user's cache: they use [`Session::with_root`]).
pub fn enabled() -> bool {
    if cfg!(test) {
        return false;
    }
    static E: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *E.get_or_init(|| std::env::var_os("RSVOL_NO_SCAN_CACHE").is_none_or(|v| v.is_empty() || v == "0"))
}

/// The scan cache directory (`~/.cache/rsvol/scan`).
pub fn cache_root() -> PathBuf {
    paths::rsvol_cache_dir().join("scan")
}

// ---------------------------------------------------------------------------------------------
// Well-known literal families (batched into full sweeps)
// ---------------------------------------------------------------------------------------------

/// Every pool tag of the built-in pool scanners (`poolscanner.builtin_constraints`, the GUI
/// constraints, netscan, callbacks).
pub const POOL_TAGS: [&[u8]; 28] = [
    b"AtmT", b"Pro\xe3", b"Proc", b"Thr\xe5", b"Thre", b"Fil\xe5", b"File", b"Mut\xe1", b"Muta", b"Dri\xf6", b"Driv", b"MmLd", b"Sym\xe2", b"Symb",
    b"CM10", b"Wind", b"Desk", b"IoFs", b"IoSh", b"Cbrb", b"DbCb", b"Pnp9", b"PnpD", b"PnpC", b"TcpL", b"TcpE", b"UdpA", b"TTcb",
];
/// Physical-layer signatures: mftscan's yara literals, mbrscan's boot signature.
pub const PHYS_LITERALS: [&[u8]; 4] = [b"FILE0", b"FILE*", b"BAAD", b"\x55\xaa"];
/// VMCS revision ids of the shipped `generic/vmcs` ISFs (vmscan's page-start signatures).
pub const VMCS_REVISION_IDS: [u32; 5] = [4, 14, 15, 16, 18];

// ---------------------------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------------------------

/// 64-bit hash of key material / payloads (file names, checksums): every 8-byte word is fully
/// mixed (murmur3 `fmix64`) before the next one. NOT FxHash: its multiply only carries a
/// difference upwards, so two keys differing in the top byte of one word and the low byte of
/// the next collide easily -- measured on real keys (kernel-address needles straddling a word
/// boundary). Every step is a bijection of the state, so keys that differ in one word never
/// collide; the length is mixed in first.
fn key_hash(b: &[u8]) -> u64 {
    #[inline(always)]
    fn fmix(mut h: u64) -> u64 {
        h ^= h >> 33;
        h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
        h ^= h >> 33;
        h = h.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
        h ^ (h >> 33)
    }
    let mut h = fmix(0x9e37_79b9_7f4a_7c15 ^ b.len() as u64);
    let (words, rest) = b.as_chunks::<8>();
    for w in words {
        h = fmix(h ^ u64::from_le_bytes(*w));
    }
    if !rest.is_empty() {
        let mut w = [0u8; 8];
        w[..rest.len()].copy_from_slice(rest);
        h = fmix(h ^ u64::from_le_bytes(w));
    }
    h
}

/// Canonical key material builder.
struct Key(Vec<u8>);

impl Key {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn bytes(&mut self, b: &[u8]) {
        self.u64(b.len() as u64);
        self.0.extend_from_slice(b);
    }
}

/// Identity of an open file: canonical path + size + mtime + device/inode (of the open
/// descriptor, i.e. of the bytes we map).
fn file_identity(f: &super::FileLayer, k: &mut Key) -> Option<()> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    let md = f.file().metadata().ok()?;
    k.bytes(b"file");
    k.bytes(f.path().as_os_str().as_bytes());
    k.u64(md.len());
    k.u64(md.mtime() as u64);
    k.u64(md.mtime_nsec() as u64);
    k.u64(md.dev());
    k.u64(md.ino());
    Some(())
}

/// The identity of a layer: everything that determines its bytes at every address (see the
/// module docs). `None` for layers whose translation depends on state not visible here
/// (registry hives: never cached).
pub fn layer_identity(layer: &dyn Layer) -> Option<Vec<u8>> {
    let mut k = Key(Vec::new());
    identity(layer, &mut k, 0)?;
    Some(k.0)
}

fn identity(layer: &dyn Layer, k: &mut Key, depth: u32) -> Option<()> {
    if depth > 16 || layer.as_registry_hive().is_some() {
        return None;
    }
    if let Some(f) = layer.as_file() {
        return file_identity(f, k);
    }
    k.bytes(b"layer");
    k.bytes(layer.class_name().as_bytes());
    k.u64(layer.min_address());
    k.u64(layer.max_address());
    k.u8(layer.is_linear() as u8);
    if let Some(i) = layer.as_intel() {
        // the name of a translation layer does not change its bytes
        k.bytes(b"intel");
        k.bytes(format!("{:?}/{:?}", i.mode(), i.flavor()).as_bytes());
        k.u64(i.page_map_offset());
    } else {
        k.bytes(layer.name().as_bytes());
        k.u64(layer.dtb().unwrap_or(u64::MAX));
    }
    match layer.lower() {
        Some(l) => {
            k.u8(1);
            identity(l.as_ref(), k, depth + 1)?;
        }
        None => k.u8(0),
    }
    let deps = layer.dependencies();
    k.u64(deps.len() as u64);
    for d in &deps {
        identity(d.as_ref(), k, depth + 1)?;
    }
    Some(())
}

/// This executable's identity (a rebuilt binary never trusts an older one's cache).
fn exe_identity(k: &mut Key) {
    use std::os::unix::fs::MetadataExt;
    static ID: std::sync::OnceLock<(u64, u64, u64)> = std::sync::OnceLock::new();
    let &(len, s, ns) = ID.get_or_init(|| {
        paths::current_exe().and_then(|p| std::fs::metadata(p).ok()).map_or((0, 0, 0), |m| (m.len(), m.mtime() as u64, m.mtime_nsec() as u64))
    });
    k.bytes(b"exe");
    k.u64(len);
    k.u64(s);
    k.u64(ns);
}

/// One atom of a scan configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Atom<'a> {
    Lit(&'a [u8]),
    Page(u32),
    Opaque(&'a [u8]),
}

impl Atom<'_> {
    fn kind(&self) -> u32 {
        match self {
            Atom::Lit(_) => 0,
            Atom::Page(_) => 1,
            Atom::Opaque(_) => 2,
        }
    }
    fn tagged(&self) -> bool {
        matches!(self, Atom::Opaque(_))
    }
}

/// Where the atoms of one scan configuration (layer + sections + chunking) live.
pub struct Session {
    dir: PathBuf,
    /// key material shared by the configuration's atoms
    key: Vec<u8>,
    /// full scan with python's default sections and chunking (batching allowed)
    full_default: bool,
    /// a translation (Intel) layer
    intel: bool,
    /// vmscan page starts can be recorded by a sweep (see [`pages_recordable`])
    pages: bool,
    /// the image directory existed when the session was made
    dir_existed: bool,
}

impl Session {
    /// The cache session of a scan of `secs` (coalesced sections; `full` = python's default
    /// sections) of `layer` with the given chunking, or `None` when the scan is not cacheable
    /// (cache disabled, no backing file, unidentifiable layer, nothing to scan).
    pub fn new(layer: &dyn Layer, secs: &[(u64, u64)], full: bool, chunk_size: u64, overlap: u64) -> Option<Session> {
        if !enabled() || secs.iter().map(|s| s.1 as u128).sum::<u128>() < MIN_CACHED_SPAN {
            return None;
        }
        Session::with_root(&cache_root(), layer, secs, full, chunk_size, overlap)
    }

    /// [`Session::new`] with an explicit cache root (tests).
    pub fn with_root(root: &Path, layer: &dyn Layer, secs: &[(u64, u64)], full: bool, chunk_size: u64, overlap: u64) -> Option<Session> {
        if secs.is_empty() || chunk_size == 0 {
            return None;
        }
        let file = super::base_file(layer)?;
        let mut img = Key(Vec::new());
        img.bytes(b"rsvol-scan-image");
        img.u64(CACHE_VERSION as u64);
        exe_identity(&mut img);
        file_identity(file, &mut img)?;
        let dir = root.join(format!("{:016x}", key_hash(&img.0)));
        let mut k = Key(Vec::new());
        k.bytes(b"rsvol-scan");
        k.u64(CACHE_VERSION as u64);
        k.bytes(&layer_identity(layer)?);
        k.u64(secs.len() as u64);
        for &(s, l) in secs {
            k.u64(s);
            k.u64(l);
        }
        k.u64(chunk_size);
        k.u64(overlap);
        let full_default = full && chunk_size == DEFAULT_CHUNK_SIZE && overlap == DEFAULT_OVERLAP;
        let intel = layer.as_intel().is_some();
        let pages = full_default && !intel && pages_recordable(layer, secs);
        let dir_existed = dir.is_dir();
        Some(Session { dir, key: k.0, full_default, intel, pages, dir_existed })
    }

    fn atom_key(&self, atom: &Atom) -> Vec<u8> {
        let mut k = Key(self.key.clone());
        k.u64(atom.kind() as u64);
        match atom {
            Atom::Lit(p) | Atom::Opaque(p) => k.bytes(p),
            Atom::Page(v) => k.u64(*v as u64),
        }
        k.0
    }

    fn atom_path(&self, key: &[u8]) -> PathBuf {
        self.dir.join(format!("{:016x}.hits", key_hash(key)))
    }

    fn load(&self, atom: &Atom) -> Option<Groups> {
        let key = self.atom_key(atom);
        let path = self.atom_path(&key);
        let Ok(buf) = std::fs::read(&path) else {
            crate::util::trace::note(|| format!("scan cache: no {atom:?} ({})", path.display()));
            return None;
        };
        let g = decode(&buf, atom.kind(), atom.tagged(), &key);
        if g.is_none() {
            crate::util::trace::note(|| {
                let stored = buf.get(HEADER..).unwrap_or(&[]);
                let diff = key.iter().zip(stored).position(|(a, b)| a != b);
                format!("scan cache: damaged {atom:?} ({}), key len {} first key difference at {diff:?}", path.display(), key.len())
            });
        }
        g
    }

    /// Write the atoms, then keep the cache under its size cap when this created the image
    /// directory. Sequential: a small-file create + rename costs ~20 us on btrfs and parallel
    /// writers only contend on the directory (measured: 30 atoms 0.9 ms sequential, 1.2 ms on
    /// all cores).
    fn store_all(&self, atoms: &[(Atom, &Groups)]) {
        if std::fs::create_dir_all(&self.dir).is_err() {
            return;
        }
        for (atom, g) in atoms {
            let key = self.atom_key(atom);
            match encode(atom.kind(), atom.tagged(), &key, g) {
                Some(buf) => {
                    let _ = write_atomic(&self.atom_path(&key), &buf);
                }
                None => crate::util::trace::note(|| format!("scan cache: {atom:?} not stored ({} chunks, {} matches)", g.starts.len(), g.rels.len())),
            }
        }
        if !self.dir_existed {
            prune(self.dir.parent().unwrap_or(Path::new(".")), &self.dir, MAX_TOTAL_BYTES);
        }
    }
}

/// Whether a sweep of `layer` may record vmscan page starts: the layer's bytes are read the way
/// vmscan reads them (the file, or a linear container over it: direct file reads), and every
/// python chunk starts on a page boundary (python's `PageStartScanner` checks
/// `data_offset % 0x1000 + k * 0x1000`; for aligned chunks those are the chunk's pages).
fn pages_recordable(layer: &dyn Layer, secs: &[(u64, u64)]) -> bool {
    if layer.as_file().is_some() {
        return secs.iter().all(|s| s.0 % 0x1000 == 0);
    }
    if !(layer.is_linear() && layer.lower().is_some_and(|l| l.as_file().is_some())) {
        return false;
    }
    let mut ok = true;
    for &(s, l) in secs {
        layer.mapping(s, l, &mut |m| {
            ok &= m.offset % 0x1000 == 0;
            ok
        });
    }
    ok
}

// ---------------------------------------------------------------------------------------------
// Hit lists and their file format
// ---------------------------------------------------------------------------------------------

/// Per-chunk match lists: chunk `i` starts at `starts[i]` and has matches
/// `rels[ends[i-1]..ends[i]]` (+ `tags` for opaque atoms). Chunks without matches are absent;
/// chunk starts ascend strictly (python's chunk order).
#[derive(Default, Debug, Clone, PartialEq)]
struct Groups {
    starts: Vec<u64>,
    ends: Vec<u32>,
    rels: Vec<u64>,
    tags: Vec<u32>,
}

impl Groups {
    #[inline]
    fn range(&self, i: usize) -> std::ops::Range<usize> {
        (if i == 0 { 0 } else { self.ends[i - 1] as usize })..self.ends[i] as usize
    }
    /// Append a match of the chunk at `start` (chunks in ascending order); false if out of order.
    #[inline]
    fn push(&mut self, start: u64, rel: u64, tag: Option<u32>) -> bool {
        match self.starts.last() {
            Some(&s) if s == start => {}
            Some(&s) if s > start => return false,
            _ => {
                self.starts.push(start);
                self.ends.push(self.rels.len() as u32);
            }
        }
        self.rels.push(rel);
        if let Some(t) = tag {
            self.tags.push(t);
        }
        *self.ends.last_mut().unwrap() = self.rels.len() as u32;
        true
    }
}

#[inline]
fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push(v as u8 | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

#[inline]
fn get_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    let mut shift = 0u32;
    loop {
        let b = *buf.get(*pos)?;
        *pos += 1;
        if shift == 63 && b > 1 {
            return None;
        }
        v |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some(v);
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
}

#[inline]
fn zigzag(d: i64) -> u64 {
    ((d << 1) ^ (d >> 63)) as u64
}

#[inline]
fn unzigzag(v: u64) -> i64 {
    ((v >> 1) as i64) ^ -((v & 1) as i64)
}

fn checksum(key: &[u8], payload: &[u8]) -> u64 {
    key_hash(key) ^ key_hash(payload).rotate_left(17)
}

/// Serialize `g` (None when too big or malformed).
fn encode(kind: u32, tagged: bool, key: &[u8], g: &Groups) -> Option<Vec<u8>> {
    let mut payload = Vec::with_capacity(g.rels.len() * 2 + g.starts.len() * 4);
    let mut prev_start = 0u64;
    for i in 0..g.starts.len() {
        let s = g.starts[i];
        if i > 0 && s <= prev_start {
            return None;
        }
        put_varint(&mut payload, if i == 0 { s } else { s - prev_start });
        prev_start = s;
        let r = g.range(i);
        if r.is_empty() {
            return None;
        }
        put_varint(&mut payload, r.len() as u64);
        let mut prev = 0u64;
        for j in r {
            let rel = g.rels[j];
            if tagged {
                put_varint(&mut payload, zigzag(rel.wrapping_sub(prev) as i64));
                put_varint(&mut payload, g.tags[j] as u64);
            } else {
                put_varint(&mut payload, rel.checked_sub(prev)?);
            }
            prev = rel;
        }
        if payload.len() > MAX_ATOM_BYTES {
            return None;
        }
    }
    let mut out = Vec::with_capacity(HEADER + key.len() + payload.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&(key.len() as u64).to_le_bytes());
    out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    out.extend_from_slice(&(g.starts.len() as u64).to_le_bytes());
    out.extend_from_slice(&(g.rels.len() as u64).to_le_bytes());
    out.extend_from_slice(&checksum(key, &payload).to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(key);
    out.extend_from_slice(&payload);
    Some(out)
}

/// Parse and verify a file written by [`encode`] for `key`; None on any mismatch or damage.
fn decode(buf: &[u8], kind: u32, tagged: bool, key: &[u8]) -> Option<Groups> {
    let u32_at = |o: usize| u32::from_le_bytes(buf[o..o + 4].try_into().unwrap());
    let u64_at = |o: usize| u64::from_le_bytes(buf[o..o + 8].try_into().unwrap());
    if buf.len() < HEADER || &buf[..8] != MAGIC || u32_at(8) != FORMAT_VERSION || u32_at(12) != kind {
        return None;
    }
    let (klen, plen, ngroups, nrecs, sum) = (u64_at(16), u64_at(24), u64_at(32), u64_at(40), u64_at(48));
    if u64_at(56) != 0 || klen != key.len() as u64 || (buf.len() - HEADER) as u64 != klen.checked_add(plen)? {
        return None;
    }
    let (k, payload) = buf[HEADER..].split_at(key.len());
    if k != key || checksum(key, payload) != sum {
        return None;
    }
    // every group takes >= 3 bytes, every record >= 1 (2 when tagged)
    if ngroups > plen / 3 || nrecs > plen || nrecs > u32::MAX as u64 {
        return None;
    }
    let mut g = Groups {
        starts: Vec::with_capacity(ngroups as usize),
        ends: Vec::with_capacity(ngroups as usize),
        rels: Vec::with_capacity(nrecs as usize),
        tags: Vec::with_capacity(if tagged { nrecs as usize } else { 0 }),
    };
    let mut pos = 0usize;
    let mut start = 0u64;
    for i in 0..ngroups {
        let d = get_varint(payload, &mut pos)?;
        if i > 0 && d == 0 {
            return None;
        }
        start = start.checked_add(d)?;
        let n = get_varint(payload, &mut pos)?;
        if n == 0 || n > nrecs - g.rels.len() as u64 {
            return None;
        }
        g.starts.push(start);
        let mut rel = 0u64;
        for _ in 0..n {
            let v = get_varint(payload, &mut pos)?;
            if tagged {
                rel = rel.wrapping_add(unzigzag(v) as u64);
                let t = get_varint(payload, &mut pos)?;
                g.tags.push(u32::try_from(t).ok()?);
            } else {
                rel = rel.checked_add(v)?;
            }
            g.rels.push(rel);
        }
        g.ends.push(g.rels.len() as u32);
    }
    if pos != payload.len() || g.rels.len() as u64 != nrecs {
        return None;
    }
    Some(g)
}

/// Write `data` to `path` (in an existing directory) atomically: a temp file unique to this
/// process and call, then rename.
fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let tmp = path.with_extension(format!("tmp{}.{}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed)));
    let r = std::fs::write(&tmp, data).and_then(|_| std::fs::rename(&tmp, path));
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r
}

/// Remove the oldest image directories under `root` (never `keep`) until the scan cache
/// takes at most `cap` bytes.
fn prune(root: &Path, keep: &Path, cap: u64) {
    let Ok(rd) = std::fs::read_dir(root) else { return };
    let mut dirs: Vec<(std::time::SystemTime, u64, PathBuf)> = Vec::new();
    let mut total = 0u64;
    for e in rd.flatten() {
        let p = e.path();
        let Ok(md) = e.metadata() else { continue };
        if !md.is_dir() {
            continue;
        }
        let size: u64 = std::fs::read_dir(&p).map(|r| r.flatten().filter_map(|f| f.metadata().ok()).map(|m| m.len()).sum()).unwrap_or(0);
        total += size;
        if p != keep {
            dirs.push((md.modified().unwrap_or(std::time::UNIX_EPOCH), size, p));
        }
    }
    dirs.sort();
    for (_, size, p) in dirs {
        if total <= cap {
            break;
        }
        if std::fs::remove_dir_all(&p).is_ok() {
            total -= size;
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Scanning through the cache
// ---------------------------------------------------------------------------------------------

/// The opaque key of a greedy query cached whole: every pattern in order (tags are indices),
/// the start limit and the cap. The scanner's prescan computes exactly this query.
fn whole_query_key(patterns: &[Vec<u8>], limit: u64, cap: usize) -> Vec<u8> {
    let mut k = Key(Vec::new());
    k.bytes(b"greedy-query/1");
    k.u64(limit);
    k.u64(cap as u64);
    k.u64(patterns.len() as u64);
    for p in patterns {
        k.bytes(p);
    }
    k.0
}

/// Distinct non-empty patterns of a query: `(bytes, tag = index of the first equal pattern)`.
fn distinct_patterns(patterns: &[Vec<u8>]) -> Vec<(&[u8], u32)> {
    let mut out: Vec<(&[u8], u32)> = Vec::new();
    for (i, p) in patterns.iter().enumerate() {
        if !p.is_empty() && !out.iter().any(|(q, _)| *q == p.as_slice()) {
            out.push((p, i as u32));
        }
    }
    out
}

/// How a chunk's literal occurrences become the scanner's prescan matches.
enum Derive {
    /// greedy over the literals `lit id -> (tag, len)` (None = not in the query)
    Greedy { map: Vec<Option<(u32, u32)>>, limit: u64, cap: usize },
    Every { id: u32, limit: u64 },
}

impl Derive {
    /// `occ`: `(rel, literal id)` of one chunk, ascending by rel per literal. Appends the
    /// query's matches to `out`; `cand` is scratch.
    fn apply(&self, occ: &[(u64, u32)], cand: &mut Vec<(u64, u32, u32)>, out: &mut Vec<(u64, u32)>) {
        match self {
            Derive::Every { id, limit } => out.extend(occ.iter().filter(|o| o.1 == *id && o.0 < *limit).map(|o| (o.0, 0))),
            Derive::Greedy { map, limit, cap } => {
                cand.clear();
                cand.extend(occ.iter().filter_map(|&(rel, id)| map.get(id as usize).copied().flatten().map(|(tag, len)| (rel, len, tag))));
                greedy(cand, *limit, *cap, out);
            }
        }
    }
}

/// python's leftmost-longest non-overlapping selection over one chunk's occurrences
/// `(rel, len, tag)` (any order): at each position the longest pattern wins, the search resumes
/// after it; only starts before `limit`, at most `cap` matches.
fn greedy(cand: &mut [(u64, u32, u32)], limit: u64, cap: usize, out: &mut Vec<(u64, u32)>) {
    if !cand.is_sorted_by_key(|c| c.0) {
        cand.sort_unstable_by_key(|c| c.0);
    }
    let mut next = 0u64;
    let mut n = 0usize;
    let mut i = 0usize;
    while i < cand.len() {
        let rel = cand[i].0;
        let mut best = i;
        let mut j = i + 1;
        while j < cand.len() && cand[j].0 == rel {
            if cand[j].1 > cand[best].1 {
                best = j;
            }
            j += 1;
        }
        i = j;
        if rel >= limit || n >= cap {
            break;
        }
        if rel < next {
            continue;
        }
        out.push((rel, cand[best].2));
        next = rel + cand[best].1 as u64;
        n += 1;
    }
}

/// [`super::scan::scan_each`] through the cache: replay the cached matches of this scan
/// configuration, or run the scan (a sweep that also records the atoms) and store them.
pub fn scan_each<S, F>(session: &Session, layer: &dyn Layer, scanner: &S, q: CacheQuery, secs: &[(u64, u64)], f: F)
where
    S: Scanner,
    F: FnMut(S::Hit) -> bool,
{
    let q = match q {
        CacheQuery::Greedy { patterns, limit, cap } if distinct_patterns(patterns).len() > MAX_LITERAL_ATOMS => {
            CacheQuery::Opaque { key: whole_query_key(patterns, limit, cap) }
        }
        q => q,
    };
    let cached = {
        let _t = crate::util::trace::span("scan cache: load");
        load_query(session, &q)
    };
    match cached {
        Some(m) => {
            let _t = crate::util::trace::span("scan cache: replay");
            crate::util::trace::note(|| format!("scan cache: hit, {} chunks, {} matches", m.starts.len(), m.rels.len()));
            replay(scanner, &m, f)
        }
        None => {
            crate::util::trace::note(|| {
                let what = match &q {
                    CacheQuery::Greedy { patterns, .. } => format!("{} literals {:?}", patterns.len(), patterns.iter().map(|p| String::from_utf8_lossy(p).into_owned()).collect::<Vec<_>>()),
                    CacheQuery::Every { needle, .. } => format!("needle {:?}", String::from_utf8_lossy(needle)),
                    CacheQuery::Opaque { key } => format!("opaque {:?}", String::from_utf8_lossy(key)),
                };
                format!("scan cache: miss ({what}) in {}", session.dir.display())
            });
            let plan = Plan::new(session, &q);
            let opaque = match &q {
                CacheQuery::Opaque { key } => Some(key.clone()),
                _ => None,
            };
            let mut may_wait = true;
            loop {
                match take_turn(session, &q, &plan.lits, opaque.as_deref(), may_wait) {
                    Turn::Wait(e) => {
                        let _t = crate::util::trace::span("scan cache: wait for a running sweep");
                        e.wait();
                        may_wait = false;
                        if let Some(m) = load_query(session, &q) {
                            return replay(scanner, &m, f);
                        }
                    }
                    Turn::Sweep(claim) => {
                        match &opaque {
                            Some(key) => sweep_opaque(session, layer, scanner, key, secs, f),
                            None => sweep_literals(session, layer, scanner, plan, secs, f),
                        }
                        drop(claim);
                        return;
                    }
                }
            }
        }
    }
}

/// The matches of `q` (the scanner's prescan output per chunk) from the cache, if every atom
/// it needs is there.
fn load_query(session: &Session, q: &CacheQuery) -> Option<Groups> {
    match q {
        CacheQuery::Opaque { key } => session.load(&Atom::Opaque(key)),
        CacheQuery::Every { needle, limit } => {
            let a = session.load(&Atom::Lit(needle))?;
            let mut g = Groups::default();
            for i in 0..a.starts.len() {
                for j in a.range(i) {
                    if a.rels[j] < *limit {
                        g.push(a.starts[i], a.rels[j], Some(0));
                    }
                }
            }
            Some(g)
        }
        CacheQuery::Greedy { patterns, limit, cap } => {
            let pats = distinct_patterns(patterns);
            let mut atoms: Vec<(Groups, u32, u32)> = Vec::with_capacity(pats.len());
            for &(p, tag) in &pats {
                atoms.push((session.load(&Atom::Lit(p))?, tag, p.len() as u32));
            }
            Some(merge_greedy(&atoms, *limit, *cap))
        }
    }
}

/// Merge per-literal atoms `(groups, tag, len)` chunk by chunk and apply the greedy selection.
fn merge_greedy(atoms: &[(Groups, u32, u32)], limit: u64, cap: usize) -> Groups {
    let mut out = Groups::default();
    let mut cur = vec![0usize; atoms.len()];
    let mut cand: Vec<(u64, u32, u32)> = Vec::new();
    let mut sel: Vec<(u64, u32)> = Vec::new();
    loop {
        let mut cs = u64::MAX;
        let mut any = false;
        for (i, (g, _, _)) in atoms.iter().enumerate() {
            if let Some(&s) = g.starts.get(cur[i])
                && (!any || s < cs)
            {
                cs = s;
                any = true;
            }
        }
        if !any {
            break;
        }
        cand.clear();
        for (i, (g, tag, len)) in atoms.iter().enumerate() {
            if g.starts.get(cur[i]) == Some(&cs) {
                cand.extend(g.range(cur[i]).map(|j| (g.rels[j], *len, *tag)));
                cur[i] += 1;
            }
        }
        sel.clear();
        greedy(&mut cand, limit, cap, &mut sel);
        for &(rel, tag) in &sel {
            out.push(cs, rel, Some(tag));
        }
    }
    out
}

/// Matches per replay work item (about).
const REPLAY_ITEM: usize = 256;

/// Hand the cached matches to `scanner.finish` chunk by chunk (in parallel, results in python
/// order, `f` may stop early).
fn replay<S, F>(scanner: &S, m: &Groups, mut f: F)
where
    S: Scanner,
    F: FnMut(S::Hit) -> bool,
{
    let n = m.starts.len();
    let matches: Vec<(u64, u32)> = m.rels.iter().zip(&m.tags).map(|(&r, &t)| (r, t)).collect();
    let run = |a: usize, b: usize, hits: &mut Vec<S::Hit>| {
        for i in a..b {
            scanner.finish(&matches[m.range(i)], m.starts[i], hits);
        }
    };
    if matches.len() <= REPLAY_ITEM || par::threads() <= 1 {
        let mut hits = Vec::new();
        for i in 0..n {
            run(i, i + 1, &mut hits);
            for h in hits.drain(..) {
                if !f(h) {
                    return;
                }
            }
        }
        return;
    }
    let mut items: Vec<(usize, usize)> = Vec::new();
    let mut a = 0usize;
    let mut cnt = 0usize;
    for i in 0..n {
        cnt += m.range(i).len();
        if cnt >= REPLAY_ITEM {
            items.push((a, i + 1));
            a = i + 1;
            cnt = 0;
        }
    }
    if a < n {
        items.push((a, n));
    }
    par::par_map_stream(
        items.len(),
        par::threads() * 4,
        |k| {
            let mut hits = Vec::new();
            run(items[k].0, items[k].1, &mut hits);
            hits
        },
        |_, hits| {
            for h in hits {
                if !f(h) {
                    return false;
                }
            }
            true
        },
    );
}

/// A hit of a recording sweep: one chunk's raw matches (to record) or a hit of the scanner.
enum Rec<H> {
    Raw(u64, Box<[(u64, u32)]>),
    Hit(H),
}

/// The literals of a sweep: ONE Teddy pass for all of them (measured on the 5 GiB image: a
/// sweep for 32 literals incl. the 2-byte MBR signature costs the same as a plain scan for one
/// of them -- the pass is memory bound; a second pass for short literals cost ~6%). Literals
/// are distinct and non-empty, so a pattern index is the literal id.
struct Literals {
    ms: MultiStringScanner,
    max_len: usize,
}

impl Literals {
    fn new(lits: &[Vec<u8>]) -> Literals {
        Literals { ms: MultiStringScanner::new(lits), max_len: lits.iter().map(|l| l.len()).max().unwrap_or(1) }
    }

    fn get(&self, id: usize) -> &[u8] {
        self.ms.pattern(id)
    }

    fn len(&self) -> usize {
        self.ms.patterns().len()
    }

    /// Every occurrence starting in `data[from..limit)`: `(base + pos, literal id)`.
    #[inline]
    fn search(&self, data: &[u8], base: u64, from: usize, limit: usize, out: &mut Vec<(u64, u32)>) {
        self.ms.search_every(data, from, limit, |p, i| out.push((base + p as u64, i)));
    }
}

/// The recording adapter of a literal sweep: finds every literal (the query's and the batched
/// ones) and vmscan page starts, records them per chunk and hands the query's matches to the
/// scanner's `finish`.
struct Sweep<'a, S> {
    inner: &'a S,
    lits: Literals,
    /// page-start values (ids `lits.len() + i`)
    pages: Vec<u32>,
    derive: Derive,
}

impl<S: Scanner> Sweep<'_, S> {
    #[inline]
    fn pages_in(&self, data: &[u8], base: u64, from: usize, limit: usize, out: &mut Vec<(u64, u32)>) {
        if self.pages.is_empty() {
            return;
        }
        let first = (from as u64 + base).next_multiple_of(0x1000) - base;
        let mut q = first as usize;
        while q < limit && q + 4 <= data.len() {
            let v = u32::from_le_bytes(data[q..q + 4].try_into().unwrap());
            if let Some(i) = self.pages.iter().position(|&p| p == v) {
                out.push((base + q as u64, (self.lits.len() + i) as u32));
            }
            q += 0x1000;
        }
    }
}

impl<S: Scanner> Scanner for Sweep<'_, S> {
    type Hit = Rec<S::Hit>;
    fn chunk_size(&self) -> u64 {
        self.inner.chunk_size()
    }
    fn overlap(&self) -> u64 {
        self.inner.overlap()
    }
    fn scan(&self, data: &[u8], data_offset: u64, hits: &mut Vec<Self::Hit>) {
        let mut m = Vec::new();
        self.prescan(data, &mut m);
        if !m.is_empty() {
            self.finish(&m, data_offset, hits);
        }
    }
    fn prescan(&self, data: &[u8], out: &mut Vec<(u64, u32)>) -> bool {
        self.lits.search(data, 0, 0, data.len(), out);
        self.pages_in(data, 0, 0, data.len(), out);
        true
    }
    fn finish(&self, matches: &[(u64, u32)], data_offset: u64, hits: &mut Vec<Self::Hit>) {
        hits.push(Rec::Raw(data_offset, matches.into()));
        let mut cand = Vec::new();
        let mut mine = Vec::new();
        self.derive.apply(matches, &mut cand, &mut mine);
        if !mine.is_empty() {
            let mut h = Vec::new();
            self.inner.finish(&mine, data_offset, &mut h);
            hits.extend(h.into_iter().map(Rec::Hit));
        }
    }
    fn stream_window(&self) -> Option<usize> {
        Some(if self.pages.is_empty() { self.lits.max_len } else { self.lits.max_len.max(4) })
    }
    fn prescan_piece(&self, data: &[u8], base: u64, from: usize, limit: usize, out: &mut Vec<(u64, u32)>) -> usize {
        // every position is independent: nothing carries over to the next piece
        self.lits.search(data, base, from, limit, out);
        self.pages_in(data, base, from, limit, out);
        limit
    }
}

/// What a literal sweep searches: the query's literals plus the batched families, vmscan page
/// starts, and how the query's matches are derived from them.
struct Plan {
    lits: Vec<Vec<u8>>,
    pages: Vec<u32>,
    derive: Derive,
}

impl Plan {
    fn new(session: &Session, q: &CacheQuery) -> Plan {
        let mut lits: Vec<Vec<u8>> = Vec::new();
        let add = |p: &[u8], lits: &mut Vec<Vec<u8>>| -> u32 {
            match lits.iter().position(|l| l == p) {
                Some(i) => i as u32,
                None => {
                    lits.push(p.to_vec());
                    (lits.len() - 1) as u32
                }
            }
        };
        let derive = match q {
            CacheQuery::Every { needle, limit } => Derive::Every { id: add(needle, &mut lits), limit: *limit },
            CacheQuery::Greedy { patterns, limit, cap } => {
                let mut map = Vec::new();
                for (p, tag) in distinct_patterns(patterns) {
                    let id = add(p, &mut lits) as usize;
                    map.resize(map.len().max(id + 1), None);
                    map[id] = Some((tag, p.len() as u32));
                }
                Derive::Greedy { map, limit: *limit, cap: *cap }
            }
            CacheQuery::Opaque { .. } => Derive::Every { id: u32::MAX, limit: 0 },
        };
        let mut pages = Vec::new();
        if session.full_default && !matches!(q, CacheQuery::Opaque { .. }) {
            if session.intel {
                for t in POOL_TAGS {
                    add(t, &mut lits);
                }
            } else {
                let pool_scan = lits.iter().any(|l| POOL_TAGS.contains(&l.as_slice()));
                for t in PHYS_LITERALS {
                    add(t, &mut lits);
                }
                if pool_scan {
                    for t in POOL_TAGS {
                        add(t, &mut lits);
                    }
                }
                if session.pages {
                    pages = VMCS_REVISION_IDS.to_vec();
                }
            }
        }
        Plan { lits, pages, derive }
    }
}

/// A miss of a literal query: sweep the layer once for the plan's literals, feed the scanner,
/// and store every atom when the scan ran to the end.
fn sweep_literals<S, F>(session: &Session, layer: &dyn Layer, scanner: &S, plan: Plan, secs: &[(u64, u64)], mut f: F)
where
    S: Scanner,
    F: FnMut(S::Hit) -> bool,
{
    let nlits = plan.lits.len();
    let sweep = Sweep { inner: scanner, lits: Literals::new(&plan.lits), pages: plan.pages, derive: plan.derive };
    let mut rec: Vec<Groups> = (0..nlits + sweep.pages.len()).map(|_| Groups::default()).collect();
    let mut ok = true;
    let mut total = 0usize;
    let mut stopped = false;
    scan::execute(layer, &sweep, secs, |h| match h {
        Rec::Raw(cs, m) => {
            if ok {
                for &(rel, id) in m.iter() {
                    ok &= rec[id as usize].push(cs, rel, None);
                }
                total += m.len();
                if total > MAX_RECORDS {
                    ok = false;
                    rec = Vec::new();
                }
            }
            true
        }
        Rec::Hit(h) => {
            if f(h) {
                true
            } else {
                stopped = true;
                false
            }
        }
    });
    if stopped || !ok {
        return;
    }
    let _t = crate::util::trace::span("scan cache: store");
    let atoms: Vec<(Atom, &Groups)> =
        rec.iter().enumerate().map(|(id, g)| (if id < nlits { Atom::Lit(sweep.lits.get(id)) } else { Atom::Page(sweep.pages[id - nlits]) }, g)).collect();
    session.store_all(&atoms);
}

// ---------------------------------------------------------------------------------------------
// Sweeps in flight (one process): concurrent plugins (timeliner runs them on parallel threads)
// that miss on the same configuration would all sweep; a scan whose atoms a running sweep will
// record waits for it and replays instead. A thread that is sweeping never waits (its consumer
// may start further scans), so waits cannot form cycles; the registration is released on every
// exit path (also by a panicking consumer), and a wait gives up after `INFLIGHT_WAIT`.
// ---------------------------------------------------------------------------------------------

/// Longest wait for another thread's sweep before sweeping ourselves.
const INFLIGHT_WAIT: std::time::Duration = std::time::Duration::from_secs(120);

struct InFlight {
    key: Vec<u8>,
    /// literals the sweep records (literal sweeps) / the opaque key (opaque sweeps)
    lits: Vec<Vec<u8>>,
    opaque: Option<Vec<u8>>,
    done: std::sync::Mutex<bool>,
    cv: std::sync::Condvar,
}

impl InFlight {
    fn covers(&self, key: &[u8], q: &CacheQuery) -> bool {
        self.key == key
            && match q {
                CacheQuery::Opaque { key } => self.opaque.as_deref() == Some(key.as_slice()),
                CacheQuery::Every { needle, .. } => self.opaque.is_none() && self.lits.iter().any(|l| l.as_slice() == *needle),
                CacheQuery::Greedy { patterns, .. } => {
                    self.opaque.is_none() && patterns.iter().filter(|p| !p.is_empty()).all(|p| self.lits.iter().any(|l| l == p))
                }
            }
    }

    fn wait(&self) {
        let deadline = std::time::Instant::now() + INFLIGHT_WAIT;
        let mut done = self.done.lock().unwrap_or_else(|e| e.into_inner());
        while !*done {
            let now = std::time::Instant::now();
            if now >= deadline {
                return;
            }
            done = self.cv.wait_timeout(done, deadline - now).unwrap_or_else(|e| e.into_inner()).0;
        }
    }
}

static INFLIGHT: std::sync::Mutex<Vec<std::sync::Arc<InFlight>>> = std::sync::Mutex::new(Vec::new());

thread_local! {
    static SWEEPING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// This thread's registration of a sweep (released on drop).
struct Claim {
    entry: std::sync::Arc<InFlight>,
    was_sweeping: bool,
}

impl Drop for Claim {
    fn drop(&mut self) {
        SWEEPING.with(|s| s.set(self.was_sweeping));
        INFLIGHT.lock().unwrap_or_else(|e| e.into_inner()).retain(|e| !std::sync::Arc::ptr_eq(e, &self.entry));
        *self.entry.done.lock().unwrap_or_else(|e| e.into_inner()) = true;
        self.entry.cv.notify_all();
    }
}

enum Turn {
    Wait(std::sync::Arc<InFlight>),
    Sweep(Claim),
}

/// Wait for a running sweep that records `q` (unless `may_wait` is false or this thread is
/// sweeping), else register this thread's sweep of `lits` / `opaque`.
fn take_turn(session: &Session, q: &CacheQuery, lits: &[Vec<u8>], opaque: Option<&[u8]>, may_wait: bool) -> Turn {
    let mut reg = INFLIGHT.lock().unwrap_or_else(|e| e.into_inner());
    let sweeping = SWEEPING.with(|s| s.get());
    if may_wait
        && !sweeping
        && let Some(e) = reg.iter().find(|e| e.covers(&session.key, q))
    {
        return Turn::Wait(e.clone());
    }
    let entry = std::sync::Arc::new(InFlight {
        key: session.key.clone(),
        lits: lits.to_vec(),
        opaque: opaque.map(|o| o.to_vec()),
        done: std::sync::Mutex::new(false),
        cv: std::sync::Condvar::new(),
    });
    reg.push(entry.clone());
    SWEEPING.with(|s| s.set(true));
    Turn::Sweep(Claim { entry, was_sweeping: sweeping })
}

/// The recording adapter of an opaque query: the scanner's own prescan, recorded per chunk.
struct OpaqueSweep<'a, S> {
    inner: &'a S,
}

impl<S: Scanner> Scanner for OpaqueSweep<'_, S> {
    type Hit = Rec<S::Hit>;
    fn chunk_size(&self) -> u64 {
        self.inner.chunk_size()
    }
    fn overlap(&self) -> u64 {
        self.inner.overlap()
    }
    fn scan(&self, data: &[u8], data_offset: u64, hits: &mut Vec<Self::Hit>) {
        let mut m = Vec::new();
        self.prescan(data, &mut m);
        if !m.is_empty() {
            self.finish(&m, data_offset, hits);
        }
    }
    fn prescan(&self, data: &[u8], out: &mut Vec<(u64, u32)>) -> bool {
        self.inner.prescan(data, out)
    }
    fn finish(&self, matches: &[(u64, u32)], data_offset: u64, hits: &mut Vec<Self::Hit>) {
        hits.push(Rec::Raw(data_offset, matches.into()));
        let mut h = Vec::new();
        self.inner.finish(matches, data_offset, &mut h);
        hits.extend(h.into_iter().map(Rec::Hit));
    }
    fn stream_window(&self) -> Option<usize> {
        self.inner.stream_window()
    }
    fn prescan_piece(&self, data: &[u8], base: u64, from: usize, limit: usize, out: &mut Vec<(u64, u32)>) -> usize {
        self.inner.prescan_piece(data, base, from, limit, out)
    }
}

fn sweep_opaque<S, F>(session: &Session, layer: &dyn Layer, scanner: &S, key: &[u8], secs: &[(u64, u64)], mut f: F)
where
    S: Scanner,
    F: FnMut(S::Hit) -> bool,
{
    if !scanner.prescan(&[], &mut Vec::new()) {
        // not two-phase: nothing to record
        return scan::execute(layer, scanner, secs, f);
    }
    let mut g = Groups::default();
    let mut ok = true;
    let mut stopped = false;
    scan::execute(layer, &OpaqueSweep { inner: scanner }, secs, |h| match h {
        Rec::Raw(cs, m) => {
            if ok {
                for &(rel, tag) in m.iter() {
                    ok &= g.push(cs, rel, Some(tag));
                }
                if g.rels.len() > MAX_RECORDS {
                    ok = false;
                    g = Groups::default();
                }
            }
            true
        }
        Rec::Hit(h) => {
            if f(h) {
                true
            } else {
                stopped = true;
                false
            }
        }
    });
    if !stopped && ok {
        session.store_all(&[(Atom::Opaque(key), &g)]);
    }
}

/// vmscan (python `PageStartScanner(signatures)` over the physical layer with default chunking):
/// the `(chunk start, offset in chunk, signature index)` hits of the 4-byte `sigs`, from the
/// cache or from `compute` (which must return exactly python's hits in chunk order; they are
/// then stored). Signatures are u32 little-endian values.
pub fn page_start_hits(layer: &dyn Layer, sigs: &[u32], compute: impl FnOnce() -> Vec<(u64, u64, u32)>) -> Vec<(u64, u64, u32)> {
    let full = [(layer.min_address(), layer.max_address() - layer.min_address())];
    let secs = scan::coalesce_sections(layer, &full);
    match Session::new(layer, &secs, true, DEFAULT_CHUNK_SIZE, DEFAULT_OVERLAP) {
        Some(s) => page_start_hits_in(&s, sigs, compute),
        None => compute(),
    }
}

fn page_start_hits_in(session: &Session, sigs: &[u32], compute: impl FnOnce() -> Vec<(u64, u64, u32)>) -> Vec<(u64, u64, u32)> {
    let loaded: Option<Vec<Groups>> = sigs.iter().map(|&v| session.load(&Atom::Page(v))).collect();
    if let Some(atoms) = loaded {
        let mut out: Vec<(u64, u64, u32)> = Vec::new();
        for (si, g) in atoms.iter().enumerate() {
            for i in 0..g.starts.len() {
                out.extend(g.range(i).map(|j| (g.starts[i], g.rels[j], si as u32)));
            }
        }
        // chunk order, then offset (one value per page start: no ties)
        out.sort_unstable();
        return out;
    }
    let hits = compute();
    let mut per: Vec<Groups> = sigs.iter().map(|_| Groups::default()).collect();
    let mut ok = true;
    for &(cs, rel, si) in &hits {
        match per.get_mut(si as usize) {
            Some(g) => ok &= g.push(cs, rel, None),
            None => ok = false,
        }
    }
    if ok {
        let atoms: Vec<(Atom, &Groups)> = sigs.iter().zip(&per).map(|(&v, g)| (Atom::Page(v), g)).collect();
        session.store_all(&atoms);
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layers::FileLayer;
    use crate::layers::scan::{BytesScanner, scan};
    use std::sync::Arc;

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    fn scratch(tag: &str) -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!("rsvol-scancache-{}-{}-{tag}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)))
    }

    fn file_with(data: &[u8]) -> (PathBuf, Arc<FileLayer>) {
        let p = scratch("img");
        std::fs::write(&p, data).unwrap();
        let f = Arc::new(FileLayer::open(&p).unwrap());
        (p, f)
    }

    /// A MultiStringScanner with custom chunking (to exercise overlaps and tail chunks).
    struct Chunked<S>(S, u64, u64);
    impl<S: Scanner> Scanner for Chunked<S> {
        type Hit = S::Hit;
        fn chunk_size(&self) -> u64 {
            self.1
        }
        fn overlap(&self) -> u64 {
            self.2
        }
        fn scan(&self, d: &[u8], o: u64, h: &mut Vec<S::Hit>) {
            let mut m = Vec::new();
            self.prescan(d, &mut m);
            self.finish(&m, o, h)
        }
        fn prescan(&self, d: &[u8], out: &mut Vec<(u64, u32)>) -> bool {
            // the inner scanner's prescan with this chunk size
            match self.0.cache_query() {
                Some(CacheQuery::Greedy { patterns, .. }) => {
                    let ms = MultiStringScanner::new(patterns);
                    let lim = self.1 as usize;
                    let mut v = Vec::new();
                    ms.search(d, |p, i| {
                        if p < lim {
                            v.push((p as u64, i));
                            true
                        } else {
                            false
                        }
                    });
                    out.extend(v);
                }
                Some(CacheQuery::Every { needle, .. }) => {
                    let mut p = 0;
                    while let Some(i) = scan::find(&d[p..], needle) {
                        if (p + i) as u64 >= self.1 {
                            break;
                        }
                        out.push(((p + i) as u64, 0));
                        p += i + 1;
                    }
                }
                _ => unreachable!(),
            }
            true
        }
        fn finish(&self, m: &[(u64, u32)], o: u64, h: &mut Vec<S::Hit>) {
            self.0.finish(m, o, h)
        }
        fn cache_query(&self) -> Option<CacheQuery<'_>> {
            match self.0.cache_query()? {
                CacheQuery::Greedy { patterns, cap, .. } => Some(CacheQuery::Greedy { patterns, limit: self.1, cap }),
                CacheQuery::Every { needle, .. } => Some(CacheQuery::Every { needle, limit: self.1 }),
                q => Some(q),
            }
        }
    }

    fn cached<S: Scanner>(root: &Path, layer: &dyn Layer, s: &S, secs: Option<&[(u64, u64)]>) -> (Vec<S::Hit>, bool) {
        let full = [(layer.min_address(), layer.max_address() - layer.min_address())];
        let secs = scan::coalesce_sections(layer, secs.unwrap_or(&full));
        let session = Session::with_root(root, layer, &secs, secs.len() == 1 && secs[0] == full[0], s.chunk_size(), s.overlap()).unwrap();
        let q = s.cache_query().unwrap();
        let hit = load_query(&session, &q).is_some();
        let mut v = Vec::new();
        scan_each(&session, layer, s, q, &secs, |h| {
            v.push(h);
            true
        });
        (v, hit)
    }

    fn reference<S: Scanner>(layer: &dyn Layer, s: &S, secs: Option<&[(u64, u64)]>) -> Vec<S::Hit> {
        let full = [(layer.min_address(), layer.max_address() - layer.min_address())];
        let secs = scan::coalesce_sections(layer, secs.unwrap_or(&full));
        let mut v = Vec::new();
        scan::execute(layer, s, &secs, |h| {
            v.push(h);
            true
        });
        v
    }

    /// Keys that differ only in a pattern straddling a word boundary (kernel-address needles:
    /// FxHash collided on real ones) all get distinct names.
    #[test]
    fn key_hash_no_structured_collisions() {
        let mut key = vec![0u8; 431];
        for (i, b) in key.iter_mut().enumerate() {
            *b = (i * 37 % 251) as u8;
        }
        let mut seen = std::collections::HashSet::new();
        for p0 in 0..=255u8 {
            for p1 in 0..=255u8 {
                key[423] = p0;
                key[424] = p1;
                assert!(seen.insert(key_hash(&key)), "collision at {p0} {p1}");
            }
        }
        // the real pair
        let mut a = key.clone();
        let mut b = key.clone();
        a[423..431].copy_from_slice(&[40, 135, 79, 184, 255, 255, 255, 255]);
        b[423..431].copy_from_slice(&[120, 133, 79, 184, 255, 255, 255, 255]);
        assert_ne!(key_hash(&a), key_hash(&b));
        // length matters, zero padding does not alias
        assert_ne!(key_hash(b"abc"), key_hash(b"abc\0"));
    }

    #[test]
    fn varint_roundtrip() {
        for v in [0u64, 1, 127, 128, 300, 1 << 35, u64::MAX - 1, u64::MAX] {
            let mut b = Vec::new();
            put_varint(&mut b, v);
            let mut p = 0;
            assert_eq!(get_varint(&b, &mut p), Some(v));
            assert_eq!(p, b.len());
        }
        for d in [0i64, -1, 1, i64::MIN, i64::MAX, -12345] {
            assert_eq!(unzigzag(zigzag(d)), d);
        }
        // overlong / truncated
        assert_eq!(get_varint(&[0x80], &mut 0), None);
        assert_eq!(get_varint(&[0xff; 11], &mut 0), None);
    }

    #[test]
    fn file_format_roundtrip_and_corruption() {
        let mut g = Groups::default();
        let mut rng = Rng(7);
        let mut cs = 0u64;
        for _ in 0..50 {
            cs += 1 + rng.below(1 << 30);
            let mut rel = 0;
            for _ in 0..1 + rng.below(20) {
                rel += rng.below(5000);
                assert!(g.push(cs, rel, None));
            }
        }
        let key = b"some key material".to_vec();
        let buf = encode(0, false, &key, &g).unwrap();
        assert_eq!(decode(&buf, 0, false, &key), Some(g.clone()));
        // wrong key / kind / version
        assert_eq!(decode(&buf, 0, false, b"some key materiaL"), None);
        assert_eq!(decode(&buf, 1, false, &key), None);
        let mut v = buf.clone();
        v[8] ^= 1;
        assert_eq!(decode(&v, 0, false, &key), None);
        // every truncation and every single-byte corruption is detected
        for n in 0..buf.len() {
            assert_eq!(decode(&buf[..n], 0, false, &key), None, "truncated to {n}");
        }
        for i in 0..buf.len() {
            let mut v = buf.clone();
            v[i] ^= 0x5a;
            assert_eq!(decode(&v, 0, false, &key), None, "byte {i} flipped");
        }
        // tagged (opaque) groups with unordered offsets
        let mut t = Groups::default();
        for (cs, rel, tag) in [(5u64, 9u64, 3u32), (5, 2, 0), (5, u64::MAX, 7), (900, 0, u32::MAX)] {
            assert!(t.push(cs, rel, Some(tag)));
        }
        let buf = encode(2, true, &key, &t).unwrap();
        assert_eq!(decode(&buf, 2, true, &key), Some(t));
        // out-of-order chunks are refused
        let mut bad = Groups::default();
        assert!(bad.push(10, 1, None));
        assert!(!bad.push(9, 1, None));
        // empty atom
        let e = Groups::default();
        assert_eq!(decode(&encode(0, false, &key, &e).unwrap(), 0, false, &key), Some(e));
    }

    #[test]
    fn greedy_selection() {
        // "ab"(0) "abcd"(1) "bc"(2): at 1 both ab and abcd match -> longest; overlapping bc skipped
        let mut c = vec![(1u64, 2u32, 0u32), (1, 4, 1), (2, 2, 2), (6, 2, 2), (9, 2, 0)];
        let mut out = Vec::new();
        greedy(&mut c, u64::MAX, usize::MAX, &mut out);
        assert_eq!(out, vec![(1, 1), (6, 2), (9, 0)]);
        out.clear();
        greedy(&mut c, 9, usize::MAX, &mut out);
        assert_eq!(out, vec![(1, 1), (6, 2)]);
        out.clear();
        greedy(&mut c, u64::MAX, 1, &mut out);
        assert_eq!(out, vec![(1, 1)]);
    }

    /// Cached scans (cold = recording sweep, warm = replay) return exactly the executor's hits,
    /// for random pattern sets (prefixes, overlaps, duplicates, empties), odd chunkings with
    /// duplicate reports in tail chunks, and explicit sections; atoms recorded for one query
    /// answer other queries over the same literals.
    #[test]
    fn cached_scans_match_executor() {
        let mut rng = Rng(0x1234_5678_9abc);
        let alpha = [b'a', b'b', b'c', 0u8];
        let n = 50_000usize;
        let data: Vec<u8> = (0..n).map(|_| alpha[rng.below(4) as usize]).collect();
        let (p, file) = file_with(&data);
        let root = scratch("root");
        for trial in 0..40 {
            let np = 1 + rng.below(5) as usize;
            let pats: Vec<Vec<u8>> = (0..np).map(|_| (0..rng.below(5)).map(|_| alpha[rng.below(4) as usize]).collect()).collect();
            let (cs, ov) = match trial % 4 {
                0 => (DEFAULT_CHUNK_SIZE, DEFAULT_OVERLAP),
                1 => (1000, 64),
                2 => (4096, 4096),
                _ => (7777, 3),
            };
            let secs_v = [(100u64, 20_000u64), (30_000, 7_000), (29_000, 1_500)];
            let secs: Option<&[(u64, u64)]> = if trial % 3 == 2 { Some(&secs_v) } else { None };
            let ms = Chunked(MultiStringScanner::new(&pats), cs, ov);
            let want = reference(file.as_ref(), &ms, secs);
            let (cold, hit0) = cached(&root, file.as_ref(), &ms, secs);
            let (warm, hit1) = cached(&root, file.as_ref(), &ms, secs);
            assert_eq!(cold, want, "trial {trial} cold {pats:?}");
            assert_eq!(warm, want, "trial {trial} warm {pats:?}");
            assert!(hit1 || pats.iter().all(|p| p.is_empty()) || hit0, "trial {trial}: not cached");
            if let Some(needle) = pats.iter().find(|p| !p.is_empty()) {
                let bs = Chunked(BytesScanner::new(needle), cs, ov);
                let want = reference(file.as_ref(), &bs, secs);
                let (got, hit) = cached(&root, file.as_ref(), &bs, secs);
                assert!(hit, "trial {trial}: bytes scan not answered by the recorded atoms");
                assert_eq!(got, want, "trial {trial} bytes {needle:?}");
            }
        }
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_file(&p);
    }

    /// A full default-chunked sweep records the batched families (here: physical literals and
    /// vmscan page starts), and damaged cache files are rebuilt, never trusted.
    #[test]
    fn batching_and_rebuild() {
        let mut data = vec![0u8; 3 << 20];
        let mut rng = Rng(99);
        for b in data.iter_mut() {
            *b = rng.below(256) as u8;
        }
        for (i, at) in [0x1000usize, 0x5000, 0x20_0000].into_iter().enumerate() {
            data[at..at + 4].copy_from_slice(&VMCS_REVISION_IDS[i].to_le_bytes());
        }
        for at in [77usize, 0x10_0000, 0x10_0400] {
            data[at..at + 5].copy_from_slice(b"FILE0");
        }
        data[0x3000..0x3004].copy_from_slice(b"Proc");
        data[0x3001 + 0x200..0x3005 + 0x200].copy_from_slice(b"\x55\xaa\x55\xaa");
        let (p, file) = file_with(&data);
        let root = scratch("root");
        let l: &dyn Layer = file.as_ref();
        // a pool-tag scan sweeps and batches
        let ps = MultiStringScanner::new(&[b"Pro\xe3".as_ref(), b"Proc"]);
        let (got, hit) = cached(&root, l, &ps, None);
        assert!(!hit);
        assert_eq!(got, vec![(0x3000, 1)]);
        // ... so mftscan's / mbrscan's / other pool scans' literals are cached now
        for pats in [vec![b"FILE0".to_vec(), b"FILE*".to_vec(), b"BAAD".to_vec()], vec![b"\x55\xaa".to_vec()], vec![b"Thre".to_vec(), b"Proc".to_vec()]] {
            let ms = MultiStringScanner::new(&pats);
            let want = reference(l, &ms, None);
            let (got, hit) = cached(&root, l, &ms, None);
            assert!(hit, "{pats:?} not batched");
            assert_eq!(got, want);
        }
        // vmscan page starts were recorded too
        let full = scan::coalesce_sections(l, &[(0, l.max_address())]);
        let session = Session::with_root(&root, l, &full, true, DEFAULT_CHUNK_SIZE, DEFAULT_OVERLAP).unwrap();
        let hits = page_start_hits_in(&session, &VMCS_REVISION_IDS, || panic!("page starts not batched"));
        assert_eq!(hits, vec![(0, 0x1000, 0), (0, 0x5000, 1), (0, 0x20_0000, 2)]);
        // damage every cache file in turn: the scan result never changes, the file is rebuilt
        let files: Vec<PathBuf> = std::fs::read_dir(&session.dir).unwrap().map(|e| e.unwrap().path()).collect();
        assert!(files.len() >= 8, "{files:?}");
        let ms = MultiStringScanner::new(&[b"FILE0".as_ref(), b"FILE*", b"BAAD", b"Proc", b"\x55\xaa"]);
        let want = reference(l, &ms, None);
        for (i, f) in files.iter().enumerate() {
            let orig = std::fs::read(f).unwrap();
            let bad = match i % 3 {
                0 => orig[..orig.len() / 2].to_vec(),
                1 => {
                    let mut v = orig.clone();
                    let k = v.len() - 1;
                    v[k] ^= 0xff;
                    v
                }
                _ => b"garbage".to_vec(),
            };
            std::fs::write(f, &bad).unwrap();
            let (got, _) = cached(&root, l, &ms, None);
            assert_eq!(got, want);
            let (got, hit) = cached(&root, l, &ms, None);
            assert_eq!(got, want);
            assert!(hit);
        }
        // a touched (newer mtime) image is a different image
        let t = std::time::SystemTime::now() + std::time::Duration::from_secs(5);
        std::fs::File::options().write(true).open(&p).unwrap().set_modified(t).unwrap();
        let file2 = Arc::new(FileLayer::open(&p).unwrap());
        let (_, hit) = cached(&root, file2.as_ref(), &ms, None);
        assert!(!hit, "modified image must miss");
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_file(&p);
    }

    /// Container (translation) layers: chunks per mapping run; cached == executor.
    #[test]
    fn container_layer() {
        let mut img = Vec::new();
        let pages = |n: usize, seed: u64| {
            let mut r = Rng(seed);
            let mut v: Vec<u8> = (0..n * 4096).map(|_| b"abP\0"[r.below(4) as usize]).collect();
            v[100..104].copy_from_slice(b"Proc");
            v
        };
        // two segments: [0x1000, +3 pages) and [0x10000, +5 pages)
        for (start, np, seed) in [(0x1000u64, 3usize, 1u64), (0x10000, 5, 2)] {
            img.extend_from_slice(&crate::layers::containers::lime::MAGIC.to_le_bytes());
            img.extend_from_slice(&1u32.to_le_bytes());
            img.extend_from_slice(&start.to_le_bytes());
            img.extend_from_slice(&(start + np as u64 * 4096 - 1).to_le_bytes());
            img.extend_from_slice(&0u64.to_le_bytes());
            img.extend(pages(np, seed));
        }
        let (p, file) = file_with(&img);
        let l = crate::layers::containers::stack(file).unwrap();
        assert_eq!(l.name(), "LimeLayer");
        let root = scratch("root");
        for pats in [vec![b"Proc".to_vec()], vec![b"ab".to_vec(), b"abP".to_vec(), b"P".to_vec()]] {
            let ms = Chunked(MultiStringScanner::new(&pats), 4096, 1000);
            let want = reference(l.as_ref(), &ms, None);
            assert!(!want.is_empty());
            let (cold, _) = cached(&root, l.as_ref(), &ms, None);
            let (warm, hit) = cached(&root, l.as_ref(), &ms, None);
            assert!(hit);
            assert_eq!(cold, want);
            assert_eq!(warm, want);
        }
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_file(&p);
    }

    /// Random bytes with `pats` planted around 64 KiB piece boundaries and at random places.
    fn planted(n: usize, pats: &[&[u8]], seed: u64) -> Vec<u8> {
        let mut rng = Rng(seed);
        let mut data: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
        let mut at = 0usize;
        while at + 64 < n {
            let p = pats[rng.below(pats.len() as u64) as usize];
            let pos = if rng.below(2) == 0 { (at | 0xffff) + 1 - rng.below(8) as usize } else { at + rng.below(4000) as usize };
            if pos + p.len() < n {
                data[pos..pos + p.len()].copy_from_slice(p);
            }
            at += 1 + rng.below(20_000) as usize;
        }
        data
    }

    /// Big chunks (streamed in pieces by the executor) and translation layers with many small
    /// chunks (grouped by file range): cached == executor, cold and warm.
    #[test]
    fn executor_paths_match() {
        let pats: [&[u8]; 8] = [b"ABC", b"ABCD", b"BCDE", b"FILE0", b"FILE*", b"Proc", b"\x55\xaa", b"CDEAB"];
        let data = planted(12 << 20, &pats, 5);
        let (p, file) = file_with(&data);
        let root = scratch("root");
        let queries: Vec<Vec<Vec<u8>>> = vec![
            pats.iter().map(|p| p.to_vec()).collect(),
            vec![b"ABC".to_vec(), b"BCDE".to_vec()],
            vec![b"\x55\xaa".to_vec(), b"ABCD".to_vec()],
            vec![b"CDEAB".to_vec(), b"ABCD".to_vec(), b"ABC".to_vec(), b"ABC".to_vec()],
        ];
        for (cs, ov) in [(1u64 << 20, 0x1000u64), (3 << 20, 10), (DEFAULT_CHUNK_SIZE, DEFAULT_OVERLAP)] {
            for q in &queries {
                let ms = Chunked(MultiStringScanner::new(q), cs, ov);
                let want = reference(file.as_ref(), &ms, None);
                assert!(!want.is_empty());
                let (cold, _) = cached(&root, file.as_ref(), &ms, None);
                let (warm, hit) = cached(&root, file.as_ref(), &ms, None);
                assert!(hit);
                assert_eq!(cold, want, "cs {cs} {q:?}");
                assert_eq!(warm, want, "cs {cs} {q:?}");
                let bs = Chunked(BytesScanner::new(&q[0]), cs, ov);
                let (got, hit) = cached(&root, file.as_ref(), &bs, None);
                assert!(hit);
                assert_eq!(got, reference(file.as_ref(), &bs, None));
            }
        }
        // the real scanners (their own prescan_piece streaming vs the sweep)
        for q in &queries {
            let ms = MultiStringScanner::new(q);
            let want = reference(file.as_ref(), &ms, None);
            assert_eq!(cached(&root, file.as_ref(), &ms, None).0, want);
        }
        // a LiME layer of 3000 small segments, some pages mapped twice in the file order
        let mut img = Vec::new();
        let mut rng = Rng(11);
        let mut start = 0x10000u64;
        for i in 0..3000u64 {
            let np = 1 + rng.below(3);
            img.extend_from_slice(&crate::layers::containers::lime::MAGIC.to_le_bytes());
            img.extend_from_slice(&1u32.to_le_bytes());
            img.extend_from_slice(&start.to_le_bytes());
            img.extend_from_slice(&(start + np * 4096 - 1).to_le_bytes());
            img.extend_from_slice(&0u64.to_le_bytes());
            let off = (i as usize * 4096 * 3) % (data.len() - 3 * 4096);
            img.extend_from_slice(&data[off..off + np as usize * 4096]);
            start += np * 4096 + 4096 * rng.below(2);
        }
        let (p2, lf) = file_with(&img);
        let l = crate::layers::containers::stack(lf).unwrap();
        for q in &queries {
            for (cs, ov) in [(4096u64, 0x1000u64), (DEFAULT_CHUNK_SIZE, DEFAULT_OVERLAP)] {
                let ms = Chunked(MultiStringScanner::new(q), cs, ov);
                let want = reference(l.as_ref(), &ms, None);
                let (cold, _) = cached(&root, l.as_ref(), &ms, None);
                let (warm, hit) = cached(&root, l.as_ref(), &ms, None);
                assert!(hit);
                assert_eq!(cold, want, "lime cs {cs} {q:?}");
                assert_eq!(warm, want, "lime cs {cs} {q:?}");
            }
        }
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(&p2);
    }

    /// Concurrent cold scans of one configuration (timeliner's parallel plugins) and a scan
    /// started from inside a sweeping consumer: identical results, no deadlock.
    #[test]
    fn concurrent_and_nested() {
        let pats: [&[u8]; 4] = [b"ABC", b"ABCD", b"Proc", b"Thre"];
        let data = planted(9 << 20, &pats, 21);
        let (p, file) = file_with(&data);
        let l: &dyn Layer = file.as_ref();
        let root = scratch("root");
        let queries: Vec<Vec<Vec<u8>>> = vec![vec![b"Proc".to_vec()], vec![b"Thre".to_vec(), b"Proc".to_vec()], vec![b"ABC".to_vec(), b"ABCD".to_vec()], vec![b"ABCD".to_vec()]];
        let want: Vec<Vec<(u64, u32)>> = queries.iter().map(|q| reference(l, &MultiStringScanner::new(q), None)).collect();
        for round in 0..3 {
            let _ = std::fs::remove_dir_all(&root);
            std::thread::scope(|s| {
                let hs: Vec<_> = (0..8).map(|t| {
                    let (root, q) = (&root, &queries[t % queries.len()]);
                    s.spawn(move || cached(root, l, &MultiStringScanner::new(q), None).0)
                }).collect();
                for (t, h) in hs.into_iter().enumerate() {
                    assert_eq!(h.join().unwrap(), want[t % queries.len()], "round {round} thread {t}");
                }
            });
        }
        // nested: a cold scan whose consumer runs another cached scan of the same configuration
        let _ = std::fs::remove_dir_all(&root);
        let outer = MultiStringScanner::new(&queries[0]);
        let full = scan::coalesce_sections(l, &[(0, l.max_address())]);
        let session = Session::with_root(&root, l, &full, true, DEFAULT_CHUNK_SIZE, DEFAULT_OVERLAP).unwrap();
        let mut got = Vec::new();
        let mut inner = Vec::new();
        scan_each(&session, l, &outer, outer.cache_query().unwrap(), &full, |h| {
            if got.is_empty() {
                inner = cached(&root, l, &MultiStringScanner::new(&queries[1]), None).0;
            }
            got.push(h);
            true
        });
        assert_eq!(got, want[0]);
        assert_eq!(inner, want[1]);
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_file(&p);
    }

    /// A greedy query over many literals is cached whole (one file) and replays exactly.
    #[test]
    fn many_literals_one_atom() {
        let data = planted(6 << 20, &[b"ABCD", b"ABCE", b"XYZW"], 17);
        let (p, file) = file_with(&data);
        let l: &dyn Layer = file.as_ref();
        let root = scratch("root");
        let mut pats: Vec<Vec<u8>> = (0..200u32).map(|i| format!("N{i:03}").into_bytes()).collect();
        pats.push(b"ABCD".to_vec());
        pats.push(b"ABC".to_vec());
        pats.push(b"ABCD".to_vec());
        let ms = MultiStringScanner::new(&pats);
        let want = reference(l, &ms, None);
        assert!(!want.is_empty());
        let (cold, h0) = cached(&root, l, &ms, None);
        let (warm, _) = cached(&root, l, &ms, None);
        assert!(!h0);
        assert_eq!(cold, want);
        assert_eq!(warm, want);
        let dir = std::fs::read_dir(&root).unwrap().next().unwrap().unwrap().path();
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1, "one atom for the whole query");
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_file(&p);
    }

    /// An opaque two-phase scanner (tagged matches in any order) is cached as is.
    struct Odd;
    impl Scanner for Odd {
        type Hit = (u64, u32);
        fn scan(&self, d: &[u8], o: u64, h: &mut Vec<(u64, u32)>) {
            let mut m = Vec::new();
            self.prescan(d, &mut m);
            self.finish(&m, o, h)
        }
        fn prescan(&self, d: &[u8], out: &mut Vec<(u64, u32)>) -> bool {
            // every 'Z' followed by a digit; reported in descending order, tag = the digit
            let mut v: Vec<(u64, u32)> = d.windows(2).enumerate().filter(|(_, w)| w[0] == b'Z' && w[1].is_ascii_digit()).map(|(i, w)| (i as u64, (w[1] - b'0') as u32)).collect();
            v.reverse();
            out.extend(v);
            true
        }
        fn finish(&self, m: &[(u64, u32)], o: u64, h: &mut Vec<(u64, u32)>) {
            h.extend(m.iter().map(|&(r, t)| (o + r, t * 10)));
        }
        fn cache_query(&self) -> Option<CacheQuery<'_>> {
            Some(CacheQuery::Opaque { key: b"test.Odd/1".to_vec() })
        }
    }

    #[test]
    fn opaque_scanner() {
        let data = planted(6 << 20, &[b"Z1", b"Z9", b"ZZ7"], 3);
        let (p, file) = file_with(&data);
        let root = scratch("root");
        let want = reference(file.as_ref(), &Odd, None);
        assert!(!want.is_empty());
        let (cold, h0) = cached(&root, file.as_ref(), &Odd, None);
        let (warm, h1) = cached(&root, file.as_ref(), &Odd, None);
        assert!(!h0 && h1);
        assert_eq!(cold, want);
        assert_eq!(warm, want);
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn identity_distinguishes_layers() {
        let (p, file) = file_with(&[1u8; 8192]);
        let a = layer_identity(file.as_ref()).unwrap();
        assert_eq!(a, layer_identity(file.as_ref()).unwrap());
        // same file under another name: same bytes, same identity
        assert_eq!(layer_identity(&file.with_name("memory_layer")).unwrap(), a);
        let (p2, file2) = file_with(&[1u8; 8192]);
        assert_ne!(layer_identity(file2.as_ref()).unwrap(), a);
        let phys: Arc<dyn Layer> = file.clone();
        let i1 = crate::layers::IntelLayer::new("layer_name", phys.clone(), 0x1000, crate::layers::PagingMode::Intel32e, crate::layers::PteFlavor::Windows);
        let i2 = crate::layers::IntelLayer::new("layer_name", phys.clone(), 0x2000, crate::layers::PagingMode::Intel32e, crate::layers::PteFlavor::Windows);
        let i3 = crate::layers::IntelLayer::new("other", phys, 0x1000, crate::layers::PagingMode::Intel32e, crate::layers::PteFlavor::Linux);
        let (k1, k2, k3) = (layer_identity(&i1).unwrap(), layer_identity(&i2).unwrap(), layer_identity(&i3).unwrap());
        assert!(k1 != k2 && k1 != k3 && k2 != k3);
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(&p2);
    }

    #[test]
    fn prune_keeps_cap() {
        let root = scratch("prune");
        for (i, n) in [(0, 3000usize), (1, 3000), (2, 3000)] {
            let d = root.join(format!("{i:016x}"));
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("a.hits"), vec![0u8; n]).unwrap();
            let t = std::time::SystemTime::now() - std::time::Duration::from_secs(100 - i as u64 * 10);
            std::fs::File::open(&d).unwrap().set_modified(t).unwrap();
        }
        let keep = root.join(format!("{:016x}", 0));
        prune(&root, &keep, 6500);
        // the oldest other directory (1) went, 0 is kept even though it is older
        assert!(keep.is_dir());
        assert!(!root.join(format!("{:016x}", 1)).exists());
        assert!(root.join(format!("{:016x}", 2)).exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Sweep cost vs a plain scan on a real image (no files written):
    /// `RSVOL_BENCH_IMG=img cargo test --release sweep_bench -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn sweep_bench() {
        let Ok(path) = std::env::var("RSVOL_BENCH_IMG") else { return };
        let reps: usize = std::env::var("RSVOL_BENCH_REPS").ok().and_then(|v| v.parse().ok()).unwrap_or(5);
        let ctx = crate::context::Context::new(crate::context::GlobalOptions { file: Some(path), ..Default::default() }).unwrap();
        let k = ctx.windows_kernel().unwrap();
        let best = |f: &dyn Fn() -> usize| {
            let mut b = f64::MAX;
            let mut n = 0;
            for _ in 0..reps {
                let t = std::time::Instant::now();
                n = f();
                b = b.min(t.elapsed().as_secs_f64() * 1e3);
            }
            (b, n)
        };
        let run_plain = |l: &dyn Layer, pats: &[&[u8]]| {
            let ms = MultiStringScanner::new(pats);
            best(&|| {
                let secs = scan::coalesce_sections(l, &[(l.min_address(), l.max_address() - l.min_address())]);
                let mut n = 0;
                scan::execute(l, &ms, &secs, |_| {
                    n += 1;
                    true
                });
                n
            })
        };
        let run_sweep = |l: &dyn Layer, pats: &[&[u8]], batch: &[&[u8]], pages: bool| {
            let ms = MultiStringScanner::new(pats);
            best(&|| {
                let secs = scan::coalesce_sections(l, &[(l.min_address(), l.max_address() - l.min_address())]);
                let mut lits: Vec<Vec<u8>> = pats.iter().map(|p| p.to_vec()).collect();
                let mut map = Vec::new();
                for (i, p) in pats.iter().enumerate() {
                    map.push(Some((i as u32, p.len() as u32)));
                }
                for b in batch {
                    if !lits.iter().any(|l| l == b) {
                        lits.push(b.to_vec());
                    }
                }
                let sw = Sweep {
                    inner: &ms,
                    lits: Literals::new(&lits),
                    pages: if pages { VMCS_REVISION_IDS.to_vec() } else { Vec::new() },
                    derive: Derive::Greedy { map, limit: DEFAULT_CHUNK_SIZE, cap: usize::MAX },
                };
                let mut n = 0;
                scan::execute(l, &sw, &secs, |h| {
                    match h {
                        Rec::Raw(_, m) => n += m.len(),
                        Rec::Hit(_) => {}
                    }
                    true
                });
                n
            })
        };
        let ps: [&[u8]; 2] = [b"Pro\xe3", b"Proc"];
        eprintln!("kernel plain psscan      {:?}", run_plain(k.vlayer, &ps));
        eprintln!("kernel sweep psscan+pool {:?}", run_sweep(k.vlayer, &ps, &POOL_TAGS, false));
        let mbr: [&[u8]; 1] = [b"\x55\xaa"];
        let mft: [&[u8]; 3] = [b"FILE0", b"FILE*", b"BAAD"];
        eprintln!("phys plain mbr           {:?}", run_plain(k.phys, &mbr));
        eprintln!("phys plain mft           {:?}", run_plain(k.phys, &mft));
        eprintln!("phys sweep mbr+phys      {:?}", run_sweep(k.phys, &mbr, &PHYS_LITERALS, false));
        eprintln!("phys sweep mbr+phys+pg   {:?}", run_sweep(k.phys, &mbr, &PHYS_LITERALS, true));
        eprintln!("phys sweep mft+phys+pg   {:?}", run_sweep(k.phys, &mft, &PHYS_LITERALS, true));
        let mut all: Vec<&[u8]> = PHYS_LITERALS.to_vec();
        all.extend(POOL_TAGS);
        eprintln!("phys sweep mft+all+pg    {:?}", run_sweep(k.phys, &mft, &all, true));
    }

    /// Decode a cache file with the key stored in it: `RSVOL_HITS_FILE=f cargo test decode_file -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn decode_file() {
        let Ok(p) = std::env::var("RSVOL_HITS_FILE") else { return };
        let buf = std::fs::read(p).unwrap();
        let klen = u64::from_le_bytes(buf[16..24].try_into().unwrap()) as usize;
        let kind = u32::from_le_bytes(buf[12..16].try_into().unwrap());
        let key = buf[HEADER..HEADER + klen].to_vec();
        let g = decode(&buf, kind, kind == 2, &key);
        eprintln!("decode: {:?}", g.as_ref().map(|g| (g.starts.len(), g.rels.len())));
    }

    /// Occurrence counts of candidate batch patterns:
    /// `RSVOL_BENCH_IMG=img cargo test --profile fast scancache_counts -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn scancache_counts() {
        let Ok(path) = std::env::var("RSVOL_BENCH_IMG") else { return };
        let ctx = crate::context::Context::new(crate::context::GlobalOptions { file: Some(path), ..Default::default() }).unwrap();
        let k = ctx.windows_kernel().unwrap();
        let mut pats: Vec<&[u8]> = POOL_TAGS.to_vec();
        pats.extend(PHYS_LITERALS);
        for (name, l) in [("kernel", k.vlayer), ("physical", k.phys)] {
            let mut tot = 0;
            for &p in &pats {
                let n = scan(l, &BytesScanner::new(p), None).len();
                tot += n;
                eprintln!("{name} {:<24} {n:>9}", format!("{p:x?}"));
            }
            eprintln!("{name} total {tot}");
        }
    }
}
