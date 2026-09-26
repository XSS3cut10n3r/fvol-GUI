//! Bit-exact port of zlib 1.3.2's compressor (`deflate.c` + `trees.c`).
//!
//! [`Deflater`] reproduces `deflateInit2()` / `deflate()` byte for byte — same
//! `configuration_table`, hash chains, lazy matching, `TOO_FAR` / `Z_FILTERED` rules, block
//! splitting (symbol buffer of `1 << (memLevel + 6)` entries), stored/static/dynamic block
//! choice, Huffman tree construction (incl. the bit-length overflow fix-up), flush semantics
//! (`Z_NO_FLUSH` .. `Z_BLOCK`, `Z_FINISH`), zlib / gzip / raw wrappers and return codes — so
//! that files written by python code (`zlib.compress`, `zlib.compressobj`, Pillow's PNG
//! encoder, ...) can be regenerated exactly. The fast, non-exact encoder is
//! [`super::deflate_enc`].
//!
//! Exactness notes (all mirrored here):
//! * the window content beyond the current data is observable (longest_match compares up to
//!   258 bytes past `strstart` before clamping to the lookahead), so the window is slid,
//!   refilled and zero-padded (`high_water`) exactly like zlib does;
//! * the input chunking of the `deflate()` calls matters (it decides when `fill_window` runs
//!   and hence when the window slides), the output chunking does not except for level 0
//!   (`deflate_stored` sizes blocks by `avail_out`). [`Deflater::deflate`] takes a bounded
//!   output slice (`avail_out` semantics), [`Deflater::deflate_vec`] an unbounded one.
//!
//! Speed: same algorithm, but matches are compared 8 bytes at a time, bits are accumulated in
//! a 64-bit buffer, and the checksum is the vectorised Adler-32 of [`super::zlib`].
//! Verified against the system libz 1.3.2 by the ignored test `zlib_exact_oracle` (C side:
//! `bench/refbench/zlib_exact_ref.c`).
//!
//! zlib (C) 1995-2026 Jean-loup Gailly and Mark Adler, zlib license.

use super::crc::crc32_update;
use super::zlib::adler32_update;

// ---------------------------------------------------------------------------------------------
// Public constants (zlib.h values)

pub const Z_NO_FLUSH: i32 = 0;
pub const Z_PARTIAL_FLUSH: i32 = 1;
pub const Z_SYNC_FLUSH: i32 = 2;
pub const Z_FULL_FLUSH: i32 = 3;
pub const Z_FINISH: i32 = 4;
pub const Z_BLOCK: i32 = 5;

pub const Z_OK: i32 = 0;
pub const Z_STREAM_END: i32 = 1;
pub const Z_STREAM_ERROR: i32 = -2;
pub const Z_BUF_ERROR: i32 = -5;

pub const Z_DEFAULT_COMPRESSION: i32 = -1;
pub const Z_DEFAULT_STRATEGY: i32 = 0;
pub const Z_FILTERED: i32 = 1;
pub const Z_HUFFMAN_ONLY: i32 = 2;
pub const Z_RLE: i32 = 3;
pub const Z_FIXED: i32 = 4;

/// `DEF_MEM_LEVEL` (what `deflateInit` / python's `zlib.compress` use).
pub const DEF_MEM_LEVEL: i32 = 8;

// ---------------------------------------------------------------------------------------------
// Internal constants (deflate.h / trees.c)

const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 258;
const MIN_LOOKAHEAD: usize = MAX_MATCH + MIN_MATCH + 1;
const WIN_INIT: usize = MAX_MATCH;
const TOO_FAR: usize = 4096;
const MAX_STORED: usize = 65535;
const NIL: usize = 0;

const LENGTH_CODES: usize = 29;
const LITERALS: usize = 256;
const L_CODES: usize = LITERALS + 1 + LENGTH_CODES;
const D_CODES: usize = 30;
const BL_CODES: usize = 19;
const HEAP_SIZE: usize = 2 * L_CODES + 1;
const MAX_BITS: usize = 15;
const MAX_BL_BITS: usize = 7;
const END_BLOCK: usize = 256;
const REP_3_6: usize = 16;
const REPZ_3_10: usize = 17;
const REPZ_11_138: usize = 18;

const STORED_BLOCK: u32 = 0;
const STATIC_TREES: u32 = 1;
const DYN_TREES: u32 = 2;

const INIT_STATE: i32 = 42;
const GZIP_STATE: i32 = 57;
const BUSY_STATE: i32 = 113;
const FINISH_STATE: i32 = 666;

/// OS_CODE of the gzip header (zutil.h, Unix).
const OS_CODE: u8 = 3;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Func {
    Stored,
    Fast,
    Slow,
}

/// `configuration_table`: good, lazy, nice, chain, function.
const CONFIG: [(u16, u16, u16, u16, Func); 10] = [
    (0, 0, 0, 0, Func::Stored),
    (4, 4, 8, 4, Func::Fast),
    (4, 5, 16, 8, Func::Fast),
    (4, 6, 32, 32, Func::Fast),
    (4, 4, 16, 16, Func::Slow),
    (8, 16, 32, 32, Func::Slow),
    (8, 16, 128, 128, Func::Slow),
    (8, 32, 128, 256, Func::Slow),
    (32, 128, 258, 1024, Func::Slow),
    (32, 258, 258, 4096, Func::Slow),
];

#[inline]
fn rank(f: i32) -> i32 {
    f * 2 - if f > 4 { 9 } else { 0 }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BlockState {
    NeedMore,
    BlockDone,
    FinishStarted,
    FinishDone,
}

// ---------------------------------------------------------------------------------------------
// Static tables (trees.c tr_static_init / trees.h), built at compile time.

/// `ct_data`: `fc` is Freq/Code, `dl` is Dad/Len (C unions — the aliasing is relied upon).
#[derive(Clone, Copy, Default)]
struct Ct {
    fc: u16,
    dl: u16,
}

const EXTRA_LBITS: [u8; LENGTH_CODES] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const EXTRA_DBITS: [u8; D_CODES] =
    [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
const EXTRA_BLBITS: [u8; BL_CODES] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 7];
const BL_ORDER: [u8; BL_CODES] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

const fn bi_reverse(mut code: u32, mut len: u32) -> u32 {
    let mut res = 0u32;
    loop {
        res |= code & 1;
        code >>= 1;
        res <<= 1;
        len -= 1;
        if len == 0 {
            break;
        }
    }
    res >> 1
}

struct Tables {
    length_code: [u8; 256],
    dist_code: [u8; 512],
    base_length: [u8; LENGTH_CODES],
    base_dist: [u16; D_CODES],
    static_ltree: [Ct; L_CODES + 2],
    static_dtree: [Ct; D_CODES],
}

const fn build_tables() -> Tables {
    let mut t = Tables {
        length_code: [0; 256],
        dist_code: [0; 512],
        base_length: [0; LENGTH_CODES],
        base_dist: [0; D_CODES],
        static_ltree: [Ct { fc: 0, dl: 0 }; L_CODES + 2],
        static_dtree: [Ct { fc: 0, dl: 0 }; D_CODES],
    };
    let mut length = 0usize;
    let mut code = 0usize;
    while code < LENGTH_CODES - 1 {
        t.base_length[code] = length as u8;
        let mut n = 0;
        while n < (1 << EXTRA_LBITS[code]) {
            t.length_code[length] = code as u8;
            length += 1;
            n += 1;
        }
        code += 1;
    }
    t.length_code[length - 1] = code as u8;
    let mut dist = 0usize;
    code = 0;
    while code < 16 {
        t.base_dist[code] = dist as u16;
        let mut n = 0;
        while n < (1 << EXTRA_DBITS[code]) {
            t.dist_code[dist] = code as u8;
            dist += 1;
            n += 1;
        }
        code += 1;
    }
    dist >>= 7;
    while code < D_CODES {
        t.base_dist[code] = (dist << 7) as u16;
        let mut n = 0;
        while n < (1 << (EXTRA_DBITS[code] - 7)) {
            t.dist_code[256 + dist] = code as u8;
            dist += 1;
            n += 1;
        }
        code += 1;
    }
    let mut bl_count = [0u16; MAX_BITS + 1];
    let mut n = 0;
    while n <= 287 {
        let len = if n <= 143 {
            8
        } else if n <= 255 {
            9
        } else if n <= 279 {
            7
        } else {
            8
        };
        t.static_ltree[n].dl = len;
        bl_count[len as usize] += 1;
        n += 1;
    }
    // gen_codes(static_ltree, L_CODES + 1, bl_count)
    let mut next_code = [0u16; MAX_BITS + 1];
    let mut c = 0u32;
    let mut bits = 1;
    while bits <= MAX_BITS {
        c = (c + bl_count[bits - 1] as u32) << 1;
        next_code[bits] = c as u16;
        bits += 1;
    }
    n = 0;
    while n <= L_CODES + 1 {
        let len = t.static_ltree[n].dl as usize;
        if len != 0 {
            t.static_ltree[n].fc = bi_reverse(next_code[len] as u32, len as u32) as u16;
            next_code[len] += 1;
        }
        n += 1;
    }
    n = 0;
    while n < D_CODES {
        t.static_dtree[n] = Ct { fc: bi_reverse(n as u32, 5) as u16, dl: 5 };
        n += 1;
    }
    t
}

static TABLES: Tables = build_tables();

#[inline(always)]
fn d_code(dist: usize) -> usize {
    if dist < 256 { TABLES.dist_code[dist] as usize } else { TABLES.dist_code[256 + (dist >> 7)] as usize }
}

struct StaticDesc {
    stree: Option<&'static [Ct]>,
    extra: &'static [u8],
    extra_base: usize,
    elems: usize,
    max_length: u32,
}

static STATIC_L_DESC: StaticDesc = StaticDesc {
    stree: Some(&TABLES.static_ltree),
    extra: &EXTRA_LBITS,
    extra_base: LITERALS + 1,
    elems: L_CODES,
    max_length: MAX_BITS as u32,
};
static STATIC_D_DESC: StaticDesc =
    StaticDesc { stree: Some(&TABLES.static_dtree), extra: &EXTRA_DBITS, extra_base: 0, elems: D_CODES, max_length: MAX_BITS as u32 };
static STATIC_BL_DESC: StaticDesc =
    StaticDesc { stree: None, extra: &EXTRA_BLBITS, extra_base: 0, elems: BL_CODES, max_length: MAX_BL_BITS as u32 };

// ---------------------------------------------------------------------------------------------
// Huffman tree construction (trees.c), operating on one tree + the shared heap state.

struct Heap {
    heap: [i32; 2 * L_CODES + 1],
    heap_len: usize,
    heap_max: usize,
    depth: [u8; 2 * L_CODES + 1],
    bl_count: [u16; MAX_BITS + 1],
    opt_len: u64,
    static_len: u64,
}

impl Heap {
    #[inline(always)]
    fn smaller(&self, tree: &[Ct], n: usize, m: usize) -> bool {
        tree[n].fc < tree[m].fc || (tree[n].fc == tree[m].fc && self.depth[n] <= self.depth[m])
    }

    fn pqdownheap(&mut self, tree: &[Ct], mut k: usize) {
        let v = self.heap[k] as usize;
        let mut j = k << 1;
        while j <= self.heap_len {
            if j < self.heap_len && self.smaller(tree, self.heap[j + 1] as usize, self.heap[j] as usize) {
                j += 1;
            }
            if self.smaller(tree, v, self.heap[j] as usize) {
                break;
            }
            self.heap[k] = self.heap[j];
            k = j;
            j <<= 1;
        }
        self.heap[k] = v as i32;
    }

    fn gen_bitlen(&mut self, tree: &mut [Ct], max_code: usize, desc: &StaticDesc) {
        let stree = desc.stree;
        let extra = desc.extra;
        let base = desc.extra_base;
        let max_length = desc.max_length;
        let mut overflow = 0i32;
        self.bl_count = [0; MAX_BITS + 1];
        tree[self.heap[self.heap_max] as usize].dl = 0;
        let mut h = self.heap_max + 1;
        while h < HEAP_SIZE {
            let n = self.heap[h] as usize;
            let mut bits = tree[tree[n].dl as usize].dl as u32 + 1;
            if bits > max_length {
                bits = max_length;
                overflow += 1;
            }
            tree[n].dl = bits as u16;
            h += 1;
            if n > max_code {
                continue;
            }
            self.bl_count[bits as usize] += 1;
            let mut xbits = 0u32;
            if n >= base {
                xbits = extra[n - base] as u32;
            }
            let f = tree[n].fc as u64;
            self.opt_len = self.opt_len.wrapping_add(f * (bits + xbits) as u64);
            if let Some(st) = stree {
                self.static_len = self.static_len.wrapping_add(f * (st[n].dl as u32 + xbits) as u64);
            }
        }
        if overflow == 0 {
            return;
        }
        loop {
            let mut bits = max_length as usize - 1;
            while self.bl_count[bits] == 0 {
                bits -= 1;
            }
            self.bl_count[bits] -= 1;
            self.bl_count[bits + 1] += 2;
            self.bl_count[max_length as usize] -= 1;
            overflow -= 2;
            if overflow <= 0 {
                break;
            }
        }
        let mut h = HEAP_SIZE;
        let mut bits = max_length as usize;
        while bits != 0 {
            let mut n = self.bl_count[bits];
            while n != 0 {
                h -= 1;
                let m = self.heap[h] as usize;
                if m > max_code {
                    continue;
                }
                if tree[m].dl as usize != bits {
                    self.opt_len = self
                        .opt_len
                        .wrapping_add((bits as u64).wrapping_sub(tree[m].dl as u64).wrapping_mul(tree[m].fc as u64));
                    tree[m].dl = bits as u16;
                }
                n -= 1;
            }
            bits -= 1;
        }
    }

    /// build_tree: returns max_code.
    fn build_tree(&mut self, tree: &mut [Ct], desc: &StaticDesc) -> usize {
        let stree = desc.stree;
        let elems = desc.elems;
        let mut max_code: isize = -1;
        self.heap_len = 0;
        self.heap_max = HEAP_SIZE;
        for n in 0..elems {
            if tree[n].fc != 0 {
                self.heap_len += 1;
                self.heap[self.heap_len] = n as i32;
                max_code = n as isize;
                self.depth[n] = 0;
            } else {
                tree[n].dl = 0;
            }
        }
        while self.heap_len < 2 {
            let node = if max_code < 2 {
                max_code += 1;
                max_code as usize
            } else {
                0
            };
            self.heap_len += 1;
            self.heap[self.heap_len] = node as i32;
            tree[node].fc = 1;
            self.depth[node] = 0;
            self.opt_len = self.opt_len.wrapping_sub(1);
            if let Some(st) = stree {
                self.static_len = self.static_len.wrapping_sub(st[node].dl as u64);
            }
        }
        let max_code = max_code as usize;
        let mut n = self.heap_len / 2;
        while n >= 1 {
            self.pqdownheap(tree, n);
            n -= 1;
        }
        let mut node = elems;
        loop {
            // pqremove
            let n = self.heap[1] as usize;
            self.heap[1] = self.heap[self.heap_len];
            self.heap_len -= 1;
            self.pqdownheap(tree, 1);
            let m = self.heap[1] as usize;
            self.heap_max -= 1;
            self.heap[self.heap_max] = n as i32;
            self.heap_max -= 1;
            self.heap[self.heap_max] = m as i32;
            tree[node].fc = tree[n].fc.wrapping_add(tree[m].fc);
            self.depth[node] = (if self.depth[n] >= self.depth[m] { self.depth[n] } else { self.depth[m] }).wrapping_add(1);
            tree[n].dl = node as u16;
            tree[m].dl = node as u16;
            self.heap[1] = node as i32;
            node += 1;
            self.pqdownheap(tree, 1);
            if self.heap_len < 2 {
                break;
            }
        }
        self.heap_max -= 1;
        self.heap[self.heap_max] = self.heap[1];
        self.gen_bitlen(tree, max_code, desc);
        gen_codes(tree, max_code, &self.bl_count);
        max_code
    }
}

fn gen_codes(tree: &mut [Ct], max_code: usize, bl_count: &[u16; MAX_BITS + 1]) {
    let mut next_code = [0u16; MAX_BITS + 1];
    let mut code = 0u32;
    for bits in 1..=MAX_BITS {
        code = (code + bl_count[bits - 1] as u32) << 1;
        next_code[bits] = code as u16;
    }
    for n in 0..=max_code {
        let len = tree[n].dl as usize;
        if len == 0 {
            continue;
        }
        tree[n].fc = bi_reverse(next_code[len] as u32, len as u32) as u16;
        next_code[len] = next_code[len].wrapping_add(1);
    }
}

fn scan_tree(bl_tree: &mut [Ct], tree: &mut [Ct], max_code: usize) {
    let mut prevlen: i32 = -1;
    let mut nextlen = tree[0].dl as i32;
    let mut count = 0i32;
    let mut max_count = 7;
    let mut min_count = 4;
    if nextlen == 0 {
        max_count = 138;
        min_count = 3;
    }
    tree[max_code + 1].dl = 0xffff;
    for n in 0..=max_code {
        let curlen = nextlen;
        nextlen = tree[n + 1].dl as i32;
        count += 1;
        if count < max_count && curlen == nextlen {
            continue;
        } else if count < min_count {
            bl_tree[curlen as usize].fc = bl_tree[curlen as usize].fc.wrapping_add(count as u16);
        } else if curlen != 0 {
            if curlen != prevlen {
                bl_tree[curlen as usize].fc = bl_tree[curlen as usize].fc.wrapping_add(1);
            }
            bl_tree[REP_3_6].fc = bl_tree[REP_3_6].fc.wrapping_add(1);
        } else if count <= 10 {
            bl_tree[REPZ_3_10].fc = bl_tree[REPZ_3_10].fc.wrapping_add(1);
        } else {
            bl_tree[REPZ_11_138].fc = bl_tree[REPZ_11_138].fc.wrapping_add(1);
        }
        count = 0;
        prevlen = curlen;
        if nextlen == 0 {
            max_count = 138;
            min_count = 3;
        } else if curlen == nextlen {
            max_count = 6;
            min_count = 3;
        } else {
            max_count = 7;
            min_count = 4;
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Pending output + bit buffer. zlib keeps at most 16 bits in bi_buf; we keep up to 64 and
// emit whole bytes lazily. The byte stream is identical; at every point where zlib looks at
// `pending`/`bi_valid` (flush_pending, stored blocks) the whole bytes have been emitted first,
// leaving exactly `total_bits % 8` bits, like zlib's bi_flush.

struct Pend {
    buf: Vec<u8>,
    /// zlib's `pending_out` (offset of the next byte to hand to the caller).
    out: usize,
    /// `pending_out + pending`: where the next byte goes.
    end: usize,
    bi_buf: u64,
    bi_valid: u32,
}

impl Pend {
    #[inline(always)]
    fn pending(&self) -> usize {
        self.end - self.out
    }

    /// Make room for `n` more bytes (+ 8 bytes of slack for the 64-bit stores).
    #[inline]
    fn reserve(&mut self, n: usize) {
        let need = self.end + n + 16;
        if need > self.buf.len() {
            self.buf.resize(need.next_power_of_two(), 0);
        }
    }

    #[inline(always)]
    fn put_byte(&mut self, b: u8) {
        self.buf[self.end] = b;
        self.end += 1;
    }

    #[inline(always)]
    fn put_short(&mut self, w: u16) {
        self.put_byte(w as u8);
        self.put_byte((w >> 8) as u8);
    }

    #[inline(always)]
    fn put_short_msb(&mut self, b: u32) {
        self.put_byte((b >> 8) as u8);
        self.put_byte(b as u8);
    }

    /// Store the whole bytes of the bit buffer.
    #[inline(always)]
    fn spill(&mut self) {
        let e = self.end;
        self.buf[e..e + 8].copy_from_slice(&self.bi_buf.to_le_bytes());
        let nbytes = self.bi_valid >> 3;
        self.end = e + nbytes as usize;
        self.bi_buf = self.bi_buf.checked_shr(nbytes * 8).unwrap_or(0);
        self.bi_valid &= 7;
    }

    #[inline(always)]
    fn send_bits(&mut self, value: u32, length: u32) {
        if self.bi_valid + length > 64 {
            self.spill();
        }
        self.bi_buf |= (value as u64) << self.bi_valid;
        self.bi_valid += length;
    }

    #[inline(always)]
    fn send_code(&mut self, c: usize, tree: &[Ct]) {
        self.send_bits(tree[c].fc as u32, tree[c].dl as u32);
    }

    /// bi_flush: emit whole bytes, keep at most 7 bits.
    #[inline]
    fn flush_bits(&mut self) {
        if self.bi_valid >= 8 {
            self.spill();
        }
    }

    /// bi_windup: emit everything, byte aligned.
    fn windup(&mut self) {
        self.flush_bits();
        if self.bi_valid > 0 {
            self.put_byte(self.bi_buf as u8);
        }
        self.bi_buf = 0;
        self.bi_valid = 0;
    }
}

// ---------------------------------------------------------------------------------------------
// Output sinks and the per-call stream view.

/// Where `deflate()` writes: a bounded slice (`avail_out` semantics) or an unbounded Vec.
trait Sink {
    fn avail_out(&self) -> usize;
    fn write(&mut self, data: &[u8]);
}

struct SliceSink<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl Sink for SliceSink<'_> {
    #[inline(always)]
    fn avail_out(&self) -> usize {
        self.buf.len() - self.pos
    }
    #[inline(always)]
    fn write(&mut self, data: &[u8]) {
        self.buf[self.pos..self.pos + data.len()].copy_from_slice(data);
        self.pos += data.len();
    }
}

struct VecSink<'a>(&'a mut Vec<u8>);

impl Sink for VecSink<'_> {
    #[inline(always)]
    fn avail_out(&self) -> usize {
        u32::MAX as usize
    }
    #[inline(always)]
    fn write(&mut self, data: &[u8]) {
        self.0.extend_from_slice(data);
    }
}

struct Io<'a, S> {
    input: &'a [u8],
    pos: usize,
    out: S,
}

impl<S> Io<'_, S> {
    #[inline(always)]
    fn avail_in(&self) -> usize {
        self.input.len() - self.pos
    }
}

// ---------------------------------------------------------------------------------------------
// The compressor state (deflate_state + the z_stream fields deflate uses).

/// A zlib 1.3.2 `deflate` stream (see the module docs).
pub struct Deflater {
    /// `strm->total_in` / `strm->total_out`.
    pub total_in: u64,
    pub total_out: u64,
    /// `strm->adler` (Adler-32 or CRC-32 of the input consumed so far).
    adler: u32,
    status: i32,
    pend: Pend,
    pending_buf_size: usize,
    wrap: i32,
    last_flush: i32,
    w_size: usize,
    w_mask: usize,
    w_bits: u32,
    window: Vec<u8>,
    window_size: usize,
    prev: Vec<u16>,
    head: Vec<u16>,
    ins_h: u32,
    hash_mask: u32,
    hash_shift: u32,
    block_start: i64,
    match_length: usize,
    prev_match: usize,
    match_available: bool,
    strstart: usize,
    match_start: usize,
    lookahead: usize,
    prev_length: usize,
    max_chain_length: u32,
    max_lazy_match: usize,
    level: i32,
    strategy: i32,
    good_match: usize,
    nice_match: usize,
    dyn_ltree: [Ct; HEAP_SIZE],
    dyn_dtree: [Ct; 2 * D_CODES + 1],
    bl_tree: [Ct; 2 * BL_CODES + 1],
    l_max_code: usize,
    d_max_code: usize,
    hp: Heap,
    /// Symbol buffer (zlib's LIT_MEM layout: distance / literal-or-length per symbol).
    d_buf: Vec<u16>,
    l_buf: Vec<u8>,
    sym_next: usize,
    sym_end: usize,
    insert: usize,
    high_water: usize,
    /// Pending hash slides of `deflate_stored` (zlib's `s->matches` reuse).
    matches: u32,
}

impl Deflater {
    /// `deflateInit2(level, Z_DEFLATED, window_bits, mem_level, strategy)`. `window_bits` 8..15
    /// (zlib), -8..-15 (raw deflate) or 24..31 (gzip, default header). `None` where zlib
    /// returns `Z_STREAM_ERROR`.
    pub fn new(level: i32, window_bits: i32, mem_level: i32, strategy: i32) -> Option<Deflater> {
        let mut level = level;
        let mut window_bits = window_bits;
        let mut wrap = 1;
        if level == Z_DEFAULT_COMPRESSION {
            level = 6;
        }
        if window_bits < 0 {
            wrap = 0;
            if window_bits < -15 {
                return None;
            }
            window_bits = -window_bits;
        } else if window_bits > 15 {
            wrap = 2;
            window_bits -= 16;
        }
        if !(1..=9).contains(&mem_level)
            || !(8..=15).contains(&window_bits)
            || !(0..=9).contains(&level)
            || !(0..=Z_FIXED).contains(&strategy)
            || (window_bits == 8 && wrap != 1)
        {
            return None;
        }
        if window_bits == 8 {
            window_bits = 9;
        }
        let w_bits = window_bits as u32;
        let w_size = 1usize << w_bits;
        let hash_bits = mem_level as u32 + 7;
        let hash_size = 1usize << hash_bits;
        let lit_bufsize = 1usize << (mem_level + 6);
        let pending_buf_size = lit_bufsize * 4;
        let (good, lazy, nice, chain, _) = CONFIG[level as usize];
        let mut s = Deflater {
            total_in: 0,
            total_out: 0,
            adler: 0,
            status: INIT_STATE,
            pend: Pend { buf: vec![0; pending_buf_size + 64], out: 0, end: 0, bi_buf: 0, bi_valid: 0 },
            pending_buf_size,
            wrap,
            last_flush: -2,
            w_size,
            w_mask: w_size - 1,
            w_bits,
            // + padding: the 8-byte match comparisons never read past window_size, but the
            // slack keeps every access trivially in bounds.
            window: vec![0; 2 * w_size + 16],
            window_size: 2 * w_size,
            prev: vec![0; w_size],
            head: vec![0; hash_size],
            ins_h: 0,
            hash_mask: hash_size as u32 - 1,
            hash_shift: (hash_bits + MIN_MATCH as u32 - 1) / MIN_MATCH as u32,
            block_start: 0,
            match_length: MIN_MATCH - 1,
            prev_match: 0,
            match_available: false,
            strstart: 0,
            match_start: 0,
            lookahead: 0,
            prev_length: MIN_MATCH - 1,
            max_chain_length: chain as u32,
            max_lazy_match: lazy as usize,
            level,
            strategy,
            good_match: good as usize,
            nice_match: nice as usize,
            dyn_ltree: [Ct::default(); HEAP_SIZE],
            dyn_dtree: [Ct::default(); 2 * D_CODES + 1],
            bl_tree: [Ct::default(); 2 * BL_CODES + 1],
            l_max_code: 0,
            d_max_code: 0,
            hp: Heap {
                heap: [0; 2 * L_CODES + 1],
                heap_len: 0,
                heap_max: 0,
                depth: [0; 2 * L_CODES + 1],
                bl_count: [0; MAX_BITS + 1],
                opt_len: 0,
                static_len: 0,
            },
            d_buf: vec![0; lit_bufsize],
            l_buf: vec![0; lit_bufsize],
            sym_next: 0,
            sym_end: lit_bufsize - 1,
            insert: 0,
            high_water: 0,
            matches: 0,
        };
        // deflateResetKeep
        s.status = if s.wrap == 2 { GZIP_STATE } else { INIT_STATE };
        s.adler = if s.wrap == 2 { 0 } else { 1 };
        s.init_block();
        Some(s)
    }

    /// `strm->adler`: the running Adler-32 (zlib/raw) or CRC-32 (gzip) of the input.
    pub fn adler(&self) -> u32 {
        self.adler
    }

    /// One `deflate(strm, flush)` call: consumes from `input` (`next_in`/`avail_in`), writes to
    /// `output` (`next_out`/`avail_out`). Returns `(ret, consumed, produced)` where `ret` is
    /// zlib's return code (`Z_OK`, `Z_STREAM_END`, `Z_BUF_ERROR`, `Z_STREAM_ERROR`).
    /// Slices longer than 4 GiB - 1 are clamped like `uInt` fields.
    pub fn deflate(&mut self, input: &[u8], output: &mut [u8], flush: i32) -> (i32, usize, usize) {
        let input = &input[..input.len().min(u32::MAX as usize)];
        let olen = output.len().min(u32::MAX as usize);
        let mut io = Io { input, pos: 0, out: SliceSink { buf: &mut output[..olen], pos: 0 } };
        let ret = self.deflate_impl(&mut io, flush);
        (ret, io.pos, io.out.pos)
    }

    /// `deflate()` with an output buffer that never fills: consumes all of `input` and appends
    /// everything produced to `out`. For levels 1-9 the byte stream equals any sequence of
    /// bounded calls with the same input chunks; level 0 (stored blocks sized by `avail_out`)
    /// equals one call with an unlimited `avail_out`. Returns the last `deflate()` return code.
    pub fn deflate_vec(&mut self, input: &[u8], out: &mut Vec<u8>, flush: i32) -> i32 {
        let mut rest = input;
        loop {
            let n = rest.len().min(u32::MAX as usize);
            let (chunk, tail) = rest.split_at(n);
            let f = if tail.is_empty() { flush } else { Z_NO_FLUSH };
            let mut io = Io { input: chunk, pos: 0, out: VecSink(out) };
            let ret = self.deflate_impl(&mut io, f);
            rest = tail;
            if rest.is_empty() || ret < 0 {
                return ret;
            }
        }
    }

    // --- deflate.c ---------------------------------------------------------------------------

    fn deflate_impl<S: Sink>(&mut self, io: &mut Io<S>, flush: i32) -> i32 {
        if !(0..=Z_BLOCK).contains(&flush) {
            return Z_STREAM_ERROR;
        }
        if self.status == FINISH_STATE && flush != Z_FINISH {
            return Z_STREAM_ERROR;
        }
        if io.out.avail_out() == 0 {
            return Z_BUF_ERROR;
        }
        let old_flush = self.last_flush;
        self.last_flush = flush;

        if self.pend.pending() != 0 {
            self.flush_pending(io);
            if io.out.avail_out() == 0 {
                self.last_flush = -1;
                return Z_OK;
            }
        } else if io.avail_in() == 0 && rank(flush) <= rank(old_flush) && flush != Z_FINISH {
            return Z_BUF_ERROR;
        }
        if self.status == FINISH_STATE && io.avail_in() != 0 {
            return Z_BUF_ERROR;
        }
        if self.status == INIT_STATE && self.wrap == 0 {
            self.status = BUSY_STATE;
        }
        if self.status == INIT_STATE {
            let mut header = (8 + ((self.w_bits - 8) << 4)) << 8;
            let level_flags = if self.strategy >= Z_HUFFMAN_ONLY || self.level < 2 {
                0
            } else if self.level < 6 {
                1
            } else if self.level == 6 {
                2
            } else {
                3
            };
            header |= level_flags << 6;
            if self.strstart != 0 {
                header |= 0x20; // PRESET_DICT
            }
            header += 31 - (header % 31);
            self.pend.reserve(8);
            self.pend.put_short_msb(header);
            if self.strstart != 0 {
                self.pend.put_short_msb(self.adler >> 16);
                self.pend.put_short_msb(self.adler & 0xffff);
            }
            self.adler = 1;
            self.status = BUSY_STATE;
            self.flush_pending(io);
            if self.pend.pending() != 0 {
                self.last_flush = -1;
                return Z_OK;
            }
        }
        if self.status == GZIP_STATE {
            self.adler = 0;
            self.pend.reserve(16);
            for b in [31u8, 139, 8, 0, 0, 0, 0, 0] {
                self.pend.put_byte(b);
            }
            let xfl = if self.level == 9 {
                2
            } else if self.strategy >= Z_HUFFMAN_ONLY || self.level < 2 {
                4
            } else {
                0
            };
            self.pend.put_byte(xfl);
            self.pend.put_byte(OS_CODE);
            self.status = BUSY_STATE;
            self.flush_pending(io);
            if self.pend.pending() != 0 {
                self.last_flush = -1;
                return Z_OK;
            }
        }

        if io.avail_in() != 0 || self.lookahead != 0 || (flush != Z_NO_FLUSH && self.status != FINISH_STATE) {
            let bstate = if self.level == 0 {
                self.deflate_stored(io, flush)
            } else if self.strategy == Z_HUFFMAN_ONLY {
                self.deflate_huff(io, flush)
            } else if self.strategy == Z_RLE {
                self.deflate_rle(io, flush)
            } else if CONFIG[self.level as usize].4 == Func::Fast {
                self.deflate_fast(io, flush)
            } else {
                self.deflate_slow(io, flush)
            };
            if bstate == BlockState::FinishStarted || bstate == BlockState::FinishDone {
                self.status = FINISH_STATE;
            }
            if bstate == BlockState::NeedMore || bstate == BlockState::FinishStarted {
                if io.out.avail_out() == 0 {
                    self.last_flush = -1;
                }
                return Z_OK;
            }
            if bstate == BlockState::BlockDone {
                if flush == Z_PARTIAL_FLUSH {
                    self.tr_align();
                } else if flush != Z_BLOCK {
                    self.tr_stored_block(0, 0, false);
                    if flush == Z_FULL_FLUSH {
                        self.clear_hash();
                        if self.lookahead == 0 {
                            self.strstart = 0;
                            self.block_start = 0;
                            self.insert = 0;
                        }
                    }
                }
                self.flush_pending(io);
                if io.out.avail_out() == 0 {
                    self.last_flush = -1;
                    return Z_OK;
                }
            }
        }

        if flush != Z_FINISH {
            return Z_OK;
        }
        if self.wrap <= 0 {
            return Z_STREAM_END;
        }
        self.pend.reserve(16);
        if self.wrap == 2 {
            for b in self.adler.to_le_bytes() {
                self.pend.put_byte(b);
            }
            for b in (self.total_in as u32).to_le_bytes() {
                self.pend.put_byte(b);
            }
        } else {
            self.pend.put_short_msb(self.adler >> 16);
            self.pend.put_short_msb(self.adler & 0xffff);
        }
        self.flush_pending(io);
        if self.wrap > 0 {
            self.wrap = -self.wrap;
        }
        if self.pend.pending() != 0 { Z_OK } else { Z_STREAM_END }
    }

    fn clear_hash(&mut self) {
        self.head.fill(0);
    }

    fn slide_hash(&mut self) {
        let wsize = self.w_size as u16;
        for h in self.head.iter_mut() {
            *h = h.saturating_sub(wsize);
        }
        for p in self.prev.iter_mut() {
            *p = p.saturating_sub(wsize);
        }
    }

    #[inline(always)]
    fn update_hash(&self, h: u32, c: u8) -> u32 {
        ((h << self.hash_shift) ^ c as u32) & self.hash_mask
    }

    /// INSERT_STRING: returns the previous head of the chain.
    #[inline(always)]
    fn insert_string(&mut self, str: usize) -> usize {
        self.ins_h = self.update_hash(self.ins_h, self.window[str + (MIN_MATCH - 1)]);
        let h = self.ins_h as usize;
        let head = self.head[h];
        self.prev[str & self.w_mask] = head;
        self.head[h] = str as u16;
        head as usize
    }

    /// read_buf into window[at..], updating the check value and total_in.
    fn read_buf<S>(&mut self, io: &mut Io<S>, at: usize, size: usize) -> usize {
        let len = io.avail_in().min(size);
        if len == 0 {
            return 0;
        }
        let src = &io.input[io.pos..io.pos + len];
        self.window[at..at + len].copy_from_slice(src);
        if self.wrap == 1 {
            self.adler = adler32_update(self.adler, src);
        } else if self.wrap == 2 {
            self.adler = crc32_update(self.adler, src);
        }
        io.pos += len;
        self.total_in += len as u64;
        len
    }

    /// Updates the check value for input copied straight to the output (deflate_stored).
    fn read_buf_direct<S: Sink>(&mut self, io: &mut Io<S>, len: usize) {
        let len = io.avail_in().min(len);
        if len == 0 {
            return;
        }
        let src = &io.input[io.pos..io.pos + len];
        if self.wrap == 1 {
            self.adler = adler32_update(self.adler, src);
        } else if self.wrap == 2 {
            self.adler = crc32_update(self.adler, src);
        }
        io.out.write(src);
        io.pos += len;
        self.total_in += len as u64;
    }

    fn fill_window<S>(&mut self, io: &mut Io<S>) {
        let wsize = self.w_size;
        loop {
            let mut more = self.window_size - self.lookahead - self.strstart;
            if self.strstart >= wsize + (wsize - MIN_LOOKAHEAD) {
                self.window.copy_within(wsize..wsize + wsize - more, 0);
                self.match_start = self.match_start.wrapping_sub(wsize);
                self.strstart -= wsize;
                self.block_start -= wsize as i64;
                if self.insert > self.strstart {
                    self.insert = self.strstart;
                }
                self.slide_hash();
                more += wsize;
            }
            if io.avail_in() == 0 {
                break;
            }
            let n = self.read_buf(io, self.strstart + self.lookahead, more);
            self.lookahead += n;
            if self.lookahead + self.insert >= MIN_MATCH {
                let mut str = self.strstart - self.insert;
                self.ins_h = self.window[str] as u32;
                self.ins_h = self.update_hash(self.ins_h, self.window[str + 1]);
                while self.insert != 0 {
                    self.ins_h = self.update_hash(self.ins_h, self.window[str + MIN_MATCH - 1]);
                    let h = self.ins_h as usize;
                    self.prev[str & self.w_mask] = self.head[h];
                    self.head[h] = str as u16;
                    str += 1;
                    self.insert -= 1;
                    if self.lookahead + self.insert < MIN_MATCH {
                        break;
                    }
                }
            }
            if !(self.lookahead < MIN_LOOKAHEAD && io.avail_in() != 0) {
                break;
            }
        }
        if self.high_water < self.window_size {
            let curr = self.strstart + self.lookahead;
            if self.high_water < curr {
                let init = (self.window_size - curr).min(WIN_INIT);
                self.window[curr..curr + init].fill(0);
                self.high_water = curr + init;
            } else if self.high_water < curr + WIN_INIT {
                let init = (curr + WIN_INIT - self.high_water).min(self.window_size - self.high_water);
                self.window[self.high_water..self.high_water + init].fill(0);
                self.high_water += init;
            }
        }
    }

    fn flush_pending<S: Sink>(&mut self, io: &mut Io<S>) {
        self.pend.flush_bits();
        let len = self.pend.pending().min(io.out.avail_out());
        if len == 0 {
            return;
        }
        io.out.write(&self.pend.buf[self.pend.out..self.pend.out + len]);
        self.pend.out += len;
        self.total_out += len as u64;
        if self.pend.out == self.pend.end {
            self.pend.out = 0;
            self.pend.end = 0;
        }
    }

    /// FLUSH_BLOCK_ONLY.
    fn flush_block_only<S: Sink>(&mut self, io: &mut Io<S>, last: bool) {
        let buf = if self.block_start >= 0 { Some(self.block_start as usize) } else { None };
        let stored_len = (self.strstart as i64 - self.block_start) as u64;
        self.tr_flush_block(buf, stored_len, last);
        self.block_start = self.strstart as i64;
        self.flush_pending(io);
    }

    /// longest_match (non-FASTEST). Sets match_start, returns the length.
    #[inline(always)]
    fn longest_match(&mut self, mut cur_match: usize) -> usize {
        let mut chain_length = self.max_chain_length;
        let win = &self.window[..];
        let scan = self.strstart;
        let mut best_len = self.prev_length;
        let mut nice_match = self.nice_match;
        let max_dist = self.w_size - MIN_LOOKAHEAD;
        let limit = if self.strstart > max_dist { self.strstart - max_dist } else { NIL };
        let prev = &self.prev[..];
        let wmask = self.w_mask;
        let scan_start = rd16(win, scan);
        let mut scan_end = rd16(win, scan + best_len - 1);
        if self.prev_length >= self.good_match {
            chain_length >>= 2;
        }
        if nice_match > self.lookahead {
            nice_match = self.lookahead;
        }
        let mut match_start = self.match_start;
        loop {
            if rd16(win, cur_match + best_len - 1) == scan_end && rd16(win, cur_match) == scan_start {
                let len = match_len(win, scan, cur_match);
                if len > best_len {
                    match_start = cur_match;
                    best_len = len;
                    if len >= nice_match {
                        break;
                    }
                    scan_end = rd16(win, scan + best_len - 1);
                }
            }
            cur_match = prev[cur_match & wmask] as usize;
            if cur_match <= limit {
                break;
            }
            chain_length -= 1;
            if chain_length == 0 {
                break;
            }
        }
        self.match_start = match_start;
        if best_len <= self.lookahead { best_len } else { self.lookahead }
    }

    #[inline(always)]
    fn tally_lit(&mut self, c: u8) -> bool {
        self.d_buf[self.sym_next] = 0;
        self.l_buf[self.sym_next] = c;
        self.sym_next += 1;
        let f = &mut self.dyn_ltree[c as usize].fc;
        *f = f.wrapping_add(1);
        self.sym_next == self.sym_end
    }

    /// `dist` is the match distance, `lc` the match length - MIN_MATCH.
    #[inline(always)]
    fn tally_dist(&mut self, dist: usize, lc: usize) -> bool {
        self.d_buf[self.sym_next] = dist as u16;
        self.l_buf[self.sym_next] = lc as u8;
        self.sym_next += 1;
        let dist = (dist as u16).wrapping_sub(1) as usize;
        let f = &mut self.dyn_ltree[TABLES.length_code[lc as u8 as usize] as usize + LITERALS + 1].fc;
        *f = f.wrapping_add(1);
        let f = &mut self.dyn_dtree[d_code(dist)].fc;
        *f = f.wrapping_add(1);
        self.sym_next == self.sym_end
    }

    fn deflate_stored<S: Sink>(&mut self, io: &mut Io<S>, flush: i32) -> BlockState {
        let mut min_block = (self.pending_buf_size - 5).min(self.w_size);
        let mut last = false;
        let mut used = io.avail_in();
        loop {
            let mut len = MAX_STORED;
            let mut have = (self.pend.bi_valid as usize + 42) >> 3;
            if io.out.avail_out() < have {
                break;
            }
            have = io.out.avail_out() - have;
            let mut left = (self.strstart as i64 - self.block_start) as usize;
            if len > left + io.avail_in() {
                len = left + io.avail_in();
            }
            if len > have {
                len = have;
            }
            if len < min_block
                && ((len == 0 && flush != Z_FINISH) || flush == Z_NO_FLUSH || len != left + io.avail_in())
            {
                break;
            }
            last = flush == Z_FINISH && len == left + io.avail_in();
            self.tr_stored_block(0, 0, last);
            let e = self.pend.end;
            self.pend.buf[e - 4] = len as u8;
            self.pend.buf[e - 3] = (len >> 8) as u8;
            self.pend.buf[e - 2] = !len as u8;
            self.pend.buf[e - 1] = (!len >> 8) as u8;
            self.flush_pending(io);
            if left != 0 {
                if left > len {
                    left = len;
                }
                let bs = self.block_start as usize;
                io.out.write(&self.window[bs..bs + left]);
                self.total_out += left as u64;
                self.block_start += left as i64;
                len -= left;
            }
            if len != 0 {
                self.read_buf_direct(io, len);
                self.total_out += len as u64;
            }
            if last {
                break;
            }
        }

        used -= io.avail_in();
        if used != 0 {
            if used >= self.w_size {
                self.matches = 2;
                let src = &io.input[io.pos - self.w_size..io.pos];
                self.window[..self.w_size].copy_from_slice(src);
                self.strstart = self.w_size;
                self.insert = self.strstart;
            } else {
                if self.window_size - self.strstart <= used {
                    self.strstart -= self.w_size;
                    self.window.copy_within(self.w_size..self.w_size + self.strstart, 0);
                    if self.matches < 2 {
                        self.matches += 1;
                    }
                    if self.insert > self.strstart {
                        self.insert = self.strstart;
                    }
                }
                let src = &io.input[io.pos - used..io.pos];
                self.window[self.strstart..self.strstart + used].copy_from_slice(src);
                self.strstart += used;
                self.insert += used.min(self.w_size - self.insert);
            }
            self.block_start = self.strstart as i64;
        }
        if self.high_water < self.strstart {
            self.high_water = self.strstart;
        }
        if last {
            return BlockState::FinishDone;
        }
        if flush != Z_NO_FLUSH && flush != Z_FINISH && io.avail_in() == 0 && self.strstart as i64 == self.block_start {
            return BlockState::BlockDone;
        }
        let mut have = self.window_size - self.strstart;
        if io.avail_in() > have && self.block_start >= self.w_size as i64 {
            self.block_start -= self.w_size as i64;
            self.strstart -= self.w_size;
            self.window.copy_within(self.w_size..self.w_size + self.strstart, 0);
            if self.matches < 2 {
                self.matches += 1;
            }
            have += self.w_size;
            if self.insert > self.strstart {
                self.insert = self.strstart;
            }
        }
        if have > io.avail_in() {
            have = io.avail_in();
        }
        if have != 0 {
            self.read_buf(io, self.strstart, have);
            self.strstart += have;
            self.insert += have.min(self.w_size - self.insert);
        }
        if self.high_water < self.strstart {
            self.high_water = self.strstart;
        }
        let have = (self.pend.bi_valid as usize + 42) >> 3;
        let have = (self.pending_buf_size - have).min(MAX_STORED);
        min_block = have.min(self.w_size);
        let left = (self.strstart as i64 - self.block_start) as usize;
        if left >= min_block
            || ((left != 0 || flush == Z_FINISH) && flush != Z_NO_FLUSH && io.avail_in() == 0 && left <= have)
        {
            let len = left.min(have);
            last = flush == Z_FINISH && io.avail_in() == 0 && len == left;
            self.tr_stored_block(self.block_start as usize, len, last);
            self.block_start += len as i64;
            self.flush_pending(io);
        }
        if last { BlockState::FinishStarted } else { BlockState::NeedMore }
    }

    fn deflate_fast<S: Sink>(&mut self, io: &mut Io<S>, flush: i32) -> BlockState {
        let max_dist = self.w_size - MIN_LOOKAHEAD;
        loop {
            if self.lookahead < MIN_LOOKAHEAD {
                self.fill_window(io);
                if self.lookahead < MIN_LOOKAHEAD && flush == Z_NO_FLUSH {
                    return BlockState::NeedMore;
                }
                if self.lookahead == 0 {
                    break;
                }
            }
            let mut hash_head = NIL;
            if self.lookahead >= MIN_MATCH {
                hash_head = self.insert_string(self.strstart);
            }
            if hash_head != NIL && self.strstart.wrapping_sub(hash_head) <= max_dist {
                self.match_length = self.longest_match(hash_head);
            }
            let bflush;
            if self.match_length >= MIN_MATCH {
                bflush = self.tally_dist(self.strstart - self.match_start, self.match_length - MIN_MATCH);
                self.lookahead -= self.match_length;
                if self.match_length <= self.max_lazy_match && self.lookahead >= MIN_MATCH {
                    self.match_length -= 1;
                    loop {
                        self.strstart += 1;
                        self.insert_string(self.strstart);
                        self.match_length -= 1;
                        if self.match_length == 0 {
                            break;
                        }
                    }
                    self.strstart += 1;
                } else {
                    self.strstart += self.match_length;
                    self.match_length = 0;
                    self.ins_h = self.window[self.strstart] as u32;
                    self.ins_h = self.update_hash(self.ins_h, self.window[self.strstart + 1]);
                }
            } else {
                bflush = self.tally_lit(self.window[self.strstart]);
                self.lookahead -= 1;
                self.strstart += 1;
            }
            if bflush {
                self.flush_block_only(io, false);
                if io.out.avail_out() == 0 {
                    return BlockState::NeedMore;
                }
            }
        }
        self.insert = if self.strstart < MIN_MATCH - 1 { self.strstart } else { MIN_MATCH - 1 };
        self.finish_block(io, flush)
    }

    /// The common tail of deflate_fast / slow / rle / huff.
    fn finish_block<S: Sink>(&mut self, io: &mut Io<S>, flush: i32) -> BlockState {
        if flush == Z_FINISH {
            self.flush_block_only(io, true);
            if io.out.avail_out() == 0 {
                return BlockState::FinishStarted;
            }
            return BlockState::FinishDone;
        }
        if self.sym_next != 0 {
            self.flush_block_only(io, false);
            if io.out.avail_out() == 0 {
                return BlockState::NeedMore;
            }
        }
        BlockState::BlockDone
    }

    fn deflate_slow<S: Sink>(&mut self, io: &mut Io<S>, flush: i32) -> BlockState {
        let max_dist = self.w_size - MIN_LOOKAHEAD;
        let filtered = self.strategy == Z_FILTERED;
        loop {
            if self.lookahead < MIN_LOOKAHEAD {
                self.fill_window(io);
                if self.lookahead < MIN_LOOKAHEAD && flush == Z_NO_FLUSH {
                    return BlockState::NeedMore;
                }
                if self.lookahead == 0 {
                    break;
                }
            }
            let mut hash_head = NIL;
            if self.lookahead >= MIN_MATCH {
                hash_head = self.insert_string(self.strstart);
            }
            self.prev_length = self.match_length;
            self.prev_match = self.match_start;
            self.match_length = MIN_MATCH - 1;
            if hash_head != NIL
                && self.prev_length < self.max_lazy_match
                && self.strstart.wrapping_sub(hash_head) <= max_dist
            {
                self.match_length = self.longest_match(hash_head);
                if self.match_length <= 5
                    && (filtered
                        || (self.match_length == MIN_MATCH
                            && self.strstart.wrapping_sub(self.match_start) > TOO_FAR))
                {
                    self.match_length = MIN_MATCH - 1;
                }
            }
            if self.prev_length >= MIN_MATCH && self.match_length <= self.prev_length {
                let max_insert = (self.strstart + self.lookahead).wrapping_sub(MIN_MATCH);
                let bflush =
                    self.tally_dist(self.strstart - 1 - self.prev_match, self.prev_length - MIN_MATCH);
                self.lookahead -= self.prev_length - 1;
                self.prev_length -= 2;
                loop {
                    self.strstart += 1;
                    if self.strstart <= max_insert {
                        self.insert_string(self.strstart);
                    }
                    self.prev_length -= 1;
                    if self.prev_length == 0 {
                        break;
                    }
                }
                self.match_available = false;
                self.match_length = MIN_MATCH - 1;
                self.strstart += 1;
                if bflush {
                    self.flush_block_only(io, false);
                    if io.out.avail_out() == 0 {
                        return BlockState::NeedMore;
                    }
                }
            } else if self.match_available {
                let bflush = self.tally_lit(self.window[self.strstart - 1]);
                if bflush {
                    self.flush_block_only(io, false);
                }
                self.strstart += 1;
                self.lookahead -= 1;
                if io.out.avail_out() == 0 {
                    return BlockState::NeedMore;
                }
            } else {
                self.match_available = true;
                self.strstart += 1;
                self.lookahead -= 1;
            }
        }
        if self.match_available {
            self.tally_lit(self.window[self.strstart - 1]);
            self.match_available = false;
        }
        self.insert = if self.strstart < MIN_MATCH - 1 { self.strstart } else { MIN_MATCH - 1 };
        self.finish_block(io, flush)
    }

    fn deflate_rle<S: Sink>(&mut self, io: &mut Io<S>, flush: i32) -> BlockState {
        loop {
            if self.lookahead <= MAX_MATCH {
                self.fill_window(io);
                if self.lookahead <= MAX_MATCH && flush == Z_NO_FLUSH {
                    return BlockState::NeedMore;
                }
                if self.lookahead == 0 {
                    break;
                }
            }
            self.match_length = 0;
            if self.lookahead >= MIN_MATCH && self.strstart > 0 {
                let w = &self.window;
                let s = self.strstart;
                let prev = w[s - 1];
                if prev == w[s] && prev == w[s + 1] && prev == w[s + 2] {
                    let mut len = 3;
                    while len < MAX_MATCH {
                        if w[s + len] != prev {
                            break;
                        }
                        len += 1;
                    }
                    // the C loop compares positions 3..=258, stopping at the first mismatch
                    self.match_length = len.min(MAX_MATCH);
                    if self.match_length > self.lookahead {
                        self.match_length = self.lookahead;
                    }
                }
            }
            let bflush;
            if self.match_length >= MIN_MATCH {
                bflush = self.tally_dist(1, self.match_length - MIN_MATCH);
                self.lookahead -= self.match_length;
                self.strstart += self.match_length;
                self.match_length = 0;
            } else {
                bflush = self.tally_lit(self.window[self.strstart]);
                self.lookahead -= 1;
                self.strstart += 1;
            }
            if bflush {
                self.flush_block_only(io, false);
                if io.out.avail_out() == 0 {
                    return BlockState::NeedMore;
                }
            }
        }
        self.insert = 0;
        self.finish_block(io, flush)
    }

    fn deflate_huff<S: Sink>(&mut self, io: &mut Io<S>, flush: i32) -> BlockState {
        loop {
            if self.lookahead == 0 {
                self.fill_window(io);
                if self.lookahead == 0 {
                    if flush == Z_NO_FLUSH {
                        return BlockState::NeedMore;
                    }
                    break;
                }
            }
            self.match_length = 0;
            let bflush = self.tally_lit(self.window[self.strstart]);
            self.lookahead -= 1;
            self.strstart += 1;
            if bflush {
                self.flush_block_only(io, false);
                if io.out.avail_out() == 0 {
                    return BlockState::NeedMore;
                }
            }
        }
        self.insert = 0;
        self.finish_block(io, flush)
    }

    // --- trees.c -----------------------------------------------------------------------------

    fn init_block(&mut self) {
        for n in 0..L_CODES {
            self.dyn_ltree[n].fc = 0;
        }
        for n in 0..D_CODES {
            self.dyn_dtree[n].fc = 0;
        }
        for n in 0..BL_CODES {
            self.bl_tree[n].fc = 0;
        }
        self.dyn_ltree[END_BLOCK].fc = 1;
        self.hp.opt_len = 0;
        self.hp.static_len = 0;
        self.sym_next = 0;
    }

    fn build_bl_tree(&mut self) -> usize {
        scan_tree(&mut self.bl_tree, &mut self.dyn_ltree, self.l_max_code);
        scan_tree(&mut self.bl_tree, &mut self.dyn_dtree, self.d_max_code);
        self.hp.build_tree(&mut self.bl_tree, &STATIC_BL_DESC);
        let mut max_blindex = BL_CODES - 1;
        while max_blindex >= 3 {
            if self.bl_tree[BL_ORDER[max_blindex] as usize].dl != 0 {
                break;
            }
            max_blindex -= 1;
        }
        self.hp.opt_len = self.hp.opt_len.wrapping_add(3 * (max_blindex as u64 + 1) + 5 + 5 + 4);
        max_blindex
    }

    fn send_tree(&mut self, which_d: bool, max_code: usize) {
        let tree: &[Ct] = if which_d { &self.dyn_dtree } else { &self.dyn_ltree };
        let bl = &self.bl_tree;
        let p = &mut self.pend;
        let mut prevlen: i32 = -1;
        let mut nextlen = tree[0].dl as i32;
        let mut count = 0i32;
        let mut max_count = 7;
        let mut min_count = 4;
        if nextlen == 0 {
            max_count = 138;
            min_count = 3;
        }
        for n in 0..=max_code {
            let curlen = nextlen;
            nextlen = tree[n + 1].dl as i32;
            count += 1;
            if count < max_count && curlen == nextlen {
                continue;
            } else if count < min_count {
                loop {
                    p.send_code(curlen as usize, bl);
                    count -= 1;
                    if count == 0 {
                        break;
                    }
                }
            } else if curlen != 0 {
                if curlen != prevlen {
                    p.send_code(curlen as usize, bl);
                    count -= 1;
                }
                p.send_code(REP_3_6, bl);
                p.send_bits((count - 3) as u32, 2);
            } else if count <= 10 {
                p.send_code(REPZ_3_10, bl);
                p.send_bits((count - 3) as u32, 3);
            } else {
                p.send_code(REPZ_11_138, bl);
                p.send_bits((count - 11) as u32, 7);
            }
            count = 0;
            prevlen = curlen;
            if nextlen == 0 {
                max_count = 138;
                min_count = 3;
            } else if curlen == nextlen {
                max_count = 6;
                min_count = 3;
            } else {
                max_count = 7;
                min_count = 4;
            }
        }
    }

    fn send_all_trees(&mut self, lcodes: usize, dcodes: usize, blcodes: usize) {
        self.pend.send_bits((lcodes - 257) as u32, 5);
        self.pend.send_bits((dcodes - 1) as u32, 5);
        self.pend.send_bits((blcodes - 4) as u32, 4);
        for rank in 0..blcodes {
            let len = self.bl_tree[BL_ORDER[rank] as usize].dl as u32;
            self.pend.send_bits(len, 3);
        }
        self.send_tree(false, lcodes - 1);
        self.send_tree(true, dcodes - 1);
    }

    /// `_tr_stored_block(s, window + buf, stored_len, last)`.
    fn tr_stored_block(&mut self, buf: usize, stored_len: usize, last: bool) {
        self.pend.reserve(stored_len + 16);
        self.pend.send_bits((STORED_BLOCK << 1) + last as u32, 3);
        self.pend.windup();
        self.pend.put_short(stored_len as u16);
        self.pend.put_short(!(stored_len as u16));
        if stored_len != 0 {
            let e = self.pend.end;
            self.pend.buf[e..e + stored_len].copy_from_slice(&self.window[buf..buf + stored_len]);
            self.pend.end += stored_len;
        }
    }

    fn tr_align(&mut self) {
        self.pend.reserve(16);
        self.pend.send_bits(STATIC_TREES << 1, 3);
        self.pend.send_code(END_BLOCK, &TABLES.static_ltree);
        self.pend.flush_bits();
    }

    fn compress_block(&mut self, dynamic: bool) {
        let ltree: &[Ct] = if dynamic { &self.dyn_ltree } else { &TABLES.static_ltree };
        let dtree: &[Ct] = if dynamic { &self.dyn_dtree } else { &TABLES.static_dtree };
        let n = self.sym_next;
        let p = &mut self.pend;
        for sx in 0..n {
            let dist = self.d_buf[sx] as usize;
            let lc = self.l_buf[sx] as usize;
            if dist == 0 {
                p.send_code(lc, ltree);
            } else {
                let code = TABLES.length_code[lc] as usize;
                p.send_code(code + LITERALS + 1, ltree);
                let extra = EXTRA_LBITS[code] as u32;
                if extra != 0 {
                    p.send_bits((lc - TABLES.base_length[code] as usize) as u32, extra);
                }
                let dist = dist - 1;
                let code = d_code(dist);
                p.send_code(code, dtree);
                let extra = EXTRA_DBITS[code] as u32;
                if extra != 0 {
                    p.send_bits((dist - TABLES.base_dist[code] as usize) as u32, extra);
                }
            }
        }
        p.send_code(END_BLOCK, ltree);
    }

    fn tr_flush_block(&mut self, buf: Option<usize>, stored_len: u64, last: bool) {
        let mut opt_lenb;
        let static_lenb;
        let mut max_blindex = 0;
        if self.level > 0 {
            self.l_max_code = self.hp.build_tree(&mut self.dyn_ltree, &STATIC_L_DESC);
            self.d_max_code = self.hp.build_tree(&mut self.dyn_dtree, &STATIC_D_DESC);
            max_blindex = self.build_bl_tree();
            opt_lenb = self.hp.opt_len.wrapping_add(3 + 7) >> 3;
            static_lenb = self.hp.static_len.wrapping_add(3 + 7) >> 3;
            if static_lenb <= opt_lenb || self.strategy == Z_FIXED {
                opt_lenb = static_lenb;
            }
        } else {
            opt_lenb = stored_len + 5;
            static_lenb = opt_lenb;
        }
        // Room for whatever gets emitted: every symbol is at most 48 bits, the trees < 1 KiB.
        self.pend.reserve(self.sym_next * 6 + 1024);
        if stored_len + 4 <= opt_lenb && buf.is_some() {
            self.tr_stored_block(buf.unwrap_or(0), stored_len as usize, last);
        } else if static_lenb == opt_lenb {
            self.pend.send_bits((STATIC_TREES << 1) + last as u32, 3);
            self.compress_block(false);
        } else {
            self.pend.send_bits((DYN_TREES << 1) + last as u32, 3);
            self.send_all_trees(self.l_max_code + 1, self.d_max_code + 1, max_blindex + 1);
            self.compress_block(true);
        }
        self.init_block();
        if last {
            self.pend.windup();
        }
    }
}

#[inline(always)]
fn rd16(w: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([w[i], w[i + 1]])
}

#[inline(always)]
fn rd64(w: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(w[i..i + 8].try_into().unwrap())
}

/// Length of the match between `a` and `b` as zlib's longest_match computes it: bytes 0 and 1
/// are known equal, byte 2 is not compared, the result is the index of the first difference
/// in 3..=258, or 258.
#[inline(always)]
fn match_len(w: &[u8], a: usize, b: usize) -> usize {
    let mut len = 3;
    while len < 259 {
        let x = rd64(w, a + len) ^ rd64(w, b + len);
        if x != 0 {
            return len + (x.trailing_zeros() / 8) as usize;
        }
        len += 8;
    }
    MAX_MATCH
}

// ---------------------------------------------------------------------------------------------
// One-shot helpers

/// python's `zlib.compress(data, level)` (`deflateInit2(level, Z_DEFLATED, 15, 8, 0)` + one
/// `deflate(Z_FINISH)`). Byte-identical for levels 1-9 (and -1); level 0 splits stored blocks
/// by an unbounded output buffer, python by its growing output buffer blocks.
pub fn compress(data: &[u8], level: i32) -> Vec<u8> {
    compress2(data, level, 15, DEF_MEM_LEVEL, Z_DEFAULT_STRATEGY)
}

/// All of `data` compressed with `deflateInit2(level, Z_DEFLATED, window_bits, mem_level,
/// strategy)` and a single unbounded `deflate(Z_FINISH)`. Invalid parameters give an empty Vec.
pub fn compress2(data: &[u8], level: i32, window_bits: i32, mem_level: i32, strategy: i32) -> Vec<u8> {
    let Some(mut d) = Deflater::new(level, window_bits, mem_level, strategy) else { return Vec::new() };
    let mut out = Vec::with_capacity(data.len() / 2 + 64);
    d.deflate_vec(data, &mut out, Z_FINISH);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xorshift(s: &mut u64) -> u64 {
        *s ^= *s << 13;
        *s ^= *s >> 7;
        *s ^= *s << 17;
        *s
    }

    /// Data with every kind of structure: text-like runs, repeats at all distances, noise.
    pub(crate) fn mixed(n: usize, seed: u64) -> Vec<u8> {
        let mut s = seed | 1;
        let mut v = Vec::with_capacity(n);
        let words: [&[u8]; 8] = [b"the ", b"quick ", b"brown ", b"fox ", b"jumps ", b"over ", b"lazy ", b"dog\n"];
        while v.len() < n {
            let r = xorshift(&mut s);
            match r % 6 {
                0 => {
                    for _ in 0..(r >> 8) % 40 {
                        v.extend_from_slice(words[(xorshift(&mut s) % 8) as usize]);
                    }
                }
                1 if v.len() > 10 => {
                    let d = 1 + ((r >> 8) as usize % v.len().min(40000));
                    let l = 3 + (r >> 32) as usize % 300;
                    for _ in 0..l {
                        let b = v[v.len() - d];
                        v.push(b);
                    }
                }
                2 => {
                    for _ in 0..(r >> 8) % 500 {
                        v.push(xorshift(&mut s) as u8);
                    }
                }
                3 => v.extend(std::iter::repeat_n((r >> 16) as u8, ((r >> 24) % 1000) as usize)),
                _ => {
                    for i in 0..(r >> 8) % 200 {
                        v.push((i as u8).wrapping_mul(3) ^ (r >> 40) as u8);
                    }
                }
            }
        }
        v.truncate(n);
        v
    }

    /// Replays one oracle case exactly like `zlib_exact_ref oracle` does.
    fn replay(p: (i32, i32, i32, i32), outchunk: usize, script: &[(Option<usize>, i32)], input: &[u8]) -> (String, Vec<u8>) {
        use std::fmt::Write;
        let mut trace = String::new();
        let mut out = Vec::new();
        let Some(mut d) = Deflater::new(p.0, p.1, p.2, p.3) else {
            return ("init -2\n".to_string(), out);
        };
        let mut obuf = vec![0u8; outchunk];
        let mut pos = 0usize;
        let mut calls = 0u64;
        for &(len, flush) in script {
            let len = len.unwrap_or(input.len() - pos).min(input.len() - pos);
            let mut chunk = &input[pos..pos + len];
            loop {
                let (ret, c, prod) = d.deflate(chunk, &mut obuf, flush);
                writeln!(trace, "{ret} {c} {prod}").unwrap();
                out.extend_from_slice(&obuf[..prod]);
                chunk = &chunk[c..];
                let more = (prod == outchunk || (flush == Z_FINISH && ret == Z_OK)) && ret != Z_STREAM_ERROR;
                calls += 1;
                if !more || calls >= 1_000_000 {
                    break;
                }
            }
            pos += len - chunk.len();
        }
        (trace, out)
    }

    fn fib_data(n: usize, seed: u64) -> Vec<u8> {
        // Literal frequencies following the Fibonacci sequence: optimal Huffman codes deeper
        // than 15 bits, exercising gen_bitlen's overflow fix-up.
        let mut s = seed | 1;
        let mut v = Vec::with_capacity(n);
        while v.len() < n {
            let mut block = Vec::new();
            let (mut a, mut b) = (1usize, 1usize);
            for sym in 0..20u8 {
                block.extend(std::iter::repeat_n(sym.wrapping_mul(37), a));
                let c = a + b;
                a = b;
                b = c;
            }
            for i in (1..block.len()).rev() {
                let j = (xorshift(&mut s) % (i as u64 + 1)) as usize;
                block.swap(i, j);
            }
            v.extend_from_slice(&block);
        }
        v.truncate(n);
        v
    }

    fn oracle_inputs() -> Vec<(&'static str, Vec<u8>)> {
        let mut s = 99u64;
        let mut noise = vec![0u8; 200_000];
        for b in noise.iter_mut() {
            *b = xorshift(&mut s) as u8;
        }
        let mut chains = Vec::new();
        for i in 0..400_000usize {
            chains.push(if i % 7 == 0 { (i / 7) as u8 } else { b'a' + (i % 3 == 0) as u8 });
        }
        let mut runs = Vec::new();
        while runs.len() < 300_000 {
            let r = xorshift(&mut s);
            runs.extend(std::iter::repeat_n(r as u8 & 7, 1 + (r >> 8) as usize % 700));
        }
        let mut img = Vec::new();
        for y in 0..600usize {
            img.push((y % 5) as u8);
            for x in 0..1024usize {
                img.push(((x * 3 + y) / 7) as u8);
                img.push((x ^ y) as u8 & 0x0f);
                img.push(if (x / 16 + y / 16) % 2 == 0 { 0 } else { 1 });
                img.push(0);
            }
        }
        let mut two = vec![0u8; 250_000];
        for b in two.iter_mut() {
            *b = (xorshift(&mut s) & 1) as u8;
        }
        vec![
            ("empty", Vec::new()),
            ("one", vec![b'x']),
            ("two", b"ab".to_vec()),
            ("tiny", b"hello hello hello hello, world".to_vec()),
            ("mixed5k", mixed(5_000, 1)),
            ("mixed64k", mixed(65_536 + 123, 2)),
            ("mixed300k", mixed(300_000, 3)),
            ("mixed1m5", mixed(1_500_000, 4)),
            ("noise200k", noise),
            ("zeros500k", vec![0; 500_000]),
            ("chains400k", chains),
            ("runs300k", runs),
            ("img600", img),
            ("twosym250k", two),
            ("fib300k", fib_data(300_000, 5)),
        ]
    }

    /// Differential test against the system zlib through `bench/refbench/zlib_exact_ref.c`:
    ///
    /// ```text
    /// gcc -O3 -o target/zlib_exact_ref bench/refbench/zlib_exact_ref.c -lz
    /// ZLIB_EXACT_CASES=2000 cargo test --profile fast zlib_exact_oracle -- --ignored --nocapture
    /// ```
    /// Random (seeded) parameter sets x input chunking x flush sequences x output buffer
    /// sizes; both the compressed bytes and the (ret, consumed, produced) of every deflate()
    /// call must match.
    #[test]
    #[ignore]
    fn zlib_exact_oracle() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let refbin = std::env::var("ZLIB_EXACT_REF")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| root.join("target/zlib_exact_ref"));
        let dir = std::env::var("ZLIB_EXACT_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| root.join("testdata/zlib_exact"));
        let ncases: usize = std::env::var("ZLIB_EXACT_CASES").ok().and_then(|s| s.parse().ok()).unwrap_or(400);
        let seed: u64 = std::env::var("ZLIB_EXACT_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(12345);
        std::fs::create_dir_all(&dir).unwrap();
        let inputs = oracle_inputs();
        for (name, data) in &inputs {
            std::fs::write(dir.join(format!("{name}.bin")), data).unwrap();
        }
        // Fixed cases first: every level x strategy for the Pillow-like row feeding, plus the
        // one-shot python defaults.
        let mut cases = Vec::new();
        for level in -1..=9 {
            for strategy in 0..=4 {
                cases.push((12usize, (level, 15, 9, strategy), 65536usize, "4097r".to_string()));
                cases.push((6usize, (level, 15, 8, strategy), 1 << 22, "*:4".to_string()));
            }
        }
        let mut s = seed;
        let wbits = [8, 9, 10, 11, 12, 13, 14, 15, 15, 15, -9, -15, -15, 24, 31, 31, 16, 7, 32];
        let outs = [1usize, 2, 3, 7, 64, 300, 4096, 65536, 65536, 1 << 22];
        let rows = [1usize, 3, 64, 1001, 4097, 7681, 65536];
        while cases.len() < ncases {
            let r = xorshift(&mut s);
            let input = (r % inputs.len() as u64) as usize;
            let level = (xorshift(&mut s) % 12) as i32 - 1; // -1..=10
            let wb = wbits[(xorshift(&mut s) % wbits.len() as u64) as usize];
            let mem = (xorshift(&mut s) % 10) as i32; // 0..=9 (0 is invalid)
            let strategy = (xorshift(&mut s) % 6) as i32 - (xorshift(&mut s) % 20 == 0) as i32;
            let big = inputs[input].1.len() > 70_000;
            let mut outchunk = outs[(xorshift(&mut s) % outs.len() as u64) as usize];
            if big && outchunk < 64 {
                outchunk = 4096;
            }
            let script = match xorshift(&mut s) % 4 {
                0 => "*:4".to_string(),
                1 => format!("{}r", rows[(xorshift(&mut s) % rows.len() as u64) as usize]),
                _ => {
                    let mut sc = Vec::new();
                    let n = inputs[input].1.len();
                    let mut fed = 0;
                    while fed < n && sc.len() < 200 {
                        let len = (xorshift(&mut s) % (n as u64 / 8 + 2)) as usize;
                        let flush = [0, 0, 0, 0, 1, 2, 3, 5, 0][(xorshift(&mut s) % 9) as usize];
                        sc.push(format!("{len}:{flush}"));
                        fed += len;
                    }
                    sc.push("*:4".into());
                    if xorshift(&mut s) % 4 == 0 {
                        sc.push("0:4".into());
                    }
                    sc.join(",")
                }
            };
            cases.push((input, (level, wb, mem, strategy), outchunk, script));
        }
        let expand = |spec: &str, n: usize| -> String {
            if let Some(k) = spec.strip_suffix('r') {
                let k: usize = k.parse().unwrap();
                let mut v: Vec<String> = (0..n.div_ceil(k)).map(|_| format!("{k}:0")).collect();
                v.push("0:4".into());
                v.join(",")
            } else {
                spec.to_string()
            }
        };
        let next = std::sync::atomic::AtomicUsize::new(0);
        let failures = std::sync::Mutex::new(Vec::new());
        let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).min(8);
        std::thread::scope(|sc| {
            for t in 0..threads {
                let (cases, inputs, dir, refbin, next, failures) = (&cases, &inputs, &dir, &refbin, &next, &failures);
                let expand = &expand;
                sc.spawn(move || {
                    loop {
                        let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if i >= cases.len() {
                            break;
                        }
                        let (input, p, outchunk, spec) = &cases[i];
                        let (name, data) = &inputs[*input];
                        let script_s = expand(spec, data.len());
                        let script: Vec<(Option<usize>, i32)> = script_s
                            .split(',')
                            .map(|st| {
                                let (l, f) = st.split_once(':').unwrap();
                                (if l == "*" { None } else { Some(l.parse().unwrap()) }, f.parse().unwrap())
                            })
                            .collect();
                        let outfile = dir.join(format!("out{t}.z"));
                        let _ = std::fs::remove_file(&outfile);
                        let res = std::process::Command::new(refbin)
                            .args(["oracle", &p.0.to_string(), &p.1.to_string(), &p.2.to_string(), &p.3.to_string()])
                            .arg(outchunk.to_string())
                            .arg(spec)
                            .arg(dir.join(format!("{name}.bin")))
                            .arg(&outfile)
                            .output()
                            .expect("run zlib_exact_ref (build it first, see the doc comment)");
                        let want_trace = String::from_utf8_lossy(&res.stdout).to_string();
                        let want = std::fs::read(&outfile).unwrap_or_default();
                        let (trace, got) = replay(*p, *outchunk, &script, data);
                        if trace != want_trace || got != want {
                            let at = got.iter().zip(&want).position(|(a, b)| a != b).unwrap_or(got.len().min(want.len()));
                            let msg = format!(
                                "case {i}: {name} params {p:?} outchunk {outchunk} script {}: got {} bytes want {} (first diff at {at}), trace {}",
                                if spec.len() > 60 { &spec[..60] } else { spec },
                                got.len(),
                                want.len(),
                                if trace == want_trace { "same" } else { "DIFFERS" }
                            );
                            eprintln!("{msg}");
                            failures.lock().unwrap().push(msg);
                        }
                    }
                });
            }
        });
        let failures = failures.into_inner().unwrap();
        println!("zlib_exact_oracle: {} cases, {} failures", cases.len(), failures.len());
        assert!(failures.is_empty());
    }

    /// Throughput harness matching `zlib_exact_ref bench` (bench/refbench/zlib_exact_run.sh):
    /// ZX_FILE, ZX_PARAMS="level,wbits,memlevel,strategy", ZX_ROWLEN (0 = one deflate(Z_FINISH)
    /// call, else ROWLEN-byte Z_NO_FLUSH calls then Z_FINISH), ZX_RUNS. Prints
    /// "rust zlib_exact LEVEL FILE IN_BYTES OUT_BYTES BEST_MS MB/s".
    #[test]
    #[ignore]
    fn zlib_exact_bench() {
        let Ok(path) = std::env::var("ZX_FILE") else {
            eprintln!("set ZX_FILE");
            return;
        };
        let p: Vec<i32> = std::env::var("ZX_PARAMS")
            .unwrap_or_else(|_| "6,15,8,0".into())
            .split(',')
            .map(|s| s.parse().unwrap())
            .collect();
        let rowlen: usize = std::env::var("ZX_ROWLEN").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
        let runs: usize = std::env::var("ZX_RUNS").ok().and_then(|s| s.parse().ok()).unwrap_or(5);
        let data = std::fs::read(&path).unwrap();
        let mut best = f64::MAX;
        let mut outlen = 0;
        let mut out = Vec::with_capacity(data.len() + data.len() / 8 + 4096);
        for _ in 0..runs {
            out.clear();
            let t = std::time::Instant::now();
            let mut d = Deflater::new(p[0], p[1], p[2], p[3]).unwrap();
            if rowlen > 0 {
                for row in data.chunks(rowlen) {
                    d.deflate_vec(row, &mut out, Z_NO_FLUSH);
                }
                assert_eq!(d.deflate_vec(&[], &mut out, Z_FINISH), Z_STREAM_END);
            } else {
                assert_eq!(d.deflate_vec(&data, &mut out, Z_FINISH), Z_STREAM_END);
            }
            let dt = t.elapsed().as_secs_f64();
            best = best.min(dt);
            outlen = out.len();
        }
        println!(
            "rust zlib_exact {} {} {} {} {:.3} {:.1}",
            p[0],
            path,
            data.len(),
            outlen,
            best * 1e3,
            data.len() as f64 / best / 1e6
        );
    }

    // python: zlib.compress(b"", 6), zlib.compress(b"a", 6), zlib.compress(b"hello hello hello hello", 9)
    #[test]
    fn tiny_vectors() {
        assert_eq!(compress(b"", 6), [0x78, 0x9c, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01]);
        assert_eq!(compress(b"a", 6), [0x78, 0x9c, 0x4b, 0x04, 0x00, 0x00, 0x62, 0x00, 0x62]);
        assert_eq!(
            compress(b"hello hello hello hello", 9),
            [0x78, 0xda, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0xc8, 0x40, 0x27, 0x01, 0x68, 0x03, 0x08, 0xb1]
        );
    }

    #[test]
    fn roundtrip_all_levels_strategies() {
        let data = mixed(300_000, 7);
        for level in 0..=9 {
            for strategy in 0..=4 {
                for (wbits, mem) in [(15, 8), (15, 9), (9, 1), (12, 4)] {
                    let z = compress2(&data, level, wbits, mem, strategy);
                    let back = super::super::zlib::decompress(&z).unwrap();
                    assert!(back == data, "level {level} strategy {strategy} wbits {wbits} mem {mem}");
                }
            }
        }
    }

    #[test]
    fn bounded_output_matches_unbounded() {
        let data = mixed(200_000, 11);
        for level in 1..=9 {
            let want = compress2(&data, level, 15, 9, Z_FILTERED);
            let mut d = Deflater::new(level, 15, 9, Z_FILTERED).unwrap();
            let mut got = Vec::new();
            let mut buf = [0u8; 777];
            for row in data.chunks(1001) {
                let mut rest = row;
                loop {
                    let (ret, c, p) = d.deflate(rest, &mut buf, Z_NO_FLUSH);
                    assert_eq!(ret, Z_OK);
                    got.extend_from_slice(&buf[..p]);
                    rest = &rest[c..];
                    if p < buf.len() && rest.is_empty() {
                        break;
                    }
                }
            }
            loop {
                let (ret, _, p) = d.deflate(&[], &mut buf, Z_FINISH);
                got.extend_from_slice(&buf[..p]);
                if ret == Z_STREAM_END {
                    break;
                }
                assert_eq!(ret, Z_OK);
            }
            // Row-wise input differs from one-shot input only through the window slide timing,
            // so compare against a row-wise unbounded run.
            let mut d2 = Deflater::new(level, 15, 9, Z_FILTERED).unwrap();
            let mut want2 = Vec::new();
            for row in data.chunks(1001) {
                d2.deflate_vec(row, &mut want2, Z_NO_FLUSH);
            }
            d2.deflate_vec(&[], &mut want2, Z_FINISH);
            assert!(got == want2, "level {level}");
            assert_eq!(super::super::zlib::decompress(&want).unwrap(), data);
        }
    }
}
