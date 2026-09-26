//! `.xz` container decoder.
//!
//! Supports multiple streams (with stream padding), multiple blocks, the LZMA2 filter with
//! optional x86 BCJ / delta pre-filters, and CRC32 / CRC64 integrity checks (SHA-256 and
//! other check types are skipped without verification).
//!
//! Decoding runs in two passes:
//! 1. a structural scan that validates headers, index and footer and walks the LZMA2 chunk
//!    headers of every block (no decoding), which yields the exact uncompressed layout;
//! 2. decoding every block straight into its slice of one exactly-sized output buffer —
//!    in parallel when a file has several blocks (e.g. produced by `xz -T0`).

use super::crc::{crc32, crc64};
use super::lzma::{lzma2_decode_into, lzma2_scan};
use crate::error::{Error, Result};

const HEADER_MAGIC: [u8; 6] = [0xFD, b'7', b'z', b'X', b'Z', 0x00];
const FOOTER_MAGIC: [u8; 2] = [b'Y', b'Z'];

const FILTER_DELTA: u64 = 0x03;
const FILTER_X86: u64 = 0x04;
const FILTER_LZMA2: u64 = 0x21;

/// Minimum total output before multi-block files are decoded on several threads.
const PARALLEL_MIN_BYTES: usize = 1 << 20;

fn err(what: &str) -> Error {
    Error::Msg(format!("xz: {what}"))
}

/// Returns true if `data` starts with the `.xz` magic.
pub fn is_xz(data: &[u8]) -> bool {
    data.starts_with(&HEADER_MAGIC)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Filter {
    Delta { dist: usize },
    X86 { start: u32 },
}

#[derive(Debug, Clone)]
struct Block {
    header_size: usize,
    /// Range of LZMA2 data in the input.
    data_start: usize,
    data_end: usize,
    /// Integrity check location and type.
    check_start: usize,
    check_type: u8,
    /// Pre-filters applied before LZMA2 when compressing (in chain order), at most 3.
    filters: [Option<Filter>; 3],
    out_start: usize,
    out_len: usize,
}

/// Size in bytes of the check field for a check type id.
fn check_size(check: u8) -> usize {
    match check {
        0 => 0,
        1..=3 => 4,
        4..=6 => 8,
        7..=9 => 16,
        10..=12 => 32,
        _ => 64,
    }
}

/// Reads an xz variable-length integer at `*off`.
fn read_vli(buf: &[u8], off: &mut usize) -> Result<u64> {
    let mut v = 0u64;
    for i in 0..9 {
        let b = *buf.get(*off).ok_or_else(|| err("truncated integer"))?;
        *off += 1;
        v |= ((b & 0x7F) as u64) << (7 * i);
        if b & 0x80 == 0 {
            if b == 0 && i > 0 {
                return Err(err("non-minimal integer encoding"));
            }
            return Ok(v);
        }
    }
    Err(err("integer too long"))
}

/// Parses stream flags (2 bytes) returning the check type.
fn parse_stream_flags(f: &[u8]) -> Result<u8> {
    if f[0] != 0 || f[1] & 0xF0 != 0 {
        return Err(err("unsupported stream flags"));
    }
    Ok(f[1] & 0x0F)
}

struct BlockHeader {
    size: usize,
    compressed: Option<u64>,
    uncompressed: Option<u64>,
    filters: [Option<Filter>; 3],
}

fn parse_block_header(data: &[u8], off: usize) -> Result<BlockHeader> {
    let size = (data[off] as usize + 1) * 4;
    let h = data.get(off..off + size).ok_or_else(|| err("truncated block header"))?;
    let stored_crc = u32::from_le_bytes(h[size - 4..].try_into().unwrap());
    if crc32(&h[..size - 4]) != stored_crc {
        return Err(err("block header CRC mismatch"));
    }
    let body = &h[..size - 4];
    let flags = body[1];
    if flags & 0x3C != 0 {
        return Err(err("unsupported block flags"));
    }
    let nfilters = (flags & 3) as usize + 1;
    let mut p = 2usize;
    let compressed = if flags & 0x40 != 0 { Some(read_vli(body, &mut p)?) } else { None };
    let uncompressed = if flags & 0x80 != 0 { Some(read_vli(body, &mut p)?) } else { None };
    if compressed == Some(0) {
        return Err(err("zero compressed size"));
    }
    let mut filters = [None; 3];
    for i in 0..nfilters {
        let id = read_vli(body, &mut p)?;
        let psize = read_vli(body, &mut p)? as usize;
        let props = body.get(p..p.saturating_add(psize)).ok_or_else(|| err("truncated filter properties"))?;
        p += psize;
        let last = i + 1 == nfilters;
        match id {
            FILTER_LZMA2 if last => {
                if psize != 1 || props[0] > 40 {
                    return Err(err("invalid LZMA2 properties"));
                }
            }
            FILTER_DELTA if !last => {
                if psize != 1 {
                    return Err(err("invalid delta properties"));
                }
                filters[i] = Some(Filter::Delta { dist: props[0] as usize + 1 });
            }
            FILTER_X86 if !last => {
                let start = match psize {
                    0 => 0,
                    4 => u32::from_le_bytes(props.try_into().unwrap()),
                    _ => return Err(err("invalid x86 filter properties")),
                };
                filters[i] = Some(Filter::X86 { start });
            }
            _ => return Err(err(&format!("unsupported filter chain (filter id {id:#x})"))),
        }
    }
    if body[p..].iter().any(|&b| b != 0) {
        return Err(err("non-zero block header padding"));
    }
    Ok(BlockHeader { size, compressed, uncompressed, filters })
}

/// Structural scan of the whole file. Returns the blocks and the total output size.
fn scan(data: &[u8]) -> Result<(Vec<Block>, usize)> {
    let mut blocks: Vec<Block> = Vec::new();
    let mut out_total = 0usize;
    let mut off = 0usize;
    let mut streams = 0usize;
    loop {
        // ---- stream header ----
        if data.len() < off + 12 || data[off..off + 6] != HEADER_MAGIC {
            if streams == 0 {
                return Err(err("not an xz file"));
            }
            break; // trailing garbage is ignored (like python's lzma module)
        }
        let hdr = &data[off..off + 12];
        if crc32(&hdr[6..8]) != u32::from_le_bytes(hdr[8..12].try_into().unwrap()) {
            return Err(err("stream header CRC mismatch"));
        }
        let check_type = parse_stream_flags(&hdr[6..8])?;
        let csize = check_size(check_type);
        off += 12;

        // ---- blocks ----
        let first_block = blocks.len();
        loop {
            let b = *data.get(off).ok_or_else(|| err("truncated stream"))?;
            if b == 0 {
                break; // index indicator
            }
            let bh = parse_block_header(data, off)?;
            let data_start = off + bh.size;
            let (comp_len, uncomp) = lzma2_scan(&data[data_start..])?;
            if bh.compressed.is_some_and(|c| c != comp_len as u64) {
                return Err(err("block compressed size mismatch"));
            }
            if bh.uncompressed.is_some_and(|u| u != uncomp) {
                return Err(err("block uncompressed size mismatch"));
            }
            let data_end = data_start + comp_len;
            let pad = (4 - comp_len % 4) % 4;
            let padding = data.get(data_end..data_end + pad).ok_or_else(|| err("truncated block"))?;
            if padding.iter().any(|&b| b != 0) {
                return Err(err("non-zero block padding"));
            }
            let check_start = data_end + pad;
            if data.len() < check_start + csize {
                return Err(err("truncated block check"));
            }
            let out_len = usize::try_from(uncomp).map_err(|_| err("block too large"))?;
            blocks.push(Block {
                header_size: bh.size,
                data_start,
                data_end,
                check_start,
                check_type,
                filters: bh.filters,
                out_start: out_total,
                out_len,
            });
            out_total = out_total.checked_add(out_len).ok_or_else(|| err("output too large"))?;
            off = check_start + csize;
        }

        // ---- index ----
        let index_start = off;
        off += 1;
        let count = read_vli(data, &mut off)?;
        let stream_blocks = &blocks[first_block..];
        if count != stream_blocks.len() as u64 {
            return Err(err("index block count mismatch"));
        }
        for blk in stream_blocks {
            let unpadded = read_vli(data, &mut off)?;
            let uncompressed = read_vli(data, &mut off)?;
            // Unpadded size = block header + compressed data + check.
            let expect = (blk.header_size + (blk.data_end - blk.data_start) + csize) as u64;
            if unpadded != expect || uncompressed != blk.out_len as u64 {
                return Err(err("index record mismatch"));
            }
        }
        while (off - index_start) % 4 != 0 {
            if *data.get(off).ok_or_else(|| err("truncated index"))? != 0 {
                return Err(err("non-zero index padding"));
            }
            off += 1;
        }
        let crc_bytes = data.get(off..off + 4).ok_or_else(|| err("truncated index"))?;
        if crc32(&data[index_start..off]) != u32::from_le_bytes(crc_bytes.try_into().unwrap()) {
            return Err(err("index CRC mismatch"));
        }
        off += 4;
        let index_size = off - index_start;

        // ---- stream footer ----
        let f = data.get(off..off + 12).ok_or_else(|| err("truncated stream footer"))?;
        if f[10..12] != FOOTER_MAGIC {
            return Err(err("bad stream footer magic"));
        }
        if crc32(&f[4..10]) != u32::from_le_bytes(f[0..4].try_into().unwrap()) {
            return Err(err("stream footer CRC mismatch"));
        }
        let backward = (u32::from_le_bytes(f[4..8].try_into().unwrap()) as usize + 1) * 4;
        if backward != index_size || f[8..10] != hdr[6..8] {
            return Err(err("stream footer does not match"));
        }
        off += 12;
        streams += 1;

        // ---- stream padding ----
        let mut z = off;
        while z < data.len() && data[z] == 0 {
            z += 1;
        }
        if z == data.len() {
            if (z - off) % 4 != 0 {
                return Err(err("stream padding not a multiple of four"));
            }
            break;
        }
        if (z - off) % 4 != 0 {
            break; // not a valid continuation: ignore trailing garbage
        }
        off = z;
    }
    Ok((blocks, out_total))
}

/// Decodes one block into `out` (exactly the block's uncompressed size) and verifies it.
fn decode_block(data: &[u8], blk: &Block, out: &mut [u8]) -> Result<()> {
    let input = &data[blk.data_start..blk.data_end];
    let used = lzma2_decode_into(input, out)?;
    if used != input.len() {
        return Err(err("block size mismatch"));
    }
    for f in blk.filters.iter().rev().flatten() {
        match *f {
            Filter::Delta { dist } => delta_decode(out, dist),
            Filter::X86 { start } => x86_decode(out, start),
        }
    }
    let check = &data[blk.check_start..blk.check_start + check_size(blk.check_type)];
    match blk.check_type {
        1 => {
            if crc32(out) != u32::from_le_bytes(check.try_into().unwrap()) {
                return Err(err("CRC32 mismatch"));
            }
        }
        4 => {
            if crc64(out) != u64::from_le_bytes(check.try_into().unwrap()) {
                return Err(err("CRC64 mismatch"));
            }
        }
        _ => {} // none / SHA-256 / reserved types: not verified
    }
    Ok(())
}

/// Decompresses a complete `.xz` file (all streams).
pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    let (blocks, total) = scan(data)?;
    let mut out = super::try_zeroed(total)?;
    decode_blocks(data, &blocks, &mut out, true)?;
    Ok(out)
}

/// Uncompressed size of a complete `.xz` file (structural scan only, nothing is decoded).
pub fn uncompressed_size(data: &[u8]) -> Result<usize> {
    Ok(scan(data)?.1)
}

/// [`decompress`] into a caller-owned buffer that is reused across calls (a worker decoding
/// many files faults its pages in once instead of once per file). `buf` grows to the largest
/// output seen and is never shrunk; the output is `buf[..n]` for the returned `n`.
/// `parallel`: decode multi-block files on several threads (false when the caller already
/// runs one decode per core).
pub fn decompress_reuse(data: &[u8], buf: &mut Vec<u8>, parallel: bool) -> Result<usize> {
    let (blocks, total) = scan(data)?;
    if buf.len() < total {
        buf.clear();
        buf.try_reserve_exact(total).map_err(|_| err("output too large"))?;
        super::advise_huge(buf.as_mut_ptr(), buf.capacity());
        buf.resize(total, 0);
    }
    decode_blocks(data, &blocks, &mut buf[..total], parallel)?;
    Ok(total)
}

/// Blocks up to this size are decoded into a per-thread buffer and written with `pwrite`;
/// bigger ones (a single-block file) straight into a writable mapping of the output file.
pub(crate) const FILE_BUF_MAX: usize = 64 << 20;
/// Memory the per-thread buffers may use together (limits the threads for big blocks).
const FILE_BUF_BUDGET: usize = 1 << 30;

/// [`decompress`] into `file` (from offset 0; it is resized to the output size) without
/// holding the output in memory: multi-block files are decoded in parallel, each thread
/// decoding one block at a time into its own buffer and writing it at the block's offset.
/// `file` must be open for reading and writing (blocks over 64 MiB are decoded into a
/// shared mapping of it). Returns the decompressed size.
pub fn decompress_to_file(data: &[u8], file: &std::fs::File) -> Result<u64> {
    decompress_to_file_with(data, file, FILE_BUF_MAX)
}

/// [`decompress_to_file`] with blocks bigger than `buf_max` decoded into a mapping.
pub(crate) fn decompress_to_file_with(data: &[u8], file: &std::fs::File, buf_max: usize) -> Result<u64> {
    use std::os::unix::fs::FileExt;
    let (blocks, total) = scan(data)?;
    let io = |e: std::io::Error| Error::Msg(format!("cannot write the decompressed file: {e}"));
    file.set_len(total as u64).map_err(io)?;
    let biggest = blocks.iter().map(|b| b.out_len).filter(|&n| n <= buf_max).max().unwrap_or(0);
    let avail = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let threads = avail.min(blocks.len()).min((FILE_BUF_BUDGET / biggest.max(1)).max(1)).max(1);
    let next = std::sync::atomic::AtomicUsize::new(0);
    let failed = std::sync::atomic::AtomicBool::new(false);
    let first_err: std::sync::Mutex<Option<Error>> = std::sync::Mutex::new(None);
    let work = || {
        let mut buf: Vec<u8> = Vec::new();
        let r = (|| -> Result<()> {
            loop {
                if failed.load(std::sync::atomic::Ordering::Relaxed) {
                    return Ok(());
                }
                let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let Some(blk) = blocks.get(i) else { return Ok(()) };
                if blk.out_len > buf_max {
                    // map the block's pages (from the page boundary below its start)
                    let a = blk.out_start & !0xfff;
                    let mut map = crate::util::mmap::MmapMut::map(file, a as u64, blk.out_start - a + blk.out_len).map_err(io)?;
                    decode_block(data, blk, &mut map.as_mut_slice()[blk.out_start - a..])?;
                    continue;
                }
                if buf.len() < blk.out_len {
                    buf.clear();
                    buf.try_reserve_exact(blk.out_len).map_err(|_| err("output too large"))?;
                    buf.resize(blk.out_len, 0);
                }
                let out = &mut buf[..blk.out_len];
                decode_block(data, blk, out)?;
                file.write_all_at(out, blk.out_start as u64).map_err(io)?;
            }
        })();
        if let Err(e) = r {
            failed.store(true, std::sync::atomic::Ordering::Relaxed);
            if let Ok(mut fe) = first_err.lock() {
                fe.get_or_insert(e);
            }
        }
    };
    std::thread::scope(|s| {
        for _ in 1..threads {
            if std::thread::Builder::new().spawn_scoped(s, work).is_err() {
                break;
            }
        }
        work();
    });
    if let Some(e) = first_err.into_inner().ok().flatten() {
        return Err(e);
    }
    Ok(total as u64)
}

fn decode_blocks(data: &[u8], blocks: &[Block], out: &mut [u8], parallel: bool) -> Result<()> {
    let total = out.len();
    let threads = if parallel && blocks.len() > 1 && total >= PARALLEL_MIN_BYTES {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1).min(blocks.len())
    } else {
        1
    };
    if threads <= 1 {
        for blk in blocks {
            decode_block(data, blk, &mut out[blk.out_start..blk.out_start + blk.out_len])?;
        }
        return Ok(());
    }

    // Split the output into per-block slices and hand them out to worker threads.
    let mut jobs: Vec<(&Block, &mut [u8])> = Vec::with_capacity(blocks.len());
    let mut rest: &mut [u8] = out;
    for blk in blocks {
        let (head, tail) = std::mem::take(&mut rest).split_at_mut(blk.out_len);
        jobs.push((blk, head));
        rest = tail;
    }
    // Largest blocks first for better balance (the queue pops from the end).
    jobs.sort_by_key(|j| j.1.len());
    let queue = std::sync::Mutex::new(jobs);
    let first_err: std::sync::Mutex<Option<Error>> = std::sync::Mutex::new(None);
    let (q, fe_ref) = (&queue, &first_err);
    let work = move || {
        loop {
            let job = q.lock().ok().and_then(|mut q| q.pop());
            let Some((blk, buf)) = job else { break };
            if let Err(e) = decode_block(data, blk, buf) {
                if let Ok(mut fe) = fe_ref.lock() {
                    fe.get_or_insert(e);
                }
                if let Ok(mut q) = q.lock() {
                    q.clear();
                }
                break;
            }
        }
    };
    std::thread::scope(|s| {
        // Helpers plus the calling thread; if the OS refuses a thread, the others (at least
        // this one) simply take more blocks.
        for _ in 1..threads {
            if std::thread::Builder::new().spawn_scoped(s, work).is_err() {
                break;
            }
        }
        work();
    });
    if let Some(e) = first_err.into_inner().ok().flatten() {
        return Err(e);
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Filters
// ---------------------------------------------------------------------------------------

fn delta_decode(buf: &mut [u8], dist: usize) {
    for i in dist..buf.len() {
        buf[i] = buf[i].wrapping_add(buf[i - dist]);
    }
}

/// First index in `from..end` whose byte is 0xE8 or 0xE9 (CALL/JMP), or `end`. The BCJ
/// state only changes at those bytes, so the filter skips everything else 16 bytes at a
/// time (was a byte loop at ~2 cycles/byte, ~6% of decoding x86 code).
#[inline]
fn next_e8(buf: &[u8], mut from: usize, end: usize) -> usize {
    debug_assert!(end <= buf.len());
    #[cfg(target_arch = "x86_64")]
    {
        use std::arch::x86_64::*;
        // SAFETY: SSE2 is part of x86-64; every load reads 16 bytes below `end`.
        unsafe {
            let fe = _mm_set1_epi8(0xFEu8 as i8);
            let e8 = _mm_set1_epi8(0xE8u8 as i8);
            while from + 16 <= end {
                let v = _mm_loadu_si128(buf.as_ptr().add(from) as *const __m128i);
                let m = _mm_movemask_epi8(_mm_cmpeq_epi8(_mm_and_si128(v, fe), e8)) as u32;
                if m != 0 {
                    return from + m.trailing_zeros() as usize;
                }
                from += 16;
            }
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        // SWAR: bytes b with (b ^ 0xE8) & 0xFE == 0; the lowest flagged byte is exact.
        const LO: u64 = 0x0101_0101_0101_0101;
        while from + 8 <= end {
            let w = u64::from_le_bytes(buf[from..from + 8].try_into().unwrap());
            let y = (w ^ (0xE8 * LO)) & (0xFE * LO);
            let z = y.wrapping_sub(LO) & !y & (0x80 * LO);
            if z != 0 {
                return from + (z.trailing_zeros() / 8) as usize;
            }
            from += 8;
        }
    }
    while from < end && buf[from] & 0xFE != 0xE8 {
        from += 1;
    }
    from
}

/// x86 BCJ decoder over a complete block (converts absolute CALL/JMP targets back to
/// relative ones). `start` is the filter's start offset.
fn x86_decode(buf: &mut [u8], start: u32) {
    const ALLOWED: [bool; 8] = [true, true, true, false, true, false, false, false];
    const BIT_NUM: [u32; 8] = [0, 1, 2, 2, 3, 3, 3, 3];
    #[inline(always)]
    fn test_ms_byte(b: u8) -> bool {
        b == 0 || b == 0xFF
    }
    if buf.len() < 5 {
        return;
    }
    let mut prev_mask: u32 = 0;
    let mut prev_pos: u32 = start.wrapping_sub(5);
    let limit = buf.len() - 5;
    let mut i = 0usize;
    while i <= limit {
        i = next_e8(buf, i, limit + 1);
        if i > limit {
            break;
        }
        let now = start.wrapping_add(i as u32);
        let offset = now.wrapping_sub(prev_pos);
        prev_pos = now;
        if offset > 5 {
            prev_mask = 0;
        } else {
            for _ in 0..offset {
                prev_mask &= 0x77;
                prev_mask <<= 1;
            }
        }
        let b4 = buf[i + 4];
        if test_ms_byte(b4) && ALLOWED[((prev_mask >> 1) & 7) as usize] && (prev_mask >> 1) < 0x10 {
            let mut src = u32::from_le_bytes([buf[i + 1], buf[i + 2], buf[i + 3], b4]);
            let mut dest;
            loop {
                dest = src.wrapping_sub(now.wrapping_add(5));
                if prev_mask == 0 {
                    break;
                }
                let idx = BIT_NUM[(prev_mask >> 1) as usize & 7];
                let bb = (dest >> (24 - idx * 8)) as u8;
                if !test_ms_byte(bb) {
                    break;
                }
                src = dest ^ ((1u32 << (32 - idx * 8)) - 1);
            }
            let d = dest & 0x01FF_FFFF;
            let top = if (dest >> 24) & 1 != 0 { 0xFFu8 } else { 0 };
            buf[i + 1] = d as u8;
            buf[i + 2] = (d >> 8) as u8;
            buf[i + 3] = (d >> 16) as u8;
            buf[i + 4] = top;
            i += 5;
            prev_mask = 0;
        } else {
            i += 1;
            prev_mask |= 1;
            if test_ms_byte(b4) {
                prev_mask |= 0x10;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codecs::lzma;

    // Fixtures generated by testdata/gen_xz.py with xz(1) 5.8 and python's lzma module.
    const TEXT: &[u8] = include_bytes!("testdata/text.json");
    const NOISE: &[u8] = include_bytes!("testdata/noise.bin");
    const X86: &[u8] = include_bytes!("testdata/x86.bin");
    const SAMPLES: &[u8] = include_bytes!("testdata/samples.bin");

    #[test]
    fn codecs_xz_variants() {
        let cases: &[(&str, &[u8], &[u8])] = &[
            ("default", include_bytes!("testdata/text.xz"), TEXT),
            ("-9e", include_bytes!("testdata/text.e9.xz"), TEXT),
            ("multi-block", include_bytes!("testdata/text.blocks.xz"), TEXT),
            ("multi-block, sizes in headers", include_bytes!("testdata/text.mt.xz"), TEXT),
            ("check none", include_bytes!("testdata/text.none.xz"), TEXT),
            ("check crc32", include_bytes!("testdata/text.crc32.xz"), TEXT),
            ("check sha256", include_bytes!("testdata/text.sha256.xz"), TEXT),
            ("lc1 lp3 pb1", include_bytes!("testdata/text.props.xz"), TEXT),
            ("uncompressed chunks", include_bytes!("testdata/noise.xz"), NOISE),
            ("x86 bcj", include_bytes!("testdata/x86.bin.xz"), X86),
            ("delta", include_bytes!("testdata/samples.bin.xz"), SAMPLES),
            ("empty", include_bytes!("testdata/empty.xz"), b""),
        ];
        for (name, xz, want) in cases {
            assert_eq!(decompress(xz).unwrap_or_else(|e| panic!("{name}: {e}")), *want, "{name}");
            assert!(is_xz(xz));
        }
    }

    /// The file decoder writes exactly what `decompress` returns, through buffers and through
    /// mappings (every variant, including multi-block, multi-stream and trailing garbage).
    #[test]
    fn codecs_xz_to_file() {
        let dir = std::env::temp_dir().join(format!("rsvol-xz-file-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut g = include_bytes!("testdata/text.xz").to_vec();
        g.extend_from_slice(b"garbage!");
        let cases: &[&[u8]] = &[
            include_bytes!("testdata/text.xz"),
            include_bytes!("testdata/text.blocks.xz"),
            include_bytes!("testdata/text.mt.xz"),
            include_bytes!("testdata/x86.bin.xz"),
            include_bytes!("testdata/samples.bin.xz"),
            include_bytes!("testdata/multi.xz"),
            include_bytes!("testdata/empty.xz"),
            &g,
        ];
        for (i, xz) in cases.iter().enumerate() {
            let want = decompress(xz).unwrap();
            for buf_max in [0, FILE_BUF_MAX] {
                let p = dir.join(format!("{i}-{buf_max}"));
                // stale longer contents are cut to the output size
                std::fs::write(&p, vec![7u8; want.len() + 100]).unwrap();
                let f = std::fs::OpenOptions::new().read(true).write(true).open(&p).unwrap();
                assert_eq!(decompress_to_file_with(xz, &f, buf_max).unwrap(), want.len() as u64);
                drop(f);
                assert_eq!(std::fs::read(&p).unwrap(), want, "case {i} buf_max {buf_max}");
            }
        }
        let mut bad = include_bytes!("testdata/text.blocks.xz").to_vec();
        let n = bad.len();
        bad[n / 2] ^= 0x40;
        let f = std::fs::File::create(dir.join("bad")).unwrap();
        assert!(decompress_to_file(&bad, &f).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Throughput of [`decompress_to_file`] against decoding alone:
    /// `RSVOL_XZ_BENCH=<file.xz> RSVOL_XZ_BENCH_OUT=<scratch file on disk>`
    /// `cargo test --profile fast codecs_xz_file_throughput -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn codecs_xz_file_throughput() {
        let p = std::env::var("RSVOL_XZ_BENCH").expect("RSVOL_XZ_BENCH");
        let f = std::fs::File::open(&p).unwrap();
        let map = crate::util::mmap::Mmap::map(&f).unwrap();
        let data = map.as_slice();
        let (blocks, total) = scan(data).unwrap();
        let t = std::time::Instant::now();
        let next = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|s| {
            for _ in 0..std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1) {
                s.spawn(|| {
                    let mut buf = Vec::new();
                    loop {
                        let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let Some(b) = blocks.get(i) else { break };
                        buf.resize(buf.len().max(b.out_len), 0);
                        decode_block(data, b, &mut buf[..b.out_len]).unwrap();
                    }
                });
            }
        });
        let d = t.elapsed().as_secs_f64();
        eprintln!("{} blocks, {total} bytes: decode only {d:.3}s = {:.0} MB/s", blocks.len(), total as f64 / d / 1e6);
        let out = std::env::var("RSVOL_XZ_BENCH_OUT").expect("RSVOL_XZ_BENCH_OUT");
        let o = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&out).unwrap();
        let t = std::time::Instant::now();
        decompress_to_file(data, &o).unwrap();
        let d = t.elapsed().as_secs_f64();
        eprintln!("decompress_to_file {d:.3}s = {:.0} MB/s", total as f64 / d / 1e6);
        drop(o);
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn codecs_xz_multi_stream_padding_trailing() {
        let multi = include_bytes!("testdata/multi.xz");
        let mut want = TEXT.to_vec();
        want.extend_from_slice(NOISE);
        assert_eq!(decompress(multi).unwrap(), want);
        // Trailing garbage after a complete stream is ignored (python's lzma module does too).
        let mut g = include_bytes!("testdata/text.xz").to_vec();
        g.extend_from_slice(b"garbage!");
        assert_eq!(decompress(&g).unwrap(), TEXT);
        // Stream padding that is not a multiple of four is an error at end of file.
        let mut p = include_bytes!("testdata/text.xz").to_vec();
        p.extend_from_slice(&[0, 0, 0]);
        assert!(decompress(&p).is_err());
    }

    #[test]
    fn codecs_xz_corruption_detected() {
        let good = include_bytes!("testdata/text.blocks.xz");
        // Truncation anywhere is an error.
        for n in 0..good.len() {
            assert!(decompress(&good[..n]).is_err(), "truncated at {n}");
        }
        // Flipping any single bit is detected (header CRCs, LZMA2 structure, CRC64, index).
        let mut s = 0x1234_5678_9ABC_DEF1u64;
        for _ in 0..3000 {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            let mut v = good.to_vec();
            let i = (s as usize) % v.len();
            v[i] ^= 1 << ((s >> 32) & 7);
            if let Ok(out) = decompress(&v) {
                assert_eq!(out, TEXT, "undetected corruption at byte {i}");
            }
        }
    }

    #[test]
    fn codecs_xz_garbage_never_panics() {
        let mut s = 0xDEAD_BEEF_CAFE_F00Du64;
        let seeds: [&[u8]; 3] = [
            include_bytes!("testdata/text.props.xz"),
            include_bytes!("testdata/x86.bin.xz"),
            include_bytes!("testdata/noise.xz"),
        ];
        for round in 0..3000 {
            let mut v = seeds[round % 3].to_vec();
            for _ in 0..(round % 7 + 1) {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                let i = (s as usize) % v.len();
                v[i] = (s >> 40) as u8;
            }
            let _ = decompress(&v);
            let _ = lzma::decompress_lzma2(&v[12..]);
            let _ = lzma::decompress(&v);
        }
    }

    #[test]
    fn codecs_lzma_alone_raw_formats() {
        assert_eq!(lzma::decompress(include_bytes!("testdata/text.lzma")).unwrap(), TEXT);
        // Same stream with the size field filled in: decoding stops at the declared size.
        assert_eq!(lzma::decompress(include_bytes!("testdata/text.sized.lzma")).unwrap(), TEXT);
        assert_eq!(lzma::decompress_lzma2(include_bytes!("testdata/text.lzma2")).unwrap(), TEXT);
        // Raw LZMA1, preset 6 properties lc=3 lp=0 pb=2 -> 93.
        let raw1 = include_bytes!("testdata/text.lzma1");
        assert_eq!(lzma::decompress_lzma1_raw(raw1, 93, None).unwrap(), TEXT);
        assert_eq!(lzma::decompress_lzma1_raw(raw1, 93, Some(TEXT.len() as u64)).unwrap(), TEXT);
        assert_eq!(lzma::decompress_lzma1_raw(raw1, 93, Some(100)).unwrap(), &TEXT[..100]);
        // Truncated .lzma files are errors.
        let alone = include_bytes!("testdata/text.lzma");
        for n in 0..alone.len() - 1 {
            assert!(lzma::decompress(&alone[..n]).is_err(), "truncated at {n}");
        }
    }

    #[test]
    fn codecs_xz_filters_direct() {
        // Delta decode is the inverse of delta encode.
        let mut enc = SAMPLES.to_vec();
        for i in (3..enc.len()).rev() {
            enc[i] = enc[i].wrapping_sub(SAMPLES[i - 3]);
        }
        delta_decode(&mut enc, 3);
        assert_eq!(enc, SAMPLES);
        // Short buffers are left alone by the x86 filter.
        let mut short = [0xE8u8, 1, 2, 3];
        x86_decode(&mut short, 0);
        assert_eq!(short, [0xE8, 1, 2, 3]);
    }

    /// The BCJ x86 decoder's CALL/JMP scan against a byte loop, and the whole filter against
    /// the byte-at-a-time reference, on buffers dense and sparse in E8/E9 bytes.
    #[test]
    fn codecs_xz_x86_scan() {
        fn reference(buf: &mut [u8], start: u32) {
            const ALLOWED: [bool; 8] = [true, true, true, false, true, false, false, false];
            const BIT_NUM: [u32; 8] = [0, 1, 2, 2, 3, 3, 3, 3];
            let ms = |b: u8| b == 0 || b == 0xFF;
            if buf.len() < 5 {
                return;
            }
            let (mut prev_mask, mut prev_pos) = (0u32, start.wrapping_sub(5));
            let mut i = 0;
            while i <= buf.len() - 5 {
                if buf[i] != 0xE8 && buf[i] != 0xE9 {
                    i += 1;
                    continue;
                }
                let now = start.wrapping_add(i as u32);
                let offset = now.wrapping_sub(prev_pos);
                prev_pos = now;
                if offset > 5 {
                    prev_mask = 0;
                } else {
                    for _ in 0..offset {
                        prev_mask = (prev_mask & 0x77) << 1;
                    }
                }
                let b4 = buf[i + 4];
                if ms(b4) && ALLOWED[((prev_mask >> 1) & 7) as usize] && (prev_mask >> 1) < 0x10 {
                    let mut src = u32::from_le_bytes([buf[i + 1], buf[i + 2], buf[i + 3], b4]);
                    let mut dest;
                    loop {
                        dest = src.wrapping_sub(now.wrapping_add(5));
                        if prev_mask == 0 {
                            break;
                        }
                        let idx = BIT_NUM[(prev_mask >> 1) as usize & 7];
                        if !ms((dest >> (24 - idx * 8)) as u8) {
                            break;
                        }
                        src = dest ^ ((1u32 << (32 - idx * 8)) - 1);
                    }
                    let d = dest & 0x01FF_FFFF;
                    buf[i + 1..i + 5].copy_from_slice(&[d as u8, (d >> 8) as u8, (d >> 16) as u8, if (dest >> 24) & 1 != 0 { 0xFF } else { 0 }]);
                    i += 5;
                    prev_mask = 0;
                } else {
                    i += 1;
                    prev_mask |= 1 | if ms(b4) { 0x10 } else { 0 };
                }
            }
        }
        let mut s = 0x0BCD_1234_5678_9EF1u64;
        let mut rnd = move || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for round in 0..400 {
            let n = (rnd() % 300) as usize;
            let density = 1 + rnd() % 40;
            let buf: Vec<u8> = (0..n)
                .map(|_| match rnd() % density {
                    0 => 0xE8,
                    1 => 0xE9,
                    2 => 0x00,
                    3 => 0xFF,
                    _ => rnd() as u8,
                })
                .collect();
            for from in 0..=n.min(40) {
                for end in from..=n {
                    let want = (from..end).find(|&k| buf[k] & 0xFE == 0xE8).unwrap_or(end);
                    assert_eq!(next_e8(&buf, from, end), want, "round {round} from {from} end {end}");
                }
            }
            let start = rnd() as u32;
            let (mut a, mut b) = (buf.clone(), buf.clone());
            x86_decode(&mut a, start);
            reference(&mut b, start);
            assert_eq!(a, b, "round {round}");
        }
        let mut x = X86.to_vec();
        let mut y = X86.to_vec();
        x86_decode(&mut x, 0);
        reference(&mut y, 0);
        assert_eq!(x, y);
    }

    /// Long mutation fuzz over every xz/lzma fixture (CODECS_FUZZ_ITERS, default 200k):
    /// `cargo test codecs_xz_fuzz_long -- --ignored`, also run under valgrind memcheck.
    #[test]
    #[ignore]
    fn codecs_xz_fuzz_long() {
        let iters: usize = std::env::var("CODECS_FUZZ_ITERS").ok().and_then(|s| s.parse().ok()).unwrap_or(200_000);
        let seeds: [&[u8]; 10] = [
            include_bytes!("testdata/text.xz"),
            include_bytes!("testdata/text.mt.xz"),
            include_bytes!("testdata/text.props.xz"),
            include_bytes!("testdata/noise.xz"),
            include_bytes!("testdata/x86.bin.xz"),
            include_bytes!("testdata/samples.bin.xz"),
            include_bytes!("testdata/multi.xz"),
            include_bytes!("testdata/text.lzma"),
            include_bytes!("testdata/text.lzma2"),
            include_bytes!("testdata/text.lzma1"),
        ];
        let mut s = 0x0123_4567_89AB_CDEFu64;
        let mut rnd = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for it in 0..iters {
            let seed = seeds[it % seeds.len()];
            let mut v = seed.to_vec();
            let r = rnd();
            match r % 4 {
                0 => {
                    // a few random bytes
                    for _ in 0..(r >> 8) % 4 + 1 {
                        let i = rnd() as usize % v.len();
                        v[i] = rnd() as u8;
                    }
                }
                1 => {
                    // bit flip in the compressed payload
                    let i = rnd() as usize % v.len();
                    v[i] ^= 1 << (rnd() % 8);
                }
                2 => {
                    // truncate
                    v.truncate(rnd() as usize % v.len());
                }
                _ => {
                    // splice a chunk of another fixture in
                    let other = seeds[rnd() as usize % seeds.len()];
                    let a = rnd() as usize % v.len();
                    let b = rnd() as usize % other.len();
                    let n = (rnd() as usize % 64).min(v.len() - a).min(other.len() - b);
                    v[a..a + n].copy_from_slice(&other[b..b + n]);
                }
            }
            let _ = decompress(&v);
            let _ = lzma::decompress(&v);
            let _ = lzma::decompress_lzma2(&v);
            let _ = lzma::decompress_lzma1_raw(&v, 93, None);
            let _ = lzma::decompress_lzma1_raw(&v, (rnd() % 225) as u8, Some(rnd() % 20000));
        }
    }

    /// The real volatility ISF (single 6.7 MB block) when it is present on this machine.
    #[test]
    fn codecs_xz_real_isf() {
        let path = std::env::var("HOME").unwrap_or_default()
            + "/.cache/volatility3/symbols/windows/ntkrnlmp.pdb/8E3373D6124E747F0E72EF8E02E676B3-1.json.xz";
        let Ok(data) = std::fs::read(&path) else { return };
        let out = decompress(&data).unwrap();
        assert_eq!(out.len(), 6_690_613);
        assert_eq!(crate::codecs::crc::crc32(&out), 0x0549_61b7);
    }
}
