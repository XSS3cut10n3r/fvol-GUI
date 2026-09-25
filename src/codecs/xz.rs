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
    let mut out = vec![0u8; total];
    let threads = if blocks.len() > 1 && total >= PARALLEL_MIN_BYTES {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1).min(blocks.len())
    } else {
        1
    };
    if threads <= 1 {
        for blk in &blocks {
            decode_block(data, blk, &mut out[blk.out_start..blk.out_start + blk.out_len])?;
        }
        return Ok(out);
    }

    // Split the output into per-block slices and hand them out to worker threads.
    let mut jobs: Vec<(&Block, &mut [u8])> = Vec::with_capacity(blocks.len());
    let mut rest: &mut [u8] = &mut out;
    for blk in &blocks {
        let (head, tail) = std::mem::take(&mut rest).split_at_mut(blk.out_len);
        jobs.push((blk, head));
        rest = tail;
    }
    // Largest blocks first for better balance.
    jobs.sort_by_key(|j| std::cmp::Reverse(j.1.len()));
    let queue = std::sync::Mutex::new(jobs);
    let first_err: std::sync::Mutex<Option<Error>> = std::sync::Mutex::new(None);
    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| {
                loop {
                    let job = queue.lock().ok().and_then(|mut q| q.pop());
                    let Some((blk, buf)) = job else { break };
                    if let Err(e) = decode_block(data, blk, buf) {
                        if let Ok(mut fe) = first_err.lock() {
                            fe.get_or_insert(e);
                        }
                        if let Ok(mut q) = queue.lock() {
                            q.clear();
                        }
                        break;
                    }
                }
            });
        }
    });
    if let Some(e) = first_err.into_inner().ok().flatten() {
        return Err(e);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------
// Filters
// ---------------------------------------------------------------------------------------

fn delta_decode(buf: &mut [u8], dist: usize) {
    for i in dist..buf.len() {
        buf[i] = buf[i].wrapping_add(buf[i - dist]);
    }
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
        let b = buf[i];
        if b != 0xE8 && b != 0xE9 {
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
