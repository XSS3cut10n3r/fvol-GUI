//! AVML (Acquire Volatile Memory for Linux) v2 images: LiME-like 32-byte headers
//! (`<IIQQQ`: magic "AVML", version 2, start, end (inclusive), padding) each followed by a
//! snappy framing-format stream of the range and an 8-byte trailer.
//! Derived from Volatility 3's layers/avml.py (Volatility Software License 1.0).
//!
//! python decompresses every frame at load time to learn its size; here only the snappy
//! length preamble is parsed (frames are decoded lazily through the block cache), so opening
//! an image costs one pass over the frame headers.

use super::segmented::{Access, Block, Codec, Seg, SegmentedLayer, Src};
use super::Base;
use crate::codecs::snappy;
use crate::error::{Error, Result};

pub const MAGIC: u32 = 0x4C4D_5641;
pub const VERSION: u32 = 2;
const HEADER: u64 = 32;

fn err(msg: &str) -> Error {
    Error::Layer(format!("AVML: {msg}"))
}

pub(crate) fn stack(base: &Base) -> Result<SegmentedLayer> {
    // python _check_header
    let h = base.bytes(0, 8)?;
    if u32::from_le_bytes(h[0..4].try_into().unwrap()) != MAGIC || u32::from_le_bytes(h[4..8].try_into().unwrap()) != VERSION {
        return Err(err("file not in AVML format"));
    }
    let len = base.len();
    let mut segs = Vec::new();
    let mut blocks = Vec::new();
    let mut offset = 0u64;
    // python: while offset + 4 < base_layer.maximum_address
    while offset.saturating_add(5) < len {
        let hdr = base.bytes(offset, HEADER as usize)?;
        let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
        let version = u32::from_le_bytes(hdr[4..8].try_into().unwrap());
        let start = u64::from_le_bytes(hdr[8..16].try_into().unwrap());
        let end = u64::from_le_bytes(hdr[16..24].try_into().unwrap());
        if magic != MAGIC || version != VERSION {
            return Err(err("file not completely in AVML format"));
        }
        // python reads min(end - start, maximum_address - (offset + 32)) bytes; a
        // non-positive length raises ValueError
        let data_at = offset + HEADER;
        let avail = (len as i128 - 1) - data_at as i128;
        let want = end as i128 - start as i128;
        let chunk_len = want.min(avail);
        if chunk_len <= 0 {
            return Err(err("bad block length"));
        }
        let chunk = base.bytes(data_at, chunk_len as usize)?;
        let consumed = read_frames(&chunk, want as u64, start, data_at, &mut segs, &mut blocks)?;
        offset = data_at.checked_add(consumed).and_then(|o| o.checked_add(8)).ok_or_else(|| err("offset overflow"))?;
    }
    SegmentedLayer::with_blocks("AVMLLayer", base, segs, blocks, Codec::Snappy, Access::WholeSegment)
}

/// python `_read_snappy_frames` over one block's data. Frame layout: u32 LE (type | size<<8).
/// Returns the number of bytes consumed.
fn read_frames(data: &[u8], expected: u64, start: u64, data_at: u64, segs: &mut Vec<Seg>, blocks: &mut Vec<Block>) -> Result<u64> {
    let mut decompressed: u64 = 0;
    let mut off = 0usize;
    while decompressed <= expected {
        if off + 4 >= data.len() {
            // python loops forever here; refuse the file instead
            return Err(err("truncated snappy stream"));
        }
        let v = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        let ty = v & 0xff;
        let size = (v >> 8) as usize;
        let body_start = off + 4;
        let body = &data[body_start.min(data.len())..(body_start + size).min(data.len())];
        match ty {
            0xff => {
                if body != b"sNaPpY" {
                    return Err(err("snappy header missing"));
                }
            }
            0x00 | 0x01 => {
                // python: frame_data = data[mapped_start + 4 : mapped_start + frame_size]
                let fd_start = (body_start + 4).min(data.len());
                let fd_end = (body_start + size).min(data.len()).max(fd_start);
                let frame = &data[fd_start..fd_end];
                let file_off = data_at + fd_start as u64;
                let ulen = if ty == 0x00 {
                    if body_start + size > data.len() {
                        // python's uncompress of a truncated frame fails
                        return Err(err("truncated compressed frame"));
                    }
                    let (ulen, _) = snappy::uncompressed_len(frame).map_err(|_| err("bad snappy frame"))?;
                    // a valid block expands at most ~21x (3-byte copy -> 64 bytes)
                    if ulen as u64 > frame.len() as u64 * 22 + 64 {
                        return Err(err("bad snappy frame length"));
                    }
                    let idx = u32::try_from(blocks.len()).map_err(|_| err("too many frames"))?;
                    blocks.push(Block { off: file_off, clen: frame.len() as u32, ulen: ulen as u32 });
                    if let Some(s) = start.checked_add(decompressed) {
                        segs.push(Seg { start: s, len: ulen as u64, src: Src::Block(idx) });
                    }
                    ulen as u64
                } else {
                    if let Some(s) = start.checked_add(decompressed) {
                        segs.push(Seg { start: s, len: frame.len() as u64, src: Src::Raw(file_off) });
                    }
                    frame.len() as u64
                };
                decompressed += ulen;
            }
            0x02..=0x7f => return Err(err("unskippable chunk")),
            _ => {}
        }
        off = body_start + size;
    }
    Ok(off as u64)
}
