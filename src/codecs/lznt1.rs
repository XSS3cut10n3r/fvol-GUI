//! LZNT1 decompression (NTFS file compression, `RtlDecompressBuffer(COMPRESSION_FORMAT_LZNT1)`).
//!
//! # Format
//!
//! A stream is a sequence of chunks. Each chunk starts with a 2-byte little-endian header `h`
//! followed by `(h & 0x0FFF) + 1` data bytes. `h == 0`, or fewer than two input bytes left,
//! ends the stream. Bit 15 set: the data is compressed and expands to at most 4096 bytes;
//! clear: the data is stored as-is. Bits 12..14 hold a signature (3 in practice) that is not
//! checked (Windows does not check it either).
//!
//! A compressed chunk is a sequence of groups: one flag byte, then up to 8 items. Flag bit `i`
//! (LSB first) selects a literal byte (0) or a 16-bit LE back-reference token (1). The split of
//! a token into offset and length bits depends on the output position `pos` inside the chunk:
//! `bits = max(4, bit_length(pos - 1))`, `offset = (token >> (16 - bits)) + 1`,
//! `length = (token & (0xFFFF >> bits)) + 3`. A reference may overlap the bytes it produces
//! (repeating a pattern) but never reaches before the start of its chunk.
//!
//! # Short chunks: padding or not
//!
//! On Windows every chunk owns a 4096-byte slot of the output. When a chunk (compressed or
//! stored) expands to fewer than 4096 bytes and another chunk follows, `RtlDecompressBuffer`
//! zero-fills the rest of the slot (Wine's implementation, whose conformance tests run against
//! real Windows, does the same; ntfs-3g zero-pads each 4 KiB sub-block of a compression unit).
//! Encoders only produce short chunks at the end of a stream, so this matters only for unusual
//! streams. The commonly used forensic decoders (libfwnt, dissect, ruby_smb, ...) do not pad,
//! and neither does [`decompress`]. [`decompress_padded`] and [`decompress_buffer`] reproduce
//! the Windows layout.
//!
//! # Errors
//!
//! A truncated chunk, a token cut short by the end of its chunk, a back-reference before the
//! chunk start and a chunk expanding beyond 4096 bytes are errors (Windows returns
//! `STATUS_BAD_COMPRESSION_BUFFER`; ntfs-3g also rejects the first three). Malformed input
//! never panics.
//!
//! # Speed
//!
//! The chunk decoder works on raw pointers with the bounds proven once per 8-item group:
//! literal runs are moved with one 8-byte copy (the flag byte's trailing zero count gives the
//! run length), matches with 16-byte copies (8-byte for offsets 8..15, a replicated pattern
//! word for offsets below 8), and the output buffer is sized up front from the chunk headers.
//! Wide copies may write up to [`SLACK`] bytes past the chunk end; the spare capacity is
//! reserved for that.

use crate::error::{Error, Result};
use std::mem::MaybeUninit;
use std::ptr;

/// Maximum decompressed size of one chunk (also the chunk slot size on Windows).
pub const CHUNK_SIZE: usize = 4096;

/// Bytes the fast chunk decoder may write past the last byte it produces (wide copies write at
/// most 16 bytes past the end of a chunk; the rest is margin).
const SLACK: usize = 32;

/// Input bytes a group needs for the unchecked path: the flag byte, 8 two-byte tokens and an
/// 8-byte speculative literal read after the last item.
const FAST_IN: usize = 1 + 16 + 8;

/// Why a compressed chunk is invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Bad {
    /// A back-reference points before the start of the chunk.
    Offset,
    /// The chunk expands beyond 4096 bytes (or a match runs past the caller's buffer).
    Overflow,
    /// The chunk ends in the middle of a token.
    Truncated,
}

fn chunk_err(bad: Bad, at: usize) -> Error {
    let what = match bad {
        Bad::Offset => "back-reference before the start of the chunk",
        Bad::Overflow => "chunk expands beyond 4096 bytes",
        Bad::Truncated => "chunk ends inside a token",
    };
    Error::Msg(format!("lznt1: {what} (chunk at input offset {at})"))
}

fn truncated_err(at: usize) -> Error {
    Error::Msg(format!("lznt1: truncated chunk at input offset {at}"))
}

fn oom_err() -> Error {
    Error::Msg("lznt1: cannot allocate the output buffer".into())
}

/// Decompresses an LZNT1 stream (chunks until a zero header or the end of the input).
///
/// Chunks are concatenated as they expand, without padding short chunks to 4096 bytes (like
/// libfwnt, dissect and ruby_smb); see [`decompress_padded`] for the Windows layout. An empty
/// input or a trailing single byte is accepted.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    decode_vec(data, &mut out, false)?;
    Ok(out)
}

/// Like [`decompress`], appending the output to `out`. On error `out` keeps the chunks
/// decoded so far.
pub fn decompress_into(data: &[u8], out: &mut Vec<u8>) -> Result<()> {
    decode_vec(data, out, false)
}

/// Decompresses with the Windows (`RtlDecompressBuffer`) chunk layout: a chunk that expands to
/// fewer than 4096 bytes and is followed by another chunk is zero-padded to 4096 bytes.
/// Equivalent to [`decompress_buffer`] with an unbounded output buffer.
pub fn decompress_padded(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    decode_vec(data, &mut out, true)?;
    Ok(out)
}

/// `RtlDecompressBuffer(COMPRESSION_FORMAT_LZNT1)` into a caller-provided buffer; returns the
/// final uncompressed size.
///
/// Windows semantics: short chunks followed by another chunk are zero-padded to 4096 bytes
/// (the padding is skipped, and decoding stops, when it would reach the end of `out`); output
/// that does not fit is cut at the end of `out` for stored chunks and literals, while a
/// back-reference running past the end of `out` is an error (as on every Windows version);
/// an input shorter than 2 bytes is an error. Bytes of `out` past the returned size are never
/// written.
///
/// For an NTFS compression unit (e.g. 16 clusters), pass the unit-sized buffer and zero the
/// bytes past the returned size: `let n = decompress_buffer(cu, &mut buf)?; buf[n..].fill(0);`
pub fn decompress_buffer(data: &[u8], out: &mut [u8]) -> Result<usize> {
    if data.len() < 2 {
        return Err(Error::Msg("lznt1: input shorter than a chunk header".into()));
    }
    let mut tmp = MaybeUninit::<[u8; CHUNK_SIZE + SLACK]>::uninit();
    let mut ip = 0usize;
    let mut op = 0usize;
    while data.len() - ip >= 2 {
        let at = ip;
        let h = u16::from_le_bytes([data[ip], data[ip + 1]]) as usize;
        if h == 0 {
            break;
        }
        ip += 2;
        let size = (h & 0x0FFF) + 1;
        let chunk = data.get(ip..ip + size).ok_or_else(|| truncated_err(at))?;
        ip += size;
        let partial = op & (CHUNK_SIZE - 1);
        if partial != 0 {
            let fill = CHUNK_SIZE - partial;
            if op + fill >= out.len() {
                break;
            }
            out[op..op + fill].fill(0);
            op += fill;
        }
        if op >= out.len() {
            break;
        }
        let room = out.len() - op;
        if h & 0x8000 == 0 {
            let n = size.min(room);
            out[op..op + n].copy_from_slice(&chunk[..n]);
            op += n;
        } else if room >= CHUNK_SIZE {
            let t = tmp.as_mut_ptr() as *mut u8;
            // SAFETY: `tmp` holds CHUNK_SIZE + SLACK writable bytes; the decoder only reads
            // bytes it wrote, and exactly `n` bytes are initialized on success.
            let n = unsafe { decode_chunk_fast(chunk, t) }.map_err(|b| chunk_err(b, at))?;
            // SAFETY: n <= CHUNK_SIZE <= room.
            unsafe { ptr::copy_nonoverlapping(t, out.as_mut_ptr().add(op), n) };
            op += n;
        } else {
            op += decode_chunk_ref(chunk, &mut out[op..]).map_err(|b| chunk_err(b, at))?;
        }
    }
    Ok(op)
}

/// Upper bound of the output size, from the chunk headers alone.
fn output_bound(data: &[u8], pad: bool) -> usize {
    let mut ip = 0usize;
    let mut n = 0usize;
    while data.len() - ip >= 2 {
        let h = u16::from_le_bytes([data[ip], data[ip + 1]]) as usize;
        if h == 0 {
            break;
        }
        let size = (h & 0x0FFF) + 1;
        n += if h & 0x8000 != 0 || pad { CHUNK_SIZE } else { size };
        ip = (ip + 2 + size).min(data.len());
    }
    n
}

fn decode_vec(data: &[u8], out: &mut Vec<u8>, pad: bool) -> Result<()> {
    let base = out.len();
    // Every chunk is at least 3 bytes and expands to at most 4096, so the bound can exceed the
    // real size only for hostile streams of tiny chunks: reserve it when possible (untouched
    // capacity is only address space), else start smaller and grow.
    let bound = output_bound(data, pad) + SLACK;
    if out.try_reserve_exact(bound).is_err() {
        out.try_reserve(bound.min(data.len().saturating_mul(4)) + SLACK).map_err(|_| oom_err())?;
    }
    let mut ip = 0usize;
    while data.len() - ip >= 2 {
        let at = ip;
        let h = u16::from_le_bytes([data[ip], data[ip + 1]]) as usize;
        if h == 0 {
            break;
        }
        ip += 2;
        let size = (h & 0x0FFF) + 1;
        let chunk = data.get(ip..ip + size).ok_or_else(|| truncated_err(at))?;
        ip += size;
        let partial = (out.len() - base) & (CHUNK_SIZE - 1);
        let fill = if pad && partial != 0 { CHUNK_SIZE - partial } else { 0 };
        let need = fill + if h & 0x8000 == 0 { size } else { CHUNK_SIZE + SLACK };
        if out.capacity() - out.len() < need {
            out.try_reserve(need).map_err(|_| oom_err())?;
        }
        out.resize(out.len() + fill, 0);
        if h & 0x8000 == 0 {
            out.extend_from_slice(chunk);
        } else {
            let len = out.len();
            // SAFETY: at least CHUNK_SIZE + SLACK bytes of spare capacity follow `len`; the
            // decoder only reads bytes it wrote and returns how many it produced.
            let n = unsafe { decode_chunk_fast(chunk, out.as_mut_ptr().add(len)) }
                .map_err(|b| chunk_err(b, at))?;
            // SAFETY: the first n bytes of the spare capacity are initialized.
            unsafe { out.set_len(len + n) };
        }
    }
    // Only a hostile stream leaves much unused capacity behind.
    if out.capacity() - out.len() > (out.len() / 4).max(1 << 20) {
        out.shrink_to_fit();
    }
    Ok(())
}

#[inline(always)]
unsafe fn rd16(p: *const u8) -> usize {
    // SAFETY: caller guarantees 2 readable bytes.
    u16::from_le_bytes(unsafe { ptr::read_unaligned(p as *const [u8; 2]) }) as usize
}

#[inline(always)]
unsafe fn copy8(src: *const u8, dst: *mut u8) {
    // SAFETY: caller guarantees 8 readable bytes at src and 8 writable bytes at dst.
    unsafe { ptr::write_unaligned(dst as *mut [u8; 8], ptr::read_unaligned(src as *const [u8; 8])) }
}

#[inline(always)]
unsafe fn copy16(src: *const u8, dst: *mut u8) {
    // SAFETY: caller guarantees 16 readable bytes at src and 16 writable bytes at dst.
    unsafe { ptr::write_unaligned(dst as *mut [u8; 16], ptr::read_unaligned(src as *const [u8; 16])) }
}

/// `REP[d]` replicates the low `d` bytes of a word across 8 bytes (d = 1..7).
const REP: [u64; 8] = [
    0,
    0x0101_0101_0101_0101,
    0x0001_0001_0001_0001,
    0x0001_0000_0100_0001,
    0x0000_0001_0000_0001,
    0x0000_0100_0000_0001,
    0x0001_0000_0000_0001,
    0x0100_0000_0000_0001,
];

/// `STEP[d]`: the smallest multiple of `d` that is >= 8. Once 8 bytes of a period-`d` pattern
/// are written, 8-byte blocks can be copied from that far back (it is <= d + 8, so the source
/// never starts before the pattern).
const STEP: [usize; 8] = [0, 8, 8, 9, 8, 10, 12, 14];

/// Expands the back-reference `tok` at output position `pos` (`op` = chunk start + `pos`);
/// returns its length.
///
/// # Safety
/// `op - pos` is the start of a buffer holding `pos` initialized bytes followed by at least
/// `CHUNK_SIZE - pos + 16` writable bytes when `pos <= CHUNK_SIZE`. Nothing is accessed when an
/// error is returned.
#[inline(always)]
unsafe fn copy_match(op: *mut u8, pos: usize, tok: usize) -> core::result::Result<usize, Bad> {
    // Offset bits = max(4, bit_length(pos - 1)); the mask keeps pos == 0 in range (the offset
    // check then fails) and is a no-op for pos <= 8192.
    let bits = 32 - (((pos as u32).wrapping_sub(1) | 15) & 0x1FFF).leading_zeros() as usize;
    let off = (tok >> (16 - bits)) + 1;
    let len = (tok & (0xFFFF >> bits)) + 3;
    if off > pos {
        return Err(Bad::Offset);
    }
    if pos + len > CHUNK_SIZE {
        return Err(Bad::Overflow);
    }
    // SAFETY (whole block): off <= pos keeps every read inside the bytes already written
    // (each wide block reads only bytes written before it: blocks advance by at most the
    // offset, or by STEP[off] <= off + 8 for patterns); writes end before op + len + 16 <=
    // chunk start + CHUNK_SIZE + 16.
    unsafe {
        let src = op.sub(off);
        if off >= 16 {
            copy16(src, op);
            let mut i = 16;
            while i < len {
                copy16(src.add(i), op.add(i));
                i += 16;
            }
        } else if off >= 8 {
            copy8(src, op);
            copy8(src.add(8), op.add(8));
            let mut i = 16;
            while i < len {
                copy8(src.add(i), op.add(i));
                i += 8;
            }
        } else if pos >= 8 {
            // The last `off` bytes, replicated into an 8-byte pattern.
            let w = u64::from_le_bytes(ptr::read_unaligned(op.sub(8) as *const [u8; 8]));
            let pat = (w >> (64 - 8 * off)).wrapping_mul(REP[off]);
            ptr::write_unaligned(op as *mut [u8; 8], pat.to_le_bytes());
            if len > 8 {
                if off & (off - 1) == 0 {
                    // Offsets 1, 2, 4: the pattern repeats every 8 bytes.
                    let p16 = pat as u128 | (pat as u128) << 64;
                    let mut i = 8;
                    while i < len {
                        ptr::write_unaligned(op.add(i) as *mut [u8; 16], p16.to_le_bytes());
                        i += 16;
                    }
                } else {
                    let d = STEP[off];
                    let mut i = 8;
                    while i < len {
                        copy8(op.add(i).sub(d), op.add(i));
                        i += 8;
                    }
                }
            }
        } else {
            for i in 0..len {
                *op.add(i) = *src.add(i);
            }
        }
    }
    Ok(len)
}

/// Decodes one compressed chunk into `dst`; returns the number of bytes produced (<= 4096).
///
/// # Safety
/// `dst` must be valid for writes of `CHUNK_SIZE + SLACK` bytes. Only bytes written by this
/// call are read back (nothing before `dst`).
unsafe fn decode_chunk_fast(src: &[u8], dst: *mut u8) -> core::result::Result<usize, Bad> {
    let mut s = src.as_ptr();
    // SAFETY: one past the end of `src`.
    let end = unsafe { s.add(src.len()) };
    let mut pos = 0usize;
    // Groups whose 8 items are all inside the chunk, with room for the speculative reads:
    // no per-item input checks. Output: `pos <= CHUNK_SIZE` holds at the start of each group
    // and after each match, so the 8-byte literal copies stay within the slack; literals
    // overrunning the chunk are caught at the end of the group (or by the next match check).
    while end as usize - s as usize >= FAST_IN {
        // SAFETY: FAST_IN readable bytes at s; see above for the writes.
        unsafe {
            let mut f = *s as u32 | 0x100;
            s = s.add(1);
            loop {
                // Literals before the next token (or before the sentinel bit).
                let t = f.trailing_zeros() as usize;
                copy8(s, dst.add(pos));
                s = s.add(t);
                pos += t;
                f >>= t;
                if f == 1 {
                    break;
                }
                f >>= 1;
                let tok = rd16(s);
                s = s.add(2);
                pos += copy_match(dst.add(pos), pos, tok)?;
            }
        }
        if pos > CHUNK_SIZE {
            return Err(Bad::Overflow);
        }
    }
    // Tail: the last groups, checking every item.
    while s < end {
        // SAFETY: s < end.
        let mut flags = unsafe { *s };
        s = unsafe { s.add(1) };
        let mut n = 0;
        while n < 8 && s < end {
            if flags & 1 == 0 {
                if pos >= CHUNK_SIZE {
                    return Err(Bad::Overflow);
                }
                // SAFETY: s < end, pos < CHUNK_SIZE.
                unsafe {
                    *dst.add(pos) = *s;
                    s = s.add(1);
                }
                pos += 1;
            } else {
                if (end as usize - s as usize) < 2 {
                    return Err(Bad::Truncated);
                }
                // SAFETY: 2 readable bytes at s; pos <= CHUNK_SIZE (literals are checked).
                unsafe {
                    let tok = rd16(s);
                    s = s.add(2);
                    pos += copy_match(dst.add(pos), pos, tok)?;
                }
            }
            flags >>= 1;
            n += 1;
        }
    }
    Ok(pos)
}

/// Byte-at-a-time chunk decoder into `out` (at most 4096 bytes: the chunk's output window).
/// When `out` is shorter than a chunk it is the rest of the caller's buffer: a literal that
/// does not fit ends the chunk successfully, a back-reference that does not fit is an error
/// (Windows behaviour). Also the reference the fast decoder is tested against.
fn decode_chunk_ref(src: &[u8], out: &mut [u8]) -> core::result::Result<usize, Bad> {
    let lim = out.len().min(CHUNK_SIZE);
    let mut s = 0usize;
    let mut pos = 0usize;
    while s < src.len() {
        let mut flags = src[s];
        s += 1;
        for _ in 0..8 {
            if s >= src.len() {
                break;
            }
            if flags & 1 == 0 {
                if pos >= lim {
                    return if lim < CHUNK_SIZE { Ok(pos) } else { Err(Bad::Overflow) };
                }
                out[pos] = src[s];
                pos += 1;
                s += 1;
            } else {
                if src.len() - s < 2 {
                    return Err(Bad::Truncated);
                }
                let tok = u16::from_le_bytes([src[s], src[s + 1]]) as usize;
                s += 2;
                if pos == 0 {
                    return Err(Bad::Offset);
                }
                let mut lg = 0;
                let mut i = pos - 1;
                while i >= 0x10 {
                    lg += 1;
                    i >>= 1;
                }
                let off = (tok >> (12 - lg)) + 1;
                let len = (tok & (0xFFF >> lg)) + 3;
                if off > pos {
                    return Err(Bad::Offset);
                }
                if pos + len > lim {
                    return Err(Bad::Overflow);
                }
                for k in pos..pos + len {
                    out[k] = out[k - off];
                }
                pos += len;
            }
            flags >>= 1;
        }
    }
    Ok(pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Generated by bench/refbench/lznt1_vectors.py (verified with ruby_smb's decoder).
    const V_TEXT: &str = "\
        80b1006d66740a70687973006963616c207365720076696365206b65790020706f6f6c207072006f6365737320746100626c\
        650a7468652031010c66696c00200148207610697274750072746167200a68616e6402306720106d6f647500146d656d306f\
        72790a0548059a696d0461670074616c75652080736f636b65742c03530703180140017d2c20736361426e0468746f6b6505\
        0b6b7065726e650073008a040a6f0266000d726561642077c0696e646f7773034f08a8206c61796572040b7379846d6201dc\
        6c7567690153806720686976652c043f91023a766164078b6472000f8072206c696e757801350d81102c8a48001720766f6c\
        806174696c697479854a6f037f834284888468678653039a0aff0383854c841f85970220036000d7845b7c2c2007db831a84\
        bf85b682af0af86d6163863d8431030303768369f3813f00366673c0054874432b0382ff0101818584594856020fc3030064\
        48411f80238204c101c4268450626a65ce63c731c406c4256f6605434b51078401438d4334";
    const V_TEXT_OUT: &str = "\
        6d66740a706879736963616c2073657276696365206b657920706f6f6c2070726f63657373207461626c650a746865207468\
        652066696c65207461626c65207669727475616c207461670a68616e646c6520746167206d6f64756c65206d656d6f72790a\
        7669727475616c2070726f6365737320696d6167652076616c756520736f636b65742c2066696c6520696d61676520746167\
        20706f6f6c2c207363616e207461626c6520746f6b656e207461626c65206b65726e656c20746865206b65726e656c206f66\
        207468726561642077696e646f77732066696c652066696c65207461626c65206c61796572207461626c652073796d626f6c\
        20706c7567696e2074616720686976652c20696d616765207363616e207661640a706879736963616c20647269766572206c\
        696e7578206f66207363616e2c20746f6b656e207461626c652076616420766f6c6174696c697479206b65726e656c206d65\
        6d6f72792066696c65206d6f64756c65207363616e207461672077696e646f77732068616e646c650a736f636b6574207379\
        6d626f6c206b65726e656c2070726f636573732066696c65206c61796572206d667420706c7567696e2c2070687973696361\
        6c2073796d626f6c2068616e646c65207669727475616c2076616c75650a6d6163206d6f64756c6520736f636b657420736f\
        636b657420696d616765206c696e75782068697665206f6666736574207669727475616c20746167207363616e20706f6f6c\
        20706f6f6c206b6579207468726561642066696c65207461626c6520686976652066696c652074686520766f6c6174696c69\
        747920616e642074686520616e642068616e646c65206c696e7578206f626a65637420706c7567696e2c2068616e646c6520\
        736f636b6574206f660a736f636b6574206b65726e656c206d656d6f7279206d656d6f72792076616c7565206d6f64756c65";
    const V_RANDOMIZED: &str = "\
        00b2006d66740a70687973006963616c207365720076696365206b65790020706f6f6c207072006f6365737320746100626c\
        650a74686520a1000c2066696c0020610048402076697274750072748061670a68616e640024410014206d6f6475003a6dc0\
        656d6f72790a0348059a407320696d6167007461006c756520736f636b5065742c2002536900186505005967017d6c2c2073\
        630c616e004f006820746f6b18656e20007400616b6572c06e656c207468030a000a046f66000d72656164208077696e646f\
        7773034f0900046520013365206c612879657200a66200117379046d6200dc706c75676901015f6720686976652c8f804b80\
        4b003a003a766164058b406c2064726976001e6c30696e75780035014b6e2c0787488079001720766f6c61c074696c697479\
        0050824abd027f7902458288005d84686781533980537320019a00ad01836574ba20804c6200bb801f801f208397e3846500\
        6065722000d7835b0040ff04db00db83670125806e81b680b60061e180af0a6d616381c6823d02b50f84b801c280b5806975\
        782068c1803f206f666673c005016b7b4474013a6e8162008240838025798f80598159c034401a746162006d3f020f405a40\
        7ec086424141417920e8616e64800b65c101c426835040206f626a6563c5312cf38340c05d6f63c025c0570143c084edc376\
        6c425140516dc29243354053014153";
    const V_RANDOMIZED_OUT: &str = "\
        6d66740a706879736963616c2073657276696365206b657920706f6f6c2070726f63657373207461626c650a746865207468\
        652066696c65207461626c65207669727475616c207461670a68616e646c6520746167206d6f64756c65206d656d6f72790a\
        7669727475616c2070726f6365737320696d6167652076616c756520736f636b65742c2066696c6520696d61676520746167\
        20706f6f6c2c207363616e207461626c6520746f6b656e207461626c65206b65726e656c20746865206b65726e656c206f66\
        207468726561642077696e646f77732066696c652066696c65207461626c65206c61796572207461626c652073796d626f6c\
        20706c7567696e2074616720686976652c20696d616765207363616e207661640a706879736963616c20647269766572206c\
        696e7578206f66207363616e2c20746f6b656e207461626c652076616420766f6c6174696c697479206b65726e656c206d65\
        6d6f72792066696c65206d6f64756c65207363616e207461672077696e646f77732068616e646c650a736f636b6574207379\
        6d626f6c206b65726e656c2070726f636573732066696c65206c61796572206d667420706c7567696e2c2070687973696361\
        6c2073796d626f6c2068616e646c65207669727475616c2076616c75650a6d6163206d6f64756c6520736f636b657420736f\
        636b657420696d616765206c696e75782068697665206f6666736574207669727475616c20746167207363616e20706f6f6c\
        20706f6f6c206b6579207468726561642066696c65207461626c6520686976652066696c652074686520766f6c6174696c69\
        747920616e642074686520616e642068616e646c65206c696e7578206f626a65637420706c7567696e2c2068616e646c6520\
        736f636b6574206f660a736f636b6574206b65726e656c206d656d6f7279206d656d6f72792076616c7565206d6f64756c65";
    const V_RUBY: &str = "\
        ecb000746f6b656e0a7661006420616e64206c61007965722076616c750065206b65726e656c20207461672c04446669006c\
        6520706c756769046e2001c4766972747500616c2077696e646f00777320766f6c617460696c697479057801a67080726f63\
        6573732003d20b020a00a8620094647269760100dc6f626a6563742000726567697374727901017120736f636b657400206d\
        6f64756c650a6105686d656d6f002003a56807005c0044020c0a6f66667303002f013a696d6167652c2d05760a0656079d2c\
        05726c69b06e75782c825283450a0271006d6163206d66742c0103252073796d626f6c000a6c61";
    const V_RUBY_OUT: &str = "\
        746f6b656e0a76616420616e64206c617965722076616c7565206b65726e656c207461672c2076616c75652066696c652070\
        6c7567696e20766164207669727475616c2077696e646f777320766f6c6174696c697479206b65726e656c20616e64207072\
        6f6365737320746f6b656e0a746f6b656e207461626c6520647269766572206f626a65637420726567697374727920746167\
        20736f636b6574206d6f64756c650a7669727475616c206d656d6f7279206c617965722068616e646c65206c617965720a6f\
        66667365742074616720696d6167652c2070726f636573730a726567697374727920766f6c6174696c6974792c206f626a65\
        6374206c696e75782c20616e64206472697665720a66696c65206d6163206d66742c20696d6167652073796d626f6c0a6c61";
    const V_MULTI: &str = "\
        98b5006f66667365742c2000706f6f6c2076616c00756520766f6c617400696c6974792068690076652c2076697274007561\
        6c206f66206402720044722070726f63006573730a706879731c69630034027c003e6d616318206d66009e0666626a650063\
        74206d6f64756c010094746f6b656e206808616e64011a696d61670065207468726561640020736572766963650702730560\
        03912c2066696c0065206d656d6f7279220a020b7461620005736f08636b65075c72656769b073747279064a008d0a0480c0\
        706c7567696e01a20302c1033a2c206c61798067032d69844e6b65850476004b02377760696e646f770047068d2c43856c82\
        0f73796d62829f647f00710367836d80858310858784030ae1852864756d708398004a871903836f83026b65726e656c1f05\
        76051c038900b7031a6c696ec47578030a74616704778632ff08e90355007c021882db8363002ec300bfc23f0331841e4563\
        8420076764c533fb0490800e0a4205c000436588288540adc2560ac404c1770a049f644569ff441f404404048124454e0345\
        04a2c369ff8304411a010a053dc470840dc3b68014ef86210319891d010c2c058304c38007f1c41a7363618384c16cc4a4c5\
        1ad7c501c40ec33e0ac0552086c88408fe2c0bbac3df45200242c410c3c10004fbc5c982aa0a011fc675c50185140342ffc1\
        2883774297c6b2c6a6459443ada114ff0416631e81406442612a830a67536336ff21010523a40f6419840c2a6b84414053ff\
        4083e207c467230e044be225844be30dffc776857ce629e223632842094d03a681ff2309e90d6730cc720679c501c504e767\
        ff42344322a1120487e201ca3d0a1b027cf76419819280310a242c6431a515c423fd04070a242c8a216429e32b0b17850aff\
        e26f431384064222640d549aa333a373ff840bc1b2a15e03076294240c2523c5357f46764240a5122122810845bc60090afb\
        4174a4062c2512c14c442fc123c101ff4107c00d0404c259e15761370305625befa43a8512a32de11b0a84790484205aff03\
        37c201e10b036447c6c11c240bc00ebf85838723232202104307d5e40ac1e4ff68138412240a81b3850e6279e534820afe0a\
        c23483142b40c635c195654ca42d7fc416243d6445640420206153a09a61fe634027631124138421f30742213212ff3c3044\
        06c1587507640473105300e40dff511ba559900e83111404b616840a464bff1227f307f6841a67f73aa304e829d30efff74f\
        a56f321e4513ba46f401f206d425eff58814590645063e0a4412e53c5651efa57392141b3992090ad9114018a33bffd60db3\
        35e176a748b536c788c307e409ffb68da3044615a10f61047159f1094d17ffe30406165794027b4513c003160307707f9300\
        066cd59fa408002f4219795f0aff7641b32c800ec53ed37e07610528a123ef321306360611d3292c220242109f56ff2022c1\
        142318e10193002407242d22027fc311a42962106238e83c454510020affd6107207253ee728e7122522c438d509ff15b3d2\
        4712125376c020c016e32b0208ff66812325640013396f68977e5321040ebf84026bba722185862701351a0a0565ff238389\
        95e4bcc441643b9366760f3434fd73030a544b980ae11b310006030726ff58629106ab12802958ab911b332b8609ff510d66\
        6814a4e44e141512218790632cff878ce75e3453aa878510a163930f765bfffa30843ec206e02cb699a681102e16bdff817f\
        9418032ab4263611127336b57307ff3001857d6400054a997cc6744cbb6439ffc915c21642ac2a45b408f4044456a236fd33\
        8f67b513349d27147208d27a604aff117c6733b5c50350d210926816d3564bff050be4287658731cc6173458540e978eff13\
        7f46252d866470a330941528e3e602ff88f003050931b64f9013830dd401340bff9414934a041e16c774bc4417ca773736ff\
        d107c103d590a30d662e5545d8db9402ff023dc51de92433850216e324b230b40000763f30ce54b49480a9800e1ef8d6ee45\
        b4e37bb409e1cc4ee9d5cbf974c8ca1e3339e42e80b5b6073177ddd06f94eddcdab444e8b42f73770caece96ae321770558e\
        69f1b600764f8acdefe03d261077c356e8000094e4a00643020007b0e3832859a4007be76b1ff0fd663c0000000909090770\
        000a00004c002300812b6b680054ed1bedf7cc0000402a832741c9670a3cb050220000780000f30000c418a73be405040525\
        dc09ee0042458861a2df3f1e101d0eadef1d1354065f007f24b9b979837f48200000512ff90004ef0f0089e845e10f705f80\
        006459429234facc8002981ab0e9e8f558867d02359963d72bd00000d60100008058d45a32c5e200a4a9cb815c7c942000bf\
        f50addaabbcd3f02f58a1c4ece00004f6700b2000008b5eae2f880277f4d269245608d8400bf5a082510e5e451600564653e\
        199a4f03008200d10000301113704909018141080080ae00003b870700971c8e3f2e2e2ea9060003a01e0500814d35d005a2\
        0891dafb4071e70000860497f49231d7a457d81a60160000356a050ec92e8700670182bbb0d2000000ac8e744640dc6100d8\
        00911ce8200400b800004b0442f7050091ebeb12431f43004e8083127349a88200353c7b11a0f2530000009f286a7670e0d7\
        286568915e188f01007b012113074baf00001131f2e4b2b3010034e48309d03d87400e84ebf80107ebf83bdfc1012c097906\
        2f802e3e08000bdd380000ad06005e2c1f003d3f0041a4a0d528b908290042b51b58000016310473550800ab5ef2b7f64064\
        17716dbae3b1078212d157111b7f0c024eb563a087540000450000be040000c3df662c0bd677f707660459238620359d57d6\
        480855aedc0300b8c4f7d20c768fb11306006d7366a5184215282001c6184d81e2c0e9a2f5214e960056060000cb4fc507b6\
        92f384c25800003f8b18629a0a130000355131a44a3a483602060800741d2ea956d100e3f18f2b29ee77241066666673a0a7\
        e8161f002c0f77856a67792ed81b7389e06f0500830200060a0098a60000a23eea8410946fbbb3df0f11b100000065a4463a\
        7c48f204cf35c60e1bf2afbbc6615609756ad123c0930000480236500a6b630000947c5075c2f3ef0300ea607a160100006a\
        a31044c37c3804b217cb05b86800001300c1707ecf13c4ca3932e40110ee7f20a51a00560000a31b0a3e70f8bfb4009c069b\
        f85dde8e0dc0e1d7ec149dbcdc0606000089c06680a7b399b89ab8b31bfb08002a038323d209d6a605009103ba0800720200\
        6f04001f4700008487912640bea6352361f9a4aa6400646495e10000120f08594a2e110b9e61308e0cf7bb6ece1300679a66\
        13700000329c3f0541bb050094810300859bfb2cb40ec403e699000082000d92bf030f000f0031700d64882de04ee80e9e6f\
        0073b8072ac406caef1809c99352233b03935a24802dad1f3607bc29118706750300a0113adf236df00086756c4e48bbe4fb\
        0000276a24389c9e1370db11017cd7020f0803006a3047ca33ade6650800625208a3e49ec02f7d88273274f4838a045c5f80\
        03001f0d9e066f5f020a00cc6c4f8dee00fc73024d6bb91a000400e30700b9e0def11a0097f04900003ef8fa80d6e95e6a03\
        740a67030660040017019ba5747474f39905020ca320da06d30e7f0370008038c3cd204ef79e0300077f0a0f0000007e2c20\
        c23d40a4fa7f7141e7f609670091a2908bddd04b53983c682ddf01d701c1e6a0750100005f590000e68a42000c248262f1d6\
        3b8108391bbca80f0000dec200700700009287cf6c5ff0440f000f000f000800cd05001140de0b6dcebcffd04ded39010009\
        a2e201f40c7f030093b0b930d86c00ac0300770200c1a401393f51784a1f030500226c0400027cbf5f05b930027e0800b786\
        000033460800009008000606a275005bb9da77518f72560fcf050e00090e94008be76fde00af87de778867601b0c3ae02f03\
        0100356e33e205d106a0d04155cb0000071002bca9380000ba770fe0fc585e932290b60f000f00df58084f010f000f000c00\
        1b0100700070097a367e108c0f000900b60180a49d866e971a7fea0a760000af0400e4f22d1b1450d3c0559888001584eb63\
        ef02e4028c16c2cf05b308130817efa1706a7838e7cef0fccb5cf34f020d03cc0b92a00102004a9f96731294033b5f030600\
        8c0200df03d7036ca790f9d905cc06004255b01bf8e848de05041f101510bf05b905013611a61a25475c33f240381ce3ed69\
        ab05000040007d152d9c2d0300a000850000ae76a5fc021032f0c0e312086dd2490043070149bea9f94f2ad20000ae700036\
        40894c5ab04b121e22e708de0ede0200e11901970a9d8a07003e0a7f005a59646a94bf140d00f330ce0f824f30b7df6cbbe6\
        4033110000008ef5ed7590054c4e474f0c4b0c040100227a021fb404a5578464608f1c5d5910940f000a00b1d623e00a728f\
        3a4dd3004f0dc50c0c20e38f078607d1165f4d44698ccf0500009c80b333005d25911914e8da80808000557940bcc4930100\
        b596afd24383aa440f0f0f040fe006fe0c613f3420607713f0c4b59f06030089b10073657276696365200105706f66667365\
        74200068616e646c652070006879736963616c2000696d616765206b6500726e656c20706c758067696e20706f6f062c006c\
        696e75780a74680072656164207461620100766f626a6563742008746865037a2c2073790c6d620064048a6b65790a0100ca\
        2072656769737400727920766f6c6174c0696c6974790a036e04413076616c750698035b6475806d70206d6f6475000b0868\
        697604612077696e00646f77730a6d6674002070726f63657373c1032a766972747500c6022bb0736f636b07e28419200145\
        310466746167843382176c61f07965720a06530335001700680863616e066b6d656d6fd3000f02196f66840a2c066f8513fa\
        2c854c2c864a86bd83778220850def04a90028044e835e2c0a65800e02077b020201b8760019820106a901b720bf818b036c\
        85948656403244180a424cc70274c51704216d6163c33cc116e22c445661640a4689052d424c4fc5450303821f4348666946\
        872c67c419810407526163873f412b2c0fc134c41bc25d42106d66";
    const V_MULTI_OUT: (usize, u32) = (8956, 0xcf669171);
    const V_RLE: &str = "\
        03b00261fc0f03b00262fc0f04b00461622310";
    const V_RLE_OUT: (usize, u32) = (8232, 0xb8e239b4);
    const V_SHORT_FIRST: &str = "\
        f7b1006d6f64756c652069806d61676520666900a000736572766963650a0076616c75650a6f62006a656374207468720065\
        616420726567690073747279206d6674002070726f6365737380206b65726e656c000c8079206c696e7578052000706f6f6c\
        0a706c750067696e2064726976006572206d6163206400756d702070687973006963616c207669721c74750007012c060c6d\
        656d006f72792c20766f6c806174696c697479080a000a6f666673657420c077696e646f77067e015aa27600a27461670599\
        0a04751f06b501a2042e059003fe73796dee62803f812103580a8482871d04180987432c200444616e642c8020746f6b656e\
        0a03a3e1851d736f636b800f03030546fd031168001a803b01568101859b0633ef8380820d8573810568000e879280c1ff05\
        0e05398898865c032e8302003b85805903086f66c76243410a428174b4686506060a0a50c2852c8689ff044103398005c33c\
        c455848dc1550392ffc074810f834b011f03024489846183a1e863616ec03c628002c5a00040fb400c83460a8291435dc38e\
        88a70407fb031fc02c2c044ec7908237c4afc114fb002883467945300326411582234108ff010d4109c4680750c11f443c04\
        768109ffc30782224430040e8439400e82250239ff05ca420445264577c38c411244328224ffc217823a4155c0a08356c68b\
        0230841c006f98b6008e0d97b732c5e94902f30800bfa2249a339620deea00001702001d1050a432598814306b0000009121\
        00181818163681811d7b84411c0600e6b5e5120d0e18b3a6ee228419007a027b000f03cecda71a9dad80200000b2c396c408\
        33524701001fff08175b05003700978fe41d4fcdca07809f551ef1035890010e0b105e076bda02006b597f8d010400ea174c\
        7da9000000f05e3c9299000062841ea803002987dddd235d02110600f8a7dbf64307082e4f360500bd06f56b085e015b8c58\
        8afe000041064da66500003f0800000061a00000b8f03ffb10d217774c5c302deb6a000000e3540000b0e7089e9e9edd29b8\
        646c008c00ce06001309db50034332a070d44ef98402001d06000cca48c231573022bc15b310752ab147002ac2b9008000a0\
        f30000e57ddd25080000690200487b0000003ee986cbcb91260058006b7e4a08c242f1030080704d0000b902005f160300d5\
        028fc0187f53e2ea642141950830392629f1c402a580ea1b58b95b9bbe5c150101a597bbcb6d0fa689002547de0e5b2fd65c\
        60a54b00007105008c0bad0269860123e9f0edbf5e02ab111530396d6db89c00f20bb0cc27cbb5e98069cbc4eee2245c0300\
        122d800ba12d0c0f2a3792408f5241f163f80d092bd0c10000190600320200110e0000000db92c00004ec0d68f1838aca533\
        0415002e3103005c09da164305002ea704bf4bef07fda3afa00ac31f111f0000001e3f7f0401003805e1e013035f1d3e291d\
        6100b601c1e11a3fb30508d6ebbb0100f43b000001615aa05fb877321e6e002b5a5f0000b5d3001800fe76c03708008f2b00\
        0000c174ec3a9c23a7801f2644e750f122a10200a0498abe0ef9d9bfc8e84c7ca7089666520f11003081ae3e61bf04090091\
        070072cde526a8175f18007643534ac0076c180443d8511da188ecad008000a6373737ecbb7509102f4e3c01070006f3ffaa\
        08a07382e01ec2050037a21c01130f0c1e20a5fdc35d81209675b604971d68b50c610b003326f0d6bf0403006f2d46eb0d02\
        008294a5080090417b9f0803009700900a00d71b4f0117005ff15600005851a610eaeb720c9301d2170700adcedadb000087\
        1f00a88f307f0d27583a08d5c7ac940395d36b5f20d5dddc8c55d3000203064e0f095609f64ede2d8f0102009df6c78fe642\
        760020680dc78d95c8a670ab97d7340800df0301007c010400dd6b03ef3cf8eb02cadb014d632b2578b4f0221a0db69f030f\
        000100750db8c9eb111f1100004601bd03000afd0500a40200fa58e7bb0019ae243c635e7cd200a5d1a0f8755674ce04e1f7\
        2b06296d0000200424aa2b095e982530b264b2230500e473728409000b30c8f6c8d3806e0d00ec812820f6244c054b010076\
        dc00e3b5b18dfce87b63406363ff32281138039500bd0000e0ed00008360cd472077843f050400887b4f0c0000f230750f00\
        0900000c3b10e336a46d01007b29e0009fc7a4b76dffda2e207ad3d3bad57902aed100f5c0de8f49a1b14f007ce3954deee4\
        369a02e30200818d159180af2c2c9d9f05050087f104398cc0dd26920306e2ef010f0040187b1192575a4c017401306b780e\
        0000cf450000009f82af4eed0c4a8359120a006deb309d54cf09010200c9436ac1dbd51748cfbb17b053fe330400f2004bf9\
        f114bb389e8cc02124c19d341e70560f00010f000000379a293cb800a37e1fd6a7bcd10c403d971cb72ad24f0218c07b4a19\
        347c202f12000000e905ddde591215f70497e037006600852a538327021f0b33332e86d42001036f0862086ff4a11062a500\
        58e0c45feb696a92ffe0230f000f0001004f0649060800f4060b8f010a00c4fc0009931e1a0097b4965a1919b41a83e38d0f\
        0000e40c6bf600a1030f0008003bcbd262b0fb08ad52959e019b2273d900f1be0c0e967e57ea80293ec0ba5377d101000849\
        49495f0413b87c1c083705f6700a42a3a4d1003600009ad29ec9695e4318020d0c0f000100a4165309209347fb2197745e91\
        b70072fb3fb91375000080464c00001f1fd4906f11d69e7171a108004a1d407086b0b079a0020f000300e700cdfc444c36a0\
        3c41407c0a18b695b560c42c00f8487a5a86408ae00903002516a03ce2c47296d87f92c36f096509504fb00e000050936ec5\
        99228a503cc39304003c040000a50d8da800a761bacedea2da0390ad36baae030902a1c04dc049ebebeb711bff04fa040af4\
        600ca7010032eaa3880002c8d1e2fbc653eba53010be10bb90f4a07a478607fe2b0400df03d20340530300df0c0f008d0f00\
        845f550f0000004401001c1429b200df0dda0d00646480d2fb2353bafd516f04010d00190b5276e63f71032f0d2d0d313076\
        616420766f6c6174696c6974792c206d656d6f727920616e64206d6f64756c65207669727475616c20736f636b65742077";
    const V_SHORT_FIRST_OUT: (usize, u32) = (5146, 0x1bb8a1d4);
    const V_BINARY: &str = "\
        01b680db8d908d74670012000011a0048fa97867cec0f245326333ca06000988da220800170400012e3a0000074a3a2e0006\
        35050013d6060080e60000000af20000d37f0800004005005514000000ee010000feb6349fa03324247370072f420b21884b\
        5926016d0000781c670119009ff4000094180000007794da21ce94ea01060091182cf840000000c48c854a2cca7cee00d9b9\
        748860b20c4d01ae2f322454b98a4b2c00f32d3bb1f082fdb7b0fad5b862057b3300fd0200c04646c6c64aadb5210e002620\
        06009e0a17cfd3054c2e00da5b8ae858303030039e10110030b2cb10288458837fda9f12853ef10500da00932f4ae0d30739\
        dd00e49c4823e118964180617622dcd30c2dd00e0038f3442d6aa52beff80000fa007e0e00d04161040e0081db31d4d80000\
        cf560c23a4b61c51113cf7c001e940320cff5e571b40146fa2be984126a798650000a508008f0c8fcf00005a06aea1000000\
        1c05ba46806d0600106a000088070026b80f00cef919e6b84d77d3010000b5846be22ebb51d0e2cac3ec0500da0700520b00\
        a8a50000a0f3eedf082aea3b000140c1e36e0ef80d05d424ac0e0a321ad340245ec6c71b3d0700340250561a13153fdc1394\
        00b515437d42d874d400362727278e8e8e279ba00c0a00e308007b1af51d208909cd09b4c7f60f0000e184054e024e08000a\
        d581c2c334149f3304fe050031029a3e41cd1bef0e00009700000530f65ad48c58120a00371fa056632671483c0153080000\
        2df28e4ffe3d2b14d01b00008b0800d206009f0e2102000a481712c00028d600ac3d925ab79000008875285180561111fa07\
        008076ab3cc82ba83f8250003be30000f8a28d520238150a4471e692da4008ee4a0d07001beae5dd710700b9d5eefa0f2e02\
        6f09b4009cde2e3226dbb19deb93195410800800d80000351805000223000081b7c23292d2060d0071a9129d9de3f91d0016\
        f13b4126e287f00014b068b732de1451e4d29b03c6fdb796053f0606004119035b5400006e0800e200c60b9430bf9cf90084\
        0029060048e40000cf0702e203001f6c54d73762006a1df4dc7aecfdd300d9007db72baf42ef1ae60100debf05b105866100\
        0000587cd89da3e1144e15bf0b860e2f0b00e6d02214001414c85b223d14c3c056366269b885cf0c0600037f0fa502159c00\
        00df2202103058d8ffcf6240ba7c32c80000bf02b102df130e0071001854d6db38fc6f470eeabf010f0003001c57ec64045f\
        6b2a019e783d9c210063d5aa3b0d5e02b62094b268a6c4040033c09000008f4a8065f9d77e04177d1171530100dc7070bd66\
        0a00adb8ddb74ed5d5d5a5c302d60300a80c6e04711f0a837f0d000004c9b378858f99f103005a018a4f0107005f045f0165\
        5c01730300185ddf04080098d7060037017a11eba020cd070068118064d5b78669013bb07c0b01009203593055a7a7d6f7c0\
        0cefa97d8e660800c70570ccb206de5e08ef0b56016b006b6b72bdd67bdf000000f7dbc15bf07ca5b8ec03c5f01c0f000c00\
        dd804f7e3b0100a20ace0c1f0c110cf682f3e24a810654d3e0df0dd00dd200c03feeed4b9f7d9f630f00070f000f000100f3\
        0f2ec6b600ab62059505a8a0e3307700001005003f0216d300d84cb0c7092c13760130291cfa6a689b58de0cecac30660500\
        5b3f0000006aba7bfcb20000c20694600ba00161db6b455038c2e5a4703e0f00060073f2b0c2026073a200f40ece0000e0c8\
        e25a146406005f030f003800eb753f010f0003005afb61e0ce5c5c5c76af010e00e2f0160000216f010f000600bf1001b010\
        22d683160beffb10333ecc2831028dcd000075c19a779fc89d0100798c6c26bd0000d9481a00001f01c1bf0800720272d7d1\
        ea0e09842ee440b030afc10bd79ecc62dec9e0268444090048a388df010f00050700040400e108f340de1876694c04005c02\
        f4f4d50007ec6075734b636b803a8a9163f8ea6f9f04850a004ce5889a161cbfff0380ea6f91e3e23649b07e80fa7ef607c3\
        01d41f04010e001e8cbb950e488d0104007e0222595959c100c13a0e1566d15a300676bf040000c7ef06950d00ea1386d6f3\
        7f859d00e7ff5c4303528ee906b6af050a067033822a2a18283e3740c290b9696936039f021d0602";
    const V_BINARY_OUT: (usize, u32) = (4096, 0x9cb6bb66);
    const V_SHORT_FIRST_PADDED: (usize, u32) = (8242, 0x13066434);

    fn unhex(s: &str) -> Vec<u8> {
        let s: Vec<u8> = s.bytes().filter(|b| b.is_ascii_hexdigit()).collect();
        s.chunks(2).map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap()).collect()
    }

    fn crc(data: &[u8]) -> (usize, u32) {
        (data.len(), crate::codecs::crc::crc32(data))
    }

    /// xorshift64* for reproducible test data.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    // ---------------------------------------------------------------------------------------
    // Reference models (safe, byte at a time) the fast paths are compared against.
    // ---------------------------------------------------------------------------------------

    /// Whole-stream model of `decompress` (pad = false) / `decompress_padded` (pad = true).
    fn model(data: &[u8], pad: bool) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        let mut ip = 0;
        while data.len() - ip >= 2 {
            let h = u16::from_le_bytes([data[ip], data[ip + 1]]) as usize;
            if h == 0 {
                break;
            }
            let size = (h & 0xFFF) + 1;
            let chunk = data.get(ip + 2..ip + 2 + size)?;
            ip += 2 + size;
            if pad && out.len() % CHUNK_SIZE != 0 {
                out.resize(out.len().next_multiple_of(CHUNK_SIZE), 0);
            }
            if h & 0x8000 != 0 {
                let mut w = [0u8; CHUNK_SIZE];
                let n = decode_chunk_ref(chunk, &mut w).ok()?;
                out.extend_from_slice(&w[..n]);
            } else {
                out.extend_from_slice(chunk);
            }
        }
        Some(out)
    }

    /// Model of `decompress_buffer` with an `cap`-byte buffer (Wine's loop, Windows match rule).
    fn model_buffer(data: &[u8], cap: usize) -> Option<Vec<u8>> {
        if data.len() < 2 {
            return None;
        }
        let mut out = Vec::new();
        let mut ip = 0;
        while data.len() - ip >= 2 {
            let h = u16::from_le_bytes([data[ip], data[ip + 1]]) as usize;
            if h == 0 {
                break;
            }
            let size = (h & 0xFFF) + 1;
            let chunk = data.get(ip + 2..ip + 2 + size)?;
            ip += 2 + size;
            if out.len() % CHUNK_SIZE != 0 {
                let fill = CHUNK_SIZE - out.len() % CHUNK_SIZE;
                if out.len() + fill >= cap {
                    break;
                }
                out.resize(out.len() + fill, 0);
            }
            if out.len() >= cap {
                break;
            }
            let room = cap - out.len();
            if h & 0x8000 != 0 {
                let mut w = vec![0u8; room.min(CHUNK_SIZE)];
                let n = decode_chunk_ref(chunk, &mut w).ok()?;
                out.extend_from_slice(&w[..n]);
            } else {
                out.extend_from_slice(&chunk[..size.min(room)]);
            }
        }
        Some(out)
    }

    /// Runs every public entry point on `data` and checks them against the models; never
    /// panics on malformed input.
    fn check_all(data: &[u8]) -> Option<Vec<u8>> {
        let got = decompress(data).ok();
        assert_eq!(got, model(data, false), "decompress vs model");
        assert_eq!(decompress_padded(data).ok(), model(data, true), "decompress_padded vs model");
        let mut v = vec![7u8; 3];
        let r = decompress_into(data, &mut v);
        assert_eq!(r.is_ok(), got.is_some());
        if let Some(g) = &got {
            assert_eq!(&v[..3], &[7, 7, 7]);
            assert_eq!(&v[3..], &g[..]);
        }
        let full = model(data, true).map(|v| v.len()).unwrap_or(0);
        for cap in [0, 1, 100, 4095, 4096, 4097, full.saturating_sub(1), full, full + 40] {
            let mut buf = vec![0xA5u8; cap + 64];
            let r = decompress_buffer(data, &mut buf[..cap]);
            let m = model_buffer(data, cap);
            match (&r, &m) {
                (Ok(n), Some(m)) => {
                    assert_eq!(&buf[..*n], &m[..], "decompress_buffer({cap}) output");
                    assert!(buf[*n..].iter().all(|&b| b == 0xA5), "wrote past the returned size");
                }
                (Err(_), None) => {}
                _ => panic!("decompress_buffer({cap}) = {r:?}, model {:?}", m.map(|m| m.len())),
            }
        }
        got
    }

    // ---------------------------------------------------------------------------------------
    // Test-only encoder.
    // ---------------------------------------------------------------------------------------

    /// Emits the items of one compressed chunk by hand.
    struct Enc {
        body: Vec<u8>,
        flag_at: usize,
        items: usize,
        pos: usize,
    }
    impl Enc {
        fn new() -> Enc {
            Enc { body: Vec::new(), flag_at: 0, items: 8, pos: 0 }
        }
        fn slot(&mut self, token: bool) {
            if self.items == 8 {
                self.flag_at = self.body.len();
                self.body.push(0);
                self.items = 0;
            }
            if token {
                self.body[self.flag_at] |= 1 << self.items;
            }
            self.items += 1;
        }
        fn lit(&mut self, b: u8) {
            self.slot(false);
            self.body.push(b);
            self.pos += 1;
        }
        /// Token for (offset, length); both must be encodable at the current position.
        fn tok(&mut self, off: usize, len: usize) {
            let bits = 4usize.max((usize::BITS - (self.pos - 1).leading_zeros()) as usize);
            assert!(off >= 1 && off <= 1 << bits && len >= 3 && len - 3 <= 0xFFFF >> bits);
            self.slot(true);
            let t = (((off - 1) << (16 - bits)) | (len - 3)) as u16;
            self.body.extend_from_slice(&t.to_le_bytes());
            self.pos += len;
        }
        fn raw_token(&mut self, t: u16) {
            self.slot(true);
            self.body.extend_from_slice(&t.to_le_bytes());
        }
        /// The chunk (header + body).
        fn chunk(&self) -> Vec<u8> {
            assert!(!self.body.is_empty() && self.body.len() <= 4096);
            let mut v = (0xB000u16 | (self.body.len() - 1) as u16).to_le_bytes().to_vec();
            v.extend_from_slice(&self.body);
            v
        }
    }

    #[derive(Clone, Copy)]
    enum Strategy {
        /// Longest match, nearest first.
        Greedy,
        /// Random candidates, random shortened lengths, random literals instead of matches.
        Random,
        /// Literals only.
        Literal,
    }

    /// Compressed body of one chunk (hash chains on 3-byte prefixes).
    fn compress_chunk(chunk: &[u8], strategy: Strategy, rng: &mut Rng) -> Vec<u8> {
        fn hash(c: &[u8], p: usize) -> usize {
            ((c[p] as usize) << 16 | (c[p + 1] as usize) << 8 | c[p + 2] as usize).wrapping_mul(2654435761) >> 20 & 0xFFF
        }
        fn insert(c: &[u8], head: &mut [usize], prev: &mut [usize], p: usize) {
            if p + 3 <= c.len() {
                let h = hash(c, p);
                prev[p] = head[h];
                head[h] = p;
            }
        }
        let n = chunk.len();
        let mut head = vec![usize::MAX; 1 << 12];
        let mut prev = vec![usize::MAX; n];
        let mut e = Enc::new();
        while e.pos < n {
            let pos = e.pos;
            let mut best: Option<(usize, usize)> = None;
            if !matches!(strategy, Strategy::Literal) && pos > 0 && pos + 3 <= n {
                let bits = 4usize.max((usize::BITS - (pos - 1).leading_zeros()) as usize);
                let max_len = ((0xFFFF >> bits) + 3).min(n - pos);
                let mut cands = Vec::new();
                let mut c = head[hash(chunk, pos)];
                let mut depth = 0;
                while c != usize::MAX && depth < 48 {
                    let len = (0..max_len).take_while(|&k| chunk[c + k] == chunk[pos + k]).count();
                    if len >= 3 {
                        cands.push((pos - c, len));
                    }
                    c = prev[c];
                    depth += 1;
                }
                if !cands.is_empty() {
                    best = match strategy {
                        Strategy::Random if rng.below(5) == 0 => None,
                        Strategy::Random => {
                            let (off, len) = cands[rng.below(cands.len())];
                            Some((off, 3 + rng.below(len - 2)))
                        }
                        _ => cands.iter().copied().max_by_key(|&(off, len)| (len, usize::MAX - off)),
                    };
                }
            }
            match best {
                Some((off, len)) => {
                    e.tok(off, len);
                    for p in pos..pos + len {
                        insert(chunk, &mut head, &mut prev, p);
                    }
                }
                None => {
                    e.lit(chunk[pos]);
                    insert(chunk, &mut head, &mut prev, pos);
                }
            }
        }
        e.body
    }

    /// LZNT1 stream: chunk input sizes from `size_of(k)`, chunk `k` stored when `raw(k)` or
    /// when compression does not help.
    fn compress(
        data: &[u8],
        strategy: Strategy,
        rng: &mut Rng,
        size_of: &dyn Fn(usize) -> usize,
        raw: &dyn Fn(usize) -> bool,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        let mut pos = 0;
        let mut k = 0;
        while pos < data.len() {
            let chunk = &data[pos..(pos + size_of(k)).min(data.len())];
            let body = compress_chunk(chunk, strategy, rng);
            if !raw(k) && body.len() <= 4096 && (body.len() < chunk.len() || matches!(strategy, Strategy::Literal)) {
                out.extend_from_slice(&(0xB000u16 | (body.len() - 1) as u16).to_le_bytes());
                out.extend_from_slice(&body);
            } else {
                out.extend_from_slice(&(0x3000u16 | (chunk.len() - 1) as u16).to_le_bytes());
                out.extend_from_slice(chunk);
            }
            pos += chunk.len();
            k += 1;
        }
        out
    }

    fn gen_data(rng: &mut Rng, kind: usize, n: usize) -> Vec<u8> {
        const WORDS: &[&str] =
            &["the ", "process ", "thread ", "handle ", "kernel ", "pool ", "tag ", "0x", "ff", "\n", ", ", "vad "];
        let mut v = Vec::with_capacity(n + 64);
        while v.len() < n {
            match (kind, rng.below(8)) {
                (0, _) => v.extend_from_slice(WORDS[rng.below(WORDS.len())].as_bytes()),
                (1, 0..=1) => v.extend(std::iter::repeat_n(0u8, 1 + rng.below(64))),
                (1, 2..=3) if v.len() > 8 => {
                    let d = 1 + rng.below(v.len().min(600));
                    for _ in 0..3 + rng.below(40) {
                        v.push(v[v.len() - d]);
                    }
                }
                (1, 4) => v.extend(std::iter::repeat_n(rng.next() as u8, 1 + rng.below(20))),
                (1, _) => v.extend_from_slice(&rng.next().to_le_bytes()[..1 + rng.below(8)]),
                (2, _) => v.push(rng.next() as u8),
                _ => v.extend(std::iter::repeat_n(b"ab"[rng.below(2)], 1 + rng.below(3000))),
            }
        }
        v.truncate(n);
        v
    }

    // ---------------------------------------------------------------------------------------
    // Known vectors.
    // ---------------------------------------------------------------------------------------

    #[test]
    fn codecs_lznt1_ruby_smb_spec_vectors() {
        assert_eq!(decompress(b"\x06\x30RubySMB").unwrap(), b"RubySMB");
        assert_eq!(decompress(b"\x03\xB0\x02\x01\xFC\x01").unwrap(), vec![1u8; 0x200]);
        check_all(b"\x03\xB0\x02\x01\xFC\x01");
    }

    /// Wine's RtlDecompressBuffer conformance table (dlls/ntdll/tests/rtl.c), run against
    /// real Windows by Wine: (stream, expected output or None for STATUS_BAD_COMPRESSION_BUFFER).
    #[test]
    fn codecs_lznt1_wine_conformance_vectors() {
        let cases: &[(&[u8], Option<&[u8]>)] = &[
            (b"\x03\x30Wine", Some(b"Wine")),
            (b"\x07\x30WineWine", Some(b"WineWine")),
            (b"\x04\xB0\x00Wine", Some(b"Wine")),
            (b"\x08\xB0\x00WineWine", Some(b"WineWine")),
            (b"\x06\xB0\x10Wine\x01\x30", Some(b"WineWine")),
            (b"\x06\xB0\x10Wine\x05\x30", Some(b"WineWineWine")),
            (b"\x06\xB0\x30Wine\x01\x30", Some(b"WineWine")),
            (b"\x01\xB0\x02W", Some(b"W")),
            (b"\x03\x30Wine\x00\x00\x03\x30Wine", Some(b"Wine")),
            (b"\x14\xB0\x00ABCDEFGH\x00IJKLMNOP\x01\x01\xF0", Some(b"ABCDEFGHIJKLMNOPABCD")),
            (b"\x15\xB0\x00ABCDEFGH\x00IJKLMNOP\x02A\x00\x78", Some(b"ABCDEFGHIJKLMNOPABCD")),
            (b"\x03\x20Wine", Some(b"Wine")),
            (b"\x04\xA0\x00Wine", Some(b"Wine")),
            (b"\x00\xB0\x02\x01", Some(b"")),
            (b"\x00\xB0\x00", Some(b"")),
            (b"\x00\xB0\x01", Some(b"")),
            (b"", None),
            (b"\x01", None),
            (b"\x00\x30", None),
            (b"\x06\xB0\x10Wine\x05\x40", None),
            (b"\x05\xB0\x10Wine\x05", None),
            (b"\x07\x30Wine", None),
            (b"\x08\xB0\x00Wine", None),
            (b"\x00\xB0\x02\x00\xB0", None),
        ];
        for (i, &(input, want)) in cases.iter().enumerate() {
            let mut buf = [0x11u8; 0x2000];
            match (decompress_buffer(input, &mut buf), want) {
                (Ok(n), Some(w)) => {
                    assert_eq!(&buf[..n], w, "case {i}");
                    assert_eq!(buf[n], 0x11, "case {i}: wrote past the end");
                }
                (Err(_), None) => {}
                (r, w) => panic!("case {i}: got {r:?}, want {w:?}"),
            }
            // Exactly sized and one byte short (Windows: literals/stored bytes are cut, a match
            // that does not fit is an error).
            if let Some(w) = want.filter(|w| !w.is_empty()) {
                let mut exact = vec![0x11u8; w.len() + 1];
                assert_eq!(decompress_buffer(input, &mut exact[..w.len()]).unwrap(), w.len(), "case {i}");
                assert_eq!(&exact[..w.len()], w);
                let mut short = vec![0x11u8; w.len()];
                let r = decompress_buffer(input, &mut short[..w.len() - 1]);
                let broken_on_windows = [4, 5, 6, 9, 10].contains(&i); // DECOMPRESS_BROKEN_TRUNCATED
                if broken_on_windows {
                    assert!(r.is_err(), "case {i}: match past the buffer end must fail");
                } else {
                    assert_eq!(r.unwrap(), w.len() - 1, "case {i}");
                    assert_eq!(&short[..w.len() - 1], &w[..w.len() - 1]);
                    assert_eq!(short[w.len() - 1], 0x11);
                }
            }
            // `decompress` agrees except for the inputs shorter than a header, which it accepts.
            match (decompress(input), want) {
                (Ok(v), Some(w)) => assert_eq!(v, w, "case {i}"),
                (Ok(v), None) => assert!(input.len() < 2 && v.is_empty(), "case {i}"),
                (Err(_), None) => {}
                (r, w) => panic!("case {i}: decompress {r:?}, want {w:?}"),
            }
            check_all(input);
        }
    }

    #[test]
    fn codecs_lznt1_generated_vectors() {
        for (stream, want) in [(V_TEXT, V_TEXT_OUT), (V_RANDOMIZED, V_RANDOMIZED_OUT), (V_RUBY, V_RUBY_OUT)] {
            let stream = unhex(stream);
            assert_eq!(decompress(&stream).unwrap(), unhex(want));
            check_all(&stream);
        }
        for (stream, want) in [
            (V_MULTI, V_MULTI_OUT),
            (V_RLE, V_RLE_OUT),
            (V_SHORT_FIRST, V_SHORT_FIRST_OUT),
            (V_BINARY, V_BINARY_OUT),
        ] {
            let stream = unhex(stream);
            assert_eq!(crc(&decompress(&stream).unwrap()), want);
            check_all(&stream);
        }
        // A short chunk followed by another one: Windows layout pads it to 4096 bytes.
        let s = unhex(V_SHORT_FIRST);
        let padded = decompress_padded(&s).unwrap();
        assert_eq!(crc(&padded), V_SHORT_FIRST_PADDED);
        let plain = decompress(&s).unwrap();
        assert_eq!(&padded[..1000], &plain[..1000]);
        assert!(padded[1000..4096].iter().all(|&b| b == 0));
        assert_eq!(&padded[4096..], &plain[1000..]);
        let mut unit = vec![0xEEu8; 3 * 4096];
        let n = decompress_buffer(&s, &mut unit).unwrap();
        assert_eq!(&unit[..n], &padded[..]);
    }

    // ---------------------------------------------------------------------------------------
    // Hand-built chunks: every offset/length split, overlaps, limits, errors.
    // ---------------------------------------------------------------------------------------

    /// A match with the largest offset and length encodable right at and after each split
    /// boundary (pos = 16, 17, 32, 33, ... 2048, 2049), plus overlapping copies at every
    /// short offset.
    #[test]
    fn codecs_lznt1_every_split_width() {
        let mut rng = Rng(42);
        for bound in [16usize, 32, 64, 128, 256, 512, 1024, 2048] {
            for pos in [bound - 1, bound, bound + 1, bound + 2] {
                for pick in 0..3 {
                    let mut e = Enc::new();
                    let mut want = Vec::new();
                    while e.pos < pos {
                        let b = rng.next() as u8;
                        e.lit(b);
                        want.push(b);
                    }
                    let bits = 4usize.max((usize::BITS - (pos - 1).leading_zeros()) as usize);
                    let max_len = ((0xFFFF >> bits) + 3).min(CHUNK_SIZE - pos);
                    let (off, len) = match pick {
                        0 => (pos, max_len),
                        1 => (1 + rng.below(pos), 3 + rng.below(max_len - 2)),
                        _ => (1 + rng.below(pos.min(20)), max_len),
                    };
                    e.tok(off, len);
                    for _ in 0..len {
                        want.push(want[want.len() - off]);
                    }
                    for _ in 0..rng.below(40).min(CHUNK_SIZE - e.pos) {
                        let b = rng.next() as u8;
                        e.lit(b);
                        want.push(b);
                    }
                    let c = e.chunk();
                    assert_eq!(decompress(&c).unwrap(), want, "pos {pos} off {off} len {len}");
                    check_all(&c);
                }
            }
        }
        // Overlapping copies (offset < length) at every short offset and many lengths, from
        // every alignment of the output position.
        for start in 1..24usize {
            for off in 1..=start.min(20) {
                for len in [3usize, 4, 7, 8, 9, 15, 16, 17, 31, 33, 100, 1000] {
                    let mut e = Enc::new();
                    let mut want = Vec::new();
                    for _ in 0..start {
                        let b = rng.next() as u8;
                        e.lit(b);
                        want.push(b);
                    }
                    let bits = 4usize.max((usize::BITS - (start - 1).leading_zeros()) as usize);
                    if len - 3 > 0xFFFF >> bits {
                        continue;
                    }
                    e.tok(off, len);
                    for _ in 0..len {
                        want.push(want[want.len() - off]);
                    }
                    e.lit(b'!');
                    want.push(b'!');
                    let c = e.chunk();
                    assert_eq!(decompress(&c).unwrap(), want, "start {start} off {off} len {len}");
                }
            }
        }
    }

    #[test]
    fn codecs_lznt1_chunk_limits() {
        // One literal + a 4095-byte run fills the chunk exactly; a trailing flag byte without
        // items is fine; one more literal (or match byte) is an overflow.
        let mut e = Enc::new();
        e.lit(b'x');
        e.tok(1, 4095);
        assert_eq!(decompress(&e.chunk()).unwrap(), vec![b'x'; 4096]);
        let mut full = Enc::new();
        for i in 0..7 {
            full.lit(i);
        }
        full.tok(1, 4089); // the 8th item ends exactly at 4096
        let mut fl = full.chunk();
        fl.push(0xFF); // a flag byte with no items after it
        fl[0] += 1;
        assert_eq!(decompress(&fl).unwrap().len(), 4096);
        let mut over = Enc::new();
        over.lit(b'x');
        over.tok(1, 4095);
        over.lit(b'y');
        assert!(decompress(&over.chunk()).is_err());
        // Overflow detected in the unchecked group path: a full group of literals past 4096
        // followed by enough input to stay on the fast path.
        let mut fast = Enc::new();
        fast.lit(b'x');
        fast.tok(1, 4095);
        for i in 0..40 {
            fast.lit(i);
        }
        assert!(decompress(&fast.chunk()).is_err());
        let mut m = Enc::new();
        m.lit(0);
        m.tok(1, 4089);
        m.tok(1, 18); // 4090 + 18 > 4096
        assert!(decompress(&m.chunk()).is_err());
        // Largest literal-only compressed chunk: 3640 literals + 455 flag bytes = 4095 bytes.
        let mut l = Enc::new();
        for i in 0..3640 {
            l.lit(i as u8);
        }
        assert_eq!(decompress(&l.chunk()).unwrap(), (0..3640).map(|i| i as u8).collect::<Vec<_>>());
        // Full-size stored chunk, and two chunks + terminator + garbage.
        let mut raw = vec![0xFF, 0x3F];
        raw.extend((0..4096).map(|i| (i * 7) as u8));
        assert_eq!(decompress(&raw).unwrap(), &raw[2..]);
        let mut two = raw.clone();
        two.extend_from_slice(&e.chunk());
        two.extend_from_slice(&[0, 0, 0xFF, 0xFF, 1, 2, 3]);
        let out = decompress(&two).unwrap();
        assert_eq!(out.len(), 8192);
        assert_eq!(decompress_padded(&two).unwrap(), out);
        check_all(&two);
    }

    #[test]
    fn codecs_lznt1_errors() {
        // Token as the first item / offset past the chunk start.
        let mut e = Enc::new();
        e.raw_token(0);
        assert!(decompress(&e.chunk()).is_err());
        let mut e = Enc::new();
        e.lit(1);
        e.lit(2);
        e.raw_token(0x2000); // offset 3 at pos 2
        assert!(decompress(&e.chunk()).is_err());
        // Back-references never reach the previous chunk.
        let mut a = Enc::new();
        for i in 0..10 {
            a.lit(i);
        }
        let mut s = a.chunk();
        let mut b = Enc::new();
        b.lit(0);
        b.raw_token(0x3000); // offset 4 at pos 1
        s.extend_from_slice(&b.chunk());
        assert!(decompress(&s).is_err());
        // Token cut by the chunk end (inside a longer input), in the fast and the tail path.
        for pre in [2usize, 60] {
            let mut e = Enc::new();
            for i in 0..pre {
                e.lit(i as u8);
            }
            e.slot(true);
            e.body.push(0x01);
            let mut s = e.chunk();
            s.extend_from_slice(&[0x02, 0x30, 1, 2, 3]);
            assert!(decompress(&s).is_err());
        }
        // Truncated chunks.
        assert!(decompress(b"\x05\x30abc").is_err());
        assert!(decompress(b"\x05\xB0\x00ab").is_err());
        // Error messages carry the chunk offset.
        let msg = decompress(b"\x03\x30abcd\x05\x30abc").unwrap_err().to_string();
        assert!(msg.contains("offset 6"), "{msg}");
    }

    // ---------------------------------------------------------------------------------------
    // Round trips through the test encoder, differential and fuzz tests.
    // ---------------------------------------------------------------------------------------

    #[test]
    fn codecs_lznt1_round_trip() {
        let mut rng = Rng(0x1234_5678);
        let lens = [0usize, 1, 2, 3, 15, 16, 17, 100, 4095, 4096, 4097, 8192, 10000, 20000];
        for kind in 0..4 {
            for (i, &n) in lens.iter().enumerate() {
                let data = gen_data(&mut rng, kind, n);
                let strategy = [Strategy::Greedy, Strategy::Random, Strategy::Literal][i % 3];
                let seed = rng.next();
                // Full chunks (Windows layout): all three decoders agree.
                let s = compress(&data, strategy, &mut Rng(seed), &|_| 4096, &|k| k % 5 == 4);
                assert_eq!(decompress(&s).unwrap(), data, "kind {kind} len {n}");
                assert_eq!(decompress_padded(&s).unwrap(), data);
                let mut buf = vec![0u8; n];
                assert_eq!(decompress_buffer(&s, &mut buf).map_err(|_| ()), if s.len() < 2 { Err(()) } else { Ok(n) });
                assert_eq!(buf, data);
                check_all(&s);
                // Arbitrary chunk sizes: only the unpadded layout reproduces the input.
                let sizes: Vec<usize> = (0..64).map(|_| 1 + rng.below(4096)).collect();
                let s = compress(&data, strategy, &mut Rng(seed), &|k| sizes[k % 64], &|k| k % 7 == 3);
                assert_eq!(decompress(&s).unwrap(), data, "kind {kind} len {n} (short chunks)");
                check_all(&s);
            }
        }
    }

    /// The unchecked chunk decoder against the byte-at-a-time one on random chunk bodies
    /// (biased towards valid tokens so that long streams of items survive).
    #[test]
    fn codecs_lznt1_fast_matches_reference() {
        let mut rng = Rng(99);
        let mut tmp = vec![0u8; CHUNK_SIZE + SLACK];
        let mut agree_ok = 0;
        for iter in 0..20000 {
            let len = 1 + rng.below(if iter % 4 == 0 { 4096 } else { 200 });
            let mut body = Vec::with_capacity(len);
            while body.len() < len {
                let r = rng.next();
                body.push(match iter % 3 {
                    0 => r as u8,
                    1 => (r as u8) & 0x07,  // mostly-literal flags, small tokens
                    _ => [0x00, 0xFF, 0x01, 0x10, 0x80, r as u8][rng.below(6)],
                });
            }
            let mut w = [0u8; CHUNK_SIZE];
            let want = decode_chunk_ref(&body, &mut w);
            // SAFETY: tmp holds CHUNK_SIZE + SLACK bytes.
            let got = unsafe { decode_chunk_fast(&body, tmp.as_mut_ptr()) };
            match (want, got) {
                (Ok(a), Ok(b)) => {
                    assert_eq!(a, b);
                    assert_eq!(&w[..a], &tmp[..b], "iter {iter}");
                    agree_ok += 1;
                }
                (Err(_), Err(_)) => {}
                (a, b) => panic!("iter {iter}: reference {a:?}, fast {b:?}"),
            }
        }
        assert!(agree_ok > 1000, "too few valid chunks ({agree_ok})");
    }

    #[test]
    fn codecs_lznt1_fuzz_never_panics() {
        let mut rng = Rng(7);
        let mut seeds = vec![
            unhex(V_TEXT),
            unhex(V_MULTI),
            unhex(V_BINARY),
            unhex(V_SHORT_FIRST),
            unhex(V_RLE),
            b"\x03\xB0\x02\x01\xFC\x01".to_vec(),
        ];
        for kind in 0..4 {
            let data = gen_data(&mut rng, kind, 9000);
            seeds.push(compress(&data, Strategy::Random, &mut Rng(kind as u64 + 1), &|_| 4096, &|_| false));
        }
        for iter in 0..3000 {
            let mut s = seeds[iter % seeds.len()].clone();
            match iter % 4 {
                0 => {
                    for _ in 0..1 + rng.below(4) {
                        let i = rng.below(s.len());
                        s[i] ^= 1 << rng.below(8);
                    }
                }
                1 => {
                    let i = rng.below(s.len());
                    s[i] = rng.next() as u8;
                    s.truncate(rng.below(s.len() + 1));
                }
                2 => {
                    // Random bytes behind a plausible header.
                    let n = rng.below(300);
                    s = (0..n).map(|_| rng.next() as u8).collect();
                    if n >= 2 {
                        s[1] |= 0x80;
                    }
                }
                _ => {
                    let i = rng.below(s.len());
                    let j = rng.below(s.len());
                    s.swap(i, j);
                    if i < s.len() {
                        s.insert(i, rng.next() as u8);
                    }
                }
            }
            check_all(&s);
        }
    }

    /// Hostile headers: thousands of tiny chunks that claim 4096 bytes each must not make the
    /// output reservation fail or linger.
    #[test]
    fn codecs_lznt1_tiny_chunks() {
        let mut s = Vec::new();
        for _ in 0..100_000 {
            s.extend_from_slice(b"\x00\xB0\x00");
        }
        assert_eq!(decompress(&s).unwrap(), b"");
        let mut rle = Vec::new();
        for _ in 0..2_000 {
            rle.extend_from_slice(b"\x03\xB0\x02\x01\xFC\x01");
        }
        let v = decompress(&rle).unwrap();
        assert_eq!(v.len(), 2_000 * 512);
        assert!(v.iter().all(|&b| b == 1));
        let p = decompress_padded(&rle).unwrap();
        assert_eq!(p.len(), 1_999 * 4096 + 512);
    }
}
