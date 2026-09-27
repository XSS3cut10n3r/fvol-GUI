//! A `.xz` ISF decoded while its lazy index reads the part already decoded.
//!
//! python-written ISFs are one xz block of LZMA2 whose chunks never reset the dictionary: the
//! decode is one serial chain (6.7 MB of a Windows kernel ISF: ~16 ms), and the lazy index
//! (the document's structure, then every member of the big sections checked on all cores:
//! 3-5 ms, 15-20 ms for a 64 MB Linux ISF) used to start only after it. Here the decoder
//! publishes its progress after every LZMA2 chunk (<= 2 MiB of output) and the index follows
//! it: the structural pass runs over each newly decoded piece, member ranges go to worker
//! threads as soon as their bytes are there, and only a short tail remains when the decode
//! ends (see `lazy::LazyCore::build_streaming`).
//!
//! Handled: one xz stream of blocks of plain LZMA2 (no BCJ / delta filter; several blocks are
//! decoded in parallel, the progress is the contiguous decoded prefix), CRC32 / CRC64 checks
//! (verified as the codec does; other check types are not verified, like the codec). The
//! container is first validated by the codec's own structural scan
//! (`codecs::xz::uncompressed_size`). Anything else is left to the codec (`plan` says `None`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::codecs::lzma::{LzmaDecoder, Props, RangeDecoder, Stop, lzma2_scan};
use crate::error::{Error, Result};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};

/// Output bytes decoded between two progress reports.
const SLICE: usize = 128 << 10;

fn err(what: &str) -> Error {
    Error::Msg(format!("xz: {what}"))
}

/// One xz block: its LZMA2 data, its check, where its output goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Block {
    data: std::ops::Range<usize>,
    check: std::ops::Range<usize>,
    out: std::ops::Range<usize>,
}

/// The blocks of a `.xz` file [`Decoding`] handles, and the output size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Plan {
    check_type: u8,
    blocks: Vec<Block>,
    pub total: usize,
}

fn read_vli(b: &[u8], at: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    for i in 0..9 {
        let c = *b.get(*at)?;
        *at += 1;
        v |= ((c & 0x7F) as u64) << (7 * i);
        if c & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

/// The plan of `data`: `None` unless it is one valid xz stream of plain LZMA2 blocks.
pub(crate) fn plan(data: &[u8]) -> Option<Plan> {
    // the codec's structural scan validates every header, the index and the footer
    let total = crate::codecs::xz::uncompressed_size(data).ok()?;
    let check_type = data.get(7)? & 0x0F;
    let csize = match check_type {
        0 => 0,
        1..=3 => 4,
        4..=6 => 8,
        7..=9 => 16,
        10..=12 => 32,
        _ => 64,
    };
    let mut blocks = Vec::new();
    let (mut off, mut out) = (12usize, 0usize);
    loop {
        let b = *data.get(off)?;
        if b == 0 {
            break; // the index (the codec checked the rest)
        }
        let hsize = (b as usize + 1) * 4;
        let h = data.get(off..off + hsize)?;
        let flags = h[1];
        if flags & 3 != 0 {
            return None; // a filter chain (BCJ / delta before LZMA2)
        }
        let mut p = 2usize;
        if flags & 0x40 != 0 {
            read_vli(h, &mut p)?;
        }
        if flags & 0x80 != 0 {
            read_vli(h, &mut p)?;
        }
        if read_vli(h, &mut p)? != 0x21 || read_vli(h, &mut p)? != 1 {
            return None;
        }
        let start = off + hsize;
        let (comp, uncomp) = lzma2_scan(data.get(start..)?).ok()?;
        let len = usize::try_from(uncomp).ok()?;
        let end = start + comp;
        let check = end + (4 - comp % 4) % 4;
        blocks.push(Block { data: start..end, check: check..check + csize, out: out..out + len });
        out += len;
        off = check + csize;
    }
    // (a second stream: its bytes are counted in `total`, not in these blocks)
    (out == total && !blocks.is_empty()).then_some(Plan { check_type, blocks, total })
}

/// The output of a decode in progress, shared with the threads that read it.
pub(crate) struct Decoding {
    /// owns the output; not accessed as a `Vec` until the decode is over
    buf: Vec<u8>,
    ptr: *mut u8,
    total: usize,
    /// per block: bytes of its output decoded (Release-stored by its decoder)
    done: Vec<AtomicUsize>,
    starts: Vec<usize>,
    lens: Vec<usize>,
    failed: AtomicBool,
    finished: AtomicUsize,
    lock: Mutex<()>,
    moved: Condvar,
}

// SAFETY: the buffer is written by the block decoders at bytes no reader reads yet (beyond the
// published progress of their block), and read by others below the progress they observed
// with an Acquire load; see `decode_block` and `prefix`.
unsafe impl Sync for Decoding {}
unsafe impl Send for Decoding {}

impl Decoding {
    /// An output buffer for `plan` (fresh zero pages).
    pub(crate) fn new(plan: &Plan) -> Option<Decoding> {
        let mut buf = crate::codecs::try_zeroed(plan.total).ok()?;
        let ptr = buf.as_mut_ptr();
        Some(Decoding {
            buf,
            ptr,
            total: plan.total,
            done: plan.blocks.iter().map(|_| AtomicUsize::new(0)).collect(),
            starts: plan.blocks.iter().map(|b| b.out.start).collect(),
            lens: plan.blocks.iter().map(|b| b.out.len()).collect(),
            failed: AtomicBool::new(false),
            finished: AtomicUsize::new(0),
            lock: Mutex::new(()),
            moved: Condvar::new(),
        })
    }

    pub(crate) fn total(&self) -> usize {
        self.total
    }

    /// Decode every block of `plan` from `data` (in parallel when there are several),
    /// publishing the progress as it goes. Errors mark the decode failed.
    pub(crate) fn run(&self, data: &[u8], plan: &Plan) -> Result<()> {
        let r = if plan.blocks.len() == 1 {
            self.decode_block(data, plan, 0)
        } else {
            let threads = crate::util::par::threads().clamp(1, plan.blocks.len());
            let next = AtomicUsize::new(0);
            let work = || -> Result<()> {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= plan.blocks.len() {
                        return Ok(());
                    }
                    self.decode_block(data, plan, i)?;
                }
            };
            std::thread::scope(|s| {
                let hs: Vec<_> = (1..threads).map(|_| s.spawn(work)).collect();
                let mut r = work();
                for h in hs {
                    let hr = h.join().unwrap_or_else(|_| Err(err("decoder panicked")));
                    if r.is_ok() {
                        r = hr;
                    }
                }
                r
            })
        };
        if r.is_err() {
            self.fail();
        }
        r
    }

    /// Mark the decode failed (readers waiting are woken up).
    fn fail(&self) {
        self.failed.store(true, Ordering::Release);
        self.notify();
    }

    fn notify(&self) {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        self.moved.notify_all();
    }

    /// Decode block `i` into its output, publishing each LZMA2 chunk (the loop of
    /// `codecs::lzma::lzma2_decode_into`, with the progress published and the check computed
    /// chunk by chunk while the output is in cache).
    fn decode_block(&self, data: &[u8], plan: &Plan, i: usize) -> Result<()> {
        let b = &plan.blocks[i];
        let input = &data[b.data.clone()];
        // SAFETY: the block's own output range; readers only read below its published
        // progress, which this decoder never writes again (LZMA writes at and after the
        // current position only: matches read the dictionary behind it)
        let out: &mut [u8] = unsafe { std::slice::from_raw_parts_mut(self.ptr.add(b.out.start), b.out.len()) };
        let publish = |n: usize| {
            self.done[i].store(n, Ordering::Release);
            self.notify();
        };
        let (mut ip, mut pos, mut dict_start) = (0usize, 0usize, 0usize);
        let (mut need_dict_reset, mut need_props) = (true, true);
        let mut dec: Option<(LzmaDecoder, Props)> = None;
        let (mut c32, mut c64) = (0u32, 0u64);
        let mut checked = 0usize;
        loop {
            let c = *input.get(ip).ok_or_else(|| err("truncated lzma2 stream"))?;
            ip += 1;
            if c == 0 {
                break;
            }
            if c >= 0xE0 || c == 1 {
                need_props = true;
                need_dict_reset = false;
                dict_start = pos;
            } else if need_dict_reset {
                return Err(err("lzma2 missing dictionary reset"));
            }
            if c >= 0x80 {
                let hlen = if c >= 0xC0 { 5 } else { 4 };
                let h = input.get(ip..ip + hlen).ok_or_else(|| err("truncated lzma2 chunk header"))?;
                let unpacked = (((c & 0x1F) as usize) << 16) + u16::from_be_bytes([h[0], h[1]]) as usize + 1;
                let packed = u16::from_be_bytes([h[2], h[3]]) as usize + 1;
                if c >= 0xC0 {
                    let props = Props::from_byte(h[4])?;
                    if props.lc + props.lp > 4 {
                        return Err(err("lzma2 lc + lp > 4"));
                    }
                    match dec.as_mut() {
                        Some((d, p)) if *p == props => d.reset_state(),
                        Some((d, p)) => {
                            d.set_props(props);
                            *p = props;
                        }
                        None => dec = Some((LzmaDecoder::new(props), props)),
                    }
                    need_props = false;
                } else if need_props {
                    return Err(err("lzma2 missing properties"));
                } else if c >= 0xA0
                    && let Some((d, _)) = dec.as_mut()
                {
                    d.reset_state();
                }
                ip += hlen;
                let chunk = input.get(ip..ip + packed).ok_or_else(|| err("truncated lzma2 chunk"))?;
                let limit = pos + unpacked;
                if limit > out.len() {
                    return Err(err("lzma2 uncompressed size mismatch"));
                }
                let (d, _) = dec.as_mut().ok_or_else(|| err("lzma2 missing properties"))?;
                let mut rc = RangeDecoder::new(chunk, 0)?;
                let window = &mut out[dict_start..];
                let mut wpos = pos - dict_start;
                let end = limit - dict_start;
                // in steps of SLICE output bytes, each published (a chunk holds up to 2 MiB:
                // the index should not wait for all of it); the decoder keeps its state across
                // the calls (a match cut at a step is finished by the next call)
                loop {
                    let step = (wpos + SLICE).min(end);
                    let stop = d.decode(&mut rc, chunk, window, &mut wpos, step)?;
                    if stop != Stop::Limit || wpos != step {
                        return Err(err("lzma2 chunk"));
                    }
                    let at = dict_start + wpos;
                    match plan.check_type {
                        1 => c32 = crate::codecs::crc::crc32_update(c32, &window[checked - dict_start..wpos]),
                        4 => c64 = crate::codecs::crc::crc64_update(c64, &window[checked - dict_start..wpos]),
                        _ => {}
                    }
                    checked = at;
                    if wpos == end {
                        break;
                    }
                    publish(at);
                }
                rc.finish(chunk);
                if d.pending_len != 0 || rc.ip != packed || !rc.is_finished_ok() {
                    return Err(err("lzma2 chunk"));
                }
                pos = limit;
                ip += packed;
            } else if c == 1 || c == 2 {
                let h = input.get(ip..ip + 2).ok_or_else(|| err("truncated lzma2 chunk header"))?;
                let size = u16::from_be_bytes([h[0], h[1]]) as usize + 1;
                ip += 2;
                let src = input.get(ip..ip + size).ok_or_else(|| err("truncated lzma2 chunk"))?;
                let dst = out.get_mut(pos..pos + size).ok_or_else(|| err("lzma2 uncompressed size mismatch"))?;
                dst.copy_from_slice(src);
                pos += size;
                ip += size;
            } else {
                return Err(err("lzma2 control byte"));
            }
            // the check over the new output while it is in cache, then publish it
            match plan.check_type {
                1 => c32 = crate::codecs::crc::crc32_update(c32, &out[checked..pos]),
                4 => c64 = crate::codecs::crc::crc64_update(c64, &out[checked..pos]),
                _ => {}
            }
            checked = pos;
            if pos < out.len() {
                publish(pos);
            }
        }
        if pos != out.len() || ip != input.len() {
            return Err(err("lzma2 uncompressed size mismatch"));
        }
        let check = &data[b.check.clone()];
        let ok = match plan.check_type {
            1 => c32 == u32::from_le_bytes(check.try_into().map_err(|_| err("check"))?),
            4 => c64 == u64::from_le_bytes(check.try_into().map_err(|_| err("check"))?),
            _ => true,
        };
        if !ok {
            return Err(err(if plan.check_type == 1 { "CRC32 mismatch" } else { "CRC64 mismatch" }));
        }
        // the block is complete (and verified)
        self.done[i].store(out.len(), Ordering::Release);
        self.finished.fetch_add(1, Ordering::AcqRel);
        self.notify();
        Ok(())
    }

    /// The contiguous decoded prefix: complete blocks, then the progress of the first
    /// incomplete one. (A block counts as complete once its check passed.)
    pub(crate) fn ready(&self) -> usize {
        let mut n = 0;
        for (i, d) in self.done.iter().enumerate() {
            let d = d.load(Ordering::Acquire);
            n = self.starts[i] + d;
            if d < self.lens[i] {
                return n;
            }
        }
        n
    }

    /// The decode stopped (failed, or every block complete).
    pub(crate) fn ended(&self) -> bool {
        self.failed.load(Ordering::Acquire) || self.finished.load(Ordering::Acquire) == self.done.len()
    }

    pub(crate) fn failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }

    /// Wait until more than `have` bytes are ready or the decode stopped; the bytes ready.
    pub(crate) fn wait(&self, have: usize) -> usize {
        let mut g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            let r = self.ready();
            if r > have || self.ended() {
                return r;
            }
            g = self.moved.wait(g).unwrap_or_else(|e| e.into_inner());
        }
    }

    /// The first `n` decoded bytes (`n` at most what [`Decoding::ready`] returned).
    pub(crate) fn prefix(&self, n: usize) -> &[u8] {
        assert!(n <= self.total);
        // SAFETY: bytes below a published progress are final (see `decode_block`)
        unsafe { std::slice::from_raw_parts(self.ptr, n) }
    }

    /// The output, once [`Decoding::run`] succeeded.
    pub(crate) fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

/// Decode `data` with [`Decoding`] while `follow` reads the decoded prefix (on this thread):
/// `follow(dec)` returns when it has consumed everything or given up. Returns the decode's
/// result, the output and what `follow` returned.
pub(crate) fn decode_following<R>(data: &[u8], plan: &Plan, follow: impl FnOnce(&Decoding) -> R) -> Option<(Result<()>, Decoding, R)> {
    let dec = Decoding::new(plan)?;
    let t0 = std::time::Instant::now();
    let (res, r) = std::thread::scope(|s| {
        let h = std::thread::Builder::new().name("rsvol-xz".into()).spawn_scoped(s, || {
            // (a panic must not leave the reader waiting)
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| dec.run(data, plan))).unwrap_or_else(|_| {
                dec.fail();
                Err(err("decoder panicked"))
            });
            crate::util::trace::note(|| format!("xz decode ({} blocks, {} MB) done at {:.2} ms", plan.blocks.len(), plan.total >> 20, t0.elapsed().as_secs_f64() * 1e3));
            r
        });
        let Ok(h) = h else { return (Err(err("no decoder thread")), None) };
        let r = follow(&dec);
        (h.join().unwrap_or_else(|_| Err(err("decoder panicked"))), Some(r))
    });
    Some((res, dec, r?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A streamed decode equals the codec's decode (single-block python-style files and
    /// multi-block ones), its progress only grows, and corrupt data fails like the codec.
    #[test]
    fn streamed_decode_equals_codec() {
        use crate::codecs::xz_enc::{XzEncoder, XzOptions};
        use std::io::Write;
        let json: Vec<u8> = (0..300_000u32).flat_map(|i| format!("  \"k{}\": {{\"v\": {}}},\n", i % 9973, i % 131).into_bytes()).collect();
        for block in [usize::MAX, 1 << 20] {
            let mut e = XzEncoder::with_options(Vec::new(), XzOptions { block_size: block, ..XzOptions::preset(1) });
            e.write_all(&json).unwrap();
            let xz = e.finish().unwrap();
            let p = plan(&xz).unwrap();
            assert_eq!(p.total, json.len());
            assert_eq!(p.blocks.len() > 1, block != usize::MAX);
            let (r, dec, seen) = decode_following(&xz, &p, |d| {
                let mut seen = vec![0usize];
                loop {
                    let n = d.wait(*seen.last().unwrap());
                    assert!(n >= *seen.last().unwrap());
                    assert!(d.prefix(n) == &json[..n]);
                    seen.push(n);
                    if d.ended() && n == d.ready() {
                        return seen;
                    }
                }
            })
            .unwrap();
            r.unwrap();
            assert_eq!(*seen.last().unwrap(), json.len());
            assert!(dec.into_vec() == json);
            // a flipped byte in the compressed data: an error, never a wrong output accepted
            let mut bad = xz.clone();
            let at = p.blocks[0].data.start + 100;
            bad[at] ^= 0x55;
            if let Some(bp) = plan(&bad) {
                let (r, _, _) = decode_following(&bad, &bp, |d| while !d.ended() { d.wait(d.ready()); }).unwrap();
                assert!(r.is_err());
            }
            assert!(crate::codecs::xz::decompress(&bad).is_err());
        }
        // not an xz file / filters: left to the codec
        assert!(plan(b"not xz").is_none());
    }
}
