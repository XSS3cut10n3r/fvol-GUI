//! Output of the streaming decoders (`gzip::decompress_to`, `bzip2::decompress_to`,
//! `xz::decompress_to_file`): decompressed data leaves the decoder in chunks of a few MiB, so a
//! multi-GB memory image is decompressed with bounded memory.
//!
//! [`FileSink`] writes the chunks on a writer thread (the decoder keeps decoding while the
//! previous chunk is copied into the page cache); the decoder hands over whole buffers and
//! gets recycled ones back, so the only copy on the decoder side is the small history window
//! it keeps (32 KiB for DEFLATE, nothing for bzip2). A `Vec<u8>` is a sink too (tests).

use crate::error::{Error, Result};
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::sync::mpsc::{Receiver, SyncSender};

/// Where a streaming decoder puts its output.
pub trait Sink {
    /// Emits `buf[from..]` as the next output bytes. Afterwards `buf` holds only the former
    /// last `keep` bytes (`keep <= buf.len()`), which the decoder still needs as history
    /// (they were emitted by this or an earlier call), and has at least its old capacity.
    fn flush(&mut self, buf: &mut Vec<u8>, from: usize, keep: usize) -> Result<()>;

    /// Number of bytes emitted so far.
    fn position(&self) -> u64;

    /// Discards everything after the first `len` emitted bytes (`len <= position()`).
    fn truncate(&mut self, len: u64) -> Result<()>;
}

impl Sink for Vec<u8> {
    fn flush(&mut self, buf: &mut Vec<u8>, from: usize, keep: usize) -> Result<()> {
        self.try_reserve(buf.len() - from).map_err(|_| Error::Msg("out of memory".into()))?;
        self.extend_from_slice(&buf[from..]);
        let n = buf.len();
        buf.copy_within(n - keep.min(n).., 0);
        buf.truncate(keep.min(n));
        Ok(())
    }

    fn position(&self) -> u64 {
        self.len() as u64
    }

    fn truncate(&mut self, len: u64) -> Result<()> {
        Vec::truncate(self, len as usize);
        Ok(())
    }
}

enum Msg {
    /// write `buf[from..]`
    Data(Vec<u8>, usize),
    /// set the file length (and the write position) to this
    Truncate(u64),
}

/// A [`Sink`] writing sequentially to a file on its own thread. At most `DEPTH` chunks are
/// queued, so a slow disk slows the decoder down instead of filling memory.
pub struct FileSink {
    tx: Option<SyncSender<Msg>>,
    back: Receiver<Vec<u8>>,
    handle: Option<std::thread::JoinHandle<std::io::Result<File>>>,
    pos: u64,
}

const DEPTH: usize = 2;

impl FileSink {
    /// Writes to `file` from its current position.
    pub fn new(file: File) -> Result<FileSink> {
        let (tx, rx) = std::sync::mpsc::sync_channel::<Msg>(DEPTH);
        let (back_tx, back) = std::sync::mpsc::channel::<Vec<u8>>();
        let handle = std::thread::Builder::new()
            .name("rsvol-write".into())
            .spawn(move || -> std::io::Result<File> {
                let mut file = file;
                let mut err: Option<std::io::Error> = None;
                for m in rx {
                    match m {
                        Msg::Data(buf, from) => {
                            if err.is_none()
                                && let Err(e) = file.write_all(&buf[from..])
                            {
                                err = Some(e);
                            }
                            let _ = back_tx.send(buf);
                        }
                        Msg::Truncate(len) => {
                            if err.is_none()
                                && let Err(e) = file.set_len(len).and_then(|()| file.seek(SeekFrom::Start(len)).map(|_| ()))
                            {
                                err = Some(e);
                            }
                        }
                    }
                }
                match err {
                    Some(e) => Err(e),
                    None => Ok(file),
                }
            })
            .map_err(|e| Error::Msg(format!("cannot start the writer thread: {e}")))?;
        Ok(FileSink { tx: Some(tx), back, handle: Some(handle), pos: 0 })
    }

    fn send(&mut self, m: Msg) -> Result<()> {
        let sent = self.tx.as_ref().is_some_and(|tx| tx.send(m).is_ok());
        if sent {
            return Ok(());
        }
        // the writer is gone: it failed, and finish() reports why
        Err(self.finish_inner().err().unwrap_or_else(|| Error::Msg("write failed".into())))
    }

    fn finish_inner(&mut self) -> Result<File> {
        self.tx = None;
        match self.handle.take().map(|h| h.join()) {
            Some(Ok(Ok(f))) => Ok(f),
            Some(Ok(Err(e))) => Err(Error::Msg(format!("cannot write the decompressed file: {e}"))),
            Some(Err(_)) => Err(Error::Msg("the writer thread panicked".into())),
            None => Err(Error::Msg("write failed".into())),
        }
    }

    /// Waits for every chunk to be written; returns the file.
    pub fn finish(mut self) -> Result<File> {
        self.finish_inner()
    }
}

impl Drop for FileSink {
    fn drop(&mut self) {
        let _ = self.finish_inner();
    }
}

impl Sink for FileSink {
    fn flush(&mut self, buf: &mut Vec<u8>, from: usize, keep: usize) -> Result<()> {
        if from >= buf.len() {
            let n = buf.len();
            buf.copy_within(n - keep.min(n).., 0);
            buf.truncate(keep.min(n));
            return Ok(());
        }
        // a recycled buffer (or a new one) of the same capacity continues the output
        let mut next = self.back.try_recv().unwrap_or_default();
        next.clear();
        if next.capacity() < buf.capacity() {
            next.try_reserve_exact(buf.capacity()).map_err(|_| Error::Msg("out of memory".into()))?;
        }
        let n = buf.len();
        next.extend_from_slice(&buf[n - keep.min(n)..]);
        let old = std::mem::replace(buf, next);
        self.pos += (n - from) as u64;
        self.send(Msg::Data(old, from))
    }

    fn position(&self) -> u64 {
        self.pos
    }

    fn truncate(&mut self, len: u64) -> Result<()> {
        if len < self.pos {
            self.pos = len;
            self.send(Msg::Truncate(len))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_sink_writes_in_order_and_truncates() {
        let dir = std::env::temp_dir().join(format!("rsvol-sink-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("out");
        let mut s = FileSink::new(File::create(&p).unwrap()).unwrap();
        let mut want = Vec::new();
        let mut buf = Vec::with_capacity(64);
        for i in 0..50u8 {
            // history of 3 bytes kept after every flush
            let from = buf.len();
            buf.extend_from_slice(&[i; 10]);
            want.extend_from_slice(&[i; 10]);
            s.flush(&mut buf, from, 3).unwrap();
            assert_eq!(buf, [i; 3]);
            assert!(buf.capacity() >= 64);
        }
        assert_eq!(s.position(), 500);
        s.truncate(495).unwrap();
        want.truncate(495);
        let mut buf = b"xyz".to_vec();
        s.flush(&mut buf, 0, 0).unwrap();
        want.extend_from_slice(b"xyz");
        s.finish().unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), want);
        let mut v = Vec::new();
        let mut buf = b"abcdef".to_vec();
        Sink::flush(&mut v, &mut buf, 2, 2).unwrap();
        assert_eq!((v.as_slice(), buf.as_slice()), (&b"cdef"[..], &b"ef"[..]));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
