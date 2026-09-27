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
        Self::spawn(file, None)
    }

    /// Writes to `file` from offset `at` with positional writes (`pwrite`: the file position
    /// is not used, so several sinks can fill different parts of one file through cloned
    /// handles). `truncate` only moves the write offset back, it does not shrink the file.
    pub fn at(file: File, at: u64) -> Result<FileSink> {
        Self::spawn(file, Some(at))
    }

    fn spawn(file: File, at: Option<u64>) -> Result<FileSink> {
        use std::os::unix::fs::FileExt;
        let (tx, rx) = std::sync::mpsc::sync_channel::<Msg>(DEPTH);
        let (back_tx, back) = std::sync::mpsc::channel::<Vec<u8>>();
        let handle = std::thread::Builder::new()
            .name("rsvol-write".into())
            .spawn(move || -> std::io::Result<File> {
                let mut file = file;
                let mut err: Option<std::io::Error> = None;
                let mut off = at.unwrap_or(0);
                for m in rx {
                    match m {
                        Msg::Data(buf, from) => {
                            let r = match at {
                                Some(_) => file.write_all_at(&buf[from..], off),
                                None => file.write_all(&buf[from..]),
                            };
                            off += (buf.len() - from) as u64;
                            if err.is_none()
                                && let Err(e) = r
                            {
                                err = Some(e);
                            }
                            let _ = back_tx.send(buf);
                        }
                        Msg::Truncate(len) => {
                            if let Some(a) = at {
                                off = a + len;
                            } else if err.is_none()
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

    /// Positional sinks on cloned handles fill their own parts of one file, whatever the
    /// shared file position does.
    #[test]
    fn file_sink_at_offsets() {
        let dir = std::env::temp_dir().join(format!("rsvol-sink-at-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("out");
        let f = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&p).unwrap();
        f.set_len(3000).unwrap();
        let mut a = FileSink::at(f.try_clone().unwrap(), 0).unwrap();
        let mut b = FileSink::at(f.try_clone().unwrap(), 1000).unwrap();
        let mut want = vec![0u8; 3000];
        for i in 0..10u8 {
            let mut x = vec![b'a' + i; 100];
            want[i as usize * 100..][..100].fill(b'a' + i);
            a.flush(&mut x, 0, 0).unwrap();
            let mut y = vec![b'A' + i; 150];
            want[1000 + i as usize * 150..][..150].fill(b'A' + i);
            b.flush(&mut y, 0, 0).unwrap();
        }
        // moving back overwrites
        b.truncate(1400).unwrap();
        let mut y = vec![b'#'; 10];
        want[2400..2410].fill(b'#');
        b.flush(&mut y, 0, 0).unwrap();
        a.finish().unwrap();
        b.finish().unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), want);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
