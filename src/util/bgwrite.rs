//! [`ThreadWriter`]: a `Write` adapter that hands full buffers to a writer thread through a
//! bounded queue, so the producer (e.g. a compressor's collecting thread) keeps working while
//! the kernel throttles the file writes (dirty-page writeback: beyond `vm.dirty_bytes` a
//! `write` sleeps in `balance_dirty_pages`). Bytes reach the inner writer in order; `flush`
//! waits until everything before it is written and the inner writer flushed. An error of the
//! inner writer is returned by a later `write` / `flush` (or dropped with the writer, like
//! `BufWriter`'s).

use std::io::{self, Write};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::thread::JoinHandle;

enum Msg {
    Data(Vec<u8>),
    Flush(SyncSender<io::Result<()>>),
}

pub struct ThreadWriter {
    buf: Vec<u8>,
    cap: usize,
    tx: Option<SyncSender<Msg>>,
    /// emptied buffers coming back from the writer thread (no fresh pages to fault in)
    back: Receiver<Vec<u8>>,
    handle: Option<JoinHandle<io::Result<()>>>,
}

impl ThreadWriter {
    /// Buffers of `cap` bytes, at most `depth` of them queued for the writer thread.
    pub fn new<W: Write + Send + 'static>(mut w: W, cap: usize, depth: usize) -> ThreadWriter {
        let depth = depth.max(1);
        let (tx, rx) = sync_channel::<Msg>(depth);
        let (btx, brx) = sync_channel::<Vec<u8>>(depth + 2);
        let handle = std::thread::spawn(move || -> io::Result<()> {
            for m in rx {
                match m {
                    Msg::Data(mut b) => {
                        w.write_all(&b)?;
                        b.clear();
                        let _ = btx.try_send(b);
                    }
                    Msg::Flush(reply) => {
                        let _ = reply.send(w.flush());
                    }
                }
            }
            w.flush()
        });
        ThreadWriter { buf: Vec::with_capacity(cap), cap, tx: Some(tx), back: brx, handle: Some(handle) }
    }

    /// The writer thread stopped (an error of the inner writer): join it for the error.
    fn failed(&mut self) -> io::Error {
        self.tx = None;
        match self.handle.take().map(|h| h.join()) {
            Some(Ok(Err(e))) => e,
            Some(Err(_)) => io::Error::other("writer thread panicked"),
            _ => io::Error::other("writer thread stopped"),
        }
    }

    fn send(&mut self, m: Msg) -> io::Result<()> {
        let ok = self.tx.as_ref().is_some_and(|tx| tx.send(m).is_ok());
        if ok { Ok(()) } else { Err(self.failed()) }
    }

    fn send_buf(&mut self) -> io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let next = self.back.try_recv().unwrap_or_else(|_| Vec::with_capacity(self.cap));
        let full = std::mem::replace(&mut self.buf, next);
        self.send(Msg::Data(full))
    }
}

impl Write for ThreadWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.buf.len() + data.len() > self.cap {
            self.send_buf()?;
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.send_buf()?;
        let (rtx, rrx) = sync_channel(1);
        self.send(Msg::Flush(rtx))?;
        match rrx.recv() {
            Ok(r) => r,
            Err(_) => Err(self.failed()),
        }
    }
}

impl Drop for ThreadWriter {
    fn drop(&mut self) {
        let _ = self.send_buf();
        self.tx = None;
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_order_and_flushed() {
        let path = std::env::temp_dir().join(format!("rsvol-bgwrite-{}", std::process::id()));
        let f = std::fs::File::create(&path).unwrap();
        let mut w = ThreadWriter::new(f, 1000, 2);
        let mut want = Vec::new();
        for i in 0..5000u32 {
            let b = i.to_le_bytes().repeat((i % 7) as usize);
            w.write_all(&b).unwrap();
            want.extend_from_slice(&b);
        }
        // a write bigger than the buffer
        let big: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        w.write_all(&big).unwrap();
        want.extend_from_slice(&big);
        w.flush().unwrap();
        assert!(std::fs::read(&path).unwrap() == want);
        w.write_all(b"tail").unwrap();
        drop(w);
        want.extend_from_slice(b"tail");
        assert!(std::fs::read(&path).unwrap() == want);
        std::fs::remove_file(&path).unwrap();
    }

    /// An inner writer that fails after `ok` bytes.
    struct Failing {
        ok: usize,
    }
    impl Write for Failing {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            if self.ok < b.len() {
                return Err(io::Error::other("disk full"));
            }
            self.ok -= b.len();
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn errors_surface() {
        let mut w = ThreadWriter::new(Failing { ok: 3000 }, 1000, 1);
        let mut err = None;
        for _ in 0..100 {
            if let Err(e) = w.write_all(&[1u8; 700]) {
                err = Some(e);
                break;
            }
        }
        let e = err.or_else(|| w.flush().err()).expect("the inner writer's error is reported");
        assert_eq!(e.to_string(), "disk full");
    }
}
