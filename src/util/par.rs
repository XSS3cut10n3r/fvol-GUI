//! Parallel helpers with atomic work stealing, on the persistent worker pool
//! ([`crate::util::pool`]: no thread is spawned per call). Results always come back in index
//! order, so output stays deterministic (python volatility3 order).
//!
//! * [`par_for`]      – run `f(i)` for `i in 0..n` on all cores.
//! * [`par_map`]      – `(0..n).map(f).collect()` in parallel, results in order.
//! * [`par_map_stream`] – parallel map with in-order streaming consumption on the calling thread
//!   and early stop (for "scan until the first good hit" patterns), with bounded look-ahead.
//!
//! Use them for anything that touches lots of memory (scans, per-process work). For tiny `n`
//! they run inline on the caller's thread. The calling thread works on its own section too;
//! sections may nest and may run concurrently from several threads.
//!
//! A panic in `f` (or in `consume`) propagates to the caller with its original payload, after
//! every pool thread has left the section: the one of the lowest failing index, as the
//! equivalent sequential loop would raise it. `par_map_stream` first hands every result before
//! the failed item to `consume`, like the sequential loop.

use crate::util::pool::{self, Payload, Work};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard, OnceLock};

/// Number of worker threads to use (all logical CPUs; override with `FASTVOL_THREADS`).
pub fn threads() -> usize {
    static N: OnceLock<usize> = OnceLock::new();
    *N.get_or_init(|| {
        if let Some(n) = crate::util::env::var("THREADS").ok().and_then(|v| v.parse::<usize>().ok()) {
            return n.max(1);
        }
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4)
    })
}

/// Run `f(i)` for every `i` in `0..n` across all cores.
pub fn par_for<F>(n: usize, f: F)
where
    F: Fn(usize) + Sync,
{
    pool::for_each_bounded(n, threads(), &f)
}

/// Parallel `(0..n).map(f).collect::<Vec<_>>()`; results in index order.
pub fn par_map<R, F>(n: usize, f: F) -> Vec<R>
where
    R: Send,
    F: Fn(usize) -> R + Sync,
{
    pool::map_bounded(n, threads(), f)
}

/// [`par_map`] with at most `max_threads` threads at once, the caller's included (for
/// memory-heavy items, e.g. decompressing many large ISFs at once).
pub fn par_map_bounded<R, F>(n: usize, max_threads: usize, f: F) -> Vec<R>
where
    R: Send,
    F: Fn(usize) -> R + Sync,
{
    pool::map_bounded(n, max_threads.max(1), f)
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The items of a [`par_map_stream`] section.
struct Stream<'a, R, F> {
    f: &'a F,
    n: usize,
    /// items are claimed only below `consumed + lookahead`
    lookahead: usize,
    next: AtomicUsize,
    /// results handed to the consumer so far
    consumed: AtomicUsize,
    stop: AtomicBool,
    /// a helper found the look-ahead window full and left
    starved: AtomicBool,
    st: Mutex<StreamState<R>>,
    /// the consumer waits here for `StreamState::waiting`
    ready: Condvar,
}

struct StreamState<R> {
    slots: Vec<Option<Result<R, Payload>>>,
    /// the item the consumer waits for (`usize::MAX`: none)
    waiting: usize,
}

impl<R: Send, F: Fn(usize) -> R + Sync> Stream<'_, R, F> {
    /// The next item, if one may be computed now.
    fn claim(&self) -> Option<usize> {
        let mut k = self.next.load(Ordering::Relaxed);
        loop {
            if self.stop.load(Ordering::Relaxed) || k >= self.n {
                return None;
            }
            if k >= self.consumed.load(Ordering::SeqCst).saturating_add(self.lookahead) {
                // the consumer pokes the pool when it moves on (a Dekker pair with `consume`'s
                // store + swap: one side always sees the other)
                self.starved.store(true, Ordering::SeqCst);
                if k >= self.consumed.load(Ordering::SeqCst).saturating_add(self.lookahead) {
                    return None;
                }
            }
            match self.next.compare_exchange_weak(k, k + 1, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return Some(k),
                Err(now) => k = now,
            }
        }
    }
}

impl<R: Send, F: Fn(usize) -> R + Sync> Work for Stream<'_, R, F> {
    fn help(&self) {
        while let Some(i) = self.claim() {
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (self.f)(i)));
            if r.is_err() {
                // items below i are claimed already and still arrive
                self.stop.store(true, Ordering::Relaxed);
            }
            let mut g = lock(&self.st);
            g.slots[i] = Some(r);
            let wake = g.waiting == i;
            drop(g);
            if wake {
                self.ready.notify_one();
            }
        }
    }
    fn has_work(&self) -> bool {
        let k = self.next.load(Ordering::Relaxed);
        !self.stop.load(Ordering::Relaxed) && k < self.n && k < self.consumed.load(Ordering::Relaxed).saturating_add(self.lookahead)
    }
}

/// Parallel map over `0..n` whose results are handed to `consume` on the calling thread in
/// index order as soon as they are ready. `consume` returns `false` to stop early; no new
/// items are started then. At most `lookahead` items are computed ahead of the consumer
/// (0 = unbounded), so an early stop wastes little work.
pub fn par_map_stream<R, F, C>(n: usize, lookahead: usize, f: F, mut consume: C)
where
    R: Send,
    F: Fn(usize) -> R + Sync,
    C: FnMut(usize, R) -> bool,
{
    let t = threads().min(n);
    if t <= 1 {
        for i in 0..n {
            if !consume(i, f(i)) {
                return;
            }
        }
        return;
    }
    let job = Stream {
        f: &f,
        n,
        lookahead: if lookahead == 0 { usize::MAX } else { lookahead.max(t) },
        next: AtomicUsize::new(0),
        consumed: AtomicUsize::new(0),
        stop: AtomicBool::new(false),
        starved: AtomicBool::new(false),
        st: Mutex::new(StreamState { slots: (0..n).map(|_| None).collect(), waiting: usize::MAX }),
        ready: Condvar::new(),
    };
    // the consumer never computes ahead (a slow item would hold up the results before it),
    // so up to `t` helpers compute
    pool::run_job(&job, t, || {
        // however the consumer leaves (done, early stop, a panic): no new items
        struct Stop<'a>(&'a AtomicBool);
        impl Drop for Stop<'_> {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Relaxed);
            }
        }
        let _stop = Stop(&job.stop);
        for i in 0..n {
            let r = {
                let mut g = lock(&job.st);
                loop {
                    if let Some(r) = g.slots[i].take() {
                        break r;
                    }
                    if job.next.load(Ordering::Relaxed) == i && job.next.compare_exchange(i, i + 1, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
                        // nobody took it (every pool thread is busy elsewhere): run it here
                        drop(g);
                        break Ok(f(i));
                    }
                    g.waiting = i;
                    g = job.ready.wait(g).unwrap_or_else(|e| e.into_inner());
                    g.waiting = usize::MAX;
                }
            };
            job.consumed.store(i + 1, Ordering::SeqCst);
            if job.starved.swap(false, Ordering::SeqCst) {
                // one more item may start (a spinning helper also sees the poke)
                pool::poke(1);
            }
            match r {
                Ok(v) => {
                    if !consume(i, v) {
                        return;
                    }
                }
                Err(p) => std::panic::resume_unwind(p),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn map_in_order() {
        let v = par_map(1000, |i| i * 2);
        assert_eq!(v, (0..1000).map(|i| i * 2).collect::<Vec<_>>());
        let v = par_map_bounded(1000, 3, |i| i * 2);
        assert_eq!(v, (0..1000).map(|i| i * 2).collect::<Vec<_>>());
    }
    #[test]
    fn bounded_threads() {
        let active = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        par_map_bounded(200, 3, |_| {
            let a = active.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(a, Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_micros(200));
            active.fetch_sub(1, Ordering::SeqCst);
        });
        assert!(peak.load(Ordering::SeqCst) <= 3);
    }
    #[test]
    fn stream_in_order_and_stop() {
        let mut seen = Vec::new();
        par_map_stream(10_000, 64, |i| i, |i, r| {
            assert_eq!(i, r);
            seen.push(r);
            r < 500
        });
        assert_eq!(seen.len(), 501);
        let mut all = 0;
        par_map_stream(777, 0, |i| i, |_, _| {
            all += 1;
            true
        });
        assert_eq!(all, 777);
    }
    /// The look-ahead bound holds: nothing is computed `lookahead` items past the consumer.
    #[test]
    fn stream_lookahead_bound() {
        let la = threads().max(8);
        let computed = AtomicUsize::new(0);
        let mut max_ahead = 0usize;
        par_map_stream(
            2000,
            la,
            |i| {
                computed.fetch_max(i + 1, Ordering::SeqCst);
                i
            },
            |i, _| {
                max_ahead = max_ahead.max(computed.load(Ordering::SeqCst).saturating_sub(i + 1));
                true
            },
        );
        assert!(max_ahead <= la, "{max_ahead} > {la}");
    }
    #[test]
    fn for_all() {
        let c = AtomicUsize::new(0);
        par_for(12345, |_| {
            c.fetch_add(1, Ordering::Relaxed);
        });
        assert_eq!(c.load(Ordering::Relaxed), 12345);
    }

    fn msg(p: Box<dyn std::any::Any + Send>) -> String {
        p.downcast_ref::<String>().cloned().or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default()
    }

    /// A panicking item used to hang `par_map_stream` (its slot never filled, the consumer
    /// waited forever): now every result before it is consumed, then its panic propagates.
    #[test]
    fn stream_worker_panic_propagates() {
        for la in [0, 1, 64] {
            let mut seen = 0;
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                par_map_stream(
                    1000,
                    la,
                    |i| {
                        if i == 321 {
                            panic!("item {i} failed");
                        }
                        i
                    },
                    |i, r| {
                        assert_eq!(i, r);
                        seen += 1;
                        true
                    },
                )
            }));
            assert_eq!(msg(r.unwrap_err()), "item 321 failed");
            assert_eq!(seen, 321);
        }
    }

    /// A panic in `consume` stops the workers (no hang on a full look-ahead window).
    #[test]
    fn stream_consumer_panic_propagates() {
        let computed = AtomicUsize::new(0);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            par_map_stream(
                100_000,
                16,
                |i| {
                    computed.fetch_add(1, Ordering::Relaxed);
                    i
                },
                |i, _| {
                    if i == 50 {
                        panic!("consumer");
                    }
                    true
                },
            )
        }));
        assert_eq!(msg(r.unwrap_err()), "consumer");
        assert!(computed.load(Ordering::Relaxed) < 1000);
    }

    #[test]
    fn map_and_for_panics_propagate() {
        let r = std::panic::catch_unwind(|| par_map(500, |i| if i == 77 { panic!("ValueError: {i}") } else { i }));
        assert_eq!(msg(r.unwrap_err()), "ValueError: 77");
        let r = std::panic::catch_unwind(|| par_map_bounded(50, 4, |i| if i == 7 { panic!("bounded") } else { i }));
        assert_eq!(msg(r.unwrap_err()), "bounded");
        let r = std::panic::catch_unwind(|| par_for(500, |i| if i == 3 { panic!("for") }));
        assert_eq!(msg(r.unwrap_err()), "for");
        // the pool is still fine afterwards
        assert_eq!(par_map(100, |i| i).len(), 100);
    }

    /// Sections nest (a stream inside a map inside a stream) and run from several threads.
    #[test]
    fn nested_sections() {
        let total = AtomicUsize::new(0);
        std::thread::scope(|s| {
            for _ in 0..3 {
                s.spawn(|| {
                    par_map_stream(
                        40,
                        8,
                        |_| {
                            par_map(10, |_| {
                                let mut sum = 0;
                                par_map_stream(5, 0, |k| k, |_, k| {
                                    sum += k;
                                    true
                                });
                                sum
                            })
                            .iter()
                            .sum::<usize>()
                        },
                        |_, v| {
                            total.fetch_add(v, Ordering::Relaxed);
                            true
                        },
                    )
                });
            }
        });
        assert_eq!(total.load(Ordering::Relaxed), 3 * 40 * 10 * 10);
    }
}
