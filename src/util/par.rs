//! Parallel helpers on `std::thread::scope` with atomic work stealing. Results always come back
//! in index order, so output stays deterministic (python volatility3 order).
//!
//! * [`par_for`]      – run `f(i)` for `i in 0..n` on all cores.
//! * [`par_map`]      – `(0..n).map(f).collect()` in parallel, results in order.
//! * [`par_map_stream`] – parallel map with in-order streaming consumption on the calling thread
//!   and early stop (for "scan until the first good hit" patterns), with bounded look-ahead.
//!
//! Use them for anything that touches lots of memory (scans, per-process work). For tiny `n`
//! they run inline on the caller's thread.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, OnceLock};

/// Number of worker threads to use (all logical CPUs; override with `RSVOL_THREADS`).
pub fn threads() -> usize {
    static N: OnceLock<usize> = OnceLock::new();
    *N.get_or_init(|| {
        if let Some(n) = std::env::var("RSVOL_THREADS").ok().and_then(|v| v.parse::<usize>().ok()) {
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
    let t = threads().min(n);
    if t <= 1 {
        (0..n).for_each(f);
        return;
    }
    let next = AtomicUsize::new(0);
    std::thread::scope(|s| {
        for _ in 0..t {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= n {
                        break;
                    }
                    f(i);
                }
            });
        }
    });
}

/// Parallel `(0..n).map(f).collect::<Vec<_>>()`; results in index order.
pub fn par_map<R, F>(n: usize, f: F) -> Vec<R>
where
    R: Send,
    F: Fn(usize) -> R + Sync,
{
    let t = threads().min(n);
    if t <= 1 {
        return (0..n).map(f).collect();
    }
    let next = AtomicUsize::new(0);
    let mut parts: Vec<Vec<(usize, R)>> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..t)
            .map(|_| {
                s.spawn(|| {
                    let mut local = Vec::new();
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        if i >= n {
                            break;
                        }
                        local.push((i, f(i)));
                    }
                    local
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().expect("worker panicked")).collect()
    });
    // reassemble in order
    let mut slots: Vec<Option<R>> = (0..n).map(|_| None).collect();
    for part in parts.iter_mut() {
        for (i, r) in part.drain(..) {
            slots[i] = Some(r);
        }
    }
    slots.into_iter().map(|r| r.expect("missing result")).collect()
}

/// Parallel map over `0..n` whose results are handed to `consume` on the calling thread in
/// index order as soon as they are ready. `consume` returns `false` to stop early; workers then
/// stop picking up new items. At most `lookahead` items are computed ahead of the consumer
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
    let lookahead = if lookahead == 0 { usize::MAX } else { lookahead.max(t) };
    struct Shared<R> {
        slots: Vec<Option<R>>,
        consumed: usize,
    }
    let shared = Mutex::new(Shared { slots: (0..n).map(|_| None).collect(), consumed: 0 });
    let ready = Condvar::new(); // signalled when a slot is filled
    let space = Condvar::new(); // signalled when the consumer advances
    let next = AtomicUsize::new(0);
    let stop = AtomicBool::new(false);
    std::thread::scope(|s| {
        for _ in 0..t {
            s.spawn(|| {
                loop {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= n {
                        break;
                    }
                    // bounded look-ahead
                    if lookahead != usize::MAX {
                        let mut g = shared.lock().unwrap();
                        while i >= g.consumed.saturating_add(lookahead) && !stop.load(Ordering::Relaxed) {
                            g = space.wait(g).unwrap();
                        }
                        drop(g);
                        if stop.load(Ordering::Relaxed) {
                            break;
                        }
                    }
                    let r = f(i);
                    let mut g = shared.lock().unwrap();
                    g.slots[i] = Some(r);
                    drop(g);
                    ready.notify_all();
                }
            });
        }
        // consumer
        let mut i = 0;
        while i < n {
            let r = {
                let mut g = shared.lock().unwrap();
                loop {
                    if let Some(r) = g.slots[i].take() {
                        g.consumed = i + 1;
                        break r;
                    }
                    g = ready.wait(g).unwrap();
                }
            };
            space.notify_all();
            if !consume(i, r) {
                stop.store(true, Ordering::Relaxed);
                space.notify_all();
                break;
            }
            i += 1;
        }
        stop.store(true, Ordering::Relaxed);
        space.notify_all();
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn map_in_order() {
        let v = par_map(1000, |i| i * 2);
        assert_eq!(v, (0..1000).map(|i| i * 2).collect::<Vec<_>>());
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
    #[test]
    fn for_all() {
        let c = AtomicUsize::new(0);
        par_for(12345, |_| {
            c.fetch_add(1, Ordering::Relaxed);
        });
        assert_eq!(c.load(Ordering::Relaxed), 12345);
    }
}
