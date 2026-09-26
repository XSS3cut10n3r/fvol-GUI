//! The persistent worker pool behind every parallel helper ([`crate::util::par`], and
//! [`for_each`] / [`map`] here).
//!
//! The workers start lazily (on the first parallel section, or at [`warm`]) and live for the
//! rest of the process. A parallel section is a *job* published to the pool: its owner (the
//! calling thread) works on it itself, idle workers join it (at most `max_helpers` at a time),
//! and the owner returns once every helper has left the job. So:
//!
//! * no thread is spawned per section (a 20-thread spawn + join costs 0.15-0.4 ms), and the
//!   workers' thread-local caches (TLB entries, scan buffers) stay warm from one section to
//!   the next;
//! * sections nest and run concurrently from any number of threads. An owner never waits for
//!   an item nobody has claimed (it runs unclaimed items itself); it only waits for items in
//!   progress on helpers, and a helper only ever waits for a job nested deeper inside its
//!   item. Waits therefore always point to deeper jobs and cannot form a cycle: no deadlock,
//!   whatever the pool size or the nesting;
//! * a panicking item is caught on the thread that ran it. The job stops handing out items,
//!   and once every helper has left, the owner re-raises the panic of the lowest-index failed
//!   item (the one a sequential loop would have hit first) with its original payload, so the
//!   CLI reports it like any plugin panic (python's uncaught exception).

use std::any::Any;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard};

/// A caught panic.
pub(crate) type Payload = Box<dyn Any + Send + 'static>;

/// A job's work as the pool sees it.
pub(crate) trait Work: Sync {
    /// Run items until none is left for this helper (or the job stopped).
    fn help(&self);
    /// Whether a helper joining now would find an item.
    fn has_work(&self) -> bool;
}

/// A published job (lives on the owner's stack while it is published).
struct Header {
    /// lifetime erased: see [`run_job`]
    work: *const (dyn Work + 'static),
    max_helpers: usize,
    /// helpers inside `work.help()` (changed under the pool lock)
    helpers: AtomicUsize,
    /// the owner waits for the helpers to leave (set under the pool lock)
    owner_waiting: AtomicBool,
}

struct State {
    /// published jobs, oldest first
    jobs: Vec<*const Header>,
    /// workers asleep on `wake`
    idle: usize,
}

// SAFETY: the job pointers are only dereferenced under the rules of `run_job`
unsafe impl Send for State {}

struct Pool {
    state: Mutex<State>,
    /// idle workers sleep here
    wake: Condvar,
    /// owners wait here for their helpers to leave
    done: Condvar,
    /// bumped whenever there may be new work (spinning workers watch it)
    epoch: AtomicU64,
}

static POOL: Pool = Pool {
    state: Mutex::new(State { jobs: Vec::new(), idle: 0 }),
    wake: Condvar::new(),
    done: Condvar::new(),
    epoch: AtomicU64::new(0),
};

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// How long an idle worker keeps looking for the next job before it sleeps (back-to-back
/// sections then start without a futex wake-up).
const SPIN: std::time::Duration = std::time::Duration::from_micros(50);

/// Start the workers (once; returns at once). One thread is spawned here and spawns the rest,
/// so the first parallel section pays for a single spawn and runs while the others start.
fn start() {
    static STARTED: AtomicBool = AtomicBool::new(false);
    if STARTED.load(Ordering::Relaxed) || STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    let n = crate::util::par::threads();
    if n <= 1 {
        return;
    }
    let spawn = |f: fn()| std::thread::Builder::new().name("rsvol-pool".into()).spawn(f).is_ok();
    // without any worker every owner simply runs its whole job itself
    spawn(|| {
        for _ in 1..crate::util::par::threads() {
            if std::thread::Builder::new().name("rsvol-pool".into()).spawn(worker).is_err() {
                break;
            }
        }
        worker();
    });
}

/// Start the pool's workers now, off the calling thread (returns at once): for callers that
/// know parallel work is coming after something serial.
pub fn warm() {
    start();
}

fn worker() {
    let p = &POOL;
    let mut s = lock(&p.state);
    let mut spun = false;
    loop {
        // the newest job first: the innermost of nested sections, which holds up the others
        let pick = s.jobs.iter().rev().copied().find(|&h| {
            // SAFETY: a published job is alive (its owner unpublishes it under this lock)
            let h = unsafe { &*h };
            h.helpers.load(Ordering::Relaxed) < h.max_helpers && unsafe { &*h.work }.has_work()
        });
        if let Some(h) = pick {
            // SAFETY: registered as a helper under the lock; the owner waits for it to leave
            let h = unsafe { &*h };
            h.helpers.fetch_add(1, Ordering::Relaxed);
            drop(s);
            unsafe { &*h.work }.help();
            s = lock(&p.state);
            if h.helpers.fetch_sub(1, Ordering::Relaxed) == 1 && h.owner_waiting.load(Ordering::Relaxed) {
                p.done.notify_all();
            }
            spun = false;
            continue;
        }
        if !spun {
            let e = p.epoch.load(Ordering::Acquire);
            drop(s);
            let t0 = std::time::Instant::now();
            'spin: loop {
                for _ in 0..64 {
                    if p.epoch.load(Ordering::Acquire) != e {
                        break 'spin;
                    }
                    std::hint::spin_loop();
                }
                if t0.elapsed() >= SPIN {
                    break;
                }
            }
            s = lock(&p.state);
            spun = true;
            continue;
        }
        s.idle += 1;
        s = p.wake.wait(s).unwrap_or_else(|e| e.into_inner());
        s.idle -= 1;
    }
}

/// Wake up to `k` idle workers (after new work appeared in a published job).
pub(crate) fn poke(k: usize) {
    let p = &POOL;
    let s = lock(&p.state);
    p.epoch.fetch_add(1, Ordering::Release);
    notify(&s, k);
}

fn notify(s: &State, k: usize) {
    let k = k.min(s.idle);
    if k == 0 {
        return;
    }
    if k == s.idle {
        POOL.wake.notify_all();
    } else {
        for _ in 0..k {
            POOL.wake.notify_one();
        }
    }
}

/// Run a job: the calling thread runs `owner`, which must work on `work` itself until nothing
/// is left to claim (it may also consume results), while up to `max_helpers` pool workers
/// join `work`. Returns (or unwinds) only after every helper has left the job.
pub(crate) fn run_job<R>(work: &(dyn Work + '_), max_helpers: usize, owner: impl FnOnce() -> R) -> R {
    if max_helpers == 0 || crate::util::par::threads() <= 1 {
        return owner();
    }
    start();
    // SAFETY: only the lifetime is erased. The job is unpublished and every helper has left
    // it before this function returns or unwinds (`Unpublish`), and a helper only touches it
    // between registering and deregistering under the pool lock.
    let work: *const (dyn Work + 'static) = unsafe { std::mem::transmute::<*const (dyn Work + '_), *const (dyn Work + 'static)>(work) };
    let h = Header { work, max_helpers, helpers: AtomicUsize::new(0), owner_waiting: AtomicBool::new(false) };
    struct Unpublish<'a>(&'a Header);
    impl Drop for Unpublish<'_> {
        fn drop(&mut self) {
            let p = &POOL;
            let mut s = lock(&p.state);
            if let Some(i) = s.jobs.iter().rposition(|&j| std::ptr::eq(j, self.0)) {
                s.jobs.remove(i);
            }
            self.0.owner_waiting.store(true, Ordering::Relaxed);
            while self.0.helpers.load(Ordering::Relaxed) > 0 {
                s = p.done.wait(s).unwrap_or_else(|e| e.into_inner());
            }
        }
    }
    {
        let p = &POOL;
        let mut s = lock(&p.state);
        s.jobs.push(&h);
        p.epoch.fetch_add(1, Ordering::Release);
        notify(&s, max_helpers);
    }
    let _unpublish = Unpublish(&h);
    owner()
}

/// The items `0..n` of a fork-join section ([`for_each_bounded`]).
struct Items<'a> {
    f: &'a (dyn Fn(usize) + Sync),
    n: usize,
    next: AtomicUsize,
    stop: AtomicBool,
    /// the lowest-index panic caught so far
    panic: Mutex<Option<(usize, Payload)>>,
}

impl Work for Items<'_> {
    fn help(&self) {
        while !self.stop.load(Ordering::Relaxed) {
            let i = self.next.fetch_add(1, Ordering::Relaxed);
            if i >= self.n {
                break;
            }
            // a claimed item always runs, so every item below a failed one runs too
            if let Err(p) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (self.f)(i))) {
                self.stop.store(true, Ordering::Relaxed);
                let mut g = lock(&self.panic);
                if g.as_ref().is_none_or(|(j, _)| i < *j) {
                    *g = Some((i, p));
                }
            }
        }
    }
    fn has_work(&self) -> bool {
        !self.stop.load(Ordering::Relaxed) && self.next.load(Ordering::Relaxed) < self.n
    }
}

/// Run `f(i)` for every `i` in `0..n` on at most `threads` threads (the caller's included).
/// A panic in `f` is re-raised here (the lowest-index one, with its payload) once every
/// thread has left; items not yet started when it happened are skipped.
pub(crate) fn for_each_bounded(n: usize, threads: usize, f: &(dyn Fn(usize) + Sync)) {
    let t = threads.min(crate::util::par::threads()).min(n);
    if t <= 1 {
        (0..n).for_each(f);
        return;
    }
    let job = Items { f, n, next: AtomicUsize::new(0), stop: AtomicBool::new(false), panic: Mutex::new(None) };
    run_job(&job, t - 1, || job.help());
    if let Some((_, p)) = job.panic.into_inner().unwrap_or_else(|e| e.into_inner()) {
        std::panic::resume_unwind(p);
    }
}

/// `(0..n).map(f).collect()` on at most `threads` threads; results in index order. Panics as
/// in [`for_each_bounded`].
pub(crate) fn map_bounded<R: Send>(n: usize, threads: usize, f: impl Fn(usize) -> R + Sync) -> Vec<R> {
    let t = threads.min(crate::util::par::threads()).min(n);
    if t <= 1 {
        return (0..n).map(f).collect();
    }
    let mut out: Vec<Option<R>> = (0..n).map(|_| None).collect();
    {
        struct Slots<R>(*mut Option<R>);
        // SAFETY: item i (claimed exactly once) writes only slot i
        unsafe impl<R: Send> Sync for Slots<R> {}
        let slots = Slots(out.as_mut_ptr());
        let slots = &slots;
        for_each_bounded(n, t, &|i| {
            let r = f(i);
            unsafe { *slots.0.add(i) = Some(r) };
        });
    }
    out.into_iter().map(|r| r.expect("pool task result")).collect()
}

/// Run `f(i)` for every `i` in `0..n` on the pool (and the calling thread).
pub fn for_each(n: usize, f: &(dyn Fn(usize) + Sync)) {
    for_each_bounded(n, usize::MAX, f)
}

/// `(0..n).map(f).collect()` on the pool; results in index order.
pub fn map<R: Send>(n: usize, f: impl Fn(usize) -> R + Sync) -> Vec<R> {
    map_bounded(n, usize::MAX, f)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn map_in_order_and_nested() {
        for n in [0usize, 1, 2, 7, 100, 1000] {
            let v = map(n, |i| i * 3);
            assert_eq!(v, (0..n).map(|i| i * 3).collect::<Vec<_>>());
        }
        // nested sections run on the pool too
        let v = map(8, |i| map(5, |j| i * 10 + j).iter().sum::<usize>());
        assert_eq!(v, (0..8).map(|i| (0..5).map(|j| i * 10 + j).sum::<usize>()).collect::<Vec<_>>());
        // concurrent owners share it
        std::thread::scope(|s| {
            let hs: Vec<_> = (0..4).map(|k| s.spawn(move || map(50, |i| i + k).iter().sum::<usize>())).collect();
            for (k, h) in hs.into_iter().enumerate() {
                assert_eq!(h.join().unwrap(), (0..50).map(|i| i + k).sum::<usize>());
            }
        });
    }

    /// Deep and wide nesting from many owners at once completes (no deadlock, whatever the
    /// pool size), with every item run exactly once.
    #[test]
    fn nesting_never_deadlocks() {
        fn rec(depth: u32, count: &AtomicUsize) {
            count.fetch_add(1, Ordering::Relaxed);
            if depth > 0 {
                for_each(3, &|_| rec(depth - 1, count));
            }
        }
        let count = AtomicUsize::new(0);
        std::thread::scope(|s| {
            for _ in 0..6 {
                s.spawn(|| rec(5, &count));
            }
        });
        // 1 + 3 + 9 + ... + 3^5 per owner
        assert_eq!(count.load(Ordering::Relaxed), 6 * (3usize.pow(6) - 1) / 2);
    }

    #[test]
    fn panics_propagate_after_join() {
        let r = std::panic::catch_unwind(|| {
            for_each(64, &|i| {
                if i == 17 {
                    panic!("boom");
                }
            })
        });
        assert!(r.is_err());
        // the pool still works
        assert_eq!(map(10, |i| i).len(), 10);
    }

    /// The payload of the lowest-index failing item is re-raised (python raises the first
    /// failure of its sequential loop), and a nested panic crosses both levels.
    #[test]
    fn panic_payload_is_the_lowest_index() {
        for _ in 0..20 {
            let r = std::panic::catch_unwind(|| {
                map(200, |i| {
                    if i % 50 == 13 {
                        // later items fail sooner
                        std::thread::sleep(std::time::Duration::from_micros((200 - i as u64) * 20));
                        std::panic::panic_any(format!("item {i}"));
                    }
                    i
                })
            });
            let p = r.unwrap_err();
            assert_eq!(p.downcast_ref::<String>().map(|s| s.as_str()), Some("item 13"));
        }
        let r = std::panic::catch_unwind(|| map(8, |i| map(8, |j| if i == 3 && j == 5 { panic!("inner {i} {j}") } else { j }).len()));
        assert_eq!(r.unwrap_err().downcast_ref::<String>().map(|s| s.as_str()), Some("inner 3 5"));
    }

    #[test]
    #[ignore]
    fn round_cost() {
        for _ in 0..3 {
            let t = std::time::Instant::now();
            for _ in 0..200 {
                for_each(20, &|i| {
                    std::hint::black_box(i);
                });
            }
            println!("pool round (20 tasks): {:.1} us", t.elapsed().as_secs_f64() * 1e6 / 200.0);
            let t = std::time::Instant::now();
            for _ in 0..200 {
                let next = AtomicUsize::new(0);
                std::thread::scope(|s| {
                    for _ in 0..crate::util::par::threads().min(20) {
                        s.spawn(|| {
                            while next.fetch_add(1, Ordering::Relaxed) < 20 {
                                std::hint::black_box(0);
                            }
                        });
                    }
                });
            }
            println!("scoped spawn round (20 tasks): {:.1} us", t.elapsed().as_secs_f64() * 1e6 / 200.0);
        }
    }
}
