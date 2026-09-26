//! A persistent worker pool for short fork-join phases.
//!
//! [`crate::util::par`] spawns fresh scoped threads per call (~0.2 ms for 20 threads). The ISF
//! loader runs half a dozen parallel phases of 0.1-2 ms each back to back, where that spawn
//! cost is a large share; this pool starts its workers once and hands them jobs.
//!
//! * [`for_each`] – run `f(i)` for `i in 0..n` on the pool plus the calling thread.
//! * [`map`] – the same, collecting the results in index order.
//!
//! One job runs at a time: a call made while the pool is busy (another thread's job) falls
//! back to [`crate::util::par`]; a call from inside a pool task runs inline (no deadlock).
//! A panicking task is re-raised on the caller after every worker has left the job.

use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, OnceLock};

/// One fork-join job; lives on the caller's stack for the duration of the call.
struct Job {
    /// the task function, lifetime erased (the caller outlives every use, see `for_each`)
    f: *const (dyn Fn(usize) + Sync),
    n: usize,
    next: AtomicUsize,
    panicked: AtomicBool,
}

struct State {
    job: *const Job,
    /// workers currently inside `job`
    busy: usize,
}

// SAFETY: the raw pointers are only dereferenced while the owning call waits (see for_each)
unsafe impl Send for State {}

struct Pool {
    state: Mutex<State>,
    generation: AtomicU64,
    wake: Condvar,
    done: Condvar,
    run: Mutex<()>,
    workers: usize,
}

thread_local! {
    static IN_POOL: Cell<bool> = const { Cell::new(false) };
}

fn pool() -> &'static Pool {
    static P: OnceLock<&'static Pool> = OnceLock::new();
    P.get_or_init(|| {
        let workers = crate::util::par::threads().saturating_sub(1);
        let p: &'static Pool = Box::leak(Box::new(Pool {
            state: Mutex::new(State { job: std::ptr::null(), busy: 0 }),
            generation: AtomicU64::new(0),
            wake: Condvar::new(),
            done: Condvar::new(),
            run: Mutex::new(()),
            workers,
        }));
        for _ in 0..workers {
            if std::thread::Builder::new().name("rsvol-pool".into()).spawn(move || worker(p)).is_err() {
                break;
            }
        }
        p
    })
}

/// Execute tasks of `job` until none are left.
fn drain(job: &Job) {
    // SAFETY: `f` outlives the job (the caller of for_each waits for every worker)
    let f = unsafe { &*job.f };
    loop {
        let i = job.next.fetch_add(1, Ordering::Relaxed);
        if i >= job.n {
            break;
        }
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(i))).is_err() {
            job.panicked.store(true, Ordering::Relaxed);
        }
    }
}

fn worker(p: &'static Pool) {
    IN_POOL.with(|c| c.set(true));
    let mut seen = 0u64;
    loop {
        // spin briefly (back-to-back phases), then sleep
        let mut spins = 0u32;
        while p.generation.load(Ordering::Acquire) == seen && spins < 20_000 {
            std::hint::spin_loop();
            spins += 1;
        }
        let job = {
            let mut s = p.state.lock().unwrap_or_else(|e| e.into_inner());
            while p.generation.load(Ordering::Acquire) == seen {
                s = p.wake.wait(s).unwrap_or_else(|e| e.into_inner());
            }
            seen = p.generation.load(Ordering::Acquire);
            if s.job.is_null() {
                continue;
            }
            s.busy += 1;
            s.job
        };
        // SAFETY: registered as busy under the lock while the job was published
        drain(unsafe { &*job });
        let mut s = p.state.lock().unwrap_or_else(|e| e.into_inner());
        s.busy -= 1;
        if s.busy == 0 {
            p.done.notify_all();
        }
    }
}

/// Run `f(i)` for every `i` in `0..n` on the pool (and the calling thread).
pub fn for_each(n: usize, f: &(dyn Fn(usize) + Sync)) {
    if n <= 1 || IN_POOL.with(|c| c.get()) {
        (0..n).for_each(f);
        return;
    }
    let p = pool();
    if p.workers == 0 {
        (0..n).for_each(f);
        return;
    }
    let Ok(_run) = p.run.try_lock() else {
        crate::util::par::par_for(n, f);
        return;
    };
    // SAFETY: the lifetime is erased only for the duration of this call: the job is
    // unpublished and every worker that joined it has left before we return
    let f_static: *const (dyn Fn(usize) + Sync) = unsafe { std::mem::transmute::<&(dyn Fn(usize) + Sync), &'static (dyn Fn(usize) + Sync)>(f) };
    let job = Job { f: f_static, n, next: AtomicUsize::new(0), panicked: AtomicBool::new(false) };
    {
        let mut s = p.state.lock().unwrap_or_else(|e| e.into_inner());
        s.job = &job;
        p.generation.fetch_add(1, Ordering::AcqRel);
        p.wake.notify_all();
    }
    IN_POOL.with(|c| c.set(true));
    drain(&job);
    IN_POOL.with(|c| c.set(false));
    {
        let mut s = p.state.lock().unwrap_or_else(|e| e.into_inner());
        s.job = std::ptr::null();
        while s.busy > 0 {
            s = p.done.wait(s).unwrap_or_else(|e| e.into_inner());
        }
    }
    if job.panicked.load(Ordering::Relaxed) {
        panic!("a parallel task panicked");
    }
}

/// `(0..n).map(f).collect()` on the pool; results in index order.
pub fn map<R: Send>(n: usize, f: impl Fn(usize) -> R + Sync) -> Vec<R> {
    let mut out: Vec<Option<R>> = (0..n).map(|_| None).collect();
    {
        struct Slots<R>(*mut Option<R>);
        // SAFETY: task i writes only slot i
        unsafe impl<R: Send> Sync for Slots<R> {}
        let slots = Slots(out.as_mut_ptr());
        let slots = &slots;
        for_each(n, &|i| {
            let r = f(i);
            unsafe { *slots.0.add(i) = Some(r) };
        });
    }
    out.into_iter().map(|r| r.expect("pool task result")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_in_order_and_nested() {
        for n in [0usize, 1, 2, 7, 100, 1000] {
            let v = map(n, |i| i * 3);
            assert_eq!(v, (0..n).map(|i| i * 3).collect::<Vec<_>>());
        }
        // nested calls run inline, concurrent callers fall back to scoped threads
        let v = map(8, |i| map(5, |j| i * 10 + j).iter().sum::<usize>());
        assert_eq!(v, (0..8).map(|i| (0..5).map(|j| i * 10 + j).sum::<usize>()).collect::<Vec<_>>());
        std::thread::scope(|s| {
            let hs: Vec<_> = (0..4).map(|k| s.spawn(move || map(50, |i| i + k).iter().sum::<usize>())).collect();
            for (k, h) in hs.into_iter().enumerate() {
                assert_eq!(h.join().unwrap(), (0..50).map(|i| i + k).sum::<usize>());
            }
        });
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
        }
    }
}
