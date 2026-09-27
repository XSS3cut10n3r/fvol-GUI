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
    /// workers looking for a job before they sleep (see [`spin`])
    spinning: usize,
    /// workers started or being started
    workers: usize,
    /// workers still to be started by the ones starting (see [`grow`])
    to_start: usize,
    /// workers whose thread runs (or ran)
    started: usize,
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
    state: Mutex::new(State { jobs: Vec::new(), idle: 0, spinning: 0, workers: 0, to_start: 0, started: 0 }),
    wake: Condvar::new(),
    done: Condvar::new(),
    epoch: AtomicU64::new(0),
};

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// How long an idle worker keeps looking for the next job before it sleeps: back-to-back
/// sections then start without a futex wake-up (`FASTVOL_POOL_SPIN_US`, default 20).
fn spin() -> std::time::Duration {
    static US: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    std::time::Duration::from_micros(*US.get_or_init(|| crate::util::env::var("POOL_SPIN_US").ok().and_then(|v| v.parse().ok()).unwrap_or(20)))
}

/// Reserve `k` more workers (up to [`crate::util::par::threads`] in all); true when the caller
/// must start one ([`spawn_worker`]). Every worker starting starts others while some are still
/// due, so `k` workers are up after ~log2(k) thread creations instead of `k` in a row.
fn grow(s: &mut State, k: usize) -> bool {
    let k = k.min(crate::util::par::threads().saturating_sub(s.workers));
    if k == 0 || SHUTDOWN.load(Ordering::Relaxed) {
        return false;
    }
    s.workers += k;
    s.to_start += k - 1;
    true
}

/// Set by [`shutdown`]: workers leave, and every section runs on its caller alone.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// One word per started worker: nonzero until its thread has left the address space (see
/// [`leave`]).
static GONE: Mutex<Vec<&'static std::sync::atomic::AtomicU32>> = Mutex::new(Vec::new());

/// Stop the pool at the end of a one-shot run (`main`, before `util::exit` hands the address
/// space to its teardown helper): every worker leaves, and when this returns no worker thread
/// uses the address space any more. For idle workers (no section running); later sections run
/// on their caller alone.
pub fn shutdown() {
    {
        let mut s = lock(&POOL.state);
        if SHUTDOWN.swap(true, Ordering::Relaxed) {
            return;
        }
        // workers not started yet never will be
        s.workers -= std::mem::take(&mut s.to_start);
        POOL.epoch.fetch_add(1, Ordering::Release);
    }
    POOL.wake.notify_all();
    // the workers being started (whose words are not listed yet) first
    let mut s = lock(&POOL.state);
    while s.started < s.workers {
        s = POOL.done.wait(s).unwrap_or_else(|e| e.into_inner());
    }
    drop(s);
    for gone in lock(&GONE).iter() {
        wait_zero(gone);
    }
}

/// Stack of a worker: nested sections run their items on the thread that waits for them, below
/// the frames of the item it is in (a scoped thread used to start with a fresh 2 MiB stack for
/// each), so workers get the main thread's usual 8 MiB (reserved, touched only as used).
const WORKER_STACK: usize = 8 << 20;

fn spawn_worker() {
    let started = std::thread::Builder::new().name("fastvol-pool".into()).stack_size(WORKER_STACK).spawn(|| {
        let gone: &'static std::sync::atomic::AtomicU32 = Box::leak(Box::new(std::sync::atomic::AtomicU32::new(1)));
        {
            let mut s = lock(&POOL.state);
            s.started += 1;
            lock(&GONE).push(gone);
            if SHUTDOWN.load(Ordering::Relaxed) {
                POOL.done.notify_all();
            }
        }
        // start the others still due first (each start is ~10-20 us of kernel work)
        loop {
            let mut s = lock(&POOL.state);
            if s.to_start == 0 {
                break;
            }
            s.to_start -= 1;
            drop(s);
            spawn_worker();
        }
        worker();
        leave(gone);
    });
    if started.is_err() {
        // without workers every owner simply runs its whole job itself
        let mut s = lock(&POOL.state);
        s.workers -= 1 + std::mem::take(&mut s.to_start);
        if SHUTDOWN.load(Ordering::Relaxed) {
            POOL.done.notify_all();
        }
    }
}

/// End a worker's thread after [`shutdown`]: the kernel zeroes `gone` (and wakes its waiter)
/// once the thread no longer uses the address space (`set_tid_address`). The thread ends right
/// away, without the thread library's exit: its thread-locals are not dropped and its stack is
/// not unmapped (nothing is left that uses them; the process exits next and its teardown
/// frees them), which keeps the exit path short.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn leave(gone: &'static std::sync::atomic::AtomicU32) -> ! {
    unsafe extern "C" {
        fn syscall(n: std::ffi::c_long, ...) -> std::ffi::c_long;
    }
    const SYS_EXIT: std::ffi::c_long = 60;
    const SYS_SET_TID_ADDRESS: std::ffi::c_long = 218;
    // SAFETY: `gone` lives forever; a thread exit takes no other resource with it
    unsafe {
        syscall(SYS_SET_TID_ADDRESS, gone.as_ptr());
        loop {
            syscall(SYS_EXIT, 0);
        }
    }
}

/// [`leave`] elsewhere: the thread ends normally, after it is counted out.
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn leave(gone: &'static std::sync::atomic::AtomicU32) {
    gone.store(0, Ordering::Release);
}

/// Wait until `word` is zero (the kernel zeroes and wakes it, see [`leave`]).
fn wait_zero(word: &std::sync::atomic::AtomicU32) {
    loop {
        let v = word.load(Ordering::Acquire);
        if v == 0 {
            return;
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            unsafe extern "C" {
                fn syscall(n: std::ffi::c_long, ...) -> std::ffi::c_long;
            }
            const SYS_FUTEX: std::ffi::c_long = 202;
            // FUTEX_WAIT without the private flag: the kernel's wake at thread exit is shared
            const FUTEX_WAIT: std::ffi::c_int = 0;
            // SAFETY: a futex wait on a live word; returns on a wake, a changed value or a signal
            unsafe {
                syscall(SYS_FUTEX, word.as_ptr(), FUTEX_WAIT, v, std::ptr::null::<u8>());
            }
        }
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        std::thread::yield_now();
    }
}

/// Start the pool's workers now (returns at once): for callers that know parallel work is
/// coming after something serial.
pub fn warm() {
    let mut s = lock(&POOL.state);
    let spawn = crate::util::par::threads() > 1 && grow(&mut s, usize::MAX);
    drop(s);
    if spawn {
        spawn_worker();
    }
}

fn worker() {
    let p = &POOL;
    let mut s = lock(&p.state);
    let mut spun = false;
    loop {
        if SHUTDOWN.load(Ordering::Relaxed) {
            return;
        }
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
        if !spun && !spin().is_zero() {
            let e = p.epoch.load(Ordering::Acquire);
            s.spinning += 1;
            drop(s);
            let t0 = std::time::Instant::now();
            'spin: loop {
                for _ in 0..64 {
                    if p.epoch.load(Ordering::Acquire) != e {
                        break 'spin;
                    }
                    std::hint::spin_loop();
                }
                if t0.elapsed() >= spin() {
                    break;
                }
            }
            s = lock(&p.state);
            s.spinning -= 1;
            spun = true;
            continue;
        }
        s.idle += 1;
        s = p.wake.wait(s).unwrap_or_else(|e| e.into_inner());
        s.idle -= 1;
        spun = true;
    }
}

/// Wake up to `k` idle workers (after new work appeared in a published job).
pub(crate) fn poke(k: usize) {
    let p = &POOL;
    let s = lock(&p.state);
    p.epoch.fetch_add(1, Ordering::Release);
    let (wake, all) = (k.min(s.idle), k >= s.idle);
    drop(s);
    notify(wake, all);
}

/// Wake `k` sleeping workers (`all`: every one).
fn notify(k: usize, all: bool) {
    if k == 0 {
    } else if all {
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
    if max_helpers == 0 || crate::util::par::threads() <= 1 || SHUTDOWN.load(Ordering::Relaxed) {
        return owner();
    }
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
    let p = &POOL;
    // (before the job is published: it is taken back whatever happens next)
    let _unpublish = Unpublish(&h);
    let mut s = lock(&p.state);
    s.jobs.push(&h);
    p.epoch.fetch_add(1, Ordering::Release);
    // wake sleepers; start workers when too few are around (busy ones join when their items
    // are done)
    let (wake, all) = (max_helpers.min(s.idle), max_helpers >= s.idle);
    let short = max_helpers.saturating_sub(s.idle + s.spinning);
    let spawn = short > 0 && grow(&mut s, short);
    drop(s);
    notify(wake, all);
    if spawn {
        spawn_worker();
    }
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

    /// After [`shutdown`] no worker thread is left (the process has its main thread only) and
    /// sections still work, on their caller. Runs in a child process: the pool is global.
    #[test]
    fn shutdown_leaves_no_worker() {
        if crate::util::env::var_os("POOL_SHUTDOWN_CHILD").is_some() {
            // threads other than the harness's (libtest may run the test on a thread of its own)
            let tasks = || {
                std::fs::read_dir("/proc/self/task")
                    .map(|d| d.flatten().filter(|t| std::fs::read_to_string(t.path().join("comm")).is_ok_and(|c| c.starts_with("fastvol-pool"))).count())
                    .unwrap_or(0)
            };
            // nested sections: all workers started
            let v = map(64, |i| map(8, |j| i * j).iter().sum::<usize>());
            assert_eq!(v.len(), 64);
            // (workers may still be starting: shutdown waits for them too)
            shutdown();
            assert_eq!(tasks(), 0, "workers left after shutdown");
            let gone = lock(&GONE);
            assert!(crate::util::par::threads() <= 1 || !gone.is_empty());
            assert!(gone.iter().all(|g| g.load(Ordering::Relaxed) == 0));
            drop(gone);
            assert_eq!(map(100, |i| i * 2), (0..100).map(|i| i * 2).collect::<Vec<_>>());
            let mut seen = 0;
            crate::util::par::par_map_stream(50, 4, |i| i, |_, _| {
                seen += 1;
                true
            });
            assert_eq!(seen, 50);
            shutdown();
            return;
        }
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "util::pool::tests::shutdown_leaves_no_worker", "--test-threads=1", "--nocapture"])
            .env("FASTVOL_POOL_SHUTDOWN_CHILD", "1")
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success() && text.contains("1 passed"), "{text}");
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
