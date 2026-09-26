//! Ordered, memory-bounded parallel job pipeline for the streaming encoders
//! ([`super::gzip_enc::GzipEncoder`], [`super::bzip2_enc::Bzip2Encoder`],
//! [`super::xz_enc::XzEncoder`]).
//!
//! The producer (the thread calling `Write::write`) submits numbered jobs; long-lived worker
//! threads (spawned lazily, up to `max_threads`) run `work(&mut state, job)` with a per-thread
//! state built by `init` (compressor tables are allocated once per thread); results are
//! handed back strictly in submission order. The producer bounds memory by collecting results
//! (blocking) whenever `in_flight()` reaches its budget: that is the backpressure on `write`.
//! With `max_threads <= 1` jobs run inline on the calling thread (no threads at all).

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;

type WorkFn<S, J, R> = dyn Fn(&mut S, J) -> R + Send + Sync;
type InitFn<S> = dyn Fn() -> S + Send + Sync;

struct Queue<J, R> {
    jobs: VecDeque<(u64, J)>,
    done: BTreeMap<u64, std::thread::Result<R>>,
    shutdown: bool,
    idle: usize,
}

struct Shared<J, R> {
    q: Mutex<Queue<J, R>>,
    job_cv: Condvar,
    done_cv: Condvar,
}

impl<J, R> Shared<J, R> {
    fn lock(&self) -> MutexGuard<'_, Queue<J, R>> {
        self.q.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// See the module documentation.
pub(crate) struct Pipeline<S, J, R> {
    shared: Arc<Shared<J, R>>,
    init: Arc<InitFn<S>>,
    work: Arc<WorkFn<S, J, R>>,
    handles: Vec<JoinHandle<()>>,
    max_threads: usize,
    next_seq: u64,
    next_out: u64,
    local: Option<S>,
}

impl<S: 'static, J: Send + 'static, R: Send + 'static> Pipeline<S, J, R> {
    /// A pipeline with at most `max_threads` workers (0 or 1 = run jobs inline).
    pub(crate) fn new(
        max_threads: usize,
        init: impl Fn() -> S + Send + Sync + 'static,
        work: impl Fn(&mut S, J) -> R + Send + Sync + 'static,
    ) -> Self {
        Pipeline {
            shared: Arc::new(Shared {
                q: Mutex::new(Queue { jobs: VecDeque::new(), done: BTreeMap::new(), shutdown: false, idle: 0 }),
                job_cv: Condvar::new(),
                done_cv: Condvar::new(),
            }),
            init: Arc::new(init),
            work: Arc::new(work),
            handles: Vec::new(),
            max_threads,
            next_seq: 0,
            next_out: 0,
            local: None,
        }
    }

    /// Jobs submitted whose results have not been returned by [`Pipeline::next`] yet.
    pub(crate) fn in_flight(&self) -> usize {
        (self.next_seq - self.next_out) as usize
    }

    /// Number of jobs submitted so far.
    pub(crate) fn submitted(&self) -> u64 {
        self.next_seq
    }

    /// Queues `job` for a worker (or runs it inline when the pipeline has no workers).
    pub(crate) fn submit(&mut self, job: J) {
        if self.max_threads <= 1 {
            self.run_inline(job);
            return;
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        let spawn = {
            let mut q = self.shared.lock();
            q.jobs.push_back((seq, job));
            q.idle == 0 && self.handles.len() < self.max_threads
        };
        self.shared.job_cv.notify_one();
        if spawn {
            let (shared, init, work) = (self.shared.clone(), self.init.clone(), self.work.clone());
            let h = std::thread::Builder::new()
                .name("rsvol-enc".into())
                .spawn(move || worker(&shared, &*init, &*work));
            match h {
                Ok(h) => self.handles.push(h),
                // No thread available: run everything queued inline (in order) instead.
                Err(_) if self.handles.is_empty() => self.drain_queue_inline(),
                Err(_) => {}
            }
        }
    }

    /// Runs `job` on the calling thread; its result is returned in order like any other.
    pub(crate) fn run_inline(&mut self, job: J) {
        let seq = self.next_seq;
        self.next_seq += 1;
        let r = self.compute_local(job);
        self.shared.lock().done.insert(seq, r);
    }

    fn compute_local(&mut self, job: J) -> std::thread::Result<R> {
        let st = self.local.get_or_insert_with(|| (self.init)());
        let work = &self.work;
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| work(st, job)));
        if r.is_err() {
            self.local = None;
        }
        r
    }

    fn drain_queue_inline(&mut self) {
        loop {
            let Some((seq, job)) = self.shared.lock().jobs.pop_front() else { break };
            let r = self.compute_local(job);
            self.shared.lock().done.insert(seq, r);
        }
    }

    /// The next result in submission order: `None` when nothing is in flight, or (with
    /// `block == false`) when the next result is not ready yet. A job that panicked yields an
    /// error.
    pub(crate) fn next(&mut self, block: bool) -> Option<std::io::Result<R>> {
        if self.next_out == self.next_seq {
            return None;
        }
        let mut q = self.shared.lock();
        loop {
            if let Some(r) = q.done.remove(&self.next_out) {
                drop(q);
                self.next_out += 1;
                return Some(r.map_err(|_| std::io::Error::other("encoder worker panicked")));
            }
            if !block {
                return None;
            }
            q = self.shared.done_cv.wait(q).unwrap_or_else(|e| e.into_inner());
        }
    }
}

fn worker<S, J, R>(shared: &Shared<J, R>, init: &InitFn<S>, work: &WorkFn<S, J, R>) {
    let mut state: Option<S> = None;
    loop {
        let (seq, job) = {
            let mut q = shared.lock();
            loop {
                if let Some(j) = q.jobs.pop_front() {
                    break j;
                }
                if q.shutdown {
                    return;
                }
                q.idle += 1;
                q = shared.job_cv.wait(q).unwrap_or_else(|e| e.into_inner());
                q.idle -= 1;
            }
        };
        let st = state.get_or_insert_with(init);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| work(st, job)));
        if r.is_err() {
            state = None;
        }
        shared.lock().done.insert(seq, r);
        shared.done_cv.notify_all();
    }
}

impl<S, J, R> Drop for Pipeline<S, J, R> {
    fn drop(&mut self) {
        {
            let mut q = self.shared.lock();
            q.shutdown = true;
            q.jobs.clear();
        }
        self.shared.job_cv.notify_all();
        for h in self.handles.drain(..) {
            let _ = h.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codecs_enc_pipeline_ordered_bounded() {
        for threads in [1usize, 2, 7] {
            let mut p: Pipeline<u64, u64, u64> = Pipeline::new(
                threads,
                || 0,
                |calls, x| {
                    *calls += 1;
                    // uneven work so results complete out of order
                    std::thread::sleep(std::time::Duration::from_micros((x * 7919) % 300));
                    x * x
                },
            );
            let mut got = Vec::new();
            for i in 0..200u64 {
                p.submit(i);
                while p.in_flight() >= 5 {
                    got.push(p.next(true).unwrap().unwrap());
                }
                while let Some(r) = p.next(false) {
                    got.push(r.unwrap());
                }
            }
            while let Some(r) = p.next(true) {
                got.push(r.unwrap());
            }
            assert_eq!(got, (0..200u64).map(|i| i * i).collect::<Vec<_>>(), "threads {threads}");
        }
    }

    #[test]
    fn codecs_enc_pipeline_panic_is_error() {
        let mut p: Pipeline<(), u32, u32> = Pipeline::new(3, || (), |_, x| if x == 3 { panic!("boom") } else { x });
        for i in 0..6 {
            p.submit(i);
        }
        let r: Vec<bool> = std::iter::from_fn(|| p.next(true)).map(|r| r.is_ok()).collect();
        assert_eq!(r, [true, true, true, false, true, true]);
    }
}
