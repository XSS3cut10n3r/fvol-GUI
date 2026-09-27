//! Background work that must finish before the process exits but not before the output: cache
//! writes. [`spawn`] starts a thread right away (the write overlaps the plugin run and its
//! output); `main` calls [`join_all`] after the output is complete, before `exit`.

use std::sync::Mutex;
use std::thread::JoinHandle;

static PENDING: Mutex<Vec<JoinHandle<()>>> = Mutex::new(Vec::new());

/// Run `f` on a background thread that [`join_all`] waits for. Runs inline if no thread can
/// be started.
pub fn spawn(f: impl FnOnce() + Send + 'static) {
    let f = std::sync::Arc::new(Mutex::new(Some(f)));
    let g = f.clone();
    let h = std::thread::Builder::new().name("fastvol-bg".into()).spawn(move || {
        if let Some(f) = g.lock().ok().and_then(|mut o| o.take()) {
            f();
        }
    });
    match h {
        Ok(h) => {
            let mut p = PENDING.lock().unwrap_or_else(|e| e.into_inner());
            // a long-running process (the web UI) should not accumulate finished handles
            p.retain(|h| !h.is_finished());
            p.push(h)
        }
        Err(_) => {
            if let Some(f) = f.lock().ok().and_then(|mut o| o.take()) {
                f();
            }
        }
    }
}

/// Wait for every background job started so far (and any they started).
pub fn join_all() {
    loop {
        let hs: Vec<JoinHandle<()>> = std::mem::take(&mut *PENDING.lock().unwrap_or_else(|e| e.into_inner()));
        if hs.is_empty() {
            return;
        }
        for h in hs {
            let _ = h.join();
        }
    }
}
