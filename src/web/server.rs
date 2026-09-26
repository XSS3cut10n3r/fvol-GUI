//! Accept loop: one thread per connection (they mostly sleep in reads; a spawn costs ~15 µs),
//! bounded by a global connection cap. Every request must arrive within a hard wall-clock
//! deadline, idle keep-alive connections are closed after 30 s, unauthenticated clients are
//! not kept alive, and long-lived streams have their own cap (see `api::StreamSlot`).

use super::App;
use super::http::{Conn, HttpError, Limits, Method, Response, write_response};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// How long a connection may sit idle between requests.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a client may take to send its first byte.
pub const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(10);
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_REQUESTS_PER_CONN: usize = 10_000;

static CONNS: AtomicUsize = AtomicUsize::new(0);

struct ConnSlot;
impl Drop for ConnSlot {
    fn drop(&mut self) {
        CONNS.fetch_sub(1, Ordering::Relaxed);
    }
}

fn refuse(mut s: TcpStream) {
    use std::io::Write;
    let _ = s.set_write_timeout(Some(Duration::from_secs(2)));
    let _ = s.write_all(b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 12\r\nconnection: close\r\nretry-after: 1\r\n\r\nserver busy\n");
}

pub fn serve(app: Arc<App>, listener: TcpListener, max_conns: usize) {
    for s in listener.incoming() {
        let Ok(s) = s else { continue };
        if CONNS.fetch_add(1, Ordering::Relaxed) >= max_conns {
            CONNS.fetch_sub(1, Ordering::Relaxed);
            refuse(s);
            continue;
        }
        let slot = ConnSlot;
        let app = app.clone();
        let spawned = std::thread::Builder::new().name("http".into()).stack_size(1 << 20).spawn(move || {
            let _slot = slot;
            handle_conn(&app, s);
        });
        if spawned.is_err() {
            // the closure (and its slot) was dropped
            continue;
        }
    }
}

fn handle_conn(app: &Arc<App>, s: TcpStream) {
    let _ = s.set_nodelay(true);
    let _ = s.set_write_timeout(Some(WRITE_TIMEOUT));
    let Ok(mut out) = s.try_clone() else { return };
    let mut conn = Conn::new(s);
    let limits = Limits::default();
    for n in 0..MAX_REQUESTS_PER_CONN {
        let timeout = if n == 0 { FIRST_BYTE_TIMEOUT } else { IDLE_TIMEOUT };
        let _ = conn.stream.set_read_timeout(Some(timeout));
        let req = match conn.read_request(&limits) {
            Ok(r) => r,
            Err(HttpError::Closed) | Err(HttpError::Io) => return,
            Err(e) => {
                if let Some(st) = e.status() {
                    let r = Response::text(st, e.message());
                    let _ = write_response(&mut out, r, true, false, false, &super::api::common_headers(false));
                }
                return;
            }
        };
        let head = req.method == Method::Head;
        let resp = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| super::api::handle(app, &req))) {
            Ok(r) => r,
            Err(_) => Response::text(500, "internal error"),
        };
        // clients without the token don't get to keep a connection open
        let keep = req.keep_alive && n + 1 < MAX_REQUESTS_PER_CONN && resp.status != 401 && resp.status != 421;
        let html = resp.headers.iter().any(|(n, v)| *n == "content-type" && v.starts_with("text/html"));
        match write_response(&mut out, resp, req.http11, keep, head, &super::api::common_headers(html)) {
            Ok(true) => continue,
            _ => return,
        }
    }
}
