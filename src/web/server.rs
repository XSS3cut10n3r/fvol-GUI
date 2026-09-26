//! Accept loop + fixed worker pool. Each worker owns one connection at a time and serves its
//! keep-alive requests; a full queue answers 503 straight from the acceptor.

use super::App;
use super::http::{Conn, HttpError, Limits, Method, Response, write_response};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// How long a connection may sit idle between requests.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a client may take to send one request once it started.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_REQUESTS_PER_CONN: usize = 10_000;

pub fn serve(app: Arc<App>, listener: TcpListener, workers: usize) {
    let (tx, rx): (SyncSender<TcpStream>, Receiver<TcpStream>) = sync_channel(256);
    let rx = Arc::new(Mutex::new(rx));
    for i in 0..workers.max(2) {
        let rx = rx.clone();
        let app = app.clone();
        let _ = std::thread::Builder::new().name(format!("http-{i}")).spawn(move || {
            loop {
                let s = match rx.lock().unwrap_or_else(|e| e.into_inner()).recv() {
                    Ok(s) => s,
                    Err(_) => return,
                };
                handle_conn(&app, s);
            }
        });
    }
    for s in listener.incoming() {
        let Ok(s) = s else { continue };
        match tx.try_send(s) {
            Ok(()) => {}
            Err(TrySendError::Full(mut s)) => {
                use std::io::Write;
                let _ = s.set_write_timeout(Some(Duration::from_secs(2)));
                let _ = s.write_all(b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 12\r\nconnection: close\r\nretry-after: 1\r\n\r\nserver busy\n");
            }
            Err(TrySendError::Disconnected(_)) => return,
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
        let timeout = if n == 0 || conn.pending() > 0 { REQUEST_TIMEOUT } else { IDLE_TIMEOUT };
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
        let keep = req.keep_alive && n + 1 < MAX_REQUESTS_PER_CONN;
        let resp = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| super::api::handle(app, &req))) {
            Ok(r) => r,
            Err(_) => Response::text(500, "internal error"),
        };
        let html = resp.headers.iter().any(|(n, v)| *n == "content-type" && v.starts_with("text/html"));
        match write_response(&mut out, resp, req.http11, keep, head, &super::api::common_headers(html)) {
            Ok(true) => continue,
            _ => return,
        }
    }
}
