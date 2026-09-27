//! A small, strict HTTP/1.1 implementation for `fvol serve`: request parsing with hard limits,
//! keep-alive with pipelining, fixed-length / chunked responses.
//!
//! Deliberately strict (this server reads evidence; ambiguity is how request smuggling and
//! parser differentials happen): CRLF line endings only, no obs-fold, origin-form targets
//! only, a single valid Content-Length, request bodies with Transfer-Encoding are refused
//! (501), header names must be tokens, and every size is capped.

use std::io::{self, Read, Write};

/// Size limits for one request.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// request line + headers (bytes, including the blank line)
    pub max_head: usize,
    pub max_headers: usize,
    pub max_body: usize,
    /// total time a client may take to send one request, from its first byte
    pub request_time: std::time::Duration,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits { max_head: 16 * 1024, max_headers: 64, max_body: 1 << 20, request_time: std::time::Duration::from_secs(10) }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
    Post,
    Delete,
    Options,
    Other,
}

#[derive(Debug)]
pub struct Request {
    pub method: Method,
    /// percent-decoded path (always starts with '/')
    pub path: String,
    /// decoded query parameters in order
    pub query: Vec<(String, String)>,
    /// header names lower-cased, values trimmed
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// HTTP/1.1 (true) or HTTP/1.0
    pub http11: bool,
    /// the client asked to keep the connection open (1.1 default, 1.0 with keep-alive)
    pub keep_alive: bool,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }
    pub fn param(&self, name: &str) -> Option<&str> {
        self.query.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }
}

/// Why a request could not be read. `status()` is the response to send (None: just close).
#[derive(Debug, PartialEq, Eq)]
pub enum HttpError {
    /// connection closed (or idle timeout) before any byte of a request
    Closed,
    /// timed out in the middle of a request
    Timeout,
    Bad(&'static str),
    HeadTooLarge,
    BodyTooLarge,
    NotImplemented(&'static str),
    Version,
    Io,
}

impl HttpError {
    pub fn status(&self) -> Option<u16> {
        match self {
            HttpError::Closed | HttpError::Io => None,
            HttpError::Timeout => Some(408),
            HttpError::Bad(_) => Some(400),
            HttpError::HeadTooLarge => Some(431),
            HttpError::BodyTooLarge => Some(413),
            HttpError::NotImplemented(_) => Some(501),
            HttpError::Version => Some(505),
        }
    }
    pub fn message(&self) -> &'static str {
        match self {
            HttpError::Bad(m) | HttpError::NotImplemented(m) => m,
            HttpError::HeadTooLarge => "request header too large",
            HttpError::BodyTooLarge => "request body too large",
            HttpError::Timeout => "request timeout",
            HttpError::Version => "HTTP version not supported",
            _ => "",
        }
    }
}

/// Buffered reader over a connection that keeps bytes of pipelined requests.
pub struct Conn<S> {
    pub stream: S,
    buf: Vec<u8>,
    start: usize,
    end: usize,
}

fn is_tchar(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c)
}

fn find_crlfcrlf(b: &[u8]) -> Option<usize> {
    b.windows(4).position(|w| w == b"\r\n\r\n")
}

/// `%XX` decoding; `plus` turns '+' into ' ' (query strings). None on malformed escapes.
pub fn percent_decode(s: &str, plus: bool) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let h = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
                out.push(u8::from_str_radix(h, 16).ok()?);
                i += 3;
            }
            b'+' if plus => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// Parse `a=1&b=2` (percent-decoded). Malformed pairs are an error.
pub fn parse_query(q: &str) -> Option<Vec<(String, String)>> {
    let mut v = Vec::new();
    for part in q.split('&') {
        if part.is_empty() {
            continue;
        }
        let (k, val) = part.split_once('=').unwrap_or((part, ""));
        v.push((percent_decode(k, true)?, percent_decode(val, true)?));
    }
    Some(v)
}

/// Parse the head (request line + headers, without the final CRLFCRLF).
pub fn parse_head(head: &[u8], lim: &Limits) -> Result<Request, HttpError> {
    let text = std::str::from_utf8(head).map_err(|_| HttpError::Bad("non-UTF-8 request head"))?;
    let mut lines = text.split("\r\n");
    let line = lines.next().ok_or(HttpError::Bad("empty request"))?;
    let mut parts = line.split(' ');
    let (m, target, ver) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(m), Some(t), Some(v), None) => (m, t, v),
        _ => return Err(HttpError::Bad("malformed request line")),
    };
    if m.is_empty() || !m.bytes().all(is_tchar) {
        return Err(HttpError::Bad("malformed method"));
    }
    let method = match m {
        "GET" => Method::Get,
        "HEAD" => Method::Head,
        "POST" => Method::Post,
        "DELETE" => Method::Delete,
        "OPTIONS" => Method::Options,
        _ => Method::Other,
    };
    let http11 = match ver {
        "HTTP/1.1" => true,
        "HTTP/1.0" => false,
        v if v.starts_with("HTTP/") => return Err(HttpError::Version),
        _ => return Err(HttpError::Bad("malformed request line")),
    };
    if !target.starts_with('/') || target.starts_with("//") {
        return Err(HttpError::Bad("only origin-form request targets are accepted"));
    }
    if target.bytes().any(|c| c <= 0x20 || c >= 0x7f || c == b'#') {
        return Err(HttpError::Bad("invalid character in request target"));
    }
    let (rawpath, rawq) = target.split_once('?').unwrap_or((target, ""));
    let path = percent_decode(rawpath, false).ok_or(HttpError::Bad("malformed path encoding"))?;
    if path.contains('\0') {
        return Err(HttpError::Bad("NUL in path"));
    }
    let query = parse_query(rawq).ok_or(HttpError::Bad("malformed query string"))?;

    let mut headers: Vec<(String, String)> = Vec::new();
    for l in lines {
        if l.is_empty() {
            return Err(HttpError::Bad("unexpected empty header line"));
        }
        if l.starts_with(' ') || l.starts_with('\t') {
            return Err(HttpError::Bad("obsolete header line folding"));
        }
        let (n, v) = l.split_once(':').ok_or(HttpError::Bad("malformed header"))?;
        if n.is_empty() || !n.bytes().all(is_tchar) {
            return Err(HttpError::Bad("malformed header name"));
        }
        if v.bytes().any(|c| (c < 0x20 && c != b'\t') || c == 0x7f) {
            return Err(HttpError::Bad("control character in header value"));
        }
        headers.push((n.to_ascii_lowercase(), v.trim_matches([' ', '\t']).to_string()));
        if headers.len() > lim.max_headers {
            return Err(HttpError::HeadTooLarge);
        }
    }
    let conn_tokens: Vec<String> = headers
        .iter()
        .filter(|(n, _)| n == "connection")
        .flat_map(|(_, v)| v.split(',').map(|t| t.trim().to_ascii_lowercase()).collect::<Vec<_>>())
        .collect();
    let keep_alive = if http11 { !conn_tokens.iter().any(|t| t == "close") } else { conn_tokens.iter().any(|t| t == "keep-alive") };
    let hosts = headers.iter().filter(|(n, _)| n == "host").count();
    if hosts > 1 || (http11 && hosts == 0) {
        return Err(HttpError::Bad("exactly one Host header is required"));
    }
    Ok(Request { method, path, query, headers, body: Vec::new(), http11, keep_alive })
}

/// Content-Length of a parsed head (None when absent); strict digits, all copies equal.
pub fn content_length(req: &Request, lim: &Limits) -> Result<usize, HttpError> {
    if req.headers.iter().any(|(n, _)| n == "transfer-encoding") {
        return Err(HttpError::NotImplemented("chunked request bodies are not supported"));
    }
    let mut len: Option<usize> = None;
    for (n, v) in &req.headers {
        if n != "content-length" {
            continue;
        }
        if v.is_empty() || v.len() > 12 || !v.bytes().all(|c| c.is_ascii_digit()) {
            return Err(HttpError::Bad("malformed Content-Length"));
        }
        let l: usize = v.parse().map_err(|_| HttpError::Bad("malformed Content-Length"))?;
        if len.is_some_and(|x| x != l) {
            return Err(HttpError::Bad("conflicting Content-Length headers"));
        }
        len = Some(l);
    }
    let len = len.unwrap_or(0);
    if len > lim.max_body {
        return Err(HttpError::BodyTooLarge);
    }
    Ok(len)
}

/// Lets the reader bound each socket read by the time left for the whole request.
pub trait ReadTimeout {
    fn set_timeout(&self, _d: Option<std::time::Duration>) {}
}
impl ReadTimeout for std::net::TcpStream {
    fn set_timeout(&self, d: Option<std::time::Duration>) {
        let _ = self.set_read_timeout(d);
    }
}
impl<T> ReadTimeout for std::io::Cursor<T> {}

impl<S: Read + ReadTimeout> Conn<S> {
    pub fn new(stream: S) -> Conn<S> {
        Conn { stream, buf: vec![0; 32 * 1024], start: 0, end: 0 }
    }

    /// Bytes buffered but not yet consumed.
    pub fn pending(&self) -> usize {
        self.end - self.start
    }

    fn fill(&mut self, cap: usize) -> Result<usize, HttpError> {
        if self.start > 0 && self.start == self.end {
            self.start = 0;
            self.end = 0;
        }
        if self.end == self.buf.len() {
            if self.start > 0 {
                self.buf.copy_within(self.start..self.end, 0);
                self.end -= self.start;
                self.start = 0;
            } else if self.buf.len() < cap {
                let n = (self.buf.len() * 2).min(cap.max(self.buf.len()));
                self.buf.resize(n, 0);
            } else {
                return Err(HttpError::HeadTooLarge);
            }
        }
        loop {
            match self.stream.read(&mut self.buf[self.end..]) {
                Ok(n) => {
                    self.end += n;
                    return Ok(n);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                    return Err(HttpError::Timeout);
                }
                Err(_) => return Err(HttpError::Io),
            }
        }
    }

    /// Read one request (head + body).
    pub fn read_request(&mut self, lim: &Limits) -> Result<Request, HttpError> {
        // slow clients: the whole request must arrive within `request_time` of its first byte
        let mut started = if self.pending() > 0 { Some(std::time::Instant::now()) } else { None };
        let late = |s: &Option<std::time::Instant>| s.is_some_and(|t| t.elapsed() > lim.request_time);
        // skip CRLFs between pipelined requests (RFC 9112 2.2)
        let head_end = loop {
            while self.start < self.end && (self.buf[self.start] == b'\r' || self.buf[self.start] == b'\n') {
                self.start += 1;
            }
            if let Some(p) = find_crlfcrlf(&self.buf[self.start..self.end]) {
                break p;
            }
            if self.end - self.start > lim.max_head {
                return Err(HttpError::HeadTooLarge);
            }
            let had = self.end - self.start;
            if late(&started) {
                return Err(HttpError::Timeout);
            }
            // a hard wall-clock deadline, not just a per-read one: a client dripping a byte
            // every few seconds can't hold a worker past `request_time`
            if let Some(t) = started {
                self.stream.set_timeout(Some(lim.request_time.saturating_sub(t.elapsed()).max(std::time::Duration::from_millis(1))));
            }
            match self.fill(lim.max_head + 4) {
                Ok(0) => return Err(if had == 0 { HttpError::Closed } else { HttpError::Bad("truncated request") }),
                Ok(_) => {
                    if started.is_none() {
                        started = Some(std::time::Instant::now());
                    }
                }
                Err(HttpError::Timeout) if had == 0 => return Err(HttpError::Closed),
                Err(e) => return Err(e),
            }
        };
        if head_end + 4 > lim.max_head {
            return Err(HttpError::HeadTooLarge);
        }
        let mut req = parse_head(&self.buf[self.start..self.start + head_end], lim)?;
        self.start += head_end + 4;
        let len = content_length(&req, lim)?;
        let mut body = Vec::with_capacity(len);
        while body.len() < len {
            if late(&started) {
                return Err(HttpError::Timeout);
            }
            if let Some(t) = started {
                self.stream.set_timeout(Some(lim.request_time.saturating_sub(t.elapsed()).max(std::time::Duration::from_millis(1))));
            }
            if self.start == self.end {
                match self.fill(usize::MAX) {
                    Ok(0) => return Err(HttpError::Bad("truncated body")),
                    Ok(_) => {}
                    Err(e) => return Err(e),
                }
            }
            let take = (len - body.len()).min(self.end - self.start);
            body.extend_from_slice(&self.buf[self.start..self.start + take]);
            self.start += take;
        }
        req.body = body;
        Ok(req)
    }
}

pub fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        206 => "Partial Content",
        303 => "See Other",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        413 => "Content Too Large",
        421 => "Misdirected Request",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "Unknown",
    }
}

/// A streaming body writer: gets a `Write` that frames chunks (HTTP/1.1) or writes raw bytes
/// (HTTP/1.0, connection closes afterwards).
pub type StreamFn = Box<dyn FnOnce(&mut dyn Write) -> io::Result<()> + Send>;

pub enum Body {
    Empty,
    Bytes(Vec<u8>),
    Static(&'static [u8]),
    Stream(StreamFn),
    /// a fixed-length body copied from a reader (file downloads)
    Reader(Box<dyn Read + Send>, u64),
}

pub struct Response {
    pub status: u16,
    pub headers: Vec<(&'static str, String)>,
    pub body: Body,
}

impl Response {
    pub fn new(status: u16) -> Response {
        Response { status, headers: Vec::new(), body: Body::Empty }
    }
    pub fn header(mut self, n: &'static str, v: impl Into<String>) -> Response {
        self.headers.push((n, v.into()));
        self
    }
    pub fn bytes(mut self, ctype: &str, b: Vec<u8>) -> Response {
        self.headers.push(("content-type", ctype.to_string()));
        self.body = Body::Bytes(b);
        self
    }
    pub fn text(status: u16, msg: &str) -> Response {
        Response::new(status).bytes("text/plain; charset=utf-8", format!("{msg}\n").into_bytes())
    }
    pub fn json(status: u16, j: Vec<u8>) -> Response {
        Response::new(status).bytes("application/json; charset=utf-8", j)
    }
    pub fn stream(mut self, ctype: &str, f: StreamFn) -> Response {
        self.headers.push(("content-type", ctype.to_string()));
        self.body = Body::Stream(f);
        self
    }
}

/// Chunked-transfer framing over a writer. Small writes are coalesced into chunks of at
/// least `min` bytes; `flush()` forces out what is buffered (streams call it between events).
pub struct Chunked<'a> {
    w: &'a mut dyn Write,
    buf: Vec<u8>,
    raw: bool,
}

impl<'a> Chunked<'a> {
    pub fn new(w: &'a mut dyn Write, raw: bool) -> Chunked<'a> {
        Chunked { w, buf: Vec::with_capacity(64 * 1024), raw }
    }
    fn emit(&mut self) -> io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        if self.raw {
            self.w.write_all(&self.buf)?;
        } else {
            let mut head = format!("{:x}\r\n", self.buf.len()).into_bytes();
            head.extend_from_slice(&self.buf);
            head.extend_from_slice(b"\r\n");
            self.w.write_all(&head)?;
        }
        self.buf.clear();
        Ok(())
    }
    pub fn finish(mut self) -> io::Result<()> {
        self.emit()?;
        if !self.raw {
            self.w.write_all(b"0\r\n\r\n")?;
        }
        self.w.flush()
    }
}

impl Write for Chunked<'_> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(b);
        if self.buf.len() >= 64 * 1024 {
            self.emit()?;
        }
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.emit()?;
        self.w.flush()
    }
}

/// Write a response. `head_only` for HEAD requests. Returns whether the connection may stay
/// open (streams over HTTP/1.0 close it).
pub fn write_response(w: &mut dyn Write, resp: Response, http11: bool, keep_alive: bool, head_only: bool, extra: &[(&str, &str)]) -> io::Result<bool> {
    let mut keep = keep_alive;
    let mut h = Vec::with_capacity(512);
    let _ = write!(h, "HTTP/1.1 {} {}\r\n", resp.status, reason(resp.status));
    for (n, v) in extra {
        let _ = write!(h, "{n}: {v}\r\n");
    }
    for (n, v) in &resp.headers {
        // never let a value smuggle a header
        let v: String = v.chars().filter(|c| *c != '\r' && *c != '\n').collect();
        let _ = write!(h, "{n}: {v}\r\n");
    }
    let body_len = match &resp.body {
        Body::Empty => Some(0),
        Body::Bytes(b) => Some(b.len()),
        Body::Static(b) => Some(b.len()),
        Body::Stream(_) => None,
        Body::Reader(_, n) => Some(*n as usize),
    };
    let no_body_status = resp.status == 204 || resp.status == 304;
    match body_len {
        Some(n) if !no_body_status => {
            let _ = write!(h, "content-length: {n}\r\n");
        }
        Some(_) => {}
        None => {
            if http11 {
                h.extend_from_slice(b"transfer-encoding: chunked\r\n");
            } else {
                keep = false;
            }
        }
    }
    h.extend_from_slice(if keep { b"connection: keep-alive\r\n\r\n" } else { b"connection: close\r\n\r\n" });
    if head_only || no_body_status {
        w.write_all(&h)?;
        w.flush()?;
        return Ok(keep);
    }
    match resp.body {
        Body::Empty => w.write_all(&h)?,
        Body::Bytes(b) => {
            if b.len() < 64 * 1024 {
                h.extend_from_slice(&b);
                w.write_all(&h)?;
            } else {
                w.write_all(&h)?;
                w.write_all(&b)?;
            }
        }
        Body::Static(b) => {
            w.write_all(&h)?;
            w.write_all(b)?;
        }
        Body::Stream(f) => {
            w.write_all(&h)?;
            let mut c = Chunked::new(w, !http11);
            f(&mut c)?;
            c.finish()?;
            return Ok(keep);
        }
        Body::Reader(r, n) => {
            w.write_all(&h)?;
            let copied = io::copy(&mut r.take(n), w)?;
            if copied != n {
                // the file shrank underneath us: the framing is broken, drop the connection
                return Ok(false);
            }
        }
    }
    w.flush()?;
    Ok(keep)
}
