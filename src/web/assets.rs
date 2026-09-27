//! The UI: hand-written HTML/CSS/vanilla JS (ES modules) and a subset of JetBrains Mono,
//! embedded in the binary. No build step, no external requests.

use super::http::{Body, Request, Response};

pub const INDEX_HTML: &str = include_str!("assets/index.html");

pub struct Asset {
    pub name: &'static str,
    pub ctype: &'static str,
    pub data: &'static [u8],
}

macro_rules! asset {
    ($name:literal, $ctype:literal) => {
        Asset { name: $name, ctype: $ctype, data: include_bytes!(concat!("assets/", $name)) }
    };
}

pub static ASSETS: &[Asset] = &[
    asset!("app.css", "text/css; charset=utf-8"),
    asset!("app.js", "text/javascript; charset=utf-8"),
    asset!("theme.js", "text/javascript; charset=utf-8"),
    asset!("core.js", "text/javascript; charset=utf-8"),
    asset!("table.js", "text/javascript; charset=utf-8"),
    asset!("palette.js", "text/javascript; charset=utf-8"),
    asset!("views.js", "text/javascript; charset=utf-8"),
    asset!("procs.js", "text/javascript; charset=utf-8"),
    asset!("hex.js", "text/javascript; charset=utf-8"),
    asset!("catalog.js", "text/javascript; charset=utf-8"),
    asset!("result.js", "text/javascript; charset=utf-8"),
    asset!("favicon.svg", "image/svg+xml"),
    asset!("mascot.svg", "image/svg+xml"),
    asset!("mono-400.woff2", "font/woff2"),
    asset!("mono-700.woff2", "font/woff2"),
    asset!("OFL.txt", "text/plain; charset=utf-8"),
];

pub fn get(name: &str) -> Option<&'static Asset> {
    ASSETS.iter().find(|a| a.name == name)
}

/// FNV-1a of the content: a strong-enough ETag for embedded, immutable-per-binary files.
fn etag(a: &Asset) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in a.data {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("\"{h:016x}\"")
}

pub fn respond(a: &'static Asset, req: &Request) -> Response {
    let tag = etag(a);
    if req.header("if-none-match") == Some(tag.as_str()) {
        return Response::new(304).header("etag", tag).header("cache-control", "no-cache");
    }
    let mut r = Response::new(200).header("content-type", a.ctype).header("etag", tag).header("cache-control", "no-cache");
    r.body = Body::Static(a.data);
    r
}
