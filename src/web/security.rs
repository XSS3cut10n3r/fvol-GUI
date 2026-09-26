//! Access control for `vol serve`: the random access token, constant-time comparison, Host
//! header validation (DNS-rebinding defence) and request-origin checks.

use super::http::{Method, Request};
use std::net::IpAddr;

/// 128 random bits as 32 hex digits (from the kernel CSPRNG).
pub fn random_token() -> std::io::Result<String> {
    use std::io::Read;
    let mut b = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut b)?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// Constant-time equality (length is not secret: tokens have a fixed length).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    // prevent the compiler from short-circuiting
    std::hint::black_box(d) == 0
}

/// Which Host header values are acceptable.
#[derive(Clone, Debug)]
pub struct HostPolicy {
    pub port: u16,
    /// the server listens on a wildcard address (0.0.0.0 / ::): any IP literal is allowed
    pub wildcard: bool,
    /// the concrete bind address (when not a wildcard)
    pub bind: Option<IpAddr>,
    /// extra names allowed with --allow-host
    pub names: Vec<String>,
}

fn parse_host(h: &str) -> Option<(String, Option<u16>)> {
    let h = h.trim();
    if h.is_empty() {
        return None;
    }
    if let Some(rest) = h.strip_prefix('[') {
        let (ip, after) = rest.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => Some(p.parse().ok()?),
            None if after.is_empty() => None,
            None => return None,
        };
        return Some((format!("[{}]", ip.to_ascii_lowercase()), port));
    }
    match h.rsplit_once(':') {
        Some((n, p)) => {
            if n.contains(':') {
                return None; // bare IPv6 without brackets
            }
            Some((n.to_ascii_lowercase(), Some(p.parse().ok()?)))
        }
        None => Some((h.to_ascii_lowercase(), None)),
    }
}

impl HostPolicy {
    /// Is `host` (the Host header) a name this server may be addressed as? DNS names other
    /// than `localhost` (and --allow-host names) are refused: a rebinding attack needs one.
    pub fn allows(&self, host: &str) -> bool {
        let Some((name, port)) = parse_host(host) else { return false };
        if port.unwrap_or(80) != self.port {
            return false;
        }
        if self.names.iter().any(|n| n.eq_ignore_ascii_case(&name)) {
            return true;
        }
        let ip: Option<IpAddr> = if name.starts_with('[') { name[1..name.len() - 1].parse().ok() } else { name.parse().ok() };
        match ip {
            Some(ip) => {
                if self.wildcard {
                    return true;
                }
                match self.bind {
                    Some(b) if b.is_loopback() => ip.is_loopback(),
                    Some(b) => ip == b || ip.is_loopback(),
                    None => ip.is_loopback(),
                }
            }
            None => name == "localhost" && (self.wildcard || self.bind.is_none_or(|b| b.is_loopback())),
        }
    }
}

/// Where the token came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Auth {
    None,
    Header,
    Cookie,
}

pub fn cookie_name(port: u16) -> String {
    format!("rsvol_{port}")
}

/// Check the request's credentials: `X-Vol-Token`/`Authorization: Bearer` header, or the
/// session cookie.
pub fn authenticate(req: &Request, token: &str, port: u16) -> Auth {
    let hdr = req.header("x-vol-token").or_else(|| req.header("authorization").and_then(|a| a.strip_prefix("Bearer ")));
    if let Some(t) = hdr
        && ct_eq(t.trim().as_bytes(), token.as_bytes())
    {
        return Auth::Header;
    }
    if let Some(c) = req.cookie(&cookie_name(port))
        && ct_eq(c.as_bytes(), token.as_bytes())
    {
        return Auth::Cookie;
    }
    Auth::None
}

/// Requests a browser made on behalf of another site are refused (belt and braces on top of
/// the SameSite cookie and the header token).
pub fn cross_site(req: &Request, host: &str) -> bool {
    if let Some(s) = req.header("sec-fetch-site")
        && s != "same-origin"
        && s != "none"
    {
        return true;
    }
    if let Some(o) = req.header("origin") {
        let expect = format!("http://{host}");
        if o != expect {
            return true;
        }
    }
    false
}

/// State-changing requests must carry the token in a header (cookies alone are not enough).
pub fn needs_header(req: &Request) -> bool {
    !matches!(req.method, Method::Get | Method::Head)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pol(bind: &str, port: u16) -> HostPolicy {
        let ip: IpAddr = bind.parse().unwrap();
        HostPolicy { port, wildcard: ip.is_unspecified(), bind: if ip.is_unspecified() { None } else { Some(ip) }, names: vec![] }
    }

    #[test]
    fn host_header_rules() {
        let p = pol("127.0.0.1", 8765);
        assert!(p.allows("127.0.0.1:8765"));
        assert!(p.allows("localhost:8765"));
        assert!(p.allows("LOCALHOST:8765"));
        assert!(p.allows("[::1]:8765"));
        assert!(!p.allows("127.0.0.1:8766"));
        assert!(!p.allows("127.0.0.1"));
        assert!(!p.allows("evil.example:8765"));
        assert!(!p.allows("localhost.evil.example:8765"));
        assert!(!p.allows("192.168.1.5:8765"));
        assert!(!p.allows(""));
        assert!(!p.allows("::1:8765"));
        assert!(!p.allows("127.0.0.1:8765:1"));
        let w = pol("0.0.0.0", 80);
        assert!(w.allows("10.1.2.3"));
        assert!(w.allows("10.1.2.3:80"));
        assert!(!w.allows("attacker.example"));
        let mut n = pol("127.0.0.1", 9000);
        n.names.push("forensics-box".into());
        assert!(n.allows("forensics-box:9000"));
    }

    #[test]
    fn constant_time_eq() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }

    #[test]
    fn token_is_random_hex() {
        let a = random_token().unwrap();
        let b = random_token().unwrap();
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }
}
