//! Access control for `vol serve`: the random access token, constant-time comparison, Host
//! header validation (DNS-rebinding defence) and request-origin checks.

use super::http::Request;
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

fn digits(p: &str) -> Option<u16> {
    if p.is_empty() || p.len() > 5 || !p.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    p.parse().ok()
}

fn parse_host(h: &str) -> Option<(String, Option<u16>)> {
    let h = h.trim();
    if h.is_empty() {
        return None;
    }
    if let Some(rest) = h.strip_prefix('[') {
        let (ip, after) = rest.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => Some(digits(p)?),
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
            Some((n.to_ascii_lowercase(), Some(digits(p)?)))
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
                // exactly the address we listen on
                self.bind == Some(ip)
            }
            None => name == "localhost" && (self.wildcard || self.bind.is_none_or(|b| b.is_loopback())),
        }
    }
}

/// Check the request's credentials: the `X-Vol-Token` (or `Authorization: Bearer`) header.
/// There is deliberately no cookie: cookies are not port-isolated, so any other service on
/// 127.0.0.1 would receive it.
pub fn authenticate(req: &Request, token: &str) -> bool {
    let hdr = req.header("x-vol-token").or_else(|| req.header("authorization").and_then(|a| a.strip_prefix("Bearer ")));
    hdr.is_some_and(|t| ct_eq(t.trim().as_bytes(), token.as_bytes()))
}

/// Single-use, short-lived download tickets bound to one exact GET target.
#[derive(Default)]
pub struct Tickets {
    list: std::sync::Mutex<Vec<(String, String, std::time::Instant)>>,
}

impl Tickets {
    pub const TTL: std::time::Duration = std::time::Duration::from_secs(60);

    /// A ticket for `target` (path + query), or None when too many are pending.
    pub fn issue(&self, target: &str) -> Option<String> {
        let t = random_token().ok()?;
        let mut l = self.list.lock().unwrap_or_else(|e| e.into_inner());
        l.retain(|x| x.2.elapsed() < Self::TTL);
        if l.len() >= 256 {
            return None;
        }
        l.push((t.clone(), target.to_string(), std::time::Instant::now()));
        Some(t)
    }

    /// Consume the request's `ticket=` if it matches this exact target.
    pub fn redeem(&self, req: &Request) -> bool {
        let Some(t) = req.param("ticket") else { return false };
        // the target the ticket was issued for: path + the query without the ticket
        let mut target = req.path.clone();
        let rest: Vec<String> = req.query.iter().filter(|(k, _)| k != "ticket").map(|(k, v)| format!("{k}={v}")).collect();
        if !rest.is_empty() {
            target.push('?');
            target.push_str(&rest.join("&"));
        }
        let mut l = self.list.lock().unwrap_or_else(|e| e.into_inner());
        l.retain(|x| x.2.elapsed() < Self::TTL);
        match l.iter().position(|x| ct_eq(x.0.as_bytes(), t.as_bytes())) {
            Some(i) if percent_normalize(&l[i].1) == target => {
                l.remove(i);
                true
            }
            _ => false,
        }
    }
}

/// Decode a target the way the request parser does, to compare it with a parsed request.
fn percent_normalize(target: &str) -> String {
    let (p, q) = target.split_once('?').unwrap_or((target, ""));
    let mut out = super::http::percent_decode(p, false).unwrap_or_default();
    let pairs: Vec<String> = super::http::parse_query(q).unwrap_or_default().into_iter().map(|(k, v)| format!("{k}={v}")).collect();
    if !pairs.is_empty() {
        out.push('?');
        out.push_str(&pairs.join("&"));
    }
    out
}

/// Requests a browser made on behalf of another site are refused (defence in depth: without
/// the token header they would fail anyway).
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
        assert!(!p.allows("[::1]:8765")); // not the bound address
        assert!(!p.allows("127.0.0.2:8765"));
        assert!(!p.allows("127.0.0.1:+8765"));
        assert!(!p.allows("127.0.0.1: 8765"));
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
