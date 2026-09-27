//! `fvol serve`: a built-in web UI for fastvol.
//!
//! The binary serves a single-page app (embedded assets, no external requests) and a JSON API
//! over a small HTTP/1.1 server on `std::net`. One analysis `Context` stays alive for the
//! whole session, so after the first plugin every run skips image mapping, kernel discovery
//! and symbol loading. Plugins run on worker threads and stream their rows into compact
//! server-side tables; the browser pages through server-side filtered/sorted views, so tables
//! with millions of rows stay smooth.
//!
//! Security model: bind 127.0.0.1 by default; a random 128-bit token is required on every API
//! call; Host headers are validated (DNS rebinding); no CORS; cross-site requests refused;
//! strict request limits; downloads only from a run's own output directory.

pub mod api;
pub mod assets;
pub mod http;
pub mod jsonw;
pub mod mem;
pub mod runs;
pub mod security;
pub mod server;
pub mod session;
pub mod table;
pub mod zip;

#[cfg(test)]
mod tests;

use runs::{Hub, Runs};
use session::{Session, SessionOpts};
use std::net::{IpAddr, TcpListener};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

pub struct App {
    pub token: String,
    pub port: u16,
    pub hosts: security::HostPolicy,
    pub plugins: Vec<&'static dyn crate::plugins::Plugin>,
    pub plugins_json: Vec<u8>,
    session: RwLock<Arc<Session>>,
    pub base_opts: Mutex<SessionOpts>,
    pub runs: Arc<Runs>,
    pub hub: Arc<Hub>,
    next_session: AtomicU64,
    pub auth_failures: AtomicU64,
    pub tickets: security::Tickets,
    pub export_seq: AtomicU64,
    pub started: Instant,
}

impl App {
    pub fn new(token: String, port: u16, hosts: security::HostPolicy, opts: SessionOpts, max_parallel: usize, budget: u64) -> Result<Arc<App>, String> {
        let plugins = crate::plugins::all();
        let hub = Arc::new(Hub::default());
        let session = Arc::new(Session::new(1, &opts).map_err(|e| e.to_string())?);
        let app = Arc::new(App {
            token,
            port,
            hosts,
            plugins_json: api::plugins_json(&plugins),
            plugins,
            session: RwLock::new(session.clone()),
            base_opts: Mutex::new(opts),
            runs: Arc::new(Runs::new(hub.clone(), max_parallel, budget)),
            hub,
            next_session: AtomicU64::new(2),
            auth_failures: AtomicU64::new(0),
            tickets: security::Tickets::default(),
            export_seq: AtomicU64::new(1),
            started: Instant::now(),
        });
        app.start_warm_up(session);
        Ok(app)
    }

    pub fn session(&self) -> Arc<Session> {
        self.session.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn start_warm_up(self: &Arc<Self>, s: Arc<Session>) {
        let me = self.clone();
        let _ = std::thread::Builder::new().name("warm-up".into()).stack_size(64 << 20).spawn(move || s.warm_up(&me.hub, &me.plugins));
    }

    /// Switch to another image (explicit user action).
    pub fn open(self: &Arc<Self>, o: SessionOpts) -> Result<Arc<Session>, String> {
        let id = self.next_session.fetch_add(1, Ordering::Relaxed);
        let s = Arc::new(Session::new(id, &o).map_err(|e| e.to_string())?);
        *self.base_opts.lock().unwrap_or_else(|e| e.into_inner()) = o;
        *self.session.write().unwrap_or_else(|e| e.into_inner()) = s.clone();
        self.hub.bump();
        self.start_warm_up(s.clone());
        Ok(s)
    }
}

pub(crate) const USAGE: &str = "usage: fvol serve [-h] [-f FILE] [--host HOST] [--port PORT] [-s SYMBOL_DIRS] [-o OUTPUT_DIR]
                  [--offline] [-u URL] [--cache-path PATH] [--token TOKEN] [--allow-host NAME]
                  [--max-conns N] [--parallel N] [--max-memory SIZE]

Serve the fastvol web UI (a local, token-protected web app for analysing a memory image).

options:
  -h, --help            show this help message and exit
  -f, --file FILE       memory image to open (can also be opened from the UI)
  --host HOST           address to listen on (default 127.0.0.1; anything else exposes
                        the evidence to the network over plain HTTP)
  --port PORT           port to listen on (default 8765, or the next free one; 0 = any)
  -s, --symbol-dirs SYMBOL_DIRS
                        semi-colon separated list of paths to find symbols
  -o, --output-dir OUTPUT_DIR
                        directory for files written by plugins (one sub-directory per run;
                        default ./vol-serve-output)
  --offline             do not search online for additional JSON files
  -u, --remote-isf-url URL
                        search online for ISF json files
  --cache-path PATH     change the default cache path
  --token TOKEN         use this access token instead of a random one (at least 16 chars)
  --allow-host NAME     also accept requests addressed to NAME (e.g. a reverse proxy name)
  --max-conns N         concurrent HTTP connections (default 512)
  --parallel N          plugins that may run at the same time (default 3)
  --max-memory SIZE     memory for stored results, all runs together (default 3G); rows past
                        it are counted but not kept (exports via `fvol -r` stay complete)
";

/// "4G", "512M", "1.5g", "100000000" -> bytes
fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim().to_ascii_lowercase();
    let (num, mult) = match s.chars().last()? {
        'k' => (&s[..s.len() - 1], 1u64 << 10),
        'm' => (&s[..s.len() - 1], 1 << 20),
        'g' => (&s[..s.len() - 1], 1 << 30),
        't' => (&s[..s.len() - 1], 1 << 40),
        _ => (&s[..], 1),
    };
    let v: f64 = num.trim_end_matches(['i', 'b']).parse().ok()?;
    if !(v.is_finite() && v > 0.0) {
        return None;
    }
    Some((v * mult as f64) as u64)
}

fn human_size(n: u64) -> String {
    let units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u + 1 < units.len() {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 { format!("{n} B") } else { format!("{v:.1} {}", units[u]) }
}

/// `fvol serve ...`; `args` excludes "fvol" and "serve". Returns the exit status.
pub fn main(args: &[String]) -> i32 {
    let mut file: Option<String> = None;
    let mut host = "127.0.0.1".to_string();
    let mut port: Option<u16> = None;
    let mut symbol_dirs: Vec<String> = Vec::new();
    let mut out: Option<String> = None;
    let mut offline = false;
    let mut remote: Option<String> = None;
    let mut cache: Option<String> = None;
    let mut token: Option<String> = None;
    let mut allow: Vec<String> = Vec::new();
    let mut max_conns = 512usize;
    let mut parallel = 3usize;
    let mut budget: u64 = 3 << 30;
    let mut i = 0;
    let fail = |m: &str| -> i32 {
        eprint!("{USAGE}");
        eprintln!("fvol serve: error: {m}");
        2
    };
    while i < args.len() {
        let a = args[i].as_str();
        let (flag, inline) = match a.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f, Some(v.to_string())),
            _ => (a, None),
        };
        let val = |i: &mut usize| -> Option<String> {
            if let Some(v) = &inline {
                return Some(v.clone());
            }
            *i += 1;
            args.get(*i).cloned()
        };
        match flag {
            "-h" | "--help" => {
                print!("{USAGE}");
                return 0;
            }
            "-f" | "--file" => file = val(&mut i),
            "--host" => match val(&mut i) {
                Some(h) => host = h,
                None => return fail("--host needs a value"),
            },
            "--port" => match val(&mut i).and_then(|p| p.parse().ok()) {
                Some(p) => port = Some(p),
                None => return fail("--port needs a number"),
            },
            "-s" | "--symbol-dirs" => match val(&mut i) {
                Some(s) => symbol_dirs.extend(s.split(';').filter(|x| !x.is_empty()).map(|x| x.to_string())),
                None => return fail("-s needs a value"),
            },
            "-o" | "--output-dir" => out = val(&mut i),
            "--offline" => offline = true,
            "-u" | "--remote-isf-url" => remote = val(&mut i),
            "--cache-path" => cache = val(&mut i),
            "--token" => token = val(&mut i),
            "--allow-host" => match val(&mut i) {
                Some(h) => allow.push(h.to_ascii_lowercase()),
                None => return fail("--allow-host needs a value"),
            },
            "--max-conns" | "--workers" => max_conns = val(&mut i).and_then(|v| v.parse().ok()).unwrap_or(max_conns).clamp(8, 4096),
            "--parallel" => parallel = val(&mut i).and_then(|v| v.parse().ok()).unwrap_or(parallel).clamp(1, 64),
            "--max-memory" => match val(&mut i).as_deref().and_then(parse_size) {
                Some(b) => budget = b.max(16 << 20),
                None => return fail("--max-memory needs a size like 2G or 512M"),
            },
            _ => return fail(&format!("unrecognized argument {a}")),
        }
        i += 1;
    }
    let cwd = std::env::current_dir().unwrap_or_else(|_| "/".into());
    let image = match &file {
        Some(f) => {
            let p = cwd.join(f);
            match std::fs::canonicalize(&p) {
                Ok(p) if p.is_file() => Some(p),
                Ok(p) => return fail(&format!("{} is not a file", p.display())),
                Err(e) => return fail(&format!("{}: {e}", p.display())),
            }
        }
        None => None,
    };
    if offline && remote.is_some() {
        return fail("--offline and --remote-isf-url are mutually exclusive");
    }
    let token = match token {
        Some(t) if t.len() >= 16 && t.bytes().all(|c| c.is_ascii_graphic() && c != b';' && c != b',' && c != b'"') => t,
        Some(_) => return fail("--token must be at least 16 printable characters (no ; , or quotes)"),
        None => match security::random_token() {
            Ok(t) => t,
            Err(e) => {
                eprintln!("fvol serve: cannot read /dev/urandom for the access token: {e}");
                return 1;
            }
        },
    };
    let ip: IpAddr = match host.parse() {
        Ok(ip) => ip,
        Err(_) if host == "localhost" => IpAddr::from([127, 0, 0, 1]),
        Err(_) => return fail("--host must be an IP address (e.g. 127.0.0.1, ::1, 0.0.0.0)"),
    };
    let (listener, port) = {
        let try_bind = |p: u16| TcpListener::bind((ip, p)).ok().and_then(|l| l.local_addr().ok().map(|a| (l, a.port())));
        match port {
            Some(p) => match try_bind(p) {
                Some(x) => x,
                None => {
                    eprintln!("fvol serve: cannot listen on {host}:{p} (in use or not permitted)");
                    return 1;
                }
            },
            None => match (8765..8785).find_map(try_bind) {
                Some(x) => x,
                None => match try_bind(0) {
                    Some(x) => x,
                    None => {
                        eprintln!("fvol serve: cannot listen on {host}");
                        return 1;
                    }
                },
            },
        }
    };
    let out_root: PathBuf = match &out {
        Some(o) => cwd.join(o),
        None => cwd.join("vol-serve-output"),
    };
    let symbol_dirs: Vec<String> = symbol_dirs.iter().map(|d| crate::cli::abspath(d, &cwd.to_string_lossy())).collect();
    let opts = SessionOpts { image: image.clone(), symbol_dirs, out_root: out_root.clone(), offline, remote_isf_url: remote, cache_path: cache };
    let hosts = security::HostPolicy { port, wildcard: ip.is_unspecified(), bind: if ip.is_unspecified() { None } else { Some(ip) }, names: allow };
    let app = match App::new(token.clone(), port, hosts, opts, parallel, budget) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("fvol serve: {e}");
            return 1;
        }
    };
    let shown_host = if ip.is_unspecified() {
        "127.0.0.1".to_string()
    } else if let IpAddr::V6(v6) = ip {
        format!("[{v6}]")
    } else {
        ip.to_string()
    };
    println!("fastvol web UI · {}", crate::VERSION_BANNER);
    match &image {
        Some(p) => println!("  image   {} ({})", p.display(), human_size(std::fs::metadata(p).map(|m| m.len()).unwrap_or(0))),
        None => println!("  image   (none yet: open one from the UI)"),
    }
    println!("  output  {}", out_root.display());
    // the token travels in the URL fragment: browsers never send fragments to servers (no logs,
    // no Referer), and the page moves it into this origin's localStorage and off the URL
    println!("  open    http://{shown_host}:{port}/#token={token}");
    if !ip.is_loopback() {
        println!("WARNING: listening on {host}: the evidence is reachable from the network over unencrypted HTTP.");
    }
    println!("Anyone with this URL can read the image. Press Ctrl+C to stop.");
    use std::io::Write;
    let _ = std::io::stdout().flush();
    server::serve(app, listener, max_conns);
    0
}
