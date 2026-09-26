//! cli
// TEMPORARY - replaced by CLI agent (minimal driver: vol [-q] [-o DIR] [-s DIRS] -f FILE PLUGIN [args])

use crate::context::{Context, GlobalOptions};
use crate::plugins::{Config, ConfigValue, ReqKind};
use crate::renderers::text::QuickRenderer;
use std::io::Write;

fn parse_int(s: &str) -> Option<i128> {
    let (neg, s) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s),
    };
    let v = if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i128::from_str_radix(h, 16).ok()?
    } else if let Some(o) = s.strip_prefix("0o") {
        i128::from_str_radix(o, 8).ok()?
    } else if let Some(b) = s.strip_prefix("0b") {
        i128::from_str_radix(b, 2).ok()?
    } else {
        s.parse().ok()?
    };
    Some(if neg { -v } else { v })
}

/// Entry point; returns the process exit code. (CLI agent implements.)
pub fn main() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut opts = GlobalOptions { output_dir: ".".into(), ..Default::default() };
    let mut i = 0;
    let mut plugin_name = None;
    while i < args.len() {
        match args[i].as_str() {
            "-q" | "--quiet" => opts.quiet = true,
            "-f" | "--file" => {
                i += 1;
                opts.file = args.get(i).cloned();
            }
            "-o" | "--output-dir" => {
                i += 1;
                opts.output_dir = args.get(i).cloned().unwrap_or_else(|| ".".into());
            }
            "-s" | "--symbol-dirs" => {
                i += 1;
                opts.symbol_dirs = args.get(i).map(|s| s.split(';').map(String::from).collect()).unwrap_or_default();
            }
            "--offline" => opts.offline = true,
            "-r" | "--renderer" => i += 1,
            a if a.starts_with('-') && plugin_name.is_none() => {}
            a => {
                if plugin_name.is_none() {
                    plugin_name = Some(a.to_string());
                    i += 1;
                    break;
                }
            }
        }
        i += 1;
    }
    let Some(pname) = plugin_name else {
        println!("{}", crate::VERSION_BANNER);
        return 0;
    };
    let Some(plugin) = crate::plugins::find(&pname) else {
        eprintln!("plugin {pname} not found");
        return 2;
    };
    // plugin args
    let mut cfg = Config::default();
    let reqs = plugin.requirements();
    for r in &reqs {
        if let Some(d) = &r.default {
            cfg.set(r.name, d.clone());
        }
    }
    let rest = &args[i..];
    let mut j = 0;
    while j < rest.len() {
        let a = rest[j].trim_start_matches('-').replace('-', "_");
        if let Some(r) = reqs.iter().find(|r| r.name == a) {
            match &r.kind {
                ReqKind::Bool => cfg.set(r.name, ConfigValue::Bool(true)),
                ReqKind::Int => {
                    j += 1;
                    if let Some(v) = rest.get(j).and_then(|s| parse_int(s)) {
                        cfg.set(r.name, ConfigValue::Int(v));
                    }
                }
                ReqKind::Str | ReqKind::Uri | ReqKind::Choice(_) => {
                    j += 1;
                    if let Some(v) = rest.get(j) {
                        cfg.set(r.name, ConfigValue::Str(v.clone()));
                    }
                }
                ReqKind::ListInt => {
                    let mut l = Vec::new();
                    while j + 1 < rest.len() && !rest[j + 1].starts_with("--") {
                        j += 1;
                        if let Some(v) = parse_int(&rest[j]) {
                            l.push(ConfigValue::Int(v));
                        }
                    }
                    cfg.set(r.name, ConfigValue::List(l));
                }
                ReqKind::ListStr => {
                    let mut l = Vec::new();
                    while j + 1 < rest.len() && !rest[j + 1].starts_with("--") {
                        j += 1;
                        l.push(ConfigValue::Str(rest[j].clone()));
                    }
                    cfg.set(r.name, ConfigValue::List(l));
                }
                ReqKind::Bytes => {
                    j += 1;
                    if let Some(v) = rest.get(j) {
                        cfg.set(r.name, ConfigValue::Bytes(v.as_bytes().to_vec()));
                    }
                }
            }
        }
        j += 1;
    }
    let stdout = std::io::stdout();
    let mut lock = std::io::BufWriter::with_capacity(1 << 16, stdout.lock());
    let _ = writeln!(lock, "{}", crate::VERSION_BANNER);
    let ctx = match Context::new(opts) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let mut r = QuickRenderer::new(lock);
    match plugin.run(&ctx, &cfg, &mut r) {
        Ok(()) => {
            let _ = r.finish();
            0
        }
        Err(e) => {
            let _ = r.finish();
            eprintln!("error: {e}");
            1
        }
    }
}
