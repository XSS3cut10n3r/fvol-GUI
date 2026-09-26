//! Differential test against python volatility3: `bench/scripts/render_fixtures.py` renders the
//! grid in tests/fixtures/render_grid.json with every python renderer; the same grid is rendered
//! here and compared byte for byte.

use super::*;
use crate::cli::json::{self, Json};
use crate::renderers::DateTime;

pub(crate) fn fixture(name: &str) -> Json {
    let p = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    json::parse(&std::fs::read_to_string(&p).unwrap()).unwrap()
}

fn hex(j: &Json) -> Vec<u8> {
    let s = j.as_str().unwrap();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn int(j: &Json) -> i128 {
    match j {
        Json::Int(i) => *i,
        _ => panic!("int"),
    }
}

pub(crate) fn value(c: &Json) -> Value {
    let t = c.get("t").unwrap().as_str().unwrap();
    match t {
        "int" => Value::Int(int(c.get("v").unwrap())),
        "str" => Value::Str(c.get("v").unwrap().as_str().unwrap().to_string()),
        "bytes" => Value::Bytes(hex(c.get("hex").unwrap())),
        "float" => Value::Float(match c.get("v").unwrap() {
            Json::Float(f) => *f,
            Json::Int(i) => *i as f64,
            _ => panic!(),
        }),
        "bool" => Value::Bool(c.get("v") == Some(&Json::Bool(true))),
        "dt" => Value::DateTime(DateTime {
            secs: int(c.get("secs").unwrap()) as i64,
            micros: int(c.get("us").unwrap()) as u32,
            utc: c.get("utc") == Some(&Json::Bool(true)),
        }),
        "mtd" => Value::MultiTypeData {
            data: hex(c.get("hex").unwrap()),
            encoding: match c.get("enc").unwrap().as_str().unwrap() {
                "utf-8" => Encoding::Utf8,
                "latin-1" => Encoding::Latin1,
                _ => Encoding::Utf16Le,
            },
            split_nulls: c.get("split") == Some(&Json::Bool(true)),
            show_hex: c.get("show_hex") == Some(&Json::Bool(true)),
            converted_int: c.get("int") != Some(&Json::Null),
        },
        "dis" => Value::Disassembly {
            data: hex(c.get("hex").unwrap()),
            offset: int(c.get("off").unwrap()) as u64,
            arch: match c.get("arch").and_then(|a| a.as_str()) {
                Some("intel") => Some("intel"),
                Some("intel64") => Some("intel64"),
                Some("arm") => Some("arm"),
                Some("arm64") => Some("arm64"),
                _ => None,
            },
        },
        "layer" => Value::LayerBytes { data: hex(c.get("hex").unwrap()), errors: Vec::new() },
        "unreadable" => Value::Unreadable,
        "unparsable" => Value::Unparsable,
        "notapplicable" => Value::NotApplicable,
        "notavailable" => Value::NotAvailable,
        _ => panic!("{t}"),
    }
}

pub(crate) fn coltype(t: &str) -> ColType {
    match t {
        "int" => ColType::Int,
        "str" => ColType::Str,
        "bytes" => ColType::Bytes,
        "float" => ColType::Float,
        "bool" => ColType::Bool,
        "datetime" => ColType::DateTime,
        "hex" => ColType::Hex,
        "bin" => ColType::Bin,
        "hexbytes" => ColType::HexBytes,
        "mtd" => ColType::MultiTypeData,
        "disasm" => ColType::Disassembly,
        "layer" => ColType::LayerData,
        _ => panic!("{t}"),
    }
}

pub(crate) fn grid_columns(grid: &Json) -> Vec<Column> {
    grid.get("columns")
        .unwrap()
        .as_arr()
        .iter()
        .map(|c| Column::new(c.as_arr()[0].as_str().unwrap(), coltype(c.as_arr()[1].as_str().unwrap())))
        .collect()
}

pub(crate) fn grid_rows(grid: &Json) -> Vec<(usize, Vec<Value>)> {
    grid.get("rows")
        .unwrap()
        .as_arr()
        .iter()
        .map(|row| (int(&row.as_arr()[0]) as usize, row.as_arr()[1].as_arr().iter().map(value).collect()))
        .collect()
}

/// Render the fixture grid; returns (stdout, failed)
fn render(grid: &Json, name: &str, opts: RenderOptions) -> (String, bool) {
    let mut out: Vec<u8> = Vec::new();
    let failed;
    {
        let mut r = create(name, &mut out, opts).unwrap();
        let mut res = r.begin(grid_columns(grid));
        if res.is_ok() {
            for (level, vals) in grid_rows(grid) {
                res = r.row(level, vals);
                if res.is_err() {
                    break;
                }
            }
        }
        failed = res.is_err();
        if failed {
            assert!(r.failure().is_some(), "renderer error without failure kind");
            r.abort(false).unwrap();
        } else {
            r.finish().unwrap();
        }
    }
    (String::from_utf8(out).unwrap(), failed)
}

#[test]
fn python_renderers_match() {
    let grid = fixture("render_grid.json");
    let cases = fixture("render_expected.json");
    let mut bad = Vec::new();
    for case in cases.as_arr() {
        let name = case.get("renderer").unwrap().as_str().unwrap();
        let filters: Vec<String> =
            case.get("filters").unwrap().as_arr().iter().map(|f| f.as_str().unwrap().to_string()).collect();
        let hide = match case.get("hide").unwrap() {
            Json::Null => None,
            h => Some(h.as_arr().iter().map(|f| f.as_str().unwrap().to_string()).collect()),
        };
        let want = case.get("out").unwrap().as_str().unwrap();
        let want_exc = case.get("exc").unwrap() != &Json::Null;
        let (got, failed) =
            render(&grid, name, RenderOptions { filters: filters.clone(), hide_columns: hide.clone(), flush_rows: false });
        if got != want || failed != want_exc {
            bad.push(format!(
                "{name} filters={filters:?} hide={hide:?} exc={want_exc}/{failed}\n--- want\n{want}\n--- got\n{got}"
            ));
        }
    }
    assert!(bad.is_empty(), "{} of {} renderer cases differ:\n{}", bad.len(), cases.as_arr().len(), bad.join("\n=========\n"));
}

/// Rows handed over as pre-encoded blocks (`RowSink::encoder` / `rows_encoded`, formatted
/// "elsewhere"), mixed with ordinary rows, render exactly like ordinary rows, for every
/// renderer, with and without hidden columns, small and flush-sized blocks.
#[test]
fn encoded_rows_match_row_path() {
    let grid = fixture("render_grid.json");
    let cols = grid_columns(&grid);
    let base: Vec<Vec<Value>> = grid_rows(&grid).into_iter().map(|(_, v)| v).collect();
    for reps in [1usize, 2000] {
        let rows: Vec<Vec<Value>> = (0..reps).flat_map(|_| base.iter().cloned()).collect();
        let n = rows.len();
        for name in ["quick", "csv", "jsonl", "json", "pretty", "none"] {
            for hide in [None, Some(vec!["name".to_string(), "off".to_string(), "dump".to_string()])] {
                let opts = || RenderOptions { filters: Vec::new(), hide_columns: hide.clone(), flush_rows: false };
                let plain = {
                    let mut out: Vec<u8> = Vec::new();
                    {
                        let mut r = create(name, &mut out, opts()).unwrap();
                        r.begin(cols.clone()).unwrap();
                        for v in &rows {
                            r.row(0, v.clone()).unwrap();
                        }
                        r.finish().unwrap();
                    }
                    out
                };
                // splits: [0, a) rows, [a, b) and [b, c) encoded, [c, n) rows
                for (a, b, c) in [(0, 0, 0), (0, n / 2, n), (1, n / 3, n - 1), (n, n, n), (2, 2, 3)] {
                    let mut out: Vec<u8> = Vec::new();
                    {
                        let mut r = create(name, &mut out, opts()).unwrap();
                        r.begin(cols.clone()).unwrap();
                        let enc = r.encoder().expect("encoder");
                        for v in &rows[..a] {
                            r.row_ref(0, v).unwrap();
                        }
                        for (s, e) in [(a, b), (b, c)] {
                            let mut blk = Vec::new();
                            for v in &rows[s..e] {
                                enc.row(&mut blk, v);
                            }
                            r.rows_encoded(&blk, e - s).unwrap();
                        }
                        for v in &rows[c..] {
                            r.row(0, v.clone()).unwrap();
                        }
                        r.finish().unwrap();
                    }
                    assert!(out == plain, "{name} hide={hide:?} reps={reps} split=({a},{b},{c})");
                }
            }
        }
    }
    // tree rows (quick / csv / pretty / none): blocks encoded with row_at; json: only depth 0
    let depths: Vec<usize> = {
        let mut x = 0x2545_f491_4f6c_dd1du64;
        let mut d = 0usize;
        (0..600)
            .map(|k| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                // mostly valid steps, sometimes a jump python clamps
                d = match x % 7 {
                    0 if k > 0 => d + 1,
                    1 => d.saturating_sub(1),
                    2 => 0,
                    3 => d + 3,
                    _ => d,
                };
                d
            })
            .collect()
    };
    let rows: Vec<Vec<Value>> = (0..depths.len()).map(|i| base[i % base.len()].clone()).collect();
    for name in ["quick", "csv", "pretty", "none", "jsonl", "json"] {
        let plain = {
            let mut out: Vec<u8> = Vec::new();
            {
                let mut r = create(name, &mut out, RenderOptions::default()).unwrap();
                r.begin(cols.clone()).unwrap();
                for (v, &d) in rows.iter().zip(&depths) {
                    r.row(d, v.clone()).unwrap();
                }
                r.finish().unwrap();
            }
            out
        };
        for bs in [1usize, 7, 64, 600] {
            let mut out: Vec<u8> = Vec::new();
            {
                let mut r = create(name, &mut out, RenderOptions::default()).unwrap();
                r.begin(cols.clone()).unwrap();
                let enc = r.encoder().unwrap();
                let mut s = 0;
                while s < rows.len() {
                    let e = (s + bs).min(rows.len());
                    // a block is only encodable if its depths are valid without clamping
                    let valid = (s + 1..e).all(|i| depths[i] <= depths[i - 1] + 1);
                    let mut took = false;
                    if valid && (enc.supports_depth() || depths[s..e].iter().all(|&d| d == 0)) {
                        let mut blk = Vec::new();
                        for i in s..e {
                            enc.row_at(&mut blk, depths[i], &rows[i]);
                        }
                        took = r.rows_encoded_at(&blk, e - s, depths[s], depths[e - 1]).unwrap();
                    }
                    if !took {
                        for i in s..e {
                            r.row_ref(depths[i], &rows[i]).unwrap();
                        }
                    }
                    s = e;
                }
                r.finish().unwrap();
            }
            assert!(out == plain, "{name} tree rows, blocks of {bs}");
        }
    }
    // row templates: prefix + cell + suffix == row, for every column as the varying one
    for name in ["quick", "csv", "jsonl", "json", "pretty", "none"] {
        for hide in [None, Some(vec!["name".to_string(), "off".to_string(), "dump".to_string()])] {
            let mut sink: Vec<u8> = Vec::new();
            let mut r = create(name, &mut sink, RenderOptions { filters: Vec::new(), hide_columns: hide.clone(), flush_rows: false }).unwrap();
            r.begin(cols.clone()).unwrap();
            let enc = r.encoder().unwrap();
            for v in &base {
                let mut want = Vec::new();
                enc.row(&mut want, v);
                for c in 0..cols.len() {
                    let mut placeholder = v.clone();
                    placeholder[c] = Value::Int(0);
                    let (mut pre, mut suf) = (Vec::new(), Vec::new());
                    enc.row_template(&placeholder, c, &mut pre, &mut suf);
                    enc.cell(&mut pre, c, &v[c]);
                    pre.extend_from_slice(&suf);
                    assert!(pre == want, "{name} hide={hide:?} template column {c}");
                    for x in [0u64, 9, 10, 0xfff, 0x1000, 123456789, u64::MAX] {
                        let (mut a, mut b) = (Vec::new(), Vec::new());
                        enc.cell(&mut a, c, &Value::Int(x as i128));
                        enc.cell_u64(&mut b, c, x);
                        assert!(a == b, "{name} hide={hide:?} cell_u64 column {c} value {x}");
                    }
                }
            }
        }
    }
    // an active filter disables the encoder
    let mut out: Vec<u8> = Vec::new();
    let mut r = create("quick", &mut out, RenderOptions { filters: vec!["str,x".into()], hide_columns: None, flush_rows: false }).unwrap();
    r.begin(cols.clone()).unwrap();
    assert!(r.encoder().is_none());
}

/// Throughput of every renderer on 1M pslist-like rows written to /dev/null (values are built
/// per row, as a plugin would). Run:
///   cargo test --profile fast bench_renderers -- --ignored --nocapture
#[test]
#[ignore]
fn bench_renderers() {
    const N: u64 = 1_000_000;
    let columns = || {
        crate::cols![
            ("PID", Int),
            ("PPID", Int),
            ("ImageFileName", Str),
            ("Offset(V)", Hex),
            ("Threads", Int),
            ("Handles", Int),
            ("SessionId", Int),
            ("Wow64", Bool),
            ("CreateTime", DateTime),
            ("ExitTime", DateTime),
            ("File output", Str)
        ]
    };
    let row = |i: u64| -> Vec<Value> {
        vec![
            Value::Int(i as i128),
            Value::Int((i / 3) as i128),
            Value::Str(if i % 2 == 0 { "svchost.exe".into() } else { "MsMpEng.exe".into() }),
            Value::Int(0xe485b4eaa040 + i as i128 * 0x80),
            Value::Int((i % 97) as i128),
            Value::Unreadable,
            Value::NotApplicable,
            Value::Bool(i % 5 == 0),
            Value::DateTime(DateTime { secs: 1789354424 + i as i64, micros: 0, utc: true }),
            Value::NotApplicable,
            Value::SStr("Disabled"),
        ]
    };
    for name in ["none", "quick", "csv", "jsonl", "json", "pretty"] {
        let mut sink = std::fs::OpenOptions::new().write(true).open("/dev/null").unwrap();
        let start = std::time::Instant::now();
        {
            let mut r = create(name, &mut sink, RenderOptions::default()).unwrap();
            r.begin(columns()).unwrap();
            for i in 0..N {
                r.row((i % 3 == 2) as usize, row(i)).unwrap();
            }
            r.finish().unwrap();
        }
        let dt = start.elapsed();
        println!("{name:>7}: {N} rows in {:>7.1} ms  ({:.0} ns/row)", dt.as_secs_f64() * 1e3, dt.as_nanos() as f64 / N as f64);
    }
    // the same values in a stack array (the Str still allocates, like a plugin's would)
    let arr = |i: u64| -> [Value; 11] {
        [
            Value::Int(i as i128),
            Value::Int((i / 3) as i128),
            Value::Str(if i % 2 == 0 { "svchost.exe".into() } else { "MsMpEng.exe".into() }),
            Value::Int(0xe485b4eaa040 + i as i128 * 0x80),
            Value::Int((i % 97) as i128),
            Value::Unreadable,
            Value::NotApplicable,
            Value::Bool(i % 5 == 0),
            Value::DateTime(DateTime { secs: 1789354424 + i as i64, micros: 0, utc: true }),
            Value::NotApplicable,
            Value::SStr("Disabled"),
        ]
    };
    // borrowed rows (no Vec per row), depth 0
    for name in ["none", "quick", "csv", "jsonl", "json", "pretty"] {
        let mut sink = std::fs::OpenOptions::new().write(true).open("/dev/null").unwrap();
        let start = std::time::Instant::now();
        {
            let mut r = create(name, &mut sink, RenderOptions::default()).unwrap();
            r.begin(columns()).unwrap();
            for i in 0..N {
                r.row_ref(0, &arr(i)).unwrap();
            }
            r.finish().unwrap();
        }
        let dt = start.elapsed();
        println!("{name:>7} row_ref: {:>7.1} ms  ({:.0} ns/row)", dt.as_secs_f64() * 1e3, dt.as_nanos() as f64 / N as f64);
    }
    // pre-encoded blocks: one thread, then all threads (depth 0)
    for par in [false, true] {
        for name in ["none", "quick", "csv", "jsonl", "json", "pretty"] {
            let mut sink = std::fs::OpenOptions::new().write(true).open("/dev/null").unwrap();
            let start = std::time::Instant::now();
            {
                let mut r = create(name, &mut sink, RenderOptions::default()).unwrap();
                r.begin(columns()).unwrap();
                let enc = r.encoder().unwrap();
                const B: u64 = 16384;
                let block = |c: usize| {
                    let mut blk = Vec::with_capacity(B as usize * 128);
                    for i in c as u64 * B..((c as u64 + 1) * B).min(N) {
                        enc.row(&mut blk, &arr(i));
                    }
                    blk
                };
                let nb = N.div_ceil(B) as usize;
                if par {
                    crate::util::par::par_map_stream(nb, 0, block, |c, blk| {
                        r.rows_encoded(&blk, (((c as u64 + 1) * B).min(N) - c as u64 * B) as usize).unwrap();
                        true
                    });
                } else {
                    for c in 0..nb {
                        let blk = block(c);
                        r.rows_encoded(&blk, (((c as u64 + 1) * B).min(N) - c as u64 * B) as usize).unwrap();
                    }
                }
                r.finish().unwrap();
            }
            let dt = start.elapsed();
            let label = if par { "encoded/par" } else { "encoded/1t" };
            println!("{name:>7} {label}: {:>7.1} ms  ({:.0} ns/row)", dt.as_secs_f64() * 1e3, dt.as_nanos() as f64 / N as f64);
        }
    }
    // quick with a filter active (per-cell strings)
    let mut sink = std::fs::OpenOptions::new().write(true).open("/dev/null").unwrap();
    let start = std::time::Instant::now();
    {
        let opts = RenderOptions { filters: vec!["ImageFileName,svchost".into()], hide_columns: None, flush_rows: false };
        let mut r = create("quick", &mut sink, opts).unwrap();
        r.begin(columns()).unwrap();
        for i in 0..N {
            r.row(0, row(i)).unwrap();
        }
        r.finish().unwrap();
    }
    let dt = start.elapsed();
    println!("quick+filter: {N} rows in {:>7.1} ms  ({:.0} ns/row)", dt.as_secs_f64() * 1e3, dt.as_nanos() as f64 / N as f64);
}
