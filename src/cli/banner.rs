//! `fvol --version` (not part of volatility3, whose CLI has no version option; dispatched before
//! the CLI like `serve`): the fastvol mark drawn with half blocks next to the version lines.
//!
//! The mark is the pixel grid the README logo and the favicons are generated from
//! (`docs/assets/mark.txt`, see docs/assets/build.py): `#` glyph, `+` tile, `.` transparent. Each
//! terminal line holds two pixel rows: `▀` with the top pixel's colour as foreground and the
//! bottom one's as background, `▄` / `█` where only one half is drawn or both halves agree.

use std::io::Write;

const MARK: &str = include_str!("../../docs/assets/mark.txt");

/// (truecolor, xterm-256 index) of the glyph and the tile.
const GLYPH: ((u8, u8, u8), u8) = ((0x46, 0xe6, 0x7a), 78);
const TILE: ((u8, u8, u8), u8) = ((0x12, 0x30, 0x20), 22);

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Colors {
    /// 24-bit colour (`COLORTERM=truecolor` / `24bit`)
    True,
    /// the xterm 256-colour palette
    Xterm256,
    /// no colour: the glyph alone in block characters
    Mono,
    /// not a terminal: the version lines only
    Plain,
}

/// The version lines: the first is fastvol's, the second the python release it reproduces.
pub fn lines() -> [String; 3] {
    [
        format!("fastvol {}", env!("CARGO_PKG_VERSION")),
        format!("{} compatible", crate::VERSION_BANNER),
        "memory forensics in Rust, zero dependencies".to_string(),
    ]
}

/// What stdout can show: colour only on a terminal, and not with `NO_COLOR` or `TERM=dumb`.
pub fn detect() -> Colors {
    unsafe extern "C" {
        fn isatty(fd: i32) -> i32;
    }
    if unsafe { isatty(1) } != 1 {
        return Colors::Plain;
    }
    let var = |k: &str| std::env::var(k).unwrap_or_default();
    let term = var("TERM");
    if std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()) || term == "dumb" {
        return Colors::Mono;
    }
    let ct = var("COLORTERM");
    if ct == "truecolor" || ct == "24bit" {
        Colors::True
    } else if term.contains("256color") {
        Colors::Xterm256
    } else {
        Colors::Mono
    }
}

fn grid() -> Vec<&'static [u8]> {
    MARK.lines().filter(|l| !l.trim().is_empty()).map(str::as_bytes).collect()
}

/// The pixel's colour, None for transparent.
fn color(c: u8) -> Option<((u8, u8, u8), u8)> {
    match c {
        b'#' => Some(GLYPH),
        b'+' => Some(TILE),
        _ => None,
    }
}

fn sgr(out: &mut String, fg: bool, c: ((u8, u8, u8), u8), mode: Colors) {
    let (base, (r, g, b), idx) = (if fg { 38 } else { 48 }, c.0, c.1);
    match mode {
        Colors::True => out.push_str(&format!("\x1b[{base};2;{r};{g};{b}m")),
        _ => out.push_str(&format!("\x1b[{base};5;{idx}m")),
    }
}

/// The mark as terminal lines (without trailing newlines).
pub fn mark_lines(mode: Colors) -> Vec<String> {
    let rows = grid();
    let mut lines = Vec::new();
    if mode == Colors::Mono {
        // the glyph only: the tile would be a solid block without colour
        let glyph: Vec<&[u8]> = rows.iter().copied().filter(|r| r.contains(&b'#')).collect();
        for pair in glyph.chunks(2) {
            let (top, bot) = (pair[0], pair.get(1).copied().unwrap_or(&[]));
            let s: String = (0..top.len())
                .map(|x| match (top[x] == b'#', bot.get(x) == Some(&b'#')) {
                    (true, true) => '█',
                    (true, false) => '▀',
                    (false, true) => '▄',
                    (false, false) => ' ',
                })
                .collect();
            lines.push(s);
        }
        return lines;
    }
    for pair in rows.chunks(2) {
        let (top, bot) = (pair[0], pair.get(1).copied().unwrap_or(&[]));
        let mut s = String::new();
        for (x, &tc) in top.iter().enumerate() {
            let (t, b) = (color(tc), bot.get(x).copied().and_then(color));
            match (t, b) {
                (None, None) => s.push(' '),
                (Some(t), None) => {
                    sgr(&mut s, true, t, mode);
                    s.push('▀');
                }
                (None, Some(b)) => {
                    sgr(&mut s, true, b, mode);
                    s.push('▄');
                }
                (Some(t), Some(b)) if t == b => {
                    sgr(&mut s, true, t, mode);
                    s.push('█');
                }
                (Some(t), Some(b)) => {
                    sgr(&mut s, true, t, mode);
                    sgr(&mut s, false, b, mode);
                    s.push('▀');
                }
            }
            s.push_str("\x1b[0m");
        }
        lines.push(s);
    }
    lines
}

/// The whole output of `fvol --version` for `mode`.
pub fn render(mode: Colors) -> String {
    let text = lines();
    if mode == Colors::Plain {
        return text.iter().map(|l| format!("{l}\n")).collect();
    }
    let mark = mark_lines(mode);
    // the name on the line of the f's crossbar (the row with the longest glyph run), the other
    // lines below it; the mono mark starts at the first glyph row
    let rows = grid();
    let run = |r: &[u8]| r.split(|&c| c != b'#').map(<[u8]>::len).max().unwrap_or(0);
    let bar = (0..rows.len()).max_by_key(|&y| (run(rows[y]), std::cmp::Reverse(y))).unwrap_or(0);
    let top = if mode == Colors::Mono { rows.iter().position(|r| r.contains(&b'#')).unwrap_or(0) } else { 0 };
    let first = bar.saturating_sub(top) / 2;
    let mut out = String::new();
    for (i, m) in mark.iter().enumerate() {
        out.push_str(m);
        if let Some(t) = i.checked_sub(first).and_then(|k| text.get(k)) {
            out.push_str("   ");
            match (i - first, mode) {
                (0, Colors::Mono) => out.push_str(&format!("\x1b[1m{t}\x1b[0m")),
                (0, _) => {
                    let mut s = String::from("\x1b[1m");
                    sgr(&mut s, true, GLYPH, mode);
                    out.push_str(&format!("{s}{t}\x1b[0m"));
                }
                _ => out.push_str(t),
            }
        }
        out.push('\n');
    }
    out
}

/// `fvol --version` / `fvol -V`.
pub fn main(out: &mut dyn Write) -> i32 {
    let _ = out.write_all(render(detect()).as_bytes());
    let _ = out.flush();
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grid_is_even_and_rectangular() {
        let g = grid();
        assert_eq!(g.len() % 2, 0);
        assert!(g.iter().all(|r| r.len() == g[0].len()));
        assert!(g.iter().all(|r| r.iter().all(|c| b"#+.".contains(c))));
    }

    #[test]
    fn renders() {
        let plain = render(Colors::Plain);
        assert!(plain.starts_with(&format!("fastvol {}\n", env!("CARGO_PKG_VERSION"))));
        assert_eq!(plain.lines().count(), 3);
        for mode in [Colors::True, Colors::Xterm256] {
            let s = render(mode);
            assert_eq!(s.lines().count(), grid().len() / 2);
            assert!(s.contains(&format!("fastvol {}", env!("CARGO_PKG_VERSION"))) && s.contains("Volatility 3 Framework"));
        }
        let mono = render(Colors::Mono);
        assert!(!mono.contains("\x1b[38"));
        assert!(mono.contains('█') && mono.contains("fastvol"));
    }
}
