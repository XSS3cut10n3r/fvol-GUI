//! python `format(int, spec)` / f-string `{x:spec}` for integers and strings (the subset
//! plugins use: `#x`, `#010x`, `08X`, `>10`, `<8`, `^5`, `,`, `+d`, `b`, `o`, `c`).
//!
//! ```ignore
//! use crate::util::pyformat::fmt_int;
//! assert_eq!(fmt_int(255, "#010x"), "0x000000ff");
//! assert_eq!(fmt_int(-5, "#010x"), "-0x0000005");
//! ```

/// A parsed python format spec.
#[derive(Clone, Copy, Debug, Default)]
struct Spec {
    fill: char,
    align: Option<char>,
    sign: Option<char>,
    alternate: bool,
    zero: bool,
    width: usize,
    grouping: Option<char>,
    ty: Option<char>,
}

fn parse(spec: &str) -> Spec {
    let c: Vec<char> = spec.chars().collect();
    let mut s = Spec { fill: ' ', ..Default::default() };
    let mut i = 0;
    if c.len() >= 2 && matches!(c[1], '<' | '>' | '^' | '=') {
        s.fill = c[0];
        s.align = Some(c[1]);
        i = 2;
    } else if !c.is_empty() && matches!(c[0], '<' | '>' | '^' | '=') {
        s.align = Some(c[0]);
        i = 1;
    }
    if i < c.len() && matches!(c[i], '+' | '-' | ' ') {
        s.sign = Some(c[i]);
        i += 1;
    }
    if i < c.len() && c[i] == '#' {
        s.alternate = true;
        i += 1;
    }
    if i < c.len() && c[i] == '0' {
        s.zero = true;
        i += 1;
    }
    let ws = i;
    while i < c.len() && c[i].is_ascii_digit() {
        i += 1;
    }
    s.width = c[ws..i].iter().collect::<String>().parse().unwrap_or(0);
    if i < c.len() && (c[i] == ',' || c[i] == '_') {
        s.grouping = Some(c[i]);
        i += 1;
    }
    if i < c.len() {
        s.ty = Some(c[i]);
    }
    s
}

fn group(digits: &str, sep: char, every: usize) -> String {
    let n = digits.len();
    let mut out = String::with_capacity(n + n / every);
    for (k, ch) in digits.chars().enumerate() {
        if k > 0 && (n - k) % every == 0 {
            out.push(sep);
        }
        out.push(ch);
    }
    out
}

fn pad(body: &str, prefix: &str, s: &Spec, default_align: char) -> String {
    let len = prefix.chars().count() + body.chars().count();
    if s.width <= len {
        return format!("{prefix}{body}");
    }
    let n = s.width - len;
    let (fill, align) = if s.zero && s.align.is_none() { ('0', '=') } else { (s.fill, s.align.unwrap_or(default_align)) };
    let f = |k: usize| std::iter::repeat_n(fill, k).collect::<String>();
    match align {
        '<' => format!("{prefix}{body}{}", f(n)),
        '^' => format!("{}{prefix}{body}{}", f(n / 2), f(n - n / 2)),
        '=' => format!("{prefix}{}{body}", f(n)),
        _ => format!("{}{prefix}{body}", f(n)),
    }
}

/// python `format(v, spec)` for an int.
pub fn fmt_int(v: i128, spec: &str) -> String {
    let s = parse(spec);
    let neg = v < 0;
    let a = v.unsigned_abs();
    let (digits, alt) = match s.ty.unwrap_or('d') {
        'x' => (format!("{a:x}"), "0x"),
        'X' => (format!("{a:X}"), "0X"),
        'o' => (format!("{a:o}"), "0o"),
        'b' => (format!("{a:b}"), "0b"),
        'c' => return pad(&char::from_u32(v as u32).unwrap_or('\u{FFFD}').to_string(), "", &s, '<'),
        _ => (a.to_string(), ""),
    };
    let digits = match s.grouping {
        Some(g) => group(&digits, g, if matches!(s.ty, Some('x' | 'X' | 'o' | 'b')) { 4 } else { 3 }),
        None => digits,
    };
    let mut prefix = String::new();
    if neg {
        prefix.push('-');
    } else if s.sign == Some('+') {
        prefix.push('+');
    } else if s.sign == Some(' ') {
        prefix.push(' ');
    }
    if s.alternate {
        prefix.push_str(alt);
    }
    pad(&digits, &prefix, &s, '>')
}

/// python `format(s, spec)` for a str (`<10`, `>8`, `^5`, `.3`...).
pub fn fmt_str(v: &str, spec: &str) -> String {
    let (spec, prec) = match spec.split_once('.') {
        Some((a, b)) => (a, b.trim_end_matches('s').parse::<usize>().ok()),
        None => (spec, None),
    };
    let s = parse(spec.trim_end_matches('s'));
    let body: String = match prec {
        Some(p) => v.chars().take(p).collect(),
        None => v.to_string(),
    };
    pad(&body, "", &s, '<')
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ints() {
        assert_eq!(fmt_int(255, "#010x"), "0x000000ff");
        assert_eq!(fmt_int(-5, "#010x"), "-0x0000005");
        assert_eq!(fmt_int(255, "#x"), "0xff");
        assert_eq!(fmt_int(255, "08X"), "000000FF");
        assert_eq!(fmt_int(1234567, ","), "1,234,567");
        assert_eq!(fmt_int(42, ">6"), "    42");
        assert_eq!(fmt_int(42, "<6"), "42    ");
        assert_eq!(fmt_int(42, "^6"), "  42  ");
        assert_eq!(fmt_int(42, "+d"), "+42");
        assert_eq!(fmt_int(5, "b"), "101");
    }
    #[test]
    fn strs() {
        assert_eq!(fmt_str("ab", "<5"), "ab   ");
        assert_eq!(fmt_str("ab", ">5"), "   ab");
        assert_eq!(fmt_str("abcdef", ".3"), "abc");
    }
}
