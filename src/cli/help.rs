//! argparse `HelpFormatter` (python 3.14) and `textwrap` ports used for `--help` and usage
//! messages (derived from Volatility 3 / CPython, Volatility Software License 1.0).

use super::argparse::{Action, Nargs, Parser};

/// ANSI theme (`_colorize.Argparse`); all empty when colour is off.
#[derive(Clone, Copy)]
pub struct Theme {
    pub usage: &'static str,
    pub prog: &'static str,
    pub prog_extra: &'static str,
    pub heading: &'static str,
    pub summary_long_option: &'static str,
    pub summary_short_option: &'static str,
    pub summary_label: &'static str,
    pub summary_action: &'static str,
    pub long_option: &'static str,
    pub short_option: &'static str,
    pub label: &'static str,
    pub action: &'static str,
    pub reset: &'static str,
}

const NO_COLOR: Theme = Theme {
    usage: "",
    prog: "",
    prog_extra: "",
    heading: "",
    summary_long_option: "",
    summary_short_option: "",
    summary_label: "",
    summary_action: "",
    long_option: "",
    short_option: "",
    label: "",
    action: "",
    reset: "",
};

const COLOR: Theme = Theme {
    usage: "\x1b[1;34m",
    prog: "\x1b[1;35m",
    prog_extra: "\x1b[35m",
    heading: "\x1b[1;34m",
    summary_long_option: "\x1b[36m",
    summary_short_option: "\x1b[32m",
    summary_label: "\x1b[33m",
    summary_action: "\x1b[32m",
    long_option: "\x1b[1;36m",
    short_option: "\x1b[1;32m",
    label: "\x1b[1;33m",
    action: "\x1b[1;32m",
    reset: "\x1b[0m",
};

unsafe extern "C" {
    fn isatty(fd: i32) -> i32;
    fn ioctl(fd: i32, request: u64, ...) -> i32;
}

/// `_colorize.can_colorize()` (for sys.stdout)
pub fn can_colorize() -> bool {
    let env = |k: &str| std::env::var_os(k);
    match env("PYTHON_COLORS").as_deref().and_then(|v| v.to_str()) {
        Some("0") => return false,
        Some("1") => return true,
        _ => {}
    }
    if env("NO_COLOR").is_some_and(|v| !v.is_empty()) {
        return false;
    }
    if env("FORCE_COLOR").is_some_and(|v| !v.is_empty()) {
        return true;
    }
    if env("TERM").as_deref().and_then(|v| v.to_str()) == Some("dumb") {
        return false;
    }
    unsafe { isatty(1) == 1 }
}

thread_local! {
    /// (terminal columns, colour) forced by `cli::Settings` (tests)
    static OVERRIDES: std::cell::Cell<(Option<usize>, Option<bool>)> = const { std::cell::Cell::new((None, None)) };
}

/// Force the terminal width / colour decision for this thread (None = detect).
pub fn set_overrides(columns: Option<usize>, color: Option<bool>) {
    OVERRIDES.with(|o| o.set((columns, color)));
}

pub fn theme() -> Theme {
    let color = OVERRIDES.with(|o| o.get().1).unwrap_or_else(can_colorize);
    if color { COLOR } else { NO_COLOR }
}

/// `shutil.get_terminal_size().columns`
pub fn terminal_columns() -> usize {
    if let Some(c) = OVERRIDES.with(|o| o.get().0) {
        return c;
    }
    if let Some(c) = std::env::var("COLUMNS").ok().and_then(|v| v.trim().parse::<i64>().ok()) {
        if c > 0 {
            return c as usize;
        }
    }
    #[repr(C)]
    #[derive(Default)]
    struct Winsize {
        row: u16,
        col: u16,
        x: u16,
        y: u16,
    }
    let mut ws = Winsize::default();
    const TIOCGWINSZ: u64 = 0x5413;
    let r = unsafe { ioctl(1, TIOCGWINSZ, &mut ws as *mut Winsize) };
    if r == 0 && ws.col > 0 { ws.col as usize } else { 80 }
}

/// Visible length (characters, without ANSI escapes).
fn vlen(s: &str) -> usize {
    let mut n = 0;
    let mut in_esc = false;
    for c in s.chars() {
        if in_esc {
            if c == 'm' {
                in_esc = false;
            }
        } else if c == '\x1b' {
            in_esc = true;
        } else {
            n += 1;
        }
    }
    n
}

fn decolor(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_esc = false;
    for c in s.chars() {
        if in_esc {
            if c == 'm' {
                in_esc = false;
            }
        } else if c == '\x1b' {
            in_esc = true;
        } else {
            out.push(c);
        }
    }
    out
}

// ------------------------------------------------------------------------------------------
// textwrap

fn is_ws(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\x0b' | '\x0c' | '\r' | ' ')
}
fn is_w(c: char) -> bool {
    c == '_' || c.is_alphanumeric()
}
/// `[^\d\W]`
fn is_letter(c: char) -> bool {
    is_w(c) && !(c.is_ascii_digit() || (!c.is_ascii() && c.is_numeric()))
}
/// `[\w!"\'&.,?]`
fn is_wordpunct(c: char) -> bool {
    is_w(c) || matches!(c, '!' | '"' | '\'' | '&' | '.' | ',' | '?')
}

/// `TextWrapper.wordsep_re.split(text)` with empty chunks removed (break_on_hyphens=True).
fn split_chunks(text: &str) -> Vec<String> {
    let c: Vec<char> = text.chars().collect();
    let n = c.len();
    let at = |i: usize| -> Option<char> { c.get(i).copied() };
    // run of >=2 hyphens at i followed by a \w char: returns run length
    let emdash_at = |i: usize| -> Option<usize> {
        let mut j = i;
        while j < n && c[j] == '-' {
            j += 1;
        }
        if j - i >= 2 && j < n && is_w(c[j]) { Some(j - i) } else { None }
    };
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < n {
        if is_ws(c[pos]) {
            let st = pos;
            while pos < n && is_ws(c[pos]) {
                pos += 1;
            }
            out.push(c[st..pos].iter().collect());
            continue;
        }
        if pos > 0 && is_wordpunct(c[pos - 1]) {
            if let Some(len) = emdash_at(pos) {
                out.push(c[pos..pos + len].iter().collect());
                pos += len;
                continue;
            }
        }
        // word, possibly hyphenated: \S+? followed by one of the alternatives
        let mut k = pos + 1;
        let end = loop {
            // hyphenated word: '-' (?<=lt{2}-|lt-lt-) (?=lt -? lt)
            if at(k) == Some('-') {
                let lb = (k >= 2 && is_letter(c[k - 2]) && is_letter(c[k - 1]))
                    || (k >= 3 && is_letter(c[k - 3]) && c[k - 2] == '-' && is_letter(c[k - 1]));
                let la = at(k + 1).is_some_and(is_letter)
                    && (at(k + 2).is_some_and(is_letter)
                        || (at(k + 2) == Some('-') && at(k + 3).is_some_and(is_letter)));
                if lb && la {
                    break k + 1;
                }
            }
            // end of word
            if k >= n || is_ws(c[k]) {
                break k;
            }
            // em-dash follows
            if is_wordpunct(c[k - 1]) && emdash_at(k).is_some() {
                break k;
            }
            k += 1;
        };
        out.push(c[pos..end].iter().collect());
        pos = end;
    }
    out
}

fn clen(s: &str) -> usize {
    s.chars().count()
}

/// `textwrap.wrap(text, width, initial_indent, subsequent_indent)` (default options).
pub fn wrap(text: &str, width: usize, initial_indent: &str, subsequent_indent: &str) -> Vec<String> {
    // _munge_whitespace: expand tabs, translate whitespace to spaces
    let mut munged = String::with_capacity(text.len());
    let mut col = 0;
    for ch in text.chars() {
        if ch == '\t' {
            let pad = 8 - col % 8;
            for _ in 0..pad {
                munged.push(' ');
            }
            col += pad;
        } else if ch == '\n' || ch == '\r' {
            munged.push(' ');
            col = 0;
        } else if is_ws(ch) {
            munged.push(' ');
            col += 1;
        } else {
            munged.push(ch);
            col += 1;
        }
    }
    let mut chunks = split_chunks(&munged);
    chunks.reverse();
    let mut lines: Vec<String> = Vec::new();
    while !chunks.is_empty() {
        let mut cur_line: Vec<String> = Vec::new();
        let mut cur_len = 0usize;
        let indent = if lines.is_empty() { initial_indent } else { subsequent_indent };
        let width_left = width as isize - clen(indent) as isize;
        if chunks.last().unwrap().trim().is_empty() && !lines.is_empty() {
            chunks.pop();
        }
        while let Some(last) = chunks.last() {
            let l = clen(last);
            if (cur_len + l) as isize <= width_left {
                cur_line.push(chunks.pop().unwrap());
                cur_len += l;
            } else {
                break;
            }
        }
        if let Some(last) = chunks.last() {
            if clen(last) as isize > width_left {
                // _handle_long_word
                let space_left = if width_left < 1 { 1 } else { width_left - cur_len as isize };
                if space_left > 0 {
                    let chunk: Vec<char> = chunks.last().unwrap().chars().collect();
                    let mut end = space_left as usize;
                    if chunk.len() > end {
                        if let Some(h) = chunk[..end].iter().rposition(|&c| c == '-') {
                            if h > 0 && chunk[..h].iter().any(|&c| c != '-') {
                                end = h + 1;
                            }
                        }
                    }
                    let end = end.min(chunk.len());
                    cur_line.push(chunk[..end].iter().collect());
                    *chunks.last_mut().unwrap() = chunk[end..].iter().collect();
                } else if cur_line.is_empty() {
                    cur_line.push(chunks.pop().unwrap());
                }
                cur_len = cur_line.iter().map(|s| clen(s)).sum();
            }
        }
        if cur_line.last().is_some_and(|s| s.trim().is_empty()) {
            let l = cur_line.pop().unwrap();
            cur_len -= clen(&l);
        }
        let _ = cur_len;
        if !cur_line.is_empty() {
            lines.push(format!("{indent}{}", cur_line.concat()));
        }
    }
    lines
}

/// argparse's `_whitespace_matcher.sub(' ', text).strip()` (`\s+` with re.ASCII)
fn collapse_ws(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_ws = false;
    for c in text.chars() {
        if is_ws(c) {
            in_ws = true;
        } else {
            if in_ws && !out.is_empty() {
                out.push(' ');
            }
            in_ws = false;
            out.push(c);
        }
    }
    out
}

// ------------------------------------------------------------------------------------------
// HelpFormatter

pub struct Formatter {
    prog: String,
    width: usize,
    max_help_position: usize,
    action_max_length: usize,
    t: Theme,
}

impl Formatter {
    pub fn new(prog: &str) -> Formatter {
        let width = terminal_columns().saturating_sub(2);
        Formatter::with(prog, width, theme())
    }

    pub fn with(prog: &str, width: usize, t: Theme) -> Formatter {
        let max_help_position = 24usize.min((width as isize - 20).max(4) as usize);
        Formatter { prog: prog.to_string(), width, max_help_position, action_max_length: 0, t }
    }

    fn metavar(a: &Action, default: &str) -> String {
        if let Some(m) = &a.metavar {
            m.clone()
        } else if let Some(c) = &a.choices {
            format!("{{{}}}", c.join(","))
        } else {
            default.to_string()
        }
    }

    fn default_metavar(a: &Action) -> String {
        if a.option_strings.is_empty() { a.dest.clone() } else { a.dest.to_uppercase() }
    }

    fn format_args(a: &Action) -> String {
        let m = Self::metavar(a, &Self::default_metavar(a));
        match a.nargs {
            Nargs::Single => m,
            Nargs::Optional => format!("[{m}]"),
            Nargs::ZeroOrMore => format!("[{m} ...]"),
            Nargs::OneOrMore => format!("{m} [{m} ...]"),
            Nargs::Parser => format!("{m} ..."),
            Nargs::Zero => String::new(),
        }
    }

    fn format_invocation(&self, a: &Action) -> String {
        let t = &self.t;
        if a.option_strings.is_empty() {
            return format!("{}{}{}", t.action, Self::metavar(a, &Self::default_metavar(a)), t.reset);
        }
        let opts: Vec<String> = a
            .option_strings
            .iter()
            .map(|s| {
                if s.chars().count() > 2 {
                    format!("{}{}{}", t.long_option, s, t.reset)
                } else {
                    format!("{}{}{}", t.short_option, s, t.reset)
                }
            })
            .collect();
        if a.nargs == Nargs::Zero {
            opts.join(", ")
        } else {
            format!("{} {}{}{}", opts.join(", "), t.label, Self::format_args(a), t.reset)
        }
    }

    /// `_get_actions_usage_parts`: (parts, pos_start)
    fn usage_parts(&self, p: &Parser) -> (Vec<String>, usize) {
        let t = &self.t;
        let actions: Vec<usize> = (0..p.actions.len()).collect();
        let group_of = |i: usize| -> Option<usize> { p.mutex.iter().position(|g| g.contains(&i)) };
        let mut remaining: Vec<bool> = vec![true; actions.len()];
        let mut positionals: Vec<Vec<usize>> = Vec::new();
        for &i in &actions {
            if p.actions[i].option_strings.is_empty() {
                remaining[i] = false;
                match group_of(i) {
                    Some(g) => {
                        let mut ga: Vec<usize> = p.mutex[g]
                            .iter()
                            .copied()
                            .filter(|&j| !p.actions[j].option_strings.is_empty() && std::mem::take(&mut remaining[j]))
                            .collect();
                        ga.push(i);
                        positionals.push(ga);
                    }
                    None => positionals.push(vec![i]),
                }
            }
        }
        let mut optionals: Vec<Vec<usize>> = Vec::new();
        for &i in &actions {
            if !p.actions[i].option_strings.is_empty() && remaining[i] {
                remaining[i] = false;
                match group_of(i) {
                    Some(g) => {
                        let mut ga = vec![i];
                        ga.extend(p.mutex[g].iter().copied().filter(|&j| {
                            !p.actions[j].option_strings.is_empty() && std::mem::take(&mut remaining[j])
                        }));
                        optionals.push(ga);
                    }
                    None => optionals.push(vec![i]),
                }
            }
        }
        let nopt = optionals.len();
        let mut parts: Vec<String> = Vec::new();
        let mut pos_start = None;
        for (k, group) in optionals.into_iter().chain(positionals).enumerate() {
            let start = parts.len();
            if k == nopt {
                pos_start = Some(start);
            }
            let in_group = group.len() > 1;
            for &i in &group {
                let a = &p.actions[i];
                let part = if a.option_strings.is_empty() {
                    let mut part = Self::format_args(a);
                    if in_group && part.starts_with('[') && part.ends_with(']') {
                        part = part[1..part.len() - 1].to_string();
                    }
                    format!("{}{}{}", t.summary_action, part, t.reset)
                } else {
                    let os = &a.option_strings[0];
                    let color = if os.chars().count() > 2 { t.summary_long_option } else { t.summary_short_option };
                    let part = if a.nargs == Nargs::Zero {
                        format!("{color}{os}{}", t.reset)
                    } else {
                        format!("{color}{os} {}{}{}", t.summary_label, Self::format_args(a), t.reset)
                    };
                    if !(a.required || in_group) { format!("[{part}]") } else { part }
                };
                parts.push(part);
            }
            if in_group {
                // mutually exclusive groups here are never required
                parts[start] = format!("[{}", parts[start]);
                let last = parts.len() - 1;
                for part in parts.iter_mut().take(last).skip(start) {
                    part.push_str(" |");
                }
                parts[last].push(']');
            }
        }
        let pos_start = pos_start.unwrap_or(parts.len());
        (parts, pos_start)
    }

    /// `_format_usage(None, actions, groups, prefix)` with the trailing blank line.
    pub fn format_usage(&self, p: &Parser) -> String {
        let t = &self.t;
        let prefix = "usage: ";
        let prog = self.prog.clone();
        let usage = if p.actions.is_empty() {
            format!("{}{}{}", t.prog, prog, t.reset)
        } else {
            let (parts, pos_start) = self.usage_parts(p);
            let mut all: Vec<&str> = vec![prog.as_str()];
            all.extend(parts.iter().map(|s| s.as_str()).filter(|s| !s.is_empty()));
            let mut usage = all.join(" ");
            let text_width = self.width;
            if prefix.len() + vlen(&usage) > text_width {
                let opt_parts: Vec<String> = parts[..pos_start].to_vec();
                let pos_parts: Vec<String> = parts[pos_start..].to_vec();
                let get_lines = |parts: &[String], indent: &str, prefix: Option<&str>| -> Vec<String> {
                    let mut lines: Vec<String> = Vec::new();
                    let mut line: Vec<&str> = Vec::new();
                    let indent_length = indent.chars().count();
                    let mut line_len: isize =
                        if let Some(pf) = prefix { pf.len() as isize - 1 } else { indent_length as isize - 1 };
                    for part in parts {
                        let part_len = vlen(part) as isize;
                        if line_len + 1 + part_len > text_width as isize && !line.is_empty() {
                            lines.push(format!("{indent}{}", line.join(" ")));
                            line.clear();
                            line_len = indent_length as isize - 1;
                        }
                        line.push(part);
                        line_len += part_len + 1;
                    }
                    if !line.is_empty() {
                        lines.push(format!("{indent}{}", line.join(" ")));
                    }
                    if prefix.is_some() && !lines.is_empty() {
                        lines[0] = lines[0].chars().skip(indent_length).collect();
                    }
                    lines
                };
                let prog_len = vlen(&prog);
                let lines: Vec<String> = if (prefix.len() + prog_len) as f64 <= 0.75 * text_width as f64 {
                    let indent = " ".repeat(prefix.len() + prog_len + 1);
                    let mut first = vec![prog.clone()];
                    if !opt_parts.is_empty() {
                        first.extend(opt_parts.iter().cloned());
                        let mut lines = get_lines(&first, &indent, Some(prefix));
                        lines.extend(get_lines(&pos_parts, &indent, None));
                        lines
                    } else if !pos_parts.is_empty() {
                        first.extend(pos_parts.iter().cloned());
                        get_lines(&first, &indent, Some(prefix))
                    } else {
                        vec![prog.clone()]
                    }
                } else {
                    let indent = " ".repeat(prefix.len());
                    let all_parts: Vec<String> = opt_parts.iter().chain(pos_parts.iter()).cloned().collect();
                    let mut lines = get_lines(&all_parts, &indent, None);
                    if lines.len() > 1 {
                        lines = get_lines(&opt_parts, &indent, None);
                        lines.extend(get_lines(&pos_parts, &indent, None));
                    }
                    let mut v = vec![prog.clone()];
                    v.extend(lines);
                    v
                };
                usage = lines.join("\n");
            }
            let rest = usage.strip_prefix(prog.as_str()).unwrap_or(&usage).to_string();
            format!("{}{}{}{}", t.prog, prog, t.reset, rest)
        };
        format!("{}{}{}{}\n\n", t.usage, prefix, t.reset, usage)
    }

    fn format_text(&self, text: &str, indent: usize) -> String {
        let text = if text.contains("%(prog)") { text.replace("%(prog)s", &self.prog) } else { text.to_string() };
        let text_width = (self.width as isize - indent as isize).max(11) as usize;
        let ind = " ".repeat(indent);
        let body = wrap(&collapse_ws(&text), text_width, &ind, &ind).join("\n");
        format!("{body}\n\n")
    }

    fn expand_help(&self, a: &Action) -> String {
        let h = a.help.clone().unwrap_or_default();
        if !h.contains('%') {
            return h;
        }
        let mut out = String::new();
        let mut rest = h.as_str();
        while let Some(i) = rest.find('%') {
            out.push_str(&rest[..i]);
            rest = &rest[i + 1..];
            if let Some(r) = rest.strip_prefix('%') {
                out.push('%');
                rest = r;
            } else if let Some(r) = rest.strip_prefix('(') {
                if let Some(end) = r.find(')') {
                    let key = &r[..end];
                    let after = &r[end + 1..];
                    let val = match key {
                        "prog" => self.prog.clone(),
                        "dest" => a.dest.clone(),
                        "metavar" => a.metavar.clone().unwrap_or_else(|| "None".into()),
                        "default" => a.default.as_ref().map(|d| d.py_str()).unwrap_or_default(),
                        "choices" => a.choices.as_ref().map(|c| c.join(", ")).unwrap_or_else(|| "None".into()),
                        "required" => (if a.required { "True" } else { "False" }).into(),
                        _ => String::new(),
                    };
                    // conversion char (usually 's')
                    let mut chars = after.chars();
                    let _ = chars.next();
                    out.push_str(&val);
                    rest = chars.as_str();
                } else {
                    out.push('%');
                }
            } else {
                out.push('%');
            }
        }
        out.push_str(rest);
        out
    }

    fn format_action(&self, a: &Action, indent: usize, out: &mut String) {
        let help_position = (self.action_max_length + 2).min(self.max_help_position);
        let help_width = (self.width as isize - help_position as isize).max(11) as usize;
        let action_width = help_position as isize - indent as isize - 2;
        let header = self.format_invocation(a);
        let header_plain = decolor(&header);
        let has_help = a.help.as_deref().is_some_and(|h| !h.is_empty());
        let mut indent_first = 0usize;
        if !has_help {
            out.push_str(&" ".repeat(indent));
            out.push_str(&header);
            out.push('\n');
        } else if (clen(&header_plain) as isize) <= action_width {
            out.push_str(&" ".repeat(indent));
            let pad = action_width as usize - clen(&header_plain);
            out.push_str(&header);
            out.push_str(&" ".repeat(pad));
            out.push_str("  ");
        } else {
            out.push_str(&" ".repeat(indent));
            out.push_str(&header);
            out.push('\n');
            indent_first = help_position;
        }
        if a.help.as_deref().is_some_and(|h| !h.trim().is_empty()) {
            let text = self.expand_help(a);
            if !text.is_empty() {
                let lines = wrap(&collapse_ws(&text), help_width, "", "");
                if let Some(first) = lines.first() {
                    out.push_str(&" ".repeat(indent_first));
                    out.push_str(first);
                    out.push('\n');
                }
                for l in lines.iter().skip(1) {
                    out.push_str(&" ".repeat(help_position));
                    out.push_str(l);
                    out.push('\n');
                }
            }
        } else if !out.ends_with('\n') {
            out.push('\n');
        }
        if let Some(sub) = &a.sub_choices {
            for (name, help) in sub.iter() {
                let pseudo = Action::pseudo(name, help.clone());
                self.format_action(&pseudo, indent + 2, out);
            }
        }
    }

    /// `ArgumentParser.format_help()`
    pub fn format_help(mut self, p: &Parser) -> String {
        // add_argument pass: compute the widest invocation
        let mut maxlen = 0;
        for g in &p.groups {
            for &i in &g.actions {
                let a = &p.actions[i];
                maxlen = maxlen.max(vlen(&self.format_invocation(a)) + 2);
                if let Some(sub) = &a.sub_choices {
                    for (name, _) in sub.iter() {
                        maxlen = maxlen.max(clen(name) + 4);
                    }
                }
            }
        }
        self.action_max_length = maxlen;
        let mut help = String::from("\n");
        help.push_str(&self.format_usage(p));
        if let Some(d) = &p.description {
            help.push_str(&self.format_text(d, 0));
        }
        for g in &p.groups {
            let mut items = String::new();
            if let Some(d) = &g.description {
                items.push_str(&self.format_text(d, 2));
            }
            for &i in &g.actions {
                self.format_action(&p.actions[i], 2, &mut items);
            }
            if items.is_empty() {
                continue;
            }
            help.push('\n');
            help.push_str(self.t.heading);
            help.push_str(&g.title);
            help.push(':');
            help.push_str(self.t.reset);
            help.push('\n');
            help.push_str(&items);
            help.push('\n');
        }
        if let Some(e) = &p.epilog {
            help.push_str(&self.format_text(e, 0));
        }
        help.push('\n');
        // _long_break_matcher.sub('\n\n', help); strip('\n') + '\n'
        let mut collapsed = String::with_capacity(help.len());
        let mut nl = 0;
        for c in help.chars() {
            if c == '\n' {
                nl += 1;
            } else {
                if nl > 0 {
                    collapsed.push_str(if nl >= 2 { "\n\n" } else { "\n" });
                    nl = 0;
                }
                collapsed.push(c);
            }
        }
        let body = collapsed.trim_start_matches('\n');
        format!("{body}\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunks() {
        assert_eq!(
            split_chunks("Look, goof-ball -- use the -b option!"),
            vec!["Look,", " ", "goof-", "ball", " ", "--", " ", "use", " ", "the", " ", "-b", " ", "option!"]
        );
        assert_eq!(split_chunks("single-location"), vec!["single-", "location"]);
        assert_eq!(split_chunks("a--b"), vec!["a", "--", "b"]);
        assert_eq!(
            split_chunks("--single-swap-locations foo-bar-baz"),
            vec!["--single-", "swap-", "locations", " ", "foo-", "bar-", "baz"]
        );
        let cases: [(&str, &[&str]); 7] = [
            ("x-y", &["x-y"]),
            ("ab-cd", &["ab-", "cd"]),
            ("a-b-c-d", &["a-b-", "c-d"]),
            ("abc--", &["abc--"]),
            ("12-34", &["12-34"]),
            ("ab-c", &["ab-c"]),
            ("ab-1c", &["ab-1c"]),
        ];
        for (t, want) in cases {
            assert_eq!(split_chunks(t), want, "{t}");
        }
    }

    #[test]
    fn wrapping() {
        assert_eq!(
            wrap("Shorthand for --single-location=file:// if single-location is not defined", 54, "", ""),
            vec!["Shorthand for --single-location=file:// if single-", "location is not defined"]
        );
    }
}
