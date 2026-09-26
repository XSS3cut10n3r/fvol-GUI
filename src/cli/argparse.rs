//! A port of the parts of python 3.14's `argparse` (plus volatility3's `volargparse`
//! HelpfulArgParser / HelpfulSubparserAction) that the volatility3 CLI relies on: option
//! classification incl. abbreviations, `--opt=value`, `-fVALUE`, combined short flags, `--`,
//! nargs patterns, mutually exclusive groups, subparsers selected by substring, the exact error
//! messages and `--help` (derived from Volatility 3 / CPython, Volatility Software License 1.0).

use super::help::Formatter;
use crate::renderers::pyfmt::{parse_int0, str_repr};
use std::borrow::Cow;
use std::rc::Rc;

/// A namespace value.
#[derive(Clone, Debug, PartialEq)]
pub enum PyVal {
    None,
    Bool(bool),
    Int(i128),
    Str(String),
    List(Vec<PyVal>),
}

impl PyVal {
    /// python `str(value)`
    pub fn py_str(&self) -> String {
        match self {
            PyVal::None => "None".into(),
            PyVal::Bool(b) => (if *b { "True" } else { "False" }).into(),
            PyVal::Int(i) => i.to_string(),
            PyVal::Str(s) => s.clone(),
            PyVal::List(l) => format!("[{}]", l.iter().map(|v| v.py_repr()).collect::<Vec<_>>().join(", ")),
        }
    }
    /// python `repr(value)`
    pub fn py_repr(&self) -> String {
        match self {
            PyVal::Str(s) => str_repr(s),
            _ => self.py_str(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Nargs {
    /// `None` (exactly one)
    Single,
    Optional,
    ZeroOrMore,
    OneOrMore,
    Parser,
    /// flags (store_true, count, help)
    Zero,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Kind {
    Help,
    Store,
    StoreTrue,
    Count,
    Append,
    Extend,
    Parsers,
}

/// The `type=` callable.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Conv {
    Str,
    /// `lambda x: int(x, 0)`
    Int0,
    /// `bytes` (always fails for a str argument, like python)
    Bytes,
}

/// Lazily built (name, short help) list of the subcommands, for `--help` only.
pub type SubHelp = Rc<dyn Fn() -> Vec<(String, Option<String>)>>;

#[derive(Clone)]
pub struct Action {
    pub option_strings: Vec<String>,
    pub dest: &'static str,
    pub kind: Kind,
    pub nargs: Nargs,
    pub const_: PyVal,
    /// `None` is argparse.SUPPRESS
    pub default: Option<PyVal>,
    pub conv: Conv,
    pub choices: Option<Vec<String>>,
    pub required: bool,
    pub help: Option<Cow<'static, str>>,
    pub metavar: Option<String>,
    /// subparser choices (name, help) for the help listing
    pub sub_choices: Option<SubHelp>,
}

impl Action {
    pub fn new(option_strings: &[&str], dest: &'static str, kind: Kind) -> Action {
        let nargs = match kind {
            Kind::Help | Kind::StoreTrue | Kind::Count => Nargs::Zero,
            Kind::Parsers => Nargs::Parser,
            _ => Nargs::Single,
        };
        Action {
            option_strings: option_strings.iter().map(|s| s.to_string()).collect(),
            dest,
            kind,
            nargs,
            const_: PyVal::None,
            default: Some(match kind {
                Kind::StoreTrue => PyVal::Bool(false),
                _ => PyVal::None,
            }),
            conv: Conv::Str,
            choices: None,
            required: false,
            help: None,
            metavar: None,
            sub_choices: None,
        }
    }

    pub fn pseudo(name: &str, help: Option<String>) -> Action {
        let mut a = Action::new(&[], "", Kind::Store);
        a.metavar = Some(name.to_string());
        a.help = help.map(Cow::Owned);
        a
    }

    pub fn help(mut self, h: impl Into<Cow<'static, str>>) -> Self {
        self.help = Some(h.into());
        self
    }
    pub fn default(mut self, v: PyVal) -> Self {
        self.default = Some(v);
        self
    }
    pub fn nargs(mut self, n: Nargs) -> Self {
        self.nargs = n;
        self
    }
    pub fn metavar(mut self, m: &str) -> Self {
        self.metavar = Some(m.to_string());
        self
    }
    pub fn choices(mut self, c: Vec<String>) -> Self {
        self.choices = Some(c);
        self
    }
    pub fn conv(mut self, c: Conv) -> Self {
        self.conv = c;
        self
    }
    pub fn constant(mut self, c: PyVal) -> Self {
        self.const_ = c;
        self
    }
    pub fn required(mut self, r: bool) -> Self {
        self.required = r;
        self
    }

    /// `_get_action_name`
    fn name(&self) -> Option<String> {
        if !self.option_strings.is_empty() {
            Some(self.option_strings.join("/"))
        } else if let Some(m) = &self.metavar {
            Some(m.clone())
        } else if self.dest != "==SUPPRESS==" {
            Some(self.dest.to_string())
        } else {
            self.choices.as_ref().map(|c| format!("{{{}}}", c.join(",")))
        }
    }
}

pub struct Group {
    pub title: String,
    pub description: Option<String>,
    pub actions: Vec<usize>,
}

/// Builds the parser for the chosen subcommand (only the matched one is ever built).
pub type SubFactory = Rc<dyn Fn(&str) -> Parser>;

pub struct Parser {
    pub prog: String,
    pub description: Option<String>,
    pub epilog: Option<String>,
    pub actions: Vec<Action>,
    /// 0 = "positional arguments", 1 = "options", then user groups
    pub groups: Vec<Group>,
    /// mutually exclusive groups (never required here)
    pub mutex: Vec<Vec<usize>>,
    pub defaults: Vec<(String, PyVal)>,
    /// subcommand names (matched by substring, like volatility3's HelpfulSubparserAction)
    pub sub_names: Rc<Vec<&'static str>>,
    pub sub_factory: Option<SubFactory>,
}

/// The namespace (python `argparse.Namespace`), insertion ordered.
#[derive(Clone, Debug, Default)]
pub struct Namespace {
    pub vals: Vec<(Cow<'static, str>, PyVal)>,
    unrecognized: Vec<String>,
}

impl Namespace {
    pub fn get(&self, k: &str) -> Option<&PyVal> {
        self.vals.iter().find(|(n, _)| n == k).map(|(_, v)| v)
    }
    pub fn has(&self, k: &str) -> bool {
        self.vals.iter().any(|(n, _)| n == k)
    }
    pub fn set(&mut self, k: impl Into<Cow<'static, str>>, v: PyVal) {
        let k = k.into();
        match self.vals.iter_mut().find(|(n, _)| *n == k) {
            Some(slot) => slot.1 = v,
            None => self.vals.push((k, v)),
        }
    }
    pub fn str(&self, k: &str) -> Option<&str> {
        match self.get(k) {
            Some(PyVal::Str(s)) => Some(s),
            _ => None,
        }
    }
    pub fn bool(&self, k: &str) -> bool {
        match self.get(k) {
            Some(PyVal::Bool(b)) => *b,
            Some(PyVal::Int(i)) => *i != 0,
            Some(PyVal::Str(s)) => !s.is_empty(),
            Some(PyVal::List(l)) => !l.is_empty(),
            _ => false,
        }
    }
}

/// How the process must end when parsing does not simply succeed.
#[derive(Debug, Clone, PartialEq)]
pub enum Exit {
    /// print to stdout, exit 0
    Help(String),
    /// print to stderr, exit with the code
    Error(String, i32),
}

struct ArgError {
    arg: Option<String>,
    msg: String,
}

impl ArgError {
    fn new(a: Option<&Action>, msg: String) -> ArgError {
        ArgError { arg: a.and_then(|a| a.name()), msg }
    }
    fn text(&self) -> String {
        match &self.arg {
            None => self.msg.clone(),
            Some(n) => format!("argument {n}: {}", self.msg),
        }
    }
}

enum Fail {
    Arg(ArgError),
    Exit(Exit),
}

impl From<ArgError> for Fail {
    fn from(e: ArgError) -> Fail {
        Fail::Arg(e)
    }
}

#[derive(Clone)]
struct OptTuple {
    action: Option<usize>,
    option_string: String,
    /// None / Some(false) = '' / Some(true) = '='
    sep: Option<bool>,
    explicit_arg: Option<String>,
}

/// `needle in hay` (python) = `hay.contains(needle)`, for the ~250 short plugin names every run
/// checks: a first-byte scan plus a compare is several times cheaper than setting up std's
/// two-way searcher for each name.
fn contains(hay: &str, needle: &str) -> bool {
    let (h, n) = (hay.as_bytes(), needle.as_bytes());
    let Some((&first, rest)) = n.split_first() else { return true };
    if n.len() > h.len() {
        return false;
    }
    let last_start = h.len() - n.len();
    let mut i = 0;
    while i <= last_start {
        if h[i] == first && &h[i + 1..i + n.len()] == rest {
            return true;
        }
        i += 1;
    }
    false
}

fn looks_negative(s: &str) -> bool {
    // ^-\.?\d
    let mut it = s.chars();
    if it.next() != Some('-') {
        return false;
    }
    let mut c = it.next();
    if c == Some('.') {
        c = it.next();
    }
    c.is_some_and(|c| c.is_ascii_digit() || (!c.is_ascii() && c.is_numeric()))
}

impl Parser {
    pub fn new(prog: &str, description: Option<String>, epilog: Option<String>, add_help: bool) -> Parser {
        let mut p = Parser {
            prog: prog.to_string(),
            description,
            epilog,
            actions: Vec::new(),
            groups: vec![
                Group { title: "positional arguments".into(), description: None, actions: Vec::new() },
                Group { title: "options".into(), description: None, actions: Vec::new() },
            ],
            mutex: Vec::new(),
            defaults: Vec::new(),
            sub_names: Rc::new(Vec::new()),
            sub_factory: None,
        };
        if add_help {
            let mut a = Action::new(&["-h", "--help"], "==SUPPRESS==", Kind::Help).help("show this help message and exit");
            a.default = None;
            p.add(a);
        }
        p
    }

    /// `add_argument` into the default group (every argument here passes an explicit default,
    /// so earlier `set_defaults` values do not apply to it); returns the action index.
    pub fn add(&mut self, a: Action) -> usize {
        let g = if a.option_strings.is_empty() { 0 } else { 1 };
        self.actions.push(a);
        let i = self.actions.len() - 1;
        self.groups[g].actions.push(i);
        i
    }

    pub fn add_to_group(&mut self, group: usize, a: Action) -> usize {
        self.actions.push(a);
        let i = self.actions.len() - 1;
        self.groups[group].actions.push(i);
        i
    }

    pub fn add_group(&mut self, title: &str, description: Option<String>) -> usize {
        self.groups.push(Group { title: title.into(), description, actions: Vec::new() });
        self.groups.len() - 1
    }

    /// `set_defaults(**kwargs)`
    pub fn set_defaults(&mut self, kv: Vec<(String, PyVal)>) {
        for (k, v) in kv {
            for a in self.actions.iter_mut() {
                if a.dest == k.as_str() {
                    a.default = Some(v.clone());
                }
            }
            match self.defaults.iter_mut().find(|(n, _)| *n == k) {
                Some(slot) => slot.1 = v,
                None => self.defaults.push((k, v)),
            }
        }
    }

    fn formatter(&self) -> Formatter {
        Formatter::new(&self.prog)
    }

    pub fn format_help(&self) -> String {
        self.formatter().format_help(self)
    }

    /// `ArgumentParser.format_usage()` (a single trailing newline)
    pub fn format_usage(&self) -> String {
        let u = self.formatter().format_usage(self);
        format!("{}\n", u.trim_matches('\n'))
    }

    /// `ArgumentParser.error`: the full stderr text; exit status 2.
    pub fn error(&self, msg: &str) -> Exit {
        Exit::Error(format!("{}{}: error: {}\n", self.format_usage(), self.prog, msg), 2)
    }

    fn find_option(&self, s: &str) -> Option<usize> {
        self.actions.iter().position(|a| a.option_strings.iter().any(|o| o == s))
    }

    /// option strings in registration order (python dict order)
    fn option_strings(&self) -> impl Iterator<Item = (&str, usize)> {
        self.actions.iter().enumerate().flat_map(|(i, a)| a.option_strings.iter().map(move |o| (o.as_str(), i)))
    }

    fn has_negative_number_optionals(&self) -> bool {
        self.option_strings().any(|(o, _)| looks_negative(o))
    }

    /// `parse_args`
    pub fn parse_args(&self, args: &[String]) -> Result<Namespace, Exit> {
        let (ns, extras) = self.parse_known_args(args)?;
        if !extras.is_empty() {
            return Err(self.error(&format!("unrecognized arguments: {}", extras.join(" "))));
        }
        Ok(ns)
    }

    /// `parse_known_args`
    pub fn parse_known_args(&self, args: &[String]) -> Result<(Namespace, Vec<String>), Exit> {
        let mut ns = Namespace::default();
        for a in &self.actions {
            if a.dest != "==SUPPRESS==" && !ns.has(a.dest)
                && let Some(d) = &a.default {
                    ns.set(a.dest, d.clone());
                }
        }
        for (k, v) in &self.defaults {
            if !ns.has(k) {
                ns.set(k.clone(), v.clone());
            }
        }
        match self.parse_inner(args, &mut ns) {
            Ok(mut extras) => {
                extras.append(&mut ns.unrecognized);
                Ok((ns, extras))
            }
            Err(Fail::Arg(e)) => Err(self.error(&e.text())),
            Err(Fail::Exit(x)) => Err(x),
        }
    }

    /// `_parse_optional`
    fn parse_optional(&self, arg: &str) -> Option<Vec<OptTuple>> {
        if arg.is_empty() || !arg.starts_with('-') {
            return None;
        }
        if let Some(i) = self.find_option(arg) {
            return Some(vec![OptTuple { action: Some(i), option_string: arg.into(), sep: None, explicit_arg: None }]);
        }
        if arg.chars().count() == 1 {
            return None;
        }
        if let Some((opt, explicit)) = arg.split_once('=')
            && let Some(i) = self.find_option(opt) {
                return Some(vec![OptTuple {
                    action: Some(i),
                    option_string: opt.into(),
                    sep: Some(true),
                    explicit_arg: Some(explicit.into()),
                }]);
            }
        let tuples = self.get_option_tuples(arg);
        if !tuples.is_empty() {
            return Some(tuples);
        }
        if looks_negative(arg) && !self.has_negative_number_optionals() {
            return None;
        }
        if arg.contains(' ') {
            return None;
        }
        Some(vec![OptTuple { action: None, option_string: arg.into(), sep: None, explicit_arg: None }])
    }

    /// `_get_option_tuples` (allow_abbrev=True)
    fn get_option_tuples(&self, s: &str) -> Vec<OptTuple> {
        let mut result = Vec::new();
        let second = s.chars().nth(1);
        let (prefix, sep, explicit) = match s.split_once('=') {
            Some((p, e)) => (p, Some(true), Some(e.to_string())),
            None => (s, None, None),
        };
        if second == Some('-') {
            for (o, i) in self.option_strings() {
                if o.starts_with(prefix) {
                    result.push(OptTuple { action: Some(i), option_string: o.into(), sep, explicit_arg: explicit.clone() });
                }
            }
        } else {
            let cut = s.char_indices().nth(2).map(|(i, _)| i).unwrap_or(s.len());
            let short_prefix = &s[..cut];
            let short_explicit = &s[cut..];
            for (o, i) in self.option_strings() {
                if o == short_prefix {
                    result.push(OptTuple {
                        action: Some(i),
                        option_string: o.into(),
                        sep: Some(false),
                        explicit_arg: Some(short_explicit.into()),
                    });
                } else if o.starts_with(prefix) {
                    result.push(OptTuple { action: Some(i), option_string: o.into(), sep, explicit_arg: explicit.clone() });
                }
            }
        }
        result
    }

    /// `HelpfulArgParser._match_argument`: how many of the following strings (pattern chars
    /// 'A' argument / 'O' option / '-' for "--") an optional consumes (argparse's
    /// `([A])`, `(A?)`, `(A*)`, `(A+)`, `(A[AO]*)`, `()` patterns).
    fn match_argument(&self, a: &Action, pattern: &str) -> Result<usize, ArgError> {
        let p = pattern.as_bytes();
        let leading_a = p.iter().take_while(|&&c| c == b'A').count();
        let n = match a.nargs {
            Nargs::Single if leading_a >= 1 => Some(1),
            Nargs::Single => None,
            Nargs::Optional => Some(leading_a.min(1)),
            Nargs::ZeroOrMore => Some(leading_a),
            Nargs::OneOrMore if leading_a >= 1 => Some(leading_a),
            Nargs::OneOrMore => None,
            Nargs::Parser if leading_a >= 1 => Some(1 + p[1..].iter().take_while(|&&c| c != b'-').count()),
            Nargs::Parser => None,
            Nargs::Zero => Some(0),
        };
        n.ok_or_else(|| {
            let mut msg = match a.nargs {
                Nargs::Single => "expected one argument".to_string(),
                Nargs::Optional => "expected at most one argument".to_string(),
                Nargs::OneOrMore => "expected at least one argument".to_string(),
                _ => "expected 1 argument".to_string(),
            };
            if let Some(c) = &a.choices {
                msg = format!("{msg} (from: {})", c.join(", "));
            }
            ArgError::new(Some(a), msg)
        })
    }

    /// `_match_arguments_partial`: argparse matches the concatenated positional patterns
    /// (`(-*A-*)`, `(-*A?-*)`, `(-*[A-]*)`, `(-*A[A-]*)`, `(-*A[-AO]*)`) with `re.match`;
    /// each is a sequence of greedy single-class repeats, matched here by the same backtracking.
    fn match_arguments_partial(&self, positionals: &[usize], pattern: &str) -> Vec<usize> {
        const DASH: u8 = 1;
        const A: u8 = 2;
        const O: u8 = 4;
        const INF: usize = usize::MAX;
        // (class mask, min, max, group)
        let mut pieces: Vec<(u8, usize, usize, usize)> = Vec::with_capacity(3 * positionals.len());
        let s = pattern.as_bytes();
        for i in (1..=positionals.len()).rev() {
            pieces.clear();
            for (g, &k) in positionals[..i].iter().enumerate() {
                pieces.push((DASH, 0, INF, g));
                match self.actions[k].nargs {
                    Nargs::Single => pieces.extend([(A, 1, 1, g), (DASH, 0, INF, g)]),
                    Nargs::Optional => pieces.extend([(A, 0, 1, g), (DASH, 0, INF, g)]),
                    Nargs::ZeroOrMore => pieces.push((A | DASH, 0, INF, g)),
                    Nargs::OneOrMore => pieces.extend([(A, 1, 1, g), (A | DASH, 0, INF, g)]),
                    Nargs::Parser => pieces.extend([(A, 1, 1, g), (A | DASH | O, 0, INF, g)]),
                    Nargs::Zero => {}
                }
            }
            fn class(c: u8) -> u8 {
                match c {
                    b'A' => 2,
                    b'O' => 4,
                    _ => 1,
                }
            }
            fn m(pieces: &[(u8, usize, usize, usize)], k: usize, pos: usize, s: &[u8], ends: &mut [usize]) -> bool {
                if k == pieces.len() {
                    return true;
                }
                let (mask, min, max, _) = pieces[k];
                let mut run = 0;
                while pos + run < s.len() && run < max && class(s[pos + run]) & mask != 0 {
                    run += 1;
                }
                if run < min {
                    return false;
                }
                for take in (min..=run).rev() {
                    if m(pieces, k + 1, pos + take, s, ends) {
                        ends[k] = pos + take;
                        return true;
                    }
                }
                false
            }
            let mut ends = vec![0usize; pieces.len()];
            if m(&pieces, 0, 0, s, &mut ends) {
                let mut result = vec![0usize; i];
                let mut start = 0;
                for (k, p) in pieces.iter().enumerate() {
                    if k + 1 == pieces.len() || pieces[k + 1].3 != p.3 {
                        result[p.3] = ends[k] - start;
                        start = ends[k];
                    }
                }
                let end = ends.last().copied().unwrap_or(0);
                if end < s.len() && s[end] == b'O' {
                    while result.last() == Some(&0) {
                        result.pop();
                    }
                }
                return result;
            }
        }
        Vec::new()
    }

    /// `_get_value`
    fn get_value(&self, a: &Action, s: &str) -> Result<PyVal, ArgError> {
        match a.conv {
            Conv::Str => Ok(PyVal::Str(s.to_string())),
            Conv::Int0 => parse_int0(s)
                .map(PyVal::Int)
                .ok_or_else(|| ArgError::new(Some(a), format!("invalid <lambda> value: {}", str_repr(s)))),
            Conv::Bytes => Err(ArgError::new(Some(a), format!("invalid bytes value: {}", str_repr(s)))),
        }
    }

    /// `_check_value` (skipped for the subparser action, like HelpfulArgParser)
    fn check_value(&self, a: &Action, v: &PyVal) -> Result<(), ArgError> {
        if a.kind == Kind::Parsers {
            return Ok(());
        }
        if let Some(choices) = &a.choices {
            let sv = v.py_str();
            if !choices.contains(&sv) {
                let list: Vec<String> = choices.iter().map(|c| str_repr(c)).collect();
                return Err(ArgError::new(
                    Some(a),
                    format!("invalid choice: {} (choose from {})", str_repr(&sv), list.join(", ")),
                ));
            }
        }
        Ok(())
    }

    /// `_get_values`
    fn get_values(&self, a: &Action, args: &[String]) -> Result<PyVal, ArgError> {
        if args.is_empty() && a.nargs == Nargs::Optional {
            let v = if !a.option_strings.is_empty() { a.const_.clone() } else { a.default.clone().unwrap_or(PyVal::None) };
            if let PyVal::Str(s) = &v {
                return self.get_value(a, s);
            }
            return Ok(v);
        }
        if args.is_empty() && a.nargs == Nargs::ZeroOrMore && a.option_strings.is_empty() {
            return Ok(match &a.default {
                Some(d) if *d != PyVal::None => d.clone(),
                _ => PyVal::List(Vec::new()),
            });
        }
        if args.len() == 1 && matches!(a.nargs, Nargs::Single | Nargs::Optional) {
            let v = self.get_value(a, &args[0])?;
            self.check_value(a, &v)?;
            return Ok(v);
        }
        if a.nargs == Nargs::Parser {
            let vals: Vec<PyVal> = args.iter().map(|s| PyVal::Str(s.clone())).collect();
            return Ok(PyVal::List(vals));
        }
        let mut vals = Vec::with_capacity(args.len());
        for s in args {
            vals.push(self.get_value(a, s)?);
        }
        for v in &vals {
            self.check_value(a, v)?;
        }
        Ok(PyVal::List(vals))
    }

    /// Invoke an action (`Action.__call__`).
    fn call_action(&self, ai: usize, values: PyVal, ns: &mut Namespace) -> Result<(), Fail> {
        let a = &self.actions[ai];
        match a.kind {
            Kind::Help => Err(Fail::Exit(Exit::Help(self.format_help()))),
            Kind::Store => {
                ns.set(a.dest, values);
                Ok(())
            }
            Kind::StoreTrue => {
                ns.set(a.dest, PyVal::Bool(true));
                Ok(())
            }
            Kind::Count => {
                let n = match ns.get(a.dest) {
                    Some(PyVal::Int(i)) => *i,
                    Some(PyVal::Bool(b)) => *b as i128,
                    _ => 0,
                };
                ns.set(a.dest, PyVal::Int(n + 1));
                Ok(())
            }
            Kind::Append | Kind::Extend => {
                let mut items = match ns.get(a.dest) {
                    Some(PyVal::List(l)) => l.clone(),
                    _ => Vec::new(),
                };
                if a.kind == Kind::Append {
                    items.push(values);
                } else if let PyVal::List(v) = values {
                    items.extend(v);
                }
                ns.set(a.dest, PyVal::List(items));
                Ok(())
            }
            Kind::Parsers => self.call_subparser(a, values, ns),
        }
    }

    /// `HelpfulSubparserAction.__call__`
    fn call_subparser(&self, a: &Action, values: PyVal, ns: &mut Namespace) -> Result<(), Fail> {
        let values = match values {
            PyVal::List(v) => v,
            _ => Vec::new(),
        };
        let mut it = values.into_iter().map(|v| v.py_str());
        let parser_name = it.next().unwrap_or_default();
        let arg_strings: Vec<String> = it.collect();
        ns.set(a.dest, PyVal::Str(parser_name.clone()));
        // `sub_names` may be in registration order (the CLI skips sorting the plugin list, it
        // costs more than the whole argument parsing): python's order, sorted, only matters
        // for the messages
        let mut matched: Vec<&str> = self.sub_names.iter().copied().filter(|n| contains(n, &parser_name)).collect();
        matched.sort_unstable();
        if matched.is_empty() {
            let mut names: Vec<&str> = self.sub_names.to_vec();
            names.sort_unstable();
            return Err(Fail::Arg(ArgError::new(
                Some(a),
                format!("invalid choice {parser_name} (choose from {})", names.join(", ")),
            )));
        }
        if matched.len() > 1 {
            return Err(Fail::Arg(ArgError::new(
                Some(a),
                format!("plugin {parser_name} matches multiple plugins ({})", matched.join(", ")),
            )));
        }
        let name = matched[0].to_string();
        ns.set("plugin", PyVal::Str(name.clone()));
        let factory = self.sub_factory.as_ref().expect("subparser factory");
        let sub = factory(&name);
        let (subns, rest) = sub.parse_known_args(&arg_strings).map_err(Fail::Exit)?;
        for (k, v) in subns.vals {
            ns.set(k, v);
        }
        ns.unrecognized.extend(rest);
        Ok(())
    }

    /// `_parse_known_args` (intermixed=False)
    fn parse_inner(&self, args: &[String], ns: &mut Namespace) -> Result<Vec<String>, Fail> {
        // mutually exclusive conflicts
        let conflicts = |ai: usize| -> Vec<usize> {
            let mut v = Vec::new();
            for g in &self.mutex {
                if g.contains(&ai) {
                    v.extend(g.iter().copied().filter(|&x| x != ai));
                }
            }
            v
        };
        // classify
        let n = args.len();
        let mut option_indices: Vec<Option<Vec<OptTuple>>> = vec![None; n];
        let mut pattern = String::with_capacity(n);
        let mut k = 0;
        while k < n {
            if args[k] == "--" {
                pattern.push('-');
                for _ in k + 1..n {
                    pattern.push('A');
                }
                break;
            }
            match self.parse_optional(&args[k]) {
                None => pattern.push('A'),
                Some(t) => {
                    option_indices[k] = Some(t);
                    pattern.push('O');
                }
            }
            k += 1;
        }
        let pat = pattern.as_bytes();

        let mut seen: Vec<bool> = vec![false; self.actions.len()];
        let mut seen_non_default: Vec<bool> = vec![false; self.actions.len()];
        let mut extras: Vec<String> = Vec::new();

        let mut take_action =
            |this: &Parser, ns: &mut Namespace, ai: usize, argv: &[String], has_opt: bool| -> Result<(), Fail> {
                seen[ai] = true;
                let values = this.get_values(&this.actions[ai], argv)?;
                if has_opt || !argv.is_empty() {
                    seen_non_default[ai] = true;
                    for c in conflicts(ai) {
                        if seen_non_default[c] {
                            return Err(Fail::Arg(ArgError::new(
                                Some(&this.actions[ai]),
                                format!("not allowed with argument {}", this.actions[c].name().unwrap_or_default()),
                            )));
                        }
                    }
                }
                this.call_action(ai, values, ns)
            };

        let mut positionals: Vec<usize> =
            (0..self.actions.len()).filter(|&i| self.actions[i].option_strings.is_empty()).collect();

        let max_option_index: isize = option_indices.iter().rposition(|o| o.is_some()).map(|i| i as isize).unwrap_or(-1);
        let mut start: usize = 0;

        macro_rules! consume_positionals {
            ($start:expr) => {{
                let mut st: usize = $start;
                let counts = self.match_arguments_partial(&positionals, &pattern[st..]);
                for (idx, &count) in counts.iter().enumerate() {
                    let ai = positionals[idx];
                    let mut argv: Vec<String> = args[st..st + count].to_vec();
                    let a = &self.actions[ai];
                    if a.nargs == Nargs::Parser {
                        if pat.get(st) == Some(&b'-') {
                            if let Some(p) = argv.iter().position(|x| x == "--") {
                                argv.remove(p);
                            }
                        }
                    } else if pattern[st..st + count].contains('-') {
                        if let Some(p) = argv.iter().position(|x| x == "--") {
                            argv.remove(p);
                        }
                    }
                    st += count;
                    take_action(self, ns, ai, &argv, false)?;
                }
                positionals.drain(..counts.len());
                st
            }};
        }

        while (start as isize) <= max_option_index {
            let mut next_opt = start;
            while (next_opt as isize) <= max_option_index && option_indices[next_opt].is_none() {
                next_opt += 1;
            }
            if start != next_opt {
                let end = consume_positionals!(start);
                if end > start {
                    start = end;
                    continue;
                }
                start = end;
            }
            if option_indices.get(start).is_none_or(|o| o.is_none()) {
                extras.extend(args[start..next_opt].iter().cloned());
                start = next_opt;
            }
            // consume_optional
            let tuples = option_indices[start].clone().unwrap();
            if tuples.len() > 1 {
                let opts: Vec<&str> = tuples.iter().map(|t| t.option_string.as_str()).collect();
                return Err(Fail::Arg(ArgError::new(
                    None,
                    format!("ambiguous option: {} could match {}", args[start], opts.join(", ")),
                )));
            }
            let OptTuple { mut action, mut option_string, mut sep, mut explicit_arg } = tuples[0].clone();
            let mut action_tuples: Vec<(usize, Vec<String>)> = Vec::new();
            let mut stop = start + 1;
            loop {
                let ai = match action {
                    None => {
                        extras.push(args[start].clone());
                        break;
                    }
                    Some(ai) => ai,
                };
                let a = &self.actions[ai];
                if let Some(ea) = explicit_arg.clone() {
                    let arg_count = self.match_argument(a, "A")?;
                    let second_is_prefix = option_string.chars().nth(1) == Some('-');
                    if arg_count == 0 && !second_is_prefix && !ea.is_empty() {
                        if sep == Some(true) || ea.starts_with('-') {
                            return Err(Fail::Arg(ArgError::new(
                                Some(a),
                                format!("ignored explicit argument {}", str_repr(&ea)),
                            )));
                        }
                        action_tuples.push((ai, Vec::new()));
                        let first: char = ea.chars().next().unwrap();
                        let char0 = option_string.chars().next().unwrap();
                        let new_opt: String = [char0, first].iter().collect();
                        let rest_ea: String = ea.chars().skip(1).collect();
                        match self.find_option(&new_opt) {
                            Some(ni) => {
                                action = Some(ni);
                                option_string = new_opt;
                                if rest_ea.is_empty() {
                                    sep = None;
                                    explicit_arg = None;
                                } else if let Some(r) = rest_ea.strip_prefix('=') {
                                    sep = Some(true);
                                    explicit_arg = Some(r.to_string());
                                } else {
                                    sep = Some(false);
                                    explicit_arg = Some(rest_ea);
                                }
                            }
                            None => {
                                extras.push(format!("{char0}{ea}"));
                                break;
                            }
                        }
                    } else if arg_count == 1 {
                        action_tuples.push((ai, vec![ea]));
                        break;
                    } else {
                        return Err(Fail::Arg(ArgError::new(
                            Some(a),
                            format!("ignored explicit argument {}", str_repr(&ea)),
                        )));
                    }
                } else {
                    let s2 = start + 1;
                    let arg_count = self.match_argument(a, &pattern[s2.min(n)..])?;
                    action_tuples.push((ai, args[s2..s2 + arg_count].to_vec()));
                    stop = s2 + arg_count;
                    break;
                }
            }
            for (ai, argv) in action_tuples {
                take_action(self, ns, ai, &argv, true)?;
            }
            start = stop;
        }
        let stop_index = consume_positionals!(start);
        extras.extend(args[stop_index.min(n)..].iter().cloned());

        // required actions / string default conversion
        let mut required: Vec<String> = Vec::new();
        for (i, a) in self.actions.iter().enumerate() {
            if seen[i] {
                continue;
            }
            if a.required {
                required.push(a.name().unwrap_or_default());
            } else if let Some(PyVal::Str(d)) = &a.default
                && a.conv != Conv::Str && ns.get(a.dest) == Some(&PyVal::Str(d.clone())) {
                    let v = self.get_value(a, d)?;
                    ns.set(a.dest, v);
                }
        }
        if !required.is_empty() {
            return Err(Fail::Arg(ArgError::new(
                None,
                format!("the following arguments are required: {}", required.join(", ")),
            )));
        }
        Ok(extras)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn contains_matches_str_contains() {
        let hays = ["", "a", "windows.pslist.PsList", "windows.psscan.PsScan", "linux.pslist.PsList", "aaab", "é.x"];
        let needles = ["", "a", "ab", "aab", "pslist", "PsList", "windows.pslist.PsList", "windows.pslist.PsListX", "s.P", "é", "x", "b"];
        for h in hays {
            for n in needles {
                assert_eq!(super::contains(h, n), h.contains(n), "{h:?} {n:?}");
            }
        }
    }
}
