//! The command line: a port of volatility3 `cli/__init__.py` (`CommandLine.run`), derived from
//! Volatility 3 (Volatility Software License 1.0).
//!
//! Flow (mirrors python so stdout, stderr and exit codes line up):
//!   1. base parser, `vol.json` defaults, partial parse of argv (errors exit 2 before the banner)
//!   2. add `-r`, the automagic options and the plugin subparser, partial parse again
//!   3. banner (stdout, or stderr for structured renderers), full parse (`-h` prints help here)
//!   4. `-f`, `-c`, output dir, plugin options, `-e` -> `GlobalOptions` + `plugins::Config`
//!   5. run the plugin into the renderer; map failures to python's messages / exit status.

pub mod argparse;
pub mod complete;
pub mod files;
pub mod filter;
pub mod help;
pub mod json;
pub mod regex;

use crate::context::{Context, GlobalOptions};
use crate::error::Error;
use crate::plugins::{Config, ConfigValue, Plugin, ReqKind, Requirement};
use crate::renderers::text::{self, RenderFailure, RenderOptions};
use argparse::{Action, Conv, Exit, Kind, Nargs, Parser, PyVal};
use json::Json;
use std::io::Write;
use std::rc::Rc;

/// Knobs for tests / embedding; `Settings::default()` is the real CLI.
#[derive(Default, Clone)]
pub struct Settings {
    /// Stop once the arguments are processed and print the parsed namespace as JSON.
    pub dump_args: bool,
    /// Do not read `~/.config/volatility3/vol.json`.
    pub no_system_defaults: bool,
    /// Default cache path (python `constants.CACHE_PATH`).
    pub cache_path: Option<String>,
    /// Working directory used for the `-o` default and relative paths.
    pub cwd: Option<String>,
    /// Terminal width for help formatting (default: `COLUMNS` / the tty / 80).
    pub columns: Option<usize>,
    /// Force colour on / off in help output (default: python's `can_colorize()` rules).
    pub color: Option<bool>,
    /// Flush every rendered row (default: when stdout is a terminal).
    pub interactive: Option<bool>,
}

unsafe extern "C" {
    fn isatty(fd: i32) -> i32;
}

/// stdout without std's line buffering or locking: the renderers hand it large blocks.
struct RawStdout(std::mem::ManuallyDrop<std::fs::File>);

impl RawStdout {
    fn new() -> RawStdout {
        use std::os::fd::FromRawFd;
        // fd 1 is owned by the process; ManuallyDrop keeps it open.
        RawStdout(std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(1) }))
    }
}

impl Write for RawStdout {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        (&*self.0).write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Entry point; returns the process exit code.
pub fn main() -> i32 {
    let argv: Vec<String> = std::env::args_os().map(|a| a.to_string_lossy().into_owned()).collect();
    // `vol serve ...`: the built-in web UI; `vol completion` / `vol __complete`: shell tab
    // completion (python volatility has no plugin or option by these names)
    match argv.get(1).map(String::as_str) {
        Some("serve") => return crate::web::main(&argv[2..]),
        Some("completion") => return complete::script(&argv, &mut std::io::stdout(), &mut std::io::stderr()),
        Some("__complete") => {
            return complete::complete(&argv[2..], &crate::plugins::registered(), &mut std::io::stdout());
        }
        _ => {}
    }
    // one run, then exit: big ISFs load lazily, their blobs are written after the output
    crate::symbols::store::set_lazy_tables(true);
    // ... and the address space is torn down after the exit, off the caller's clock
    crate::util::exit::arm();
    // not sorted: only help and error messages show the order, and they sort (see
    // `add_late_arguments`, `Parser::call_subparser`); sorting ~250 names every run costs more
    // than parsing the arguments
    let plugins = crate::plugins::registered();
    let mut out = RawStdout::new();
    let mut err = std::io::stderr();
    run(&argv, &plugins, &mut out, &mut err, &Settings::default())
}

/// Run the CLI with an explicit plugin list and output streams.
pub fn run(
    argv: &[String],
    plugins: &[&'static dyn Plugin],
    out: &mut dyn Write,
    err: &mut dyn Write,
    s: &Settings,
) -> i32 {
    help::set_overrides(s.columns, s.color);
    let code = match run_inner(argv, plugins, out, err, s) {
        Ok(code) => code,
        Err(Exit::Help(t)) => {
            let _ = out.write_all(t.as_bytes());
            0
        }
        Err(Exit::Error(t, code)) => {
            let _ = err.write_all(t.as_bytes());
            code
        }
    };
    let _ = out.flush();
    let _ = err.flush();
    help::set_overrides(None, None);
    code
}

// ------------------------------------------------------------------------------------------
// paths

fn current_dir() -> String {
    std::env::current_dir().map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|_| "/".into())
}

/// python `os.path.normpath` (posix)
pub fn normpath(p: &str) -> String {
    if p.is_empty() {
        return ".".into();
    }
    let initial = if p.starts_with("//") && !p.starts_with("///") {
        2
    } else if p.starts_with('/') {
        1
    } else {
        0
    };
    let mut comps: Vec<&str> = Vec::new();
    for c in p.split('/') {
        if c.is_empty() || c == "." {
            continue;
        }
        if c != ".." || (initial == 0 && comps.is_empty()) || comps.last() == Some(&"..") {
            comps.push(c);
        } else if !comps.is_empty() {
            comps.pop();
        }
    }
    let body = comps.join("/");
    let r = format!("{}{}", "/".repeat(initial), body);
    if r.is_empty() { ".".into() } else { r }
}

/// python `os.path.abspath`
pub fn abspath(p: &str, cwd: &str) -> String {
    if p.starts_with('/') { normpath(p) } else { normpath(&format!("{cwd}/{p}")) }
}

fn quote_path(p: &str) -> String {
    let mut out = String::with_capacity(p.len());
    for &b in p.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'~' | b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn unquote(p: &str) -> String {
    let b = p.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len()
            && let Ok(v) = u8::from_str_radix(&p[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// python `urlparse(url).scheme` (lower-cased), empty when there is none
fn url_scheme(u: &str) -> String {
    if let Some(i) = u.find(':') {
        let s = &u[..i];
        if i > 0
            && s.as_bytes()[0].is_ascii_alphabetic()
            && s.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.'))
        {
            return s.to_ascii_lowercase();
        }
    }
    String::new()
}

/// Local path of a `file:` URL (python `url2pathname(urlparse(u).path)`)
fn file_url_path(u: &str) -> String {
    let rest = &u[u.find(':').map(|i| i + 1).unwrap_or(0)..];
    let rest = match rest.strip_prefix("//") {
        Some(r) => &r[r.find('/').unwrap_or(r.len())..],
        None => rest,
    };
    let end = rest.find(['?', '#']).unwrap_or(rest.len());
    unquote(&rest[..end])
}

fn path_exists(p: &str) -> bool {
    std::path::Path::new(p).exists()
}

/// Where the image lives: (local path if it is a file, URI)
struct Location {
    path: Option<String>,
    url: String,
}

/// `URIRequirement.location_from_file`
fn location_from_file(f: &str, cwd: &str) -> Result<Location, String> {
    let scheme = url_scheme(f);
    if scheme.len() <= 1 {
        let path = abspath(f, cwd);
        if !path_exists(&path) {
            return Err(format!("File does not exist: {path}"));
        }
        let url = format!("file://{}", quote_path(&path));
        return Ok(Location { path: Some(path), url });
    }
    if scheme == "file" {
        let path = file_url_path(f);
        if !path_exists(&path) {
            if path.is_empty() {
                return Err("File URL looks incorrect (potentially missing /)".into());
            }
            return Err(format!("File does not exist: {path}"));
        }
        return Ok(Location { path: Some(path), url: f.to_string() });
    }
    Ok(Location { path: None, url: f.to_string() })
}

/// populate_config's URIRequirement conversion: plain paths must exist and become file URIs.
fn uri_value(v: &str, cwd: &str) -> Result<String, String> {
    let scheme = url_scheme(v);
    if scheme.len() <= 1 {
        if !path_exists(&abspath(v, cwd)) {
            return Err(format!("FileNotFoundError: Non-existent file {v} passed to URIRequirement"));
        }
        return Ok(format!("file://{}", quote_path(&abspath(v, cwd))));
    }
    Ok(v.to_string())
}

/// `$HOME` (python's `os.path.expanduser("~")` falls back to "/" here), looked up once per run.
fn home() -> String {
    std::env::var("HOME").unwrap_or_else(|_| "/".into())
}

fn default_cache_path(home: &str) -> String {
    let base = match std::env::var("XDG_CACHE_HOME") {
        Ok(x) if !x.is_empty() => x,
        _ => format!("{home}/.cache"),
    };
    format!("{base}/volatility3")
}

// ------------------------------------------------------------------------------------------
// value conversions

fn json_to_pyval(j: &Json) -> PyVal {
    match j {
        Json::Null => PyVal::None,
        Json::Bool(b) => PyVal::Bool(*b),
        Json::Int(i) => PyVal::Int(*i),
        Json::Float(_) | Json::Obj(_) => PyVal::Str(j.dump(None)),
        Json::Str(s) => PyVal::Str(s.clone()),
        Json::Arr(v) => PyVal::List(v.iter().map(json_to_pyval).collect()),
    }
}

fn pyval_to_json(v: &PyVal) -> Json {
    match v {
        PyVal::None => Json::Null,
        PyVal::Bool(b) => Json::Bool(*b),
        PyVal::Int(i) => Json::Int(*i),
        PyVal::Str(s) => Json::Str(s.clone()),
        PyVal::List(l) => Json::Arr(l.iter().map(pyval_to_json).collect()),
    }
}

fn json_to_cv(j: &Json) -> Option<ConfigValue> {
    Some(match j {
        Json::Null => return None,
        Json::Bool(b) => ConfigValue::Bool(*b),
        Json::Int(i) => ConfigValue::Int(*i),
        Json::Float(f) => ConfigValue::Int(*f as i128),
        Json::Str(s) => ConfigValue::Str(s.clone()),
        Json::Arr(v) => ConfigValue::List(v.iter().filter_map(json_to_cv).collect()),
        Json::Obj(_) => ConfigValue::Str(j.dump(None)),
    })
}

pub(crate) fn cv_to_json(v: &ConfigValue) -> Json {
    match v {
        ConfigValue::Bool(b) => Json::Bool(*b),
        ConfigValue::Int(i) => Json::Int(*i),
        ConfigValue::Str(s) => Json::Str(s.clone()),
        ConfigValue::Bytes(b) => Json::Str(String::from_utf8_lossy(b).into_owned()),
        ConfigValue::List(l) => Json::Arr(l.iter().map(cv_to_json).collect()),
    }
}

fn cv_to_pyval(v: &ConfigValue) -> PyVal {
    match v {
        ConfigValue::Bool(b) => PyVal::Bool(*b),
        ConfigValue::Int(i) => PyVal::Int(*i),
        ConfigValue::Str(s) => PyVal::Str(s.clone()),
        ConfigValue::Bytes(b) => PyVal::Str(String::from_utf8_lossy(b).into_owned()),
        ConfigValue::List(l) => PyVal::List(l.iter().map(cv_to_pyval).collect()),
    }
}

fn pyval_to_cv(v: &PyVal) -> Option<ConfigValue> {
    Some(match v {
        PyVal::None => return None,
        PyVal::Bool(b) => ConfigValue::Bool(*b),
        PyVal::Int(i) => ConfigValue::Int(*i),
        PyVal::Str(s) => ConfigValue::Str(s.clone()),
        PyVal::List(l) => ConfigValue::List(l.iter().filter_map(pyval_to_cv).collect()),
    })
}

// ------------------------------------------------------------------------------------------
// parser construction

/// Split a python docstring the way the CLI does: (short help, additional help).
fn split_doc(p: &dyn Plugin) -> (Option<String>, Option<String>) {
    let doc = p.description();
    let (first, rest) = match doc.split_once("\n\n") {
        Some((a, b)) => (a.trim(), Some(b.trim())),
        None => (doc.trim(), None),
    };
    let short = if first.is_empty() { None } else { Some(first.to_string()) };
    let extra = p.epilog().map(|e| e.trim()).or(rest).filter(|e| !e.is_empty()).map(|e| e.to_string());
    (short, extra)
}

/// `populate_requirements_argparse` for one requirement.
fn requirement_action(r: &Requirement) -> Action {
    let flag = format!("--{}", r.name.replace('_', "-"));
    let (kind, nargs, conv, choices) = match &r.kind {
        ReqKind::Bool => (Kind::StoreTrue, Nargs::Zero, Conv::Str, None),
        ReqKind::Int => (Kind::Store, Nargs::Single, Conv::Int0, None),
        ReqKind::Str | ReqKind::Uri => (Kind::Store, Nargs::Single, Conv::Str, None),
        ReqKind::Bytes => (Kind::Store, Nargs::Single, Conv::Bytes, None),
        ReqKind::ListInt | ReqKind::ListStr => {
            let conv = if r.kind == ReqKind::ListInt { Conv::Int0 } else { Conv::Str };
            (Kind::Store, if r.optional { Nargs::ZeroOrMore } else { Nargs::OneOrMore }, conv, None)
        }
        ReqKind::Choice(c) => (Kind::Store, Nargs::Single, Conv::Str, Some(c.iter().map(|s| s.to_string()).collect())),
    };
    let mut a = Action::new(&[flag.as_str()], r.name, kind).nargs(nargs).conv(conv).required(!r.optional);
    a.help = Some(std::borrow::Cow::Borrowed(r.description));
    a.default = Some(r.default.as_ref().map(cv_to_pyval).unwrap_or(PyVal::None));
    a.choices = choices;
    a
}

/// The requirements of the LayerStacker and WinSwapLayers automagics that reach the CLI.
fn automagic_requirements() -> Vec<Requirement> {
    vec![
        Requirement::new("single_location", "Specifies a base location on which to stack", ReqKind::Uri).optional(),
        Requirement::new("stackers", "List of stackers", ReqKind::ListStr).optional(),
        Requirement::new(
            "single_swap_locations",
            "Specifies a list of swap layer URIs for use with single-location",
            ReqKind::ListStr,
        )
        .optional(),
    ]
}

fn base_parser(prog: &str, cwd: &str, cache_path: &str) -> Parser {
    let mut p = Parser::new(prog, Some("An open-source memory forensics framework".into()), None, false);
    let mut h = Action::new(&["-h", "--help"], "==SUPPRESS==", Kind::Help).help(format!(
        "Show this help message and exit, for specific plugin options use '{prog} <pluginname> --help'"
    ));
    h.default = None;
    p.add(h);
    p.add(Action::new(&["-c", "--config"], "config", Kind::Store).help("Load the configuration from a json file"));
    p.add(
        Action::new(&["--parallelism"], "parallelism", Kind::Store)
            .help("Enables parallelism (defaults to off if no argument given)")
            .nargs(Nargs::Optional)
            .choices(vec!["processes".into(), "threads".into(), "off".into()])
            .constant(PyVal::Str("processes".into())),
    );
    p.add(
        Action::new(&["-e", "--extend"], "extend", Kind::Append)
            .help("Extend the configuration with a new (or changed) setting"),
    );
    p.add(
        Action::new(&["-p", "--plugin-dirs"], "plugin_dirs", Kind::Store)
            .help("Semi-colon separated list of paths to find plugins")
            .default(PyVal::Str(String::new())),
    );
    p.add(
        Action::new(&["-s", "--symbol-dirs"], "symbol_dirs", Kind::Store)
            .help("Semi-colon separated list of paths to find symbols")
            .default(PyVal::Str(String::new())),
    );
    p.add(Action::new(&["-v", "--verbosity"], "verbosity", Kind::Count).help("Increase output verbosity").default(PyVal::Int(0)));
    p.add(Action::new(&["-l", "--log"], "log", Kind::Store).help("Log output to a file as well as the console"));
    p.add(
        Action::new(&["-o", "--output-dir"], "output_dir", Kind::Store)
            .help("Directory in which to output any generated files")
            .default(PyVal::Str(cwd.to_string())),
    );
    p.add(Action::new(&["-q", "--quiet"], "quiet", Kind::StoreTrue).help("Remove progress feedback"));
    p.add(
        Action::new(&["-f", "--file"], "file", Kind::Store)
            .metavar("FILE")
            .help("Shorthand for --single-location=file:// if single-location is not defined"),
    );
    p.add(
        Action::new(&["--write-config"], "write_config", Kind::StoreTrue)
            .help("Write configuration JSON file out to config.json"),
    );
    p.add(Action::new(&["--save-config"], "save_config", Kind::Store).help("Save configuration JSON file to a file"));
    p.add(Action::new(&["--clear-cache"], "clear_cache", Kind::StoreTrue).help("Clears out all short-term cached items"));
    p.add(
        Action::new(&["--cache-path"], "cache_path", Kind::Store)
            .help(format!("Change the default path ({cache_path}) used to store the cache"))
            .default(PyVal::Str(cache_path.to_string())),
    );
    let off = p.add(
        Action::new(&["--offline"], "offline", Kind::StoreTrue).help("Do not search online for additional JSON files"),
    );
    let url = p.add(
        Action::new(&["-u", "--remote-isf-url"], "remote_isf_url", Kind::Store)
            .metavar("URL")
            .help("Search online for ISF json files"),
    );
    p.mutex.push(vec![off, url]);
    p.add(
        Action::new(&["--filters"], "filters", Kind::Append)
            .help("List of filters to apply to the output (in the form of [+-]columname,pattern[!])")
            .default(PyVal::List(Vec::new())),
    );
    p.add(
        Action::new(&["--hide-columns"], "hide_columns", Kind::Extend)
            .help("Case-insensitive space separated list of prefixes to determine which columns to hide in the output if provided")
            .nargs(Nargs::ZeroOrMore),
    );
    p
}

fn add_late_arguments(p: &mut Parser, prog: &str, plugins: &[&'static dyn Plugin]) {
    let names: Vec<String> = text::RENDERER_NAMES.iter().map(|s| s.to_string()).collect();
    p.add(
        Action::new(&["-r", "--renderer"], "renderer", Kind::Store)
            .metavar("RENDERER")
            .help(format!("Determines how to render the output ({})", names.join(", ")))
            .default(PyVal::Str("quick".into()))
            .choices(names),
    );
    for r in automagic_requirements() {
        p.add(requirement_action(&r));
    }
    let g = p.add_group("Plugins", Some(format!("For plugin specific options, run '{prog} <plugin> --help'")));
    let names: Vec<&'static str> = plugins.iter().map(|pl| pl.name()).collect();
    let mut sub = Action::new(&[], "plugin", Kind::Parsers).metavar("PLUGIN");
    let for_help: Vec<&'static dyn Plugin> = plugins.to_vec();
    sub.sub_choices = Some(Rc::new(move || {
        // `plugins` may be in registration order (see `main`): python lists them sorted
        let mut v: Vec<(String, Option<String>)> =
            for_help.iter().map(|pl| (pl.name().to_string(), split_doc(*pl).0)).collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }));
    p.add_to_group(g, sub);
    p.sub_names = Rc::new(names);
    let plugins: Vec<&'static dyn Plugin> = plugins.to_vec();
    let prog = prog.to_string();
    p.sub_factory = Some(Rc::new(move |name: &str| {
        let plugin = plugins.iter().find(|p| p.name() == name).copied().expect("plugin");
        let (short, extra) = split_doc(plugin);
        let mut sp = Parser::new(&format!("{prog} {name}"), short, extra, true);
        for r in plugin.requirements() {
            sp.add(requirement_action(&r));
        }
        sp
    }));
}

fn load_system_defaults(home: &str) -> Result<Vec<(String, PyVal)>, String> {
    let path = format!("{home}/.config/volatility3/vol.json");
    let text = match std::fs::read(&path) {
        Ok(t) => t,
        Err(_) => return Ok(Vec::new()),
    };
    let j = json::parse(&String::from_utf8_lossy(&text)).map_err(|e| format!("json.decoder.JSONDecodeError: {}", e.0))?;
    Ok(match j {
        Json::Obj(items) => items.iter().map(|(k, v)| (k.clone(), json_to_pyval(v))).collect(),
        _ => Vec::new(),
    })
}

/// Plugin errors whose message names a python exception that is not a `VolatilityException`
/// (`"AttributeError: ..."`, `"RuntimeError: ..."`, `"yara.SyntaxError: ..."`, ...): the CLI
/// only catches `VolatilityException`s, so python dies with a traceback (see `report_error`).
/// Returns the message.
pub fn python_builtin_exception(e: &Error) -> Option<&str> {
    let m = match e {
        Error::Msg(m) | Error::Symbol(m) => m.as_str(),
        _ => return None,
    };
    let name = m.split_once(':').map_or(m, |(n, _)| n);
    // volatility3.framework.exceptions: VolatilityException and its subclasses
    let volatility = (name.ends_with("Exception") && name != "Exception") || name == "SymbolError" || name == "SymbolSpaceError";
    (is_python_exception_line(m) && !volatility).then_some(m)
}

/// `Name: message` (or a bare `Name`) where `Name` is a python exception class, possibly
/// qualified (`ValueError`, `yara.SyntaxError`, `re.PatternError`, `struct.error`).
fn is_python_exception_line(msg: &str) -> bool {
    let name = msg.split_once(':').map_or(msg, |(n, _)| n);
    let last = name.rsplit('.').next().unwrap_or(name);
    name.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
        && (["Error", "Exception", "Exit", "Interrupt", "Iteration"].iter().any(|s| last.ends_with(s)) || last == "error")
}

/// python's exception line for a failed `open(path)`: the OSError subclass python picks by
/// errno, `[Errno N] strerror: 'path'`.
fn py_oserror(e: &std::io::Error, path: &str) -> String {
    let errno = e.raw_os_error().unwrap_or(0);
    let class = match errno {
        2 => "FileNotFoundError",
        1 | 13 => "PermissionError",
        17 => "FileExistsError",
        20 => "NotADirectoryError",
        21 => "IsADirectoryError",
        _ => "OSError",
    };
    // io::Error displays as "<strerror> (os error N)"
    let text = e.to_string();
    let strerror = text.strip_suffix(&format!(" (os error {errno})")).unwrap_or(&text);
    format!("{class}: [Errno {errno}] {strerror}: '{path}'")
}

fn traceback(err: &mut dyn Write, msg: &str) -> i32 {
    let _ = write!(err, "Traceback (most recent call last):\n  File \"vol\", line 1, in <module>\n{msg}\n");
    1
}

// ------------------------------------------------------------------------------------------
// run

fn run_inner(
    argv: &[String],
    plugins: &[&'static dyn Plugin],
    out: &mut dyn Write,
    err: &mut dyn Write,
    s: &Settings,
) -> Result<i32, Exit> {
    let prog = argv.first().map(|a| a.rsplit('/').next().unwrap_or(a).to_string()).unwrap_or_else(|| "vol".into());
    let cwd = s.cwd.clone().unwrap_or_else(current_dir);
    let home = home();
    let cache_default = s.cache_path.clone().unwrap_or_else(|| default_cache_path(&home));

    let defaults = if s.no_system_defaults {
        Vec::new()
    } else {
        match load_system_defaults(&home) {
            Ok(d) => d,
            Err(e) => return Ok(traceback(err, &e)),
        }
    };

    let mut parser = base_parser(&prog, &cwd, &cache_default);
    parser.set_defaults(defaults);

    // first partial parse: the whole argv (argv[0] included) without -h/--help
    let known: Vec<String> = argv.iter().filter(|a| *a != "-h" && *a != "--help").cloned().collect();
    let (partial, _) = parser.parse_known_args(&known)?;
    if let Some(log) = partial.str("log").filter(|l| !l.is_empty())
        && let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(abspath(log, &cwd)) {
            let _ = writeln!(f, "volatility3.cli INFO     Logging started");
        }
    if partial.str("plugin_dirs").is_some_and(|p| !p.is_empty()) {
        let _ = writeln!(err, "WARNING  rsvol: plugin directories (-p) are not supported, ignoring");
    }
    // python lists the automagics next (before the banner, and before --help): SymbolCacheMagic
    // opens CACHE_PATH/identifier.cache, so with a --cache-path directory that does not exist
    // sqlite3.connect fails and the os.unlink() in its error handler raises
    // (python creates its default cache directory when it is imported)
    if let Some(cp) = partial.str("cache_path").filter(|c| !c.is_empty() && *c != cache_default) {
        let db = if cp.ends_with('/') { format!("{cp}identifier.cache") } else { format!("{cp}/identifier.cache") };
        match std::fs::metadata(abspath(cp, &cwd)) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => return Ok(traceback(err, &format!("NotADirectoryError: [Errno 20] Not a directory: '{db}'"))),
            Err(_) => return Ok(traceback(err, &format!("FileNotFoundError: [Errno 2] No such file or directory: '{db}'"))),
        }
    }

    add_late_arguments(&mut parser, &prog, plugins);

    let rest: Vec<String> = argv.iter().skip(1).cloned().collect();
    let known: Vec<String> = rest.iter().filter(|a| *a != "-h" && *a != "--help").cloned().collect();
    let (partial, _) = parser.parse_known_args(&known)?;
    let renderer_name = partial.str("renderer").unwrap_or("quick").to_string();
    let banner = format!("{}\n", crate::VERSION_BANNER);
    if text::is_structured(&renderer_name) {
        let _ = err.write_all(banner.as_bytes());
    } else {
        let _ = out.write_all(banner.as_bytes());
    }

    let args = parser.parse_args(&rest)?;
    let plugin_name = match args.get("plugin") {
        Some(PyVal::Str(n)) => n.clone(),
        _ => return Err(parser.error(&format!("Please select a plugin to run (see '{prog} --help' for options"))),
    };
    let plugin = match plugins.iter().find(|p| p.name() == plugin_name) {
        Some(p) => *p,
        None => return Err(parser.error(&format!("unknown plugin {plugin_name}"))),
    };
    let class = plugin.name().rsplit('.').next().unwrap_or(plugin.name()).to_string();

    let mut opts = GlobalOptions::default();
    let mut location: Option<Location> = None;
    if let Some(f) = args.str("file").filter(|f| !f.is_empty()) {
        match location_from_file(f, &cwd) {
            Ok(l) => location = Some(l),
            Err(m) => return Err(parser.error(&m)),
        }
    }

    // config file values, then the command line (python splices the file first)
    let mut cfg = Config::default();
    let mut config_location: Option<String> = None;
    let mut config_swaps: Vec<String> = Vec::new();
    let mut config_layer_built = false;
    if let Some(c) = args.str("config").filter(|c| !c.is_empty()) {
        let text = match std::fs::read(abspath(c, &cwd)) {
            Ok(t) => t,
            Err(e) => return Ok(traceback(err, &py_oserror(&e, c))),
        };
        let j = match json::parse(&String::from_utf8_lossy(&text)) {
            Ok(j) => j,
            Err(e) => return Ok(traceback(err, &format!("json.decoder.JSONDecodeError: {}", e.0))),
        };
        // HierarchicalDict(json_val): keys are dotted paths, nested dicts are rejected
        let items = match &j {
            Json::Obj(items) => items.clone(),
            _ => return Ok(traceback(err, "AttributeError: object has no attribute 'items'")),
        };
        if items.iter().any(|(_, v)| matches!(v, Json::Obj(_))) {
            return Ok(traceback(err, "TypeError: Invalid type stored in configuration: <class 'dict'>"));
        }
        // a saved configuration (`--save-config`) holds the layer trees the automagics built:
        // rsvol rebuilds them from the image they name (the first file layer below a
        // `memory_layer`, e.g. `kernel.layer_name.memory_layer.base_layer.location`) and its
        // swap files (`...swap_layers.swap_layers<N>.location`)
        let mut swaps: Vec<(u64, String)> = Vec::new();
        let keys: std::collections::HashSet<String> = items.iter().map(|(k, _)| k.clone()).collect();
        for (k, v) in items {
            if !k.contains('.') {
                if let Some(cv) = json_to_cv(&v) {
                    cfg.set(&k, cv);
                }
                continue;
            }
            let (Some(parts), Some(loc)) = (k.strip_suffix(".location").map(|p| p.split('.').collect::<Vec<_>>()), v.as_str()) else { continue };
            match parts.iter().rposition(|c| *c == "swap_layers") {
                Some(i) if i + 2 == parts.len() => {
                    if let Some(n) = parts[i + 1].strip_prefix("swap_layers").and_then(|n| n.parse().ok()) {
                        swaps.push((n, loc.to_string()));
                    }
                }
                Some(_) => {}
                None if config_location.is_none() && parts.contains(&"memory_layer") && !parts.contains(&"meta_layer") => {
                    // a layer the file describes completely (with its class) is built from the
                    // file: python's automagics then leave `-f` / `--single-location` unused
                    config_layer_built = keys.contains(&format!("{}.class", parts.join(".")));
                    config_location = Some(loc.to_string());
                }
                None => {}
            }
        }
        swaps.sort();
        config_swaps = swaps.into_iter().map(|(_, l)| l).collect();
    }

    let output_dir = args.str("output_dir").unwrap_or("").to_string();
    // os.path.exists("") is False
    if output_dir.is_empty() || !path_exists(&abspath(&output_dir, &cwd)) {
        return Err(parser.error(&format!("The output directory specified does not exist: {output_dir}")));
    }

    if s.dump_args {
        let j = Json::Obj(args.vals.iter().map(|(k, v)| (k.to_string(), pyval_to_json(v))).collect());
        let _ = out.write_all(format!("{}\n", j.dump(None)).as_bytes());
        return Ok(0);
    }

    // populate_config: plugin requirements, then the automagic ones
    let reqs = plugin.requirements();
    for r in &reqs {
        let v = match args.get(r.name) {
            Some(PyVal::None) | None => continue,
            Some(v) => v.clone(),
        };
        let v = match (&r.kind, v) {
            (ReqKind::Uri, PyVal::Str(x)) => match uri_value(&x, &cwd) {
                Ok(u) => PyVal::Str(u),
                Err(m) => return Ok(traceback(err, &m)),
            },
            (_, v) => v,
        };
        if let Some(cv) = pyval_to_cv(&v) {
            cfg.set(r.name, cv);
        }
    }
    if let Some(sl) = args.str("single_location") {
        match uri_value(sl, &cwd) {
            Ok(u) => {
                let path = if url_scheme(&u) == "file" { Some(file_url_path(&u)) } else { None };
                location = Some(Location { path, url: u });
            }
            Err(m) => return Ok(traceback(err, &m)),
        }
    }
    let strs = |v: Option<&PyVal>| -> Option<Vec<String>> {
        match v {
            Some(PyVal::List(l)) => Some(l.iter().map(|x| x.py_str()).collect()),
            _ => None,
        }
    };
    opts.stackers = strs(args.get("stackers"));
    opts.swap_locations = strs(args.get("single_swap_locations")).unwrap_or_default();
    // (a layer built from the file has the file's swap layers, as python's WinSwapLayers then
    // finds nothing to do)
    if opts.swap_locations.is_empty() || config_layer_built {
        opts.swap_locations = config_swaps;
    }

    // -e / --extend
    if let Some(PyVal::List(ext)) = args.get("extend") {
        for e in ext {
            let e = e.py_str();
            let Some((address, value)) = e.split_once('=') else {
                return Ok(traceback(
                    err,
                    "ValueError: Invalid extension (extensions must be of the format \"conf.path.value='value'\")",
                ));
            };
            let value = match json::parse(value) {
                Ok(v) => v,
                Err(x) => return Ok(traceback(err, &format!("json.decoder.JSONDecodeError: {}", x.0))),
            };
            let plugin_prefix = format!("plugins.{class}.");
            if let Some(name) = address.strip_prefix(&plugin_prefix) {
                if !name.contains('.') {
                    match json_to_cv(&value) {
                        Some(cv) => cfg.set(name, cv),
                        None => {
                            cfg.values.remove(name);
                        }
                    }
                }
            } else if address == "automagic.LayerStacker.single_location" {
                if let Some(u) = value.as_str() {
                    let path = if url_scheme(u) == "file" { Some(file_url_path(u)) } else { None };
                    location = Some(Location { path, url: u.to_string() });
                }
            } else if address == "automagic.LayerStacker.stackers" {
                opts.stackers = Some(value.as_arr().iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect());
            } else if address == "automagic.WinSwapLayers.single_swap_locations" {
                opts.swap_locations = value.as_arr().iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect();
            }
        }
    }
    // what python's saved configuration records as configured (before rsvol's defaults)
    let user_cfg = cfg.clone();
    // plugin defaults for everything not configured
    for r in &reqs {
        if cfg.get(r.name).is_none()
            && let Some(d) = &r.default {
                cfg.set(r.name, d.clone());
            }
    }

    if (location.is_none() || config_layer_built)
        && let Some(u) = config_location {
            let path = if url_scheme(&u) == "file" { Some(file_url_path(&u)) } else { None };
            location = Some(Location { path, url: u });
        }
    if let Some(l) = location {
        opts.file = l.path;
        opts.single_location = Some(l.url);
    }
    opts.symbol_dirs = match args.str("symbol_dirs") {
        Some(sd) if !sd.is_empty() => sd.split(';').map(|p| abspath(p, &cwd)).collect(),
        _ => Vec::new(),
    };
    opts.cache_path = args.str("cache_path").filter(|c| !c.is_empty()).map(|c| c.to_string());
    opts.offline = args.bool("offline");
    opts.remote_isf_url = args.str("remote_isf_url").map(|u| u.to_string());
    opts.output_dir = output_dir;
    opts.quiet = args.bool("quiet");
    opts.verbosity = match args.get("verbosity") {
        Some(PyVal::Int(i)) => (*i).clamp(0, 255) as u8,
        _ => 0,
    };
    opts.clear_cache = args.bool("clear_cache");

    // --write-config / --save-config
    let mut save = args.str("save_config").map(|x| x.to_string());
    if args.bool("write_config") {
        let _ = writeln!(
            err,
            "WARNING  volatility3.cli: Use of --write-config has been deprecated, replaced by --save-config <filename>"
        );
        save = Some("config.json".into());
    }
    // written once the automagics satisfied the plugin's requirements (python writes it right
    // after `construct_plugin`, before the plugin runs)
    let save = save.filter(|x| !x.is_empty()).map(|sc| SaveConfig {
        target: abspath(&sc, &cwd),
        exists: parser.error(&format!("Cannot write configuration: file {sc} already exists")),
        user: user_cfg,
        name: sc,
    });

    let filters: Vec<String> = match args.get("filters") {
        Some(PyVal::List(l)) => l.iter().map(|x| x.py_str()).collect(),
        _ => Vec::new(),
    };
    let hide_columns = match args.get("hide_columns") {
        Some(PyVal::List(l)) => Some(l.iter().map(|x| x.py_str()).collect()),
        _ => None,
    };
    drop(parser);
    let flush_rows = s.interactive.unwrap_or_else(|| unsafe { isatty(1) == 1 });
    Ok(execute(plugin, &class, opts, &cfg, save, &renderer_name, RenderOptions { filters, hide_columns, flush_rows }, out, err))
}

/// `--save-config` / `--write-config`: where to write, and python's error when the file exists.
struct SaveConfig {
    target: String,
    exists: Exit,
    /// the plugin options as configured (command line, `-c`, `-e`), without rsvol's defaults
    user: Config,
    /// the file name as given (python's `open()` error messages)
    name: String,
}

/// python's `json.dump(dict(constructed.build_configuration()), f, sort_keys=True, indent=2)`
/// plus a newline, after the automagics ran; `Err(status)` when the CLI stops instead.
fn save_config(ctx: &Context, plugin: &dyn Plugin, class: &str, sc: SaveConfig, out: &mut dyn Write, err: &mut dyn Write) -> Result<(), i32> {
    let items = match crate::plugins::generic::pyconfig::plugin_configuration(ctx, plugin.name(), &sc.user, false) {
        Ok(i) => i,
        Err(e) => return Err(report_error(&e, None, class, out, err)),
    };
    if path_exists(&sc.target) {
        let Exit::Error(t, code) = sc.exists else { return Err(2) };
        let _ = err.write_all(t.as_bytes());
        return Err(code);
    }
    if let Err(e) = std::fs::write(&sc.target, format!("{}\n", Json::Obj(items).dump(Some(2)))) {
        return Err(traceback(err, &py_oserror(&e, &sc.name)));
    }
    Ok(())
}

/// Construct the context, run the plugin into the renderer and report failures like python.
#[allow(clippy::too_many_arguments)]
fn execute(
    plugin: &dyn Plugin,
    class: &str,
    opts: GlobalOptions,
    cfg: &Config,
    save: Option<SaveConfig>,
    renderer_name: &str,
    ropts: RenderOptions,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let ctx = match Context::new(opts) {
        Ok(c) => c,
        Err(e) => return report_error(&e, None, class, out, err),
    };
    if let Some(sc) = save
        && let Err(code) = save_config(&ctx, plugin, class, sc, out, err)
    {
        return code;
    }
    let (result, failure) = {
        let mut r = match text::create(renderer_name, out, ropts) {
            Some(r) => r,
            None => return 2,
        };
        // a panicking plugin is python's uncaught exception: what was rendered so far is
        // flushed, a traceback goes to stderr, exit status 1 (no "\n\n" block)
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| plugin.run(&ctx, cfg, &mut *r)));
        let res = match res {
            Ok(res) => res,
            Err(p) => {
                let msg = p
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .or_else(|| p.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "plugin panicked".into());
                let _ = r.abort(false);
                drop(r);
                // plugins panic with python's exception line where python dies with an
                // uncaught exception (mac.pslist's "ValueError: year must be in 1..9999, not
                // -15438", yarascan's "yara.SyntaxError: ..."): reported as is
                let msg = if is_python_exception_line(&msg) { msg } else { format!("RuntimeError: {msg}") };
                return traceback(err, &msg);
            }
        };
        match res {
            Ok(()) => match r.finish() {
                Ok(()) => (Ok(()), None),
                Err(e) => (Err(e), r.failure().cloned()),
            },
            Err(e) => {
                let failure = r.failure().cloned();
                let unsatisfied = matches!(e, Error::Unsatisfied(_)) && failure.is_none();
                let _ = r.abort(unsatisfied);
                (Err(e), failure)
            }
        }
    };
    match result {
        Ok(()) => 0,
        Err(e) => report_error(&e, failure.as_ref(), class, out, err),
    }
}

fn report_error(e: &Error, failure: Option<&RenderFailure>, class: &str, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    if let Error::Io(io) = e
        && io.kind() == std::io::ErrorKind::BrokenPipe {
            return 1;
        }
    if let Some(RenderFailure::Crash(msg)) = failure {
        return traceback(err, msg);
    }
    if let (Error::Unsatisfied(msg), None) = (e, failure) {
        return report_unsatisfied(msg, class, out, err);
    }
    if let Error::Io(io) = e {
        return traceback(err, &format!("OSError: {io}"));
    }
    // a python builtin exception (not a VolatilityException) escapes the CLI as a traceback:
    // no "\n\n" on stdout (same as a plugin panic)
    if let Some(msg) = python_builtin_exception(e) {
        return traceback(err, msg);
    }
    // CommandLine.process_exceptions
    let _ = out.write_all(b"\n\n");
    let _ = out.flush();
    let bug = "Please re-run with -vvv and file a bug with the output at https://github.com/volatilityfoundation/volatility3/issues";
    let (general, detail, causes): (String, String, Vec<String>) = match (e, failure) {
        (_, Some(RenderFailure::NoVisibleColumns)) => (
            "Volatility experienced an issue when rendering the output:".into(),
            "No visible columns to render".into(),
            vec!["An invalid renderer option, such as no visible columns".into()],
        ),
        (Error::InvalidAddress { addr }, _) => (
            "Volatility was unable to read a requested page:".into(),
            format!("Page error {addr:#x} in layer layer_name ({e})"),
            vec![
                "Memory smear during acquisition (try re-acquiring if possible)".into(),
                "An intentionally invalid page lookup (operating system protection)".into(),
                "A bug in the plugin/volatility3 (re-run with -vvv and file a bug)".into(),
            ],
        ),
        (Error::Swapped { addr }, _) => (
            "Volatility was unable to read a requested page:".into(),
            format!("Swap error {addr:#x} in layer layer_name ({e})"),
            vec![
                "No suitable swap file having been provided (locate and provide the correct swap file)".into(),
                "An intentionally invalid page (operating system protection)".into(),
            ],
        ),
        (Error::Symbol(s), _) => (
            "Volatility experienced a symbol-related issue:".into(),
            s.clone(),
            vec![
                "An invalid symbol table".into(),
                "A plugin requesting a bad symbol".into(),
                "A plugin requesting a symbol from the wrong table".into(),
            ],
        ),
        (Error::Layer(s), _) => (
            "Volatility experienced a layer-related issue: layer_name".into(),
            s.clone(),
            vec![format!("A faulty layer implementation. {bug}")],
        ),
        _ => ("Volatility encountered an unexpected situation.".into(), String::new(), vec![bug.into()]),
    };
    let mut t = format!("{general}\n{detail}\n\n");
    for c in causes {
        t.push_str(&format!("\t* {c}\n"));
    }
    t.push_str("\nNo further results will be produced\n");
    let _ = err.write_all(t.as_bytes());
    1
}

/// `CommandLine.process_unsatisfied_exceptions` + the exit message.
fn report_unsatisfied(msg: &str, class: &str, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let is_path = |l: &str| !l.is_empty() && !l.contains(char::is_whitespace);
    // `plugins::unsatisfied_described` lines: "path\tkind\tdescription"
    let described = |l: &str| -> Option<(String, &'static str, String)> {
        let mut it = l.splitn(3, '\t');
        let (p, k, d) = (it.next()?, it.next()?, it.next()?);
        let k = match k {
            "layer" => "layer",
            "symbols" => "symbols",
            "other" => "other",
            _ => return None,
        };
        is_path(p).then(|| (p.to_string(), k, d.to_string()))
    };
    let lines: Vec<&str> = msg.lines().collect();
    let reqs: Vec<(String, &'static str, String)> = if !lines.is_empty() && lines.iter().all(|l| is_path(l) || described(l).is_some()) {
        lines
            .iter()
            .map(|l| match described(l) {
                Some(r) => r,
                None => {
                    let kind = if l.ends_with("layer_name") {
                        "layer"
                    } else if l.ends_with("symbol_table_name") {
                        "symbols"
                    } else {
                        "other"
                    };
                    (l.to_string(), kind, String::new())
                }
            })
            .collect()
    } else {
        vec![("kernel.layer_name".into(), "layer", String::new()), ("kernel.symbol_table_name".into(), "symbols", String::new())]
    };
    let paths: Vec<String> = reqs.iter().map(|r| format!("plugins.{class}.{}", r.0)).collect();
    let mut t = String::from("\n");
    for (p, r) in paths.iter().zip(&reqs) {
        t.push_str(&format!("Unsatisfied requirement {p}: {}\n", r.2));
    }
    if reqs.iter().any(|r| r.1 == "layer") {
        t.push_str(
            "\nA translation layer requirement was not fulfilled.  Please verify that:\n\
             \tA file was provided to create this layer (by -f, --single-location or by config)\n\
             \tThe file exists and is readable\n\
             \tThe file is a valid memory image and was acquired cleanly\n",
        );
    }
    if reqs.iter().any(|r| r.1 == "symbols") {
        t.push_str(
            "\nA symbol table requirement was not fulfilled.  Please verify that:\n\
             \tThe associated translation layer requirement was fulfilled\n\
             \tYou have the correct symbol file for the requirement\n\
             \tThe symbol file is under the correct directory or zip file\n\
             \tThe symbol file is named appropriately or contains the correct banner\n\n",
        );
    }
    let _ = out.write_all(t.as_bytes());
    let _ = out.flush();
    let list: Vec<String> = paths.iter().map(|p| crate::renderers::pyfmt::str_repr(p)).collect();
    let _ = writeln!(err, "Unable to validate the plugin requirements: [{}]", list.join(", "));
    1
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod e2e_tests;
