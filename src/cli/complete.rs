//! Shell tab completion (not part of volatility3; dispatched before the CLI, like `serve`).
//!
//! `vol completion bash` prints a bash script. Its completion function calls
//! `vol __complete bash LINE`, where LINE is the command line up to the cursor, and gets back a
//! directive line (`words`, `files`, `dirs` or `none`) followed by the candidate words.
//!
//! The candidates come from the parsers the CLI itself runs (`base_parser`, `add_late_arguments`
//! and the plugin subparsers) and from `serve`'s help text, so they follow every option,
//! choice and plugin without a second list to keep in sync.

use super::argparse::{Action, Kind, Nargs, Parser};
use crate::plugins::{Plugin, ReqKind};
use std::io::Write;

/// What the shell completes the current word with.
#[derive(Debug, PartialEq)]
pub enum Reply {
    Words(Vec<String>),
    Files,
    Dirs,
    Nothing,
}

/// Global options whose value is a path (by dest); `-f` / `--single-location` also take
/// `file://` URLs, but a path is what is typed.
const FILE_DESTS: &[&str] = &["config", "log", "save_config", "file", "single_location", "single_swap_locations"];
const DIR_DESTS: &[&str] = &["plugin_dirs", "symbol_dirs", "output_dir", "cache_path"];

/// The words that replace the plugin name as the first argument.
const COMMANDS: &[&str] = &["serve", "completion"];
const SHELLS: &[&str] = &["bash"];

/// `vol completion [bash]`: print the completion script for the shell.
pub fn script(argv: &[String], out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let prog = argv.first().map(|a| a.rsplit('/').next().unwrap_or(a)).filter(|p| !p.is_empty()).unwrap_or("vol");
    match argv.get(2).map(String::as_str) {
        None | Some("bash") if argv.len() <= 3 => {
            let _ = out.write_all(bash_script(prog).as_bytes());
            0
        }
        Some("-h" | "--help") => {
            let _ = out.write_all(usage(prog).as_bytes());
            0
        }
        _ => {
            let _ = writeln!(err, "{}{prog} completion: error: supported shells: {}", usage(prog), SHELLS.join(", "));
            2
        }
    }
}

fn usage(prog: &str) -> String {
    format!(
        "usage: {prog} completion [bash]\n\n\
         Print the bash script that completes plugin names, options and their values on TAB.\n\n\
         Load it in the current shell:   eval \"$({prog} completion bash)\"\n\
         Install it for new shells:      {prog} completion bash > ~/.local/share/bash-completion/completions/{prog}\n"
    )
}

/// `vol __complete SHELL LINE`: print the directive and the candidates for LINE's last word.
pub fn complete(args: &[String], plugins: &[&'static dyn Plugin], out: &mut dyn Write) -> i32 {
    let line = args.get(1).map(String::as_str).unwrap_or("");
    let mut words = split_line(line);
    if !words.is_empty() {
        words.remove(0); // the command itself
    }
    let cur = words.pop().unwrap_or_default();
    let mut s = String::new();
    match candidates(&words, &cur, plugins) {
        Reply::Words(mut w) => {
            w.sort_unstable();
            w.dedup();
            s.push_str("words\n");
            for x in w {
                s.push_str(&x);
                s.push('\n');
            }
        }
        Reply::Files => s.push_str("files\n"),
        Reply::Dirs => s.push_str("dirs\n"),
        Reply::Nothing => s.push_str("none\n"),
    }
    let _ = out.write_all(s.as_bytes());
    0
}

/// Split a shell command line into words the way the shell would pass them (quotes and
/// backslashes removed). The last word is the one under the cursor: empty when the line ends
/// in unquoted whitespace, and possibly inside an unterminated quote.
pub fn split_line(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut cur: Option<String> = None;
    let mut quote: Option<char> = None;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some('"'), '\\') => {
                let w = cur.get_or_insert_with(String::new);
                match chars.next() {
                    Some(n @ ('"' | '\\' | '$' | '`')) => w.push(n),
                    Some(n) => {
                        w.push('\\');
                        w.push(n);
                    }
                    None => w.push('\\'),
                }
            }
            (Some(_), c) => cur.get_or_insert_with(String::new).push(c),
            (None, '\'' | '"') => {
                quote = Some(c);
                cur.get_or_insert_with(String::new);
            }
            (None, '\\') => {
                if let Some(n) = chars.next() {
                    cur.get_or_insert_with(String::new).push(n);
                }
            }
            (None, c) if c.is_whitespace() => {
                if let Some(w) = cur.take() {
                    words.push(w);
                }
            }
            (None, c) => cur.get_or_insert_with(String::new).push(c),
        }
    }
    words.push(cur.unwrap_or_default());
    words
}

/// The parser the words so far are going to: the global one, then the plugin's.
struct Level {
    parser: Parser,
    /// dests whose values are paths / directories
    files: Vec<&'static str>,
    dirs: Vec<&'static str>,
}

fn global_level(plugins: &[&'static dyn Plugin]) -> Level {
    let mut p = super::base_parser("vol", "", "");
    super::add_late_arguments(&mut p, "vol", plugins);
    Level { parser: p, files: FILE_DESTS.to_vec(), dirs: DIR_DESTS.to_vec() }
}

fn plugin_level(global: &Parser, plugin: &dyn Plugin) -> Option<Level> {
    let parser = (global.sub_factory.as_ref()?)(plugin.name());
    let files = plugin.requirements().iter().filter(|r| r.kind == ReqKind::Uri).map(|r| r.name).collect();
    Some(Level { parser, files, dirs: Vec::new() })
}

/// `serve`'s options, read from its help text: `-f, --file FILE` -> (["-f", "--file"], "FILE").
fn serve_level() -> Level {
    let mut p = Parser::new("vol serve", None, None, false);
    for line in crate::web::USAGE.lines() {
        let Some(spec) = line.strip_prefix("  -") else { continue };
        let spec = format!("-{}", spec.split("  ").next().unwrap_or(""));
        let mut names: Vec<&str> = Vec::new();
        let mut metavar = None;
        for part in spec.split(", ") {
            let mut it = part.split(' ');
            names.extend(it.next());
            metavar = it.next().or(metavar);
        }
        let dest: &'static str = match metavar {
            None => "flag",
            Some("FILE") => "file",
            Some("PATH" | "OUTPUT_DIR" | "SYMBOL_DIRS") => "dir",
            Some(_) => "value",
        };
        let kind = if metavar.is_some() { Kind::Store } else { Kind::StoreTrue };
        p.add(Action::new(&names, dest, kind));
    }
    Level { parser: p, files: vec!["file"], dirs: vec!["dir"] }
}

fn takes_value(a: &Action) -> bool {
    a.nargs != Nargs::Zero && !matches!(a.kind, Kind::Help | Kind::StoreTrue | Kind::Count | Kind::Parsers)
}

/// A long option by its exact name or an unambiguous prefix (argparse's `allow_abbrev`).
fn find_long<'p>(p: &'p Parser, name: &str) -> Option<&'p Action> {
    let longs = || p.actions.iter().filter(|a| a.option_strings.iter().any(|o| o.starts_with("--")));
    if let Some(a) = longs().find(|a| a.option_strings.iter().any(|o| o == name)) {
        return Some(a);
    }
    let mut m = longs().filter(|a| a.option_strings.iter().any(|o| o.starts_with(name)));
    match (m.next(), m.next()) {
        (Some(a), None) => Some(a),
        _ => None,
    }
}

fn find_short(p: &Parser, c: char) -> Option<&Action> {
    let mut buf = [0u8; 4];
    let s = format!("-{}", c.encode_utf8(&mut buf));
    p.actions.iter().find(|a| a.option_strings.contains(&s))
}

fn is_negative_number(w: &str) -> bool {
    w.len() > 1 && w[1..].bytes().all(|b| b.is_ascii_digit() || b == b'.')
}

/// The candidates for `cur`, the word under the cursor, after `words`.
pub fn candidates(words: &[String], cur: &str, plugins: &[&'static dyn Plugin]) -> Reply {
    let global = global_level(plugins);
    let mut level_owned: Option<Level> = None;
    // an option waiting for its value(s)
    let mut pending: Option<Action> = None;
    let mut used: Vec<&'static str> = Vec::new();
    let mut in_plugin = false;
    for (i, w) in words.iter().enumerate() {
        let level = level_owned.as_ref().unwrap_or(&global);
        if let Some(a) = pending.take() {
            let is_opt = w.starts_with('-') && w.len() > 1 && !is_negative_number(w);
            match a.nargs {
                Nargs::Single => continue,
                Nargs::Optional if !is_opt => continue,
                Nargs::ZeroOrMore | Nargs::OneOrMore if !is_opt => {
                    pending = Some(a);
                    continue;
                }
                _ => {}
            }
        }
        if i == 0 && COMMANDS.contains(&w.as_str()) {
            return match w.as_str() {
                "completion" if words.len() == 1 => words_from(SHELLS.iter().copied(), cur),
                "completion" => Reply::Nothing,
                _ => {
                    // serve: the same loop over its own options
                    let rest: Vec<String> = words[1..].to_vec();
                    level_candidates(&serve_level(), &rest, cur)
                }
            };
        }
        if let Some(rest) = w.strip_prefix("--").filter(|r| !r.is_empty()) {
            let (name, has_value) = match rest.split_once('=') {
                Some((n, _)) => (n, true),
                None => (rest, false),
            };
            if let Some(a) = find_long(&level.parser, &format!("--{name}")) {
                used.push(a.dest);
                if takes_value(a) && !has_value {
                    pending = Some(a.clone());
                }
            }
            continue;
        }
        if w.starts_with('-') && w.len() > 1 && w != "--" && !is_negative_number(w) {
            for (j, c) in w[1..].char_indices() {
                let Some(a) = find_short(&level.parser, c) else { break };
                used.push(a.dest);
                if takes_value(a) {
                    if j + c.len_utf8() == w.len() - 1 {
                        pending = Some(a.clone());
                    }
                    break;
                }
            }
            continue;
        }
        if w == "--" || in_plugin {
            continue;
        }
        // the plugin name, matched by substring like volatility3's HelpfulSubparserAction
        let mut m = plugins.iter().filter(|p| p.name().contains(w.as_str()));
        let (Some(p), None) = (m.next(), m.next()) else { return Reply::Nothing };
        match plugin_level(&global.parser, *p) {
            Some(l) => level_owned = Some(l),
            None => return Reply::Nothing,
        }
        in_plugin = true;
        used.clear();
    }
    let level = level_owned.as_ref().unwrap_or(&global);
    let is_opt = cur.starts_with('-') && !is_negative_number(cur);
    if let Some(a) = &pending {
        let multi = matches!(a.nargs, Nargs::Optional | Nargs::ZeroOrMore | Nargs::OneOrMore);
        if !(multi && is_opt) {
            return value_reply(level, a, cur);
        }
    }
    if let Some((name, value)) = cur.strip_prefix("--").and_then(|r| r.split_once('=')) {
        return match find_long(&level.parser, &format!("--{name}")) {
            Some(a) if takes_value(a) => value_reply(level, a, value),
            _ => Reply::Nothing,
        };
    }
    if is_opt || (in_plugin && cur.is_empty()) {
        return option_words(&level.parser, &used, cur);
    }
    if in_plugin {
        return Reply::Nothing;
    }
    // the plugin name (and the commands, as the first word)
    let mut out: Vec<String> = plugins.iter().map(|p| p.name()).filter(|n| n.starts_with(cur)).map(String::from).collect();
    if words.is_empty() {
        out.extend(COMMANDS.iter().filter(|c| c.starts_with(cur)).map(|c| c.to_string()));
    }
    if out.is_empty() && !cur.is_empty() {
        out = plugins.iter().map(|p| p.name()).filter(|n| n.contains(cur)).map(String::from).collect();
    }
    Reply::Words(out)
}

/// The options-and-values loop for a level without plugins (`serve`).
fn level_candidates(level: &Level, words: &[String], cur: &str) -> Reply {
    let mut pending: Option<&Action> = None;
    let mut used = Vec::new();
    for w in words {
        if pending.take().is_some() {
            continue;
        }
        let name = w.split_once('=').map_or(w.as_str(), |(n, _)| n);
        let a = if name.starts_with("--") { find_long(&level.parser, name) } else { level.parser.actions.iter().find(|a| a.option_strings.iter().any(|o| o == name)) };
        if let Some(a) = a {
            used.push(a.dest);
            if takes_value(a) && !w.contains('=') {
                pending = Some(a);
            }
        }
    }
    if let Some(a) = pending {
        return value_reply(level, a, cur);
    }
    if let Some((name, value)) = cur.strip_prefix("--").and_then(|r| r.split_once('=')) {
        return match find_long(&level.parser, &format!("--{name}")) {
            Some(a) if takes_value(a) => value_reply(level, a, value),
            _ => Reply::Nothing,
        };
    }
    // repeatable here: every serve option but the flags just take the last value
    option_words(&level.parser, &[], cur)
}

fn value_reply(level: &Level, a: &Action, prefix: &str) -> Reply {
    if let Some(c) = &a.choices {
        return words_from(c.iter().map(String::as_str), prefix);
    }
    if level.files.contains(&a.dest) {
        return Reply::Files;
    }
    if level.dirs.contains(&a.dest) {
        return Reply::Dirs;
    }
    Reply::Nothing
}

fn words_from<'a>(it: impl Iterator<Item = &'a str>, prefix: &str) -> Reply {
    Reply::Words(it.filter(|w| w.starts_with(prefix)).map(String::from).collect())
}

/// The options that can still be given: not the positional plugin choice, and not an option
/// already used unless it accumulates (append / extend / count) or excludes a used one.
fn option_words(p: &Parser, used: &[&str], cur: &str) -> Reply {
    let excluded = |idx: usize| {
        p.mutex.iter().any(|g| g.contains(&idx) && g.iter().any(|&o| o != idx && used.contains(&p.actions[o].dest)))
    };
    let mut out = Vec::new();
    for (idx, a) in p.actions.iter().enumerate() {
        let repeatable = matches!(a.kind, Kind::Append | Kind::Extend | Kind::Count);
        if a.option_strings.is_empty() || (used.contains(&a.dest) && !repeatable) || excluded(idx) {
            continue;
        }
        out.extend(a.option_strings.iter().filter(|o| o.starts_with(cur)).cloned());
    }
    Reply::Words(out)
}

fn bash_script(prog: &str) -> String {
    let func: String = prog.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
    let name = if prog.bytes().all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b)) { prog.to_string() } else { "vol".into() };
    BASH.replace("__FUNC__", &func).replace("__PROG__", &name)
}

const BASH: &str = r#"# bash completion for __PROG__ (plugin names, options and their values).
# Load it in this shell:   eval "$(__PROG__ completion bash)"
# Install it:              __PROG__ completion bash > ~/.local/share/bash-completion/completions/__PROG__
___FUNC___complete() {
    local cmd=${COMP_WORDS[0]} cur=${COMP_WORDS[COMP_CWORD]} out kind IFS=$'\n'
    [[ $cmd == "~/"* ]] && cmd=$HOME/${cmd:2}
    # `--opt=` is the words `--opt` `=` (COMP_WORDBREAKS), but readline completes the empty
    # word after the `=`
    [[ $cur == = ]] && cur=
    out=$(command "$cmd" __complete bash "${COMP_LINE:0:COMP_POINT}" 2>/dev/null) || return
    kind=${out%%$'\n'*}
    case $kind in
    files | dirs)
        if declare -F _filedir >/dev/null; then
            if [[ $kind == dirs ]]; then _filedir -d; else _filedir; fi
        else
            compopt -o filenames 2>/dev/null
            if [[ $kind == dirs ]]; then COMPREPLY=($(compgen -d -- "$cur")); else COMPREPLY=($(compgen -f -- "$cur")); fi
        fi
        ;;
    words)
        [[ $out == *$'\n'* ]] && COMPREPLY=(${out#*$'\n'})
        ;;
    *) COMPREPLY=() ;;
    esac
    return 0
}
complete -F ___FUNC___complete __PROG__
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn w(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    fn cands(line: &str) -> Reply {
        let plugins = crate::plugins::registered();
        let mut words = split_line(line);
        let cur = words.pop().unwrap();
        candidates(&words, &cur, &plugins)
    }

    fn words(line: &str) -> Vec<String> {
        match cands(line) {
            Reply::Words(mut v) => {
                v.sort();
                v
            }
            r => panic!("{line:?}: {r:?}"),
        }
    }

    #[test]
    fn split_line_like_the_shell() {
        assert_eq!(split_line("vol -f a.raw "), w("vol -f a.raw").into_iter().chain([String::new()]).collect::<Vec<_>>());
        assert_eq!(split_line("vol -f 'a b.raw' x"), vec!["vol", "-f", "a b.raw", "x"]);
        assert_eq!(split_line(r#"vol -f "a \"b\"" c\ d"#), vec!["vol", "-f", "a \"b\"", "c d"]);
        assert_eq!(split_line("vol -f '/tmp/unterminated"), vec!["vol", "-f", "/tmp/unterminated"]);
        assert_eq!(split_line(""), vec![""]);
    }

    #[test]
    fn plugin_names() {
        let v = words("windows.psl");
        assert_eq!(v, vec!["windows.pslist.PsList"]);
        // no prefix match: python's substring rule
        let v = words("pslist.PsL");
        assert!(v.contains(&"windows.pslist.PsList".to_string()) && v.contains(&"linux.pslist.PsList".to_string()), "{v:?}");
        // every plugin, plus the commands, as the first word
        let all = words("");
        assert_eq!(all.len(), crate::plugins::registered().len() + COMMANDS.len());
        // after global options
        assert_eq!(words("-f x.raw -q windows.pslist.P"), vec!["windows.pslist.PsList"]);
        // commands only as the first word
        assert!(!words("-q ser").contains(&"serve".to_string()));
        assert_eq!(words("ser"), vec!["serve"]);
    }

    #[test]
    fn option_values() {
        assert_eq!(cands("-f "), Reply::Files);
        assert_eq!(cands("-qf "), Reply::Files);
        assert_eq!(cands("--file=/tm"), Reply::Files);
        assert_eq!(cands("-o "), Reply::Dirs);
        assert_eq!(cands("--symbol-dirs "), Reply::Dirs);
        assert_eq!(cands("--sym "), Reply::Dirs); // abbreviation
        assert_eq!(words("-r js"), vec!["json", "jsonl"]);
        assert_eq!(words("--renderer=js"), vec!["json", "jsonl"]);
        assert_eq!(words("--parallelism "), vec!["off", "processes", "threads"]);
        assert_eq!(cands("-u "), Reply::Nothing);
        // the value was given: back to plugin names
        assert!(words("-f x.raw ").len() > 100);
        assert!(words("-r json ").len() > 100);
    }

    #[test]
    fn global_options() {
        let v = words("--");
        assert!(v.contains(&"--file".to_string()) && v.contains(&"--renderer".to_string()) && v.contains(&"--single-location".to_string()));
        assert!(v.iter().all(|o| o.starts_with("--")));
        assert!(words("-").contains(&"-f".to_string()));
        // used options are not offered again; accumulating ones are
        let v = words("-f x.raw --filters a,b --");
        assert!(!v.contains(&"--file".to_string()) && v.contains(&"--filters".to_string()));
        // mutually exclusive with a used one
        assert!(!words("--offline --").contains(&"--remote-isf-url".to_string()));
    }

    #[test]
    fn plugin_options() {
        let v = words("-f x.raw windows.pslist.PsList ");
        assert_eq!(v, vec!["--dump", "--help", "--physical", "--pid", "-h"]);
        assert_eq!(words("-f x.raw windows.pslist --p"), vec!["--physical", "--pid"]);
        assert_eq!(words("windows.pslist.PsList --pid 4 8 --"), vec!["--dump", "--help", "--physical"]);
        // a list option's values, then an option again
        assert_eq!(cands("windows.pslist.PsList --pid 4 "), Reply::Nothing);
        // URI requirements take paths; choice requirements their choices
        assert_eq!(cands("windows.vadyarascan.VadYaraScan --yara-file "), Reply::Files);
        // an unknown or ambiguous plugin: nothing to offer
        assert_eq!(cands("pslist "), Reply::Nothing);
        assert_eq!(cands("nosuchplugin --"), Reply::Nothing);
    }

    #[test]
    fn serve_and_completion() {
        let v = words("serve --");
        for o in ["--file", "--host", "--port", "--symbol-dirs", "--output-dir", "--offline", "--cache-path", "--max-memory"] {
            assert!(v.contains(&o.to_string()), "{o} in {v:?}");
        }
        assert_eq!(cands("serve -f "), Reply::Files);
        assert_eq!(cands("serve --cache-path="), Reply::Dirs);
        assert_eq!(cands("serve --port "), Reply::Nothing);
        assert_eq!(words("completion "), vec!["bash"]);
    }

    #[test]
    fn protocol_and_script() {
        let plugins = crate::plugins::registered();
        let mut out = Vec::new();
        complete(&["bash".into(), "vol -r jso".into()], &plugins, &mut out);
        assert_eq!(String::from_utf8(out).unwrap(), "words\njson\njsonl\n");
        let mut out = Vec::new();
        complete(&["bash".into(), "vol -f ".into()], &plugins, &mut out);
        assert_eq!(out, b"files\n");
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(script(&["/usr/local/bin/fvol".into(), "completion".into(), "bash".into()], &mut out, &mut err), 0);
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("complete -F _fvol_complete fvol\n") && s.contains("\n_fvol_complete() {"), "{s}");
        assert_eq!(script(&["vol".into(), "completion".into(), "tcsh".into()], &mut Vec::new(), &mut err), 2);
    }
}
