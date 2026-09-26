//! End-to-end differential test: python's real CLI ran bench/scripts/py_plugins/rsvol_test.py
//! for every renderer and failure mode (bench/scripts/cli_run_fixtures.py); the same plugin is
//! recreated here and run through `cli::run`. stdout and the exit status must match.

use super::*;
use crate::renderers::RowSink;
use crate::renderers::text::tests_support::{grid_columns, grid_rows};

struct RenderTest;

impl Plugin for RenderTest {
    fn name(&self) -> &'static str {
        "rsvol_test.RenderTest"
    }
    fn description(&self) -> &'static str {
        "Renders the rsvol fixture grid."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::new("mode", "What to do", ReqKind::Str).optional().default(ConfigValue::Str("ok".into()))]
    }
    fn run(&self, _ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> crate::error::Result<()> {
        let mode = cfg.get_str("mode").unwrap_or("ok");
        if mode == "fail_before" {
            return Err(Error::Layer("test failure".into()));
        }
        let grid = crate::renderers::text::tests_support::fixture("render_grid.json");
        out.begin(grid_columns(&grid))?;
        if mode == "empty" {
            return Ok(());
        }
        for (n, (level, values)) in grid_rows(&grid).into_iter().enumerate() {
            if n == 2 && mode == "fail_after_2" {
                return Err(Error::InvalidAddress { addr: 0x1000 });
            }
            if n == 2 && mode == "symbol_after_2" {
                return Err(Error::symbol("table!sym"));
            }
            out.row(level, values)?;
        }
        Ok(())
    }
}

#[test]
fn python_end_to_end_runs_match() {
    static PLUGIN: RenderTest = RenderTest;
    let plugins: Vec<&'static dyn Plugin> = vec![&PLUGIN];
    let cases = crate::renderers::text::tests_support::fixture("cli_run.json");
    let mut bad = Vec::new();
    for c in cases.as_arr() {
        let mut argv = vec!["vol.py".to_string(), "-q".into(), "-p".into(), "plugins".into()];
        argv.extend(c.get("argv").unwrap().as_arr().iter().map(|a| a.as_str().unwrap().to_string()));
        let want = c.get("out").unwrap().as_str().unwrap();
        let want_code = match c.get("code") {
            Some(Json::Int(i)) => *i as i32,
            _ => panic!(),
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let s = Settings { no_system_defaults: true, columns: Some(80), color: Some(false), interactive: Some(true), ..Default::default() };
        let code = run(&argv, &plugins, &mut out, &mut err, &s);
        let out = String::from_utf8(out).unwrap();
        if out != want || code != want_code {
            bad.push(format!(
                "{:?}\n  code want {want_code} got {code}\n--- want\n{want}--- got\n{out}--- stderr\n{}",
                &argv[4..],
                String::from_utf8_lossy(&err)
            ));
        }
    }
    assert!(bad.is_empty(), "{} of {} end-to-end cases differ:\n{}", bad.len(), cases.as_arr().len(), bad.join("\n==========\n"));
}

#[test]
fn unsatisfied_matches_python() {
    // `vol.py -q windows.pslist.PsList` (no -f) with python volatility3 2.28.2
    struct PsList;
    impl Plugin for PsList {
        fn name(&self) -> &'static str {
            "windows.pslist.PsList"
        }
        fn description(&self) -> &'static str {
            "Lists the processes present in a particular windows memory image."
        }
        fn run(&self, _ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> crate::error::Result<()> {
            out.begin(crate::cols![("PID", Int)])?;
            Err(Error::Unsatisfied("no kernel".into()))
        }
    }
    static P: PsList = PsList;
    let plugins: Vec<&'static dyn Plugin> = vec![&P];
    let argv: Vec<String> = ["vol.py", "-q", "windows.pslist.PsList"].iter().map(|s| s.to_string()).collect();
    let mut out = Vec::new();
    let mut err = Vec::new();
    let s = Settings { no_system_defaults: true, ..Default::default() };
    let code = run(&argv, &plugins, &mut out, &mut err, &s);
    let want = "Volatility 3 Framework 2.28.2\n\nUnsatisfied requirement plugins.PsList.kernel.layer_name: \n\
                Unsatisfied requirement plugins.PsList.kernel.symbol_table_name: \n\n\
                A translation layer requirement was not fulfilled.  Please verify that:\n\
                \tA file was provided to create this layer (by -f, --single-location or by config)\n\
                \tThe file exists and is readable\n\
                \tThe file is a valid memory image and was acquired cleanly\n\n\
                A symbol table requirement was not fulfilled.  Please verify that:\n\
                \tThe associated translation layer requirement was fulfilled\n\
                \tYou have the correct symbol file for the requirement\n\
                \tThe symbol file is under the correct directory or zip file\n\
                \tThe symbol file is named appropriately or contains the correct banner\n\n";
    assert_eq!(String::from_utf8(out).unwrap(), want);
    assert_eq!(code, 1);
    assert_eq!(
        String::from_utf8(err).unwrap(),
        "Unable to validate the plugin requirements: ['plugins.PsList.kernel.layer_name', 'plugins.PsList.kernel.symbol_table_name']\n"
    );
    // a structured error naming only the symbol table
    struct Sym;
    impl Plugin for Sym {
        fn name(&self) -> &'static str {
            "windows.info.Info"
        }
        fn description(&self) -> &'static str {
            ""
        }
        fn run(&self, _ctx: &Context, _cfg: &Config, _out: &mut dyn RowSink) -> crate::error::Result<()> {
            Err(crate::plugins::unsatisfied(&["kernel.symbol_table_name"]))
        }
    }
    static S: Sym = Sym;
    let plugins: Vec<&'static dyn Plugin> = vec![&S];
    let argv: Vec<String> = ["vol.py", "-r", "csv", "windows.info.Info"].iter().map(|s| s.to_string()).collect();
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = run(&argv, &plugins, &mut out, &mut err, &s);
    assert_eq!(code, 1);
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "\nUnsatisfied requirement plugins.Info.kernel.symbol_table_name: \n\n\
         A symbol table requirement was not fulfilled.  Please verify that:\n\
         \tThe associated translation layer requirement was fulfilled\n\
         \tYou have the correct symbol file for the requirement\n\
         \tThe symbol file is under the correct directory or zip file\n\
         \tThe symbol file is named appropriately or contains the correct banner\n\n"
    );
}

/// A plugin panicking with python's exception line (mac.pslist on a garbage start time) ends
/// like python's traceback: `ValueError: ...`, not `RuntimeError: ValueError: ...`.
#[test]
fn python_exception_panic_keeps_its_line() {
    struct Boom;
    impl Plugin for Boom {
        fn name(&self) -> &'static str {
            "mac.pslist.PsList"
        }
        fn description(&self) -> &'static str {
            ""
        }
        fn run(&self, _ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> crate::error::Result<()> {
            out.begin(crate::cols![("PID", Int)])?;
            panic!("ValueError: year must be in 1..9999, not -15438");
        }
    }
    static B: Boom = Boom;
    let plugins: Vec<&'static dyn Plugin> = vec![&B];
    let argv: Vec<String> = ["vol.py", "-q", "mac.pslist.PsList"].iter().map(|s| s.to_string()).collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let s = Settings { no_system_defaults: true, ..Default::default() };
    assert_eq!(run(&argv, &plugins, &mut out, &mut err, &s), 1);
    let err = String::from_utf8(err).unwrap();
    assert_eq!(err.lines().last(), Some("ValueError: year must be in 1..9999, not -15438"), "{err}");
}

/// python 2.28.2 with a `--cache-path` directory that does not exist: SymbolCacheMagic's
/// SqliteCache fails while the automagics are listed, before the banner and before `-h`.
#[test]
fn missing_cache_path_fails_like_python() {
    let plugins: Vec<&'static dyn Plugin> = Vec::new();
    for extra in [&["windows.pslist.PsList"][..], &["-h"][..]] {
        let mut argv: Vec<String> = ["vol.py", "-q", "--cache-path", "/nonexistent/rsvol-cache"].iter().map(|s| s.to_string()).collect();
        argv.extend(extra.iter().map(|s| s.to_string()));
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let s = Settings { no_system_defaults: true, ..Default::default() };
        assert_eq!(run(&argv, &plugins, &mut out, &mut err, &s), 1);
        assert!(out.is_empty());
        let err = String::from_utf8(err).unwrap();
        assert_eq!(
            err.lines().last(),
            Some("FileNotFoundError: [Errno 2] No such file or directory: '/nonexistent/rsvol-cache/identifier.cache'")
        );
    }
}

/// Which error messages python reports as an uncaught traceback (anything but a
/// VolatilityException) and which through `process_exceptions`.
#[test]
fn python_exception_classification() {
    for m in ["RuntimeError: generator raised StopIteration", "yara.SyntaxError: line 1: x", "UnboundLocalError: x", "ValueError"] {
        assert!(python_builtin_exception(&Error::Msg(m.into())).is_some(), "{m}");
    }
    for m in ["VolatilityException: x", "LinuxPageCacheException: x", "SymbolError: x", "index out of bounds: the len is 1", "no kernel"] {
        assert!(python_builtin_exception(&Error::Msg(m.into())).is_none(), "{m}");
    }
}

/// `-c` naming a file that does not exist: python's `open()` error line, not Rust's io::Error
/// text ("... (os error 2)").
#[test]
fn missing_config_file_fails_like_python() {
    let plugins: Vec<&'static dyn Plugin> = vec![&crate::plugins::generic::frameworkinfo::FrameworkInfo];
    let argv: Vec<String> =
        ["vol.py", "-q", "-c", "/nonexistent/rsvol.json", "frameworkinfo.FrameworkInfo"].iter().map(|s| s.to_string()).collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let s = Settings { no_system_defaults: true, ..Default::default() };
    assert_eq!(run(&argv, &plugins, &mut out, &mut err, &s), 1);
    let err = String::from_utf8(err).unwrap();
    assert_eq!(err.lines().last(), Some("FileNotFoundError: [Errno 2] No such file or directory: '/nonexistent/rsvol.json'"));
}

/// `-c` with python's `--save-config` output for an ELF core: the image is the Elf64Layer's
/// `base_layer.location` (rsvol only looked for `memory_layer.location`, and the round trip
/// found no image), never a swap layer's location.
#[test]
fn config_file_finds_the_image_below_a_container_layer() {
    struct Loc;
    impl Plugin for Loc {
        fn name(&self) -> &'static str {
            "linux.pslist.PsList"
        }
        fn description(&self) -> &'static str {
            ""
        }
        fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> crate::error::Result<()> {
            out.begin(crate::cols![("Location", Str)])?;
            out.row(0, vec![crate::renderers::Value::Str(ctx.opts.single_location.clone().unwrap_or_default())])
        }
    }
    static L: Loc = Loc;
    let plugins: Vec<&'static dyn Plugin> = vec![&L];
    let dir = std::env::temp_dir().join(format!("rsvol-e2e-config-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("saved.json");
    std::fs::write(
        &cfg,
        "{\"kernel.layer_name.memory_layer.base_layer.location\": \"file:///images/core.elf\",\n\
         \"kernel.layer_name.memory_layer.class\": \"volatility3.framework.layers.elf.Elf64Layer\",\n\
         \"kernel.layer_name.swap_layers.swap_layers0.location\": \"file:///images/swap.bin\"}",
    )
    .unwrap();
    let argv: Vec<String> =
        ["vol.py", "-q", "-r", "csv", "-c", cfg.to_str().unwrap(), "linux.pslist.PsList"].iter().map(|s| s.to_string()).collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let s = Settings { no_system_defaults: true, ..Default::default() };
    assert_eq!(run(&argv, &plugins, &mut out, &mut err, &s), 0, "{}", String::from_utf8_lossy(&err));
    assert_eq!(String::from_utf8(out).unwrap(), "TreeDepth,Location\n0,file:///images/core.elf\n\n");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn output_files_follow_python_naming() {
    let dir = std::env::temp_dir().join(format!("rsvol-e2e-files-{}", std::process::id()));
    let d = dir.to_str().unwrap().to_string();
    std::fs::create_dir_all(&dir).unwrap();
    let ctx = Context::new(GlobalOptions { output_dir: d.clone(), ..Default::default() }).unwrap();
    let names: Vec<String> = (0..3).map(|_| ctx.create_output_file("pid.4.dmp").unwrap().1).collect();
    assert_eq!(names, ["pid.4.dmp", "pid.4-1.dmp", "pid.4-2.dmp"]);
    std::fs::remove_dir_all(&dir).unwrap();
}
