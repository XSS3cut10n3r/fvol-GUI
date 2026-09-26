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
        let s = Settings { no_system_defaults: true, columns: Some(80), color: Some(false), ..Default::default() };
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
