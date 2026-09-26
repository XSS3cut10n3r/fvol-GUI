//! windows.envars.Envars (python `plugins/windows/envars.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! `--silent` is a no-op in python 2.28.2: `_generator` reads `self.config.get("SILENT")` but
//! the requirement is named "silent", so the registry-derived variable list is never built.

use crate::context::Context;
use crate::error::Result;
use crate::objects::Obj;
use crate::objects::util::array_to_string;
use crate::plugins::{Config, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::WinExt;

pub struct Envars;

/// Rows of one process (a trailing Err = python raised there).
fn proc_rows(proc: &Obj) -> Vec<Result<Vec<Value>>> {
    let mut out = Vec::new();
    // python: environment_variables() calls add_process_layer() outside its try block
    if let Err(e) = proc.add_process_layer() {
        return vec![Err(e)];
    }
    let vars = proc.environment_variables();
    if vars.is_empty() {
        return out;
    }
    let r = (|| -> Result<()> {
        let mut fixed: Option<(i128, String, String)> = None;
        for (var, val) in vars {
            // python re-reads these per row; they cannot change between rows
            if fixed.is_none() {
                let pid = proc.m("UniqueProcessId")?.int()?;
                let name = array_to_string(&proc.m("ImageFileName")?, None)?;
                let env = proc.get_peb()?.m("ProcessParameters")?.m("Environment")?;
                fixed = Some((pid, name, format!("{:#x}", env.addr)));
            }
            let (pid, name, block) = fixed.as_ref().unwrap();
            out.push(Ok(vec![Value::Int(*pid), Value::Str(name.clone()), Value::Str(block.clone()), Value::Str(var), Value::Str(val)]));
        }
        Ok(())
    })();
    if let Err(e) = r {
        out.push(Err(e));
    }
    out
}

impl Plugin for Envars {
    fn name(&self) -> &'static str {
        "windows.envars.Envars"
    }
    fn description(&self) -> &'static str {
        "Display process environment variables"
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new("pid", "Filter on specific process IDs", ReqKind::ListInt).optional(),
            Requirement::new("silent", "Suppress common and non-persistent variables", ReqKind::Bool).optional(),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("PID", ColType::Int),
            Column::new("Process", ColType::Str),
            Column::new("Block", ColType::Str),
            Column::new("Variable", ColType::Str),
            Column::new("Value", ColType::Str),
        ])?;
        let k = ctx.windows_kernel()?;
        let pids = cfg.get_ints("pid");
        let filter = super::pslist::pid_filter(&pids);
        let procs = super::pslist::list_processes(k, &filter);
        crate::plugins::emit_par_rows(out, procs, |p| proc_rows(p))
    }
}
