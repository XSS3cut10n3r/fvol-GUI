//! windows.etwpatch.EtwPatch (python `plugins/windows/etwpatch.py`): first opcode of the ETW
//! functions of ntdll.dll / advapi32.dll in every process (RET / JMP patches).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use super::pe_symbols::{self, FilterModules, WantedSymbols};
use crate::context::Context;
use crate::error::Result;
use crate::layers::LayerExt;
use crate::plugins::{Config, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::WinExt;

pub struct EtwPatch;

/// python `EtwPatch.etw_functions`.
pub fn etw_functions() -> FilterModules {
    vec![
        (
            "ntdll.dll".to_string(),
            WantedSymbols::names(&["EtwEventWrite", "EtwEventWriteFull", "NtTraceEvent", "ZwTraceEvent", "NtTraceControl", "ZwTraceControl", "EtwpEventWriteFull"]),
        ),
        ("advapi32.dll".to_string(), WantedSymbols::names(&["EventWrite", "TraceEvent"])),
    ]
}

impl Plugin for EtwPatch {
    fn name(&self) -> &'static str {
        "windows.etwpatch.EtwPatch"
    }
    fn description(&self) -> &'static str {
        "Identifies ETW (Event Tracing for Windows) patching techniques used by malware to evade detection."
    }
    fn epilog(&self) -> Option<&'static str> {
        Some(
            "This plugin examines the first opcode of key ETW functions in ntdll.dll and advapi32.dll\n    to detect common ETW bypass techniques such as return pointer manipulation (RET) or function\n    redirection (JMP). Attackers often patch these functions to prevent security tools from\n    receiving telemetry about process execution, API calls, and other system events.",
        )
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::new("pid", "Filter on specific process IDs", ReqKind::ListInt).optional()]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("PID", ColType::Int),
            Column::new("Process", ColType::Str),
            Column::new("DLL", ColType::Str),
            Column::new("Function", ColType::Str),
            Column::new("Offset", ColType::Hex),
            Column::new("Opcode", ColType::Str),
        ])?;
        let k = ctx.windows_kernel()?;
        let found = pe_symbols::addresses_for_process_symbols(ctx, k, &etw_functions())?;
        let pids = cfg.get_ints("pid");
        let filter = super::pslist::pid_filter(&pids);
        for p in super::pslist::list_processes(k, &filter) {
            let proc = p?;
            let r = (|| -> Result<(i128, String, crate::objects::LayerRef)> {
                Ok((proc.m("UniqueProcessId")?.int()?, proc.image_file_name()?, proc.add_process_layer()?))
            })();
            let (pid, name, layer) = match r {
                Ok(v) => v,
                Err(e) if e.is_invalid_address() => continue,
                Err(e) => return Err(e),
            };
            for (dll, functions) in &found {
                for (func, addr) in functions {
                    let op = match layer.read_u8(*addr) {
                        Ok(b) => b,
                        Err(e) if e.is_invalid_address() => continue,
                        Err(e) => return Err(e),
                    };
                    let ins = match op {
                        0xC3 => "RET",
                        0xE9 => "JMP",
                        _ => continue,
                    };
                    out.row(0, vec![Value::Int(pid), Value::Str(name.clone()), Value::Str(dll.clone()), Value::Str(func.clone()), Value::Int(*addr as i128), Value::Str(format!("{op:02x} ({ins})"))])?;
                }
            }
        }
        Ok(())
    }
}
