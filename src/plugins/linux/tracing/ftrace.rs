//! linux.tracing.ftrace.CheckFtrace (python `plugins/linux/tracing/ftrace.py`): walk the
//! `ftrace_ops_list` and report the callbacks attached to hooked kernel functions.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::automagic::linux::LinuxKernel;
use crate::context::Context;
use crate::error::Result;
use crate::objects::{Module, Obj};
use crate::plugins::{Config, Plugin, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::linux::modules::{ALL_GATHERERS, ModuleInfo, module_lookup_by_address, run_modules_scanners};

pub struct CheckFtrace;

/// python `FtraceOpsFlags` (definition order = iteration order).
pub const FTRACE_OPS_FLAGS: [(&str, u64); 19] = [
    ("FTRACE_OPS_FL_ENABLED", 1 << 0),
    ("FTRACE_OPS_FL_DYNAMIC", 1 << 1),
    ("FTRACE_OPS_FL_SAVE_REGS", 1 << 2),
    ("FTRACE_OPS_FL_SAVE_REGS_IF_SUPPORTED", 1 << 3),
    ("FTRACE_OPS_FL_RECURSION", 1 << 4),
    ("FTRACE_OPS_FL_STUB", 1 << 5),
    ("FTRACE_OPS_FL_INITIALIZED", 1 << 6),
    ("FTRACE_OPS_FL_DELETED", 1 << 7),
    ("FTRACE_OPS_FL_ADDING", 1 << 8),
    ("FTRACE_OPS_FL_REMOVING", 1 << 9),
    ("FTRACE_OPS_FL_MODIFYING", 1 << 10),
    ("FTRACE_OPS_FL_ALLOC_TRAMP", 1 << 11),
    ("FTRACE_OPS_FL_IPMODIFY", 1 << 12),
    ("FTRACE_OPS_FL_PID", 1 << 13),
    ("FTRACE_OPS_FL_RCU", 1 << 14),
    ("FTRACE_OPS_FL_TRACE_ARRAY", 1 << 15),
    ("FTRACE_OPS_FL_PERMANENT", 1 << 16),
    ("FTRACE_OPS_FL_DIRECT", 1 << 17),
    ("FTRACE_OPS_FL_SUBOP", 1 << 18),
];

/// python `",".join(flag.name for flag in FtraceOpsFlags if flag.value & flags)`.
pub fn format_ftrace_flags(flags: u64) -> String {
    let names: Vec<&str> = FTRACE_OPS_FLAGS.iter().filter(|(_, v)| v & flags != 0).map(|(n, _)| *n).collect();
    names.join(",")
}

/// python `ParsedFtraceOps`.
#[derive(Clone, Debug)]
pub struct ParsedFtraceOps {
    pub ftrace_ops_offset: u64,
    pub callback_symbol: Option<String>,
    pub callback_address: u64,
    pub hooked_symbols: String,
    pub module_name: Option<String>,
    pub module_address: Option<u64>,
    pub flags: String,
}

/// python `CheckFtrace.extract_hash_table_filters(ftrace_ops)`: the `ftrace_func_entry`
/// structs of the ops' filter hash (first bucket, like python). A trailing `Err` = python
/// raised there.
pub fn extract_hash_table_filters(ftrace_ops: &Obj) -> Vec<Result<Obj>> {
    let mut out = Vec::new();
    let head = (|| -> Result<Option<Obj>> {
        let ftrace_hash = if ftrace_ops.has_member("func_hash") {
            // python `hasattr(ftrace_ops, "func_hash")` reads the pointer
            let func_hash = ftrace_ops.m("func_hash")?;
            func_hash.u64()?;
            func_hash.m("filter_hash")?
        } else {
            ftrace_ops.m("filter_hash")?
        };
        ftrace_hash.u64()?;
        let first = ftrace_hash.m("buckets").and_then(|b| b.m("first")).and_then(|f| f.u64().map(|_| f));
        match first {
            Ok(f) => Ok(Some(f)),
            // python: "ftrace_func_entry list of ftrace_ops@... is empty/invalid. Skipping it..."
            Err(e) if e.is_invalid_address() => Ok(None),
            Err(e) => Err(e),
        }
    })();
    let mut cur = match head {
        Ok(Some(f)) => f,
        Ok(None) => return out,
        Err(e) => {
            out.push(Err(e));
            return out;
        }
    };
    while cur.is_readable() {
        match cur.deref().and_then(|n| n.cast("ftrace_func_entry")) {
            Ok(e) => out.push(Ok(e)),
            Err(e) => {
                out.push(Err(e));
                return out;
            }
        }
        match cur.m("next").and_then(|n| n.u64().map(|_| n)) {
            Ok(n) => cur = n,
            Err(e) => {
                out.push(Err(e));
                return out;
            }
        }
    }
    out
}

/// python `CheckFtrace.parse_ftrace_ops(context, kernel, known_modules, ftrace_ops)`: streams
/// each parsed entry to `f`. `Err` = python raised there.
pub fn parse_ftrace_ops(vm: &Module, known_modules: &[ModuleInfo], ftrace_ops: &Obj, f: &mut dyn FnMut(ParsedFtraceOps) -> Result<()>) -> Result<()> {
    let callback = ftrace_ops.m("func")?.u64()?;
    let (mod_info, symbol) = module_lookup_by_address(vm, known_modules, callback)?;
    let (callback_symbol, module_name, module_address) = match mod_info {
        Some(m) => (symbol, Some(m.name), Some(m.start)),
        // python: "Could not determine ftrace_ops@... callback ... module origin."
        None => (None, None, None),
    };
    for entry in extract_hash_table_filters(ftrace_ops) {
        let entry = entry?;
        let hook_address = entry.m("ip")?.cast("pointer")?.u64()?;
        // python `get_symbols_by_absolute_location(hook_address)` (size 0: an exact-address
        // lookup; a linear scan is much cheaper than building the address index for a few
        // hooks)
        let hooked: Vec<&str> = vm.symbols_at_exact(hook_address).into_iter().map(|s| s.rsplit('!').next().unwrap_or(s)).collect();
        let flags = format_ftrace_flags(ftrace_ops.m("flags")?.u64()?);
        f(ParsedFtraceOps {
            ftrace_ops_offset: ftrace_ops.addr,
            callback_symbol: callback_symbol.clone(),
            callback_address: callback,
            hooked_symbols: hooked.join(","),
            module_name: module_name.clone(),
            module_address,
            flags,
        })?;
    }
    Ok(())
}

/// python `CheckFtrace.iterate_ftrace_ops_list(context, kernel)`: streams each `ftrace_ops`
/// to `f` (`ftrace_list_end` terminates the list). `Err` = python raised there.
pub fn iterate_ftrace_ops_list(vm: &Module, f: &mut dyn FnMut(Obj) -> Result<()>) -> Result<()> {
    let mut cur = vm.object_from_symbol("ftrace_ops_list")?;
    cur.u64()?;
    let ftrace_list_end = vm.object_from_symbol("ftrace_list_end")?;
    while cur.is_readable() {
        // ftrace_list_end is not considered a valid struct
        // see kernel function test_rec_ops_needs_regs
        if cur.u64()? == ftrace_list_end.addr {
            break;
        }
        f(cur.deref()?)?;
        cur = cur.m("next")?;
        cur.u64()?;
    }
    Ok(())
}

fn run_rows(k: &LinuxKernel, show_flags: bool, out: &mut dyn RowSink) -> Result<()> {
    if !k.has_symbol("ftrace_ops_list") {
        // python: vollog.error('The provided symbol table does not include the "ftrace_ops_list" symbol. ...')
        return Ok(());
    }
    let known_modules = {
        let _t = crate::util::trace::span("ftrace: run_modules_scanners");
        run_modules_scanners(k, &ALL_GATHERERS)?
    };
    let _t = crate::util::trace::span("ftrace: ftrace_ops walk");
    let s = |v: Option<String>| match v {
        Some(s) if !s.is_empty() => Value::Str(s),
        _ => Value::NotAvailable,
    };
    iterate_ftrace_ops_list(k, &mut |ops| {
        parse_ftrace_ops(k, &known_modules, &ops, &mut |p| {
            let mut row = vec![
                Value::Int(p.ftrace_ops_offset as i128),
                s(p.callback_symbol),
                Value::Int(p.callback_address as i128),
                s(Some(p.hooked_symbols)),
                s(p.module_name),
                p.module_address.map_or(Value::NotAvailable, |a| Value::Int(a as i128)),
            ];
            if show_flags {
                row.push(Value::Str(p.flags));
            }
            out.row(0, row)
        })
    })
}

impl Plugin for CheckFtrace {
    fn name(&self) -> &'static str {
        "linux.tracing.ftrace.CheckFtrace"
    }
    fn description(&self) -> &'static str {
        "Detect ftrace hooking"
    }
    fn epilog(&self) -> Option<&'static str> {
        Some(
            "Investigate the ftrace infrastructure to uncover kernel attached callbacks, which can be leveraged\n    to hook kernel functions and modify their behaviour.",
        )
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::flag("show_ftrace_flags", "Show ftrace flags associated with an ftrace_ops struct")]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let k = ctx.linux_kernel()?;
        let show_flags = cfg.get_bool("show_ftrace_flags");
        let mut cols = vec![
            Column::new("ftrace_ops address", ColType::Hex),
            Column::new("Callback", ColType::Str),
            Column::new("Callback address", ColType::Hex),
            Column::new("Hooked symbols", ColType::Str),
            Column::new("Module", ColType::Str),
            Column::new("Module address", ColType::Hex),
        ];
        if show_flags {
            cols.push(Column::new("Flags", ColType::Str));
        }
        out.begin(cols)?;
        run_rows(k, show_flags, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags() {
        assert_eq!(format_ftrace_flags(0), "");
        assert_eq!(format_ftrace_flags(0b101), "FTRACE_OPS_FL_ENABLED,FTRACE_OPS_FL_SAVE_REGS");
        assert_eq!(format_ftrace_flags(1 << 18 | 1 << 40), "FTRACE_OPS_FL_SUBOP");
    }
}
