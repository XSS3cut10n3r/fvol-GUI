//! linux.tracing.tracepoints.CheckTracepoints (python `plugins/linux/tracing/tracepoints.py`):
//! the probes attached to the kernel's static tracepoints.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::automagic::linux::LinuxKernel;
use crate::context::Context;
use crate::error::{Error, Result};
use crate::objects::util::{array_of_pointers, pointer_to_string};
use crate::objects::{Module, Obj};
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::linux::modules::{ALL_GATHERERS, ModuleInfo, module_lookup_by_address, run_modules_scanners};

pub struct CheckTracepoints;

/// python `ParsedTracepointFunc`.
#[derive(Clone, Debug)]
pub struct ParsedTracepointFunc {
    pub tracepoint_name: String,
    pub tracepoint_address: u64,
    pub probe_name: Option<String>,
    pub probe_address: u64,
    pub probe_priority: Option<i128>,
    pub module_name: Option<String>,
    pub module_address: Option<u64>,
}

/// python `CheckTracepoints.iterate_tracepoint_funcs(context, layer_name, tracepoint)`: the
/// `tracepoint_func` probes of a tracepoint (a `tracepoint` struct, or a pointer to one). A
/// trailing `Err` = python raised there.
pub fn iterate_tracepoint_funcs(tracepoint: &Obj) -> Vec<Result<Obj>> {
    let mut out = Vec::new();
    let funcs = match tracepoint.m("funcs").and_then(|f| f.u64().map(|_| f)) {
        Ok(f) => f,
        Err(e) => return vec![Err(e)],
    };
    // Ignore tracepoints without attached probes
    if !funcs.is_readable() {
        return out;
    }
    let mut cur = match funcs.deref() {
        Ok(c) => c,
        Err(e) => return vec![Err(e)],
    };
    let layer = cur.layer();
    let size = cur.size();
    // Inspired by kernel's debug_print_probes()
    while layer.is_valid(cur.addr, 1) {
        // python constructs (reads) the `func` pointer before `is_readable()`
        match cur.m("func").and_then(|f| f.u64().map(|_| f)) {
            Ok(f) if f.is_readable() => {}
            Ok(_) => break,
            Err(e) => {
                out.push(Err(e));
                break;
            }
        }
        out.push(Ok(cur));
        cur = cur.at_addr(cur.addr.wrapping_add(size));
    }
    out
}

/// python `CheckTracepoints.parse_tracepoint(context, kernel, known_modules, tracepoint)`:
/// streams each parsed probe to `f`. `Err` = python raised there.
pub fn parse_tracepoint(vm: &Module, known_modules: &[ModuleInfo], tracepoint: &Obj, f: &mut dyn FnMut(ParsedTracepointFunc) -> Result<()>) -> Result<()> {
    for tracepoint_func in iterate_tracepoint_funcs(tracepoint) {
        let tracepoint_func = tracepoint_func?;
        let tracepoint_name = match tracepoint.m("name").and_then(|n| pointer_to_string(&n, 512)) {
            Ok(n) => n,
            // python: "Tracepoint function at ... is smeared."
            Err(e) if e.is_invalid_address() => continue,
            Err(e) => return Err(e),
        };
        let probe_handler_address = tracepoint_func.m("func")?.u64()?;
        // Try to lookup within the known modules if the probe_handler address fits
        let (mod_info, probe_handler_symbol) = module_lookup_by_address(vm, known_modules, probe_handler_address)?;
        let (module_name, module_address) = match mod_info {
            Some(m) => (Some(m.name), Some(m.offset)),
            // python: "Could not determine tracepoint@... probe handler ... module origin."
            None => (None, None),
        };
        let prio = if tracepoint_func.has_member("prio") { Some(tracepoint_func.m("prio")?.int()?) } else { None };
        f(ParsedTracepointFunc {
            tracepoint_name,
            tracepoint_address: tracepoint.addr,
            probe_name: probe_handler_symbol,
            probe_address: probe_handler_address,
            probe_priority: prio,
            module_name,
            module_address,
        })?;
    }
    Ok(())
}

/// python `CheckTracepoints.iterate_tracepoints_array(context, kernel)`: the `tracepoint`
/// structs (pointers to them without CONFIG_HAVE_ARCH_PREL32_RELOCATIONS).
pub fn iterate_tracepoints_array(vm: &Module) -> Result<Vec<Obj>> {
    let t = vm.table();
    let start = vm.object_from_symbol("__start___tracepoints_ptrs")?;
    let end = vm.symbol_addr("__stop___tracepoints_ptrs")?;
    let size = end as i128 - start.addr as i128;
    let subtype = match start.elem_ty().or_else(|| start.target_ty()) {
        Some(s) => s,
        None => return Err(Error::msg(format!("AttributeError: {} has no attribute: subtype", start.type_name()))),
    };
    // kernel's tracepoint_ptr_deref() and tracepoint_ptr_t adjust depending on the use of
    // PC-relative addressing or not.
    let int_ty = vm.get_type("int")?;
    let prel32 = t.type_name(subtype) == "int";
    let count = |elem_size: u64| -> Result<u64> {
        if elem_size == 0 {
            return Err(Error::msg("ZeroDivisionError: integer division or modulo by zero"));
        }
        let n = size.div_euclid(elem_size as i128);
        if n < 0 {
            return Err(Error::msg("ValueError: Array count must be non-negative"));
        }
        Ok(n as u64)
    };
    let mut out = Vec::new();
    if prel32 {
        let arr = start.cast_array(count(t.size_of(int_ty))?, int_ty);
        let values = arr.ints()?;
        let elem_size = t.size_of(int_ty);
        for (i, rel) in values.into_iter().enumerate() {
            // offset_to_ptr(): the value is relative to its own address
            let elem_addr = arr.addr.wrapping_add(elem_size.wrapping_mul(i as u64)) & vm.layer().address_mask();
            let absolute = (rel + elem_addr as i128) as u64;
            out.push(vm.object_abs("tracepoint", absolute)?);
        }
    } else {
        let tp = vm.get_type("tracepoint")?;
        let arr = array_of_pointers(&start, count(t.size_of(vm.get_type("pointer")?))?, tp)?;
        out.extend(arr.elements());
    }
    Ok(out)
}

fn run_rows(k: &LinuxKernel, out: &mut dyn RowSink) -> Result<()> {
    if !k.has_symbol("__start___tracepoints_ptrs") {
        // python: vollog.error('The provided symbol table does not include the "__start___tracepoints_ptrs" symbol. ...')
        return Ok(());
    }
    let known_modules = {
        let _t = crate::util::trace::span("tracepoints: run_modules_scanners");
        run_modules_scanners(k, &ALL_GATHERERS)?
    };
    let _t = crate::util::trace::span("tracepoints: tracepoints walk");
    let tracepoints = iterate_tracepoints_array(k)?;
    let kernel_layer = k.vlayer;
    let s = |v: Option<String>| match v {
        Some(s) if !s.is_empty() => Value::Str(s),
        _ => Value::NotAvailable,
    };
    for tracepoint in tracepoints {
        if tracepoint.is_pointer() {
            // python constructs (reads) each array element while iterating
            tracepoint.u64()?;
        }
        if !kernel_layer.is_valid(tracepoint.addr, 1) {
            continue;
        }
        parse_tracepoint(k, &known_modules, &tracepoint, &mut |p| {
            out.row(
                0,
                vec![
                    Value::Str(p.tracepoint_name),
                    Value::Int(p.tracepoint_address as i128),
                    s(p.probe_name),
                    Value::Int(p.probe_address as i128),
                    match p.probe_priority {
                        Some(v) if v != 0 => Value::Int(v),
                        _ => Value::NotAvailable,
                    },
                    s(p.module_name),
                    p.module_address.map_or(Value::NotAvailable, |a| Value::Int(a as i128)),
                ],
            )
        })?;
    }
    Ok(())
}

impl Plugin for CheckTracepoints {
    fn name(&self) -> &'static str {
        "linux.tracing.tracepoints.CheckTracepoints"
    }
    fn description(&self) -> &'static str {
        "Detect tracepoints hooking"
    }
    fn epilog(&self) -> Option<&'static str> {
        Some(
            "Investigate the tracepoints subsystem to uncover kernel attached probes, which can be leveraged\n    to hook kernel functions and modify their behaviour.",
        )
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let k = ctx.linux_kernel()?;
        out.begin(vec![
            Column::new("tracepoint", ColType::Str),
            Column::new("tracepoint address", ColType::Hex),
            Column::new("Probe", ColType::Str),
            Column::new("Probe address", ColType::Hex),
            Column::new("Probe priority", ColType::Int),
            Column::new("Module", ColType::Str),
            Column::new("Module address", ColType::Hex),
        ])?;
        run_rows(k, out)
    }
}
