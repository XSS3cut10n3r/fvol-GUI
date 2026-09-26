//! linux.ebpf.EBPF (python `plugins/linux/ebpf.py`): enumerate eBPF programs by walking the
//! `prog_idr` IDR.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::{Error, Result};
use crate::objects::{Module, Obj};
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::linux::idstorage::idr_get_entries;
use crate::symbols::linux::prelude::*;

pub struct Ebpf;

/// python `EBPF.get_ebpf_programs(context, vmlinux_module_name)`: the `bpf_prog` objects of
/// `prog_idr`, in IDR order. A trailing `Err` = python raised there.
pub fn get_ebpf_programs(vm: &Module) -> Vec<Result<Obj>> {
    if !vm.has_symbol("prog_idr") {
        return vec![Err(Error::msg("Cannot find the eBPF prog idr. Unsupported kernel"))];
    }
    let prog_idr = match vm.object_from_symbol("prog_idr") {
        Ok(o) => o,
        Err(e) => return vec![Err(e)],
    };
    idr_get_entries(&prog_idr).into_iter().map(|a| a.and_then(|addr| vm.object_abs("bpf_prog", addr))).collect()
}

/// One output row of python `EBPF._generator` (evaluation order: type, tag, name).
fn prog_row(prog: &Obj) -> Result<Vec<Value>> {
    let ty = prog.get_type()?;
    let tag = prog.get_tag()?;
    let name = prog.get_name()?;
    let s = |v: Option<String>| match v {
        Some(s) if !s.is_empty() => Value::Str(s),
        _ => Value::NotAvailable,
    };
    Ok(vec![
        Value::Int(prog.addr as i128),
        s(name),
        s(tag),
        match ty {
            Some(t) if !t.is_empty() => Value::SStr(t),
            _ => Value::NotAvailable,
        },
    ])
}

impl Plugin for Ebpf {
    fn name(&self) -> &'static str {
        "linux.ebpf.EBPF"
    }
    fn description(&self) -> &'static str {
        "Enumerate eBPF programs"
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let k = ctx.linux_kernel()?;
        out.begin(vec![
            Column::new("Address", ColType::Hex),
            Column::new("Name", ColType::Str),
            Column::new("Tag", ColType::Str),
            Column::new("Type", ColType::Str),
        ])?;
        for prog in get_ebpf_programs(k) {
            out.row(0, prog_row(&prog?)?)?;
        }
        Ok(())
    }
}
