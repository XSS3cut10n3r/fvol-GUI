//! mac.check_syscall.Check_syscall and mac.check_trap_table.Check_trap_table (python
//! `plugins/mac/check_syscall.py`, `plugins/mac/check_trap_table.py`): both walk a kernel
//! array of structs holding a handler pointer.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::plugins::mac::lsmod::list_modules;
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::mac::{generate_kernel_handler_info, lookup_module_address};

pub struct CheckSyscall;
pub struct CheckTrapTable;

fn columns() -> Vec<Column> {
    vec![
        Column::new("Table Address", ColType::Hex),
        Column::new("Table Name", ColType::Str),
        Column::new("Index", ColType::Int),
        Column::new("Handler Address", ColType::Hex),
        Column::new("Handler Module", ColType::Str),
        Column::new("Handler Symbol", ColType::Str),
    ]
}

/// The shared `_generator`: `for i, ent in enumerate(kernel.object_from_symbol(symbol))`,
/// `call_addr = ent.<member>.dereference().vol.offset` (skipped on InvalidAddressException or 0).
fn run_table(ctx: &Context, out: &mut dyn RowSink, symbol: &str, member: &str, table_name: &'static str) -> Result<()> {
    let k = ctx.mac_kernel()?;
    out.begin(columns())?;
    let handlers = generate_kernel_handler_info(k, list_modules(k))?;
    let table = k.object_from_symbol(symbol)?;
    let n = table.count();
    if n == 0 {
        return Ok(());
    }
    let elem = table.at(0)?;
    let moff = elem.member_offset(member)?;
    let esize = elem.size();
    // the handler pointer of every entry (python reads them one by one; a failed read skips it)
    let ptr0 = elem.m(member)?;
    let native_mask = ptr0.sp.native.address_mask();
    let layer = table.layer();
    let mut buf = vec![0u8; (n * esize) as usize];
    let psize = ptr0.size() as usize;
    let whole = (psize == 8 || psize == 4) && layer.read(table.addr, &mut buf).is_ok();
    for i in 0..n {
        let call_addr = if whole {
            let o = (i * esize + moff) as usize;
            let mut b = [0u8; 8];
            b[..psize].copy_from_slice(&buf[o..o + psize]);
            u64::from_le_bytes(b) & native_mask
        } else {
            match ptr0.at_addr(table.addr.wrapping_add(i * esize).wrapping_add(moff)).u64() {
                Ok(v) => v,
                Err(e) if e.is_invalid_address() => continue,
                Err(e) => return Err(e),
            }
        };
        if call_addr == 0 {
            continue;
        }
        let (module, symbol) = lookup_module_address(k.table, &handlers, call_addr as i128, Some(k.offset));
        out.row(
            0,
            vec![
                Value::Int(table.addr as i128),
                Value::SStr(table_name),
                Value::Int(i as i128),
                Value::Int(call_addr as i128),
                Value::Str(module),
                Value::Str(symbol.to_string()),
            ],
        )?;
    }
    Ok(())
}

impl Plugin for CheckSyscall {
    fn name(&self) -> &'static str {
        "mac.check_syscall.Check_syscall"
    }
    fn description(&self) -> &'static str {
        "Check system call table for hooks."
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        run_table(ctx, out, "sysent", "sy_call", "SysCall")
    }
}

impl Plugin for CheckTrapTable {
    fn name(&self) -> &'static str {
        "mac.check_trap_table.Check_trap_table"
    }
    fn description(&self) -> &'static str {
        "Check mach trap table for hooks."
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        run_table(ctx, out, "mach_trap_table", "mach_trap_function", "TrapTable")
    }
}
