//! mac.check_sysctl.Check_sysctl (python `plugins/mac/check_sysctl.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::automagic::mac::MacKernel;
use crate::context::Context;
use crate::error::{Error, Result};
use crate::objects::Obj;
use crate::objects::util::{array_to_string, pointer_to_string};
use crate::plugins::mac::lsmod::list_modules;
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::mac::{MacExt, generate_kernel_handler_info, lookup_module_address};

pub struct CheckSysctl;

/// python `_parse_global_variable_sysctls(kernel, name)`.
fn parse_global_variable_sysctls(k: &MacKernel, name: &str) -> Result<String> {
    let var_name = match name {
        "hostname" => "hostname",
        "nisdomainname" => "domainname",
        _ => return Ok(String::new()),
    };
    match k.object_from_symbol(var_name) {
        Ok(arr) => array_to_string(&arr, None),
        Err(Error::Symbol(_)) => Ok(String::new()),
        Err(e) => Err(e),
    }
}

/// python recursion limit stand-in (a cyclic sysctl tree makes python raise RecursionError).
const MAX_DEPTH: usize = 900;

/// python `_process_sysctl_list(kernel, sysctl_list, recursive)`: appends `(sysctl_oid,
/// name, value)` in python's yield order (children before their parent node). `Err` = python
/// raised (items already pushed were yielded).
fn process_sysctl_list(k: &MacKernel, list: Obj, recursive: bool, items: &mut Vec<(Obj, String, String)>, depth: usize) -> Result<()> {
    if depth > MAX_DEPTH {
        panic!("RecursionError: maximum recursion depth exceeded");
    }
    let list = if list.is_pointer() {
        // `sysctl_list.dereference().cast("sysctl_oid_list")` (the pointer was read by the caller)
        Obj::named(list.sp.native_space(), "sysctl_oid_list", list.u64()?)?
    } else {
        list
    };
    // `sysctl` is a pointer (truthy when non-zero) or, after the recursive skip, a struct
    // (always truthy): keep the struct view plus the pointer value
    let first = list.m("slh_first")?;
    let mut value = first.u64()?;
    let mut cur = Obj::named(first.sp.native_space(), "sysctl_oid", value)?;
    if recursive {
        match first.m("oid_link").and_then(|l| l.m("sle_next")).and_then(|p| p.deref()) {
            Ok(s) => {
                cur = s;
                value = 1; // a struct object: truthy
            }
            Err(e) if e.is_invalid_address() => return Ok(()),
            Err(e) => return Err(e),
        }
    }
    while value != 0 {
        let s = cur;
        let name = match s.m("oid_name").and_then(|n| pointer_to_string(&n, 128)) {
            Ok(n) => n,
            Err(e) if e.is_invalid_address() => String::new(),
            Err(e) => return Err(e),
        };
        if name.is_empty() {
            break;
        }
        let ctltype = s.get_ctltype()?;
        let arg1_obj = s.m("oid_arg1")?;
        let arg1_ptr = match arg1_obj.u64() {
            Ok(v) => v,
            Err(e) if e.is_invalid_address() => 0,
            Err(e) => return Err(e),
        };
        let arg1 = arg1_obj.u64()?;
        let val = if arg1 == 0 || arg1_ptr == 0 {
            parse_global_variable_sysctls(k, &name)?
        } else if ctltype == "CTLTYPE_NODE" {
            if s.m("oid_handler")?.u64()? == 0 {
                process_sysctl_list(k, arg1_obj, true, items, depth + 1)?;
            }
            "Node".to_string()
        } else if matches!(ctltype, "CTLTYPE_INT" | "CTLTYPE_QUAD" | "CTLTYPE_OPAQUE") {
            match Obj::named(arg1_obj.sp.native_space(), "int", arg1).and_then(|o| o.int()) {
                Ok(v) => v.to_string(),
                Err(e) if e.is_invalid_address() => "-1".to_string(),
                Err(e) => return Err(e),
            }
        } else if ctltype == "CTLTYPE_STRING" {
            match pointer_to_string(&arg1_obj, 64) {
                Ok(v) => v,
                Err(e) if e.is_invalid_address() => String::new(),
                Err(e) => return Err(e),
            }
        } else {
            ctltype.to_string()
        };
        items.push((s, name, val));
        match s.m("oid_link").and_then(|l| l.m("sle_next")).and_then(|p| p.u64().map(|v| (p, v))) {
            Ok((p, v)) => {
                value = v;
                cur = Obj::named(p.sp.native_space(), "sysctl_oid", v)?;
            }
            Err(e) if e.is_invalid_address() => break,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

impl Plugin for CheckSysctl {
    fn name(&self) -> &'static str {
        "mac.check_sysctl.Check_sysctl"
    }
    fn description(&self) -> &'static str {
        "Check sysctl handlers for hooks."
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let k = ctx.mac_kernel()?;
        out.begin(vec![
            Column::new("Name", ColType::Str),
            Column::new("Number", ColType::Int),
            Column::new("Perms", ColType::Str),
            Column::new("Handler Address", ColType::Hex),
            Column::new("Value", ColType::Str),
            Column::new("Handler Module", ColType::Str),
            Column::new("Handler Symbol", ColType::Str),
        ])?;
        let handlers = generate_kernel_handler_info(k, list_modules(k))?;
        let sysctl_list = k.object_from_symbol("sysctl__children")?;
        let mut items = Vec::new();
        let res = process_sysctl_list(k, sysctl_list, false, &mut items, 0);
        for (sysctl, name, val) in items {
            let check_addr = match sysctl.m("oid_handler").and_then(|h| h.u64()) {
                Ok(v) => v,
                Err(e) if e.is_invalid_address() => continue,
                Err(e) => return Err(e),
            };
            let (module, symbol) = lookup_module_address(k.table, &handlers, check_addr as i128, Some(k.offset));
            let number = sysctl.m("oid_number")?.int()?;
            let perms = sysctl.get_perms()?;
            out.row(
                0,
                vec![
                    Value::Str(name),
                    Value::Int(number),
                    Value::Str(perms),
                    Value::Int(check_addr as i128),
                    Value::Str(val),
                    Value::Str(module),
                    Value::Str(symbol.to_string()),
                ],
            )?;
        }
        res
    }
}
