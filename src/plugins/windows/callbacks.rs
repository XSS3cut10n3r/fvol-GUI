//! windows.callbacks.Callbacks (python `plugins/windows/callbacks.py` +
//! `symbols/windows/extensions/callbacks.py`): kernel notification routines, bugcheck and
//! registry callbacks, and pool-scanned callback objects, resolved to modules / symbols.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! Every `list_*` / [`scan`] helper returns [`CallbackEntry`]s in python's order (a trailing
//! `Err` = python raised there); `detail: None` is python's `None` (rendered N/A).

use crate::context::{Context, WinKernel};
use crate::error::{Error, Result};
use crate::objects::{Obj, Space};
use crate::plugins::windows::driverirp::IRP_MJ_SHUTDOWN;
use crate::plugins::windows::poolscanner::{PoolConstraint, generate_pool_scan_each, get_type_map, pool_type};
use crate::plugins::windows::ssdt::build_module_collection;
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::pool::{PoolExt, TypeMap};
use crate::symbols::windows::{WinExt, versions};
use crate::symbols::{StrEnc, StrErrors, TableRef, Ty};

pub struct Callbacks;

/// One python `(callback_type, callback_address, callback_detail)` tuple.
#[derive(Clone, Debug)]
pub struct CallbackEntry {
    pub kind: Value,
    pub address: u64,
    /// `None` = python `None`.
    pub detail: Option<Value>,
}

fn entry(kind: &'static str, address: u64, detail: Option<Value>) -> CallbackEntry {
    CallbackEntry { kind: Value::SStr(kind), address, detail }
}

/// python `Callbacks.create_callback_symbol_table(context, nt_symbol_table, config_path)`:
/// the `callbacks-x64/x86` ISF with the kernel's natives, `nt_symbols` mapped to the kernel.
pub fn create_callback_symbol_table(ctx: &Context, k: &WinKernel) -> Result<TableRef> {
    let file = if k.table.is_64bit() { "windows/callbacks-x64" } else { "windows/callbacks-x86" };
    ctx.load_isf_with(file, Some(k.table), &[("nt_symbols", k.table.name())])
}

/// python `Callbacks.create_callback_scan_constraints(context, symbol_table, is_vista_or_above)`.
pub fn create_callback_scan_constraints(table: TableRef, is_vista_or_above: bool) -> Result<Vec<PoolConstraint>> {
    use pool_type::*;
    let n = table.name();
    let size = |t: &str| -> Result<u64> { Ok(table.size_of(table.get_type(t)?)) };
    let all = NONPAGED | PAGED | FREE;
    let mut c = vec![
        PoolConstraint::new(b"IoFs", format!("{n}!_NOTIFICATION_PACKET")).size(Some(size("_NOTIFICATION_PACKET")?), None).page_type(all),
        PoolConstraint::new(b"IoSh", format!("{n}!_SHUTDOWN_PACKET")).size(Some(size("_SHUTDOWN_PACKET")?), None).page_type(all).index(Some(0), Some(0)),
        PoolConstraint::new(b"Cbrb", format!("{n}!_GENERIC_CALLBACK")).size(Some(size("_GENERIC_CALLBACK")?), None).page_type(all),
    ];
    if is_vista_or_above {
        c.extend([
            PoolConstraint::new(b"DbCb", format!("{n}!_DBGPRINT_CALLBACK")).size(Some(0x20), Some(0x40)).page_type(all),
            PoolConstraint::new(b"Pnp9", format!("{n}!_NOTIFY_ENTRY_HEADER")).size(Some(0x30), None).page_type(all).index(Some(1), Some(1)),
            PoolConstraint::new(b"PnpD", format!("{n}!_NOTIFY_ENTRY_HEADER")).size(Some(0x40), None).page_type(all).index(Some(1), Some(1)),
            PoolConstraint::new(b"PnpC", format!("{n}!_NOTIFY_ENTRY_HEADER")).size(Some(0x38), None).page_type(all).index(Some(1), Some(1)),
        ]);
    }
    Ok(c)
}

/// python `EX_FAST_REF.dereference().cast(type)`: the object at `Object & ~max_fast_ref`
/// (python constructs, i.e. reads, a pointer there first: unreadable = InvalidAddress).
fn fast_ref_target(fast_ref: &Obj, table: TableRef, ty: Ty) -> Result<Obj> {
    let p = fast_ref.fast_ref_dereference()?;
    p.u64()?;
    Ok(Obj::new(Space::get(p.layer(), p.native(), table), ty, p.addr))
}

/// python `Callbacks.list_notify_routines(context, kernel_module_name, callback_table_name)`.
pub fn list_notify_routines(k: &WinKernel, table: TableRef) -> Vec<Result<CallbackEntry>> {
    let mut out = Vec::new();
    let r = (|| -> Result<()> {
        let is_vista_or_later = versions::IS_VISTA_OR_LATER.check(k.table);
        let gen_ty = table.get_type("_GENERIC_CALLBACK")?;
        for (symbol_name, extended) in [("PspLoadImageNotifyRoutine", false), ("PspCreateThreadNotifyRoutine", true), ("PspCreateProcessNotifyRoutine", true)] {
            let Ok(sym) = k.get_symbol(symbol_name) else { continue };
            let count = if is_vista_or_later && extended { 64 } else { 8 };
            let fast_refs = k.object("_EX_FAST_REF", sym.address)?.cast_array_of(count, "_EX_FAST_REF")?;
            for i in 0..count {
                let callback = match fast_ref_target(&fast_refs.at(i)?, table, gen_ty) {
                    Ok(c) => c,
                    Err(e) if e.is_invalid_address() => continue,
                    Err(e) => return Err(e),
                };
                let cb = callback.m("Callback")?.u64()?;
                if cb != 0 {
                    out.push(Ok(entry(symbol_name, cb, None)));
                }
            }
        }
        Ok(())
    })();
    if let Err(e) = r {
        out.push(Err(e));
    }
    out
}

/// python `list_bugcheck_callbacks` / `list_bugcheck_reason_callbacks` (`absolute`: whether
/// python builds the `Component` string at the absolute address; the non-reason variant adds
/// the kernel base, python's quirk).
fn list_bugcheck(k: &WinKernel, table: TableRef, symbol: &'static str, type_name: &str, absolute: bool) -> Vec<Result<CallbackEntry>> {
    let mut out = Vec::new();
    let r = (|| -> Result<()> {
        let Ok(sym) = k.get_symbol(symbol) else { return Ok(()) };
        let full = format!("{}!{type_name}", table.name());
        let record = Obj::named(Space::on(k.vlayer, table), type_name, k.base.wrapping_add(sym.address) & k.vlayer.address_mask())?;
        for cb in record.m("Entry")?.list_of(&full, "Entry") {
            let cb = cb?;
            let routine = cb.m("CallbackRoutine")?.u64()?;
            if !k.vlayer.is_valid(routine, 64) {
                continue;
            }
            let component = (|| -> Result<String> {
                let c = cb.m("Component")?.u64()?;
                let addr = if absolute { c } else { c.wrapping_add(k.base) } & k.vlayer.address_mask();
                Obj::new(Space::on(k.vlayer, k.table), Ty::Void, addr).cast_string(64, StrEnc::Utf8, StrErrors::Replace).string()
            })();
            let component = match component {
                Ok(s) => Value::Str(s),
                Err(e) if e.is_invalid_address() => Value::Unreadable,
                Err(e) => return Err(e),
            };
            out.push(Ok(entry(symbol, routine, Some(component))));
        }
        Ok(())
    })();
    if let Err(e) = r {
        out.push(Err(e));
    }
    out
}

/// python `Callbacks.list_bugcheck_callbacks(...)`.
pub fn list_bugcheck_callbacks(k: &WinKernel, table: TableRef) -> Vec<Result<CallbackEntry>> {
    list_bugcheck(k, table, "KeBugCheckCallbackListHead", "_KBUGCHECK_CALLBACK_RECORD", false)
}

/// python `Callbacks.list_bugcheck_reason_callbacks(...)`.
pub fn list_bugcheck_reason_callbacks(k: &WinKernel, table: TableRef) -> Vec<Result<CallbackEntry>> {
    list_bugcheck(k, table, "KeBugCheckReasonCallbackListHead", "_KBUGCHECK_REASON_CALLBACK_RECORD", true)
}

/// python `Callbacks.list_registry_callbacks(...)` (legacy `CmpCallBackVector` or
/// `CallbackListHead`).
pub fn list_registry_callbacks(k: &WinKernel, table: TableRef) -> Vec<Result<CallbackEntry>> {
    let mut out = Vec::new();
    let r = (|| -> Result<()> {
        if k.has_symbol("CmpCallBackVector") && k.has_symbol("CmpCallBackCount") {
            let count = k.object("unsigned int", k.get_symbol("CmpCallBackCount")?.address)?.u64()?;
            if count == 0 {
                return Ok(());
            }
            let ty = table.get_type("_EX_CALLBACK_ROUTINE_BLOCK")?;
            let fast_refs = k.object("_EX_FAST_REF", k.get_symbol("CmpCallBackVector")?.address)?.cast_array_of(count, "_EX_FAST_REF")?;
            for i in 0..count {
                let callback = match fast_ref_target(&fast_refs.at(i)?, table, ty) {
                    Ok(c) => c,
                    Err(e) if e.is_invalid_address() => continue,
                    Err(e) => return Err(e),
                };
                let f = callback.m("Function")?.u64()?;
                if f != 0 {
                    out.push(Ok(entry("CmRegisterCallback", f, None)));
                }
            }
        } else if k.has_symbol("CallbackListHead") && k.has_symbol("CmpCallBackCount") {
            let count = k.object("unsigned int", k.get_symbol("CmpCallBackCount")?.address)?.u64()?;
            if count == 0 {
                return Ok(());
            }
            let full = format!("{}!_CM_CALLBACK_ENTRY", table.name());
            let head = k.object("_LIST_ENTRY", k.get_symbol("CallbackListHead")?.address)?;
            for cb in head.list_of(&full, "Link") {
                let cb = cb?;
                let altitude = match cb.m("Altitude").and_then(|a| a.get_string()) {
                    Ok(s) => s,
                    Err(e) if e.is_invalid_address() => "None".to_string(),
                    Err(e) => return Err(e),
                };
                let f = cb.m("Function")?.u64()?;
                out.push(Ok(entry("CmRegisterCallbackEx", f, Some(Value::Str(format!("Altitude: {altitude}"))))));
            }
        }
        Ok(())
    })();
    if let Err(e) = r {
        out.push(Err(e));
    }
    out
}

/// python `_SHUTDOWN_PACKET.is_valid()` (x86 callbacks table only).
pub fn shutdown_packet_is_valid(p: &Obj) -> bool {
    (|| -> Result<bool> {
        let entry = p.m("Entry")?;
        Ok(entry.m("Flink")?.is_readable() && entry.m("Blink")?.is_readable() && p.m("DeviceObject")?.is_readable())
    })()
    .unwrap_or(false)
}

/// python `_SHUTDOWN_PACKET.is_parseable(type_map)` (x86 callbacks table only).
pub fn shutdown_packet_is_parseable(p: &Obj, type_map: &TypeMap) -> Result<bool> {
    if !shutdown_packet_is_valid(p) {
        return Ok(false);
    }
    let r = (|| -> Result<bool> {
        let device = p.m("DeviceObject")?;
        if device.u64()? == 0 || device.m("DriverObject")?.m("DriverStart")?.u64()? % 0x1000 != 0 {
            return Ok(false);
        }
        let header = device.deref()?.get_object_header(None)?;
        Ok(header.get_object_type(type_map, None)?.as_deref() == Some("Device"))
    })();
    match r {
        Ok(v) => Ok(v),
        Err(e) if e.is_invalid_address() => Ok(false),
        Err(Error::Msg(_)) => Ok(false),
        Err(e) => Err(e),
    }
}

/// python `Callbacks._process_scanned_callback(memory_object, type_map)`.
fn process_scanned_callback(obj: &Obj, type_map: &TypeMap) -> Result<CallbackEntry> {
    match obj.type_name().as_str() {
        "_SHUTDOWN_PACKET" => {
            let r = (|| -> Result<(u64, Value)> {
                let driver = obj.m("DeviceObject")?.m("DriverObject")?;
                driver.u64()?;
                let address = driver.m("MajorFunction")?.at(IRP_MJ_SHUTDOWN)?.u64()?;
                let name = driver.m("DriverName")?.get_string()?;
                Ok((address, if name.is_empty() { Value::Unparsable } else { Value::Str(name) }))
            })();
            let (address, details) = match r {
                Ok(v) => v,
                Err(e) if e.is_invalid_address() => (obj.addr, Value::NotApplicable),
                Err(e) => return Err(e),
            };
            Ok(entry("IoRegisterShutdownNotification", address, Some(details)))
        }
        "_NOTIFICATION_PACKET" => Ok(entry("IoRegisterFsRegistrationChange", obj.m("NotificationRoutine")?.u64()?, Some(Value::NotApplicable))),
        "_NOTIFY_ENTRY_HEADER" => {
            let dp = obj.m("DriverObject")?;
            dp.u64()?; // python reads the pointer at attribute access
            let details = if dp.is_readable() {
                let header = dp.deref()?.get_object_header(None)?;
                match header.get_object_type(type_map, None) {
                    Ok(Some(t)) if t == "Driver" => match header.name_info().and_then(|n| n.m("Name")).and_then(|n| n.get_string()) {
                        Ok(s) => Value::Str(s),
                        Err(e) if e.is_invalid_address() => Value::Unreadable,
                        Err(e) => return Err(e),
                    },
                    Ok(_) => Value::NotApplicable,
                    Err(e) if e.is_invalid_address() => Value::Unreadable,
                    Err(e) => return Err(e),
                }
            } else {
                Value::Unreadable
            };
            let ec = obj.m("EventCategory")?;
            let kind = if ec.is_valid_choice() { Value::SStr(ec.description()?) } else { Value::Unparsable };
            let address = obj.m("CallbackRoutine")?.u64()?;
            Ok(CallbackEntry { kind, address, detail: Some(details) })
        }
        "_GENERIC_CALLBACK" => Ok(entry("GenericKernelCallback", obj.m("Callback")?.u64()?, Some(Value::NotApplicable))),
        "_DBGPRINT_CALLBACK" => Ok(entry("DbgSetDebugPrintCallback", obj.m("Function")?.u64()?, Some(Value::NotApplicable))),
        t => Err(Error::msg(format!("ValueError: Unexpected object type {}!{t}", obj.table().name()))),
    }
}

/// python `Callbacks.scan(context, kernel_module_name, callback_symbol_table)`: pool-scanned
/// callback objects (unreadable ones skipped).
pub fn scan(ctx: &Context, k: &WinKernel, table: TableRef) -> Vec<Result<CallbackEntry>> {
    let mut out = Vec::new();
    let r = (|| -> Result<()> {
        let is_vista_or_later = versions::IS_VISTA_OR_LATER.check(k.table);
        let type_map = get_type_map(k)?;
        let constraints = create_callback_scan_constraints(table, is_vista_or_later)?;
        // python binds the _SHUTDOWN_PACKET class (is_parseable) only in the x86 table
        let shutdown_class = !table.is_64bit();
        generate_pool_scan_each(ctx, k, k.table, &constraints, |hit| {
            let obj = hit.object;
            let r = (|| -> Result<Option<CallbackEntry>> {
                if shutdown_class && obj.type_name() == "_SHUTDOWN_PACKET" && !shutdown_packet_is_parseable(&obj, &type_map)? {
                    return Ok(None);
                }
                Ok(Some(process_scanned_callback(&obj, &type_map)?))
            })();
            match r {
                Ok(Some(e)) => out.push(Ok(e)),
                Ok(None) => {}
                Err(e) if e.is_invalid_address() => {}
                Err(e) => return Err(e),
            }
            Ok(true)
        })
    })();
    if let Err(e) = r {
        out.push(Err(e));
    }
    out
}

impl Plugin for Callbacks {
    fn name(&self) -> &'static str {
        "windows.callbacks.Callbacks"
    }
    fn description(&self) -> &'static str {
        "Lists kernel callbacks and notification routines."
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("Type", ColType::Str),
            Column::new("Callback", ColType::Hex),
            Column::new("Module", ColType::Str),
            Column::new("Symbol", ColType::Str),
            Column::new("Detail", ColType::Str),
        ])?;
        let k = ctx.windows_kernel()?;
        let table = create_callback_symbol_table(ctx, k)?;
        let collection = build_module_collection(k)?;
        let methods: [&dyn Fn() -> Vec<Result<CallbackEntry>>; 5] = [
            &|| list_notify_routines(k, table),
            &|| list_bugcheck_callbacks(k, table),
            &|| list_bugcheck_reason_callbacks(k, table),
            &|| list_registry_callbacks(k, table),
            &|| scan(ctx, k, table),
        ];
        for method in methods {
            for e in method() {
                let e = e?;
                let detail = e.detail.clone().unwrap_or(Value::NotApplicable);
                let row = |module: Value, symbol: Value| vec![e.kind.clone(), Value::Int(e.address as i128), module, symbol, detail.clone()];
                let found = collection.module_symbols(e.address);
                if found.is_empty() {
                    out.row(0, row(Value::NotAvailable, Value::NotAvailable))?;
                }
                for (module_name, syms) in found {
                    if syms.is_empty() {
                        out.row(0, row(Value::str(module_name), Value::NotAvailable))?;
                    }
                    for s in syms {
                        out.row(0, row(Value::str(module_name), Value::str(s)))?;
                    }
                }
            }
        }
        Ok(())
    }
}
