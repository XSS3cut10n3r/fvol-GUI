//! python `symbols/windows/extensions/gui.py` (`GUIExtensions`: `tagWINDOWSTATION`,
//! `tagDESKTOP`, `tagWND`, `_LARGE_UNICODE_STRING`) as the [`GuiExt`] trait on [`Obj`], plus
//! the GUI symbol table selection of python `WindowStations.create_gui_table`.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! The python methods are per-class; here they are named after the class they belong to
//! (`winsta_*`, `desktop_*`, `wnd_*`). Errors follow python: an `Err` that
//! `is_invalid_address()` is python's `InvalidAddressException`, which these methods catch
//! exactly where python does.
//!
//! ```ignore
//! use crate::symbols::windows::gui::{self, GuiExt};
//! let gui_table = gui::create_gui_table(ctx, k.table)?;
//! if let Some((name, sid)) = winsta.winsta_get_info(k.table)? { ... }
//! for (desktop, name) in winsta.winsta_desktops(k.table)? { for t in desktop.desktop_get_threads() { ... } }
//! ```

use super::pool::PoolExt;
use super::versions::{self, OsDistinguisher};
use super::WinExt;
use crate::context::Context;
use crate::error::{Error, Result};
use crate::objects::Obj;
use crate::objects::util::{array_to_string, pointer_to_string_ex};
use crate::symbols::{StrEnc, StrErrors, TableRef, Ty};
use crate::util::FxHashSet;

/// python `WindowStations._win_version_file_map` (checked newest -> oldest).
pub static WIN_VERSION_FILE_MAP: [(&OsDistinguisher, &str); 11] = [
    (&versions::IS_WIN10_19577_OR_LATER, "gui-win10-19577-x64"),
    (&versions::IS_WIN10_19041_OR_LATER, "gui-win10-19041-x64"),
    (&versions::IS_WIN10_18362_OR_LATER, "gui-win10-18362-x64"),
    (&versions::IS_WIN10_17763_OR_LATER, "gui-win10-17763-x64"),
    (&versions::IS_WIN10_17134_OR_LATER, "gui-win10-17134-x64"),
    (&versions::IS_WIN10_16299_OR_LATER, "gui-win10-16299-x64"),
    (&versions::IS_WIN10_15063_OR_LATER, "gui-win10-15063-x64"),
    (&versions::IS_WIN10_10586_OR_LATER, "gui-win10-10586-x64"),
    (&versions::IS_WINDOWS_8_OR_LATER, "gui-win8-x64"),
    (&versions::IS_WINDOWS_7_SP1, "gui-win7sp1-x64"),
    (&versions::IS_WINDOWS_7_SP0, "gui-win7sp0-x64"),
];

/// python `WindowStations.create_gui_table(context, symbol_table, config_path)`: the embedded
/// `windows/gui/gui-*.json` table for the kernel's version, with `nt_symbols` mapped to the
/// kernel table. Errors like python's `NotImplementedError` for x86 / unknown versions.
pub fn create_gui_table(ctx: &Context, kernel_table: TableRef) -> Result<TableRef> {
    if !kernel_table.is_64bit() {
        return Err(Error::msg("NotImplementedError: This plugin only supports x64 versions of Windows"));
    }
    let file = WIN_VERSION_FILE_MAP
        .iter()
        .find(|(d, _)| d.check(kernel_table))
        .map(|(_, f)| *f)
        .ok_or_else(|| Error::msg("NotImplementedError: This version of Windows is not supported!"))?;
    ctx.load_isf_with(&format!("windows/gui/{file}"), None, &[("nt_symbols", kernel_table.name())])
}

/// `Err` that is python's `InvalidAddressException` -> `Ok(None)`, else propagate.
#[inline]
fn catch_invalid<T>(r: Result<T>) -> Result<Option<T>> {
    match r {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.is_invalid_address() => Ok(None),
        Err(e) => Err(e),
    }
}

/// python `GUIExtensions` class methods on [`Obj`].
pub trait GuiExt {
    // ---- tagWINDOWSTATION
    /// python `tagWINDOWSTATION.get_session_id()` (`dwSessionId`, None when unreadable).
    fn winsta_get_session_id(&self) -> Result<Option<i128>>;
    /// python `tagWINDOWSTATION.is_valid()`.
    fn winsta_is_valid(&self) -> bool;
    /// python `tagWINDOWSTATION.traverse(max_stations=15)`. Note python always follows
    /// `self.rpwinstaNext` (not the last station's), so this is `self` plus at most one more.
    fn winsta_traverse(&self) -> Result<Vec<Obj>>;
    /// python `tagWINDOWSTATION.get_info(kernel_symbol_table_name)`: `(name, session_id)` or
    /// None (python's `(None, None)`).
    fn winsta_get_info(&self, kernel_table: TableRef) -> Result<Option<(String, i128)>>;
    /// python `tagWINDOWSTATION.desktops(symbol_table_name, max_desktops=12)`. Like
    /// `traverse`, python always dereferences `self.rpdeskList`, so this yields at most one
    /// desktop.
    fn winsta_desktops(&self, kernel_table: TableRef) -> Result<Vec<(Obj, Option<String>)>>;

    // ---- tagDESKTOP
    /// python `tagDESKTOP.get_window_station()` (None when unreadable).
    fn desktop_get_window_station(&self) -> Result<Option<Obj>>;
    /// python `tagDESKTOP.get_session_id()`.
    fn desktop_get_session_id(&self) -> Result<Option<i128>>;
    /// python `tagDESKTOP.is_valid()`.
    fn desktop_is_valid(&self) -> bool;
    /// python `tagDESKTOP.get_threads()`: `(tagTHREADINFO, process name, pid)` for each
    /// thread of `PtiList` whose process can be read. A trailing `Err` = python raised there.
    fn desktop_get_threads(&self) -> Vec<Result<(Obj, String, i128)>>;

    // ---- tagWND
    /// python `tagWND.get_name()`: `directName` (utf16, 256 bytes) else `strName`.
    fn wnd_get_name(&self) -> Result<Option<String>>;
    /// python `tagWND.get_desktop()`.
    fn wnd_get_desktop(&self) -> Result<Option<Obj>>;
    /// python `tagWND.get_session_id()`.
    fn wnd_get_session_id(&self) -> Result<Option<i128>>;
    /// python `tagWND.is_valid()`.
    fn wnd_is_valid(&self) -> bool;
    /// python `tagWND.get_process()`: the hosting `_EPROCESS` (not read yet), None when a
    /// pointer on the way is unreadable.
    fn wnd_get_process(&self) -> Result<Option<Obj>>;
    /// python `tagWND.get_window_procedure()` (the pointer value, None when unreadable).
    fn wnd_get_window_procedure(&self) -> Result<Option<u64>>;

    // ---- _LARGE_UNICODE_STRING
    /// python `LARGE_UNICODE_STRING.get_string()`.
    fn large_unicode_get_string(&self) -> Result<String>;
}

impl GuiExt for Obj {
    fn winsta_get_session_id(&self) -> Result<Option<i128>> {
        catch_invalid(self.m("dwSessionId").and_then(|v| v.int()))
    }

    fn winsta_is_valid(&self) -> bool {
        matches!(self.winsta_get_session_id(), Ok(Some(sid)) if (0..256).contains(&sid))
    }

    fn winsta_traverse(&self) -> Result<Vec<Obj>> {
        let mut out = vec![*self];
        let mut seen = FxHashSet::default();
        while seen.len() < 15 {
            let Some(winsta) = catch_invalid(self.m("rpwinstaNext").and_then(|p| p.deref()))? else { break };
            if seen.contains(&winsta.addr) {
                break;
            }
            out.push(winsta);
            seen.insert(winsta.addr);
        }
        Ok(out)
    }

    fn winsta_get_info(&self, kernel_table: TableRef) -> Result<Option<(String, i128)>> {
        let name = self.executive_name(Some(kernel_table))?;
        let session_id = self.winsta_get_session_id()?;
        match (name, session_id) {
            (Some(name), Some(sid)) if sid < 256 && name.chars().count() > 1 => Ok(Some((name, sid))),
            _ => Ok(None),
        }
    }

    fn winsta_desktops(&self, kernel_table: TableRef) -> Result<Vec<(Obj, Option<String>)>> {
        let mut out = Vec::new();
        let mut seen = FxHashSet::default();
        while seen.len() < 12 {
            let r = catch_invalid((|| -> Result<(Obj, Option<String>)> {
                let desktop = self.m("rpdeskList")?.deref()?;
                let name = desktop.executive_name(Some(kernel_table))?;
                Ok((desktop, name))
            })())?;
            let Some((desktop, name)) = r else { break };
            if seen.contains(&desktop.addr) {
                break;
            }
            out.push((desktop, name));
            seen.insert(desktop.addr);
        }
        Ok(out)
    }

    fn desktop_get_window_station(&self) -> Result<Option<Obj>> {
        catch_invalid(self.m("rpwinstaParent").and_then(|p| p.deref()))
    }

    fn desktop_get_session_id(&self) -> Result<Option<i128>> {
        // python: `if winsta:` - a struct is always truthy
        match self.desktop_get_window_station()? {
            Some(w) => w.winsta_get_session_id(),
            None => Ok(None),
        }
    }

    fn desktop_is_valid(&self) -> bool {
        match self.desktop_get_session_id() {
            Ok(Some(sid)) if (0..256).contains(&sid) => matches!(self.desktop_get_window_station(), Ok(Some(_))),
            _ => false,
        }
    }

    fn desktop_get_threads(&self) -> Vec<Result<(Obj, String, i128)>> {
        let mut out = Vec::new();
        let head = match self.m("PtiList") {
            Ok(h) => h,
            Err(e) => return vec![Err(e)],
        };
        let ttype = format!("{}!tagTHREADINFO", self.table().name());
        for thread in head.to_list(&ttype, "PtiLink", true, true, None) {
            let thread = match thread {
                Ok(t) => t,
                Err(e) => {
                    out.push(Err(e));
                    break;
                }
            };
            let r = (|| -> Result<(String, i128)> {
                let name = array_to_string(&thread.m("ppi")?.m("Process")?.m("ImageFileName")?, None)?;
                let pid = thread.m("ppi")?.m("Process")?.m("UniqueProcessId")?.int()?;
                Ok((name, pid))
            })();
            match r {
                Ok((name, pid)) => out.push(Ok((thread, name, pid))),
                Err(e) if e.is_invalid_address() => continue,
                Err(e) => {
                    out.push(Err(e));
                    break;
                }
            }
        }
        out
    }

    fn wnd_get_name(&self) -> Result<Option<String>> {
        if self.has_member("directName") {
            match catch_invalid(self.m("directName").and_then(|p| pointer_to_string_ex(&p, 256, "replace", "utf16")))? {
                Some(s) => return Ok(Some(s)),
                None => {}
            }
        }
        catch_invalid(self.m("strName").and_then(|s| s.large_unicode_get_string()))
    }

    fn wnd_get_desktop(&self) -> Result<Option<Obj>> {
        catch_invalid(self.m("head").and_then(|h| h.m("rpdesk")).and_then(|p| p.deref()))
    }

    fn wnd_get_session_id(&self) -> Result<Option<i128>> {
        match self.wnd_get_desktop()? {
            Some(d) => d.desktop_get_session_id(),
            None => Ok(None),
        }
    }

    fn wnd_is_valid(&self) -> bool {
        matches!(self.wnd_get_session_id(), Ok(Some(sid)) if (0..256).contains(&sid))
    }

    fn wnd_get_process(&self) -> Result<Option<Obj>> {
        catch_invalid((|| -> Result<Obj> { self.m("head")?.m("pti")?.m("ppi")?.m("Process")?.deref() })())
    }

    fn wnd_get_window_procedure(&self) -> Result<Option<u64>> {
        catch_invalid((|| -> Result<u64> {
            // python: hasattr(self, "subPointer") reads the pointer (an InvalidAddressException
            // escapes hasattr and is caught below)
            if self.has_member("subPointer") {
                self.m("subPointer")?.u64()?;
                self.m("subPointer")?.m("lpfnWndProc")?.u64()
            } else {
                self.m("lpfnWndProc")?.u64()
            }
        })())
    }

    fn large_unicode_get_string(&self) -> Result<String> {
        let buffer = self.m("Buffer")?;
        let addr = buffer.u64()?;
        let length = self.m("Length")?.u64()?;
        let sp = crate::objects::Space::get(buffer.sp.native, buffer.sp.native, self.sp.table);
        Obj::new(sp, Ty::Void, addr).cast_string(length, StrEnc::Utf16, StrErrors::Replace).string()
    }
}

/// python `is_valid()` of the GUI classes, by struct name (`None` = not a GUI class). Used by
/// the `WinExt::is_valid` dispatcher (pool-scan carving calls it).
pub fn gui_is_valid(o: &Obj) -> Option<bool> {
    match o.struct_name() {
        Some("tagWINDOWSTATION") => Some(o.winsta_is_valid()),
        Some("tagDESKTOP") => Some(o.desktop_is_valid()),
        Some("tagWND") => Some(o.wnd_is_valid()),
        _ => None,
    }
}

/// A window as python's `tagDESKTOP.windows()` yields it: either a `tagWND` struct or a
/// `Pointer` to one (python yields the `spwndChild` pointer objects themselves, whose
/// `vol.offset` is the address of the pointer field, not of the window).
#[derive(Clone, Copy, Debug)]
pub struct WndRef {
    /// the `tagWND` (for a pointer: its dereferenced target)
    pub wnd: Obj,
    /// python `window.vol.offset`
    pub offset: u64,
    /// `Some(value)` when python's object is a `Pointer` (hashes/compares as its value)
    pub ptr_value: Option<u64>,
}

impl WndRef {
    /// A `tagWND` struct.
    pub fn from_struct(wnd: Obj) -> WndRef {
        WndRef { wnd, offset: wnd.addr, ptr_value: None }
    }
    /// A `Pointer` object to a `tagWND` (reads the pointer value, like python's attribute
    /// access).
    pub fn from_pointer(ptr: Obj) -> Result<WndRef> {
        let v = ptr.u64()?;
        let wnd = ptr.deref()?;
        Ok(WndRef { wnd, offset: ptr.addr, ptr_value: Some(v) })
    }
}

/// python `tagDESKTOP.windows(window, max_windows=10000)` (with `_do_get_windows`): every
/// window adjacent to and below `top` (depth first), deduplicated by `vol.offset`, with names.
///
/// NOTE on order: python iterates each local `seen_windows` set (the start window plus its
/// siblings) in CPython set order. Struct objects hash by `id()` (their heap address), so that
/// order depends on the interpreter's allocator state and differs between python runs (two
/// consecutive python runs on the same image disagree with each other). We iterate in
/// insertion order (the start window, then its siblings in list order): the same rows as
/// python, in a deterministic order.
///
/// python repeats `_do_get_windows` expansions (the leftmost-child chain is walked again from
/// every ancestor); a repeat only yields windows `windows()` already dropped, so each pointer
/// field is expanded once here.
pub fn desktop_windows(top: WndRef, max_windows: usize, out: &mut dyn FnMut(WndRef, Option<String>) -> Result<bool>) -> Result<()> {
    let mut st = WalkState { seen: FxHashSet::default(), expanded: FxHashSet::default(), max_windows, stop: false };
    do_get_windows(&mut st, top, out)
}

struct WalkState {
    /// `windows()`'s `seen_windows` (offsets already yielded)
    seen: FxHashSet<u64>,
    /// pointer fields whose `_do_get_windows` expansion already ran
    expanded: FxHashSet<u64>,
    max_windows: usize,
    stop: bool,
}

fn emit(st: &mut WalkState, w: WndRef, name: Option<String>, out: &mut dyn FnMut(WndRef, Option<String>) -> Result<bool>) -> Result<()> {
    if st.stop || st.seen.contains(&w.offset) {
        return Ok(());
    }
    st.seen.insert(w.offset);
    if !out(w, name)? {
        st.stop = true;
    }
    if st.seen.len() == st.max_windows {
        st.stop = true;
    }
    Ok(())
}

/// python `tagDESKTOP._do_get_windows(window, max_windows)`.
fn do_get_windows(st: &mut WalkState, window: WndRef, out: &mut dyn FnMut(WndRef, Option<String>) -> Result<bool>) -> Result<()> {
    if st.stop || window.offset == 0 {
        return Ok(());
    }
    let name = window.wnd.wnd_get_name()?;
    emit(st, window, name, out)?;
    let mut seen_windows: Vec<WndRef> = vec![window];
    // walk adjacent windows
    let mut cur = window;
    while seen_windows.len() < st.max_windows && !st.stop {
        let Some(next) = catch_invalid(cur.wnd.m("spwndNext").and_then(|p| p.deref()))? else { break };
        if next.addr == 0 {
            break;
        }
        // `window.vol.offset in seen_windows`: only pointer members compare equal to an int
        if seen_windows.iter().any(|w| w.ptr_value == Some(next.addr)) {
            break;
        }
        let w = WndRef::from_struct(next);
        let name = w.wnd.wnd_get_name()?;
        emit(st, w, name, out)?;
        seen_windows.push(w);
        cur = w;
    }
    // walk children windows and recursively yield them
    let mut seen_children: FxHashSet<u64> = FxHashSet::default();
    for i in 0..seen_windows.len() {
        let mut child = seen_windows[i];
        while seen_windows.len() + seen_children.len() < st.max_windows && !st.stop {
            let Some(ptr) = catch_invalid(child.wnd.m("spwndChild").and_then(|p| p.u64().map(|_| p)))? else { break };
            if ptr.addr == 0 {
                break;
            }
            let c = WndRef::from_pointer(ptr)?;
            let v = c.ptr_value.unwrap_or(0);
            if seen_children.contains(&v) {
                break;
            }
            seen_children.insert(v);
            if st.expanded.insert(c.offset) {
                do_get_windows(st, c, out)?;
            }
            child = c;
        }
    }
    Ok(())
}
