//! python `symbols/windows/extensions/consoles.py`: the conhost.exe console structures
//! (`_ROW`, `_SCREEN_INFORMATION`, `_CONSOLE_INFORMATION`, `_COMMAND_HISTORY`, `_COMMAND`,
//! `_EXE_ALIAS_LIST`, `_ALIAS`) as the [`ConsoleExt`] trait on [`Obj`], plus [`Screen`] (a
//! `_SCREEN_INFORMATION` pointer as `CONSOLE_INFORMATION.get_screens()` yields it).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! The objects come from a `windows/consoles/consoles-win10-*-x64` table loaded with
//! `table_mapping={"nt_symbols": <kernel table>}` (see `plugins::windows::consoles`). Python
//! binds these classes by type name; the methods here are meant to be called on objects of
//! the matching struct (python would raise `AttributeError` otherwise). Python *properties*
//! that shadow members are methods with snake_case names: `COMMAND_HISTORY.CommandCount` ->
//! [`ConsoleExt::command_count`], `.ProcessHandle` -> [`ConsoleExt::process_handle`],
//! `SCREEN_INFORMATION.ScreenX/ScreenY` -> [`Screen::screen_x`] / [`Screen::screen_y`],
//! `CONSOLE_INFORMATION.ScreenBuffer` -> [`ConsoleExt::screen_buffer`].
//!
//! Reads happen where python reads (primitive members and pointers are read on attribute
//! access); an `Err` is where python raises (`InvalidAddressException` ->
//! `e.is_invalid_address()`).
//!
//! ```ignore
//! use crate::symbols::windows::consoles::ConsoleExt;
//! for h in console_info.get_histories()? {
//!     let h = h?;
//!     let app = h.get_application()?;
//!     for c in h.get_commands()? { let (index, cmd) = c?; let s = cmd.get_command_string()?; }
//! }
//! ```

use crate::error::{Error, Result};
use crate::layers::{Layer, LayerExt};
use crate::objects::{Field, Obj};
use crate::symbols::windows::{ListIter, WinExt};
use crate::symbols::{StrEnc, StrErrors, Ty};
use crate::util::FxHashSet;

/// python `ROW._valid_dbcs` accepted `DbcsAttr` values, as a 256-entry lookup table.
const VALID_DBCS: [bool; 256] = {
    let ok: [u8; 29] = [
        0x0, 0x1, 0x2, 0x8, 0x10, 0x18, 0x20, 0x28, 0x30, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78, 0x80, 0x88, 0xA8, 0xB8, 0xC0,
        0xC8, 0x98, 0xD8, 0xE0, 0xE8, 0xF8, 0xF0, 0xA0,
    ];
    let mut t = [false; 256];
    let mut i = 0;
    while i < ok.len() {
        t[ok[i] as usize] = true;
        i += 1;
    }
    t
};

/// python `str.isspace()` for one character (the set `str.strip()`/`rstrip()` removes).
#[inline]
pub fn py_isspace(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n'
            | '\u{0b}'
            | '\u{0c}'
            | '\r'
            | '\u{1c}'..='\u{1f}'
            | ' '
            | '\u{85}'
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

/// python `s.rstrip()` (no argument: python whitespace, which includes `\x1c`-`\x1f` unlike
/// `str::trim_end`).
#[inline]
pub fn py_rstrip(s: &str) -> &str {
    s.trim_end_matches(py_isspace)
}

/// python `layer.read(offset, length)` on an Intel translation layer, including its edge
/// cases: a negative length reads nothing (b""), a zero length still translates `offset` and
/// raises when it is not mapped.
pub fn py_layer_read(layer: &dyn Layer, offset: u64, length: i128) -> Result<Vec<u8>> {
    if length < 0 {
        return Ok(Vec::new());
    }
    if length == 0 {
        return if layer.is_valid(offset, 1) { Ok(Vec::new()) } else { Err(Error::invalid(offset)) };
    }
    if length > usize::MAX as i128 {
        return Err(Error::invalid(offset));
    }
    layer.read_vec(offset, length as usize)
}

/// python `SCREEN_INFORMATION._truncate_rows(rows)` (with its quirk: when every row is empty
/// the result is empty, and the index of the last non-empty row counted from the end decides
/// the cut).
pub fn truncate_rows(mut rows: Vec<String>) -> Vec<String> {
    let mut non_empty_index = 0usize;
    let mut rows_traversed = false;
    for (index, row) in rows.iter().rev().enumerate() {
        if !py_rstrip(row).is_empty() {
            non_empty_index = index;
            break;
        }
        rows_traversed = true;
    }
    if non_empty_index == 0 && rows_traversed {
        rows.clear();
    } else {
        let n = rows.len() - non_empty_index;
        rows.truncate(n);
    }
    rows
}

/// A `_SCREEN_INFORMATION` as yielded by `CONSOLE_INFORMATION.get_screens()`: python yields
/// the *pointer* (`Hex(screen)` is its value) whose `TextBufferInfo.BufferRows.Rows` array had
/// its count set to `TextBufferInfo.BufferCapacity`.
#[derive(Clone, Copy, Debug)]
pub struct Screen {
    /// The `_SCREEN_INFORMATION` pointer object (`CurrentScreenBuffer`, `GetScreenBuffer` or a
    /// `Next` member).
    pub ptr: Obj,
    /// `Rows.count` as python set it (`BufferCapacity`, a short).
    pub rows_count: i128,
}

/// `obj.Member` where the member is a pointer: python reads it on attribute access.
#[inline]
fn read_ptr(o: &Obj, member: &str) -> Result<Obj> {
    let p = o.m(member)?;
    p.u64()?;
    Ok(p)
}

/// python `hasattr(row, "Row")` + `row = row.Row` (`_ROW_POINTER` on builds before 22000):
/// the member is read (a failing read raises through `hasattr`).
#[inline]
fn row_of(row: Obj) -> Result<Obj> {
    if row.has_member("Row") { read_ptr(&row, "Row") } else { Ok(row) }
}

impl Screen {
    /// The `TextBufferInfo.BufferRows.Rows` array with python's count.
    fn rows(&self, count: i128) -> Result<Obj> {
        let rows = self.ptr.m("TextBufferInfo")?.m("BufferRows")?.m("Rows")?;
        Ok(rows.with_count(count.max(0) as u64))
    }

    /// python `SCREEN_INFORMATION.ScreenX` property: `RowLength2` of the first row.
    pub fn screen_x(&self) -> Result<i128> {
        if self.rows_count <= 0 {
            return Err(Error::msg("IndexError: range object index out of range"));
        }
        let row = row_of(self.rows(self.rows_count)?.at(0)?)?;
        row.m("RowLength2")?.int()
    }

    /// python `SCREEN_INFORMATION.ScreenY` property: `TextBufferInfo.BufferCapacity`.
    pub fn screen_y(&self) -> Result<i128> {
        self.ptr.m("TextBufferInfo")?.m("BufferCapacity")?.int()
    }

    /// python `SCREEN_INFORMATION.get_buffer(truncate_rows, truncate_lines)`: the rows of the
    /// ring buffer starting at `BufferStart`, stopping at the first row whose text cannot be
    /// read. Rows are independent: they are read in parallel with pre-resolved members (see
    /// [`RowReader`]); the result is python's.
    pub fn get_buffer(&self, truncate_rows_: bool, truncate_lines: bool) -> Result<Vec<String>> {
        let tbi = read_ptr(&self.ptr.deref()?, "TextBufferInfo")?;
        let capacity = tbi.m("BufferCapacity")?.int()?;
        let start = tbi.m("BufferStart")?.int()?;
        let buffer_rows = read_ptr(&tbi.deref()?, "BufferRows")?;
        let rows = buffer_rows.m("Rows")?.with_count(capacity.max(0) as u64);
        let n = capacity.max(0) as usize;
        if n == 0 {
            return Ok(Vec::new());
        }
        let reader = RowReader::new(&rows.at(0)?);
        // per row: Ok(Some(text)) / Ok(None) = get_text failed (python: break) / Err = the
        // `hasattr(row, "Row")` read failed (python: raises out of get_buffer)
        let one = |i: usize, buf: &mut Vec<u8>| -> Result<Option<String>> {
            let index = (start + i as i128).rem_euclid(capacity);
            let elem = rows.at(index as u64)?;
            match &reader {
                Some(r) => r.text(elem, truncate_lines, buf),
                None => {
                    let row = row_of(elem)?;
                    let row = if row.is_pointer() { row.deref()? } else { row };
                    Ok(row.row_get_text(truncate_lines).ok())
                }
            }
        };
        let batch = |range: std::ops::Range<usize>| -> Vec<Result<Option<String>>> {
            let mut buf = Vec::new();
            let mut v = Vec::with_capacity(range.len());
            for i in range {
                let r = one(i, &mut buf);
                let stop = !matches!(r, Ok(Some(_)));
                v.push(r);
                if stop {
                    break;
                }
            }
            v
        };
        let results: Vec<Result<Option<String>>> = if n >= 1024 {
            let nb = crate::util::par::threads().min(n / 512).max(1);
            let per = n.div_ceil(nb);
            crate::util::par::par_map(nb, |b| batch(b * per..((b + 1) * per).min(n))).into_iter().flatten().collect()
        } else {
            batch(0..n)
        };
        let mut out = Vec::with_capacity(n);
        for r in results {
            match r? {
                Some(text) => out.push(text),
                None => break,
            }
        }
        Ok(if truncate_rows_ { truncate_rows(out) } else { out })
    }
}

/// `ROW.get_text` for many rows of one array, with the members resolved once: the
/// `_ROW_POINTER.Row` indirection (builds before 22000), `_ROW.CharRow` and `_ROW.RowLength`
/// (read together when they are close: python reads both before using either, so one read
/// fails exactly when one of the two would), and `_CHAR_ROW_CELL_ARRAY.Chars`.
pub struct RowReader {
    row_ptr: Option<Field>,
    char_row: Field,
    row_length: Field,
    chars_off: u64,
    /// (start offset relative to the row, length) of the combined CharRow + RowLength read
    span: Option<(u64, usize)>,
}

impl RowReader {
    /// Resolve the members for arrays whose elements look like `elem` (None: unexpected
    /// layout, use the generic path).
    pub fn new(elem: &Obj) -> Option<RowReader> {
        let t = elem.table();
        let row_ptr = if elem.has_member("Row") { Some(Field::new(t, elem.struct_name()?, "Row").ok()?) } else { None };
        let row_ty = match &row_ptr {
            Some(f) => match f.ty {
                Ty::Pointer { target, .. } => t.node(target),
                _ => return None,
            },
            None => elem.ty,
        };
        let row_name = match row_ty {
            Ty::Struct(ut) => t.user_type_name(ut),
            _ => return None,
        };
        let char_row = Field::new(t, row_name, "CharRow").ok()?;
        let row_length = Field::new(t, row_name, "RowLength").ok()?;
        let cells = match char_row.ty {
            Ty::Pointer { target, .. } => match t.node(target) {
                Ty::Struct(ut) => t.user_type_name(ut),
                _ => return None,
            },
            _ => return None,
        };
        let chars_off = t.offset_of(cells, "Chars").ok()?;
        let (Ty::Pointer { prim: pp, .. }, Ty::Int(lp)) = (char_row.ty, row_length.ty) else { return None };
        let (a, b) = (char_row.offset as i64, row_length.offset as i64);
        let lo = a.min(b);
        let hi = (a + pp.size as i64).max(b + lp.size as i64);
        let span = if hi - lo <= 64 && !pp.big_endian && !lp.big_endian { Some((lo as u64, (hi - lo) as usize)) } else { None };
        Some(RowReader { row_ptr, char_row, row_length, chars_off, span })
    }

    /// python `row = Rows[index]; if hasattr(row, "Row"): row = row.Row; row.get_text(...)`:
    /// `Err` = the `Row` read failed, `Ok(None)` = `get_text` raised.
    pub fn text(&self, elem: Obj, truncate: bool, buf: &mut Vec<u8>) -> Result<Option<String>> {
        let row = match &self.row_ptr {
            Some(f) => {
                let p = elem.f(f);
                p.u64()?;
                p.deref()?
            }
            None => elem,
        };
        let cr = row.f(&self.char_row);
        let rl = row.f(&self.row_length);
        let (ptr, length) = match self.span {
            Some((lo, n)) => {
                let mut b = [0u8; 64];
                let at = row.addr.wrapping_add(lo) & row.sp.layer_mask;
                if row.layer().read(at, &mut b[..n]).is_err() {
                    return Ok(None);
                }
                let (Ty::Pointer { prim: pp, .. }, Ty::Int(lp)) = (cr.ty, rl.ty) else { return Ok(None) };
                let po = self.char_row.offset.wrapping_sub(lo) as usize;
                let lo_ = self.row_length.offset.wrapping_sub(lo) as usize;
                let mut pp = pp;
                pp.signed = false;
                let ptr = (pp.decode_int(&b[po..po + pp.size as usize]) as u64) & cr.sp.native_mask;
                (ptr, lp.decode_int(&b[lo_..lo_ + lp.size as usize]))
            }
            None => match (cr.u64(), rl.int()) {
                (Ok(p), Ok(l)) => (p, l),
                _ => return Ok(None),
            },
        };
        let nsp = cr.sp.native_space();
        let chars = (ptr & nsp.layer_mask).wrapping_add(self.chars_off) & nsp.layer_mask;
        let length = length * 3;
        if !py_layer_read_into(row.layer(), chars, length, buf) {
            return Ok(None);
        }
        Ok(Some(decode_row(buf, truncate)))
    }
}

/// The characters of a `CharRow` buffer (`ROW.get_text` without the reads).
fn decode_row(char_row: &[u8], truncate: bool) -> String {
    let mut line = String::with_capacity(char_row.len() / 3);
    for cell in char_row.chunks_exact(3) {
        if cell[1] == 0 && VALID_DBCS[cell[2] as usize] {
            line.push(cell[0] as char);
        }
    }
    if truncate {
        let n = py_rstrip(&line).len();
        line.truncate(n);
    }
    line
}

/// [`py_layer_read`] into a reusable buffer; false where python raises.
fn py_layer_read_into(layer: &dyn Layer, offset: u64, length: i128, buf: &mut Vec<u8>) -> bool {
    buf.clear();
    if length < 0 {
        return true;
    }
    if length == 0 {
        return layer.is_valid(offset, 1);
    }
    if length > (1 << 30) {
        return layer.read_vec(offset, length as usize).map(|v| *buf = v).is_ok();
    }
    buf.resize(length as usize, 0);
    layer.read(offset, buf).is_ok()
}

/// Console structure extensions on [`Obj`].
pub trait ConsoleExt {
    // ---- _ROW
    /// python `ROW.get_text(truncate)`: `RowLength * 3` bytes at `CharRow.Chars`, one
    /// character per 3-byte cell (only cells with a zero high byte and a known `DbcsAttr`),
    /// right-stripped when `truncate`.
    fn row_get_text(&self, truncate: bool) -> Result<String>;

    // ---- _CONSOLE_INFORMATION
    /// python `CONSOLE_INFORMATION.ScreenBuffer` property (`GetScreenBuffer`, falling back to a
    /// `ScreenBuffer` member like python's `__getattr__` after an `AttributeError`).
    fn screen_buffer(&self) -> Result<Obj>;
    /// python `CONSOLE_INFORMATION.is_valid(max_buffers)`.
    fn console_info_is_valid(&self, max_buffers: i128) -> Result<bool>;
    /// python `CONSOLE_INFORMATION.get_title()` (any error -> "").
    fn get_title(&self) -> String;
    /// python `CONSOLE_INFORMATION.get_original_title()` (any error -> "").
    fn get_original_title(&self) -> String;
    /// python `CONSOLE_INFORMATION.get_screens()`: `CurrentScreenBuffer` and `ScreenBuffer`
    /// followed through `Next` (python's `seen` set holds the addresses of the pointer fields).
    /// A trailing `Err` is where the python generator raises.
    fn get_screens(&self) -> Vec<Result<Screen>>;
    /// python `CONSOLE_INFORMATION.get_histories()` (`_COMMAND_HISTORY` list).
    fn get_histories(&self) -> Result<ListIter>;
    /// python `CONSOLE_INFORMATION.get_exe_aliases()` (`_EXE_ALIAS_LIST` list).
    fn get_exe_aliases(&self) -> Result<ListIter>;
    /// python `CONSOLE_INFORMATION.get_processes()` (`_CONSOLE_PROCESS_LIST` list).
    fn get_processes(&self) -> Result<ListIter>;

    // ---- _COMMAND
    /// python `COMMAND.is_valid()`.
    fn command_is_valid(&self) -> Result<bool>;
    /// python `COMMAND.get_command_string()` (None when `Length >= 1024`).
    fn get_command_string(&self) -> Result<Option<String>>;

    // ---- _COMMAND_HISTORY
    /// python `COMMAND_HISTORY.CommandCount` property: `int((End - Begin) / sizeof(_COMMAND))`.
    fn command_count(&self) -> Result<i128>;
    /// python `COMMAND_HISTORY.ProcessHandle` property.
    fn process_handle(&self) -> Result<i128>;
    /// python `COMMAND_HISTORY.is_valid(max_history)`.
    fn command_history_is_valid(&self, max_history: i128) -> Result<bool>;
    /// python `COMMAND_HISTORY.get_application()`.
    fn get_application(&self) -> Result<Option<String>>;
    /// python `COMMAND_HISTORY.scan_command_bucket(end)`: the valid `_COMMAND`s from
    /// `CommandBucket.Begin` to `end` (default: `max(EndCapacity, Begin +
    /// sizeof(_COMMAND_HISTORY) * CommandCountMax)`, python's formula) as (index, command).
    fn scan_command_bucket(&self, end: Option<i128>) -> Result<CommandScan>;
    /// python `COMMAND_HISTORY.get_commands()` (`scan_command_bucket(CommandBucket.End)`).
    fn get_commands(&self) -> Result<CommandScan>;

    // ---- _EXE_ALIAS_LIST
    /// python `EXE_ALIAS_LIST.get_exename()` (builds whose `ExeName` is a pointer raise, like
    /// python's `String.get_string` AttributeError).
    fn get_exename(&self) -> Result<Option<String>>;
    /// python `EXE_ALIAS_LIST.get_aliases()` (`_ALIAS` list).
    fn get_aliases(&self) -> Result<ListIter>;

    // ---- _ALIAS
    /// python `ALIAS.get_source()`.
    fn get_source(&self) -> Result<Option<String>>;
    /// python `ALIAS.get_target()`.
    fn get_target(&self) -> Result<Option<String>>;
}

/// Iterator of python `COMMAND_HISTORY.scan_command_bucket()`: `(index, _COMMAND)` for the
/// valid commands; yields one `Err` (then stops) where python's `cmd.is_valid()` raises.
pub struct CommandScan {
    cmd: Obj,
    next: i128,
    end: i128,
    step: i128,
    index: usize,
    done: bool,
}

impl Iterator for CommandScan {
    type Item = Result<(usize, Obj)>;
    fn next(&mut self) -> Option<Result<(usize, Obj)>> {
        while !self.done && self.next < self.end {
            let cmd = self.cmd.at_addr(self.next as u64);
            let i = self.index;
            self.next += self.step;
            self.index += 1;
            match cmd.command_is_valid() {
                Ok(true) => return Some(Ok((i, cmd))),
                Ok(false) => {}
                Err(e) => {
                    self.done = true;
                    return Some(Err(e));
                }
            }
        }
        None
    }
}

/// `pointer.dereference().cast("string", encoding="utf-16", errors="replace", max_length=n)`
/// (the dereference itself reads the first byte; covered by the cast's read).
fn deref_utf16(ptr: &Obj, max_len: u64) -> Result<String> {
    let v = ptr.u64()?;
    let sp = ptr.sp.native_space();
    Obj::new(sp, Ty::Void, v).cast_string(max_len, StrEnc::Utf16, StrErrors::Replace).string()
}

/// `self.<Pointer or LIST_ENTRY member>.to_list("<conhost table>!<type>", "ListEntry")`.
fn member_list(o: &Obj, member: &str, elem_type: &str) -> Result<ListIter> {
    let mut head = o.m(member)?;
    if head.is_pointer() {
        head = head.deref()?;
    }
    Ok(head.to_list(&format!("{}!{elem_type}", o.table().name()), "ListEntry", true, true, None))
}

impl ConsoleExt for Obj {
    fn row_get_text(&self, truncate: bool) -> Result<String> {
        let offset = self.m("CharRow")?.m("Chars")?.addr;
        let length = self.m("RowLength")?.int()? * 3;
        let char_row = py_layer_read(self.layer(), offset, length)?;
        Ok(decode_row(&char_row, truncate))
    }

    fn screen_buffer(&self) -> Result<Obj> {
        match self.m("GetScreenBuffer") {
            Ok(p) => {
                p.u64()?;
                Ok(p)
            }
            Err(Error::Symbol(_)) => read_ptr(self, "ScreenBuffer"),
            Err(e) => Err(e),
        }
    }

    fn console_info_is_valid(&self, max_buffers: i128) -> Result<bool> {
        let count = self.m("HistoryBufferCount")?.int()?;
        if count < 1 || count > max_buffers {
            return Ok(false);
        }
        if self.get_title().is_empty() && self.get_original_title().is_empty() {
            return Ok(false);
        }
        Ok(true)
    }

    fn get_title(&self) -> String {
        self.m("Title").and_then(|p| deref_utf16(&p, 512)).unwrap_or_default()
    }

    fn get_original_title(&self) -> String {
        self.m("OriginalTitle").and_then(|p| deref_utf16(&p, 512)).unwrap_or_default()
    }

    fn get_screens(&self) -> Vec<Result<Screen>> {
        let mut out = Vec::new();
        let r = (|| -> Result<()> {
            let current = read_ptr(self, "CurrentScreenBuffer")?;
            let mut screens = vec![current];
            let sb = self.screen_buffer()?;
            if sb.u64()? != current.u64()? {
                screens.push(sb);
            }
            let mut seen = FxHashSet::default();
            for screen in screens {
                let mut cur = screen;
                while cur.u64()? != 0 && cur.addr != 0 && !seen.contains(&cur.addr) {
                    // python: cur.TextBufferInfo.BufferRows.Rows.count = cur.TextBufferInfo.BufferCapacity
                    let tbi = read_ptr(&cur.deref()?, "TextBufferInfo")?;
                    let capacity = tbi.m("BufferCapacity")?.int()?;
                    read_ptr(&tbi.deref()?, "BufferRows")?;
                    out.push(Ok(Screen { ptr: cur, rows_count: capacity }));
                    seen.insert(cur.addr);
                    cur = cur.m("Next")?;
                }
            }
            Ok(())
        })();
        if let Err(e) = r {
            out.push(Err(e));
        }
        out
    }

    fn get_histories(&self) -> Result<ListIter> {
        member_list(self, "HistoryList", "_COMMAND_HISTORY")
    }

    fn get_exe_aliases(&self) -> Result<ListIter> {
        member_list(self, "ExeAliasList", "_EXE_ALIAS_LIST")
    }

    fn get_processes(&self) -> Result<ListIter> {
        member_list(self, "ConsoleProcessList", "_CONSOLE_PROCESS_LIST")
    }

    fn command_is_valid(&self) -> Result<bool> {
        let length = self.m("Length")?.int()?;
        if length < 1 {
            return Ok(false);
        }
        let allocated = self.m("Allocated")?.int()?;
        Ok(!(allocated < 1 || length > 1024 || allocated > 1024))
    }

    fn get_command_string(&self) -> Result<Option<String>> {
        let length = self.m("Length")?.int()?;
        let max_len = (length * 2).max(0) as u64;
        if length < 8 {
            return Ok(Some(self.m("Chars")?.cast_string(max_len, StrEnc::Utf16, StrErrors::Replace).string()?));
        }
        if length < 1024 {
            return Ok(Some(deref_utf16(&self.m("Pointer")?, max_len)?));
        }
        Ok(None)
    }

    fn command_count(&self) -> Result<i128> {
        let command_size = self.table().size_of(self.table().get_type("_COMMAND")?);
        let bucket = self.m("CommandBucket")?;
        let end = bucket.m("End")?.int()?;
        let begin = bucket.m("Begin")?.int()?;
        if command_size == 0 {
            return Err(Error::msg("ZeroDivisionError: division by zero"));
        }
        // python true division (correctly rounded; exact for |End - Begin| < 2**53) then int()
        Ok(((end - begin) as f64 / command_size as f64).trunc() as i128)
    }

    fn process_handle(&self) -> Result<i128> {
        self.m("ConsoleProcessHandle")?.m("ProcessHandle")?.int()
    }

    fn command_history_is_valid(&self, max_history: i128) -> Result<bool> {
        let count = self.command_count()?;
        if count < 0 || count > max_history {
            return Ok(false);
        }
        let last = self.m("LastDisplayed")?.int()?;
        if last < -1 || last > max_history {
            return Ok(false);
        }
        let handle = self.process_handle()?;
        if handle <= 0 || handle > 0xFFFF || handle % 4 != 0 {
            return Ok(false);
        }
        Ok(true)
    }

    fn get_application(&self) -> Result<Option<String>> {
        self.m("Application")?.get_command_string()
    }

    fn scan_command_bucket(&self, end: Option<i128>) -> Result<CommandScan> {
        let t = self.table();
        let command_ty = t.get_type("_COMMAND")?;
        let command_history_size = self.size() as i128;
        let command_size = t.size_of(command_ty) as i128;
        let bucket = self.m("CommandBucket")?;
        let end = match end {
            Some(e) => e,
            None => {
                let end_capacity = bucket.m("EndCapacity")?.int()?;
                let begin = bucket.m("Begin")?.int()?;
                let max = self.m("CommandCountMax")?.int()?;
                end_capacity.max(begin + command_history_size * max)
            }
        };
        let begin = bucket.m("Begin")?.int()?;
        if command_size <= 0 {
            return Err(Error::msg("ValueError: range() arg 3 must not be zero"));
        }
        // python: context.object(command_type, self.vol.layer_name, pointer) (native = layer)
        let cmd = Obj::new(crate::objects::Space::on(self.layer(), t), command_ty, 0);
        Ok(CommandScan { cmd, next: begin, end, step: command_size, index: 0, done: false })
    }

    fn get_commands(&self) -> Result<CommandScan> {
        let end = self.m("CommandBucket")?.m("End")?.int()?;
        self.scan_command_bucket(Some(end))
    }

    fn get_exename(&self) -> Result<Option<String>> {
        let exe_name = self.m("ExeName")?;
        if exe_name.is_pointer() {
            // python: exe_name.dereference().get_string() -> the String object reads one byte,
            // then has no get_string (AttributeError)
            let v = exe_name.u64()?;
            exe_name.sp.native.read_vec(v, 1)?;
            return Err(Error::Symbol("AttributeError: 'String' object has no attribute 'get_string'".into()));
        }
        exe_name.get_command_string()
    }

    fn get_aliases(&self) -> Result<ListIter> {
        member_list(self, "AliasList", "_ALIAS")
    }

    fn get_source(&self) -> Result<Option<String>> {
        self.m("Source")?.get_command_string()
    }

    fn get_target(&self) -> Result<Option<String>> {
        self.m("Target")?.get_command_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_rstrip_and_truncate_rows() {
        assert_eq!(py_rstrip("ab \t\u{1c}\u{1f}\u{a0}\u{85}"), "ab");
        assert_eq!(py_rstrip("ab\0 "), "ab\0");
        let v = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(truncate_rows(v(&["a", "", " "])), v(&["a"]));
        assert_eq!(truncate_rows(v(&["a", "b"])), v(&["a", "b"]));
        assert_eq!(truncate_rows(v(&["", " "])), Vec::<String>::new());
        assert_eq!(truncate_rows(v(&[])), Vec::<String>::new());
        assert_eq!(truncate_rows(v(&["", "x", ""])), v(&["", "x"]));
    }

    #[test]
    fn dbcs_table() {
        assert!(VALID_DBCS[0] && VALID_DBCS[0xA0] && VALID_DBCS[0x98] && !VALID_DBCS[3] && !VALID_DBCS[0xFF]);
        assert_eq!(VALID_DBCS.iter().filter(|b| **b).count(), 29);
    }
}
