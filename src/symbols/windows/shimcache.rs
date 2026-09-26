//! python `symbols/windows/extensions/shimcache.py`: the `SHIM_CACHE_ENTRY`,
//! `SHIM_CACHE_HANDLE` and `_RTL_AVL_TABLE` class extensions of the hand-made shimcache ISFs
//! (`windows/shimcache/shimcache-*.json`), as the [`ShimcacheExt`] trait on [`Obj`].
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! Exception semantics follow python exactly: where python catches
//! `InvalidAddressException` the methods return the python fallback value, everywhere else a
//! read error is returned as `Err` (python raised). A missing member (python `AttributeError`,
//! `hasattr() == False`) is decided from the ISF layout, before any read, like python.
//!
//! ```ignore
//! use crate::symbols::windows::shimcache::ShimcacheExt;
//! if entry.shim_entry_is_valid()? { let path = entry.file_path()?; }
//! ```

use crate::error::{Error, Result};
use crate::layers::LayerExt;
use crate::objects::util::address_to_string;
use crate::objects::{Obj, Space, strings};
use crate::renderers::Value;
use crate::symbols::{StrEnc, StrErrors};
use crate::util::time::wintime_to_datetime;

use super::cache::eresource_is_valid;

/// python `AttributeError` (missing member) as produced by [`Obj::m`].
#[inline]
fn is_attr_err(e: &Error) -> bool {
    matches!(e, Error::Symbol(_))
}

/// `try: v except InvalidAddressException: fallback` (other errors propagate).
#[inline]
fn or_invalid<T>(r: Result<T>, fallback: T) -> Result<T> {
    match r {
        Err(e) if e.is_invalid_address() => Ok(fallback),
        r => r,
    }
}

/// Class extensions of the shimcache symbol tables.
pub trait ShimcacheExt {
    // ---- SHIM_CACHE_ENTRY
    /// python `SHIM_CACHE_ENTRY.exec_flag`. Because of the `try/except/else` in python this is
    /// `NotApplicable` whenever no exception was raised and no early return happened:
    /// `Unreadable` (read failure / invalid blob range), `Unparsable` (empty blob) or `N/A`.
    fn exec_flag(&self) -> Result<Value>;
    /// python `SHIM_CACHE_ENTRY.file_size`: `FileSize` clamped at 0, `N/A` without the member,
    /// `Unreadable` on a read failure.
    fn file_size(&self) -> Result<Value>;
    /// python `SHIM_CACHE_ENTRY.last_modified` (`ListEntryDetail.LastModified`, else the
    /// entry's own `LastModified` -- whose read errors propagate, like python's
    /// exception-in-except-handler).
    fn last_modified(&self) -> Result<Value>;
    /// python `SHIM_CACHE_ENTRY.last_update`.
    fn last_update(&self) -> Result<Value>;
    /// python `SHIM_CACHE_ENTRY.file_path`: `Path` (UNICODE_STRING) decoded as utf-16 with
    /// BOM sniffing (not cut at NUL), or the XP inline utf-16le array.
    fn file_path(&self) -> Result<Value>;
    /// python `SHIM_CACHE_ENTRY.is_valid()`.
    fn shim_entry_is_valid(&self) -> Result<bool>;

    // ---- SHIM_CACHE_HANDLE
    /// python `SHIM_CACHE_HANDLE.head`: the `SHIM_CACHE_ENTRY` right behind the handle's
    /// `_RTL_AVL_TABLE`, if valid.
    fn head(&self) -> Result<Option<Obj>>;
    /// python `SHIM_CACHE_HANDLE.is_valid(avl_section_start, avl_section_end)`.
    fn shim_handle_is_valid(&self, avl_section_start: u64, avl_section_end: u64) -> Result<bool>;

    // ---- _RTL_AVL_TABLE
    /// python `RTL_AVL_TABLE.is_valid(page_start, page_end)`.
    fn avl_table_is_valid(&self, page_start: u64, page_end: u64) -> Result<bool>;
}

impl ShimcacheExt for Obj {
    fn exec_flag(&self) -> Result<Value> {
        // Some(v) = early `return` in python; None = fell through to the `else:` clause (N/A).
        let r = (|| -> Result<Option<Value>> {
            let has_detail = self.has_member("ListEntryDetail");
            // hasattr(self, "ListEntryDetail") reads the pointer; hasattr(self.ListEntryDetail,
            // "InsertFlags") dereferences it and reads InsertFlags when the member exists.
            let detail = if has_detail { Some(self.m("ListEntryDetail")?.deref()?) } else { None };
            if let Some(d) = detail {
                if d.has_member("InsertFlags") {
                    d.m("InsertFlags")?.int()?;
                    return Ok(None);
                }
            }
            if self.has_member("InsertFlags") {
                self.m("InsertFlags")?.int()?;
                return Ok(None);
            }
            if let Some(d) = detail {
                if d.has_member("BlobBuffer") {
                    let blob_offset = d.m("BlobBuffer")?.u64()?;
                    let blob_size = d.m("BlobSize")?.u64()?;
                    let native = self.native();
                    if !native.is_valid(blob_offset, blob_size) {
                        return Ok(Some(Value::Unreadable));
                    }
                    // python reads the (valid) blob: an empty read is "not raw_flag"; any other
                    // outcome (int or struct.error) ends in the `else:` clause.
                    if blob_size == 0 {
                        return Ok(Some(Value::Unparsable));
                    }
                }
            }
            Ok(None)
        })();
        match r {
            Ok(Some(v)) => Ok(v),
            Ok(None) => Ok(Value::NotApplicable),
            Err(e) if e.is_invalid_address() => Ok(Value::Unreadable),
            Err(e) => Err(e),
        }
    }

    fn file_size(&self) -> Result<Value> {
        // (has_member first: no AttributeError value is built on the hot path)
        if !self.has_member("FileSize") {
            return Ok(Value::NotApplicable);
        }
        match self.m("FileSize").and_then(|f| f.int()) {
            Ok(v) => Ok(Value::Int(v.max(0))),
            Err(e) if is_attr_err(&e) => Ok(Value::NotApplicable),
            Err(e) if e.is_invalid_address() => Ok(Value::Unreadable),
            Err(e) => Err(e),
        }
    }

    fn last_modified(&self) -> Result<Value> {
        let first = if self.has_member("ListEntryDetail") {
            (|| -> Result<i128> { self.m("ListEntryDetail")?.m("LastModified")?.m("QuadPart")?.int() })()
        } else {
            Err(Error::Symbol(String::new()))
        };
        match first {
            Ok(q) => Ok(wintime_to_datetime(q)),
            // `except AttributeError:` -- errors raised inside the handler propagate
            Err(e) if is_attr_err(&e) => Ok(wintime_to_datetime(self.m("LastModified")?.m("QuadPart")?.int()?)),
            Err(e) if e.is_invalid_address() => Ok(Value::Unreadable),
            Err(e) => Err(e),
        }
    }

    fn last_update(&self) -> Result<Value> {
        if !self.has_member("LastUpdate") {
            return Ok(Value::NotApplicable);
        }
        match self.m("LastUpdate").and_then(|l| l.m("QuadPart")).and_then(|q| q.int()) {
            Ok(q) => Ok(wintime_to_datetime(q)),
            Err(e) if is_attr_err(&e) => Ok(Value::NotApplicable),
            Err(e) if e.is_invalid_address() => Ok(Value::Unreadable),
            Err(e) => Err(e),
        }
    }

    fn file_path(&self) -> Result<Value> {
        let path = self.m("Path")?;
        if !path.has_member("Buffer") {
            // XP: inline WCHAR array
            let s = address_to_string(path.layer(), path.addr, path.count(), "replace", "utf-16le")?;
            return Ok(Value::Str(s));
        }
        // hasattr(self.Path, "Buffer") reads the pointer outside the try block
        let buffer = path.m("Buffer")?;
        let buf = buffer.u64()?;
        let r = (|| -> Result<String> {
            let len = path.m("Length")?.u64()?;
            let data = self.native().read_vec(buf, len as usize)?;
            strings::decode(&data, StrEnc::Utf16, StrErrors::Replace)
        })();
        or_invalid(r.map(Value::Str), Value::Unreadable)
    }

    fn shim_entry_is_valid(&self) -> Result<bool> {
        let r = (|| -> Result<bool> {
            if !self.has_member("ListEntry") {
                // XP: bool(last_modified and last_update and file_size); datetimes and absent
                // values are truthy, file_size is an int (0 is falsy).
                self.last_modified()?;
                self.last_update()?;
                return Ok(!matches!(self.file_size()?, Value::Int(0)));
            }
            // Flink != 0 and Blink.dereference() != Flink.dereference() (distinct python
            // objects: always true once both are read) and Flink.Blink ==
            // Flink.Blink.dereference().vol.offset (a masked pointer equals its target offset:
            // true once readable).
            let le = self.m("ListEntry")?;
            let flink = le.m("Flink")?;
            if flink.u64()? == 0 {
                return Ok(false);
            }
            le.m("Blink")?.u64()?;
            flink.m("Blink")?.u64()?;
            Ok(true)
        })();
        or_invalid(r, false)
    }

    fn head(&self) -> Result<Option<Obj>> {
        let er = (|| -> Result<bool> { eresource_is_valid(&self.m("eresource")?.deref()?) })();
        if !or_invalid(er, false)? {
            return Ok(None);
        }
        let avl_ptr = self.m("rtl_avl_table")?;
        let avl = Obj::named(Space::get(self.layer(), self.native(), self.table()), "_RTL_AVL_TABLE", avl_ptr.u64()?)?;
        // python checks the pointer member itself (`self.rtl_avl_table.vol.offset`)
        if !self.layer().is_valid(avl_ptr.addr, 1) {
            return Ok(None);
        }
        let head = Obj::named(Space::on(self.layer(), self.table()), "SHIM_CACHE_ENTRY", avl.addr.wrapping_add(avl.size()))?;
        Ok(if head.shim_entry_is_valid()? { Some(head) } else { None })
    }

    fn shim_handle_is_valid(&self, avl_section_start: u64, avl_section_end: u64) -> Result<bool> {
        if self.addr == 0 {
            return Ok(false);
        }
        if !self.layer().is_valid(self.addr, 1) {
            return Ok(false);
        }
        if !eresource_is_valid(&self.m("eresource")?.deref()?)? {
            return Ok(false);
        }
        if !self.m("rtl_avl_table")?.deref()?.avl_table_is_valid(avl_section_start, avl_section_end)? {
            return Ok(false);
        }
        // `and self.head` then `return self.head.is_valid()`: head() only returns entries
        // that passed is_valid(), and recomputing it reads the same memory.
        Ok(self.head()?.is_some())
    }

    fn avl_table_is_valid(&self, page_start: u64, page_end: u64) -> Result<bool> {
        let r = (|| -> Result<bool> {
            let root = self.m("BalancedRoot")?;
            if root.m("Parent")?.u64()? != root.addr {
                return Ok(false);
            }
            let alloc = self.m("AllocateRoutine")?.u64()?;
            if alloc < page_start || alloc > page_end {
                return Ok(false);
            }
            let cmp = self.m("CompareRoutine")?.u64()?;
            if cmp < page_start || cmp > page_end {
                return Ok(false);
            }
            // the uniqueness check compares the members' own offsets (always distinct) but
            // reads FreeRoutine on the way
            self.m("FreeRoutine")?.u64()?;
            Ok(true)
        })();
        or_invalid(r, false)
    }
}
