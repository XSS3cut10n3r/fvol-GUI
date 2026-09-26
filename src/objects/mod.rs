//! Typed object views over layers (python `framework/objects` + `contexts.Module`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! See `src/objects/README-API.md` for the python -> rust cheat-sheet.
//!
//! * [`Obj`] is a 32-byte `Copy` handle: a [`Space`] (layer, native layer, symbol table),
//!   a [`Ty`] and an address. Creating objects never reads memory; reading happens in the
//!   value accessors (`int()`, `u64()`, `string()`, `deref()` ...), which return
//!   `Err(InvalidAddress)` exactly where python would raise `InvalidAddressException`.
//! * Layers, tables and spaces live for the whole process (`'static`), so objects have no
//!   lifetime parameters and can be stored, returned and sent across threads freely.
//! * Semantics mirror python: member/array offsets are masked with the layer's
//!   `address_mask`, pointer values with the native layer's mask, signed integers are sign
//!   extended, bitfields are `(value & ((1 << end) - 1)) >> start`, enums keep their raw value
//!   (`description()` fails for values outside the choices), strings decode then cut at NUL.
//! * Hot loops: resolve members once with [`Field`] (`obj.f(&field)`, no hashing).

pub mod strings;
pub mod util;

use crate::error::{Error, Result};
use crate::layers::{Layer, LayerExt};
use crate::symbols::table::{Prim, PrimKind, StrEnc, StrErrors, SymbolTable, Ty};
use crate::symbols::{TableRef, resolve_ref};
use crate::util::FxHashMap;
use std::sync::{Arc, Mutex, OnceLock};

/// A process-lifetime layer reference.
pub type LayerRef = &'static dyn Layer;

/// Leak an `Arc<dyn Layer>` into a `'static` reference (layers live for the whole run).
pub fn leak_layer(l: Arc<dyn Layer>) -> LayerRef {
    let b: &'static Arc<dyn Layer> = Box::leak(Box::new(l));
    &**b
}

#[inline(always)]
fn lkey(l: LayerRef) -> usize {
    l as *const dyn Layer as *const u8 as usize
}

/// The binding every object carries: python `vol.layer_name`, `vol.native_layer_name` and the
/// symbol table of its type. Interned: equal triples give the same `&'static Space`.
pub struct Space {
    /// The layer the object's bytes are read from (python `layer_name`).
    pub layer: LayerRef,
    /// The layer pointers inside the object point into (python `native_layer_name`).
    pub native: LayerRef,
    /// The symbol table of the object's type.
    pub table: TableRef,
    /// `layer.address_mask()`
    pub layer_mask: u64,
    /// `native.address_mask()`
    pub native_mask: u64,
    native_space: OnceLock<&'static Space>,
}

type SpaceKey = (usize, usize, usize);
static SPACES: Mutex<Option<FxHashMap<SpaceKey, &'static Space>>> = Mutex::new(None);

impl Space {
    /// Get (or create) the space for (layer, native layer, table).
    pub fn get(layer: LayerRef, native: LayerRef, table: TableRef) -> &'static Space {
        let key = (lkey(layer), lkey(native), table as *const SymbolTable as usize);
        let mut g = SPACES.lock().unwrap();
        let map = g.get_or_insert_with(Default::default);
        if let Some(s) = map.get(&key) {
            return s;
        }
        let s: &'static Space = Box::leak(Box::new(Space {
            layer,
            native,
            table,
            layer_mask: layer.address_mask(),
            native_mask: native.address_mask(),
            native_space: OnceLock::new(),
        }));
        map.insert(key, s);
        s
    }
    /// Space for objects living on `layer` whose pointers also point into `layer`.
    pub fn on(layer: LayerRef, table: TableRef) -> &'static Space {
        Space::get(layer, layer, table)
    }
    /// The space pointers dereference into: (native, native, table).
    #[inline]
    pub fn native_space(&self) -> &'static Space {
        self.native_space.get_or_init(|| Space::get(self.native, self.native, self.table))
    }
    /// Same layers, another table.
    pub fn with_table(&self, table: TableRef) -> &'static Space {
        Space::get(self.layer, self.native, table)
    }
    /// Same table, another layer (used as both layer and native layer).
    pub fn with_layer(&self, layer: LayerRef) -> &'static Space {
        Space::get(layer, layer, self.table)
    }
}

/// Error for a missing attribute (python `AttributeError`).
fn attr_err(o: &Obj, name: &str) -> Error {
    Error::Symbol(format!("AttributeError: {} has no attribute: {}", o.type_name(), name))
}

/// A typed view of memory (python `ObjectInterface`). `Copy`, 32 bytes.
#[derive(Clone, Copy)]
pub struct Obj {
    pub sp: &'static Space,
    pub ty: Ty,
    /// python `vol.offset` (already masked with the layer's address mask).
    pub addr: u64,
}

impl std::fmt::Debug for Obj {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<{} {} @ {:#x} on {}>", self.kind_name(), self.type_name(), self.addr, self.sp.layer.name())
    }
}

impl Obj {
    /// Create an object of type `ty` at `addr` in `sp` (python `context.object`); the address is
    /// masked with the layer's address mask like python.
    #[inline]
    pub fn new(sp: &'static Space, ty: Ty, addr: u64) -> Obj {
        Obj { sp, ty, addr: addr & sp.layer_mask }
    }

    /// Create an object by type name (user type or native) from the space's table.
    pub fn named(sp: &'static Space, type_name: &str, addr: u64) -> Result<Obj> {
        let (sp, ty) = resolve_named(sp, type_name)?;
        Ok(Obj::new(sp, ty, addr))
    }

    // ------------------------------------------------------------------ vol info

    /// python `vol.layer_name` layer.
    #[inline]
    pub fn layer(&self) -> LayerRef {
        self.sp.layer
    }
    /// python `vol.native_layer_name` layer.
    #[inline]
    pub fn native(&self) -> LayerRef {
        self.sp.native
    }
    /// The symbol table of this object's type.
    #[inline]
    pub fn table(&self) -> TableRef {
        self.sp.table
    }
    /// python `vol.offset`.
    #[inline]
    pub fn offset(&self) -> u64 {
        self.addr
    }
    /// python `vol.size`.
    #[inline]
    pub fn size(&self) -> u64 {
        self.sp.table.size_of(self.ty)
    }
    /// python `vol.type_name` without the `table!` prefix (`"_EPROCESS"`, `"unsigned long"`,
    /// `"pointer"`, `"array"`, ...).
    pub fn type_name(&self) -> String {
        self.sp.table.type_name(self.ty)
    }
    /// python `vol.type_name` including the table name (`"symbol_table_name1!_EPROCESS"`).
    pub fn full_type_name(&self) -> String {
        format!("{}!{}", self.sp.table.name(), self.type_name())
    }
    fn kind_name(&self) -> &'static str {
        match self.ty {
            Ty::Void | Ty::Function => "Void",
            Ty::Int(p) => match p.kind {
                PrimKind::Bool => "Boolean",
                PrimKind::Char => "Char",
                _ => "Integer",
            },
            Ty::Float(_) => "Float",
            Ty::Pointer { .. } => "Pointer",
            Ty::Array { .. } => "Array",
            Ty::Enum(_) => "Enumeration",
            Ty::BitField { .. } => "BitField",
            Ty::Struct(i) => match self.sp.table.user_type_kind(i) {
                crate::symbols::UserKind::Union => "UnionType",
                crate::symbols::UserKind::Class => "ClassType",
                _ => "StructType",
            },
            Ty::String { .. } => "String",
            Ty::Bytes(_) => "Bytes",
            Ty::Unresolved(_) => "Reference",
        }
    }
    /// The struct name for struct/union/class objects (no allocation), else None.
    #[inline]
    pub fn struct_name(&self) -> Option<&'static str> {
        match self.ty {
            Ty::Struct(i) => {
                let t: TableRef = self.sp.table;
                Some(t.user_type_name(i))
            }
            _ => None,
        }
    }
    /// True for struct/union/class objects.
    pub fn is_struct(&self) -> bool {
        matches!(self.ty, Ty::Struct(_))
    }
    /// True for pointers.
    pub fn is_pointer(&self) -> bool {
        matches!(self.ty, Ty::Pointer { .. })
    }
    /// True for arrays.
    pub fn is_array(&self) -> bool {
        matches!(self.ty, Ty::Array { .. })
    }

    // ------------------------------------------------------------------ members

    /// python `obj.Member` (`AggregateType.__getattr__`). On a pointer, dereferences first
    /// (python `Pointer.__getattr__`). Missing member -> `Error::Symbol("AttributeError...")`.
    #[inline]
    pub fn m(&self, name: &str) -> Result<Obj> {
        match self.ty {
            Ty::Struct(ut) => match self.sp.table.member(ut, name) {
                Some(mem) => fix_ty(self.sp, mem.ty, self.addr.wrapping_add(mem.offset) & self.sp.layer_mask),
                None => Err(attr_err(self, name)),
            },
            Ty::Pointer { .. } => self.deref()?.m(name),
            _ => Err(attr_err(self, name)),
        }
    }

    /// Dotted member path: `obj.path("Pcb.DirectoryTableBase")` == `obj.m("Pcb")?.m("DirectoryTableBase")`.
    pub fn path(&self, path: &str) -> Result<Obj> {
        let mut o = *self;
        for part in path.split('.') {
            o = o.m(part)?;
        }
        Ok(o)
    }

    /// Shorthand for `self.path(path)?.int()?` (python `obj.A.B` used as an int).
    #[inline]
    pub fn int_at(&self, path: &str) -> Result<i128> {
        self.path(path)?.int()
    }
    /// Shorthand for `self.path(path)?.u64()?`.
    #[inline]
    pub fn u64_at(&self, path: &str) -> Result<u64> {
        self.path(path)?.u64()
    }

    /// python `has_member(name)` (pointers: whether the target type has it).
    pub fn has_member(&self, name: &str) -> bool {
        match self.ty {
            Ty::Struct(ut) => self.sp.table.member(ut, name).is_some(),
            Ty::Pointer { target, .. } => match fix_ty(self.sp.native_space(), self.sp.table.node(target), 0) {
                Ok(o) => o.has_member(name),
                Err(_) => false,
            },
            _ => false,
        }
    }

    /// python `has_valid_member(name)`: member exists and can be constructed (primitives are
    /// read, like python which reads them on attribute access).
    pub fn has_valid_member(&self, name: &str) -> bool {
        if !self.has_member(name) {
            return false;
        }
        match self.m(name) {
            Ok(o) => match o.ty {
                Ty::Int(_) | Ty::Float(_) | Ty::Pointer { .. } | Ty::Enum(_) | Ty::BitField { .. } => o.int().is_ok() || o.f64().is_ok(),
                Ty::String { .. } => o.string().is_ok(),
                Ty::Bytes(_) => o.bytes().is_ok(),
                _ => true,
            },
            Err(_) => false,
        }
    }

    /// python `has_valid_members([...])`.
    pub fn has_valid_members(&self, names: &[&str]) -> bool {
        names.iter().all(|n| self.has_valid_member(n))
    }

    /// python `get_type(type).relative_child_offset(member)` for this object's type.
    pub fn member_offset(&self, name: &str) -> Result<u64> {
        match self.ty {
            Ty::Struct(ut) => self.sp.table.member(ut, name).map(|m| m.offset).ok_or_else(|| attr_err(self, name)),
            _ => Err(attr_err(self, name)),
        }
    }

    /// Pre-resolved member access (see [`Field`]); no hashing.
    #[inline(always)]
    pub fn f(&self, f: &Field) -> Obj {
        Obj { sp: f.sp.unwrap_or(self.sp), ty: f.ty, addr: self.addr.wrapping_add(f.offset) & self.sp.layer_mask }
    }

    /// All members of a struct object, in ISF order: (name, object).
    pub fn members(&self) -> Vec<(&'static str, Obj)> {
        match self.ty {
            Ty::Struct(ut) => self
                .sp
                .table
                .members(ut)
                .filter_map(|m| fix_ty(self.sp, m.ty, self.addr.wrapping_add(m.offset) & self.sp.layer_mask).ok().map(|o| (m.name, o)))
                .collect(),
            _ => Vec::new(),
        }
    }

    // ------------------------------------------------------------------ casting

    /// python `obj.cast("type_name")` (same layer/offset; name from this object's table, or
    /// `table!name`).
    pub fn cast(&self, type_name: &str) -> Result<Obj> {
        let (sp, ty) = resolve_named(self.sp, type_name)?;
        Ok(Obj { sp, ty, addr: self.addr })
    }
    /// Cast to an explicit type of this object's table.
    #[inline]
    pub fn cast_ty(&self, ty: Ty) -> Obj {
        Obj { sp: self.sp, ty, addr: self.addr }
    }
    /// Cast to a type of another table (python `cast("pe1!_IMAGE_DOS_HEADER")`).
    pub fn cast_in(&self, table: TableRef, type_name: &str) -> Result<Obj> {
        let ty = table.get_type(type_name)?;
        Ok(Obj { sp: self.sp.with_table(table), ty, addr: self.addr })
    }
    /// python `cast("string", max_length=n, encoding=..., errors=...)` as an object.
    pub fn cast_string(&self, max_len: u64, enc: StrEnc, errors: StrErrors) -> Obj {
        self.cast_ty(Ty::String { max_len: max_len.min(u32::MAX as u64) as u32, enc, errors })
    }
    /// python `cast("bytes", length=n)`.
    pub fn cast_bytes(&self, len: u64) -> Obj {
        self.cast_ty(Ty::Bytes(len.min(u32::MAX as u64) as u32))
    }
    /// python `cast("array", count=n, subtype=<type>)`.
    pub fn cast_array(&self, count: u64, elem: Ty) -> Obj {
        let e = self.sp.table.intern(elem);
        self.cast_ty(Ty::Array { count: count.min(u32::MAX as u64) as u32, elem: e })
    }
    /// python `cast("array", count=n, subtype=table.get_type(name))`.
    pub fn cast_array_of(&self, count: u64, elem_type: &str) -> Result<Obj> {
        let elem = self.sp.table.get_type(elem_type)?;
        Ok(self.cast_array(count, elem))
    }
    /// python `cast("pointer", subtype=<type>)` (pointer of the table's native pointer size).
    pub fn cast_pointer_to(&self, target: Ty) -> Result<Obj> {
        let prim = match self.sp.table.get_type("pointer")? {
            Ty::Pointer { prim, .. } => prim,
            _ => return Err(Error::symbol("pointer")),
        };
        Ok(self.cast_ty(Ty::Pointer { prim, target: self.sp.table.intern(target) }))
    }
    /// `container_of`: the `type_name` object whose `member` lives at this object's address
    /// (python `linux.LinuxUtilities.container_of` / `obj.vol.offset - relative_child_offset`).
    pub fn container_of(&self, type_name: &str, member: &str) -> Result<Obj> {
        let (sp, ty) = resolve_named(self.sp, type_name)?;
        let off = match ty {
            Ty::Struct(ut) => sp.table.member(ut, member).map(|m| m.offset).ok_or_else(|| Error::Symbol(format!("AttributeError: {type_name} has no attribute: {member}")))?,
            _ => return Err(Error::Symbol(format!("{type_name} is not a struct"))),
        };
        Ok(Obj::new(sp, ty, self.addr.wrapping_sub(off)))
    }
    /// `container_of` for a pointer value (e.g. a `list_head.next`): the `type_name` object whose
    /// `member` is at `addr` in this object's space.
    pub fn container_at(&self, addr: u64, type_name: &str, member: &str) -> Result<Obj> {
        self.at_addr(addr).container_of(type_name, member)
    }

    /// Move this object to another space (python `context.object(type, layer_name=..., offset=obj.vol.offset)`).
    pub fn in_space(&self, sp: &'static Space) -> Obj {
        Obj::new(sp, self.ty, self.addr)
    }
    /// Same type at another address.
    #[inline]
    pub fn at_addr(&self, addr: u64) -> Obj {
        Obj::new(self.sp, self.ty, addr)
    }

    // ------------------------------------------------------------------ values

    #[inline]
    fn read_prim(&self, p: Prim) -> Result<i128> {
        let n = (p.size as usize).min(16);
        if n == 0 {
            return Ok(0);
        }
        let mut b = [0u8; 16];
        self.sp.layer.read(self.addr, &mut b[..n])?;
        Ok(p.decode_int(&b[..n]))
    }

    /// The python int value of an Integer/Char/Boolean/Pointer/Enumeration/BitField object.
    /// Pointers are masked with the native layer's address mask (python `Pointer._unmarshall`).
    #[inline]
    pub fn int(&self) -> Result<i128> {
        match self.ty {
            Ty::Int(p) => self.read_prim(p),
            Ty::Pointer { prim, .. } => {
                let mut p = prim;
                p.signed = false;
                Ok((self.read_prim(p)? as u128 as u64 & self.sp.native_mask) as i128)
            }
            Ty::Enum(i) => self.read_prim(self.sp.table.enum_base(i)),
            Ty::BitField { start, end, base } => {
                let v = self.read_prim(base)?;
                let mask = if end >= 127 { -1i128 } else { (1i128 << end) - 1 };
                Ok((v & mask) >> start)
            }
            Ty::Float(_) => Ok(self.f64()? as i128),
            _ => Err(Error::msg(format!("{} is not an integer type", self.type_name()))),
        }
    }
    /// `int()` as u64 (two's complement wrap for negative values).
    #[inline]
    pub fn u64(&self) -> Result<u64> {
        self.int().map(|v| v as u64)
    }
    /// `int()` as i64.
    #[inline]
    pub fn i64(&self) -> Result<i64> {
        self.int().map(|v| v as i64)
    }
    /// python truthiness of a primitive (`if obj:`): value != 0.
    #[inline]
    pub fn bool(&self) -> Result<bool> {
        self.int().map(|v| v != 0)
    }
    /// python `Pointer.get_raw_value()` (unmasked).
    pub fn raw_u64(&self) -> Result<u64> {
        match self.ty {
            Ty::Pointer { prim, .. } | Ty::Int(prim) => {
                let mut p = prim;
                p.signed = false;
                Ok(self.read_prim(p)? as u64)
            }
            _ => self.u64(),
        }
    }
    /// Float value.
    pub fn f64(&self) -> Result<f64> {
        match self.ty {
            Ty::Float(p) => {
                let n = p.size as usize;
                let mut b = [0u8; 8];
                if !(n == 2 || n == 4 || n == 8) {
                    return Err(Error::msg("Invalid float size"));
                }
                self.sp.layer.read(self.addr, &mut b[..n])?;
                let v = match (n, p.big_endian) {
                    (8, false) => f64::from_le_bytes(b),
                    (8, true) => f64::from_be_bytes(b),
                    (4, false) => f32::from_le_bytes(b[..4].try_into().unwrap()) as f64,
                    (4, true) => f32::from_be_bytes(b[..4].try_into().unwrap()) as f64,
                    (_, big) => {
                        let h = if big { u16::from_be_bytes([b[0], b[1]]) } else { u16::from_le_bytes([b[0], b[1]]) };
                        half_to_f64(h)
                    }
                };
                Ok(v)
            }
            _ => self.int().map(|v| v as f64),
        }
    }

    /// python `Enumeration.description` / `lookup()`: the first constant name with this value;
    /// `Err` (python `ValueError`) when the value is not a choice.
    pub fn description(&self) -> Result<&'static str> {
        match self.ty {
            Ty::Enum(i) => {
                let v = self.int()?;
                let t: TableRef = self.sp.table;
                t.enum_lookup(i, v).ok_or_else(|| Error::msg("The value of the enumeration is outside the possible choices"))
            }
            _ => Err(Error::msg("not an enumeration")),
        }
    }
    /// python `Enumeration.is_valid_choice`.
    pub fn is_valid_choice(&self) -> bool {
        self.description().is_ok()
    }
    /// python `enum.CONSTANT` (value of a named choice).
    pub fn enum_value(&self, name: &str) -> Result<i64> {
        match self.ty {
            Ty::Enum(i) => self.sp.table.enum_value(i, name).ok_or_else(|| attr_err(self, name)),
            _ => Err(attr_err(self, name)),
        }
    }

    /// python `str(String object)`: read `max_length` bytes (strict), decode, cut at NUL.
    /// For `Array` of chars, decodes the whole array (utf-8, errors="replace").
    pub fn string(&self) -> Result<String> {
        match self.ty {
            Ty::String { max_len, enc, errors } => {
                if max_len == 0 {
                    return Ok(String::new());
                }
                let data = self.sp.layer.read_vec(self.addr, max_len as usize)?;
                strings::decode_cstring(&data, enc, errors)
            }
            Ty::Array { count, .. } => {
                let data = self.sp.layer.read_vec(self.addr, self.size() as usize)?;
                let _ = count;
                strings::decode_cstring(&data, StrEnc::Utf8, StrErrors::Replace)
            }
            Ty::Bytes(_) => {
                let b = self.bytes()?;
                strings::decode_cstring(&b, StrEnc::Latin1, StrErrors::Strict)
            }
            _ => Err(Error::msg(format!("{} is not a string", self.type_name()))),
        }
    }
    /// Shorthand: `cast("string", max_length=n, encoding=enc, errors=errs)` then `str()`.
    pub fn read_string(&self, max_len: u64, encoding: &str, errors: &str) -> Result<String> {
        self.cast_string(max_len, strings::parse_encoding(encoding), strings::parse_errors(errors)).string()
    }
    /// python `bytes(Bytes object)` / raw bytes of any object (`size()` bytes, strict read).
    pub fn bytes(&self) -> Result<Vec<u8>> {
        let n = self.size() as usize;
        if n == 0 {
            return Ok(Vec::new());
        }
        self.sp.layer.read_vec(self.addr, n)
    }

    // ------------------------------------------------------------------ pointers

    /// python `Pointer.dereference()`: an object of the target type at the pointer value, on
    /// the native layer.
    #[inline]
    pub fn deref(&self) -> Result<Obj> {
        match self.ty {
            Ty::Pointer { target, .. } => {
                let v = self.u64()?;
                let nsp = self.sp.native_space();
                fix_ty(nsp, self.sp.table.node(target), v & nsp.layer_mask)
            }
            _ => Err(Error::msg(format!("{} is not a pointer", self.type_name()))),
        }
    }
    /// python `Pointer.dereference(layer_name)`: dereference onto another layer.
    pub fn deref_on(&self, layer: LayerRef) -> Result<Obj> {
        match self.ty {
            Ty::Pointer { target, .. } => {
                let v = self.u64()?;
                let sp = Space::on(layer, self.sp.table);
                fix_ty(sp, self.sp.table.node(target), v & sp.layer_mask)
            }
            _ => Err(Error::msg(format!("{} is not a pointer", self.type_name()))),
        }
    }
    /// The pointer's target type.
    pub fn target_ty(&self) -> Option<Ty> {
        match self.ty {
            Ty::Pointer { target, .. } => Some(self.sp.table.node(target)),
            _ => None,
        }
    }
    /// python `Pointer.is_readable()`: `native.is_valid(value, subtype.size)`.
    pub fn is_readable(&self) -> bool {
        match self.ty {
            Ty::Pointer { target, .. } => {
                let Ok(v) = self.u64() else { return false };
                let size = self.sp.table.size_of(self.sp.table.node(target));
                self.sp.native.is_valid(v, size)
            }
            _ => self.sp.layer.is_valid(self.addr, self.size()),
        }
    }
    /// Whether the object's own bytes are readable (`layer.is_valid(offset, size)`).
    pub fn is_valid_addr(&self) -> bool {
        self.sp.layer.is_valid(self.addr, self.size().max(1))
    }

    // ------------------------------------------------------------------ arrays

    /// Array element count (python `vol.count` / `len(array)`); 0 for non-arrays.
    pub fn count(&self) -> u64 {
        match self.ty {
            Ty::Array { count, .. } => count as u64,
            _ => 0,
        }
    }
    /// Same array with another count (python `array.count = n`).
    pub fn with_count(&self, count: u64) -> Obj {
        match self.ty {
            Ty::Array { elem, .. } => self.cast_ty(Ty::Array { count: count.min(u32::MAX as u64) as u32, elem }),
            _ => *self,
        }
    }
    /// Element type of an array.
    pub fn elem_ty(&self) -> Option<Ty> {
        match self.ty {
            Ty::Array { elem, .. } => Some(self.sp.table.node(elem)),
            _ => None,
        }
    }
    /// python `array[i]` (no bounds check against count, like indexing a python range would;
    /// returns Err for i >= count).
    pub fn at(&self, i: u64) -> Result<Obj> {
        match self.ty {
            Ty::Array { count, elem } => {
                if i >= count as u64 {
                    return Err(Error::msg("IndexError: array index out of range"));
                }
                let et = self.sp.table.node(elem);
                let es = self.sp.table.size_of(et);
                fix_ty(self.sp, et, self.addr.wrapping_add(es.wrapping_mul(i)) & self.sp.layer_mask)
            }
            _ => Err(Error::msg(format!("{} is not an array", self.type_name()))),
        }
    }
    /// Iterate the elements of an array.
    pub fn elements(&self) -> impl Iterator<Item = Obj> + '_ {
        let n = self.count();
        (0..n).filter_map(move |i| self.at(i).ok())
    }
    /// Read all integer elements of an array (one read for the whole array).
    pub fn ints(&self) -> Result<Vec<i128>> {
        match self.ty {
            Ty::Array { count, elem } => match self.sp.table.node(elem) {
                Ty::Int(p) => {
                    let sz = p.size as usize;
                    let data = self.sp.layer.read_vec(self.addr, sz * count as usize)?;
                    Ok(data.chunks_exact(sz.max(1)).map(|c| p.decode_int(c)).collect())
                }
                _ => self.elements().map(|e| e.int()).collect(),
            },
            _ => Err(Error::msg("not an array")),
        }
    }
}

fn half_to_f64(h: u16) -> f64 {
    let sign = if h & 0x8000 != 0 { -1.0 } else { 1.0 };
    let exp = ((h >> 10) & 0x1f) as i32;
    let frac = (h & 0x3ff) as f64;
    match exp {
        0 => sign * frac * 2f64.powi(-24),
        31 => {
            if frac == 0.0 {
                sign * f64::INFINITY
            } else {
                f64::NAN
            }
        }
        e => sign * (1.0 + frac / 1024.0) * 2f64.powi(e - 15),
    }
}

/// Resolve an `Unresolved` type (cross-table `table!Type` references) into (space, type).
#[inline]
fn fix_ty(sp: &'static Space, ty: Ty, addr: u64) -> Result<Obj> {
    match ty {
        Ty::Unresolved(i) => {
            let name = sp.table.unresolved_name(i);
            match resolve_ref(sp.table, name) {
                Some((t, ty)) => {
                    let sp2 = sp.with_table(t);
                    Ok(Obj { sp: sp2, ty, addr: addr & sp2.layer_mask })
                }
                None => Err(Error::Symbol(format!("Unknown symbol: {name}"))),
            }
        }
        _ => Ok(Obj { sp, ty, addr }),
    }
}

/// Resolve `type_name` (or `table!type_name`) relative to `sp`'s table.
fn resolve_named(sp: &'static Space, type_name: &str) -> Result<(&'static Space, Ty)> {
    if type_name.contains('!') {
        let (t, ty) = resolve_ref(sp.table, type_name).ok_or_else(|| Error::Symbol(format!("Unknown symbol: {type_name}")))?;
        return Ok((sp.with_table(t), ty));
    }
    let ty = sp.table.get_type(type_name)?;
    Ok((sp, ty))
}

/// A pre-resolved member (offset + type) for hot loops:
///
/// ```ignore
/// let pid = Field::new(k.table, "_EPROCESS", "UniqueProcessId")?;
/// for p in procs { let v = p.f(&pid).u64()?; }
/// ```
#[derive(Clone, Copy)]
pub struct Field {
    pub offset: u64,
    pub ty: Ty,
    /// Set when the member's type lives in another table (cross-table reference).
    sp: Option<&'static Space>,
}

impl Field {
    /// Resolve `type_name.member` in `table`.
    pub fn new(table: TableRef, type_name: &str, member: &str) -> Result<Field> {
        let ut = table.user_type(type_name).ok_or_else(|| Error::Symbol(format!("Unknown symbol: {type_name}")))?;
        let m = table.member(ut, member).ok_or_else(|| Error::Symbol(format!("AttributeError: {type_name} has no attribute: {member}")))?;
        Ok(Field { offset: m.offset, ty: m.ty, sp: None })
    }
    /// Resolve a dotted path (`"Pcb.DirectoryTableBase"`); offsets add up (no pointers).
    pub fn path(table: TableRef, type_name: &str, path: &str) -> Result<Field> {
        let mut ty = table.get_type(type_name)?;
        let mut off = 0u64;
        for part in path.split('.') {
            let ut = match ty {
                Ty::Struct(ut) => ut,
                _ => return Err(Error::Symbol(format!("AttributeError: no attribute {part}"))),
            };
            let m = table.member(ut, part).ok_or_else(|| Error::Symbol(format!("AttributeError: no attribute {part}")))?;
            off += m.offset;
            ty = m.ty;
        }
        Ok(Field { offset: off, ty, sp: None })
    }
}

/// A module (python `contexts.Module`): a symbol table bound to a layer at a base offset.
/// Symbol addresses are relative to `offset`.
#[derive(Clone, Copy)]
pub struct Module {
    /// layer + native layer + table
    pub sp: &'static Space,
    /// base address (python `module.offset`)
    pub offset: u64,
}

impl std::fmt::Debug for Module {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Module({} @ {:#x} on {})", self.sp.table.name(), self.offset, self.sp.layer.name())
    }
}

impl Module {
    pub fn new(layer: LayerRef, table: TableRef, offset: u64) -> Module {
        Module { sp: Space::on(layer, table), offset }
    }
    /// The module's symbol table.
    #[inline]
    pub fn table(&self) -> TableRef {
        self.sp.table
    }
    /// The module's layer (python `module.layer_name`).
    #[inline]
    pub fn layer(&self) -> LayerRef {
        self.sp.layer
    }
    /// python `module.symbol_table_name`.
    pub fn symbol_table_name(&self) -> &str {
        self.sp.table.name()
    }
    /// python `module.object(object_type, offset)` (offset relative to the module base).
    pub fn object(&self, type_name: &str, offset: u64) -> Result<Obj> {
        Obj::named(self.sp, type_name, self.offset.wrapping_add(offset))
    }
    /// python `module.object(object_type, offset, absolute=True)`.
    pub fn object_abs(&self, type_name: &str, addr: u64) -> Result<Obj> {
        Obj::named(self.sp, type_name, addr)
    }
    /// python `module.object(..., layer_name=other)` (absolute address on another layer,
    /// pointers still native to the module's layer).
    pub fn object_on(&self, layer: LayerRef, type_name: &str, addr: u64) -> Result<Obj> {
        Obj::named(Space::get(layer, self.sp.native, self.sp.table), type_name, addr)
    }
    /// python `module.object_from_symbol(name)` (uses the symbol's type).
    pub fn object_from_symbol(&self, name: &str) -> Result<Obj> {
        let s = self.sp.table.get_symbol(name)?;
        let ty = s.ty.ok_or_else(|| Error::msg(format!("Symbol {name} has no associated type and no object_type specified")))?;
        fix_ty(self.sp, ty, self.offset.wrapping_add(s.address) & self.sp.layer_mask)
    }
    /// python `module.get_symbol(name)` (address relative to the base).
    pub fn get_symbol(&self, name: &str) -> Result<crate::symbols::Symbol<'static>> {
        let t: TableRef = self.sp.table;
        t.get_symbol(name)
    }
    /// Absolute address of a symbol (`module.offset + get_symbol(name).address`).
    pub fn symbol_addr(&self, name: &str) -> Result<u64> {
        Ok(self.offset.wrapping_add(self.get_symbol(name)?.address))
    }
    /// python `module.has_symbol(name)`.
    pub fn has_symbol(&self, name: &str) -> bool {
        self.sp.table.has_symbol(name)
    }
    /// python `module.get_type(name)`.
    pub fn get_type(&self, name: &str) -> Result<Ty> {
        self.sp.table.get_type(name)
    }
    /// python `module.has_type(name)`.
    pub fn has_type(&self, name: &str) -> bool {
        self.sp.table.has_type(name)
    }
    /// python `module.get_enumeration(name)`.
    pub fn get_enumeration(&self, name: &str) -> Result<u32> {
        self.sp.table.enumeration(name).ok_or_else(|| Error::Symbol(format!("Unknown enumeration: {name}")))
    }
    /// python `get_type(t).relative_child_offset(member)`.
    pub fn offset_of(&self, type_name: &str, member: &str) -> Result<u64> {
        self.sp.table.offset_of(type_name, member)
    }
    /// python `get_type(t).size`.
    pub fn size_of(&self, type_name: &str) -> Result<u64> {
        Ok(self.sp.table.size_of(self.sp.table.get_type(type_name)?))
    }
    /// python `get_symbols_by_absolute_location(offset, size)`.
    pub fn symbols_at(&self, addr: u64, size: u64) -> Vec<&'static str> {
        let t: TableRef = self.sp.table;
        t.symbols_at(addr.wrapping_sub(self.offset), size)
    }
    /// `symbols_at(addr, 0)` without building the table's address index (linear scan; for a
    /// few lookups).
    pub fn symbols_at_exact(&self, addr: u64) -> Vec<&'static str> {
        let t: TableRef = self.sp.table;
        t.symbols_at_exact(addr.wrapping_sub(self.offset))
    }
    /// A module on another layer (e.g. a process layer) with the same table and base.
    pub fn on_layer(&self, layer: LayerRef) -> Module {
        Module { sp: self.sp.with_layer(layer), offset: self.offset }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layers::Mapping;
    use crate::symbols::isf::{BuildOptions, load_table};

    /// A little-endian memory buffer layer with a 48-bit address space (like Intel32e).
    struct Mem(Vec<u8>);
    impl Layer for Mem {
        fn name(&self) -> &str {
            "mem"
        }
        fn max_address(&self) -> u64 {
            (1 << 48) - 1
        }
        fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
            let a = addr as usize;
            match self.0.get(a..a + buf.len()) {
                Some(s) => {
                    buf.copy_from_slice(s);
                    Ok(())
                }
                None => Err(Error::invalid(addr)),
            }
        }
        fn is_valid(&self, addr: u64, len: u64) -> bool {
            addr.checked_add(len).is_some_and(|e| e <= self.0.len() as u64)
        }
        fn mapping(&self, addr: u64, len: u64, f: &mut dyn FnMut(Mapping) -> bool) {
            f(Mapping { offset: addr, len, mapped: addr });
        }
    }

    const ISF: &str = r#"{
      "metadata": {"format": "6.1.0"},
      "base_types": {
        "unsigned long": {"kind": "int", "size": 4, "signed": false, "endian": "little"},
        "long": {"kind": "int", "size": 4, "signed": true, "endian": "little"},
        "unsigned char": {"kind": "char", "size": 1, "signed": false, "endian": "little"},
        "unsigned short": {"kind": "int", "size": 2, "signed": false, "endian": "little"},
        "pointer": {"kind": "int", "size": 8, "signed": false, "endian": "little"},
        "void": {"kind": "void", "size": 0, "signed": false, "endian": "little"}
      },
      "enums": {"E": {"base": "long", "size": 4, "constants": {"A": 1, "B": 2, "C": 1}}},
      "user_types": {
        "_S": {"kind": "struct", "size": 40, "fields": {
            "u": {"offset": 0, "type": {"kind": "base", "name": "unsigned long"}},
            "s": {"offset": 4, "type": {"kind": "base", "name": "long"}},
            "p": {"offset": 8, "type": {"kind": "pointer", "subtype": {"kind": "struct", "name": "_S"}}},
            "arr": {"offset": 16, "type": {"kind": "array", "count": 4, "subtype": {"kind": "base", "name": "unsigned char"}}},
            "bf": {"offset": 20, "type": {"kind": "bitfield", "bit_position": 3, "bit_length": 5, "type": {"kind": "base", "name": "long"}}},
            "e": {"offset": 24, "type": {"kind": "enum", "name": "E"}},
            "name": {"offset": 28, "type": {"kind": "array", "count": 8, "subtype": {"kind": "base", "name": "unsigned char"}}}
        }}
      },
      "symbols": {}
    }"#;

    fn setup() -> (&'static Space, Obj) {
        let mut m = vec![0u8; 0x100];
        m[0..4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        m[4..8].copy_from_slice(&(-2i32).to_le_bytes());
        // pointer with bits above 48 set: python masks with the native layer's address mask
        m[8..16].copy_from_slice(&0xFFFF_0000_0000_0040u64.to_le_bytes());
        m[16..20].copy_from_slice(&[1, 2, 3, 4]);
        m[20..24].copy_from_slice(&(-1i32).to_le_bytes());
        m[24..28].copy_from_slice(&3i32.to_le_bytes());
        m[28..36].copy_from_slice(b"ab\xffcd\0zz");
        let layer = leak_layer(Arc::new(Mem(m)));
        let t = crate::symbols::register(load_table(ISF.as_bytes(), "t", "test", &BuildOptions::default()).unwrap(), "objtest");
        let sp = Space::on(layer, t);
        (sp, Obj::named(sp, "_S", 0).unwrap())
    }

    #[test]
    fn obj_is_small() {
        assert_eq!(std::mem::size_of::<Obj>(), 32);
    }

    #[test]
    fn primitives_follow_python() {
        let (_, s) = setup();
        assert_eq!(s.m("u").unwrap().int().unwrap(), 0xFFFF_FFFF);
        assert_eq!(s.m("s").unwrap().int().unwrap(), -2);
        // pointer value masked to 48 bits
        assert_eq!(s.m("p").unwrap().u64().unwrap(), 0x40);
        assert_eq!(s.m("p").unwrap().raw_u64().unwrap(), 0xFFFF_0000_0000_0040);
        // deref + auto-deref member access
        let d = s.m("p").unwrap().deref().unwrap();
        assert_eq!(d.addr, 0x40);
        assert_eq!(s.m("p").unwrap().m("u").unwrap().addr, 0x40);
        // bitfield on a signed base: (v & ((1 << 8) - 1)) >> 3
        assert_eq!(s.m("bf").unwrap().int().unwrap(), 0x1F);
        // enum: value outside the choices -> description() errors, inverse keeps first name
        let e = s.m("e").unwrap();
        assert_eq!(e.int().unwrap(), 3);
        assert!(e.description().is_err());
        assert_eq!(e.enum_value("C").unwrap(), 1);
        assert_eq!(e.table().enum_lookup(0, 1), Some("A"));
        // arrays
        let a = s.m("arr").unwrap();
        assert_eq!(a.count(), 4);
        assert_eq!(a.ints().unwrap(), vec![1, 2, 3, 4]);
        assert_eq!(a.at(3).unwrap().int().unwrap(), 4);
        assert!(a.at(4).is_err());
        // strings: decode with replace then cut at NUL
        let n = s.m("name").unwrap();
        assert_eq!(n.read_string(8, "utf-8", "replace").unwrap(), "ab\u{FFFD}cd");
        assert!(n.read_string(8, "utf-8", "strict").is_err());
        assert_eq!(crate::objects::util::array_to_string(&n, None).unwrap(), "ab");
        // missing member / invalid read
        assert!(s.m("nope").is_err());
        assert!(!s.has_member("nope"));
        assert!(s.at_addr(0x1000).m("u").unwrap().int().unwrap_err().is_invalid_address());
        // Field
        let f = Field::new(s.table(), "_S", "s").unwrap();
        assert_eq!(s.f(&f).int().unwrap(), -2);
        assert_eq!(s.member_offset("e").unwrap(), 24);
        assert_eq!(s.size(), 40);
    }
}
