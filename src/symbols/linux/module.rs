//! python `symbols/linux/extensions/__init__.py` class extensions for kernel modules and kernel
//! symbol lookups, as the [`ModuleExt`] trait on [`Obj`] (method names follow python):
//!
//!   * `module`: [`module_is_valid`], `get_module_base`, `get_init_size`, `get_core_size`,
//!     `get_core_text_size`, `get_module_core`, `get_module_init`, `get_name`,
//!     `number_of_sections`, `get_sections`, `get_symbols` ([`ModuleSymtab`] of [`ElfSym`]),
//!     `get_symbols_names_and_addresses`, `get_module_address_boundaries`, `get_symbol`,
//!     `get_symbol_by_address`, `section_symtab` / `num_symtab` / `section_strtab` /
//!     `section_typetab`, `get_symbol_type`;
//!   * `kobject.reference_count`;
//!   * `bpf_prog`: `get_type`, `get_tag`, `get_name`, `bpf_jit_binary_hdr_address`,
//!     `get_address_region`; `bpf_prog_aux.get_name`;
//!   * `latch_tree_root.find`;
//!   * `kernel_symbol`: `get_name`, `get_value`, `get_namespace`;
//!   * `module_sect_attr.get_name`, `bin_attribute.get_name` / `address`.
//!
//! `get_name` dispatches on the struct name like python's per-class methods.
//!
//! Errors: where python raises, methods return `Err`; where python returns None they return
//! `Ok(None)`. python `TypeError`s (e.g. `kernel_symbol.get_name()` on kernels with
//! `name_offset`, where python calls `pointer_to_string` on an int) are `Err` too.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use super::constants::{ATTRIBUTE_NAME_MAX_SIZE, KSYM_NAME_LEN, MODULE_MAXIMUM_CORE_SIZE, MODULE_MAXIMUM_CORE_TEXT_SIZE, MODULE_MINIMUM_SIZE};
use super::vmlinux_of;
use crate::error::{Error, Result};
use crate::layers::LayerExt;
use crate::objects::util::{array_to_string, pointer_to_string, pointer_to_string_ex};
use crate::objects::{LayerRef, Obj};
use crate::symbols::Ty;

/// python `TypeError("pointer_to_string takes a Pointer")` (python passes an int).
fn pointer_to_string_type_error() -> Error {
    Error::msg("TypeError: pointer_to_string takes a Pointer")
}

/// Map python's "catch InvalidAddressException -> None".
#[inline]
fn none_on_invalid<T>(r: Result<T>) -> Result<Option<T>> {
    match r {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.is_invalid_address() => Ok(None),
        Err(e) => Err(e),
    }
}

/// An `Elf32_Sym` / `Elf64_Sym` entry of a kernel module's symbol table: python's `elf_sym`
/// object with `cached_strtab` set (as yielded by `module.get_symbols()`). Fields are read on
/// demand, one member at a time, like python's attribute access. A raw view (no `Obj`) of what
/// `symbols::linux::elf::ElfSym` models, for the kallsyms hot loops; the name logic is shared
/// (`elf::sym_name_at`).
#[derive(Clone, Copy)]
pub struct ElfSym {
    /// The layer of the module (python `vol.layer_name`).
    pub layer: LayerRef,
    /// Address of the entry (python `vol.offset`).
    pub addr: u64,
    /// `Elf64_Sym` (true) or `Elf32_Sym`.
    pub is64: bool,
    /// python `cached_strtab` (the module's `section_strtab` pointer value).
    pub strtab: u64,
}

impl ElfSym {
    /// python `st_name`.
    #[inline]
    pub fn st_name(&self) -> Result<u64> {
        Ok(self.layer.read_u32(self.addr)? as u64)
    }
    /// python `st_value`. python's `linux/elf.json` declares `Elf32_Sym.st_value` (offset 4)
    /// as `unsigned long long`, so on 32-bit kernels it is `st_value | st_size << 32` (python
    /// masks it with the layer's address mask where it wants the address).
    #[inline]
    pub fn st_value(&self) -> Result<u64> {
        self.layer.read_u64(self.addr.wrapping_add(if self.is64 { 8 } else { 4 }))
    }
    /// python `st_size`. `Elf32_Sym.st_size` (offset 8) is also an `unsigned long long` in
    /// python's `linux/elf.json`: on 32-bit kernels it is `st_size | st_info << 32 | st_other <<
    /// 40 | st_shndx << 48` (the garbage kallsyms sizes and the huge symbol ranges of python's
    /// module address lookups).
    #[inline]
    pub fn st_size(&self) -> Result<u64> {
        self.layer.read_u64(self.addr.wrapping_add(if self.is64 { 16 } else { 8 }))
    }
    /// python `st_info`.
    #[inline]
    pub fn st_info(&self) -> Result<u8> {
        self.layer.read_u8(self.addr.wrapping_add(if self.is64 { 4 } else { 12 }))
    }
    /// python `elf_sym.get_name()`: `None` when `st_name` cannot be read; otherwise the
    /// NUL-terminated name at `strtab + st_name` (padded read of `KSYM_NAME_LEN` bytes, utf-8
    /// with errors="replace"; may be empty).
    pub fn get_name(&self) -> Option<String> {
        let st_name = self.st_name().ok()?;
        Some(super::elf::sym_name_at(self.layer, self.strtab, st_name))
    }
    /// Like [`ElfSym::get_name`] but only reports whether the name is non-empty (python's
    /// `if not elf_sym.get_name()`), without decoding.
    pub fn has_name(&self) -> bool {
        let Ok(st_name) = self.st_name() else { return false };
        let mut b = [0u8; 1];
        self.layer.read_padded(self.strtab.wrapping_add(st_name), &mut b);
        b[0] != 0
    }
}

/// python `module.get_symbols()` result: the module's ELF symbol array (python's generator of
/// [`ElfSym`] objects with `cached_strtab` set).
#[derive(Clone, Copy)]
pub struct ModuleSymtab {
    /// The module's layer.
    pub layer: LayerRef,
    /// python `section_symtab` (address of the first entry, masked like the python array offset).
    pub symtab: u64,
    /// python `num_symtab`.
    pub count: u64,
    /// python `section_strtab` pointer value.
    pub strtab: u64,
    /// `Elf64_Sym` entries (24 bytes) vs `Elf32_Sym` (16 bytes).
    pub is64: bool,
}

impl ModuleSymtab {
    /// Size of one entry.
    #[inline]
    pub fn entry_size(&self) -> u64 {
        if self.is64 { 24 } else { 16 }
    }
    /// The `i`-th symbol (python `elf_syms[i]`).
    #[inline]
    pub fn sym(&self, i: u64) -> ElfSym {
        let addr = self.symtab.wrapping_add(i.wrapping_mul(self.entry_size())) & self.layer.address_mask();
        ElfSym { layer: self.layer, addr, is64: self.is64, strtab: self.strtab }
    }
    /// Iterate the symbols in python order.
    pub fn iter(&self) -> impl Iterator<Item = ElfSym> + '_ {
        (0..self.count).map(move |i| self.sym(i))
    }
}

/// python `module.is_valid()` with python's exceptions kept (`Err`).
pub fn module_is_valid_checked(m: &Obj) -> Result<bool> {
    if !m.layer().is_valid(m.addr, m.size()) {
        return Ok(false);
    }
    let core_size = m.get_core_size()?;
    let core_text_size = m.get_core_text_size()?;
    let init_size = m.get_init_size()?;
    if !(0 < core_text_size && core_text_size <= MODULE_MAXIMUM_CORE_TEXT_SIZE && 0 < core_size && core_size <= MODULE_MAXIMUM_CORE_SIZE && core_size + init_size >= MODULE_MINIMUM_SIZE) {
        return Ok(false);
    }
    // `self.mkobj and self.mkobj.mod and self.mkobj.mod.is_readable() and self.mkobj.mod == self.vol.offset`
    let modp = m.m("mkobj")?.m("mod")?;
    let v = modp.u64()?;
    if v == 0 || !modp.is_readable() || v != m.addr {
        return Ok(false);
    }
    Ok(true)
}

/// python `module.is_valid()` (python exceptions -> false).
pub fn module_is_valid(m: &Obj) -> bool {
    module_is_valid_checked(m).unwrap_or(false)
}

/// Kernel module / kernel symbol class extensions on [`Obj`] (see the module docs).
pub trait ModuleExt {
    // ---- module
    /// python `module.mod_mem_type.get(name)`: the `mod_mem_type` enum value (kernels >= 6.4).
    fn mod_mem_type(&self, name: &str) -> Option<i64>;
    /// python `module._get_mem_type(name)`: the `module_memory` element `mem[MOD_*]`.
    fn get_mem_type(&self, name: &str) -> Result<Obj>;
    /// python `module.get_module_base()` (the pointer value).
    fn get_module_base(&self) -> Result<u64>;
    /// python `module.get_init_size()`.
    fn get_init_size(&self) -> Result<i128>;
    /// python `module.get_core_size()`.
    fn get_core_size(&self) -> Result<i128>;
    /// python `module.get_core_text_size()`.
    fn get_core_text_size(&self) -> Result<i128>;
    /// python `module.get_module_core()` (a pointer object).
    fn get_module_core(&self) -> Result<Obj>;
    /// python `module.get_module_init()` (a pointer object).
    fn get_module_init(&self) -> Result<Obj>;
    /// python `get_name()` of `module`, `kernel_symbol`, `module_sect_attr`, `bin_attribute`,
    /// `bpf_prog` and `bpf_prog_aux` (dispatch on the struct name). `Ok(None)` where python
    /// returns None.
    fn get_name(&self) -> Result<Option<String>>;
    /// python `module.number_of_sections`.
    fn number_of_sections(&self) -> Result<i128>;
    /// python `module.get_sections()`: the array of section attribute objects
    /// (`module_sect_attr`), `number_of_sections` long (count 0 when python yields nothing);
    /// iterate it lazily with `.elements()` (the count comes from memory).
    fn get_sections(&self) -> Result<Obj>;
    /// python `module.get_symbols()`: `Ok(None)` where python's generator yields nothing
    /// (no strtab / no symbols).
    fn get_symbols(&self) -> Result<Option<ModuleSymtab>>;
    /// python `module.get_symbols_names_and_addresses(max_symbols)` streamed to `f(name,
    /// address)` (return false to stop). `Err` where python raises mid-iteration.
    fn for_each_symbol_name_and_address(&self, max_symbols: u64, f: &mut dyn FnMut(&str, u64) -> bool) -> Result<()>;
    /// python `module.get_symbols_names_and_addresses(max_symbols)` (default 4096) collected;
    /// a trailing `Err` means python raised there.
    fn get_symbols_names_and_addresses(&self, max_symbols: u64) -> Vec<Result<(String, u64)>>;
    /// python `module.get_module_address_boundaries()` (python's `st_value & mask + st_size`
    /// precedence kept for the maximum).
    fn get_module_address_boundaries(&self) -> Result<Option<(u64, u64)>>;
    /// python `module.get_symbol(name)`.
    fn get_symbol(&self, wanted_sym_name: &str) -> Result<Option<u64>>;
    /// python `module.get_symbol_by_address(address)`.
    fn get_symbol_by_address(&self, wanted_sym_address: u64) -> Result<Option<String>>;
    /// python `module.section_symtab` (a pointer object).
    fn section_symtab(&self) -> Result<Option<Obj>>;
    /// python `module.num_symtab`.
    fn num_symtab(&self) -> Result<Option<i128>>;
    /// python `module.section_strtab` (a pointer object).
    fn section_strtab(&self) -> Result<Option<Obj>>;
    /// python `module.section_typetab` (a pointer object).
    fn section_typetab(&self) -> Result<Option<Obj>>;
    /// python `module.get_symbol_type(symbol, symbol_index)`.
    fn get_symbol_type(&self, symbol: &ElfSym, symbol_index: u64) -> Result<Option<String>>;

    // ---- kobject
    /// python `kobject.reference_count()`.
    fn reference_count(&self) -> Result<i128>;

    // ---- bpf_prog
    /// python `bpf_prog.get_type()` (the program type enum name).
    fn get_type(&self) -> Result<Option<&'static str>>;
    /// python `bpf_prog.get_tag()` (hex string).
    fn get_tag(&self) -> Result<Option<String>>;
    /// python `bpf_prog.bpf_jit_binary_hdr_address()`.
    fn bpf_jit_binary_hdr_address(&self) -> Result<u64>;
    /// python `bpf_prog.get_address_region()` -> (start, end).
    fn get_address_region(&self) -> Result<(u64, u64)>;

    // ---- latch_tree_root
    /// python `latch_tree_root.find(key, comp_function)`: `comp(key, latch_tree_node)` returns
    /// `Some(<0 | 0 | >0)` or `None` (python None stops the search).
    fn find(&self, key: u64, comp: &mut dyn FnMut(u64, &Obj) -> Result<Option<i64>>) -> Result<Option<Obj>>;

    // ---- kernel_symbol
    /// python `kernel_symbol.get_value()`.
    fn get_value(&self) -> Result<Option<u64>>;
    /// python `kernel_symbol.get_namespace()`.
    fn get_namespace(&self) -> Result<Option<String>>;

    // ---- bin_attribute
    /// python `bin_attribute.address` (the `private` pointer object).
    fn address(&self) -> Result<Obj>;
}

/// `_offset_to_ptr(off)` of `kernel_symbol`.
fn ksym_offset_to_ptr(o: &Obj, off: i128) -> u64 {
    (o.addr as i128).wrapping_add(off) as u64
}

impl ModuleExt for Obj {
    fn mod_mem_type(&self, name: &str) -> Option<i64> {
        let t = self.table();
        let e = t.enumeration("mod_mem_type")?;
        t.enum_value(e, name)
    }

    fn get_mem_type(&self, name: &str) -> Result<Obj> {
        let idx = self.mod_mem_type(name).ok_or_else(|| Error::msg(format!("AttributeError: Unknown module memory type '{name}'")))?;
        let mem = self.m("mem")?;
        if !(0 <= idx && (idx as u64) < mem.count()) {
            return Err(Error::msg(format!("AttributeError: Invalid module memory type index '{idx}'")));
        }
        mem.at(idx as u64)
    }

    fn get_module_base(&self) -> Result<u64> {
        if self.has_member("mem") {
            self.get_mem_type("MOD_TEXT")?.m("base")?.u64()
        } else if self.has_member("core_layout") {
            self.m("core_layout")?.m("base")?.u64()
        } else if self.has_member("module_core") {
            self.m("module_core")?.u64()
        } else {
            Err(Error::msg("AttributeError: Unable to get module base"))
        }
    }

    fn get_init_size(&self) -> Result<i128> {
        if self.has_member("mem") {
            let a = self.get_mem_type("MOD_INIT_TEXT")?.m("size")?.int()?;
            let b = self.get_mem_type("MOD_INIT_DATA")?.m("size")?.int()?;
            let c = self.get_mem_type("MOD_INIT_RODATA")?.m("size")?.int()?;
            Ok(a + b + c)
        } else if self.has_member("init_layout") {
            self.m("init_layout")?.m("size")?.int()
        } else if self.has_member("init_size") {
            self.m("init_size")?.int()
        } else {
            Err(Error::msg("AttributeError: Unable to determine .init section size of module"))
        }
    }

    fn get_core_size(&self) -> Result<i128> {
        if self.has_member("mem") {
            let a = self.get_mem_type("MOD_TEXT")?.m("size")?.int()?;
            let b = self.get_mem_type("MOD_DATA")?.m("size")?.int()?;
            let c = self.get_mem_type("MOD_RODATA")?.m("size")?.int()?;
            let d = self.get_mem_type("MOD_RO_AFTER_INIT")?.m("size")?.int()?;
            Ok(a + b + c + d)
        } else if self.has_member("core_layout") {
            self.m("core_layout")?.m("size")?.int()
        } else if self.has_member("core_size") {
            self.m("core_size")?.int()
        } else {
            Err(Error::msg("AttributeError: Unable to determine core size of module"))
        }
    }

    fn get_core_text_size(&self) -> Result<i128> {
        if self.has_member("mem") {
            self.get_mem_type("MOD_TEXT")?.m("size")?.int()
        } else if self.has_member("core_layout") {
            self.m("core_layout")?.m("text_size")?.int()
        } else if self.has_member("core_text_size") {
            self.m("core_text_size")?.int()
        } else {
            Err(Error::msg("AttributeError: Unable to determine core text size of module"))
        }
    }

    fn get_module_core(&self) -> Result<Obj> {
        if self.has_member("mem") {
            self.get_mem_type("MOD_TEXT")?.m("base")
        } else if self.has_member("core_layout") {
            self.m("core_layout")?.m("base")
        } else if self.has_member("module_core") {
            self.m("module_core")
        } else {
            Err(Error::msg("AttributeError: Unable to get module core"))
        }
    }

    fn get_module_init(&self) -> Result<Obj> {
        if self.has_member("mem") {
            self.get_mem_type("MOD_INIT_TEXT")?.m("base")
        } else if self.has_member("init_layout") {
            self.m("init_layout")?.m("base")
        } else if self.has_member("module_init") {
            self.m("module_init")
        } else {
            Err(Error::msg("AttributeError: Unable to get module init"))
        }
    }

    fn get_name(&self) -> Result<Option<String>> {
        match self.struct_name() {
            Some("module") => none_on_invalid(self.m("name").and_then(|n| array_to_string(&n, None))),
            Some("kernel_symbol") => kernel_symbol_get_name(self),
            Some("module_sect_attr") => module_sect_attr_get_name(self),
            Some("bin_attribute") => none_on_invalid(self.m("attr").and_then(|a| a.m("name")).and_then(|n| pointer_to_string(&n, ATTRIBUTE_NAME_MAX_SIZE))),
            Some("bpf_prog") => {
                if !self.has_member("aux") {
                    return Ok(None);
                }
                match self.m("aux").and_then(|a| a.deref()) {
                    Ok(aux) => match bpf_prog_aux_get_name(&aux) {
                        Err(e) if e.is_invalid_address() => Ok(None),
                        r => r,
                    },
                    Err(e) if e.is_invalid_address() => Ok(None),
                    Err(e) => Err(e),
                }
            }
            Some("bpf_prog_aux") => bpf_prog_aux_get_name(self),
            _ => Err(Error::msg(format!("AttributeError: {} has no attribute: get_name", self.type_name()))),
        }
    }

    fn number_of_sections(&self) -> Result<i128> {
        let sa = self.m("sect_attrs")?;
        if sa.has_member("nsections") {
            return sa.m("nsections")?.int();
        }
        get_sect_count(&sa.m("grp")?)
    }

    fn get_sections(&self) -> Result<Obj> {
        let n = self.number_of_sections()?;
        let attrs = self.m("sect_attrs")?.m("attrs")?;
        let elem = attrs.elem_ty().ok_or_else(|| Error::msg("sect_attrs.attrs is not an array"))?;
        // python: context.object(array, layer_name=self.vol.layer_name, offset=attrs.vol.offset)
        let count = if n <= 0 { 0 } else { n.min(u32::MAX as i128) as u64 };
        Ok(Obj::new(self.sp, elem, attrs.addr).cast_array(count, elem))
    }

    fn get_symbols(&self) -> Result<Option<ModuleSymtab>> {
        let strtab = match self.section_strtab()? {
            Some(p) => p.u64()?,
            None => return Ok(None),
        };
        if strtab == 0 {
            return Ok(None);
        }
        let n = self.num_symtab()?.ok_or_else(|| Error::msg("TypeError: '<' not supported between instances of 'NoneType' and 'int'"))?;
        if n < 1 {
            return Ok(None);
        }
        let symtab = self.section_symtab()?.ok_or_else(|| Error::msg("TypeError: unsupported operand type(s) for &: 'NoneType' and 'int'"))?.u64()?;
        let layer = self.layer();
        Ok(Some(ModuleSymtab { layer, symtab: symtab & layer.address_mask(), count: n as u64, strtab, is64: self.table().is_64bit() }))
    }

    fn for_each_symbol_name_and_address(&self, max_symbols: u64, f: &mut dyn FnMut(&str, u64) -> bool) -> Result<()> {
        let Some(tab) = self.get_symbols()? else { return Ok(()) };
        let mask = self.layer().address_mask();
        for (i, sym) in tab.iter().enumerate() {
            if i as u64 > max_symbols {
                return Ok(());
            }
            let Some(name) = sym.get_name() else { continue };
            if name.is_empty() {
                continue;
            }
            let addr = sym.st_value()? & mask;
            if !f(&name, addr) {
                return Ok(());
            }
        }
        Ok(())
    }

    fn get_symbols_names_and_addresses(&self, max_symbols: u64) -> Vec<Result<(String, u64)>> {
        let mut out = Vec::new();
        if let Err(e) = self.for_each_symbol_name_and_address(max_symbols, &mut |n, a| {
            out.push(Ok((n.to_string(), a)));
            true
        }) {
            out.push(Err(e));
        }
        out
    }

    fn get_module_address_boundaries(&self) -> Result<Option<(u64, u64)>> {
        let Some(tab) = self.get_symbols()? else { return Ok(None) };
        // sorted(elf_syms, key=st_value) (stable): read every st_value
        let mut vals: Vec<(u64, u64)> = Vec::with_capacity(tab.count.min(1 << 20) as usize);
        for i in 0..tab.count {
            vals.push((tab.sym(i).st_value()?, i));
        }
        vals.sort_by_key(|v| v.0);
        if vals.len() < 2 {
            return Err(Error::msg("IndexError: list index out of range"));
        }
        let mask = self.layer().address_mask();
        let first = vals[1].0;
        let (last_val, last_idx) = vals[vals.len() - 1];
        let last_size = tab.sym(last_idx).st_size()?;
        let minimum = first & mask;
        // python: `last.st_value & layer.address_mask + last.st_size` (`+` binds tighter)
        let maximum = ((last_val as u128) & (mask as u128 + last_size as u128)) as u64;
        Ok(Some((minimum, maximum)))
    }

    fn get_symbol(&self, wanted_sym_name: &str) -> Result<Option<u64>> {
        let mut found = None;
        self.for_each_symbol_name_and_address(4096, &mut |n, a| {
            if n == wanted_sym_name {
                found = Some(a);
                return false;
            }
            true
        })?;
        Ok(found)
    }

    fn get_symbol_by_address(&self, wanted_sym_address: u64) -> Result<Option<String>> {
        let mut found = None;
        self.for_each_symbol_name_and_address(4096, &mut |n, a| {
            if a == wanted_sym_address {
                found = Some(n.to_string());
                return false;
            }
            true
        })?;
        Ok(found)
    }

    fn section_symtab(&self) -> Result<Option<Obj>> {
        mod_kallsyms_member(self, "kallsyms", "symtab", "symtab", "AttributeError: Unable to get symtab")
    }

    fn num_symtab(&self) -> Result<Option<i128>> {
        let r = if self.has_member("kallsyms") {
            self.m("kallsyms").and_then(|k| k.m("num_symtab")).and_then(|v| v.int())
        } else if self.has_member("num_symtab") {
            self.m("num_symtab").and_then(|v| v.int())
        } else {
            return Err(Error::msg("AttributeError: Unable to determine number of symbols"));
        };
        none_on_invalid(r)
    }

    fn section_strtab(&self) -> Result<Option<Obj>> {
        mod_kallsyms_member(self, "kallsyms", "strtab", "strtab", "AttributeError: Unable to get strtab")
    }

    fn section_typetab(&self) -> Result<Option<Obj>> {
        if self.has_member("kallsyms") && self.m("kallsyms")?.has_member("typetab") {
            return none_on_invalid(self.m("kallsyms").and_then(|k| k.m("typetab")).and_then(|p| p.u64().map(|_| p)));
        }
        Err(Error::msg("AttributeError: Unable to get typetab section, it needs a kernel >= 5.2"))
    }

    fn get_symbol_type(&self, symbol: &ElfSym, symbol_index: u64) -> Result<Option<String>> {
        let r = (|| -> Result<String> {
            if self.has_member("kallsyms") && self.m("kallsyms")?.has_member("typetab") {
                let tt = self.section_typetab()?.ok_or_else(|| Error::msg("TypeError: unsupported operand type(s) for +: 'NoneType' and 'int'"))?.u64()?;
                let b = self.layer().read_u8(tt.wrapping_add(symbol_index))?;
                // decode("utf-8", errors="ignore") of one byte
                Ok(if b < 0x80 { (b as char).to_string() } else { String::new() })
            } else {
                let c = symbol.st_info()?;
                Ok((c as char).to_string())
            }
        })();
        none_on_invalid(r)
    }

    fn reference_count(&self) -> Result<i128> {
        let refcnt = self.m("kref")?.m("refcount")?;
        if refcnt.has_member("counter") { refcnt.m("counter")?.int() } else { refcnt.m("refs")?.m("counter")?.int() }
    }

    fn get_type(&self) -> Result<Option<&'static str>> {
        if self.has_member("type") {
            return self.m("type")?.description().map(Some);
        }
        if self.has_member("aux") {
            let aux = self.m("aux")?;
            if aux.u64()? != 0 && aux.has_member("prog_type") {
                return aux.m("prog_type")?.description().map(Some);
            }
        }
        Ok(None)
    }

    fn get_tag(&self) -> Result<Option<String>> {
        if !self.has_member("tag") {
            return Ok(None);
        }
        let vm = vmlinux_of(self)?;
        let layer = vm.layer();
        let tag = self.m("tag")?;
        let (addr, size) = (tag.addr, tag.count());
        if !layer.is_valid(addr, size) {
            return Ok(None);
        }
        let b = layer.read_vec(addr, size as usize)?;
        Ok(Some(b.iter().map(|x| format!("{x:02x}")).collect()))
    }

    fn bpf_jit_binary_hdr_address(&self) -> Result<u64> {
        let vm = vmlinux_of(self)?;
        let t = vm.table();
        let ut = t.user_type("bpf_prog_aux").ok_or_else(|| Error::Symbol("Unknown symbol: bpf_prog_aux".into()))?;
        let has_pack = t.member(ut, "use_bpf_prog_pack").is_some();
        let addr_mask = if has_pack && self.m("aux")?.m("use_bpf_prog_pack")?.int()? != 0 {
            // _BPF_PROG_CHUNK_MASK & long_mask
            !63u64
        } else {
            !0xfffu64
        };
        Ok(self.m("bpf_func")?.u64()? & addr_mask)
    }

    fn get_address_region(&self) -> Result<(u64, u64)> {
        let vm = vmlinux_of(self)?;
        let start = self.bpf_jit_binary_hdr_address()?;
        let pages = if vm.has_type("bpf_binary_header") {
            vm.object_abs("bpf_binary_header", start)?.m("pages")?.int()?
        } else {
            vm.object_abs("unsigned int", start)?.int()?
        };
        Ok((start, (start as i128 + pages * 0x1000) as u64))
    }

    fn find(&self, key: u64, comp: &mut dyn FnMut(u64, &Obj) -> Result<Option<i64>>) -> Result<Option<Obj>> {
        let vm = vmlinux_of(self)?;
        let seq = self.m("seq")?;
        let sequence = if seq.has_member("seqcount") {
            seq.m("seqcount")?.m("sequence")?.int()?
        } else if seq.has_member("sequence") {
            seq.m("sequence")?.int()?
        } else {
            return Err(Error::msg("AttributeError: Unsupported sequence type implementation"));
        };
        let idx = (sequence & 1) as u64;
        let pointer_size = vm.table().size_of(vm.get_type("pointer")?);
        let member_offset = vm.offset_of("latch_tree_node", "node")? + idx * pointer_size;
        let mut ptr = self.m("tree")?.at(idx)?.m("rb_node")?;
        loop {
            let v = ptr.u64()?;
            if v == 0 || !ptr.is_readable() {
                return Ok(None);
            }
            let rb_node = ptr.deref()?;
            // python `_get_lt_node_from_rb_node(rb_node, idx)` (index * pointer size)
            let lt_node = vm.object_abs("latch_tree_node", rb_node.addr.wrapping_sub(member_offset))?;
            match comp(key, &lt_node)? {
                None => return Ok(None),
                Some(c) if c < 0 => ptr = rb_node.m("rb_left")?,
                Some(c) if c > 0 => ptr = rb_node.m("rb_right")?,
                Some(_) => return Ok(Some(lt_node)),
            }
        }
    }

    fn get_value(&self) -> Result<Option<u64>> {
        let r = if self.has_member("value_offset") {
            self.m("value_offset").and_then(|v| v.int()).map(|off| ksym_offset_to_ptr(self, off))
        } else if self.has_member("value") {
            self.m("value").and_then(|v| v.u64())
        } else {
            return Err(Error::msg("AttributeError: Unsupported kernel_symbol type implementation"));
        };
        none_on_invalid(r)
    }

    fn get_namespace(&self) -> Result<Option<String>> {
        if self.has_member("namespace_offset") {
            // python passes an int to pointer_to_string (after reading the offset)
            return match self.m("namespace_offset").and_then(|v| v.int()) {
                Ok(_) => Err(pointer_to_string_type_error()),
                Err(e) if e.is_invalid_address() => Ok(None),
                Err(e) => Err(e),
            };
        }
        if self.has_member("namespace") {
            return none_on_invalid(self.m("namespace").and_then(|p| pointer_to_string_ex(&p, KSYM_NAME_LEN, "ignore", "utf-8")));
        }
        Err(Error::msg("AttributeError: Unsupported kernel_symbol type implementation"))
    }

    fn address(&self) -> Result<Obj> {
        self.m("private")
    }
}

/// `section_symtab` / `section_strtab`: `kallsyms.<a>` or `<b>` pointer objects (the pointer
/// value is read like python's attribute access); InvalidAddress -> None.
fn mod_kallsyms_member(m: &Obj, kallsyms: &str, a: &str, b: &str, err: &str) -> Result<Option<Obj>> {
    let r = if m.has_member(kallsyms) {
        m.m(kallsyms).and_then(|k| k.m(a)).and_then(|p| p.u64().map(|_| p))
    } else if m.has_member(b) {
        m.m(b).and_then(|p| p.u64().map(|_| p))
    } else {
        return Err(Error::msg(err.to_string()));
    };
    none_on_invalid(r)
}

/// python `module._get_sect_count(grp)`.
fn get_sect_count(grp: &Obj) -> Result<i128> {
    let arr_ptr = if grp.has_member("bin_attrs") { grp.m("bin_attrs")? } else { grp.m("attrs")? };
    if !arr_ptr.is_readable() {
        return Ok(0);
    }
    let array = arr_ptr.deref()?;
    // utility.dynamically_sized_array_of_pointers(array, subtype, iterator_guard_value=100)
    let ptr_ty = array.table().get_type("pointer")?;
    let ptr_size = array.table().size_of(ptr_ty);
    let mut offset = array.addr;
    let mut n = 0i128;
    while n < 100 {
        let entry = Obj::new(array.sp, ptr_ty, offset);
        let v = match entry.u64() {
            Ok(v) => v,
            Err(e) if e.is_invalid_address() => break,
            Err(e) => return Err(e),
        };
        if !entry.is_readable() {
            break;
        }
        offset = offset.wrapping_add(ptr_size);
        n += 1;
        if v == 0 {
            break;
        }
    }
    Ok(n)
}

/// python `kernel_symbol.get_name()`.
fn kernel_symbol_get_name(o: &Obj) -> Result<Option<String>> {
    if o.has_member("name_offset") {
        // `_offset_to_ptr(self.name_offset)` is an int: pointer_to_string raises TypeError
        return match o.m("name_offset").and_then(|v| v.int()) {
            Ok(_) => Err(pointer_to_string_type_error()),
            Err(e) if e.is_invalid_address() => Ok(None),
            Err(e) => Err(e),
        };
    }
    if o.has_member("name") {
        return none_on_invalid(o.m("name").and_then(|p| pointer_to_string_ex(&p, KSYM_NAME_LEN, "ignore", "utf-8")));
    }
    Err(Error::msg("AttributeError: Unsupported kernel_symbol type implementation"))
}

/// python `module_sect_attr.get_name()`.
fn module_sect_attr_get_name(o: &Obj) -> Result<Option<String>> {
    if o.has_member("battr") {
        return none_on_invalid(o.m("battr").and_then(|b| b.m("attr")).and_then(|a| a.m("name")).and_then(|n| pointer_to_string(&n, ATTRIBUTE_NAME_MAX_SIZE)));
    }
    // python compares `self.name.vol.type_name` ("<table>!array" / "<table>!pointer") with
    // "array" / "pointer": never equal, so only the member access itself matters.
    let _ = o.m("name")?;
    if o.has_member("mattr") {
        return none_on_invalid(o.m("mattr").and_then(|m| m.m("attr")).and_then(|a| a.m("name")).and_then(|n| pointer_to_string(&n, ATTRIBUTE_NAME_MAX_SIZE)));
    }
    Ok(None)
}

/// python `bpf_prog_aux.get_name()`.
fn bpf_prog_aux_get_name(o: &Obj) -> Result<Option<String>> {
    if !o.has_member("name") {
        return Ok(None);
    }
    let r = (|| -> Result<Option<String>> {
        let name = o.m("name")?;
        // `if not self.name`: an Array's truthiness is its length
        if name.count() == 0 {
            return Ok(None);
        }
        Ok(Some(array_to_string(&name, None)?))
    })();
    match r {
        Err(e) if e.is_invalid_address() => Ok(None),
        r => r,
    }
}

/// Type of a pointer member's target (helper for callers needing `vol.subtype`).
pub fn pointer_target(o: &Obj) -> Option<Ty> {
    o.target_ty()
}
