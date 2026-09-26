//! python `symbols/linux/extensions/elf.py` (the `elf`, `elf_phdr`, `elf_sym` and
//! `elf_linkmap` classes) and `plugins/linux/elfs.py` `Elfs.elf_dump`.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! For plugin porters:
//!   * [`elf_table`] is python's `IntermediateSymbolTable.create(.., "linux", "elf",
//!     class_types=elf.class_types)`;
//!   * [`Elf::new`] is `context.object(elf_table + "!Elf", layer_name, offset)` followed by
//!     `is_valid()` (`Ok(None)` = the object is not valid);
//!   * [`Elf::get_program_headers`] yields [`Phdr`]s (python `elf_phdr` with `parent_e_type`,
//!     `parent_offset`, `type_prefix` attached) with [`Phdr::get_vaddr`] and
//!     [`Phdr::dynamic_sections`];
//!   * [`Elf::get_section_headers`], [`Elf::get_symbols`] ([`ElfSym::get_name`]),
//!     [`Elf::get_link_maps`] ([`LinkMap::get_name`]);
//!   * [`elf_sym_get_name`] is `elf_sym.get_name()` for symbols built elsewhere (kernel
//!     modules set `cached_strtab` themselves);
//!   * [`elf_dump`] is `Elfs.elf_dump`.
//!
//! Errors: `Err` where python raises (an `InvalidAddressException` surfaces as an `Err` with
//! `is_invalid_address()`); python's `ValueError` from an enumeration lookup
//! (`p_type.description`) is caught where python catches it.

use crate::context::Context;
use crate::error::{Error, Result};
use crate::objects::util::array_to_string;
use crate::objects::{LayerRef, Obj, Space};
use crate::symbols::{TableRef, Ty};
use crate::util::FxHashSet;
use std::io::Write;

/// python `linux_constants.ELF_MAX_EXTRACTION_SIZE`.
pub const ELF_MAX_EXTRACTION_SIZE: i128 = 1024 * 1024 * 1024 * 4 - 1;

/// python `linux_constants.KSYM_NAME_LEN` (`elf_sym._MAX_NAME_LENGTH`).
pub const KSYM_NAME_LEN: usize = 512;

/// The `linux/elf` ISF (python `IntermediateSymbolTable.create(ctx, path, "linux", "elf",
/// class_types=elf.class_types)`).
pub fn elf_table(ctx: &Context) -> Result<TableRef> {
    ctx.load_isf("linux/elf")
}

/// python `elf` object (an `Elf` struct at `offset` that redirects `e_*` to the matching
/// `Elf32_Ehdr` / `Elf64_Ehdr`).
#[derive(Clone, Copy)]
pub struct Elf {
    /// `"Elf32_"` / `"Elf64_"`.
    pub type_prefix: &'static str,
    /// python `_ei_class_size` (32 / 64).
    pub ei_class_size: u32,
    /// The header object (python `_hdr`); `e_*` members live here.
    pub hdr: Obj,
    /// python `_offset` (= `vol.offset`).
    pub offset: u64,
}

/// python `elf_phdr`: a program header plus the attributes `get_program_headers` attaches.
#[derive(Clone, Copy)]
pub struct Phdr {
    /// The `Elf32_Phdr` / `Elf64_Phdr` object.
    pub obj: Obj,
    /// `parent_e_type.description` (`None` where python's lookup raises ValueError).
    pub parent_e_type: Option<&'static str>,
    /// `parent_offset` (the ELF's base address).
    pub parent_offset: u64,
    /// `type_prefix` (`"Elf32_"` / `"Elf64_"`).
    pub type_prefix: &'static str,
}

impl std::ops::Deref for Phdr {
    type Target = Obj;
    fn deref(&self) -> &Obj {
        &self.obj
    }
}

/// python `elf_sym`: a symbol entry plus its `cached_strtab`.
#[derive(Clone, Copy)]
pub struct ElfSym {
    /// The `Elf32_Sym` / `Elf64_Sym` object.
    pub obj: Obj,
    /// python `cached_strtab` (address of the string table on the symbol's layer).
    pub cached_strtab: u64,
}

impl std::ops::Deref for ElfSym {
    type Target = Obj;
    fn deref(&self) -> &Obj {
        &self.obj
    }
}

impl ElfSym {
    /// python `elf_sym.get_name()`.
    pub fn get_name(&self) -> Result<Option<String>> {
        elf_sym_get_name(&self.obj, self.cached_strtab)
    }
}

/// python `elf_sym.get_name()` for a symbol object `sym` whose `cached_strtab` is `strtab`:
/// `None` when `st_name` is unreadable; else the NUL-terminated name read (padded) from
/// `strtab + st_name`, decoded as UTF-8 with replacement.
pub fn elf_sym_get_name(sym: &Obj, strtab: u64) -> Result<Option<String>> {
    let st_name = match sym.m("st_name")?.u64() {
        Ok(v) => v,
        Err(e) if e.is_invalid_address() => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut buf = [0u8; KSYM_NAME_LEN];
    sym.layer().read_padded(strtab.wrapping_add(st_name), &mut buf);
    let n = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Ok(Some(String::from_utf8_lossy(&buf[..n]).into_owned()))
}

/// python `elf_linkmap`: an `Elf32_LinkMap` / `Elf64_LinkMap` at [`LinkMap::offset`].
#[derive(Clone, Copy)]
pub struct LinkMap {
    /// The link map object (its `addr` is masked with the layer mask).
    pub obj: Obj,
    /// python `vol.offset` (the unmasked value the object was created at).
    pub offset: u64,
}

impl std::ops::Deref for LinkMap {
    type Target = Obj;
    fn deref(&self) -> &Obj {
        &self.obj
    }
}

impl LinkMap {
    /// `l_addr`.
    pub fn l_addr(&self) -> Result<u64> {
        self.obj.m("l_addr")?.u64()
    }
    /// `l_name` (address of the name string).
    pub fn l_name(&self) -> Result<u64> {
        self.obj.m("l_name")?.u64()
    }
    /// python `elf_linkmap.get_name()`: `None` when the 256 bytes at `l_name` cannot be read
    /// (strict read), else the NUL-terminated name decoded as UTF-8 with replacement.
    pub fn get_name(&self) -> Result<Option<String>> {
        let l_name = self.l_name()?;
        let mut buf = [0u8; 256];
        match self.obj.layer().read(l_name, &mut buf) {
            Ok(()) => {}
            Err(e) if e.is_invalid_address() => return Ok(None),
            Err(e) => return Err(e),
        }
        let n = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        Ok(Some(String::from_utf8_lossy(&buf[..n]).into_owned()))
    }
}

/// Where `DT_STRTAB` / `DT_SYMTAB` point and how many symbols python assumes
/// (python `elf._find_symbols` results).
#[derive(Clone, Copy, Debug)]
pub struct SymtabInfo {
    /// `_cached_symtab`.
    pub symtab: u64,
    /// `_cached_strtab`.
    pub strtab: u64,
    /// `_cached_numsyms`.
    pub numsyms: u64,
}

impl Elf {
    /// python `elf.__init__` + `is_valid()`: `Ok(None)` when the magic cannot be read or does
    /// not match (python leaves the object invalid); `Err` where python raises (an unreadable
    /// or unsupported `EI_CLASS`).
    pub fn new(layer: LayerRef, table: TableRef, offset: u64) -> Result<Option<Elf>> {
        let sp = Space::on(layer, table);
        let magic = match Obj::named(sp, "unsigned long", offset)?.int() {
            Ok(m) => m,
            Err(e) if e.is_invalid_address() => return Ok(None),
            Err(e) => return Err(e),
        };
        if magic != 0x464C_457F {
            return Ok(None);
        }
        let ei_class = Obj::named(sp, "unsigned char", offset.wrapping_add(4))?.int()?;
        let (type_prefix, ei_class_size) = match ei_class {
            1 => ("Elf32_", 32),
            2 => ("Elf64_", 64),
            v => return Err(Error::msg(format!("ValueError: Unsupported ei_class value {v}"))),
        };
        let hdr = Obj::named(sp, &format!("{type_prefix}Ehdr"), offset)?;
        Ok(Some(Elf { type_prefix, ei_class_size, hdr, offset }))
    }

    /// The ELF symbol table.
    #[inline]
    pub fn table(&self) -> TableRef {
        self.hdr.table()
    }

    /// The layer the ELF lives on (python `vol.layer_name`).
    #[inline]
    pub fn layer(&self) -> LayerRef {
        self.hdr.layer()
    }

    /// `<type_prefix><suffix>` type of the ELF table (e.g. `"Phdr"` -> `Elf64_Phdr`).
    fn prefixed(&self, suffix: &str) -> Result<Ty> {
        self.table().get_type(&format!("{}{}", self.type_prefix, suffix))
    }

    /// python `elf.get_program_headers()`: the `e_phnum` headers at `offset + e_phoff`, each
    /// with `parent_e_type = self.e_type` (read when the first header is produced, like
    /// python's cached member). A trailing `Err` means python raised there.
    pub fn get_program_headers(&self) -> Vec<Result<Phdr>> {
        let mut out = Vec::new();
        let r = (|| -> Result<()> {
            let phoff = self.hdr.m("e_phoff")?.u64()?;
            let phnum = self.hdr.m("e_phnum")?.u64()?;
            let ty = self.prefixed("Phdr")?;
            if phnum == 0 {
                return Ok(());
            }
            let e_type = self.hdr.m("e_type")?;
            e_type.int()?;
            let parent_e_type = e_type.description().ok();
            let sp = self.hdr.sp;
            let size = self.table().size_of(ty);
            let base = self.offset.wrapping_add(phoff);
            out.reserve(phnum as usize);
            for i in 0..phnum {
                let obj = Obj::new(sp, ty, base.wrapping_add(i.wrapping_mul(size)));
                out.push(Ok(Phdr { obj, parent_e_type, parent_offset: self.offset, type_prefix: self.type_prefix }));
            }
            Ok(())
        })();
        if let Err(e) = r {
            out.push(Err(e));
        }
        out
    }

    /// python `elf.get_section_headers()`: the `Elf*_Shdr` array (`e_shnum` entries at
    /// `offset + e_shoff`).
    pub fn get_section_headers(&self) -> Result<Obj> {
        let shoff = self.hdr.m("e_shoff")?.u64()?;
        let shnum = self.hdr.m("e_shnum")?.u64()?;
        let ty = self.prefixed("Shdr")?;
        Ok(Obj::new(self.hdr.sp, ty, self.offset.wrapping_add(shoff)).cast_array(shnum, ty))
    }

    /// python `elf.get_link_maps(kernel_symbol_table_name)`: for every `PT_DYNAMIC` header's
    /// `DT_PLTGOT` entry, follow the `link_map` pointer stored in the second GOT entry (a
    /// kernel `pointer`) along `l_next` (each link map once), handing each to `f` (python's
    /// `yield`). `f` returns `Ok(false)` to stop, `Err` to abort (an exception in python's
    /// consumer); the `Err` is returned. Other `Err`s are where python's generator raises.
    pub fn get_link_maps(&self, kernel_table: TableRef, f: &mut dyn FnMut(LinkMap) -> Result<bool>) -> Result<()> {
        let got_entry_size = (self.ei_class_size / 8) as u64;
        let layer = self.layer();
        let ptr_sp = Space::on(layer, kernel_table);
        let lm_ty = self.prefixed("LinkMap")?;
        let lm_sp = self.hdr.sp;
        let mut seen: FxHashSet<u64> = FxHashSet::default();
        for phdr in self.get_program_headers() {
            let phdr = phdr?;
            if !phdr.is_type("PT_DYNAMIC")? {
                continue;
            }
            for dsec in phdr.dynamic_sections()? {
                let dsec = dsec?;
                let d_tag = dsec.m("d_tag")?;
                d_tag.int()?;
                match d_tag.description() {
                    Ok("DT_PLTGOT") => {}
                    _ => continue,
                }
                let got_start = dsec.m("d_ptr")?.u64()?;
                // link_map is stored at the second GOT entry
                let link_map_addr = got_start.wrapping_add(got_entry_size);
                let link_map_ptr = Obj::named(ptr_sp, "pointer", link_map_addr)?.u64()?;
                if link_map_ptr == 0 {
                    continue;
                }
                let mut offset = link_map_ptr;
                while offset != 0 {
                    if !seen.insert(offset) {
                        break;
                    }
                    let lm = LinkMap { obj: Obj::new(lm_sp, lm_ty, offset), offset };
                    if !f(lm)? {
                        return Ok(());
                    }
                    offset = match lm.obj.m("l_next")?.u64() {
                        Ok(v) => v,
                        Err(e) if e.is_invalid_address() => break,
                        Err(e) => return Err(e),
                    };
                }
            }
        }
        Ok(())
    }

    /// python `elf._find_symbols()`: `DT_STRTAB` / `DT_SYMTAB` / `DT_SYMENT` of the first
    /// `PT_DYNAMIC` header. `Ok(None)` when one of them is missing or zero.
    pub fn find_symbols(&self) -> Result<Option<SymtabInfo>> {
        let (mut strtab, mut symtab, mut strent) = (0u64, 0u64, 0u64);
        for phdr in self.get_program_headers() {
            let phdr = phdr?;
            if !phdr.is_type("PT_DYNAMIC")? {
                continue;
            }
            for dsec in phdr.dynamic_sections()? {
                let dsec = dsec?;
                let d_tag = dsec.m("d_tag")?;
                d_tag.int()?;
                let slot = match d_tag.description() {
                    Ok("DT_STRTAB") => &mut strtab,
                    Ok("DT_SYMTAB") => &mut symtab,
                    Ok("DT_SYMENT") => &mut strent,
                    _ => continue,
                };
                *slot = dsec.m("d_ptr")?.u64()?;
            }
            break;
        }
        if strtab == 0 || symtab == 0 || strent == 0 {
            return Ok(None);
        }
        let numsyms = if symtab < strtab { (strtab - symtab) / strent } else { 1024 };
        Ok(Some(SymtabInfo { symtab, strtab, numsyms }))
    }

    /// python `elf.get_symbols()`: the `Elf*_Sym` entries of the dynamic symbol table (empty
    /// when [`Elf::find_symbols`] finds none), each with `cached_strtab` set.
    pub fn get_symbols(&self) -> Result<Vec<ElfSym>> {
        let Some(info) = self.find_symbols()? else { return Ok(Vec::new()) };
        let ty = self.prefixed("Sym")?;
        let size = self.table().size_of(ty);
        Ok((0..info.numsyms)
            .map(|i| ElfSym { obj: Obj::new(self.hdr.sp, ty, info.symtab.wrapping_add(i.wrapping_mul(size))), cached_strtab: info.strtab })
            .collect())
    }
}

impl Phdr {
    /// `self.p_type.description == name`; python's `ValueError` (unknown value) counts as
    /// "not equal"; an unreadable `p_type` is an `Err`.
    pub fn is_type(&self, name: &str) -> Result<bool> {
        let p_type = self.obj.m("p_type")?;
        p_type.int()?;
        Ok(p_type.description().is_ok_and(|d| d == name))
    }

    /// python `elf_phdr.get_vaddr()`: `p_vaddr`, plus `parent_offset` for `ET_DYN` objects.
    pub fn get_vaddr(&self) -> Result<u64> {
        let vaddr = self.obj.m("p_vaddr")?.u64()?;
        Ok(if self.parent_e_type == Some("ET_DYN") { self.parent_offset.wrapping_add(vaddr) } else { vaddr })
    }

    /// python `elf_phdr.dynamic_sections()`: up to 256 `Elf*_Dyn` entries starting at
    /// [`Phdr::get_vaddr`], ending after the first `d_tag == 0` (checked when the next entry
    /// is requested, like python's generator). Empty unless this is a `PT_DYNAMIC` header.
    pub fn dynamic_sections(&self) -> Result<DynIter> {
        if !self.is_type("PT_DYNAMIC")? {
            return Ok(DynIter { sp: self.obj.sp, ty: Ty::Void, start: 0, size: 0, i: 256, prev: None, done: true });
        }
        let start = self.get_vaddr()?;
        let ty = self.obj.table().get_type(&format!("{}Dyn", self.type_prefix))?;
        let size = self.obj.table().size_of(ty);
        Ok(DynIter { sp: self.obj.sp, ty, start, size, i: 0, prev: None, done: false })
    }
}

/// Lazy iterator of [`Phdr::dynamic_sections`] (yields `Err` once where python raises).
pub struct DynIter {
    sp: &'static Space,
    ty: Ty,
    start: u64,
    size: u64,
    i: u64,
    prev: Option<Obj>,
    done: bool,
}

impl Iterator for DynIter {
    type Item = Result<Obj>;
    fn next(&mut self) -> Option<Result<Obj>> {
        if self.done {
            return None;
        }
        if let Some(p) = self.prev.take() {
            match p.m("d_tag").and_then(|t| t.int()) {
                Ok(0) => {
                    self.done = true;
                    return None;
                }
                Ok(_) => {}
                Err(e) => {
                    self.done = true;
                    return Some(Err(e));
                }
            }
        }
        if self.i >= 256 {
            self.done = true;
            return None;
        }
        let o = Obj::new(self.sp, self.ty, self.start.wrapping_add(self.i.wrapping_mul(self.size)));
        self.i += 1;
        self.prev = Some(o);
        Some(Ok(o))
    }
}

/// python `Elfs.elf_dump(context, layer_name, elf_table_name, vma, task, open)`: write the ELF
/// mapped at `vma.vm_start` of `proc_layer` to `pid.<pid>.<comm>.<vm_start>.dmp`. Returns the
/// file's preferred name (what python prints from `preferred_filename` before closing),
/// `Ok(None)` where python returns None, `Err` where python raises.
pub fn elf_dump(ctx: &Context, proc_layer: LayerRef, elf_table: TableRef, vma: &Obj, task: &Obj) -> Result<Option<String>> {
    Ok(elf_dump_ex(ctx, proc_layer, elf_table, vma, task)?.map(|(preferred, _)| preferred))
}

/// [`elf_dump`] returning `(preferred name, final name)`: the final name is what python's
/// `preferred_filename` holds after `close()` (a `-N` suffix when the file already existed),
/// which `linux.elfs --dump` prints.
pub fn elf_dump_ex(ctx: &Context, proc_layer: LayerRef, elf_table: TableRef, vma: &Obj, task: &Obj) -> Result<Option<(String, String)>> {
    let vm_start = vma.m("vm_start")?.u64()?;
    let Some(elf) = Elf::new(proc_layer, elf_table, vm_start)? else { return Ok(None) };
    // sections: start -> size (python dict: later duplicates win)
    let mut sections: Vec<(u64, u64)> = Vec::new();
    for ph in elf.get_program_headers() {
        let ph = ph?;
        if !ph.is_type("PT_LOAD")? {
            continue;
        }
        let mut start = ph.m("p_vaddr")?.u64()? as i128;
        let size = ph.m("p_memsz")?.u64()? as i128;
        let mut end = start + size;
        if start % 0x1000 != 0 {
            start &= !0xfff;
        }
        if end % 0x1000 != 0 {
            end = (end & !0xfff) + 0x1000;
        }
        let real_size = end - start;
        if !(0..=ELF_MAX_EXTRACTION_SIZE).contains(&real_size) {
            return Err(Error::msg(format!("ValueError: The claimed size of the ELF is invalid: {real_size}")));
        }
        let start = start as u64;
        match sections.iter_mut().find(|(s, _)| *s == start) {
            Some(e) => e.1 = real_size as u64,
            None => sections.push((start, real_size as u64)),
        }
    }
    sections.sort_by_key(|s| s.0);
    let pid = task.m("pid")?.int()?;
    let comm = array_to_string(&task.m("comm")?, None)?;
    // not sanitized (python passes it straight to open(); a '/' in comm raises ValueError)
    let name = format!("pid.{pid}.{comm}.{vm_start:#x}.dmp");
    let (mut f, final_name) = ctx.create_output_file(&name)?;
    // stream the padded reads (python concatenates them in memory first)
    let mut buf = vec![0u8; 1 << 20];
    for (start, size) in sections {
        let mut done = 0u64;
        while done < size {
            let n = (size - done).min(buf.len() as u64) as usize;
            proc_layer.read_padded(vm_start.wrapping_add(start).wrapping_add(done), &mut buf[..n]);
            f.write_all(&buf[..n])?;
            done += n as u64;
        }
    }
    f.flush()?;
    Ok(Some((name, final_name)))
}
