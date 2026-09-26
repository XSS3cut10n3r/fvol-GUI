//! python `symbols/linux/extensions/elf.py` (`elf` class: header + program headers) and
//! `plugins/linux/elfs.py` `Elfs.elf_dump`, the pieces `linux.pslist --dump` needs (the
//! `linux.elfs` porter can extend this: section headers, symbols, link maps).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::{Error, Result};
use crate::objects::util::array_to_string;
use crate::objects::{LayerRef, Obj, Space};
use crate::symbols::TableRef;
use std::io::Write;

/// python `linux_constants.ELF_MAX_EXTRACTION_SIZE`.
pub const ELF_MAX_EXTRACTION_SIZE: i128 = 1024 * 1024 * 1024 * 4 - 1;

/// The `linux/elf` ISF (python `IntermediateSymbolTable.create(ctx, path, "linux", "elf",
/// class_types=elf.class_types)`).
pub fn elf_table(ctx: &Context) -> Result<TableRef> {
    ctx.load_isf("linux/elf")
}

/// python `elf` object (an `Elf` struct at `offset` that redirects `e_*` to the matching
/// `Elf32_Ehdr` / `Elf64_Ehdr`).
pub struct Elf {
    /// `"Elf32_"` / `"Elf64_"`.
    pub type_prefix: &'static str,
    /// python `_ei_class_size` (32 / 64).
    pub ei_class_size: u32,
    /// The header object.
    pub hdr: Obj,
    pub offset: u64,
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

    /// python `elf.get_program_headers()` (reads `e_type` per header like python's
    /// `prog_header.parent_e_type = self.e_type`). A trailing `Err` means python raised there.
    pub fn get_program_headers(&self) -> Vec<Result<Obj>> {
        let mut out = Vec::new();
        let r = (|| -> Result<()> {
            let phoff = self.hdr.m("e_phoff")?.u64()?;
            let phnum = self.hdr.m("e_phnum")?.u64()?;
            let first = Obj::named(self.hdr.sp, &format!("{}Phdr", self.type_prefix), self.offset.wrapping_add(phoff))?;
            let arr = first.cast_array(phnum, first.ty);
            for i in 0..phnum {
                let ph = arr.at(i)?;
                self.hdr.m("e_type")?.int()?;
                out.push(Ok(ph));
            }
            Ok(())
        })();
        if let Err(e) = r {
            out.push(Err(e));
        }
        out
    }
}

/// python `Elfs.elf_dump(context, layer_name, elf_table_name, vma, task, open)`: write the ELF
/// mapped at `vma.vm_start` of `proc_layer` to `pid.<pid>.<comm>.<vm_start>.dmp`. Returns the
/// file's preferred name (what python prints from `preferred_filename` before closing),
/// `Ok(None)` where python returns None, `Err` where python raises.
pub fn elf_dump(ctx: &Context, proc_layer: LayerRef, elf_table: TableRef, vma: &Obj, task: &Obj) -> Result<Option<String>> {
    let vm_start = vma.m("vm_start")?.u64()?;
    let Some(elf) = Elf::new(proc_layer, elf_table, vm_start)? else { return Ok(None) };
    // sections: start -> size (python dict: later duplicates win)
    let mut sections: Vec<(u64, u64)> = Vec::new();
    for ph in elf.get_program_headers() {
        let ph = ph?;
        match ph.m("p_type")?.description() {
            Ok("PT_LOAD") => {}
            Ok(_) => continue,
            Err(e) if e.is_invalid_address() => return Err(e),
            Err(_) => continue,
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
    let (mut f, _final) = ctx.create_output_file(&name)?;
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
    Ok(Some(name))
}
