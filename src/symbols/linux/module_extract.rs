//! python `symbols/linux/utilities/modules.py` `ModuleExtract`: rebuild an analyzable ELF
//! relocatable file (`.ko`-like) from a loaded kernel module: the sections kept in memory
//! (ordered by load address, sizes from the next section), the `.strtab` read off the module
//! structure, a de-mangled `.symtab`, a synthesized `.shstrtab`, section headers and an ELF
//! header. Entry point: [`extract_module`] (used by `linux.lsmod --dump`,
//! `linux.module_extract`, ...).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use super::module::ModuleExt;
use super::modules::get_modules_memory_boundaries;
use crate::error::{Error, Result};
use crate::layers::LayerExt;
use crate::objects::{Field, Module, Obj};

/// python `linux_constants` ELF values.
pub const STB_LOCAL: u8 = 0;
pub const STB_GLOBAL: u8 = 1;
pub const STT_NOTYPE: u8 = 0;
pub const STT_OBJECT: u8 = 1;
pub const STT_FUNC: u8 = 2;
pub const STT_SECTION: u8 = 3;
pub const SHT_NULL: u32 = 0;
pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_RELA: u32 = 4;
pub const SHT_NOTE: u32 = 7;
pub const SHF_WRITE: u64 = 1;
pub const SHF_ALLOC: u64 = 2;
pub const SHF_EXECINSTR: u64 = 4;

/// python truthiness of an optional section name.
#[inline]
fn truthy(s: Option<&str>) -> bool {
    s.is_some_and(|s| !s.is_empty())
}

fn none_name_error(method: &str) -> Error {
    Error::msg(format!("AttributeError: 'NoneType' object has no attribute '{method}'"))
}

/// One rebuilt section: (name, load address, file offset, data).
struct Section {
    name: Option<String>,
    address: u64,
    file_offset: u64,
    data: Vec<u8>,
}

/// python `ModuleExtract._find_section(section_lookups, sym_address)`.
fn find_section<'a>(lookups: &'a [(Option<&'a str>, u64, u64, u64)], sym_address: u64) -> Option<&'a (Option<&'a str>, u64, u64, u64)> {
    lookups.iter().find(|(_, _, address, size)| *address as u128 <= sym_address as u128 && (sym_address as u128) < *address as u128 + *size as u128)
}

/// python `ModuleExtract._get_st_info_for_sym(sym, sym_address, sect_name)`.
fn st_info_for_sym(st_name: u64, sym_address: u64, sect_name: Option<&str>) -> u8 {
    let (bind, ty) = if st_name > 0 {
        let ty = if sym_address == 0 {
            STT_NOTYPE
        } else if let Some(n) = sect_name.filter(|n| !n.is_empty()) {
            if n.contains(".text") && !n.contains(".rela") { STT_FUNC } else { STT_OBJECT }
        } else {
            STT_NOTYPE
        };
        (STB_GLOBAL, ty)
    } else {
        (STB_LOCAL, STT_SECTION)
    };
    ((bind << 4) & 0xF0) | (ty & 0xF)
}

/// python `ModuleExtract._fix_sym_table(...)`: the de-mangled symbol table, `Ok(None)` where
/// python returns None.
fn fix_sym_table(vm: &Module, original: &[(u64, Option<String>)], sizes: &[(u64, u64)], is64: bool, module: &Obj) -> Result<Option<Vec<u8>>> {
    let mut lookups: Vec<(Option<&str>, u64, u64, u64)> = Vec::new();
    for (index, (address, name)) in original.iter().enumerate() {
        if name.as_deref() == Some(".symtab") {
            continue;
        }
        let size = sizes.iter().find(|s| s.0 == *address).map(|s| s.1).ok_or_else(|| Error::msg(format!("KeyError: {address}")))?;
        lookups.push((name.as_deref(), index as u64 + 1, *address, size));
    }
    let sym_type_name = if is64 { "Elf64_Sym" } else { "Elf32_Sym" };
    let sym_ty = vm.get_type(sym_type_name)?;
    let sym_size = vm.table().size_of(sym_ty);
    let symtab = module.section_symtab()?.ok_or_else(|| Error::msg("TypeError: offset is None"))?.u64()?;
    let count = module.num_symtab()?.ok_or_else(|| Error::msg("TypeError: count is None"))?;
    let t = vm.table();
    let f = |m: &str| Field::new(t, sym_type_name, m);
    let (f_name, f_info, f_other, f_shndx, f_value, f_size) = (f("st_name")?, f("st_info")?, f("st_other")?, f("st_shndx")?, f("st_value")?, f("st_size")?);
    let _ = f_info;
    let base = vm.object_abs(sym_type_name, symtab)?;
    let mut out: Vec<u8> = Vec::with_capacity((count.clamp(0, 1 << 20) as usize) * sym_size as usize);
    for i in 0..count.max(0) as u64 {
        let sym = base.at_addr(base.addr.wrapping_add(i.wrapping_mul(sym_size)));
        // _get_fixed_sym_fields
        let sym_address = sym.f(&f_value).u64()?;
        let sect = find_section(&lookups, sym_address);
        let (sect_name, sect_index, st_value) = match sect {
            None => (None, None, sym_address),
            Some((name, index, address, _)) => (*name, Some(*index), sym_address - *address),
        };
        let st_name = sym.f(&f_name).u64()?;
        let st_info = st_info_for_sym(st_name, sym_address, sect_name);
        let st_shndx: u64 = if truthy(sect_name) { sect_index.unwrap() } else { sym.f(&f_shndx).u64()? };
        if st_shndx > 0xFFFF {
            return Err(Error::msg("struct.error: 'H' format requires 0 <= number <= 65535"));
        }
        let st_other = sym.f(&f_other).u64()? as u8;
        let st_size = sym.f(&f_size).u64()?;
        let start = out.len();
        if is64 {
            out.extend_from_slice(&(st_name as u32).to_le_bytes());
            out.push(st_info);
            out.push(st_other);
            out.extend_from_slice(&(st_shndx as u16).to_le_bytes());
            out.extend_from_slice(&st_value.to_le_bytes());
            out.extend_from_slice(&st_size.to_le_bytes());
        } else {
            if st_value > u32::MAX as u64 || st_size > u32::MAX as u64 {
                return Err(Error::msg("struct.error: 'I' format requires 0 <= number <= 4294967295"));
            }
            out.extend_from_slice(&(st_name as u32).to_le_bytes());
            out.extend_from_slice(&(st_value as u32).to_le_bytes());
            out.extend_from_slice(&(st_size as u32).to_le_bytes());
            out.push(st_info);
            out.push(st_other);
            out.extend_from_slice(&(st_shndx as u16).to_le_bytes());
        }
        if (out.len() - start) as u64 != sym_size {
            return Ok(None);
        }
    }
    if out.is_empty() {
        return Ok(None);
    }
    Ok(Some(out))
}

/// python `ModuleExtract._parse_sections(...)`: (sections in file order, strtab index,
/// symtab index), `Ok(None)` where python returns None.
fn parse_sections(vm: &Module, module: &Obj, is64: bool) -> Result<Option<(Vec<Section>, Option<u64>, u64)>> {
    let layer = vm.layer();
    let mask = layer.address_mask();
    let (lo, hi) = get_modules_memory_boundaries(vm)?;
    let (lo, hi) = (lo & mask, hi & mask);
    // python dict {address: name} (insertion order, later duplicates overwrite the value)
    let mut original: Vec<(u64, Option<String>)> = Vec::new();
    for section in module.get_sections()?.elements() {
        let address = if section.struct_name() == Some("bin_attribute") { section.address()?.u64()? } else { section.m("address")?.u64()? };
        let a = address & mask;
        if !(lo <= a && a < hi) {
            continue;
        }
        let name = section.get_name()?;
        match original.iter_mut().find(|e| e.0 == address) {
            Some(e) => e.1 = name,
            None => original.push((address, name)),
        }
    }
    if original.is_empty() {
        return Ok(None);
    }
    let hdr = vm.table().size_of(vm.get_type(if is64 { "Elf64_Ehdr" } else { "Elf32_Ehdr" })?);
    let mut sorted: Vec<u64> = original.iter().map(|e| e.0).collect();
    sorted.sort_unstable();
    let name_of = |a: u64| original.iter().find(|e| e.0 == a).and_then(|e| e.1.clone());
    let mut symtab_address: Option<u64> = None;
    let mut strtab_index: Option<u64> = None;
    let mut file_offset = hdr;
    let mut sections: Vec<Section> = Vec::new();
    let mut sizes: Vec<(u64, u64)> = Vec::new();
    for (index, &address) in sorted.iter().enumerate() {
        let name = name_of(address);
        let data = if name.as_deref() == Some(".strtab") {
            let strtab = module.section_strtab()?.ok_or_else(|| Error::msg("TypeError: offset is None"))?.u64()?;
            let n = module.num_symtab()?.ok_or_else(|| Error::msg("TypeError: count is None"))?;
            let len = n.max(0) as u128 * 256;
            if len > 1 << 30 {
                return Err(Error::msg("MemoryError"));
            }
            let mut data = layer.read_vec_padded(strtab, len as usize);
            if let Some(end) = data.windows(2).position(|w| w == [0, 0]) {
                data.truncate(end + 1);
            }
            strtab_index = Some(index as u64);
            data
        } else if name.as_deref() == Some(".symtab") {
            symtab_address = Some(address);
            continue;
        } else {
            let size = match sorted.get(index + 1) {
                Some(next) => next - address,
                None => 0x10000,
            };
            if size > 1 << 30 {
                return Err(Error::msg("MemoryError"));
            }
            // python's Intel layer ignores the bits above the address mask
            layer.read_vec_padded(address & mask, size as usize)
        };
        sizes.push((address, data.len() as u64));
        let len = data.len() as u64;
        sections.push(Section { name, address, file_offset, data });
        file_offset += len;
    }
    let Some(symtab_address) = symtab_address.filter(|a| *a != 0) else { return Ok(None) };
    let Some(data) = fix_sym_table(vm, &original, &sizes, is64, module)? else { return Ok(None) };
    let symtab_index = sections.len() as u64;
    sections.push(Section { name: Some(".symtab".into()), address: symtab_address, file_offset, data });
    Ok(Some((sections, strtab_index, symtab_index)))
}

/// python `ModuleExtract._make_elf_header(bits, sect_hdr_offset, num_sections)`.
fn make_elf_header(is64: bool, sect_hdr_offset: u64, num_sections: u64) -> Result<Vec<u8>> {
    let mut h = Vec::with_capacity(64);
    if is64 {
        h.extend_from_slice(b"\x7f\x45\x4c\x46\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00");
    } else {
        h.extend_from_slice(b"\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00");
    }
    h.extend_from_slice(&1u16.to_le_bytes()); // ET_REL
    h.extend_from_slice(&(if is64 { 0x3Eu16 } else { 3 }).to_le_bytes());
    h.extend_from_slice(&1u32.to_le_bytes());
    let w = if is64 { 8 } else { 4 };
    h.extend(std::iter::repeat_n(0u8, w)); // e_entry
    h.extend(std::iter::repeat_n(0u8, w)); // e_phoff
    if is64 {
        h.extend_from_slice(&sect_hdr_offset.to_le_bytes());
    } else {
        let v = u32::try_from(sect_hdr_offset).map_err(|_| Error::msg("struct.error: 'I' format requires 0 <= number <= 4294967295"))?;
        h.extend_from_slice(&v.to_le_bytes());
    }
    h.extend_from_slice(&[0, 0, 0, 0]); // e_flags
    h.extend_from_slice(&(if is64 { 64u16 } else { 52 }).to_le_bytes());
    h.extend_from_slice(&[0, 0, 0, 0]); // e_phentsize, e_phnum
    h.extend_from_slice(&(if is64 { 64u16 } else { 40 }).to_le_bytes());
    let pack_h = |v: u64| u16::try_from(v).map_err(|_| Error::msg("struct.error: 'H' format requires 0 <= number <= 65535"));
    h.extend_from_slice(&pack_h(num_sections + 1)?.to_le_bytes());
    h.extend_from_slice(&pack_h(num_sections)?.to_le_bytes());
    Ok(h)
}

/// python `ModuleExtract._calc_sect_type(name)`.
fn calc_sect_type(name: &str) -> u32 {
    if name.contains(".rela.") {
        return SHT_RELA;
    }
    match name {
        ".note.gnu.build-id" => SHT_NOTE,
        ".text" | ".init.text" | ".exit.text" | ".static_call.text" | ".rodata" | ".modinfo" | "__param" | ".data" | ".gnu.linkonce.this_module" | ".comment" => SHT_PROGBITS,
        ".shstrtab" | ".strtab" => SHT_STRTAB,
        ".symtab" => SHT_SYMTAB,
        _ => SHT_PROGBITS,
    }
}

/// python `ModuleExtract._calc_sect_flags(name)`.
fn calc_sect_flags(name: &str) -> u64 {
    let mut flags = SHF_ALLOC;
    if matches!(name, ".text" | ".init.text" | ".exit.text" | ".static_call.text") {
        flags |= SHF_EXECINSTR;
    } else if matches!(name, ".data" | ".init.data" | ".exit.data" | ".bss" | "__tracepoints" | ".data.once" | "_ftrace_events" | ".gnu.linkonce.this_module") {
        flags |= SHF_WRITE;
    }
    flags
}

/// python `ModuleExtract._make_section_header(...)`: `Ok(None)` where python returns None
/// (a value does not fit its field).
#[allow(clippy::too_many_arguments)]
fn make_section_header(is64: bool, name_index: u64, name: &str, address: u64, size: u64, file_offset: u64, strtab_index: Option<u64>, symtab_index: u64) -> Option<Vec<u8>> {
    let sect_type = calc_sect_type(name);
    let flags = calc_sect_flags(name);
    let link: Option<u64> = if name.contains(".rela.") {
        Some(symtab_index)
    } else if sect_type == SHT_SYMTAB {
        strtab_index
    } else {
        Some(0)
    };
    let entsize: u64 = if name.contains(".rela.") {
        24
    } else if sect_type == SHT_SYMTAB {
        if is64 { 24 } else { 16 }
    } else {
        0
    };
    let u32f = |v: u64| u32::try_from(v).ok();
    let mut d = Vec::with_capacity(64);
    d.extend_from_slice(&u32f(name_index)?.to_le_bytes());
    d.extend_from_slice(&sect_type.to_le_bytes());
    let put = |d: &mut Vec<u8>, v: u64| -> Option<()> {
        if is64 {
            d.extend_from_slice(&v.to_le_bytes());
        } else {
            d.extend_from_slice(&u32f(v)?.to_le_bytes());
        }
        Some(())
    };
    put(&mut d, flags)?;
    put(&mut d, address)?;
    put(&mut d, file_offset)?;
    put(&mut d, size)?;
    d.extend_from_slice(&u32f(link?)?.to_le_bytes());
    d.extend_from_slice(&[0, 0, 0, 0]); // sh_info
    put(&mut d, 1)?; // sh_addralign
    put(&mut d, entsize)?;
    Some(d)
}

/// python `ModuleExtract.extract_module(context, vmlinux_name, module)`: the rebuilt ELF
/// file, `Ok(None)` where python returns None (paged out / no sections / no symbol table /
/// unbuildable header), `Err` where python raises.
pub fn extract_module(vm: &Module, module: &Obj) -> Result<Option<Vec<u8>>> {
    // bail early: `hasattr(module.sect_attrs, "nsections")` (InvalidAddress -> None)
    let early = (|| -> Result<()> {
        let sa = module.m("sect_attrs")?;
        sa.u64()?;
        if sa.has_member("nsections") {
            sa.m("nsections")?.int()?;
        }
        Ok(())
    })();
    match early {
        Ok(()) => {}
        Err(e) if e.is_invalid_address() => return Ok(None),
        Err(e) => return Err(e),
    }
    let is64 = vm.table().is_64bit();
    let Some((sections, strtab_index, symtab_index)) = parse_sections(vm, module, is64)? else { return Ok(None) };
    let t = vm.table();
    let header_size = t.size_of(vm.get_type(if is64 { "Elf64_Ehdr" } else { "Elf32_Ehdr" })?);
    let shdr_size = t.size_of(vm.get_type(if is64 { "Elf64_Shdr" } else { "Elf32_Shdr" })?);
    let mut headers = vec![0u8; shdr_size as usize];
    let total: usize = sections.iter().map(|s| s.data.len()).sum();
    let mut data: Vec<u8> = Vec::with_capacity(total + 256);
    let mut shstrtab: Vec<u8> = vec![0];
    let mut name_index = 1u64;
    let mut last: Option<(u64, u64)> = None;
    for s in &sections {
        let name = s.name.as_deref().ok_or_else(|| none_name_error("find"))?;
        let Some(h) = make_section_header(is64, name_index, name, s.address, s.data.len() as u64, s.file_offset, strtab_index, symtab_index) else { return Ok(None) };
        name_index += name.chars().count() as u64 + 1;
        headers.extend_from_slice(&h);
        data.extend_from_slice(&s.data);
        last = Some((s.file_offset, s.data.len() as u64));
        shstrtab.extend_from_slice(name.as_bytes());
        shstrtab.push(0);
    }
    shstrtab.extend_from_slice(b".shstrtab\0");
    let (lo, ls) = last.ok_or_else(|| Error::msg("TypeError: unsupported operand type(s) for +: 'NoneType' and 'NoneType'"))?;
    let h = make_section_header(is64, name_index, ".shstrtab", 0, shstrtab.len() as u64, lo + ls, strtab_index, symtab_index).ok_or_else(|| Error::msg("TypeError: can't concat NoneType to bytes"))?;
    headers.extend_from_slice(&h);
    data.extend_from_slice(&shstrtab);
    let num_sections = sections.len() as u64 + 1;
    let header = match make_elf_header(is64, header_size + data.len() as u64, num_sections) {
        Ok(h) => h,
        Err(e) => return Err(e),
    };
    let mut out = header;
    out.reserve(data.len() + headers.len());
    out.extend_from_slice(&data);
    out.extend_from_slice(&headers);
    Ok(Some(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{Context, GlobalOptions};

    /// Extract every `lsmod` module like python's `linux.lsmod --dump` (files
    /// `kernel_module.<name>.<offset>.elf`) to diff against python's output:
    /// `FASTVOL_BENCH_IMAGE=<img> FASTVOL_TEST_OUT=<dir> cargo test --profile fast
    /// extract_all_modules -- --ignored`.
    #[test]
    #[ignore]
    fn extract_all_modules() {
        let image = crate::util::env::var("BENCH_IMAGE").unwrap();
        let out = crate::util::env::var("TEST_OUT").unwrap();
        let ctx = Context::new(GlobalOptions { file: Some(image), symbol_dirs: vec!["/home/user/fvol/testdata/symbols".into()], ..Default::default() }).unwrap();
        let k = ctx.linux_kernel().unwrap();
        let t = std::time::Instant::now();
        let mut n = 0;
        for m in super::super::modules::list_modules(k) {
            let m = m.unwrap();
            let name = crate::objects::util::array_to_string(&m.m("name").unwrap(), None).unwrap();
            match extract_module(k, &m).unwrap() {
                Some(elf) => {
                    std::fs::write(format!("{out}/kernel_module.{name}.{:#x}.elf", m.addr), elf).unwrap();
                    n += 1;
                }
                None => eprintln!("no ELF for {name} at {:#x}", m.addr),
            }
        }
        eprintln!("extracted {n} modules in {:?}", t.elapsed());
    }
}
