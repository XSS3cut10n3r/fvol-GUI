//! Linux helpers (python `symbols/linux/__init__.py`: `LinuxUtilities` pieces, `VMCoreInfo`;
//! `symbols/linux/extensions`: the class extensions as the [`LinuxExt`] trait on `Obj`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! For plugin porters:
//!   * `ctx.linux_kernel()?` is python's `context.modules[self.config["kernel"]]` (derefs to a
//!     [`Module`]: `k.object_from_symbol("init_task")`, `k.get_symbol(..)`, `k.get_type(..)`;
//!     also `k.layer` / `k.vlayer` (python `layer_name`), `k.phys` (`memory_layer`),
//!     `k.table`, `k.aslr_shift` (= module offset), `k.kaslr_shift`, `k.dtb`, `k.banner`).
//!   * `use crate::symbols::linux::LinuxExt;` then call python's extension methods on objects:
//!     `task.is_valid()`, `task.get_create_time()`, `head.to_list("task_struct", "tasks", ..)`,
//!     `mm.get_vma_iter()`, `vma.get_protection()`, `file.get_inode()` ... (see [`ext`]).
//!   * `plugins::linux::pslist::list_tasks` is python's `PsList.list_tasks` (most linux plugins
//!     start from it), `get_task_fields` python's `PsList.get_task_fields`.
//!   * [`vmlinux_of`] is python's `LinuxUtilities.get_module_from_volobj_type(context, obj)`.
//!   * [`container_of`] is python's `LinuxUtilities.container_of`.
//!   * [`elf`]: python's `elf` extension (header / program headers) and `Elfs.elf_dump`.
//!   * [`vmcoreinfo`]: python's `VMCoreInfo` (search + parse; for `linux.vmcoreinfo`).
//!   * [`timespec`]: python's `Timespec64Concrete` with python's exact float semantics.

pub mod constants;
pub mod elf;
pub mod ext;
pub mod kallsyms;
pub mod module;
pub mod modules;
pub mod search;
pub mod timespec;
pub mod vmcoreinfo;

pub use ext::{HListIter, LinuxExt, ListIter};

use crate::error::{Error, Result};
use crate::objects::{Module, Obj};
use crate::symbols::TableRef;
use std::sync::Mutex;

/// python `linux_constants.PF_KTHREAD`.
pub const PF_KTHREAD: i128 = 0x0020_0000;

/// python `LinuxIntelStacker.virtual_to_physical_address`: kernel virtual -> physical
/// (ignores KASLR), with python's unbounded-int result.
pub fn virtual_to_physical_address_i(addr: i128) -> i128 {
    if addr > 0xFFFF_FFFF_8000_0000 { addr - 0xFFFF_FFFF_8000_0000 } else { addr.wrapping_sub(0xC000_0000) }
}

/// [`virtual_to_physical_address_i`] with wrapping u64 arithmetic.
pub fn virtual_to_physical_address(addr: u64) -> u64 {
    virtual_to_physical_address_i(addr as i128) as u64
}

static KERNELS: Mutex<Vec<Module>> = Mutex::new(Vec::new());

/// Register a kernel module (done by the Linux automagic) so extension methods can find
/// "their" vmlinux like python's `get_module_from_volobj_type`.
pub fn register_kernel(m: Module) {
    let mut g = KERNELS.lock().unwrap();
    if !g.iter().any(|k| std::ptr::eq(k.table(), m.table())) {
        g.push(m);
    }
}

/// python `LinuxUtilities.get_module_from_volobj_type(context, volobj)`: the first module
/// using the object's symbol table.
pub fn vmlinux_of(o: &Obj) -> Result<Module> {
    vmlinux_of_table(o.table())
}

/// The first registered kernel module using `table`.
pub fn vmlinux_of_table(table: TableRef) -> Result<Module> {
    KERNELS
        .lock()
        .unwrap()
        .iter()
        .find(|k| std::ptr::eq(k.table(), table))
        .copied()
        .ok_or_else(|| Error::msg(format!("ValueError: No module using the symbol table '{}'", table.name())))
}

/// python's module name handling (`get_module_wrapper`): `name` or `<module table>!name`
/// -> `name`; another table's prefix is a ValueError.
pub fn module_type_name<'a>(m: &Module, name: &'a str) -> Result<&'a str> {
    match name.split_once('!') {
        None => Ok(name),
        Some((t, rest)) if t == m.symbol_table_name() => Ok(rest),
        Some(_) => Err(Error::msg("ValueError: Cannot reference another module")),
    }
}

/// python `LinuxUtilities.container_of(addr, type_name, member_name, vmlinux)`: the
/// `type_name` object containing `member_name` at `addr` (on the vmlinux layer). `None` when
/// `addr` is 0 or the container address is not valid (python returns None).
pub fn container_of(addr: u64, type_name: &str, member_name: &str, vmlinux: &Module) -> Result<Option<Obj>> {
    if addr == 0 {
        return Ok(None);
    }
    let tname = module_type_name(vmlinux, type_name)?;
    let off = vmlinux.offset_of(tname, member_name)?;
    let container = addr.wrapping_sub(off);
    if !vmlinux.layer().is_valid(container, 1) {
        return Ok(None);
    }
    Ok(Some(vmlinux.object_abs(tname, container)?))
}
