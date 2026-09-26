//! mac.mount.Mount (python `plugins/mac/mount.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::automagic::mac::MacKernel;
use crate::context::Context;
use crate::error::Result;
use crate::objects::Obj;
use crate::objects::util::array_to_string;
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::mac::{MAX_ELEMENTS, MacExt};

pub struct Mount;

/// python `Mount.list_mounts(context, kernel_module_name)`: the `mount *` pointers of the
/// `mountlist` tail queue. A trailing `Err` means python raised there.
pub fn list_mounts(k: &MacKernel) -> Vec<Result<Obj>> {
    match k.object_from_symbol("mountlist") {
        Ok(head) => head.walk_tailq("mnt_list", MAX_ELEMENTS),
        Err(e) => vec![Err(e)],
    }
}

impl Plugin for Mount {
    fn name(&self) -> &'static str {
        "mac.mount.Mount"
    }
    fn description(&self) -> &'static str {
        "A module containing a collection of plugins that produce data typically found in Mac's mount command"
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let k = ctx.mac_kernel()?;
        out.begin(vec![Column::new("Device", ColType::Str), Column::new("Mount Point", ColType::Str), Column::new("Type", ColType::Str)])?;
        for mount in list_mounts(k) {
            let vfs = mount?.m("mnt_vfsstat")?;
            let device_name = array_to_string(&vfs.m("f_mntonname")?, None)?;
            let mount_point = array_to_string(&vfs.m("f_mntfromname")?, None)?;
            let mount_type = array_to_string(&vfs.m("f_fstypename")?, None)?;
            out.row(0, vec![Value::Str(device_name), Value::Str(mount_point), Value::Str(mount_type)])?;
        }
        Ok(())
    }
}
