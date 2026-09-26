//! mac.vfsevents.VFSevents (python `plugins/mac/vfsevents.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::objects::util::array_to_string;
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};

pub struct VfsEvents;

const EVENT_TYPES: [&str; 13] = [
    "CREATE_FILE",
    "DELETE",
    "STAT_CHANGED",
    "RENAME",
    "CONTENT_MODIFIED",
    "EXCHANGE",
    "FINDER_INFO_CHANGED",
    "CREATE_DIR",
    "CHOWN",
    "XATTR_MODIFIED",
    "XATTR_REMOVED",
    "DOCID_CREATED",
    "DOCID_CHANGED",
];

impl Plugin for VfsEvents {
    fn name(&self) -> &'static str {
        "mac.vfsevents.VFSevents"
    }
    fn description(&self) -> &'static str {
        "Lists processes that are filtering file system events"
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let k = ctx.mac_kernel()?;
        out.begin(vec![Column::new("Name", ColType::Str), Column::new("PID", ColType::Int), Column::new("Events", ColType::Str)])?;
        let table = k.object_from_symbol("watcher_table")?;
        for i in 0..table.count() {
            let watcher = table.at(i)?;
            if watcher.u64()? == 0 {
                continue;
            }
            let task_name = array_to_string(&watcher.m("proc_name")?, None)?;
            let task_pid = watcher.m("pid")?.int()?;
            let event_list = match watcher.m("event_list").and_then(|e| e.u64()) {
                Ok(v) => v,
                Err(e) if e.is_invalid_address() => continue,
                Err(e) => return Err(e),
            };
            // kernel.object("array", offset=event_list, absolute=True, count=13, subtype="unsigned char");
            // each element is read (and compared to 1) in turn
            let first = k.object_abs("unsigned char", event_list)?;
            let mut events: Vec<&str> = Vec::new();
            for (j, name) in EVENT_TYPES.iter().enumerate() {
                if first.at_addr(event_list.wrapping_add(j as u64)).int()? == 1 {
                    events.push(name);
                }
            }
            if !events.is_empty() {
                out.row(0, vec![Value::Str(task_name), Value::Int(task_pid), Value::Str(events.join(","))])?;
            }
        }
        Ok(())
    }
}
