//! linux.iomem.IOMem (python `plugins/linux/iomem.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::{Error, Result};
use crate::objects::Module;
use crate::objects::util::pointer_to_string;
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::util::FxHashSet;

pub struct IOMem;

/// python `IOMem.parse_resource(context, kernel, resource_offset, seen, depth)`: depth-first
/// (children, then siblings) walk of a `resource` tree; `f(depth, name, start, end)` per
/// resource. `Err` = python raised (an unreadable child/sibling pointer).
pub fn parse_resource(vm: &Module, root: u64, f: &mut dyn FnMut(usize, Value, i128, i128) -> Result<()>) -> Result<()> {
    enum Frame {
        /// python `parse_resource(offset, depth)`
        Visit(u64, usize),
        /// the `if resource.sibling != 0` step of the resource at this offset (after its
        /// child subtree)
        Sibling(u64, usize),
    }
    let mut seen: FxHashSet<u64> = FxHashSet::default();
    let mut stack: Vec<Frame> = vec![Frame::Visit(root, 0)];
    while let Some(frame) = stack.pop() {
        let (off, depth) = match frame {
            Frame::Visit(o, d) => (o, d),
            Frame::Sibling(o, d) => {
                let sibling = vm.object_abs("resource", o)?.m("sibling")?.u64()?;
                if sibling != 0 {
                    stack.push(Frame::Visit(sibling, d));
                }
                continue;
            }
        };
        let resource = vm.object_abs("resource", off)?;
        let name = match resource.m("name").and_then(|n| pointer_to_string(&n, 128)) {
            Ok(n) => Value::Str(n),
            Err(e) if e.is_invalid_address() => Value::Unreadable,
            Err(e) => return Err(e),
        };
        let se = resource.m("start").and_then(|s| s.int()).and_then(|s| Ok((s, resource.m("end")?.int()?)));
        let (start, end) = match se {
            Ok(v) => v,
            Err(e) if e.is_invalid_address() => continue,
            Err(e) => return Err(e),
        };
        if !seen.insert(off) {
            continue;
        }
        f(depth, name, start, end)?;
        // python: `if resource.child != 0: recurse`, then `if resource.sibling != 0: recurse`
        let child = resource.m("child")?.u64()?;
        stack.push(Frame::Sibling(off, depth));
        if child != 0 {
            stack.push(Frame::Visit(child, depth + 1));
        }
    }
    Ok(())
}

impl Plugin for IOMem {
    fn name(&self) -> &'static str {
        "linux.iomem.IOMem"
    }
    fn description(&self) -> &'static str {
        "Generates an output similar to /proc/iomem on a running system."
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let k = ctx.linux_kernel()?;
        if !k.has_symbol("iomem_resource") {
            return Err(Error::msg("TypeError: This plugin requires the iomem_resource symbol. This symbol is not present in the supplied symbol table. This means you are either analyzing an unsupported kernel version or that your symbol table is corrupt."));
        }
        if !k.has_type("resource") {
            return Err(Error::msg("TypeError: This plugin requires the resource type. This type is not present in the supplied symbol table. This means you are either analyzing an unsupported kernel version or that your symbol table is corrupt."));
        }
        out.begin(vec![Column::new("Name", ColType::Str), Column::new("Start", ColType::Hex), Column::new("End", ColType::Hex)])?;
        let root = k.symbol_addr("iomem_resource")?;
        parse_resource(k, root, &mut |depth, name, start, end| out.row(depth, vec![name, Value::Int(start), Value::Int(end)]))
    }
}
