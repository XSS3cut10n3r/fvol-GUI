//! generic plugins (python `volatility3/framework/plugins/*.py`).

use crate::plugins::Plugin;

pub mod banners;
pub mod configwriter;
pub mod frameworkinfo;
pub mod isfinfo;
pub mod layerwriter;
pub mod primary;
pub mod regexscan;
pub mod timeliner;
pub mod vmscan;
pub mod yarascan;

pub fn register(v: &mut Vec<&'static dyn Plugin>) {
    v.push(&banners::Banners);
    v.push(&configwriter::ConfigWriter);
    v.push(&frameworkinfo::FrameworkInfo);
    v.push(&isfinfo::IsfInfo);
    v.push(&layerwriter::LayerWriter);
    v.push(&regexscan::RegExScan);
    v.push(&timeliner::Timeliner);
    v.push(&vmscan::Vmscan);
    v.push(&yarascan::YaraScan);
}
