//! mac plugins.

use crate::plugins::Plugin;

pub mod check_syscall;
pub mod check_sysctl;
pub mod dmesg;
pub mod ifconfig;
pub mod kauth_scopes;
pub mod kevents;
pub mod list_files;
pub mod lsmod;
pub mod lsof;
pub mod mount;
pub mod netstat;
pub mod pslist;
pub mod socket_filters;
pub mod timers;
pub mod trustedbsd;
pub mod vfsevents;

pub fn register(v: &mut Vec<&'static dyn Plugin>) {
    v.push(&check_syscall::CheckSyscall);
    v.push(&check_syscall::CheckTrapTable);
    v.push(&check_sysctl::CheckSysctl);
    v.push(&dmesg::Dmesg);
    v.push(&ifconfig::Ifconfig);
    v.push(&kauth_scopes::KauthListeners);
    v.push(&kauth_scopes::KauthScopes);
    v.push(&kevents::Kevents);
    v.push(&list_files::ListFiles);
    v.push(&lsmod::Lsmod);
    v.push(&lsof::Lsof);
    v.push(&mount::Mount);
    v.push(&netstat::Netstat);
    v.push(&pslist::PsList);
    v.push(&socket_filters::SocketFilters);
    v.push(&timers::Timers);
    v.push(&trustedbsd::Trustedbsd);
    v.push(&vfsevents::VfsEvents);
}
