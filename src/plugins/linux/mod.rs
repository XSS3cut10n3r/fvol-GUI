//! linux plugins.

use crate::error::{Error, Result};
use crate::plugins::Plugin;

pub mod bash;
pub mod boottime;
pub mod capabilities;
pub mod ebpf;
pub mod elfs;
pub mod envars;
pub mod graphics;
pub mod iomem;
pub mod ip;
pub mod kallsyms;
pub mod kmsg;
pub mod kthreads;
pub mod library_list;
pub mod lsmod;
pub mod lsof;
pub mod malware;
pub mod module_extract;
pub mod mountinfo;
pub mod pagecache;
pub mod pidhashtable;
pub mod proc;
pub mod psaux;
pub mod pscallstack;
pub mod pslist;
pub mod psscan;
pub mod pstree;
pub mod ptrace;
pub mod sockscan;
pub mod sockstat;
pub mod tracing;
pub mod vmaregexscan;
pub mod vmayarascan;
pub mod vmcoreinfo;

pub fn register(v: &mut Vec<&'static dyn Plugin>) {
    v.push(&bash::Bash);
    v.push(&capabilities::Capabilities);
    v.push(&elfs::Elfs);
    v.push(&envars::Envars);
    v.push(&graphics::fbdev::Fbdev);
    v.push(&ip::Addr);
    v.push(&ip::Link);
    v.push(&library_list::LibraryList);
    v.push(&lsof::Lsof);
    v.push(&malware::malfind::Malfind);
    v.push(&mountinfo::MountInfo);
    v.push(&pagecache::Files);
    v.push(&pagecache::InodePages);
    v.push(&pagecache::RecoverFs);
    v.push(&malware::malfind::MalfindDeprecated);
    v.push(&malware::process_spoofing::ProcessSpoofing);
    v.push(&pidhashtable::PIDHashTable);
    v.push(&proc::Maps);
    v.push(&psaux::PsAux);
    v.push(&pslist::PsList);
    v.push(&psscan::PsScan);
    v.push(&pstree::PsTree);
    v.push(&ptrace::Ptrace);
    v.push(&sockscan::Sockscan);
    v.push(&sockstat::Sockstat);
    v.push(&vmaregexscan::VmaRegExScan);
    v.push(&vmayarascan::VmaYaraScan);
    v.push(&pscallstack::PsCallStack);
    v.push(&kthreads::Kthreads);
    // L2: kernel / rootkit-detection plugins
    v.push(&boottime::Boottime);
    v.push(&ebpf::Ebpf);
    v.push(&iomem::IOMem);
    v.push(&kallsyms::Kallsyms);
    v.push(&kmsg::Kmsg);
    v.push(&lsmod::Lsmod);
    v.push(&module_extract::ModuleExtract);
    v.push(&vmcoreinfo::VMCoreInfo);
    v.push(&malware::check_afinfo::CheckAfinfo);
    v.push(&malware::check_afinfo::CheckAfinfoDeprecated);
    v.push(&malware::check_creds::CheckCreds);
    v.push(&malware::check_creds::CheckCredsDeprecated);
    v.push(&malware::check_idt::CheckIdt);
    v.push(&malware::check_idt::CheckIdtDeprecated);
    v.push(&malware::check_modules::CheckModules);
    v.push(&malware::check_modules::CheckModulesDeprecated);
    v.push(&malware::check_syscall::CheckSyscall);
    v.push(&malware::check_syscall::CheckSyscallDeprecated);
    v.push(&malware::hidden_modules::HiddenModules);
    v.push(&malware::hidden_modules::HiddenModulesDeprecated);
    v.push(&malware::keyboard_notifiers::KeyboardNotifiers);
    v.push(&malware::keyboard_notifiers::KeyboardNotifiersDeprecated);
    v.push(&malware::modxview::Modxview);
    v.push(&malware::modxview::ModxviewDeprecated);
    v.push(&malware::netfilter::Netfilter);
    v.push(&malware::netfilter::NetfilterDeprecated);
    v.push(&malware::tty_check::TtyCheck);
    v.push(&malware::tty_check::TtyCheckDeprecated);
    v.push(&tracing::ftrace::CheckFtrace);
    v.push(&tracing::perf_events::PerfEvents);
    v.push(&tracing::tracepoints::CheckTracepoints);
}

pub use crate::plugins::stream_chunks;

/// [`pslist::collect_tasks`]'s result as items for [`crate::plugins::emit_par_blocks`]: the
/// tasks, then the generator's error (python raised after all of them) as an `Err` item.
pub fn task_items(tasks: Vec<crate::objects::Obj>, tail: Option<Error>) -> Vec<Result<crate::objects::Obj>> {
    let mut v: Vec<Result<crate::objects::Obj>> = tasks.into_iter().map(Ok).collect();
    v.extend(tail.map(Err));
    v
}

/// A copy of an error computed once and surfaced where python raises (possibly several times).
pub fn clone_err(e: &Error) -> Error {
    match e {
        Error::InvalidAddress { addr } => Error::InvalidAddress { addr: *addr },
        Error::Swapped { addr } => Error::Swapped { addr: *addr },
        Error::Symbol(s) => Error::Symbol(s.clone()),
        Error::Unsatisfied(s) => Error::Unsatisfied(s.clone()),
        Error::Layer(s) => Error::Layer(s.clone()),
        Error::Io(e) => Error::Io(std::io::Error::new(e.kind(), e.to_string())),
        Error::Msg(s) => Error::Msg(s.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::renderers::text::{RenderOptions, create};
    use crate::renderers::{CollectSink, RowSink, Value};

    fn cols() -> Vec<crate::renderers::Column> {
        crate::cols![("I", Int), ("Hex", Hex), ("S", Str)]
    }

    fn row(i: usize) -> [Value; 3] {
        [Value::Int(i as i128), Value::Int((i * 7) as i128), Value::Str(format!("item {i}"))]
    }

    /// Every renderer's output of `stream_chunks` is the serial `out.row` output, up to and
    /// excluding the failing item; the error comes back.
    #[test]
    fn stream_chunks_like_serial_rows() {
        for name in ["quick", "csv", "json", "jsonl", "pretty"] {
            for (n, fail) in [(0usize, None), (1, None), (1000, None), (1000, Some(537usize)), (1000, Some(0))] {
                let render = |parallel: bool| -> (Vec<u8>, bool) {
                    let mut buf = Vec::new();
                    let res;
                    {
                        let mut r = create(name, &mut buf, RenderOptions::default()).unwrap();
                        r.begin(cols()).unwrap();
                        res = if parallel {
                            stream_chunks(&mut *r, n, 7, |range, b| {
                                for i in range {
                                    if Some(i) == fail {
                                        return Some(Error::msg("boom"));
                                    }
                                    b.push_ref(&row(i));
                                }
                                None
                            })
                        } else {
                            (|| {
                                for i in 0..n {
                                    if Some(i) == fail {
                                        return Err(Error::msg("boom"));
                                    }
                                    r.row(0, row(i).to_vec())?;
                                }
                                Ok(())
                            })()
                        };
                        if res.is_ok() { r.finish().unwrap() } else { r.abort(false).unwrap() }
                    }
                    (buf, res.is_ok())
                };
                assert_eq!(render(true), render(false), "{name} n={n} fail={fail:?}");
            }
        }
        // no encoder (collectors, --filters): the values themselves, in order
        let mut sink = CollectSink::default();
        sink.begin(cols()).unwrap();
        let r = stream_chunks(&mut sink, 100, 3, |range, b| {
            for i in range {
                if i == 50 {
                    return Some(Error::msg("boom"));
                }
                b.push_ref(&row(i));
            }
            None
        });
        assert!(r.is_err());
        assert_eq!(sink.rows.len(), 50);
        assert!(sink.rows.iter().enumerate().all(|(i, (d, v))| *d == 0 && matches!(v[0], Value::Int(x) if x == i as i128)));
    }

    /// A panic on a worker (python's uncaught exceptions) comes back on the calling thread
    /// after every row before it, like the serial loop; it does not hang the stream.
    #[test]
    fn stream_chunks_resumes_worker_panics() {
        let mut sink = CollectSink::default();
        sink.begin(cols()).unwrap();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = stream_chunks(&mut sink, 1000, 7, |range, b| {
                for i in range {
                    if i == 500 {
                        panic!("ValueError: boom");
                    }
                    b.push_ref(&row(i));
                }
                None
            });
        }));
        let p = r.expect_err("the worker's panic is resumed");
        assert_eq!(p.downcast_ref::<&str>().copied(), Some("ValueError: boom"));
        assert_eq!(sink.rows.len(), 500);
    }
}
