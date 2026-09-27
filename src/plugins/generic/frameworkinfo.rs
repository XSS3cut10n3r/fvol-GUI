//! frameworkinfo.FrameworkInfo (python `plugins/frameworkinfo.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! python lists `framework.class_subclasses(<interface>)` for seven interfaces. fastvol has no
//! python class hierarchy, so the Automagic / Requirement / Layer / LayerStacker / Object /
//! Renderer categories are python's lists verbatim (class `__name__`s in python's order,
//! duplicates included: `class_subclasses` yields a class once per path through the
//! hierarchy). The Plugin category reflects the plugins fastvol registers: python's order for
//! the ones python has, then any other fastvol plugin sorted by name.

use crate::context::Context;
use crate::error::Result;
use crate::plugins::{Config, Plugin};
use crate::renderers::{RowSink, Value};
use crate::util::FxHashSet;

pub struct FrameworkInfo;

impl Plugin for FrameworkInfo {
    fn name(&self) -> &'static str {
        "frameworkinfo.FrameworkInfo"
    }
    fn description(&self) -> &'static str {
        "Plugin to list the various modular components of Volatility"
    }
    fn run(&self, _ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(crate::cols![("Data", Str)])?;
        for &(category, classes) in CATEGORIES {
            out.row(0, vec![Value::SStr(category)])?;
            if category != "Plugin" {
                for &c in classes {
                    out.row(1, vec![Value::SStr(c)])?;
                }
                continue;
            }
            let registered = crate::plugins::all(); // sorted by name
            let names: FxHashSet<&str> = registered.iter().map(|p| p.name()).collect();
            for &full in PLUGIN.iter().filter(|n| names.contains(*n)) {
                out.row(1, vec![Value::SStr(class_name(full))])?;
            }
            let known: FxHashSet<&str> = PLUGIN.iter().copied().collect();
            for p in registered.iter().filter(|p| !known.contains(p.name())) {
                out.row(1, vec![Value::SStr(class_name(p.name()))])?;
            }
        }
        Ok(())
    }
}

/// `clazz.__name__` of a plugin: the last component of its dotted name.
fn class_name(full: &'static str) -> &'static str {
    full.rsplit('.').next().unwrap_or(full)
}

/// python's category dict, in order (the Plugin entry holds CLI names, see [`PLUGIN`]).
const CATEGORIES: &[(&str, &[&str])] = &[
    ("Automagic", AUTOMAGIC),
    ("Requirement", REQUIREMENT),
    ("Layer", LAYER),
    ("LayerStacker", LAYER_STACKER),
    ("Object", OBJECT),
    ("Plugin", PLUGIN),
    ("Renderer", RENDERER),
];

#[rustfmt::skip]
const AUTOMAGIC: &[&str] = &[
    "ConstructionMagic", "LayerStacker", "SymbolCacheMagic", "SymbolFinder", "LinuxSymbolFinder",
    "MacSymbolFinder", "KernelModule", "KernelPDBScanner", "WinSwapLayers",
];
#[rustfmt::skip]
const REQUIREMENT: &[&str] = &[
    "SimpleTypeRequirement", "BooleanRequirement", "IntRequirement", "StringRequirement", "URIRequirement",
    "BytesRequirement", "ClassRequirement", "ConstructableRequirementInterface",
    "TranslationLayerRequirement", "SymbolTableRequirement", "ModuleRequirement",
    "ConfigurableRequirementInterface", "ComplexListRequirement", "LayerListRequirement",
    "TranslationLayerRequirement", "SymbolTableRequirement", "ModuleRequirement", "MultiRequirement",
    "ComplexListRequirement", "LayerListRequirement", "ListRequirement", "ChoiceRequirement",
    "VersionRequirement", "PluginRequirement",
];
#[rustfmt::skip]
const LAYER: &[&str] = &[
    "TranslationLayerInterface", "LinearlyMappedLayer", "Intel", "IntelPAE", "WindowsIntelPAE",
    "LinuxIntelPAE", "Intel32e", "WindowsIntel32e", "LinuxIntel32e", "WindowsMixin", "WindowsIntel",
    "WindowsIntelPAE", "WindowsIntel32e", "WindowsIntel", "LinuxMixin", "LinuxIntel", "LinuxIntelPAE",
    "LinuxIntel32e", "LinuxIntel", "RegistryHive", "PdbMultiStreamFormat", "PdbMSFStream", "SegmentedLayer",
    "WindowsCrashDump32Layer", "WindowsCrashDump64Layer", "Elf64Layer", "XenCoreDumpLayer", "LimeLayer",
    "VmwareLayer", "NonLinearlySegmentedLayer", "SegmentedLayer", "WindowsCrashDump32Layer",
    "WindowsCrashDump64Layer", "Elf64Layer", "XenCoreDumpLayer", "LimeLayer", "VmwareLayer", "AVMLLayer",
    "QemuSuspendLayer", "BufferDataLayer", "FileLayer",
];
#[rustfmt::skip]
const LAYER_STACKER: &[&str] = &[
    "WindowsCrashDumpStacker", "LinuxIntelStacker", "LinuxIntelVMCOREINFOStacker", "MacIntelStacker",
    "WindowsIntelStacker", "AVMLStacker", "Elf64Stacker", "XenCoreDumpStacker", "LimeStacker", "QemuStacker",
    "VmwareStacker",
];
#[rustfmt::skip]
const OBJECT: &[&str] = &[
    "Void", "Function", "PrimitiveObject", "Boolean", "Integer", "Pointer", "Float", "Char", "Bytes",
    "String", "BitField", "Enumeration", "Array", "AggregateType", "StructType", "GenericIntelProcess",
    "EPROCESS", "module", "task_struct", "proc", "IMAGE_DOS_HEADER", "IMAGE_NT_HEADERS", "KDDEBUGGER_DATA64",
    "POOL_HEADER", "POOL_HEADER_VISTA", "POOL_TRACKER_BIG_PAGES", "OBJECT_HEADER", "KSYSTEM_TIME",
    "MMVAD_SHORT", "MMVAD", "EX_FAST_REF", "DEVICE_OBJECT", "DRIVER_OBJECT", "OBJECT_SYMBOLIC_LINK",
    "FILE_OBJECT", "KMUTANT", "ETHREAD", "UNICODE_STRING", "ERESOURCE", "LIST_ENTRY", "TOKEN", "KTIMER",
    "KTHREAD", "CONTROL_AREA", "VACB", "SHARED_CACHE_MAP", "LDR_DATA_TABLE_ENTRY", "HMAP_ENTRY", "CMHIVE",
    "CM_KEY_BODY", "CM_KEY_NODE", "CM_KEY_VALUE", "elf", "elf_sym", "elf_phdr", "elf_linkmap", "fs_struct",
    "maple_tree", "mm_struct", "super_block", "vm_area_struct", "qstr", "dentry", "struct_file", "list_head",
    "hlist_head", "files_struct", "mount", "vfsmount", "kobject", "mnt_namespace", "bpf_prog", "bpf_prog_aux",
    "cred", "kernel_cap_struct", "kernel_cap_t", "timespec64", "inode", "address_space", "page", "IDR",
    "rb_root", "scatterlist", "latch_tree_root", "kernel_symbol", "module_sect_attr", "bin_attribute",
    "hist_entry", "net", "net_device", "in_device", "inet6_dev", "in_ifaddr", "inet6_ifaddr", "socket",
    "sock", "unix_sock", "inet_sock", "netlink_sock", "vsock_sock", "packet_sock", "bt_sock", "xdp_sock",
    "fileglob", "vm_map_object", "vnode", "vm_map_entry", "socket", "inpcb", "queue_entry", "ifnet",
    "sockaddr_dl", "sockaddr", "sysctl_oid", "kauth_scope", "_SHUTDOWN_PACKET", "ROW", "ALIAS",
    "EXE_ALIAS_LIST", "SCREEN_INFORMATION", "CONSOLE_INFORMATION", "COMMAND", "COMMAND_HISTORY",
    "SUMMARY_DUMP", "tagWINDOWSTATION", "tagDESKTOP", "tagWND", "LARGE_UNICODE_STRING", "PARTITION_TABLE",
    "PARTITION_ENTRY", "MFTEntry", "MFTFileName", "MFTAttribute", "_TCP_LISTENER", "_TCP_ENDPOINT",
    "_UDP_ENDPOINT", "_LOCAL_ADDRESS", "_LOCAL_ADDRESS_WIN10_UDP", "SHIM_CACHE_ENTRY", "SHIM_CACHE_HANDLE",
    "RTL_AVL_TABLE", "SERVICE_RECORD", "SERVICE_HEADER", "UnionType", "ClassType", "ExecutiveObject",
    "DEVICE_OBJECT", "DRIVER_OBJECT", "OBJECT_SYMBOLIC_LINK", "FILE_OBJECT", "KMUTANT", "ETHREAD", "EPROCESS",
    "_SHUTDOWN_PACKET", "tagWINDOWSTATION", "tagDESKTOP", "tagWND",
];
/// python 2.28.2 `class_subclasses(PluginInterface)` order, as CLI names (module path minus
/// `volatility3.plugins.`, plus the class name).
#[rustfmt::skip]
const PLUGIN: &[&str] = &[
    "windows.statistics.Statistics", "timeliner.Timeliner", "windows.pslist.PsList", "windows.info.Info",
    "windows.psscan.PsScan", "windows.handles.Handles", "windows.poolscanner.PoolScanner",
    "windows.bigpools.BigPools", "windows.registry.hivescan.HiveScan", "windows.registry.hivelist.HiveList",
    "windows.registry.printkey.PrintKey", "windows.registry.certificates.Certificates", "banners.Banners",
    "configwriter.ConfigWriter", "frameworkinfo.FrameworkInfo", "isfinfo.IsfInfo", "layerwriter.LayerWriter",
    "regexscan.RegExScan", "vmscan.Vmscan", "yarascan.YaraScan", "linux.elfs.Elfs", "linux.pslist.PsList",
    "linux.bash.Bash", "linux.boottime.Boottime", "linux.capabilities.Capabilities",
    "linux.malware.check_afinfo.Check_afinfo", "linux.check_afinfo.Check_afinfo",
    "linux.malware.check_creds.Check_creds", "linux.check_creds.Check_creds",
    "linux.malware.check_idt.Check_idt", "linux.check_idt.Check_idt",
    "linux.malware.check_modules.Check_modules", "linux.check_modules.Check_modules",
    "linux.malware.check_syscall.Check_syscall", "linux.check_syscall.Check_syscall", "linux.ebpf.EBPF",
    "linux.envars.Envars", "linux.malware.hidden_modules.Hidden_modules",
    "linux.hidden_modules.Hidden_modules", "linux.iomem.IOMem", "linux.ip.Addr", "linux.ip.Link",
    "linux.kallsyms.Kallsyms", "linux.malware.keyboard_notifiers.Keyboard_notifiers",
    "linux.keyboard_notifiers.Keyboard_notifiers", "linux.kmsg.Kmsg", "linux.kthreads.Kthreads",
    "linux.library_list.LibraryList", "linux.lsmod.Lsmod", "linux.lsof.Lsof", "linux.proc.Maps",
    "linux.malware.malfind.Malfind", "linux.malfind.Malfind", "linux.module_extract.ModuleExtract",
    "linux.malware.modxview.Modxview", "linux.modxview.Modxview", "linux.mountinfo.MountInfo",
    "linux.malware.netfilter.Netfilter", "linux.netfilter.Netfilter", "linux.pagecache.Files",
    "linux.pagecache.InodePages", "linux.pagecache.RecoverFs", "linux.pidhashtable.PIDHashTable",
    "linux.psaux.PsAux", "linux.pscallstack.PsCallStack", "linux.psscan.PsScan", "linux.pstree.PsTree",
    "linux.ptrace.Ptrace", "linux.sockstat.Sockstat", "linux.sockscan.Sockscan",
    "linux.malware.tty_check.Tty_Check", "linux.tty_check.tty_check", "linux.vmaregexscan.VmaRegExScan",
    "linux.vmayarascan.VmaYaraScan", "linux.vmcoreinfo.VMCoreInfo", "linux.graphics.fbdev.Fbdev",
    "linux.malware.process_spoofing.ProcessSpoofing", "linux.tracing.ftrace.CheckFtrace",
    "linux.tracing.perf_events.PerfEvents", "linux.tracing.tracepoints.CheckTracepoints", "mac.pslist.PsList",
    "mac.bash.Bash", "mac.lsmod.Lsmod", "mac.check_syscall.Check_syscall", "mac.check_sysctl.Check_sysctl",
    "mac.check_trap_table.Check_trap_table", "mac.dmesg.Dmesg", "mac.ifconfig.Ifconfig",
    "mac.kauth_scopes.Kauth_scopes", "mac.kauth_listeners.Kauth_listeners", "mac.kevents.Kevents",
    "mac.mount.Mount", "mac.list_files.List_Files", "mac.lsof.Lsof", "mac.malfind.Malfind",
    "mac.netstat.Netstat", "mac.proc_maps.Maps", "mac.psaux.Psaux", "mac.pstree.PsTree",
    "mac.socket_filters.Socket_filters", "mac.timers.Timers", "mac.trustedbsd.Trustedbsd",
    "mac.vfsevents.VFSevents", "windows.registry.amcache.Amcache", "windows.amcache.Amcache",
    "windows.registry.hashdump.Hashdump", "windows.registry.lsadump.Lsadump",
    "windows.registry.cachedump.Cachedump", "windows.cachedump.Cachedump", "windows.pedump.PEDump",
    "windows.modules.Modules", "windows.modscan.ModScan", "windows.ssdt.SSDT",
    "windows.driverscan.DriverScan", "windows.driverirp.DriverIrp", "windows.callbacks.Callbacks",
    "windows.cmdline.CmdLine", "windows.verinfo.VerInfo", "windows.consoles.Consoles",
    "windows.cmdscan.CmdScan", "windows.crashinfo.Crashinfo", "windows.pe_symbols.PESymbols",
    "windows.thrdscan.ThrdScan", "windows.threads.Threads", "windows.orphan_kernel_threads.Threads",
    "windows.debugregisters.DebugRegisters", "windows.windowstations.WindowStations",
    "windows.desktops.Desktops", "windows.deskscan.DeskScan", "windows.devicetree.DeviceTree",
    "windows.malware.direct_system_calls.DirectSystemCalls",
    "windows.malware.indirect_system_calls.IndirectSystemCalls",
    "windows.indirect_system_calls.IndirectSystemCalls", "windows.direct_system_calls.DirectSystemCalls",
    "windows.dlllist.DllList", "windows.malware.drivermodule.DriverModule",
    "windows.drivermodule.DriverModule", "windows.dumpfiles.DumpFiles", "windows.envars.Envars",
    "windows.etwpatch.EtwPatch", "windows.filescan.FileScan", "windows.getservicesids.GetServiceSIDs",
    "windows.getsids.GetSIDs", "windows.hashdump.Hashdump", "windows.vadinfo.VadInfo",
    "windows.malware.hollowprocesses.HollowProcesses", "windows.hollowprocesses.HollowProcesses",
    "windows.iat.IAT", "windows.joblinks.JobLinks", "windows.kpcrs.KPCRs",
    "windows.malware.ldrmodules.LdrModules", "windows.ldrmodules.LdrModules", "windows.lsadump.Lsadump",
    "windows.malware.malfind.Malfind", "windows.malfind.Malfind", "windows.mbrscan.MBRScan",
    "windows.memmap.Memmap", "windows.mftscan.MFTScan", "windows.mftscan.ADS", "windows.mftscan.ResidentData",
    "windows.mutantscan.MutantScan", "windows.netscan.NetScan", "windows.netstat.NetStat",
    "windows.privileges.Privs", "windows.malware.processghosting.ProcessGhosting",
    "windows.processghosting.ProcessGhosting", "windows.pstree.PsTree", "windows.malware.psxview.PsXView",
    "windows.psxview.PsXView", "windows.registry.scheduled_tasks.ScheduledTasks",
    "windows.scheduled_tasks.ScheduledTasks", "windows.sessions.Sessions",
    "windows.shimcachemem.ShimcacheMem", "windows.malware.skeleton_key_check.Skeleton_Key_Check",
    "windows.skeleton_key_check.Skeleton_Key_Check", "windows.strings.Strings",
    "windows.suspended_threads.SuspendedThreads", "windows.malware.suspicious_threads.SuspiciousThreads",
    "windows.suspicious_threads.SuspiciousThreads", "windows.svcscan.SvcScan", "windows.svclist.SvcList",
    "windows.malware.svcdiff.SvcDiff", "windows.svcdiff.SvcDiff", "windows.symlinkscan.SymlinkScan",
    "windows.timers.Timers", "windows.truecrypt.Passphrase",
    "windows.malware.unhooked_system_calls.UnhookedSystemCalls",
    "windows.unhooked_system_calls.unhooked_system_calls", "windows.unloadedmodules.UnloadedModules",
    "windows.vadregexscan.VadRegExScan", "windows.vadwalk.VadWalk", "windows.vadyarascan.VadYaraScan",
    "windows.virtmap.VirtMap", "windows.windows.Windows", "windows.malware.pebmasquerade.PebMasquerade",
    "windows.registry.getcellroutine.GetCellRoutine", "windows.registry.userassist.UserAssist",
];
#[rustfmt::skip]
const RENDERER: &[&str] = &[
    "CLIRenderer", "QuickTextRenderer", "NoneRenderer", "CSVRenderer", "PrettyTextRenderer", "JsonRenderer",
    "JsonLinesRenderer", "MermaidRenderer",
];
