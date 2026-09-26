// Analyst-facing knowledge about plugins: categories, one-line "why you'd run it" blurbs,
// quick actions per OS, and the per-process pivots.

/** Category of a plugin name (first match wins). */
const CATS = [
  ['Timeline', /timeliner|mftscan|\.mft\.|timers?$/i],
  ['Malware & injection', /malfind|hollow|ghost|ldrmodules|psxview|suspicious|pebmasquerade|svcdiff|skeleton|unhooked|drivermodule|check_|hidden_modules|etwpatch|yarascan|vadyarascan|vmayarascan|modxview|direct_system_calls|indirect_system_calls|iat|processghosting|keyboard_notifiers|tty_check|trace|ebpf|kallsyms|malware/i],
  ['Network', /netscan|netstat|sockstat|sockscan|ifconfig|socket|network|netfilter/i],
  ['Registry', /registry|hivelist|hivescan|printkey|userassist|amcache|shimcache|getcellroutine|certificates|scheduled_tasks/i],
  ['Credentials', /hashdump|lsadump|cachedump|truecrypt|passphrase|keychain|kcrypt|cred/i],
  ['Files', /filescan|dumpfiles|lsof|pagecache|files|mountinfo|mount|mbrscan|dentry|inode|fdinfo/i],
  ['Memory', /vadinfo|vadwalk|vadregex|memmap|virtmap|maps|proc\.|elfs|strings|bigpools|poolscanner|regexscan|vmscan|pe_symbols|thread_pe|library_list|capabilities|vmaregex/i],
  ['Processes & threads', /pslist|pstree|psscan|psaux|pidhash|cmdline|envars|getsids|getservicesids|privileges|privs|sessions|joblinks|handles|dlllist|threads|thrdscan|suspended|debugregisters|consoles|cmdscan|bash|zsh|verinfo|windows\.windows|windowstations|desktops|deskscan|kthreads|ptrace|creds|psscan/i],
  ['Kernel & drivers', /modules|modscan|lsmod|driverscan|driverirp|devicetree|ssdt|callbacks|kpcrs|unloadedmodules|kmsg|dmesg|idt|syscall|symlinkscan|mutantscan|kevents|trustedbsd|notifiers|vfsevents|kauth|timers|orphan|kernel|mutant|symlink|poolscanner/i],
  ['Services', /svcscan|svclist|services/i],
  ['System info', /info|banners|frameworkinfo|isfinfo|crashinfo|statistics|layerwriter|configwriter|vmcoreinfo|boottime|lime/i],
];

export function category(name) {
  const n = name.toLowerCase();
  for (const [c, re] of CATS) if (re.test(n)) return c;
  return 'Other';
}

/** Short, analyst-oriented explanations (keyed by the name without OS prefix and class). */
export const BLURBS = {
  'pslist': 'Active processes from the kernel\'s process list. The baseline for everything else.',
  'pstree': 'Processes arranged by parent. Spot odd parents (a shell under a web server, svchost not under services.exe).',
  'psscan': 'Carves process objects from memory: finds exited and unlinked (hidden) processes pslist misses.',
  'psxview': 'Cross-checks several process sources; a process missing from some lists may be hidden.',
  'malware.psxview': 'Cross-checks several process sources; a process missing from some lists may be hidden.',
  'cmdline': 'The command line each process was started with — often the fastest way to spot abuse.',
  'envars': 'Environment variables per process (paths, user, temp dirs, injected variables).',
  'dlllist': 'Modules loaded by each process, from the PEB loader lists.',
  'handles': 'Open handles (files, registry keys, mutexes, events...) per process.',
  'getsids': 'The user and group SIDs of each process token — who a process runs as.',
  'privileges': 'Token privileges per process; watch for enabled debug / impersonation privileges.',
  'malfind': 'Finds injected code: private, executable memory with suspicious content. Review hexdump + disassembly.',
  'malware.malfind': 'Finds injected code: private, executable memory with suspicious content. Review hexdump + disassembly.',
  'malware.hollowprocesses': 'Detects process hollowing: the image in memory doesn\'t match the mapped file.',
  'malware.ldrmodules': 'Compares the three PEB module lists with the VADs; unlinked DLLs indicate stealth loading.',
  'ldrmodules': 'Compares the three PEB module lists with the VADs; unlinked DLLs indicate stealth loading.',
  'malware.processghosting': 'Processes whose image file was deleted before it ran (process ghosting).',
  'malware.suspicious_threads': 'Threads starting in memory that isn\'t backed by a file.',
  'netscan': 'Network connections and listeners, carved from memory (includes closed sockets).',
  'netstat': 'Network connections and listeners from the live TCP/IP tables.',
  'svcscan': 'Windows services from the service control manager: names, binaries, states.',
  'svclist': 'Windows services from the service control manager\'s list.',
  'filescan': 'File objects in memory — what was open, including files that are gone from disk.',
  'dumpfiles': 'Extract cached file contents from memory.',
  'modules': 'Loaded kernel drivers from the kernel\'s module list.',
  'modscan': 'Carves kernel modules from memory, including unloaded/hidden ones.',
  'driverscan': 'Carves driver objects from memory.',
  'ssdt': 'The system call table; entries outside ntoskrnl/win32k suggest hooks.',
  'callbacks': 'Kernel notification callbacks — a favourite rootkit persistence spot.',
  'timeliner': 'Merges timestamps from every timeline-capable plugin into one chronology.',
  'registry.hivelist': 'Registry hives loaded in memory, with their paths.',
  'registry.printkey': 'Print a registry key and its values (default: the root of every hive).',
  'registry.userassist': 'UserAssist: GUI programs a user ran, with counts and last run time.',
  'registry.amcache': 'Programs that executed, with hashes and paths, from the Amcache hive.',
  'registry.hashdump': 'Local account password hashes (needs the SAM and SYSTEM hives in memory).',
  'registry.lsadump': 'LSA secrets (service account passwords, cached keys).',
  'registry.cachedump': 'Cached domain logon hashes (DCC2).',
  'info': 'OS version, build, kernel base, DTB, capture time — what this image is.',
  'vadinfo': 'Virtual address descriptors: every memory region of a process with protection and backing file.',
  'memmap': 'Virtual to physical page mappings of a process (large).',
  'threads': 'Threads of each process with start addresses.',
  'sessions': 'Logon sessions and the processes in them.',
  'consoles': 'Console history and screen buffers (cmd.exe / conhost).',
  'cmdscan': 'Command history from console processes.',
  'strings': 'Map strings found in the image back to processes and kernel.',
  'bigpools': 'Large kernel pool allocations by tag.',
  'mutantscan': 'Named mutexes — malware often uses a unique mutex to avoid double infection.',
  'symlinkscan': 'Object-manager symbolic links (drive letters, device aliases).',
  'unloadedmodules': 'Recently unloaded kernel drivers.',
  'shimcachemem': 'Application compatibility cache (ShimCache) — evidence of executables on the system.',
  'psaux': 'Processes with their full argument lists.',
  'bash': 'Bash command history recovered from memory.',
  'lsof': 'Open files per process.',
  'lsmod': 'Loaded kernel modules.',
  'sockstat': 'Sockets per process with addresses and states.',
  'proc.maps': 'Memory mappings of each process (like /proc/PID/maps).',
  'elfs': 'ELF files mapped in each process.',
  'check_syscall': 'Checks the system call table for hooks.',
  'check_modules': 'Finds kernel modules hidden from the module list.',
  'hidden_modules': 'Finds kernel modules hidden from the module list.',
  'tty_check': 'Checks TTY operation handlers for hooks (keyloggers).',
  'mountinfo': 'Mount points per mount namespace.',
  'kmsg': 'The kernel log buffer (dmesg).',
  'envars.Envars': 'Environment variables per process.',
};

export function blurb(name) {
  const parts = name.split('.');
  const noOs = ['windows', 'linux', 'mac'].includes(parts[0]) ? parts.slice(1) : parts;
  const key = noOs.slice(0, -1).join('.');
  return BLURBS[key] || BLURBS[noOs[noOs.length - 2]] || '';
}

/** Overview quick actions: [label, [candidate plugin names], key hint]. */
export const QUICK = {
  windows: [
    ['Process tree', ['windows.pstree.PsTree', 'windows.pslist.PsList']],
    ['Command lines', ['windows.cmdline.CmdLine']],
    ['Network', ['windows.netscan.NetScan', 'windows.netstat.NetStat']],
    ['Injected code', ['windows.malware.malfind.Malfind', 'windows.malfind.Malfind']],
    ['Hidden processes', ['windows.malware.psxview.PsXView', 'windows.psxview.PsXView', 'windows.psscan.PsScan']],
    ['Services', ['windows.svcscan.SvcScan', 'windows.svclist.SvcList']],
    ['Loaded DLLs', ['windows.dlllist.DllList']],
    ['Open files', ['windows.filescan.FileScan']],
    ['Kernel drivers', ['windows.modules.Modules']],
    ['Registry hives', ['windows.registry.hivelist.HiveList']],
    ['Executed programs', ['windows.registry.userassist.UserAssist', 'windows.registry.amcache.Amcache', 'windows.shimcachemem.ShimcacheMem']],
    ['Timeline', ['timeliner.Timeliner']],
  ],
  linux: [
    ['Process tree', ['linux.pstree.PsTree', 'linux.pslist.PsList']],
    ['Command lines', ['linux.psaux.PsAux']],
    ['Network', ['linux.sockstat.Sockstat', 'linux.netstat.Netstat']],
    ['Injected code', ['linux.malware.malfind.Malfind', 'linux.malfind.Malfind']],
    ['Shell history', ['linux.bash.Bash']],
    ['Open files', ['linux.lsof.Lsof']],
    ['Kernel modules', ['linux.lsmod.Lsmod']],
    ['Hidden modules', ['linux.malware.hidden_modules.Hidden_modules', 'linux.hidden_modules.Hidden_modules']],
    ['Syscall hooks', ['linux.malware.check_syscall.Check_syscall', 'linux.check_syscall.Check_syscall']],
    ['Kernel log', ['linux.kmsg.Kmsg']],
    ['Mounts', ['linux.mountinfo.MountInfo']],
    ['Timeline', ['timeliner.Timeliner']],
  ],
  mac: [
    ['Process tree', ['mac.pstree.PsTree', 'mac.pslist.PsList']],
    ['Command lines', ['mac.psaux.Psaux']],
    ['Network', ['mac.netstat.Netstat']],
    ['Injected code', ['mac.malfind.Malfind']],
    ['Shell history', ['mac.bash.Bash']],
    ['Open files', ['mac.lsof.Lsof']],
    ['Kernel extensions', ['mac.lsmod.Lsmod']],
    ['Syscall hooks', ['mac.check_syscall.Check_syscall']],
    ['Kernel log', ['mac.dmesg.Dmesg']],
    ['Timeline', ['timeliner.Timeliner']],
  ],
};

/** Process list per OS and how to read its columns. */
export const PROCLIST = {
  windows: ['windows.pslist.PsList'],
  linux: ['linux.pslist.PsList'],
  mac: ['mac.pslist.PsList'],
};
export const PCOLS = {
  pid: ['PID', 'Pid'],
  ppid: ['PPID', 'PPid'],
  name: ['ImageFileName', 'COMM', 'Name', 'Process', 'COMMAND'],
  create: ['CreateTime', 'CREATION TIME', 'Start', 'StartTime'],
  exit: ['ExitTime'],
  offset: ['Offset(V)', 'OFFSET (V)', 'OFFSET', 'Offset'],
  threads: ['Threads'],
  handles: ['Handles'],
  session: ['SessionId'],
  wow64: ['Wow64'],
  uid: ['UID'],
};

/** Per-process pivots: [label, [candidates], {pidCol}] — plugins with a pid option get
 * `--pid N`, the others run once and are filtered on their PID column. */
export const PIVOTS = {
  windows: [
    ['Handles', ['windows.handles.Handles']],
    ['DLLs', ['windows.dlllist.DllList']],
    ['Memory regions', ['windows.vadinfo.VadInfo']],
    ['Environment', ['windows.envars.Envars']],
    ['Network', ['windows.netscan.NetScan', 'windows.netstat.NetStat']],
    ['Threads', ['windows.threads.Threads']],
    ['Injected code', ['windows.malware.malfind.Malfind', 'windows.malfind.Malfind']],
    ['Unlinked DLLs', ['windows.malware.ldrmodules.LdrModules', 'windows.ldrmodules.LdrModules']],
    ['SIDs', ['windows.getsids.GetSIDs']],
    ['Privileges', ['windows.privileges.Privs']],
    ['Sessions', ['windows.sessions.Sessions']],
  ],
  linux: [
    ['Open files', ['linux.lsof.Lsof']],
    ['Memory maps', ['linux.proc.Maps']],
    ['Environment', ['linux.envars.Envars']],
    ['Sockets', ['linux.sockstat.Sockstat']],
    ['Injected code', ['linux.malware.malfind.Malfind', 'linux.malfind.Malfind']],
    ['ELF files', ['linux.elfs.Elfs']],
    ['Libraries', ['linux.library_list.LibraryList']],
    ['Capabilities', ['linux.capabilities.Capabilities']],
  ],
  mac: [
    ['Open files', ['mac.lsof.Lsof']],
    ['Memory maps', ['mac.proc_maps.Maps']],
    ['Injected code', ['mac.malfind.Malfind']],
    ['Arguments', ['mac.psaux.Psaux']],
  ],
};

/** Plugins that print a process's command line: [plugin, column]. */
export const CMDLINE = {
  windows: [['windows.cmdline.CmdLine', 'Args']],
  linux: [['linux.psaux.PsAux', 'ARGS']],
  mac: [['mac.psaux.Psaux', 'Argv']],
};

/** Windows "find evil": expected parents and singleton processes. */
export const WIN_PARENTS = {
  'svchost.exe': ['services.exe', 'MsMpEng.exe'],
  'services.exe': ['wininit.exe'],
  'lsass.exe': ['wininit.exe'],
  'lsaiso.exe': ['wininit.exe'],
  'wininit.exe': ['smss.exe'],
  'winlogon.exe': ['smss.exe'],
  'csrss.exe': ['smss.exe'],
  'smss.exe': ['System', 'smss.exe'],
  'taskhostw.exe': ['svchost.exe'],
  'RuntimeBroker.exe': ['svchost.exe'],
  'explorer.exe': ['userinit.exe'],
  'spoolsv.exe': ['services.exe'],
  'dllhost.exe': ['svchost.exe', 'services.exe'],
  'WmiPrvSE.exe': ['svchost.exe'],
  'SearchIndexer.exe': ['services.exe'],
};
export const WIN_SINGLETONS = ['lsass.exe', 'services.exe', 'wininit.exe', 'lsaiso.exe', 'System', 'Registry', 'MemCompression'];
export const SUSPICIOUS_CHILDREN = /^(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|whoami|net1?|nltest|psexe?c?|wmic)\.exe$/i;
