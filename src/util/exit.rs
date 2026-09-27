//! The end of a one-shot run: exit without making the caller wait for the address-space
//! teardown, and keep the executable's code on huge pages.
//!
//! **Teardown off the exit path.** When a process exits, `exit_group` unmaps its whole address
//! space before the parent's `wait` returns: ~4,000 PTEs of executable, symbol blobs and the
//! memory image, 0.1-0.3 ms of a 1 ms run. [`detach_teardown`] hands the address space to a
//! helper process that shares it (`clone(CLONE_VM)`) and outlives this one by a moment, so this
//! process's `exit_group` only drops a reference and the unmapping happens in the helper after
//! the parent has been reaped. The helper runs on a static stack, makes raw system calls only
//! (no libc, TLS or allocation: it shares this process's memory), blocks every signal that can
//! be blocked, waits for its parent's death (`PR_SET_PDEATHSIG` with a blocked signal, re-checked
//! with `getppid`), then exits. Nothing observable changes:
//! * the output is complete: every descriptor is closed *before* the clone (after the final
//!   flush), so the helper holds no pipe or file and readers see EOF exactly as before;
//! * the exit status is this process's own `exit(code)`; a failed clone just exits normally;
//! * the helper is untraced (`CLONE_UNTRACED`), has no exit signal while the parent lives, is
//!   reparented and reaped by init (or the nearest subreaper) and never runs longer than the
//!   parent plus the teardown (and the huge-page collapse below).
//!
//! Caveat, CPU accounting: the teardown's CPU time is charged to the helper, so the caller's
//! `wait4`/`getrusage(RUSAGE_CHILDREN)`/`time` no longer include it (the cgroup still does).
//! It is only used by the one-shot CLI ([`arm`]): never by `vol serve`, tests or embedders.
//! `RSVOL_EXIT_HELPER=0` turns it off (and with it the collapse below).
//!
//! **Huge-page text.** The release binary is linked with 2 MB-aligned segments
//! (`.cargo/config.toml`), so the kernel can map its code and read-only data with 2 MB page-table
//! entries once they are in the page cache as 2 MB folios (read-only THP for regular files,
//! `CONFIG_READ_ONLY_THP_FOR_FS`, Linux 6.1+ for `MADV_COLLAPSE`). Mapped that way, a run takes a
//! handful of faults on the executable instead of ~100, and the hot code needs one iTLB entry.
//! The helper, after the parent is gone and off everyone's critical path, asks the kernel to
//! collapse those ranges (`MADV_COLLAPSE`): real work the first time (a few ms) and again only
//! if memory pressure split the folios; a cheap check when they are already huge; an error
//! (unsupported kernel or file system, no free huge page) is ignored and the next run just
//! tries again. `RSVOL_EXIT_HELPER=nothp` keeps the helper but skips the collapse.

use std::sync::atomic::{AtomicBool, Ordering};

static ARMED: AtomicBool = AtomicBool::new(false);

/// Let the next [`detach_teardown`] act: called by the one-shot CLI once it knows it is not
/// `vol serve`.
pub fn arm() {
    ARMED.store(true, Ordering::Relaxed);
}

/// `RSVOL_EXIT_HELPER`: unset (or anything else) = helper + huge-page collapse, `0` (or empty)
/// = neither, `nothp` = the helper without the collapse. `None` = off.
fn knob() -> Option<bool> {
    unsafe extern "C" {
        fn getenv(name: *const std::ffi::c_char) -> *const std::ffi::c_char;
    }
    let v = unsafe { getenv(c"RSVOL_EXIT_HELPER".as_ptr()) };
    if v.is_null() {
        return Some(true);
    }
    // SAFETY: getenv returns null or a NUL-terminated string
    match unsafe { std::ffi::CStr::from_ptr(v) }.to_bytes() {
        b"" | b"0" => None,
        b"nothp" => Some(false),
        _ => Some(true),
    }
}

/// Right before `exit`, once all output is written and flushed and no other thread writes
/// anything any more: if [`arm`]ed, close every descriptor and start the teardown helper (see
/// the module docs). Returns whether the helper runs. After a `true`, nothing may be written.
pub fn detach_teardown() -> bool {
    if !ARMED.swap(false, Ordering::Relaxed) {
        return false;
    }
    match knob() {
        Some(thp) => imp::detach(thp),
        None => false,
    }
}

/// The 2 MB-aligned parts of the running executable's read-only file-backed segments
/// (`(start, len)`, code first), from its program headers: what `MADV_COLLAPSE` can map with
/// huge pages. Empty when the load address or the segments are not 2 MB-aligned.
pub fn huge_ranges() -> Vec<(usize, usize)> {
    const AT_PHDR: u64 = 3;
    const AT_PHNUM: u64 = 5;
    const PT_LOAD: u32 = 1;
    const PT_PHDR: u32 = 6;
    const PF_X: u32 = 1;
    const PF_W: u32 = 2;
    const HUGE: u64 = 2 << 20;
    #[repr(C)]
    struct Phdr {
        p_type: u32,
        p_flags: u32,
        p_offset: u64,
        p_vaddr: u64,
        p_paddr: u64,
        p_filesz: u64,
        p_memsz: u64,
        p_align: u64,
    }
    unsafe extern "C" {
        fn getauxval(t: u64) -> u64;
    }
    let (phdr, n) = unsafe { (getauxval(AT_PHDR), getauxval(AT_PHNUM)) };
    if phdr == 0 || n == 0 || n > 64 || phdr % 8 != 0 {
        return Vec::new();
    }
    // SAFETY: AT_PHDR/AT_PHNUM describe the program headers the kernel mapped for this process
    let ph = unsafe { std::slice::from_raw_parts(phdr as *const Phdr, n as usize) };
    let bias = match ph.iter().find(|p| p.p_type == PT_PHDR) {
        Some(p) => phdr.wrapping_sub(p.p_vaddr),
        None => return Vec::new(),
    };
    if bias % HUGE != 0 {
        return Vec::new();
    }
    let mut v: Vec<(bool, usize, usize)> = Vec::new();
    for p in ph.iter().filter(|p| p.p_type == PT_LOAD && p.p_flags & PF_W == 0) {
        if p.p_vaddr.wrapping_sub(p.p_offset) % HUGE != 0 {
            continue;
        }
        let start = (bias + p.p_vaddr).next_multiple_of(HUGE);
        let end = (bias + p.p_vaddr + p.p_filesz) / HUGE * HUGE;
        if end > start {
            v.push((p.p_flags & PF_X == 0, start as usize, (end - start) as usize));
        }
    }
    v.sort();
    v.into_iter().map(|(_, s, l)| (s, l)).collect()
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod imp {
    use std::cell::UnsafeCell;

    const SYS_MADVISE: usize = 28;
    const SYS_GETPID: usize = 39;
    const SYS_CLONE: usize = 56;
    const SYS_EXIT_GROUP: usize = 231;
    const SYS_GETPPID: usize = 110;
    const SYS_PRCTL: usize = 157;
    const SYS_RT_SIGPROCMASK: usize = 14;
    const SYS_RT_SIGTIMEDWAIT: usize = 128;
    const SYS_CLOSE_RANGE: usize = 436;
    const CLONE_VM: usize = 0x100;
    const CLONE_UNTRACED: usize = 0x0080_0000;
    const PR_SET_PDEATHSIG: usize = 1;
    const SIGUSR1: usize = 10;
    const SIG_SETMASK: usize = 2;
    const MADV_COLLAPSE: usize = 25;
    const EINVAL: isize = 22;
    const ENOMEM: isize = 12;
    const MAX_RANGES: usize = 8;

    #[repr(C)]
    struct Args {
        parent: usize,
        n: usize,
        ranges: [(usize, usize); MAX_RANGES],
    }

    /// Written once by the parent before the clone, read only by the helper.
    struct Shared<T>(UnsafeCell<T>);
    // SAFETY: see above; one writer strictly before the (only) reader starts
    unsafe impl<T> Sync for Shared<T> {}

    static ARGS: Shared<Args> = Shared(UnsafeCell::new(Args { parent: 0, n: 0, ranges: [(0, 0); MAX_RANGES] }));
    /// The helper's stack (it needs a few hundred bytes).
    #[repr(C, align(64))]
    struct Stack([u8; 16384]);
    static STACK: Shared<Stack> = Shared(UnsafeCell::new(Stack([0; 16384])));

    #[inline(always)]
    unsafe fn sys(n: usize, a: usize, b: usize, c: usize, d: usize) -> isize {
        let r: isize;
        // SAFETY: a raw system call; the caller vouches for the arguments
        unsafe {
            std::arch::asm!("syscall", inlateout("rax") n as isize => r, in("rdi") a, in("rsi") b, in("rdx") c,
                in("r10") d, lateout("rcx") _, lateout("r11") _, options(nostack));
        }
        r
    }

    pub(super) fn detach(thp: bool) -> bool {
        let ranges = if thp { super::huge_ranges() } else { Vec::new() };
        // SAFETY: no helper runs yet, nothing else touches ARGS
        let args = unsafe { &mut *ARGS.0.get() };
        args.n = ranges.len().min(MAX_RANGES);
        args.ranges[..args.n].copy_from_slice(&ranges[..args.n]);
        drop(ranges);
        unsafe {
            args.parent = sys(SYS_GETPID, 0, 0, 0, 0) as usize;
            // every descriptor, so the helper's copy of the table is empty (EOF for pipe readers
            // comes with this process's exit, as before)
            if sys(SYS_CLOSE_RANGE, 0, u32::MAX as usize, 0, 0) != 0 {
                return false;
            }
            // the helper starts with every signal blocked: no handler ever runs on its stack
            let all: u64 = !0;
            let mut old: u64 = 0;
            sys(SYS_RT_SIGPROCMASK, SIG_SETMASK, &all as *const u64 as usize, &mut old as *mut u64 as usize, 8);
            let top = (STACK.0.get() as usize + std::mem::size_of::<Stack>()) & !15;
            let ret: isize;
            std::arch::asm!(
                "syscall",
                "test rax, rax",
                "jnz 2f",
                // child: own stack, shared memory; never returns
                "xor ebp, ebp",
                "mov rdi, r12",
                "call {helper}",
                "ud2",
                "2:",
                helper = sym helper,
                inlateout("rax") SYS_CLONE as isize => ret,
                in("rdi") CLONE_VM | CLONE_UNTRACED, // no exit signal: nobody waits for it
                in("rsi") top,
                in("rdx") 0usize,
                in("r10") 0usize,
                in("r8") 0usize,
                in("r12") ARGS.0.get() as usize,
                lateout("rcx") _,
                lateout("r11") _,
            );
            sys(SYS_RT_SIGPROCMASK, SIG_SETMASK, &old as *const u64 as usize, 0, 8);
            ret > 0
        }
    }

    /// The helper process. Raw system calls only: it shares the parent's memory, TLS included.
    extern "C" fn helper(args: *const Args) -> ! {
        unsafe {
            let a = &*args;
            // woken by a (blocked, so only queued) SIGUSR1 when the parent dies; the getppid
            // check covers a parent that died before the prctl, and spurious signals
            sys(SYS_PRCTL, PR_SET_PDEATHSIG, SIGUSR1, 0, 0);
            let set: u64 = 1 << (SIGUSR1 - 1);
            while sys(SYS_GETPPID, 0, 0, 0, 0) as usize == a.parent {
                sys(SYS_RT_SIGTIMEDWAIT, &set as *const u64 as usize, 0, 0, 8);
            }
            let ranges = &a.ranges[..a.n.min(MAX_RANGES)];
            if !ranges.is_empty() && !all_huge(ranges) {
                for &(start, len) in ranges {
                    let r = sys(SYS_MADVISE, start, len, MADV_COLLAPSE, 0);
                    // not supported here, or no huge page to be had: do not keep trying
                    if r == -EINVAL || r == -ENOMEM {
                        break;
                    }
                }
            }
            sys(SYS_EXIT_GROUP, 0, 0, 0, 0);
            std::hint::unreachable_unchecked()
        }
    }

    /// Whether every page of `ranges` the run touched is mapped by a huge page (then the page
    /// cache still holds the collapsed folios and there is nothing to do): one `PAGEMAP_SCAN`
    /// (Linux 6.7+) for present pages that are not huge. `false` when it cannot tell.
    unsafe fn all_huge(ranges: &[(usize, usize)]) -> bool {
        const SYS_OPEN: usize = 2;
        const SYS_CLOSE: usize = 3;
        const SYS_IOCTL: usize = 16;
        const O_RDONLY_CLOEXEC: usize = 0o2000000;
        const PAGEMAP_SCAN: usize = 0xc060_6610; // _IOWR('f', 16, struct pm_scan_arg)
        const PAGE_IS_PRESENT: u64 = 1 << 3;
        const PAGE_IS_HUGE: u64 = 1 << 6;
        #[repr(C)]
        struct PmScanArg {
            size: u64,
            flags: u64,
            start: u64,
            end: u64,
            walk_end: u64,
            vec: u64,
            vec_len: u64,
            max_pages: u64,
            category_inverted: u64,
            category_mask: u64,
            category_anyof_mask: u64,
            return_mask: u64,
        }
        unsafe {
            let fd = sys(SYS_OPEN, c"/proc/self/pagemap".as_ptr() as usize, O_RDONLY_CLOEXEC, 0, 0);
            if fd < 0 {
                return false;
            }
            let mut found = 0isize;
            for &(start, len) in ranges {
                let mut region = [0u64; 3];
                let mut arg = PmScanArg {
                    size: std::mem::size_of::<PmScanArg>() as u64,
                    flags: 0,
                    start: start as u64,
                    end: (start + len) as u64,
                    walk_end: 0,
                    vec: region.as_mut_ptr() as u64,
                    vec_len: 1,
                    max_pages: 0,
                    // present and not huge
                    category_inverted: PAGE_IS_HUGE,
                    category_mask: PAGE_IS_PRESENT | PAGE_IS_HUGE,
                    category_anyof_mask: 0,
                    return_mask: PAGE_IS_PRESENT,
                };
                found = sys(SYS_IOCTL, fd as usize, PAGEMAP_SCAN, &mut arg as *mut PmScanArg as usize, 0);
                if found != 0 {
                    break;
                }
            }
            sys(SYS_CLOSE, fd as usize, 0, 0, 0);
            found == 0
        }
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
mod imp {
    pub(super) fn detach(_thp: bool) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn huge_ranges_are_aligned_and_read_only() {
        // test binaries may or may not be linked with 2 MB segments: whatever is returned must
        // be 2 MB-aligned, inside the executable's read-only mappings
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        let exe = std::fs::read_link("/proc/self/exe").unwrap();
        for (s, l) in super::huge_ranges() {
            assert!(s % (2 << 20) == 0 && l % (2 << 20) == 0 && l > 0);
            let inside = maps.lines().filter(|m| m.ends_with(exe.to_str().unwrap())).any(|m| {
                let mut it = m.split_whitespace();
                let (range, perms) = (it.next().unwrap(), it.next().unwrap());
                let (lo, hi) = range.split_once('-').unwrap();
                let (lo, hi) = (usize::from_str_radix(lo, 16).unwrap(), usize::from_str_radix(hi, 16).unwrap());
                !perms.contains('w') && lo <= s && s + l <= hi
            });
            assert!(inside, "{s:#x}+{l:#x} not in a read-only mapping of the executable");
        }
    }

    #[test]
    fn detach_is_off_unless_armed() {
        // tests never arm it: no helper, no closed descriptors
        assert!(!super::detach_teardown());
        assert!(std::fs::metadata("/proc/self/fd/1").is_ok() || std::fs::metadata("/proc/self/fd/2").is_ok());
    }
}
