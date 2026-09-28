#!/usr/bin/env python3
"""Robustness fuzzer for fastvol: corrupt memory images, run every plugin, classify the outcome.

fastvol must never panic, hang, exhaust memory or run away on a damaged image (DESIGN.md rule 4:
"Never panic on malformed memory"). This driver builds corrupted copies ("mutants") of the test
images *without copying them* -- a btrfs reflink (`cp --reflink=auto`) shares every extent with
the original, then targeted in-place writes, hole punches and truncation cost only the changed
blocks -- runs the plugins of the image's OS on each mutant through `bench/scripts/limit.sh`
(memory cap + timeout on every run) and classifies each run:

    OK       exit 0
    ERROR    other clean exit (a python-style error / traceback; compare with python)
    PANIC    "panicked at" / stack overflow on stderr           <- bug
    HANG     killed by the per-run timeout                       <- bug
    OOM      killed by the memory cgroup cap                     <- bug
    SIGNAL   died by another signal (SIGSEGV/SIGABRT)            <- bug
    RUNAWAY  stdout exceeded the output cap                      <- bug

Corruption targets (see `targets` subcommand): random byte flips in page-table pages, kernel
objects (_EPROCESS / task_struct / hives / drivers / files ...) and their linked-list pointers
(made cyclic), kernel symbols, container headers (ELF/LiME/crash/...), plus generic damage:
zeroed / garbage pages, truncation at random offsets, huge counts.

Subcommands (run with -h for options):
    targets    BASE          discover structures to corrupt in a clean image  -> targets/<BASE>.json
    campaign   BASE          N mutants x every plugin case; keeps only failing mutants
    mutate     BASE SEED     build one mutant, print its path and mutation log
    rerun      LOGFILE       rebuild a mutant from its log and re-run its cases
    pycompare  RESULTS.jsonl run python vol3 on a sample of runs and diff stdout with fastvol
    containers               mutate the tiny container fixtures (tests/fixtures/containers)
    report     RESULTS...    print summary tables

Everything goes through limit.sh (slot pool "fuzz", memory cap -m, default 4G) with a per-run
timeout of max(--min-timeout, 20 x the clean run time). Mutants, caches and outputs live under
testdata/scratch/fuzz (disk, never /tmp). Standard library only.
"""

import argparse
import hashlib
import json
import os
import random
import signal
import struct
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fuzz_geom as G
import fuzz_targets as T

ROOT = '/home/user/fvol'
LIMIT = ROOT + '/bench/scripts/limit.sh'
SCRATCH = ROOT + '/testdata/scratch/fuzz'
SYMS = ROOT + '/testdata/symbols'
PYTHON = ROOT + '/bench/venv/bin/python'
VOLPY = ROOT + '/volatility3/vol.py'
IMG = ROOT + '/testdata/images'
FIXT = ROOT + '/tests/fixtures/containers'

BASES = {
    'win10': ('/home/user/cbc2/task2/memory-dirty.raw', 'windows'),
    'win1809': (IMG + '/windows/rsvol-win10-x64-17763-imagery.raw', 'windows'),
    'noble-elf': (IMG + '/linux/rsvol-noble-6.8.0-139.elf', 'linux'),
    'noble-lime': (IMG + '/linux/rsvol-noble-6.8.0-139.lime', 'linux'),
    'jammy-elf': (IMG + '/linux/rsvol-jammy-5.15.0-191.elf', 'linux'),
    'jammy-lime': (IMG + '/linux/rsvol-jammy-5.15.0-191.lime', 'linux'),
    'mac': (IMG + '/mac/rsvol-mac-mavericks-10.9.2-13C64.dmp', 'mac'),
}
BAD = ('PANIC', 'HANG', 'OOM', 'SIGNAL', 'RUNAWAY')


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def read_list(path):
    with open(path) as f:
        return [l.strip() for l in f if l.strip() and not l.startswith('#')]


# ---------------------------------------------------------------------------------------------
# run one plugin case in a memory-capped scope with a timeout; classify the result

class Run:
    __slots__ = ('cls', 'rc', 'secs', 'out_bytes', 'out_sha1', 'err_tail', 'stdout', 'label', 'argv')


def run_case(binary, image, osname, argv, timeout, mem, cache, outdir, slots,
             keep_stdout=False, out_cap=1 << 31, pool='fuzz', python=False):
    os.makedirs(outdir, exist_ok=True)
    if python:
        cmd = [LIMIT, '-m', mem, '-p', 'fuzzpy', '-s', str(slots), PYTHON, VOLPY]
    else:
        cmd = [LIMIT, '-m', mem, '-p', pool, '-s', str(slots), binary]
    cmd += ['-q', '-f', image, '-o', outdir]
    if osname in ('linux', 'mac'):
        cmd += ['-s', SYMS]
    cmd += argv
    env = dict(os.environ)
    env['FASTVOL_CACHE'] = cache
    env.pop('FASTVOL_TRACE', None)
    env.pop('RSVOL_TRACE', None)  # the pre-rename name is an alias
    t0 = time.monotonic()
    p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, env=env, start_new_session=True)
    st = {'bytes': 0, 'killed': None}
    h = hashlib.sha1()
    chunks, err = [], bytearray()

    def kill(why):
        if st['killed'] is None:
            st['killed'] = why
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def rd_out():
        while True:
            b = p.stdout.read(1 << 16)
            if not b:
                break
            st['bytes'] += len(b)
            h.update(b)
            if keep_stdout:
                chunks.append(b)
            if st['bytes'] > out_cap:
                kill('RUNAWAY')
                break

    def rd_err():
        while True:
            b = p.stderr.read(1 << 14)
            if not b:
                break
            err.extend(b)
            if len(err) > 1 << 16:
                del err[:len(err) - (1 << 16)]

    ts = [threading.Thread(target=rd_out, daemon=True), threading.Thread(target=rd_err, daemon=True)]
    for t in ts:
        t.start()
    try:
        p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        kill('HANG')
        p.wait()
    for t in ts:
        t.join(timeout=10)
    r = Run()
    r.rc, r.secs = p.returncode, round(time.monotonic() - t0, 3)
    r.out_bytes, r.out_sha1 = st['bytes'], h.hexdigest()
    r.stdout = b''.join(chunks) if keep_stdout else None
    et = err.decode('utf-8', 'replace')
    r.err_tail = et[-3000:]
    if st['killed']:
        r.cls = st['killed']
    elif r.rc in (137, -9) or 'memory allocation of' in et:
        r.cls = 'OOM'
    elif 'has overflowed its stack' in et:
        r.cls = 'PANIC'          # stack overflow -> real bug (unbounded recursion)
    elif 'panicked at' in et:
        r.cls = classify_panic(et)
    elif r.rc is not None and (r.rc >= 128 or r.rc < 0):
        r.cls = 'SIGNAL'
    elif r.rc == 0:
        r.cls = 'OK'
    else:
        r.cls = 'ERROR'
    return r


# fastvol deliberately emulates python's uncaught exceptions by panicking with a message that names
# the python exception; the CLI catches it (catch_unwind) and exits 1, exactly as python does, so
# these are NOT bugs (stderr text is irrelevant to parity). A panic whose message is a Rust-internal
# fault (index/unwrap/overflow/slice/unreachable/...) IS a bug: python would have skipped the object.
_PY_EXC = ('ValueError', 'TypeError', 'KeyError', 'IndexError', 'AttributeError', 'RuntimeError',
           'RecursionError', 'OverflowError', 'ZeroDivisionError', 'NotImplementedError',
           'FileNotFoundError', 'UnboundLocalError', 'AssertionError', 'UnicodeDecodeError',
           'StopIteration', 'OSError', 'MemoryError', 'NameError', 'LookupError', 'ArithmeticError',
           'struct.error', 're.error', 'yara.Error', 'yara.SyntaxError', 'PermissionError')
_RUST_PANIC = ('index out of bounds', 'Option::unwrap()', 'Result::unwrap()', 'unwrap()` on',
               'Option::expect', 'Result::expect', 'attempt to add with overflow',
               'attempt to subtract with overflow', 'attempt to multiply with overflow',
               'attempt to divide by zero', 'attempt to calculate the remainder with a divisor of zero',
               'attempt to negate with overflow', 'attempt to shift left with overflow',
               'attempt to shift right with overflow', 'slice index starts at', 'range start index',
               'range end index', 'byte index', 'out of range for slice', 'capacity overflow',
               'entered unreachable code', 'not yet implemented', 'not implemented',
               'assertion failed', 'assertion `left', 'misaligned pointer', 'explicit panic',
               'called `Option::unwrap()`', 'called `Result::unwrap()`')


def _panic_message(et):
    lines = et.splitlines()
    for i, l in enumerate(lines):
        if 'panicked at' in l:
            # message is on the next non-empty line(s)
            for m in lines[i + 1:]:
                if m.strip() and not m.startswith('note:') and not m.startswith('stack backtrace'):
                    return m.strip()
            return l.strip()
    return ''


def classify_panic(et):
    msg = _panic_message(et)
    if any(s in msg for s in _RUST_PANIC):
        return 'PANIC'
    # "No active exception to reraise" and "<name>: ..." are python-raise emulations
    if msg.startswith('No active exception') or any(
            msg == n or msg.startswith(n + ':') or msg.startswith(n + ' ') for n in _PY_EXC):
        return 'PYRAISE'
    # unrecognised panic message -> treat as a real bug to investigate
    return 'PANIC'


def err_summary(txt):
    lines = [l for l in txt.strip().splitlines() if l.strip()]
    for i, l in enumerate(lines):
        if 'panicked at' in l or 'overflowed its stack' in l:
            return ' | '.join(lines[i:i + 2])[:300]
    return (lines[-1] if lines else '')[:300]


# ---------------------------------------------------------------------------------------------
# plugin cases for an OS (no-arg lists + argument/dump/scan cases)

def plugin_cases(osname, tg):
    lists = {'windows': 'win_noarg.txt', 'linux': 'linux_noarg.txt', 'mac': 'mac_noarg.txt'}
    cases = [(p, [p]) for p in read_list(ROOT + '/bench/' + lists[osname])]
    extra = (tg or {}).get('case_args', {})
    pid = str(extra.get('pid', 4))
    if osname == 'windows':
        cases += [
            ('windows.memmap.Memmap', ['windows.memmap.Memmap', '--pid', pid]),
            ('windows.mftscan.MFTScan', ['windows.mftscan.MFTScan']),
            ('windows.mftscan.ADS', ['windows.mftscan.ADS']),
            ('windows.mftscan.ResidentData', ['windows.mftscan.ResidentData']),
            ('windows.malware.direct_system_calls.DirectSystemCalls', ['windows.malware.direct_system_calls.DirectSystemCalls']),
            ('windows.malware.indirect_system_calls.IndirectSystemCalls', ['windows.malware.indirect_system_calls.IndirectSystemCalls']),
            ('windows.vadyarascan.VadYaraScan', ['windows.vadyarascan.VadYaraScan', '--yara-rules', 'kernel32']),
            ('yarascan.YaraScan', ['yarascan.YaraScan', '--yara-rules', 'Microsoft']),
            ('regexscan.RegExScan', ['regexscan.RegExScan', '--pattern', r'http://[a-z]+\.com']),
            ('windows.pslist.PsList+dump', ['windows.pslist.PsList', '--dump']),
            ('windows.dlllist.DllList+dump', ['windows.dlllist.DllList', '--pid', pid, '--dump']),
            ('windows.vadinfo.VadInfo+dump', ['windows.vadinfo.VadInfo', '--pid', pid, '--dump']),
            ('windows.modules.Modules+dump', ['windows.modules.Modules', '--dump']),
            ('windows.registry.hivelist.HiveList+dump', ['windows.registry.hivelist.HiveList', '--dump']),
            ('windows.registry.printkey.PrintKey+recurse', ['windows.registry.printkey.PrintKey', '--recurse']),
            ('windows.malware.malfind.Malfind+dump', ['windows.malware.malfind.Malfind', '--dump']),
            ('windows.dumpfiles.DumpFiles', ['windows.dumpfiles.DumpFiles', '--pid', pid]),
            ('configwriter.ConfigWriter', ['configwriter.ConfigWriter']),
            ('layerwriter.LayerWriter', ['layerwriter.LayerWriter']),
        ]
        if extra.get('pedump_base'):
            cases.append(('windows.pedump.PEDump', ['windows.pedump.PEDump', '--pid', pid, '--base', extra['pedump_base']]))
    elif osname == 'linux':
        cases += [
            ('linux.vmaregexscan.VmaRegExScan', ['linux.vmaregexscan.VmaRegExScan', '--pattern', 'rsvol']),
            ('yarascan.YaraScan', ['yarascan.YaraScan', '--yara-rules', 'rsvol']),
            ('regexscan.RegExScan', ['regexscan.RegExScan', '--pattern', r'rsvol_[a-z]+']),
            ('linux.pslist.PsList+dump', ['linux.pslist.PsList', '--dump']),
            ('linux.proc.Maps+dump', ['linux.proc.Maps', '--pid', pid, '--dump']),
            ('linux.lsmod.Lsmod+dump', ['linux.lsmod.Lsmod', '--dump']),
            ('linux.pagecache.InodePages', ['linux.pagecache.InodePages', '--find', '/etc/passwd']),
            ('configwriter.ConfigWriter', ['configwriter.ConfigWriter']),
        ]
        if extra.get('module_base'):
            cases.append(('linux.module_extract.ModuleExtract', ['linux.module_extract.ModuleExtract', '--base', extra['module_base']]))
    elif osname == 'mac':
        cases += [
            ('yarascan.YaraScan', ['yarascan.YaraScan', '--yara-rules', 'Darwin']),
            ('mac.proc_maps.Maps+dump', ['mac.proc_maps.Maps', '--pid', pid, '--dump']),
            ('configwriter.ConfigWriter', ['configwriter.ConfigWriter']),
        ]
    seen, out = set(), []
    for c in cases:
        if c[0] not in seen:
            seen.add(c[0])
            out.append(c)
    return out


def parse_quick(text):
    lines = text.split('\n')
    i = 0
    while i < len(lines) and (lines[i].startswith('Volatility 3') or not lines[i].strip()):
        i += 1
    if i >= len(lines):
        return []
    hdr = lines[i].split('\t')
    rows = []
    for l in lines[i + 1:]:
        if not l.strip():
            continue
        f = l.lstrip('*').split('\t')
        if len(f) >= len(hdr):
            rows.append(dict(zip(hdr, f)))
    return rows


def hexint(s):
    s = s.strip()
    try:
        return int(s, 16) if s.startswith('0x') else None
    except ValueError:
        return None


def automagic_values(cache):
    d = os.path.join(cache, 'automagic')
    out = {}
    if os.path.isdir(d):
        for n in sorted(os.listdir(d)):
            with open(os.path.join(d, n)) as f:
                for l in f.read().splitlines()[1:]:
                    if '=' in l:
                        k, v = l.split('=', 1)
                        out.setdefault(k, v)
    return out


if __name__ == '__main__':
    import fuzz_cmds
    fuzz_cmds.main()
