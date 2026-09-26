#!/usr/bin/env python3
"""Subcommands for the rsvol robustness fuzzer (fuzz_images.py)."""

import argparse
import json
import os
import random
import sys

import fuzz_geom as G
import fuzz_targets as T
import fuzz_mutate as M
from fuzz_images import (BASES, BAD, SCRATCH, SYMS, ROOT, FIXT, log, run_case, err_summary,
                         plugin_cases, parse_quick, hexint, automagic_values)


def _tg_path(base):
    return os.path.join(SCRATCH, 'targets', base + '.json')


# ---------------------------------------------------------------------------------------------
# targets: discover structures to corrupt in a clean image

def cmd_targets(a):
    base, osname = BASES[a.base]
    os.makedirs(os.path.join(SCRATCH, 'targets'), exist_ok=True)
    cache = os.path.join(SCRATCH, 'cache', 'targets-' + a.base)
    outdir = os.path.join(SCRATCH, 'out', 'targets-' + a.base)
    rng = random.Random(1)
    geo = G.Geometry(base)
    tg = {'base': a.base, 'image': base, 'os': osname, 'size': geo.size, 'kind': geo.kind,
          'headers': geo.headers, 'data_ranges': geo.data_ranges(), 'case_args': {}}

    # run the clean plugins that reveal object offsets, plus info
    want = sorted({s[0] for s in T.OBJ_SOURCES[osname]})
    if osname == 'windows':
        want += ['windows.info.Info', 'windows.dlllist.DllList']
    outputs = {}
    for p in want:
        r = run_case(a.bin, base, osname, [p], 1200, '6G', cache, outdir, 2, keep_stdout=True)
        log(f'  {p}: {r.cls} {r.secs}s')
        outputs[p] = r.stdout.decode('utf-8', 'replace') if r.cls in ('OK', 'ERROR') else ''

    am = automagic_values(cache)
    dtb = int(am['dtb'], 16)
    tg['dtb'] = dtb
    if osname == 'windows':
        info = {r['Variable']: r['Value'] for r in parse_quick(outputs.get('windows.info.Info', ''))}
        isf_path, shift, kbase = info.get('Symbols'), 0, int(info.get('Kernel Base', '0'), 16)
    elif osname == 'linux':
        # kernel-text symbols relocate by the text ASLR shift (`aslr`), not the physmap `kaslr`
        isf_path, shift, kbase = am.get('isf_a'), int(am.get('aslr', am.get('kaslr', '0')), 16), 0
    else:
        isf_path, shift, kbase = am.get('isf', '').split('\t')[-1], int(am.get('kaslr', '0'), 16), 0
    log(f'  ISF {isf_path}, dtb {dtb:#x}, shift {shift:#x}, kbase {kbase:#x}')
    isf = T.load_isf(isf_path) if isf_path else {}

    fd = os.open(base, os.O_RDONLY)
    w = G.Walker(fd, geo, dtb)

    def parts_v(va, size):
        """[voff, foff, len] page-by-page for [va, va+size)."""
        out, end, off = [], va + size, 0
        while va < end:
            chunk = min(end - va, G.PAGE - (va & 0xfff))
            f = w.v2f(va)
            if f is not None:
                out.append([off, f, chunk])
            va += chunk
            off += chunk
        return out

    # objects from clean output
    objs = []
    for plugin, col, stype, kind in T.OBJ_SOURCES[osname]:
        rows = parse_quick(outputs.get(plugin, ''))
        vals = sorted({G.canon(v) for r in rows if (v := hexint(r.get(col, ''))) })
        if len(vals) > a.max_per_kind:
            vals = sorted(rng.sample(vals, a.max_per_kind))
        s = T.struct_of(isf, stype)
        size = min(s['size'], 0x2000) if s and s['size'] else 0x400
        lists = []
        for fld in T.LIST_FIELDS.get(stype, []):
            o = T.member_offset(isf, stype, fld)
            if o is not None and o < size:
                lists.append([fld, o])
        n = 0
        for va in vals:
            parts = parts_v(va, size)
            if parts:
                objs.append({'kind': kind, 'type': stype, 'va': va, 'size': size,
                             'parts': parts, 'lists': lists})
                n += 1
        # capture a valid pid/base for argument cases
        if kind == 'proc' and rows and not tg['case_args'].get('pid'):
            for r in rows:
                pidv = r.get('PID') or r.get('Pid')
                if pidv and pidv.isdigit() and pidv != '0':
                    tg['case_args']['pid'] = int(pidv)
                    break
        log(f'  {kind}: {n} objects (size {size:#x}, lists {[l[0] for l in lists]})')
    tg['objects'] = objs

    # kernel symbols
    syms, table = [], isf.get('symbols', {})
    names = [n for n in T.SYMBOLS[osname] if n in table]
    other = [n for n in table if n not in names and table[n].get('address')]
    names += rng.sample(other, min(len(other), a.random_symbols))
    for n in names:
        addr = table[n].get('address')
        if addr is None:
            continue
        va = G.canon((kbase + addr) if osname == 'windows' else (addr + shift))
        parts = parts_v(va, 0x40)
        if parts:
            syms.append({'name': n, 'va': va, 'parts': parts})
    tg['symbols'] = syms
    log(f'  symbols: {len(syms)}')

    # page tables: kernel half + a sample of process DTBs
    tabs = w.tables(dtb, kernel_half=True, limit=a.max_tables, rng=rng)
    dtbs = []
    if osname == 'windows':
        for r in parse_quick(outputs.get('windows.pslist.PsList', '')):
            pass
    pt_foff = {}
    seen = set()
    for lvl, pa in tabs:
        if pa in seen:
            continue
        seen.add(pa)
        f = geo.p2f(pa)
        if f is not None:
            pt_foff[str(pa)] = f
    tg['tables'] = [[lvl, pa] for lvl, pa in tabs if pa in seen and str(pa) in pt_foff]
    tg['pt_foff'] = pt_foff
    log(f'  page tables: {len(tg["tables"])}')

    os.close(fd)
    with open(_tg_path(a.base), 'w') as f:
        json.dump(tg, f)
    log(f'  wrote {_tg_path(a.base)} '
        f'({len(objs)} objs, {len(syms)} syms, {len(tg["tables"])} PT, {len(geo.headers)} hdrs)')


def load_targets(base):
    with open(_tg_path(base)) as f:
        return json.load(f)


# ---------------------------------------------------------------------------------------------
# mutate / rerun

def build_mutant(base_img, tg, seed, nops, dst):
    M.reflink(base_img, dst)
    size = os.path.getsize(dst)
    fd = os.open(dst, os.O_RDWR)
    rng = random.Random(seed)
    mut = M.Mutator(fd, size, rng)
    ops = M.choose_ops(tg, seed, nops)
    descs = []
    for op, desc in ops:
        mut.apply(op)
        descs.append(desc)
    os.close(fd)
    return mut.log, descs


def cmd_mutate(a):
    base_img, osname = BASES[a.base]
    tg = load_targets(a.base)
    dst = a.out or os.path.join(SCRATCH, 'mutants', f'{a.base}-s{a.seed}.img')
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    mlog, descs = build_mutant(base_img, tg, a.seed, a.nops, dst)
    meta = {'base': a.base, 'image': base_img, 'os': osname, 'seed': a.seed, 'nops': a.nops,
            'log': mlog, 'descs': descs, 'mutant': dst}
    lp = dst + '.mutlog.json'
    with open(lp, 'w') as f:
        json.dump(meta, f)
    print(dst)
    for d in descs:
        print('   ', d)
    print('log:', lp)


def cmd_rerun(a):
    with open(a.logfile) as f:
        meta = json.load(f)
    base_img, osname = meta['image'], meta['os']
    dst = a.out or os.path.join(SCRATCH, 'mutants', f'rerun-{meta["base"]}-s{meta["seed"]}.img')
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    M.reflink(base_img, dst)
    fd = os.open(dst, os.O_RDWR)
    mut = M.Mutator(fd, os.path.getsize(dst), random.Random(0))
    for op in meta['log']:
        mut.apply(tuple(op))
    os.close(fd)
    log(f'rebuilt {dst} ({len(meta["log"])} ops)')
    tg = {'case_args': load_targets(meta['base']).get('case_args', {})} if os.path.exists(_tg_path(meta['base'])) else {'case_args': {}}
    cases = plugin_cases(osname, tg)
    if a.plugin:
        cases = [c for c in cases if a.plugin in c[0]]
    cache = os.path.join(SCRATCH, 'cache', 'rerun')
    outdir = os.path.join(SCRATCH, 'out', 'rerun')
    for label, argv in cases:
        r = run_case(a.bin, dst, osname, argv, a.timeout, a.mem, cache, outdir, a.jobs)
        mark = '  <<<' if r.cls in BAD else ''
        print(f'{r.cls:8} {label:55} {r.secs:6.1f}s{mark}')
        if r.cls in BAD:
            print('    ', err_summary(r.err_tail))
    if not a.keep:
        os.unlink(dst)


# ---------------------------------------------------------------------------------------------
# baseline: clean-image times and output hashes (for timeouts + pycompare context)

def _baseline_path(base):
    return os.path.join(SCRATCH, 'baseline', base + '.json')


def cmd_baseline(a):
    base_img, osname = BASES[a.base]
    tg = load_targets(a.base) if os.path.exists(_tg_path(a.base)) else {'case_args': {}}
    cases = plugin_cases(osname, tg)
    cache = os.path.join(SCRATCH, 'cache', 'baseline-' + a.base)
    outdir = os.path.join(SCRATCH, 'out', 'baseline-' + a.base)
    run_case(a.bin, base_img, osname, ['banners.Banners'], 900, '6G', cache, outdir, 2)
    bl = {}
    for label, argv in cases:
        r = run_case(a.bin, base_img, osname, argv, a.timeout, '6G', cache, outdir, 2)
        bl[label] = {'cls': r.cls, 'secs': r.secs, 'sha1': r.out_sha1, 'bytes': r.out_bytes}
        log(f'  {r.cls:8} {label:55} {r.secs:7.1f}s')
    os.makedirs(os.path.join(SCRATCH, 'baseline'), exist_ok=True)
    with open(_baseline_path(a.base), 'w') as f:
        json.dump({'base': a.base, 'os': osname, 'cases': bl}, f)
    log(f'  wrote {_baseline_path(a.base)}')


def _timeout_for(clean_secs, a):
    if clean_secs is None or clean_secs <= 0:
        return a.min_timeout
    t = max(a.min_timeout, int(a.mult * clean_secs))
    if t > a.max_timeout:
        t = max(a.max_timeout, int(clean_secs * 1.5))
    return t


# ---------------------------------------------------------------------------------------------
# campaign: N mutants x all cases; keep only mutants that produced a bug

def cmd_campaign(a):
    import threading
    from concurrent.futures import ThreadPoolExecutor
    base_img, osname = BASES[a.base]
    tg = load_targets(a.base)
    tg['_focus'] = a.focus
    bl = {}
    if os.path.exists(_baseline_path(a.base)):
        bl = json.load(open(_baseline_path(a.base)))['cases']
    cases = plugin_cases(osname, tg)
    if a.plugin:
        cases = [c for c in cases if a.plugin in c[0]]
    if a.skip:
        sk = a.skip.split(',')
        cases = [c for c in cases if not any(s in c[0] for s in sk)]
    os.makedirs(os.path.join(SCRATCH, 'results'), exist_ok=True)
    os.makedirs(os.path.join(SCRATCH, 'mutants'), exist_ok=True)
    os.makedirs(os.path.join(SCRATCH, 'kept'), exist_ok=True)
    results_path = a.results or os.path.join(SCRATCH, 'results', f'{a.base}.jsonl')
    lock = threading.Lock()
    counts = {}
    bugs = []
    rf = open(results_path, 'a')

    def one_mutant(seed):
        import shutil
        mdst = os.path.join(SCRATCH, 'mutants', f'{a.base}-s{seed}.img')
        cache = os.path.join(SCRATCH, 'cache', f'mut-{a.base}-s{seed}')
        outdir = os.path.join(SCRATCH, 'out', f'mut-{a.base}-s{seed}')
        try:
            mlog, descs = build_mutant(base_img, tg, seed, a.nops, mdst)
        except Exception as e:
            log(f'  seed {seed}: build failed {e}')
            return
        bad_here = []
        recs = []
        for label, argv in cases:
            to = _timeout_for((bl.get(label) or {}).get('secs'), a)
            r = run_case(a.bin, mdst, osname, argv, to, a.mem, cache, outdir, a.slots)
            rec = {'base': a.base, 'seed': seed, 'label': label, 'cls': r.cls, 'rc': r.rc,
                   'secs': r.secs, 'out_bytes': r.out_bytes, 'timeout': to, 'nops': a.nops,
                   'clean': (bl.get(label) or {}).get('cls')}
            if r.cls in BAD:
                rec['err'] = err_summary(r.err_tail)
                bad_here.append((label, r.cls, rec['err']))
            recs.append(rec)
            with lock:
                counts[r.cls] = counts.get(r.cls, 0) + 1
        with lock:
            for rec in recs:
                rf.write(json.dumps(rec) + '\n')
            rf.flush()
            for label, cls, err in bad_here:
                bugs.append((seed, label, cls, err))
                log(f'  BUG seed {seed} {cls} {label}: {err}')
        try:
            if bad_here:
                kept = os.path.join(SCRATCH, 'kept', f'{a.base}-s{seed}.img')
                os.replace(mdst, kept)
                with open(kept + '.mutlog.json', 'w') as f:
                    json.dump({'base': a.base, 'image': base_img, 'os': osname, 'seed': seed,
                               'nops': a.nops, 'log': mlog, 'descs': descs, 'mutant': kept,
                               'bugs': [{'label': l, 'cls': c, 'err': e} for l, c, e in bad_here]}, f)
                log(f'  kept {kept}')
            else:
                os.unlink(mdst)
        except OSError:
            pass
        shutil.rmtree(cache, ignore_errors=True)
        shutil.rmtree(outdir, ignore_errors=True)

    seeds = list(range(a.start, a.start + a.mutants))
    log(f'campaign {a.base}: {len(seeds)} mutants x {len(cases)} cases, par={a.par}, mem={a.mem}')
    if a.par > 1:
        with ThreadPoolExecutor(max_workers=a.par) as ex:
            list(ex.map(one_mutant, seeds))
    else:
        for s in seeds:
            one_mutant(s)
    rf.close()
    log(f'== {a.base} classes: ' + ' '.join(f'{k}={v}' for k, v in sorted(counts.items())))
    log(f'== bugs: {len(bugs)}')
    for seed, label, cls, err in bugs[:80]:
        log(f'   s{seed} {cls} {label}: {err}')


# ---------------------------------------------------------------------------------------------
# containers: fuzz the tiny synthetic container fixtures

def cmd_containers(a):
    import shutil
    fixtures = [f for f in sorted(os.listdir(FIXT))
                if not f.endswith(('.expect', '.py', '.sh')) and os.path.isfile(os.path.join(FIXT, f))]
    os.makedirs(os.path.join(SCRATCH, 'ctn'), exist_ok=True)
    cache = os.path.join(SCRATCH, 'cache', 'ctn')
    outdir = os.path.join(SCRATCH, 'out', 'ctn')
    counts, bugs = {}, []
    cases = [['banners.Banners'], ['layerwriter.LayerWriter'], ['frameworkinfo.FrameworkInfo']]
    for fx in fixtures:
        src = os.path.join(FIXT, fx)
        size = os.path.getsize(src)
        for seed in range(a.mutants):
            rng = random.Random(hash((fx, seed)) & 0xffffffff)
            dst = os.path.join(SCRATCH, 'ctn', f'{fx}.s{seed}')
            shutil.copy(src, dst)
            fd = os.open(dst, os.O_RDWR)
            mut = M.Mutator(fd, size, rng)
            style = seed % 5
            if style == 0:
                for _ in range(rng.randint(3, 12)):
                    mut.flip(rng.randrange(min(256, size)), rng.choice([1, 2, 4]))
            elif style == 1:
                mut.garbage(0, min(rng.randint(16, 128), size))
            elif style == 2:
                mut.apply(('truncate', rng.randrange(1, size)))
            elif style == 3:
                for _ in range(rng.randint(2, 6)):
                    mut.setbytes(rng.randrange(min(size, 512)), b'\xff\xff\xff\xff\xff\xff\xff\x7f')
            else:
                for _ in range(rng.randint(4, 20)):
                    mut.flip(rng.randrange(size), rng.choice([1, 2, 4, 8]))
            os.close(fd)
            for argv in cases:
                r = run_case(a.bin, dst, 'raw', argv, a.timeout, a.mem, cache, outdir, a.slots)
                counts[r.cls] = counts.get(r.cls, 0) + 1
                if r.cls in BAD:
                    bugs.append((fx, seed, argv[0], r.cls, err_summary(r.err_tail)))
                    log(f'  BUG {fx} s{seed} {argv[0]} {r.cls}: {err_summary(r.err_tail)}')
            os.unlink(dst)
    log('== containers classes: ' + ' '.join(f'{k}={v}' for k, v in sorted(counts.items())))
    log(f'== container bugs: {len(bugs)}')


# ---------------------------------------------------------------------------------------------
# pycompare: run python vol3 on a sample of degradation cases, diff stdout with rsvol

def cmd_pycompare(a):
    recs = [json.loads(l) for l in open(a.results) if l.strip()]
    # compare degradations: real panics + python-raise emulations first, then a sample of OK/ERROR
    rng = random.Random(a.seed)
    prio = [r for r in recs if r['cls'] in ('PANIC', 'PYRAISE')]
    rest = [r for r in recs if r['cls'] in ('OK', 'ERROR')]
    rng.shuffle(prio)
    rng.shuffle(rest)
    pool = prio + rest
    byfam, picked = {}, []
    for r in pool:
        parts = r['label'].split('.')
        fam = parts[0] + '.' + parts[1] if len(parts) > 1 else parts[0]
        if byfam.get(fam, 0) < a.per_family:
            byfam[fam] = byfam.get(fam, 0) + 1
            picked.append(r)
        if len(picked) >= a.limit:
            break
    log(f'pycompare: {len(picked)} sampled runs')
    cache_rs = os.path.join(SCRATCH, 'cache', 'pyc-rs')
    cache_py = os.path.join(SCRATCH, 'cache', 'pyc-py')
    outdir = os.path.join(SCRATCH, 'out', 'pyc')
    same = diffcls = diffout = 0
    for r in picked:
        base = r['base']
        tg = load_targets(base)
        base_img, osname = BASES[base]
        mdst = os.path.join(SCRATCH, 'mutants', f'pyc-{base}-s{r["seed"]}.img')
        build_mutant(base_img, tg, r['seed'], r.get('nops', 6), mdst)
        argv = None
        for label, av in plugin_cases(osname, tg):
            if label == r['label']:
                argv = av
                break
        if argv is None:
            os.unlink(mdst)
            continue
        to = r.get('timeout', a.timeout)
        rr = run_case(a.bin, mdst, osname, argv, to, a.mem, cache_rs, outdir, 2, keep_stdout=True)
        pr = run_case(a.bin, mdst, osname, argv, max(to, 120), '8G', cache_py, outdir, 2,
                      keep_stdout=True, pool='fuzzpy', python=True)
        rs_out = (rr.stdout or b'').decode('utf-8', 'replace')
        py_out = (pr.stdout or b'').decode('utf-8', 'replace')
        rsc, pyc = rr.cls, pr.cls
        tag = 'SAME'
        if (rsc == 'OK') != (pyc == 'OK'):
            tag = 'DIFF-CLASS'
            diffcls += 1
        elif rr.out_sha1 == pr.out_sha1:
            same += 1
        elif sorted(rs_out.splitlines()) == sorted(py_out.splitlines()):
            same += 1
        else:
            tag = 'DIFF-OUT'
            diffout += 1
        log(f'  {tag:10} {r["label"]:45} s{r["seed"]:<4} rs={rsc}/{rr.out_bytes} py={pyc}/{pr.out_bytes}')
        if tag != 'SAME' and a.verbose:
            import difflib
            d = list(difflib.unified_diff(py_out.splitlines(), rs_out.splitlines(),
                                          'python', 'rsvol', lineterm=''))
            for l in d[:24]:
                log('      ' + l)
        os.unlink(mdst)
    log(f'== pycompare: SAME={same} DIFF-CLASS={diffcls} DIFF-OUT={diffout}')


# ---------------------------------------------------------------------------------------------
# report

def cmd_report(a):
    counts, bugs, total = {}, [], 0
    for path in a.results:
        for l in open(path):
            if not l.strip():
                continue
            r = json.loads(l)
            total += 1
            counts[r['cls']] = counts.get(r['cls'], 0) + 1
            if r['cls'] in BAD:
                bugs.append(r)
    print(f'total runs: {total}')
    for k in sorted(counts):
        print(f'  {k:9} {counts[k]}')
    print(f'bugs (PANIC/HANG/OOM/SIGNAL/RUNAWAY): {len(bugs)}')
    seen = set()
    for r in bugs:
        key = (r['label'], r['cls'], r.get('err', '')[:80])
        if key in seen:
            continue
        seen.add(key)
        print(f"  {r['cls']:8} {r['base']}/s{r['seed']} {r['label']}: {r.get('err', '')}")


# ---------------------------------------------------------------------------------------------
# argparse

def main():
    import fuzz_images
    ap = argparse.ArgumentParser(prog='fuzz_images.py', description=fuzz_images.__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--bin', default=os.path.join(SCRATCH, 'bin', 'vol-base'), help='rsvol binary')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('targets')
    p.add_argument('base', choices=list(BASES))
    p.add_argument('--max-per-kind', type=int, default=60)
    p.add_argument('--max-tables', type=int, default=1200)
    p.add_argument('--random-symbols', type=int, default=40)
    p.set_defaults(fn=cmd_targets)

    p = sub.add_parser('baseline')
    p.add_argument('base', choices=list(BASES))
    p.add_argument('--timeout', type=float, default=1200)
    p.set_defaults(fn=cmd_baseline)

    p = sub.add_parser('mutate')
    p.add_argument('base', choices=list(BASES))
    p.add_argument('seed', type=int)
    p.add_argument('--nops', type=int, default=6)
    p.add_argument('--out')
    p.set_defaults(fn=cmd_mutate)

    p = sub.add_parser('rerun')
    p.add_argument('logfile')
    p.add_argument('--plugin')
    p.add_argument('--out')
    p.add_argument('--keep', action='store_true')
    p.add_argument('--timeout', type=float, default=120)
    p.add_argument('--mem', default='4G')
    p.add_argument('--jobs', type=int, default=2)
    p.set_defaults(fn=cmd_rerun)

    p = sub.add_parser('campaign')
    p.add_argument('base', choices=list(BASES))
    p.add_argument('--mutants', type=int, default=20)
    p.add_argument('--start', type=int, default=0)
    p.add_argument('--nops', type=int, default=6)
    p.add_argument('--par', type=int, default=2, help='mutants in parallel')
    p.add_argument('--slots', type=int, default=4, help='limit.sh global slots')
    p.add_argument('--mem', default='4G')
    p.add_argument('--min-timeout', type=float, default=45)
    p.add_argument('--max-timeout', type=float, default=600)
    p.add_argument('--mult', type=float, default=10)
    p.add_argument('--focus', choices=['mixed', 'objects', 'structure'], default='mixed',
                   help="'objects' keeps the kernel discoverable and hammers object/list/symbol "
                        "paths; 'structure' attacks page tables/containers/truncation")
    p.add_argument('--plugin', help='only cases whose label contains this')
    p.add_argument('--skip', help='comma-separated substrings of labels to skip')
    p.add_argument('--results')
    p.set_defaults(fn=cmd_campaign)

    p = sub.add_parser('containers')
    p.add_argument('--mutants', type=int, default=25, help='mutants per fixture')
    p.add_argument('--timeout', type=float, default=30)
    p.add_argument('--mem', default='2G')
    p.add_argument('--slots', type=int, default=4)
    p.set_defaults(fn=cmd_containers)

    p = sub.add_parser('pycompare')
    p.add_argument('results')
    p.add_argument('--limit', type=int, default=20)
    p.add_argument('--per-family', type=int, default=3)
    p.add_argument('--seed', type=int, default=0)
    p.add_argument('--timeout', type=float, default=120)
    p.add_argument('--mem', default='4G')
    p.add_argument('--verbose', action='store_true')
    p.set_defaults(fn=cmd_pycompare)

    p = sub.add_parser('report')
    p.add_argument('results', nargs='+')
    p.set_defaults(fn=cmd_report)

    a = ap.parse_args()
    a.fn(a)
