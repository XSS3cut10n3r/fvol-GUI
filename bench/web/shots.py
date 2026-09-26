"""Drive the UI in headless chromium and take screenshots; fails on JS errors.

  bench/scripts/limit.sh -m 4G python3 bench/web/shots.py [--port 18765] [--name win] [steps...]

Needs a server started with bench/web/serve.sh (token testtoken-NAME-0123456789)."""

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from cdp import Chrome  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, default=18765)
ap.add_argument("--name", default="win")
ap.add_argument("--out", default="/home/user/rs-vol/testdata/scratch/webui/shots")
ap.add_argument("--size", default="1440x900")
ap.add_argument("steps", nargs="*")
a = ap.parse_args()
os.makedirs(a.out, exist_ok=True)
W, H = map(int, a.size.split("x"))
BASE = f"http://127.0.0.1:{a.port}"
TOKEN = f"testtoken-{a.name}-0123456789"

c = Chrome(W, H)
failed = []


def shot(name):
    p = os.path.join(a.out, f"{a.name}-{name}.png")
    c.shot(p)
    print("shot", p)


def step(name):
    def deco(fn):
        STEPS.append((name, fn))
        return fn
    return deco


STEPS = []


def login(hash_=""):
    c.goto(f"{BASE}/?token={TOKEN}{hash_}", 1.0)
    c.wait("document.querySelector('.tab')", 20)


def ready():
    c.wait("document.querySelectorAll('.tnode').length > 0 || document.querySelector('.tree-empty')", 30)
    c.pump(0.4)


@step("overview")
def overview():
    login()
    ready()
    c.pump(0.8)
    shot("01-overview")


@step("process")
def process():
    # the process with the most children that is still running: usually explorer / services
    pid = c.eval("import('/assets/core.js').then(m => { const ps = (m.store.procs||[]).filter(p => p.exit === null && p.name); ps.sort((a,b) => b.kids.length - a.kids.length); const e = ps.find(p => /explorer|systemd|launchd|bash|sshd/i.test(p.name)) || ps[0]; return e ? e.pid : null; })")
    c.eval(f"location.hash = 'proc/{pid}'")
    c.wait("document.querySelector('.pv-head h2')", 10)
    c.wait("document.querySelector('.subpanes .vt-row:not(.loading)') || document.querySelector('.subpanes .errcard') || document.querySelector('.subpanes .vt-empty:not([hidden])')", 30)
    c.pump(1.0)
    shot("02-process")


@step("palette")
def palette():
    c.key("k", mods=2)
    c.wait("document.querySelector('.palette')", 5)
    c.type("mal")
    c.pump(0.4)
    shot("03-palette")
    c.key("Tab")
    c.pump(0.3)
    shot("03b-palette-form")
    c.key("Escape")
    c.pump(0.2)


@step("results")
def results():
    c.eval("import('/assets/core.js').then(m => { location.hash = 'plugin/' + m.store.session.os + '.pslist.PsList'; })")
    c.wait("document.querySelector('#panes > .pane:not([hidden]) .vt-row:not(.loading)')", 20)
    c.pump(0.3)
    # sort by CreateTime descending via keyboard: focus table, move to column, press s twice
    c.eval("document.querySelector('#panes > .pane:not([hidden]) .vt').focus()")
    for _ in range(8):
        c.key("ArrowRight")
    c.key("s")
    c.pump(0.2)
    c.key("s")
    c.pump(0.5)
    c.key("ArrowDown")
    c.key("ArrowDown")
    c.key("Enter")
    c.pump(0.5)
    shot("04-results-drawer")


@step("filescan")
def filescan():
    c.eval("location.hash = 'plugin/windows.filescan.FileScan'")
    c.wait("document.querySelector('#panes > .pane:not([hidden]) .vt-row:not(.loading)')", 60)
    c.pump(0.5)
    c.key("/")
    c.type("\\users\\")
    c.pump(0.8)
    c.eval("document.querySelector('#panes > .pane:not([hidden]) .vt').focus()")
    c.key("f")
    c.pump(0.3)
    shot("05-filescan-filter")


@step("hex")
def hexview():
    off = c.eval("import('/assets/core.js').then(m => { const p = (m.store.procs||[]).find(p => typeof p.offset === 'string'); return p ? p.offset : '0x0'; })")
    c.eval(f"location.hash = 'hex/kernel/{off}'")
    c.wait("document.querySelector('#panes > .pane:not([hidden]) .hx-row b')", 10)
    c.pump(1.0)
    c.eval("document.querySelector('#panes > .pane:not([hidden]) .hx-grid').focus()")
    for k in ["ArrowRight"] * 8:
        c.key(k)
    c.key("d")
    c.pump(1.0)
    shot("06-hex")


@step("compare")
def compare():
    ids = c.eval("import('/assets/core.js').then(m => [...m.store.runs.values()].filter(r => r.status === 'done').map(r => [r.id, r.plugin]))")
    by = {p: i for i, p in ids}
    a_id = by.get("windows.pslist.PsList")
    run = c.eval("import('/assets/core.js').then(m => m.runPlugin('windows.psscan.PsScan', {}, {reuse: true}).then(r => r.id))")
    c.eval(f"import('/assets/core.js').then(m => m.whenDone({run}))")
    c.eval(f"location.hash = 'compare/{a_id}/{run}'")
    c.wait("document.querySelectorAll('.cmp-side .vt-row:not(.loading)').length > 2", 20)
    c.pump(0.8)
    shot("07-compare")


@step("timeline")
def timeline():
    c.eval("import('/assets/core.js').then(m => { location.hash = 'plugin/' + m.store.session.os + '.pslist.PsList'; })")
    c.wait("document.querySelector('#panes > .pane:not([hidden]) .vt-row:not(.loading)')", 20)
    c.eval("[...document.querySelectorAll('#panes > .pane:not([hidden]) .rv-bar button')].find(b => b.textContent === 'Timeline').click()")
    c.wait("document.querySelector('#panes > .pane:not([hidden]) .hist svg')", 10)
    c.pump(0.5)
    shot("08-timeline")


@step("light")
def light():
    c.eval("localStorage.setItem('rsvol.theme', 'light')")
    login()
    ready()
    c.pump(0.8)
    shot("09-overview-light")
    pid = c.eval("import('/assets/core.js').then(m => { const ps = (m.store.procs||[]).filter(p => p.exit === null && p.name); ps.sort((a,b) => b.kids.length - a.kids.length); return ps[0] ? ps[0].pid : null; })")
    c.eval(f"location.hash = 'proc/{pid}'")
    c.wait("document.querySelector('.subpanes .vt-row:not(.loading)') || document.querySelector('.subpanes .errcard')", 30)
    c.pump(0.8)
    shot("10-process-light")
    c.eval("localStorage.setItem('rsvol.theme', 'dark')")


@step("laptop")
def laptop():
    c.resize(1280, 720)
    login()
    ready()
    c.eval("import('/assets/core.js').then(m => { location.hash = 'plugin/' + m.store.session.os + '.pslist.PsList'; })")
    c.wait("document.querySelector('#panes > .pane:not([hidden]) .vt-row:not(.loading)')", 20)
    c.pump(0.6)
    shot("11-laptop-1280")
    c.resize(W, H)


@step("error")
def error():
    other = c.eval("import('/assets/core.js').then(m => m.store.session.os === 'windows' ? 'linux.pslist.PsList' : 'windows.info.Info')")
    c.eval(f"location.hash = 'plugin/{other}'")
    c.wait("document.querySelector('#panes > .pane:not([hidden]) .errcard')", 20)
    c.pump(0.4)
    shot("13-error")


@step("nosession")
def nosession():
    login()
    c.wait("document.querySelector('.evcard') || document.querySelector('.openbox')", 10)
    c.pump(1.0)
    shot("14-session")


@step("help")
def helpstep():
    c.key("?")
    c.pump(0.3)
    shot("12-help")
    c.key("Escape")


try:
    login()
    ready()
    for name, fn in STEPS:
        if a.steps and name not in a.steps:
            continue
        t = time.time()
        try:
            fn()
            print(f"ok   {name} ({time.time() - t:.1f}s)")
        except Exception as e:
            failed.append(name)
            print(f"FAIL {name}: {e}")
            try:
                shot("fail-" + name)
            except Exception:
                pass
finally:
    if c.errors:
        print("JS ERRORS:")
        for e in c.errors:
            print("  ", e[:400])
    c.close()
sys.exit(1 if failed or c.errors else 0)
