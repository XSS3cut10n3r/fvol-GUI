"""Performance numbers for `vol serve` (run via bench/web/perf.sh).

Server side: warm plugin latency vs the CLI, streaming throughput and table memory for a
42-million-row plugin (windows.memmap without --pid), window fetch latency, view build times.
Browser side (headless chromium over CDP): shell load time, per-frame render cost while
scrolling the huge table, filter-to-pixels latency."""

import http.client
import json
import os
import statistics
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))

PORT = 18765
TOKEN = "testtoken-win-0123456789"
BIN = os.environ.get("BIN", "target/fast/vol")
IMG = "/home/user/cbc2/task2/memory-dirty.raw"
conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=600)


def req(method, path, body=None):
    h = {"Host": f"127.0.0.1:{PORT}", "X-Vol-Token": TOKEN}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    conn.request(method, path, body=data, headers=h)
    r = conn.getresponse()
    out = r.read()
    if path.endswith("/stream"):
        return out
    return json.loads(out) if out[:1] in (b"{", b"[") else out


def ms(xs):
    xs = sorted(xs)
    return f"median {statistics.median(xs) * 1e3:.2f} ms, p95 {xs[int(len(xs) * 0.95) - 1] * 1e3:.2f} ms"


print("== warm plugin latency (web: POST + stream to the end; cli: a fresh vol process)")
web, cli = [], []
for _ in range(20):
    t = time.perf_counter()
    r = req("POST", "/api/runs", {"plugin": "windows.pslist.PsList"})
    req("GET", f"/api/runs/{r['id']}/stream")
    web.append(time.perf_counter() - t)
for _ in range(20):
    t = time.perf_counter()
    subprocess.run([BIN, "-q", "-f", IMG, "windows.pslist"], capture_output=True)
    cli.append(time.perf_counter() - t)
print(f"windows.pslist  web {ms(web)}   cli {ms(cli)}")
web = []
for _ in range(10):
    t = time.perf_counter()
    r = req("POST", "/api/runs", {"plugin": "windows.handles.Handles"})
    req("GET", f"/api/runs/{r['id']}/stream")
    web.append(time.perf_counter() - t)
cli = []
for _ in range(10):
    t = time.perf_counter()
    subprocess.run([BIN, "-q", "-f", IMG, "windows.handles"], capture_output=True)
    cli.append(time.perf_counter() - t)
print(f"windows.handles web {ms(web)}   cli {ms(cli)}")

print("== 42M-row plugin: windows.memmap (no --pid)")
t = time.perf_counter()
r = req("POST", "/api/runs", {"plugin": "windows.memmap.Memmap"})
rid = r["id"]
first = None
while True:
    s = req("GET", f"/api/runs/{rid}")
    if first is None and s["stored"] > 0:
        first = time.perf_counter() - t
    if s["status"] != "running" and s["status"] != "queued" and not s["busy"]:
        break
    time.sleep(0.05)
total = time.perf_counter() - t
st = req("GET", "/api/stats")
print(f"first rows after {first * 1e3:.0f} ms; finished in {total:.1f} s; {s['rows']:,} rows produced, {s['stored']:,} stored "
      f"({s['rows'] / total / 1e6:.2f} M rows/s); table memory {st['table_bytes'] / 2**20:.0f} MiB "
      f"({st['table_bytes'] / max(1, s['stored']):.1f} B/row); truncated={s['truncated']}")

lat = []
n = s["stored"]
for i in range(300):
    off = (i * 7919 * 1000) % max(1, n - 256)
    t = time.perf_counter()
    req("GET", f"/api/runs/{rid}/rows?view=0&from={off}&count=256")
    lat.append(time.perf_counter() - t)
print(f"256-row window fetch at random offsets: {ms(lat)}")

for name, spec in [
    ("global filter 'ffff'", {"q": "0x1a2b"}),
    ("column filter Physical >= 0x100000000", {"cols": {"1": ">=0x100000000"}}),
    ("sort by Physical desc", {"sort": [[1, "desc"]]}),
]:
    t = time.perf_counter()
    v = req("POST", f"/api/runs/{rid}/view", spec)
    d = time.perf_counter() - t
    t = time.perf_counter()
    req("GET", f"/api/runs/{rid}/rows?view={v['view']}&from={v['total'] // 2}&count=256")
    d2 = time.perf_counter() - t
    print(f"view {name:<40} {d * 1e3:8.0f} ms -> {v['total']:>11,} rows; window fetch {d2 * 1e3:.2f} ms")

print("== browser (headless chromium)")
from cdp import Chrome  # noqa: E402
c = Chrome(1440, 900)
try:
    c.goto(f"http://127.0.0.1:{PORT}/#token={TOKEN}", 1.5)
    c.wait("document.querySelectorAll('.tnode').length > 0", 30)
    nav = c.eval("JSON.stringify(performance.getEntriesByType('navigation').map(e => [e.domContentLoadedEventEnd, e.loadEventEnd]))")
    print(f"app shell: DOMContentLoaded / load at {nav} ms after navigation start (after the login redirect)")
    c.eval(f"location.hash = 'run/{rid}'")
    c.wait("document.querySelector('#panes > .pane:not([hidden]) .vt-row:not(.loading)')", 30)
    c.pump(0.5)
    res = c.eval("""(async () => {
      const vt = document.querySelector('#panes > .pane:not([hidden]) .vt')._vt;
      const sc = vt.scroll;
      const costs = [];
      const H = sc.scrollHeight;
      for (let i = 0; i < 120; i++) {
        sc.scrollTop = (H * ((i * 37) % 120)) / 120;
        const t0 = performance.now();
        vt.render();
        document.body.getBoundingClientRect();
        void sc.offsetHeight;
        costs.push(performance.now() - t0);
        await new Promise(r => setTimeout(r, 30));
      }
      // after pages arrive
      const t1 = performance.now();
      vt.render();
      void sc.offsetHeight;
      const warm = performance.now() - t1;
      costs.sort((a, b) => a - b);
      return { median: costs[60], p95: costs[114], max: costs[119], warm, rows: vt.total };
    })()""")
    print(f"scroll-jump render over {res['rows']:,} rows (JS + layout per frame): median {res['median']:.2f} ms, p95 {res['p95']:.2f} ms, max {res['max']:.2f} ms")
    res = c.eval("""(async () => {
      const pane = document.querySelector('#panes > .pane:not([hidden])');
      const vt = pane.querySelector('.vt')._vt;
      const q = pane.querySelector('input.q');
      const t0 = performance.now();
      q.value = '0x7ff';
      q.dispatchEvent(new Event('input'));
      while (!(vt.view && vt.rowAt(0))) await new Promise(r => setTimeout(r, 5));
      vt.render();
      return { ms: performance.now() - t0, rows: vt.total };
    })()""")
    print(f"type a filter -> filtered rows on screen (incl. 180 ms debounce): {res['ms']:.0f} ms ({res['rows']:,} matching rows)")
    c.eval(f"location.hash = 'plugin/windows.pslist.PsList'")
    c.wait("document.querySelector('#panes > .pane:not([hidden]) .vt-row:not(.loading)')", 30)
    res = c.eval("""(() => {
      const vt = document.querySelector('#panes > .pane:not([hidden]) .vt')._vt;
      const costs = [];
      for (let i = 0; i < 50; i++) { const t0 = performance.now(); vt.moveTo(i); void vt.scroll.offsetHeight; costs.push(performance.now() - t0); }
      costs.sort((a, b) => a - b);
      return { median: costs[25], max: costs[49] };
    })()""")
    print(f"keyboard row move in a table (render + layout): median {res['median']:.2f} ms, max {res['max']:.2f} ms")
    if c.errors:
        print("JS errors:", c.errors)
finally:
    c.close()
