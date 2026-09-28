"""End-to-end checks of `fvol serve` against the real CLI (run via bench/web/e2e.sh).

Every check compares what the web API returns with what `fvol` prints for the same plugin and
options: streamed rows == the quick renderer's rows, python-identical exports == `fvol -r X`,
dumped files == the CLI's dumped files. Plus the access-control rules over real sockets."""

import hashlib
import http.client
import json
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# the untracked test data (testdata/, bench/ref/, bench/venv/, volatility3/) is in the main checkout,
# which linked worktrees find through git; FASTVOL_DATA overrides
DATA = os.environ.get("FASTVOL_DATA") or os.path.dirname(subprocess.run(
    ["git", "-C", ROOT, "rev-parse", "--path-format=absolute", "--git-common-dir"],
    capture_output=True, text=True).stdout.strip() or os.path.join(ROOT, ".git"))
BIN = os.environ.get("BIN", "target/fast/fvol")
SCR = os.path.join(DATA, "testdata/scratch/webui/e2e")
os.makedirs(SCR, exist_ok=True)
fails = []
passed = 0


def check(name, cond, detail=""):
    global passed
    if cond:
        passed += 1
        print(f"  ok   {name}")
    else:
        fails.append(name)
        print(f"  FAIL {name} {detail}")


class Server:
    def __init__(self, port, token):
        self.port, self.token = port, token

    def req(self, method, path, body=None, headers=None, host=None, raw=False):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=120)
        h = {"Host": host or f"127.0.0.1:{self.port}", "X-Vol-Token": self.token}
        if headers is not None:
            h.update(headers)
            h = {k: v for k, v in h.items() if v is not None}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        c.request(method, path, body=data, headers=h)
        r = c.getresponse()
        out = r.read()
        c.close()
        if raw:
            return r.status, out, r
        try:
            return r.status, json.loads(out) if out else None
        except ValueError:
            return r.status, out

    def run(self, plugin, args=None):
        st, j = self.req("POST", "/api/runs", {"plugin": plugin, "args": args or {}})
        assert st == 200, (st, j)
        rid = j["id"]
        # the NDJSON stream ends when the run is finished
        st, raw, _ = self.req("GET", f"/api/runs/{rid}/stream", raw=True)
        cols, rows, end = None, [], None
        for line in raw.decode().splitlines():
            ev = json.loads(line)
            if ev["t"] == "cols":
                cols = ev["cols"]
            elif ev["t"] == "rows":
                rows += ev["rows"]
            elif ev["t"] == "end":
                end = ev["run"]
        return rid, cols, rows, end


def cli(image, plugin, args=(), renderer="quick", syms=None, outdir=None):
    cmd = [BIN, "-q", "-r", renderer, "-f", image]
    if syms:
        cmd += ["-s", syms]
    if outdir:
        cmd += ["-o", outdir]
    cmd += [plugin, *args]
    return subprocess.run(cmd, capture_output=True).stdout


def quick_lines(rows):
    out = []
    for r in rows:
        d = r[1] >> 2
        cells = ["-" if c is None else "N/A" if c == 0 else c for c in r[2:]]
        out.append(("*" * d + " " if d else "") + "\t".join(cells))
    return out


def cli_quick_rows(text):
    # banner, blank, header, blank, rows... (multi-line cells make this approximate; compare joined text)
    lines = text.decode().split("\n")
    return "\n".join(lines[4:]).rstrip("\n")


def same_plugin(srv, image, plugin, args=None, argv=(), syms=None):
    rid, cols, rows, end = srv.run(plugin, args)
    check(f"{plugin} {' '.join(argv)} finished", end and end["status"] == "done", end and end.get("error"))
    q = cli(image, plugin, argv, syms=syms)
    check(f"{plugin} {' '.join(argv)}: streamed rows == fvol quick rows ({len(rows)})", "\n".join(quick_lines(rows)) == cli_quick_rows(q))
    for rend in ("jsonl", "csv", "quick"):
        st, body, _ = srv.req("GET", f"/api/runs/{rid}/vol?renderer={rend}", raw=True)
        ref = cli(image, plugin, argv, renderer=rend, syms=syms)
        check(f"{plugin} {' '.join(argv)}: export fvol -r {rend} byte-identical", st == 200 and body == ref, f"{len(body)} vs {len(ref)} bytes")
    return rid, cols, rows


def main():
    win = os.path.join(DATA, "testdata/images/windows/memory-dirty.raw")
    lnx = os.path.join(DATA, "testdata/images/linux/rsvol-noble-6.8.0-139.elf")
    syms = os.path.join(DATA, "testdata/symbols")
    w = Server(18765, "testtoken-win-0123456789")
    l = Server(18766, "testtoken-lnx-0123456789")

    print("access control")
    st, _ = w.req("GET", "/api/plugins", headers={"X-Vol-Token": None})
    check("no token -> 401", st == 401)
    st, _ = w.req("GET", "/api/plugins", headers={"X-Vol-Token": "x" * 24})
    check("wrong token -> 401", st == 401)
    st, _ = w.req("GET", "/api/plugins", host="attacker.example:18765")
    check("DNS-rebinding Host -> 421", st == 421)
    st, _ = w.req("GET", "/api/plugins", headers={"Sec-Fetch-Site": "cross-site"})
    check("cross-site fetch -> 403", st == 403)
    st, _ = w.req("GET", "/api/plugins", headers={"X-Vol-Token": None, "Cookie": f"fastvol_18765={w.token}"})
    check("a cookie is never a credential", st == 401)
    st, raw, r = w.req("GET", "/", headers={"X-Vol-Token": None}, raw=True)
    check("page holds no token and sets no cookie", st == 200 and w.token.encode() not in raw and not r.getheader("set-cookie"))
    st, j = w.req("POST", "/api/ticket", {"path": "/api/plugins"})
    tk = j["url"] if st == 200 else ""
    st1, _ = w.req("GET", tk, headers={"X-Vol-Token": None})
    st2, _ = w.req("GET", tk, headers={"X-Vol-Token": None})
    check("download ticket: works once, then refused", st1 == 200 and st2 == 401)
    st, j = w.req("POST", "/api/runs", {"plugin": "windows.strings.Strings", "args": {"strings_file": "http://127.0.0.1:9/x"}})
    check("remote URI options refused (no SSRF)", st in (404, 422))
    st, _ = w.req("GET", "/api/plugins", host="127.0.0.1:+18765")
    check("Host with a decorated port refused", st == 421)
    st, raw, r = w.req("GET", "/assets/app.js", raw=True)
    check("assets served with nosniff", st == 200 and r.getheader("x-content-type-options") == "nosniff")
    st, raw, r = w.req("GET", "/", headers={"X-Vol-Token": None}, raw=True)
    csp = r.getheader("content-security-policy") or ""
    check("app page has strict CSP", st == 200 and "script-src 'self'" in csp and "unsafe" not in csp)
    st, j = w.req("POST", "/api/runs", {"plugin": "windows.pslist.PsList", "args": {"pid": ["010"]}})
    check("python int(x,0) validation: '010' rejected", st == 422 and "invalid int value" in j["error"])
    st, j = w.req("POST", "/api/runs", {"plugin": "windows.nope.Nope"})
    check("unknown plugin -> 404", st == 404)

    print("windows: web == cli")
    rid, cols, rows = same_plugin(w, win, "windows.pslist.PsList")
    same_plugin(w, win, "windows.pstree.PsTree")
    same_plugin(w, win, "windows.pslist.PsList", {"pid": ["4", "0x1ac0"]}, ["--pid", "4", "0x1ac0"])
    same_plugin(w, win, "windows.handles.Handles", {"pid": [4688]}, ["--pid", "4688"])
    same_plugin(w, win, "windows.filescan.FileScan")

    print("views")
    st, v = w.req("POST", f"/api/runs/{rid}/view", {"q": "svchost", "sort": [[0, "desc"]]})
    exp = sorted([r for r in rows if any(isinstance(c, str) and "svchost" in c.lower() for c in r[2:])], key=lambda r: -int(r[2]))
    st2, page = w.req("GET", f"/api/runs/{rid}/rows?view={v['view']}&from=0&count=500")
    check(f"filter+sort view == python ({v['total']} rows)", v["total"] == len(exp) and [r[0] for r in page["rows"]] == [r[0] for r in exp])
    st, v = w.req("POST", f"/api/runs/{rid}/view", {"cols": {"0": ">=0x1000"}})
    check("numeric column filter", v["total"] == sum(1 for r in rows if int(r[2]) >= 0x1000))
    st, raw, _ = w.req("GET", f"/api/runs/{rid}/export?format=csv&view=0", raw=True)
    check("CSV export has every row", raw.decode().count("\r\n") == len(rows) + 1)

    print("dumped files")
    st, j = w.req("POST", "/api/runs", {"plugin": "windows.pslist.PsList", "args": {"pid": [4688], "dump": True}})
    rid = j["id"]
    w.req("GET", f"/api/runs/{rid}/stream", raw=True)
    st, files = w.req("GET", f"/api/runs/{rid}/files")
    d = os.path.join(SCR, "cli-dump")
    os.makedirs(d, exist_ok=True)
    for f in os.listdir(d):
        os.remove(os.path.join(d, f))
    cli(win, "windows.pslist.PsList", ["--pid", "4688", "--dump"], outdir=d)
    ref = {f: hashlib.sha256(open(os.path.join(d, f), "rb").read()).hexdigest() for f in os.listdir(d)}
    got = {}
    for f in files:
        # the way the browser does it: a ticket, then a plain GET without the header
        st, j = w.req("POST", "/api/ticket", {"path": f"/api/runs/{rid}/files/{f['name']}"})
        st, raw, _ = w.req("GET", j["url"], headers={"X-Vol-Token": None}, raw=True)
        got[f["name"]] = hashlib.sha256(raw).hexdigest()
    check(f"dumped files identical to the CLI's ({len(ref)} files)", ref and got == ref, f"{got} vs {ref}")
    # dumpfiles writes from parallel worker threads: its files must still land in the run's dir
    st, j = w.req("POST", "/api/runs", {"plugin": "windows.dumpfiles.DumpFiles", "args": {"pid": 5816}})
    did = j["id"]
    w.req("GET", f"/api/runs/{did}/stream", raw=True)
    st, dfiles = w.req("GET", f"/api/runs/{did}/files")
    d2 = os.path.join(SCR, "cli-dumpfiles")
    os.makedirs(d2, exist_ok=True)
    for f in os.listdir(d2):
        os.remove(os.path.join(d2, f))
    cli(win, "windows.dumpfiles.DumpFiles", ["--pid", "5816"], outdir=d2)
    ref2 = {f: hashlib.sha256(open(os.path.join(d2, f), "rb").read()).hexdigest() for f in os.listdir(d2)}
    got2 = {}
    for f in dfiles:
        st, j = w.req("POST", "/api/ticket", {"path": f"/api/runs/{did}/files/{f['name']}"})
        st, raw, _ = w.req("GET", j["url"], headers={"X-Vol-Token": None}, raw=True)
        got2[f["name"]] = hashlib.sha256(raw).hexdigest()
    check(f"dumpfiles (parallel writers): files identical to the CLI's ({len(ref2)} files)", ref2 and got2 == ref2, f"{len(got2)} vs {len(ref2)}")
    st, raw, _ = w.req("GET", f"/api/runs/{rid}/files/..%2f..%2fetc%2fpasswd", raw=True)
    check("download path traversal refused", st in (400, 404))
    st, raw, _ = w.req("GET", f"/api/runs/{rid}/files.zip", raw=True)
    check("zip of the run's files", st == 200 and raw[:4] == b"PK\x03\x04")

    print("memory")
    off = [r for r in rows if r[4] == "System"]
    st, m = w.req("GET", "/api/mem?layer=kernel&addr=0xf8014aa00000&len=64")
    check("kernel memory read (MZ at kernel base)", st == 200 and m["hex"].startswith("4d5a"))
    st, m = w.req("GET", "/api/mem?layer=pid:4688&addr=0x7ff000000000&len=16")
    check("process layer read answers (readable or reported bad)", st == 200 and (m["bad"] or len(m["hex"]) == 32))

    print("linux: web == cli")
    same_plugin(l, lnx, "linux.pslist.PsList", syms=syms)

    print(f"\n{passed} passed, {len(fails)} failed")
    if fails:
        print("FAILED:", *fails, sep="\n  ")
        sys.exit(1)


main()
