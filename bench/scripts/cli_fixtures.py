#!/usr/bin/env python3
"""Differential fixtures for the CLI (argument parsing, --help, errors, exit codes).

Writes
  tests/fixtures/cli_plugins.json  every python plugin: name, docstring, CLI-visible
                                   requirements, and its `vol.py <plugin> -h` output
  tests/fixtures/cli_cases.json    argv cases run through python's real CLI (stopped before the
                                   plugin runs, see vol_argdump.py): stdout, stderr, exit code
`cargo test` builds fake plugins with the same metadata and replays every case through
`cli::run`.

Run with:  /home/user/fvol/bench/venv/bin/python bench/scripts/cli_fixtures.py
"""
import json
import os
import subprocess
import sys

sys.path.insert(0, "/home/user/fvol/volatility3")

PY = "/home/user/fvol/bench/venv/bin/python"
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FIX = os.path.join(ROOT, "tests", "fixtures")
DUMP = os.path.join(ROOT, "bench", "scripts", "vol_argdump.py")
# fixed sandbox shared with the rust test (src/cli/tests.rs)
BASE = "/tmp/rsvol-cli-fixture"
IMG = BASE + "/image.raw"
CFG = BASE + "/config.json"
CFG_NESTED = BASE + "/config_nested.json"
FILES = {
    CFG: json.dumps({"pid": [4], "kernel.offset": 1, "dump": True}),
    CFG_NESTED: json.dumps({"pid": [4], "kernel": {"offset": 1}}),
    IMG: "\0" * 4096,
}


def env(columns=80):
    e = dict(os.environ)
    e.update(
        {
            "COLUMNS": str(columns),
            "XDG_CACHE_HOME": BASE + "/cache",
            "HOME": BASE + "/home",
            "PYTHON_COLORS": "0",
        }
    )
    e.pop("NO_COLOR", None)
    e.pop("FORCE_COLOR", None)
    return e


def run(args, columns=80):
    p = subprocess.run([PY, DUMP] + args, cwd=BASE, env=env(columns), capture_output=True, text=True)
    return {"out": p.stdout, "err": p.stderr, "code": p.returncode}


def plugin_metadata():
    from volatility3 import framework
    from volatility3.framework import interfaces
    from volatility3.framework.configuration import requirements as R
    import volatility3.plugins

    framework.import_files(volatility3.plugins, True)
    plugins = framework.list_plugins()

    def default(d):
        if isinstance(d, bytes):
            return {"bytes": d.hex()}
        return d

    out = []
    for name in sorted(plugins):
        cls = plugins[name]
        reqs = []
        for r in cls.get_requirements():
            if isinstance(r, interfaces.configuration.SimpleTypeRequirement):
                if isinstance(r, R.BooleanRequirement):
                    kind = "bool"
                elif isinstance(r, R.IntRequirement):
                    kind = "int"
                elif isinstance(r, R.BytesRequirement):
                    kind = "bytes"
                elif isinstance(r, R.URIRequirement):
                    kind = "uri"
                elif isinstance(r, R.StringRequirement):
                    kind = "str"
                else:
                    raise TypeError(f"{name}: unknown simple requirement {type(r)}")
            elif isinstance(r, R.ListRequirement):
                kind = "list_int" if r.element_type is int else "list_str"
            elif isinstance(r, R.ChoiceRequirement):
                kind = "choice"
            else:
                continue
            reqs.append(
                {
                    "name": r.name,
                    "description": r.description,
                    "kind": kind,
                    "default": default(r.default),
                    "optional": r.optional,
                    "choices": list(r.choices) if kind == "choice" else None,
                }
            )
        out.append({"name": name, "doc": cls.__doc__, "requirements": reqs})
    return out


def cases(meta):
    by_kind = {}
    for p in meta:
        for r in p["requirements"]:
            by_kind.setdefault(r["kind"], []).append((p["name"], r))
    required = [(p["name"], r) for p in meta for r in p["requirements"] if not r["optional"]]

    c = [
        [],
        ["-h"],
        ["--help"],
        ["-h", "windows.pslist"],
        ["--he"],
        ["windows.pslist.PsList", "-h"],
        ["windows.pslist", "--help"],
        ["windows.info", "-h", "--bogus"],
        ["pslist"],
        ["foo.bar"],
        ["windows.pslist", "--bogus"],
        ["-q", "windows.pslist.PsList", "--pid", "x"],
        ["-f", IMG, "windows.pslist", "--pid", "4", "0x10", "0o7", "0b11", "1_000", "-1"],
        ["-f", IMG, "windows.pslist", "--pid"],
        ["-f", IMG, "windows.pslist", "--pid=4", "--dump", "--physical"],
        ["-f", IMG, "windows.pslist", "--pi", "4"],
        ["-f", IMG, "windows.pslist", "--p", "4"],
        ["-f", IMG, "windows.pslist", "--dump=1"],
        ["-f", IMG, "windows.pslist", "--pid", "01"],
        ["-f", "/nonexistent", "windows.info"],
        ["-f", "file:///nonexistent", "windows.info"],
        ["-f", "file://" + IMG, "windows.info"],
        ["-f", "http://example.com/x", "windows.info"],
        ["-o", "/nonexistent_dir", "windows.info"],
        ["-o", BASE, "-f", IMG, "windows.info"],
        ["-o", "", "windows.info"],
        ["-f", "", "-c", "", "windows.info"],
        ["-o", "cache", "windows.info"],
        ["-f", "image.raw", "windows.info"],
        ["-f", "./sub/../image.raw", "windows.info"],
        ["-f"],
        ["-l"],
        ["-r", "bogus", "windows.info"],
        ["-r"],
        ["-r", "json", "windows.info"],
        ["-r", "csv", "-h"],
        ["--offline", "-u", "http://x", "windows.info"],
        ["-u", "http://x", "--offline", "windows.info"],
        ["--offline", "--offline", "windows.info"],
        ["--fi", "x", "windows.info"],
        ["--file=" + IMG, "-qvv", "windows.info"],
        ["-f" + IMG, "-r", "csv", "windows.info"],
        ["-qf" + IMG, "windows.info"],
        ["-qvf", IMG, "windows.info"],
        ["-q=1", "windows.info"],
        ["-vvv", "--filters", "a", "--filters=b", "--hide-columns", "x", "y", "-e", "a=1", "windows.info"],
        ["--hide-columns", "x", "--", "windows.info"],
        ["--hide-columns", "windows.info"],
        ["--hide-columns", "-q", "windows.info"],
        ["--parallelism", "windows.info"],
        ["--parallelism", "--", "windows.info"],
        ["--parallelism=threads", "windows.info"],
        ["--parallelism", "-q", "windows.info"],
        ["-f", IMG, "windows.info", "-f", IMG],
        ["-q", "windows.info.Info", "extra"],
        ["--single-location", IMG, "windows.info"],
        ["--single-l", "x", "windows.info"],
        ["--sing", "x", "windows.info"],
        ["--stackers", "A", "B", "windows.info"],
        ["--stackers", "A", "-q", "windows.info"],
        ["--single-swap-locations", "a", "b", "-q", "windows.info"],
        ["-c", CFG, "windows.info"],
        ["-c", CFG, "-f", IMG, "windows.pslist"],
        ["-c", CFG_NESTED, "windows.info"],
        ["-c", BASE + "/missing.json", "windows.info"],
        ["-e", "plugins.Info.x=1", "-e", "y=[1]", "windows.info"],
        ["--", "windows.info"],
        ["-q", "--", "-f", "windows.info"],
        ["--cache-path", BASE + "/cache", "-s", "a;b", "-p", "", "windows.info"],
        ["--save-config", "out.json", "--write-config", "windows.info"],
        ["-v", "-v", "--verbosity", "windows.info"],
        ["-", "windows.info"],
        ["-x", "windows.info"],
        ["--output-dir", BASE, "--log", BASE + "/log.txt", "windows.info"],
        ["windows.info", "--help"],
        ["timeliner"],
        ["windows"],
        ["Info"],
    ]
    # one valid and one invalid value for every requirement kind the plugins use
    samples = {
        "int": ["0x10", "zz"],
        "str": ["abc", "--"],
        "uri": [IMG, ""],
        "bytes": ["abc"],
        "list_int": ["1", "0x2", "q"],
        "list_str": ["a", "b"],
        "bool": [],
    }
    for kind, entries in sorted(by_kind.items()):
        pname, r = entries[0]
        flag = "--" + r["name"].replace("_", "-")
        if kind == "choice":
            c.append(["-f", IMG, pname, flag, r["choices"][0]])
            c.append(["-f", IMG, pname, flag, "not-a-choice"])
            c.append(["-f", IMG, pname, flag])
            continue
        if kind == "bool":
            c.append(["-f", IMG, pname, flag])
            continue
        for v in samples[kind]:
            c.append(["-f", IMG, pname, flag, v])
        c.append(["-f", IMG, pname, flag])
    for pname, r in required[:3]:
        c.append(["-f", IMG, pname])
    return c


def main():
    os.makedirs(BASE + "/home", exist_ok=True)
    for path, content in FILES.items():
        with open(path, "w") as f:
            f.write(content)
    os.makedirs(FIX, exist_ok=True)

    meta = plugin_metadata()
    p = subprocess.run([PY, DUMP, "--rsvol-plugin-helps"], cwd=BASE, env=env(), capture_output=True, text=True)
    helps = json.loads(p.stdout.strip().splitlines()[-1])
    for m in meta:
        m["help"] = helps[m["name"]]
    with open(os.path.join(FIX, "cli_plugins.json"), "w") as f:
        json.dump({"base": BASE, "plugins": meta}, f, indent=1)
        f.write("\n")

    results = []
    for args in cases(meta):
        results.append({"argv": args, "columns": 80, **run(args)})
    for cols in (40, 57, 200):
        results.append({"argv": ["-h"], "columns": cols, **run(["-h"], cols)})
        results.append({"argv": ["windows.pslist", "-h"], "columns": cols, **run(["windows.pslist", "-h"], cols)})
        results.append({"argv": ["pslist"], "columns": cols, **run(["pslist"], cols)})
    with open(os.path.join(FIX, "cli_cases.json"), "w") as f:
        json.dump({"base": BASE, "files": FILES, "cases": results}, f, indent=1)
        f.write("\n")
    print(f"{len(meta)} plugins, {len(results)} cases written to {FIX}")


if __name__ == "__main__":
    main()
