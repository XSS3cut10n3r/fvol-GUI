#!/usr/bin/env python3
"""End-to-end CLI fixtures: python's real CLI runs the test plugin in bench/scripts/py_plugins
(loaded with -p) for every renderer and failure mode; stdout and the exit status are recorded
in tests/fixtures/cli_run.json. `cargo test` runs an equivalent fake plugin through `cli::run`.

Run with:  /home/user/rs-vol/bench/venv/bin/python bench/scripts/cli_run_fixtures.py
"""
import json
import os
import subprocess

PY = "/home/user/rs-vol/bench/venv/bin/python"
VOL = "/home/user/rs-vol/volatility3/vol.py"
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PLUGINS = os.path.join(ROOT, "bench", "scripts", "py_plugins")
FIX = os.path.join(ROOT, "tests", "fixtures")

RENDERERS = ["quick", "csv", "pretty", "json", "jsonl", "none", "mermaid"]
MODES = ["ok", "fail_before", "fail_after_2", "symbol_after_2", "empty"]
EXTRA = [
    ["--hide-columns", "p", "n", "o", "f", "r", "w", "c", "d", "v", "--"],
    ["--filters", "pid,[bad!"],
    ["--filters", "Name,e", "--hide-columns", "Raw", "Dump", "--"],
    ["--filters", "-Name,e", "--filters", "wow,True"],
    ["--filters=-Name,e", "--filters", "wow,True"],
    ["--filters", "pid,^1\\d$!", "--filters=-comment,x"],
]


def run(args):
    env = dict(os.environ, COLUMNS="80", PYTHON_COLORS="0")
    p = subprocess.run([PY, VOL, "-q", "-p", PLUGINS] + args, capture_output=True, text=True, env=env)
    return {"out": p.stdout, "code": p.returncode, "err": p.stderr}


def main():
    cases = []
    for r in RENDERERS:
        for m in MODES:
            args = ["-r", r, "rsvol_test.RenderTest", "--mode", m]
            cases.append({"argv": args, **run(args)})
        for extra in EXTRA:
            args = ["-r", r] + extra + ["rsvol_test.RenderTest"]
            cases.append({"argv": args, **run(args)})
    with open(os.path.join(FIX, "cli_run.json"), "w") as f:
        json.dump(cases, f, indent=1)
        f.write("\n")
    print(f"{len(cases)} end-to-end cases written")


if __name__ == "__main__":
    main()
