#!/usr/bin/env python3
"""python volatility3's `--save-config` for many plugins from ONE python start (a forked child per
case, so memory does not pile up): the real CLI
(argument parsing, automagics, `construct_plugin`, the config writer) runs per plugin, and the
plugin's `run()` is replaced by an early exit, so only construction is paid for.

    py_save_configs.py OUTDIR 'GLOBAL ARGS' LIST
      OUTDIR       per plugin: <name>.json (the saved configuration, when python wrote one),
                   <name>.rc (exit status), <name>.out (stdout + stderr)
      GLOBAL ARGS  word-split global options, e.g. "-f IMG -s DIR" (";" in -s kept)
      LIST         file: one line per case, "<plugin> [plugin args...]"; the case name is the
                   line with spaces replaced by "_" and '/' by '%'

Run it through bench/scripts/limit.sh (one python volatility process).
"""
import contextlib
import io
import os
import shlex
import sys

sys.path.insert(0, "/home/user/fvol/volatility3")

outdir, global_args, listfile = sys.argv[1], sys.argv[2], sys.argv[3]
os.makedirs(outdir, exist_ok=True)

import volatility3.cli as cli  # noqa: E402
from volatility3.framework import plugins as fw_plugins  # noqa: E402


class Stop(BaseException):
    pass


_construct = fw_plugins.construct_plugin


def construct_then_stop(*args, **kwargs):
    constructed = _construct(*args, **kwargs)

    def stop():
        raise Stop()

    constructed.run = stop
    return constructed


fw_plugins.construct_plugin = construct_then_stop

cases = [line.split() for line in open(listfile) if line.strip() and not line.startswith("#")]


def run_case(case, name, target):
    sys.argv = ["vol.py", "-q"] + shlex.split(global_args) + ["--save-config", target] + case
    buf = io.StringIO()
    rc = 0
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        try:
            cli.CommandLine().run()
        except Stop:
            rc = 0
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
        except BaseException as e:  # noqa: BLE001
            rc = 1
            buf.write(f"EXCEPTION {type(e).__name__}: {e}\n")
    with open(os.path.join(outdir, name + ".out"), "w") as f:
        f.write(buf.getvalue())
    with open(os.path.join(outdir, name + ".rc"), "w") as f:
        f.write(f"{rc}\n")
    return rc


# one forked child per case: python keeps symbol tables alive across CLI runs, a child's memory
# goes away with it
for case in cases:
    name = "_".join(case).replace("/", "%")
    target = os.path.join(outdir, name + ".json")
    if os.path.exists(target):
        os.unlink(target)
    sys.stdout.flush()
    pid = os.fork()
    if pid == 0:
        try:
            code = run_case(case, name, target)
        finally:
            sys.stdout.flush()
        os._exit(code & 0xFF)
    _, status = os.waitpid(pid, 0)
    rc = os.waitstatus_to_exitcode(status)
    sys.__stdout__.write(f"{rc} {name}\n")
    sys.__stdout__.flush()
