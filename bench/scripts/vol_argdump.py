#!/usr/bin/env python3
"""python volatility3's CLI, stopped right before it populates the plugin configuration:
prints `json.dumps(vars(args), sort_keys=True)` and exits 0. Everything before that point
(argument parsing, --help, errors, the banner, -f / -c / -o checks) is the real code.

rsvol's `cli::Settings { dump_args: true, .. }` stops at the same point, so both can be diffed.

Special mode: `vol_argdump.py --rsvol-plugin-helps` prints a JSON map plugin -> `<plugin> -h`
output (captured in-process, one parser build for all plugins).
"""
import io
import json
import sys

sys.path.insert(0, "/home/user/rs-vol/volatility3")

HELPS = len(sys.argv) > 1 and sys.argv[1] == "--rsvol-plugin-helps"
sys.argv = ["vol.py"] + ([] if HELPS else sys.argv[1:])

import volatility3.cli as cli  # noqa: E402
from volatility3.cli import volargparse  # noqa: E402


def dump(self, context, configurables_list, args, plugin_config_path):
    sys.stdout.write(json.dumps(vars(args), sort_keys=True) + "\n")
    sys.stdout.flush()
    sys.exit(0)


cli.CommandLine.populate_config = dump

if HELPS:
    orig = volargparse.HelpfulArgParser.parse_args

    def all_helps(self, args=None, namespace=None):
        sub = [a for a in self._actions if isinstance(a, volargparse.HelpfulSubparserAction)][0]
        result = {}
        real_out, real_err = sys.stdout, sys.stderr
        for name in sub._name_parser_map:
            out, err = io.StringIO(), io.StringIO()
            sys.stdout, sys.stderr = out, err
            code = None
            try:
                orig(self, [name, "-h"])
            except SystemExit as e:
                code = e.code
            finally:
                sys.stdout, sys.stderr = real_out, real_err
            result[name] = {"out": out.getvalue(), "err": err.getvalue(), "code": code}
        sys.stdout.write(json.dumps(result) + "\n")
        sys.exit(0)

    volargparse.HelpfulArgParser.parse_args = all_helps

cli.main()
