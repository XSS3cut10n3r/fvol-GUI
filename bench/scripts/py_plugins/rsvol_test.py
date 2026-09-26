# Test-only volatility3 plugin used by bench/scripts/cli_run_fixtures.py (loaded with -p).
# It renders the grid from tests/fixtures/render_grid.json and can fail at chosen points, so the
# whole CLI path (banner, renderer start/finish, exception reporting, exit status) can be diffed.
import json
import os

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements

HERE = os.path.dirname(os.path.abspath(__file__))
GRID = os.path.join(HERE, "..", "..", "..", "tests", "fixtures", "render_grid.json")


class RenderTest(interfaces.plugins.PluginInterface):
    """Renders the rsvol fixture grid.

    Modes: ok, fail_before, fail_after_2 (InvalidAddress), symbol_after_2, empty."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.StringRequirement(name="mode", description="What to do", optional=True, default="ok"),
        ]

    def _generator(self, rows, mode):
        for n, row in enumerate(rows):
            if n == 2 and mode == "fail_after_2":
                raise exceptions.PagedInvalidAddressException("layer_name", 0x1000, 0, 0, "test failure")
            if n == 2 and mode == "symbol_after_2":
                raise exceptions.SymbolError("sym", "table", "test failure")
            yield row

    def run(self):
        import sys

        sys.path.insert(0, os.path.join(HERE, ".."))
        import render_fixtures  # noqa

        mode = self.config.get("mode", "ok")
        if mode == "fail_before":
            raise exceptions.LayerException("layer_name", "test failure")
        with open(GRID) as f:
            spec = json.load(f)
        make_grid = render_fixtures.build_grid(spec)
        grid = make_grid()
        rows = list(grid._generator)
        if mode == "empty":
            rows = []
        return renderers.TreeGrid([(c.name, c.type) for c in grid.columns], self._generator(rows, mode))
