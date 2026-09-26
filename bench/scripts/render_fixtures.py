#!/usr/bin/env python3
"""Differential fixtures for the text renderers.

Builds a volatility3 TreeGrid covering every column type and tricky values from the grid spec
in tests/fixtures/render_grid.json, renders it with every python CLI renderer (plus filter /
hide-column variants) and writes the expected outputs to tests/fixtures/render_expected.json.
`cargo test` renders the same spec with the Rust renderers and compares byte for byte.

Run with:  /home/user/rs-vol/bench/venv/bin/python bench/scripts/render_fixtures.py
"""
import datetime
import io
import json
import os
import sys

sys.path.insert(0, "/home/user/rs-vol/volatility3")

from volatility3.cli import text_filter, text_renderer  # noqa: E402
from volatility3.framework import contexts, renderers  # noqa: E402
from volatility3.framework.layers import physical  # noqa: E402
from volatility3.framework.renderers import format_hints  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FIX = os.path.join(ROOT, "tests", "fixtures")

TYPES = {
    "int": int,
    "str": str,
    "bytes": bytes,
    "float": float,
    "bool": bool,
    "datetime": datetime.datetime,
    "hex": format_hints.Hex,
    "bin": format_hints.Bin,
    "hexbytes": format_hints.HexBytes,
    "mtd": format_hints.MultiTypeData,
    "disasm": renderers.Disassembly,
    "layer": renderers.LayerData,
}

ABSENT = {
    "unreadable": renderers.UnreadableValue,
    "unparsable": renderers.UnparsableValue,
    "notapplicable": renderers.NotApplicableValue,
    "notavailable": renderers.NotAvailableValue,
}

UTC = datetime.timezone.utc


def build_spec():
    """The grid: (name, type) columns and rows of (level, [cell...])."""
    cols = [
        ["PID", "int"],
        ["Name", "str"],
        ["Offset(V)", "hex"],
        ["Flags", "bin"],
        ["Raw", "bytes"],
        ["Ratio", "float"],
        ["Wow64", "bool"],
        ["CreateTime", "datetime"],
        ["Dump", "hexbytes"],
        ["Value", "mtd"],
        ["Disasm", "disasm"],
        ["Data", "layer"],
        ["Comment", "str"],
    ]

    def row(level, pid, name, off, flags, raw, ratio, wow, dt, hb, mtd, dis, layer, name2):
        return [level, [pid, name, off, flags, raw, ratio, wow, dt, hb, mtd, dis, layer, name2]]

    I = lambda v: {"t": "int", "v": v}  # noqa: E731
    S = lambda v: {"t": "str", "v": v}  # noqa: E731
    B = lambda h: {"t": "bytes", "hex": h}  # noqa: E731
    F = lambda v: {"t": "float", "v": v}  # noqa: E731
    BO = lambda v: {"t": "bool", "v": v}  # noqa: E731
    DT = lambda s, us=0, utc=True: {"t": "dt", "secs": s, "us": us, "utc": utc}  # noqa: E731
    MTD = lambda h, enc="utf-16-le", split=False, show=False, num=None: {  # noqa: E731
        "t": "mtd", "hex": h, "enc": enc, "split": split, "show_hex": show, "int": num}
    DIS = lambda h, off=0, arch=None: {"t": "dis", "hex": h, "off": off, "arch": arch}  # noqa: E731
    LD = lambda h: {"t": "layer", "hex": h}  # noqa: E731
    A = lambda k: {"t": k}  # noqa: E731

    u16 = lambda s: s.encode("utf-16-le").hex()  # noqa: E731
    rows = [
        row(0, I(4), S("System"), I(0xE485B4EAA040), I(5), B("deadbeef"), F(1.0), BO(False),
            DT(1789354424, 0), B("00"), MTD(u16("svchost.exe")), DIS("90c3"), LD("41424344"), S("n")),
        row(1, I(-1), S("tab\there"), I(-255), I(-5), B(""), F(0.1), BO(True),
            DT(1789354424, 123456), B(""), MTD(u16("a\x00b\x00c"), split=True), DIS("", 16), LD(""), S("")),
        row(2, I(2**64 + 5), S("new\nline"), I(0), I(0), B("00ff7f80"), F(1e16), BO(False),
            DT(-11644473600, 1, utc=False), B("000102030405060708090a0b0c0d0e0f"), MTD(u16("x\x00yy\x00zzz")),
            A("unreadable"), LD("000102030405060708090a0b0c0d0e0f10"), S("x")),
        row(3, I(0), S('quote"comma,back\\slash'), A("unreadable"), A("unparsable"), A("notapplicable"),
            A("notavailable"), A("unreadable"), A("notapplicable"), A("unparsable"), A("notavailable"),
            A("notapplicable"), A("unreadable"), S("y")),
        row(1, I(123456789012345678901234567890), S("unicode é中\U0001f600 wide"), I(0x10), I(1),
            B("20414243"), F(float("nan")), BO(True), DT(0, 999999, utc=False),
            B("41" * 33), MTD("41424344", enc="utf-8"), DIS("c3", 0x1000, "bogus"), LD("61"), S("z")),
        row(0, I(7), S(""), I(0xFFFFFFFFFFFFFFFF), I(255), B("5c22"), F(-0.0), BO(False),
            DT(253402300799, 999999), B("5c225c"), MTD(u16("123"), num=123), A("notavailable"), A("notapplicable"),
            S(" lead")),
        row(3, I(8), S("  spaced  "), I(1), I(2), B("0a0d"), F(2.5e-07), BO(True),
            DT(951782400, 5), B("0a"), MTD("00d841", show=True), DIS("0f0b", 1, None), LD("7f80"),
            S("trail ")),
        row(0, I(9), S("#hash"), I(3), I(3), B("2c"), F(12345.678), BO(False),
            DT(1, 0), B("ff"), MTD("e9e0", enc="latin-1"), DIS("90"), LD("22"), S('"')),
        row(1, I(10), S("x-é"), I(4), I(4), B("22"), F(1e-5), BO(True),
            DT(2, 0), B("22"), MTD(u16("été") + "00", split=True), DIS("90"), LD("5c"), S("\\")),
        row(1, I(11), S("-"), I(5), I(5), B("2d"), F(float("inf")), BO(False),
            DT(3, 0), B("2d"), MTD(u16("-")), DIS("90"), LD("2d"), S("N/A")),
        row(2, I(12), S("N/A"), I(6), I(6), B("00"), F(123456789012345678.0), BO(True),
            DT(4, 0), B("00"), MTD("", enc="utf-16-le"), DIS("90"), LD("00"), S("-")),
    ]
    return {"columns": cols, "rows": rows}


def make_value(cell, ctx, layer_name, layer_bytes):
    t = cell["t"]
    if t in ABSENT:
        return ABSENT[t]()
    if t == "int":
        return cell["v"]
    if t == "str":
        return cell["v"]
    if t == "bytes":
        return bytes.fromhex(cell["hex"])
    if t == "float":
        return float(cell["v"])
    if t == "bool":
        return bool(cell["v"])
    if t == "dt":
        base = datetime.datetime(1970, 1, 1, tzinfo=UTC if cell["utc"] else None)
        return base + datetime.timedelta(seconds=cell["secs"], microseconds=cell["us"])
    if t == "mtd":
        if cell["int"] is not None:
            return format_hints.MultiTypeData(cell["int"], cell["enc"], cell["split"], cell["show_hex"])
        return format_hints.MultiTypeData(bytes.fromhex(cell["hex"]), cell["enc"], cell["split"], cell["show_hex"])
    if t == "dis":
        return renderers.Disassembly(bytes.fromhex(cell["hex"]), cell["off"], cell["arch"] or "none")
    if t == "layer":
        data = bytes.fromhex(cell["hex"])
        off = len(layer_bytes)
        layer_bytes.extend(data)
        return renderers.LayerData(ctx, layer_name, off, len(data))
    raise ValueError(t)


def wrap_value(coltype, v):
    from volatility3.framework import interfaces
    if isinstance(v, interfaces.renderers.BaseAbsentValue):
        return v
    if coltype == "hex":
        return format_hints.Hex(v)
    if coltype == "bin":
        return format_hints.Bin(v)
    if coltype == "hexbytes":
        return format_hints.HexBytes(v)
    return v


def build_grid(spec):
    ctx = contexts.Context()
    layer_name = "fixture_layer"
    layer_bytes = bytearray()
    cols = [(n, TYPES[t]) for n, t in spec["columns"]]
    rows = []
    for level, cells in spec["rows"]:
        vals = [wrap_value(spec["columns"][i][1], make_value(c, ctx, layer_name, layer_bytes))
                for i, c in enumerate(cells)]
        rows.append((level, vals))
    layer = physical.BufferDataLayer(ctx, "layer_cfg", layer_name, bytes(layer_bytes))
    ctx.add_layer(layer)
    return lambda: renderers.TreeGrid(cols, iter([(lv, list(v)) for lv, v in rows]))


RENDERERS = {
    "quick": text_renderer.QuickTextRenderer,
    "none": text_renderer.NoneRenderer,
    "csv": text_renderer.CSVRenderer,
    "pretty": text_renderer.PrettyTextRenderer,
    "json": text_renderer.JsonRenderer,
    "jsonl": text_renderer.JsonLinesRenderer,
    "mermaid": text_renderer.MermaidRenderer,
}

VARIANTS = [
    ([], None),
    (["System"], None),
    (["-name,tab"], None),
    (["pid,^1\\d$!"], None),
    (["name,e!", "-pid,4"], None),
    (["nomatch,x"], None),
    (["+Offset,0x1"], None),
    (["wow,True"], None),
    (["Ratio,e+16"], None),
    ([], ["name", "DISASM"]),
    ([], ["d"]),
    ([], []),
    (["System"], ["pid"]),
    (["Data,41"], ["pid"]),  # python indexes the visible line with the full-grid column index
    (["Comment,y"], ["pid", "name"]),  # IndexError in python: column index beyond visible line
    ([], ["p", "n", "o", "f", "r", "w", "c", "d", "v"]),  # all hidden
    (["pid,[bad!"], None),  # invalid regex
]


def render(make_grid, name, filters, hide):
    grid = make_grid()
    r = RENDERERS[name]()
    r.filter = text_filter.CLIFilter(grid, filters)
    r.column_hide_list = hide
    buf = io.StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = buf, io.StringIO()
    exc = None
    try:
        r.render(grid)
    except Exception as e:  # noqa: BLE001
        exc = type(e).__name__
    finally:
        sys.stdout, sys.stderr = old_out, old_err
    return buf.getvalue(), exc


def main():
    spec = build_spec()
    os.makedirs(FIX, exist_ok=True)
    with open(os.path.join(FIX, "render_grid.json"), "w") as f:
        json.dump(spec, f, indent=1)
        f.write("\n")
    make_grid = build_grid(spec)
    cases = []
    for name in RENDERERS:
        for filters, hide in VARIANTS:
            out, exc = render(make_grid, name, filters, hide)
            cases.append({"renderer": name, "filters": filters, "hide": hide, "out": out, "exc": exc})
    with open(os.path.join(FIX, "render_expected.json"), "w") as f:
        json.dump(cases, f, indent=1)
        f.write("\n")
    print(f"{len(cases)} renderer cases written to {FIX}")


if __name__ == "__main__":
    main()
