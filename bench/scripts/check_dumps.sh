#!/bin/bash
# Dump-parity gate: run the --dump variants of every file-writing plugin (pslist / psscan / dlllist /
# modules / modscan / vadinfo / memmap --pid / malfind / dumpfiles / pedump / hivelist / certificates /
# layerwriter on Windows; pslist / elfs / lsmod / proc.Maps --dump, RecoverFs, InodePages, fbdev,
# layerwriter on Linux; proc_maps + layerwriter on mac) on every image of bench/images.tsv (plus the
# main image's bench/ref/pyargs dump cases) and compare exit code, stdout and the dumped files (names,
# sizes, SHA-256; RecoverFs tarballs by member) with python's.
# Usage: check_dumps.sh [-b BIN] [-c CASE_GLOB]... [--py-only|--rs-only] [--list] [NAME|GLOB ...]
#   default BIN: target/release/vol of the main checkout. Python references are generated on first use
#   (one python at a time, 8G cap, 15 min timeout -> SKIP) and cached under testdata/scratch/dumpgate/py/;
#   all dumps are deleted after hashing. Details: bench/scripts/dumpgate.py.
exec python3 "$(dirname "$0")/dumpgate.py" "$@"
