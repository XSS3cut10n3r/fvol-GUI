#!/bin/bash
# Check every Windows no-arg plugin on every extra Windows test image of bench/images.tsv (all images
# except the main memory-dirty.raw, which check_all.sh covers) against the python references.
# Usage: check_win_images.sh [-b BIN] [NAME|PATTERN ...]   (default: every windows image of the manifest;
#        an argument selects manifest names equal to it or matching it as a bash glob, e.g. 'win7*')
#   DIFFLINES=3  diff lines shown per DIFF;  OUTBASE=bench/out  where our outputs go (<OUTBASE>/<name>/)
# Plugins without a reference file in the image's ref dir are skipped (format-variant images only have
# references for a reduced list, see bench/win_fmt_noarg.txt).
exec /home/user/rs-vol/bench/scripts/check_images.sh -o windows "$@"
