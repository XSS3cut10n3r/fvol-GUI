#!/bin/bash
# Check every linux/mac no-arg plugin on every linux/mac test image of bench/images.tsv against the
# python references.
# Usage: check_nix.sh [-b BIN] [linux|mac|all] [NAME|PATTERN ...]
#   e.g. check_nix.sh linux 'bionic*'   (names = first manifest column, bash globs allowed)
#   DIFFLINES=3  diff lines shown per DIFF;  OUTBASE=bench/out  where our outputs go (<OUTBASE>/<name>/)
# Plugins without a reference file are skipped (format-variant images only have references for the
# reduced bench/linux_fmt_noarg.txt list).
args=()
if [ "$1" = "-b" ]; then args=(-b "$2"); shift 2; fi
case ${1:-all} in
  linux) oses=linux; shift;;
  mac) oses=mac; shift;;
  all) oses=linux,mac; [ $# -gt 0 ] && shift;;
  *) oses=linux,mac;;
esac
exec /home/user/fvol/bench/scripts/check_images.sh -o $oses "${args[@]}" "$@"
