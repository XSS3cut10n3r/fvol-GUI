rsvol's cold start is building its binary symbol table from the 0.6 MB `.json.xz` kernel ISF (read +
xz decode 34 ms, parse + build 16 ms; the cache file is written by a background thread joined before
exit; `RSVOL_TRACE=1`); vol-rs's cold start parses its 4 MB plain-JSON symbol file; python's rebuilds
its identifier cache. Python's warm best is 1.20 s here vs 1.00 s in run 1 (run 1's three warm runs
spread from 1.00 to 1.21 s, run 2's from 1.203 to 1.206 s).
