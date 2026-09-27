fvol's first run takes 19.1 ms (pass 2: 64.7 ms; 49.5 ms with the lazy symbol tables right after
pass 2, see [pass 2's rerun](BENCHMARKS-run2.md#first-runs-with-lazy-symbol-tables-rsvol-cold-rerun)):
it no longer builds the binary symbol table of the 0.6 MB `.json.xz` kernel ISF before the plugin but
resolves what the plugin uses and leaves the full table to a detached helper after the output; the
rest came with the optimization pass's cold-start and startup work (not broken down here). A warm run
takes 2.5 ms (median 2.8 ms; pass 2: 3.3 ms): hot-text ordering, RELR relocations, the exit-teardown
helper and warm-path trims ([docs/building.md](../../docs/building.md#startup)). vol-rs and python
were run again for this table: vol-rs 3% below pass 2; python's best cold run is 1.98 s (pass 2:
1.87 s) and its best warm run 1.01 s (pass 2: 1.20 s; run 1: 998 ms).
