Where an rsvol column is not the fastest number of its row:

- `vmscan.Vmscan` (all three rsvol columns): vol-rs ships no VMCS ISFs, so it prints the empty table in
  4 ms without reading the image; python and rsvol scan the whole 5 GiB image for VMCS page starts
  (rsvol steady 311 ms, rsvol warm 15 ms replaying its cached hits). Same output in all three tools.
- `windows.suspended_threads.SuspendedThreads` (rsvol cold only): 107 ms vs vol-rs warm 103 ms; the
  cold run is ~65 ms of first-run symbol-table building plus the plugin's 38 ms (rsvol steady).
- Linux, rsvol cold only (49 of 59 plugins): a first-ever rsvol run spends ~0.53 s indexing and
  converting the 3.3 MB `.json.xz` kernel ISF (64 MB of JSON), so it loses to vol-rs *warm* (0.12-0.53 s)
  on the plugins that are cheap once the symbols are loaded; it beats vol-rs cold (2.0-3.2 s; banners 0.4 s, RecoverFs 87 s) on all 59,
  and rsvol steady / warm are the fastest on all 59 (see Checks).
