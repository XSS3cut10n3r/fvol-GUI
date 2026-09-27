Where a fastvol column is not the fastest number of its row:

- `vmscan.Vmscan` (fastvol cold and steady): vol-rs ships no VMCS ISFs, so it prints the empty table in
  4.1 ms without reading the image; python and fastvol scan the whole 5 GiB image for VMCS page starts
  (fastvol steady 39.0 ms, 311 ms in pass 2). fastvol warm replays its cached hits in 1.6 ms and is now
  the fastest. Same output in all three tools.
- `isfinfo.IsfInfo` (fastvol cold only): 30.3 ms vs vol-rs warm 3.7 ms. Not a fastvol change: during
  the Windows round python's identifier cache had no row for a kernel ISF that had appeared in python's
  symbols directory since pass 2, so every cold run indexed that ISF itself (see Changes since pass 2).
  Measured by hand after python had updated its cache, a cold isfinfo takes 4 ms, with fvol `b400e76`
  and with pass 2's rsvol `95528b2` alike. vol-rs prints 3 lines here, python and fastvol 14.
- Linux: none. fastvol cold is the fastest on all 59 plugins, ahead of vol-rs *warm* too (closest:
  `linux.ip.Link`, 94.5 ms vs 125 ms).
