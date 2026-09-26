#!/usr/bin/env python3
"""Order-sensitive manifest of a .tar.gz ignoring mtimes: member name, mode, type, link, size, uid/gid and the
sha256 of each member's contents (used to compare linux.pagecache.RecoverFs archives). Usage: tar_manifest.py FILE"""
import hashlib, sys, tarfile
h = hashlib.sha256()
n = 0
with tarfile.open(sys.argv[1], "r:gz") as t:
    for m in t:
        d = t.extractfile(m).read() if m.isfile() else b""
        h.update(f"{m.name}\0{m.mode}\0{m.type}\0{m.linkname}\0{m.size}\0{m.uid}\0{m.gid}\0".encode())
        h.update(hashlib.sha256(d).digest())
        n += 1
print(n, h.hexdigest())
