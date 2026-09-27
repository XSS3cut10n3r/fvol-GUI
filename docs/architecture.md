# How rsvol works

This page explains how rsvol is put together, how it keeps its output identical to python
volatility3 and where its speed comes from. It is background reading for contributors and for
anyone who wants to know why the results can be trusted. For the rules contributors must follow,
see [DESIGN.md](../DESIGN.md); for the API, see
[src/objects/README-API.md](../src/objects/README-API.md).

Applies to rsvol 0.1.0.

## The shape of a run

A `vol` invocation does one thing: it runs one plugin over one image and prints its rows. The
pieces involved mirror volatility3's architecture, and most modules name the python file they
port.

```text
argv ──► CLI (argparse port) ──► Context (lazy) ──► plugin.run()
                                     │                  │
                                     │  first request   │ rows
                                     ▼  for a kernel    ▼
                    automagic: stack containers,     renderer ──► stdout
                    find DTB, kernel base, symbols
                                     │
                                     ▼
                 layers (file ► container ► Intel paging) + symbol tables
                                     │
                                     ▼
                       objects: typed views that read memory
```

Nothing happens before a plugin asks for it. Creating the `Context` only records the options.
The image is opened the first time a plugin needs a layer, and the kernel is searched for the
first time a plugin asks for it. A plugin such as `banners.Banners` that needs only the physical
layer never runs kernel discovery.

## Layers

A layer is an address space that can be read. volatility3 stacks them, and rsvol builds the same
stacks with the same names, because layer names appear in output such as `windows.info.Info`.

- **The file layer** maps the image read-only with `mmap`. Reads are a bounds check and a copy,
  and `slice()` returns the mapped bytes themselves when a range is contiguous in the file.
  python reads a `.gz`, `.bz2` or `.xz` image through a decompressing file object, where every
  backwards seek decompresses again from the start of the file. rsvol decompresses such an image
  once into its cache and maps the result, so the file layer stays a mapping. The decoders
  stream to disk with bounded memory: xz blocks, bzip2 blocks and gzip members decode on all
  cores and a single DEFLATE stream decodes on one, with a writer thread copying the output
  into the page cache meanwhile (`src/util/resource.rs`, `src/codecs/sink.rs`).
- **Container layers** describe where physical memory lives inside an image format: LiME, ELF
  cores including QEMU and VirtualBox dumps, Xen cores, Windows crash dumps, VMware `.vmem` files
  with their `.vmss` or `.vmsn` metadata, QEMU savevm streams and AVML. They are detected in
  python's stacker order. All of them are `SegmentedLayer`s: a sorted table of runs over the
  file, so a read is a table lookup and one copy. Formats whose runs are compressed or filled, such as AVML and QEMU, are read through the
  layer rather than sliced.
- **Translation layers** implement x86 paging: 32-bit, PAE, 4-level and 5-level, with the
  Windows rules for transition and pagefile entries and the Linux rules for `PROT_NONE` pages.
  Their quirks are reproduced because output depends on them. For example, a page table whose
  entries are all identical counts as not present, as in python.

Translation is the hottest path in many plugins. Page-table entries are read straight from the
mapped file when the physical layer is a raw file, each thread keeps a small TLB of recent 4 KiB
translations, and the validity of each page table is computed once and shared by every process
layer built from the same kernel. Enumerating the mapped ranges of an address space, which
`memmap` and scanning need, walks the page tables level by level instead of translating page by
page.

## Symbols

volatility3 describes kernels and data structures in ISF files, which are JSON documents of up to
tens of megabytes. python parses them on every run.

rsvol converts each ISF once into a flat, position-independent binary blob: a string pool,
fixed-size records for types, members, symbols and enums, and precomputed open-addressing hash
tables. The blob is written to the cache as it is. On the next run, loading a symbol table means
mapping the cache file and checking its header, with no parsing, no hashing and no allocation.
A warm load of the Windows kernel table takes about 0.02 ms.

The first conversion is also fast. The JSON parser builds a structural index in the style of
simdjson: it finds every quote and structural character 64 bytes at a time with AVX2 and
carry-less multiplication, on several threads, and then walks the index instead of the text.

The first run does not wait for that conversion. A plugin touches a few dozen of a kernel's
10,000 to 15,000 types and 200,000 to 300,000 symbols, so a big ISF (1 MB of JSON or more) loads
as a *lazy table*: one SIMD pass finds the root object's structure and the member keys of its
`user_types`, `enums` and `symbols` sections, and every member is then parsed and checked exactly
as the full builder parses it, range by range, each range through a small structural index of
its own bytes that stays in the CPU cache. Nothing is resolved or written yet: the natives, enums
and metadata go into a small blob of the full format, and a type or symbol is resolved by the
full builder's own resolver the first time a plugin asks for it. The table API is the same, and a
unit test compares every type, member, symbol and enum of a lazy table with the full table for
every ISF on the test machine. A document the full builder would not accept, or would treat
specially (repeated names, for python's dictionary semantics), is not taken lazily. For the
64 MB Ubuntu 24.04 kernel ISF, the lazy index takes about 13 ms instead of the full build's
47 ms on a 20-thread desktop CPU; on the 32-vCPU benchmark VM a first `linux.pslist` went from
0.51 s to 0.11 s, faster than vol-rs with a warm cache (see
[bench/vm/BENCHMARKS.md](../bench/vm/BENCHMARKS.md)).

The full binary table of a lazy table is built after the plugin's output is complete: `main`
flushes the output and then hands each such ISF to a helper process, this executable started in
a hidden mode, in its own session, with no inherited file descriptors and at idle CPU priority.
The run exits at once. The helper takes a lock so that concurrent runs build a blob once,
rereads the ISF, checks that the file did not change, and writes the blob atomically; the next
run maps it. Building the blob on a thread of the run itself would add the build, 50 ms for
that kernel, to every first run. `RSVOL_DEFERRED_ISFB=thread` does that instead, and `=off`
writes no blob at all.

To find the right ISF for a Linux or macOS kernel, volatility3 compares the kernel banner in
memory with the banner stored in every ISF on the search path; for a Windows PDB it looks up
the PDB's name, GUID and age the same way. rsvol keeps an identifier index of those banners and
PDB identifiers, updated only for files whose size or modification time changed. The index is
python volatility3's own identifier cache (an SQLite database) as python would update it:
rsvol replays python's cache update in memory (drop rows of vanished files, re-read files newer
than a row older than three days, append new files) and reads only the files that update would
read. python resolves an identifier to the last matching row, so its choice among ISFs sharing
one depends on the history of its database; replaying it gives the same choice. python appends
new files in the iteration order of a `set` of their URLs, so rsvol lists the files on the
search path in python's directory-walk order and emulates CPython's set table (with the
`PYTHONHASHSEED=0` string hash, the only reproducible one); without a python database it
replays python building one from scratch. When the index has to read new files, a quick scan of
the image for the kernel version tells it which kernel table to build first, on another thread;
a big ISF under a `linux/` or `mac/` directory is then indexed lazily right away and its
identifier read from that index, one pass over the JSON instead of two. When the index is seeded
from python's cache, the likely kernel ISF, the only one or the only one of the image's kernel
release, is loaded while the image is searched for its VMCOREINFO notes; one scan of the image
finds both the kernel version and the notes. For Windows, the kernel table named by the first
candidate is loaded while the full KDBG scan is still running. A speculative table is used only
if it turns out to be the final answer.

The small ISFs that ship with volatility3, for PE files, pool headers, registry structures and
more, are compiled into the binary.

## Objects

Plugins read memory through objects, as in volatility3. An `Obj` is a 32-byte `Copy` value: a
layer and symbol table pair, a type and an address. Creating an object never reads memory. Reads
happen in the value accessors, such as `int()`, `string()` or `deref()`, which are the points
where python reads.

This matters for parity. python raises `InvalidAddressException` at the exact attribute access
that touches an unreadable page, and its plugins decide per call site whether to skip a row, stop
or print `-`. rsvol's accessors return an error at the same points, so a port can make the same
decision in the same place.

Layers and symbol tables live for the whole process, so objects carry no lifetimes and can be
passed between threads freely. Hot loops resolve a member's offset once with a `Field` and then
read it without any lookup.

## Automagic

Automagic is volatility3's name for the steps that turn an image into a usable kernel: stacking
container layers, finding the page table root, finding the kernel base and loading its symbols.
rsvol makes the same decisions from the same evidence:

- **Windows**: a scan for the self-referencing page table entry that gives the DTB, then the
  kernel's PDB signature and base, via KDBG or a scan, then the PDB symbol table, downloaded and
  converted if needed.
- **Linux**: VMCOREINFO notes when present, otherwise a scan for kernel banners that match an ISF
  and python's `swapper` search for the KASLR shift.
- **macOS**: the kernel banner scan, the KASLR shift and the `IdlePML4` root.

python scans the whole image and then chooses; rsvol streams the scan in python's hit order and
stops at the first hit python would pick. The result is stored per image in the automagic cache,
so a warm run does no scanning at all. So is a failure to find an OS's kernel: timeliner runs the
plugins of every OS, and a warm run does not look for the other two kernels again.

## Scanning

Scanning plugins, such as `psscan`, `filescan`, `netscan` and `yarascan`, search whole layers for
byte patterns. Which hits python reports depends on how it cuts the layer into chunks: 16 MiB
chunks with a one-page overlap on the file, chunks that never cross a mapped run on translation
layers, and a hit counts only if it starts before the chunk size. rsvol reproduces that chunk
list exactly, then runs it differently:

- Chunks are scanned on all cores. Results are buffered and emitted in chunk order, so the output
  order is python's, and a scan that stops early wastes at most one round of work.
- Large file-backed chunks are read in 64 KiB pieces that stay in the CPU cache, or mapped per
  worker with a private window, so page-table setup does not serialize on one global mapping.
- Scattered 4 KiB pages of a virtual layer are grouped by file offset. Physical pages mapped at
  several virtual addresses, about 60% of a Windows kernel's pages, are read and searched once.
- Multi-pattern searches use an AVX2 Teddy prefilter with trie verification, 15 to 19 GB/s per
  core. A full scan of the 5 GiB test image runs at the machine's memory bandwidth.

### The scan cache

Scanners are split into two phases: a pure byte search, `prescan`, and the python checks on each
match, `finish`. The scan cache stores only the prescan output, the raw byte positions, per image
and per layer configuration. A repeated scan replays those positions through `finish`, so all of
python's validation still runs, in python's order.

vmscan's checks read a few hundred bytes of each page whose first four bytes are a VMCS revision
id (about 1,900 pages on the 5 GiB test image). Those bytes are a pure function of the image, so
they are cached with the matches as fixed-size records; a warm vmscan maps one cache file, runs the
checks on the records and reads no image page.

A full scan that misses the cache also records a family of well-known patterns in the same sweep:
every built-in pool tag, the MFT and MBR signatures and the VMCS page signatures. The next
scanning plugin of that family is then answered from the cache even though it never ran before.
User-supplied patterns, such as YARA rules and regular expressions, are never cached.

## Plugins, renderers and the CLI

A plugin is a unit struct implementing the `Plugin` trait. It declares its command-line options
in python's order and with python's names, so `--help` output matches, and it writes columns and
then rows into a `RowSink`. It asks the `Context` for kernels, layers and symbol tables when it
needs them.

Renderers format each cell by the column type, as volatility3 does, which is why the same integer
prints as `16` in one column and `0x10` in another. The streaming renderers, `quick`, `csv` and
`jsonl`, format rows straight into one large byte buffer and write it to file descriptor 1
without the locking and line buffering of Rust's `stdout`. `pretty`, `json` and `mermaid` buffer
the whole grid as python does; `pretty` formats its lines on all cores.

The CLI is a port of volatility3's argparse setup, including its help layout, its error messages
and exit codes, `vol.json` defaults, configuration files, filters and hidden columns. A plugin
that fails in a way python would not catch produces a python-style traceback on stderr and exit
status 1.

## How parity is guaranteed

The python source of volatility3 2.28.2 is the specification. Four practices keep rsvol faithful
to it.

1. **Port behaviour, not intent.** Ports reproduce which exceptions python catches and where, the
   evaluation order that decides which rows are skipped, and python's own bugs where they are
   visible in output. When python raises halfway through a plugin, rsvol prints the same rows
   and then fails the same way.
2. **Emulate the python runtime where output depends on it.** The code includes CPython's set
   iteration order for integers and, where needed, for strings under `PYTHONHASHSEED=0`, python's
   JSON dictionary semantics for duplicate keys, format specifications, `datetime` printing, the
   `re` module's byte semantics, argparse, and a reader for python's SQLite identifier cache.
3. **Keep parallelism invisible.** Every parallel helper returns results in index order, and work
   with side effects python would not reach after an error, such as writing dump files, stays
   sequential.
4. **Diff everything.** Reference outputs from python cover seven images and every plugin that
   runs without arguments, plus argument and renderer cases and every dumped file. Differential
   fixtures cover the CLI and the renderers, and oracle harnesses compare the from-scratch
   libraries with the originals. The gates run with a cold cache and a warm one. See
   [development.md](development.md).

## Performance techniques

The design rule is to know the hardware and do the minimum work. The techniques, collected:

| Technique                     | Where                                                                 |
| ----------------------------- | --------------------------------------------------------------------- |
| Memory mapping                | The image, and cached symbol tables, are mapped, never read into memory. Scans map private windows per worker. |
| Zero-copy access              | `slice()` hands out mapped bytes; symbol tables are used in place.    |
| Parallelism                   | Scans, per-process work, ISF builds, the identifier index and row formatting use all cores through one persistent worker pool with work stealing: no thread is started per parallel section, sections nest and run concurrently, and a panic in a worker reaches the caller like one on its own thread. |
| SIMD                          | AVX2 pattern search, AVX2 and PCLMULQDQ JSON indexing, AES-NI and VAES, SHA-NI, selected at run time. |
| Caching                       | Symbol tables, the identifier index, automagic results and raw scan hits. |
| Speculation                   | Likely kernel symbol tables are built while the scans that confirm them run. |
| Laziness                      | A first run resolves only the types and symbols it uses; the full symbol table is built by a detached helper after the output. |
| Fixed per-run cost            | A static-pie binary without dynamic loading, a C `main` that skips most of the Rust runtime setup, a lazy `Context`, and cache writes on background threads that finish after the output. A warm `windows.pslist.PsList` takes about 3 ms. |
| Allocation-free inner loops   | Precomputed member offsets, compact 8-byte rows in the timeliner merge, table-driven cell formatting. |

Each from-scratch library is benchmarked against its reference implementation on the same input
and machine, with the harnesses in `bench/refbench/`: liblzma, zlib, libbz2, libsnappy, OpenSSL,
capstone, libyara, PCRE2 and RE2, and python's own PDB converter and JSON parser. The target is to
beat the reference. [bench/PACKAGES.md](../bench/PACKAGES.md) records the results, for example
AES at about twice OpenSSL's speed and the regex and YARA engines at 1.3 to 20 times the best of
PCRE2-JIT and RE2.

## Caches and correctness

Every cache is a pure function of its inputs: image identity, symbol file identity, format
versions and, for the scan cache, the rsvol executable. Each cache file carries its full key,
which is compared on load, and is written atomically. The rules and the list of cache files are
in [caching.md](caching.md).
