# Caching and environment variables

rsvol caches what it learns about symbol files and images so that repeat runs are cheap, and the
caches are built so that they can never change a run's output. This page lists every cache file,
how the caches are keyed and cleared, and the environment variables that control them. For the
design behind them, see [architecture.md](architecture.md#caches-and-correctness).

Applies to rsvol 0.1.0.

- [Where the caches are](#where-the-caches-are)
- [How symbol files are chosen](#how-symbol-files-are-chosen)
- [Clear the caches](#clear-the-caches)
- [Why a cache cannot change output](#why-a-cache-cannot-change-output)
- [Environment variables](#environment-variables)

## Where the caches are

rsvol keeps its own cache in `~/.cache/rsvol`, or in `$XDG_CACHE_HOME/rsvol` when that variable is
set. It reads and writes python's symbol directory `~/.cache/volatility3/symbols` too, so symbol
files downloaded by either tool are shared.

| What                               | Where                                           | Why                                                        |
| ---------------------------------- | ----------------------------------------------- | ---------------------------------------------------------- |
| Binary symbol tables               | `~/.cache/rsvol/isf/*.isfb`                     | A warm symbol table load is one `mmap`, with no JSON parse |
| Symbol file identifier index       | `~/.cache/rsvol/identifiers.cache`              | Finds the ISF for a kernel banner or PDB without rereading |
| python's identifier cache (read)   | `~/.cache/volatility3/identifier.cache`         | Seeds the identifier index, and picks python's ISF        |
| Kernel discovery results           | `~/.cache/rsvol/automagic/`                     | Warm runs skip the DTB, KDBG and banner scans, also where an OS's kernel is not found (timeliner) |
| Windows ISF choices                | `~/.cache/rsvol/isfchoice/`                     | Warm runs skip the identifier index for Windows PDBs       |
| Raw scan hits                      | `~/.cache/rsvol/scan/`, capped at 256 MiB       | Scanning plugins replay hits instead of rereading memory   |
| `isfinfo --live` results           | `~/.cache/rsvol/isfinfo.cache`                  | Warm `isfinfo` runs parse no files                         |
| Downloads                          | `~/.cache/rsvol/data_<SHA512>.cache`            | Remote images and `-u` files are downloaded once           |
| Decompressed images                | `~/.cache/rsvol/decompressed/`                  | A `.gz`, `.bz2` or `.xz` image is decompressed once        |
| Downloaded Windows PDBs            | `~/.cache/volatility3/data_<SHA512>.cache`      | Kept where python keeps them, and shared with python       |
| Converted Windows PDBs             | `~/.cache/volatility3/symbols/windows/`         | Shared with python volatility3                             |

A binary symbol table is written after the run that first loads its ISF. For a big ISF, such as
a Linux kernel's, that run resolves only the types and symbols it uses, and a helper process
started after its output is complete writes the table in the background, at idle priority,
while the run exits: `ps` shows it as `rsvol-isfb-helper`. Concurrent runs build a table once.

A downloaded PDB is converted to `windows/<PDB>/<GUID>-<AGE>.json.xz` in the first symbol
directory where the file can be created, as python does: normally
`~/.cache/volatility3/symbols`, but a writable `-s` directory or python volatility3 installation
comes first. The PDB itself stays in python's cache directory under the name python gives it,
`data_` and the SHA-512 of its symbol server URL, or in the `--cache-path` directory. python finds
it there, and rsvol uses a PDB that python or rsvol downloaded before instead of downloading it
again.

Downloads are named like python's, `data_` and the SHA-512 of the URL, and like python's they are
never checked for changes on the server.

A decompressed image is stored with its key: the image location and the canonical path, size and
modification time of the compressed file. When the compressed file changes, the next run
decompresses it again and deletes the old copy, and copies of compressed files that no longer
exist are deleted whenever an image is decompressed. A copy is as big as the uncompressed image.

## How symbol files are chosen

When python volatility3 has run on this machine, rsvol reads its identifier cache (never writes
it; `--cache-path` selects it as for python) instead of reading every symbol file on the search
path. It takes python's entries exactly as python's own cache update would keep them and reads
only the files python would read again, so a first run with a large symbol pack costs
milliseconds instead of hundreds. When several ISFs carry the same Linux or macOS banner or the
same Windows PDB GUID and age, for example `x.json` next to `x.json.xz`, or a kernel ISF both in
volatility3's `symbols` directory and in `~/.cache/volatility3/symbols`, python loads the one
its cache lists last, and so does rsvol. Without python's cache, or with `--clear-cache`, which
makes python start a new one, rsvol takes the one python's new cache would list last. The
answer for a Windows PDB is kept in `~/.cache/rsvol/isfchoice/` until python's cache or a
directory on the search path changes. Set `RSVOL_NO_PY_IDENT_SEED=1` to build the index from
the symbol files alone, in search path order.

## Clear the caches

To empty the caches, run any plugin with `--clear-cache` or delete the directory. Like python's
`--clear-cache`, which deletes every `*.cache` file in its cache directory, downloads included,
rsvol's deletes every `*.cache` file in `~/.cache/rsvol`: downloads, the identifier index and the
`isfinfo` cache. It also removes the symbol tables, the kernel discovery results, the Windows
ISF choices, the scan results and the decompressed images. It deletes nothing outside
`~/.cache/rsvol`, so converted PDBs and python's own cache stay. Where python's `--clear-cache`
would have deleted a file in its own cache, rsvol ignores that file for the run: it does not read
python's identifier cache but chooses ISFs as python's new one would, and it downloads a needed
PDB again.

```bash
vol --clear-cache -f <IMAGE> windows.info.Info
rm -rf ~/.cache/rsvol
```

## Why a cache cannot change output

A cache can make a run faster but cannot change its output:

- Every cache file stores its complete key and the key is compared on load, so a hash collision
  or a stale file is a miss, never a wrong answer.
- Keys identify their inputs. Image-based caches use the canonical path, size and modification
  time of the image; the scan cache adds the inode and the identity of the rsvol executable, so a
  rebuilt binary never trusts scans recorded by an older one. Symbol tables are keyed by the
  source file's URL, size and modification time and the table format version. A remembered
  failure to find a kernel ("no Linux kernel in this image") is also keyed by the rsvol
  executable and, for Linux and macOS, by the state of every ISF of that OS on the search path
  and of python's identifier cache: adding, removing or changing one looks for the kernel again.
- The scan cache stores raw byte matches (and, for `vmscan.Vmscan`, the few hundred image bytes of
  each matched page that its checks read), never a plugin's results. On a replay every plugin
  still runs all of its python-equivalent validation on those matches, in python's order.
- Writes are atomic, so a crash or a concurrent run leaves either the old file or the new one.
- The parity gates run the reference comparisons twice, once with an empty cache and once warm.

The one assumption: an image file whose size and modification time did not change still has the
same contents. If you modify an image in place and restore its timestamp, clear the cache.

## Environment variables

| Variable                 | Effect                                                                              |
| ------------------------ | ----------------------------------------------------------------------------------- |
| `RSVOL_CACHE=<DIR>`      | Use `<DIR>` as the rsvol cache directory. An empty directory gives a cold run.      |
| `XDG_CACHE_HOME=<DIR>`   | Base directory of both the rsvol and the python volatility3 caches.                 |
| `RSVOL_NO_SCAN_CACHE=1`  | Disable the scan cache.                                                             |
| `RSVOL_THREADS=<N>`      | Number of worker threads. The default is every logical CPU.                         |
| `RSVOL_POOL_SPIN_US=<N>` | How long an idle worker thread looks for new work before it sleeps (default 20). |
| `RSVOL_NO_SIMD=1`        | Use the scalar search kernels for scanning instead of AVX2.                         |
| `RSVOL_TRACE=1`          | Print timing spans to stderr.                                                       |
| `RSVOL_VOL3_ROOT=<DIR>`  | Use the symbol directories of the python volatility3 checkout at `<DIR>`.           |
| `RSVOL_NO_PY_IDENT_SEED=1` | Build the identifier index without python's identifier cache, in search path order. |
| `RSVOL_LAZY_ISF=0`       | Build every symbol table in full before the plugin runs.                            |
| `RSVOL_DEFERRED_ISFB=<M>` | How the binary table of a lazily loaded ISF is written: `helper` (default), `thread` (by the run itself, before it exits) or `off`. |
