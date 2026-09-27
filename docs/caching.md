# Caching and environment variables

fastvol caches what it learns about symbol files and images so that repeat runs are cheap, and the
caches are built so that they can never change a run's output. This page lists every cache file,
how the caches are keyed and cleared, and the environment variables that control them. For the
design behind them, see [architecture.md](architecture.md#caches-and-correctness).

Applies to fastvol 0.1.0.

- [Where the caches are](#where-the-caches-are)
- [How symbol files are chosen](#how-symbol-files-are-chosen)
- [Clear the caches](#clear-the-caches)
- [Why a cache cannot change output](#why-a-cache-cannot-change-output)
- [Environment variables](#environment-variables)

## Where the caches are

fastvol keeps its own cache in `~/.cache/fastvol`, or in `$XDG_CACHE_HOME/fastvol` when that
variable is set. It reads and writes python's symbol directory `~/.cache/volatility3/symbols`
too, so symbol files downloaded by either tool are shared.

Versions before the rename to fastvol kept their cache in `~/.cache/rsvol`. The first run that
misses its cache, or is about to write to it, while `~/.cache/fastvol` does not exist yet renames
the old directory to the new name (one `rename`; runs that hit the cache never look for it). With
`FASTVOL_CACHE` set, nothing is renamed.

| What                               | Where                                           | Why                                                        |
| ---------------------------------- | ----------------------------------------------- | ---------------------------------------------------------- |
| Binary symbol tables               | `~/.cache/fastvol/isf/*.isfb`                   | A warm symbol table load is one `mmap`, with no JSON parse |
| Symbol file identifier index       | `~/.cache/fastvol/identifiers.cache`            | Finds the ISF for a kernel banner or PDB without rereading |
| python's identifier cache (read)   | `~/.cache/volatility3/identifier.cache`         | Seeds the identifier index, and picks python's ISF        |
| Kernel discovery results           | `~/.cache/fastvol/automagic/`                   | Warm runs skip the DTB, KDBG and banner scans, also where an OS's kernel is not found (timeliner) |
| Windows ISF choices                | `~/.cache/fastvol/isfchoice/`                   | Warm runs skip the identifier index for Windows PDBs       |
| Raw scan hits                      | `~/.cache/fastvol/scan/`, capped at 256 MiB     | Scanning plugins replay hits instead of rereading memory   |
| `isfinfo --live` results           | `~/.cache/fastvol/isfinfo.cache`                | Warm `isfinfo` runs parse no files                         |
| Downloads                          | `~/.cache/fastvol/data_<SHA512>.cache`          | Remote images and `-u` files are downloaded once           |
| Decompressed images                | `~/.cache/fastvol/decompressed/`                | A `.gz`, `.bz2` or `.xz` image is decompressed once        |
| Downloaded Windows PDBs            | `~/.cache/volatility3/data_<SHA512>.cache`      | Kept where python keeps them, and shared with python       |
| Converted Windows PDBs             | `~/.cache/volatility3/symbols/windows/`         | Shared with python volatility3                             |

A binary symbol table is written after the run that first loads its ISF. For a big ISF, such as
a Linux kernel's, that run resolves only the types and symbols it uses, and a helper process
started after its output is complete writes the table in the background, at idle priority,
while the run exits: `ps` shows it as `fastvol-isfb-helper`. Concurrent runs build a table once.
The helper then builds the tables of up to three other ISFs of the same directory that have none
yet, newest first (the other kernels of a symbol pack, the other builds of a Windows PDB), so a
later first run on such an image maps a finished table. It stops once the tables in
`~/.cache/fastvol/isf` take 512 MiB; `FASTVOL_PREBUILD=0` turns this off.

A downloaded PDB is converted to `windows/<PDB>/<GUID>-<AGE>.json.xz` in the first symbol
directory where the file can be created, as python does: normally
`~/.cache/volatility3/symbols`, but a writable `-s` directory or python volatility3 installation
comes first. The PDB itself stays in python's cache directory under the name python gives it,
`data_` and the SHA-512 of its symbol server URL, or in the `--cache-path` directory. python finds
it there, and fastvol uses a PDB that python or fastvol downloaded before instead of downloading it
again. fastvol downloads a PDB in parallel HTTP range requests, each part checked against the
server's size and ETag and the whole file against the PDB's GUID, and falls back to one request,
as python makes, whenever the server answers otherwise; the bytes are the same. When the kernel
search has to scan the whole image, the kernel's PDB is downloaded while the scan runs.

The run that converts a PDB uses the converted table from memory; the `.json.xz` file is written
right after the output, by the helper process, with the same content (the same producer
datetime). A run started in between converts the PDB once more.

Downloads are named like python's, `data_` and the SHA-512 of the URL, and like python's they are
never checked for changes on the server.

A decompressed image is stored with its key: the image location and the canonical path, size and
modification time of the compressed file. When the compressed file changes, the next run
decompresses it again and deletes the old copy, and copies of compressed files that no longer
exist are deleted whenever an image is decompressed. A copy is as big as the uncompressed image.

## How symbol files are chosen

When python volatility3 has run on this machine, fastvol reads its identifier cache (never writes
it; `--cache-path` selects it as for python) instead of reading every symbol file on the search
path. It takes python's entries exactly as python's own cache update would keep them and reads
only the files python would read again, so a first run with a large symbol pack costs
milliseconds instead of hundreds. When several ISFs carry the same Linux or macOS banner or the
same Windows PDB GUID and age, for example `x.json` next to `x.json.xz`, or a kernel ISF both in
volatility3's `symbols` directory and in `~/.cache/volatility3/symbols`, python loads the one
its cache lists last, and so does fastvol. Without python's cache, or with `--clear-cache`, which
makes python start a new one, fastvol takes the one python's new cache would list last. The
answer for a Windows PDB is kept in `~/.cache/fastvol/isfchoice/` until python's cache or a
directory on the search path changes. Set `FASTVOL_NO_PY_IDENT_SEED=1` to build the index from
the symbol files alone, in search path order.

## Clear the caches

To empty the caches, run any plugin with `--clear-cache` or delete the directory. Like python's
`--clear-cache`, which deletes every `*.cache` file in its cache directory, downloads included,
fastvol's deletes every `*.cache` file in `~/.cache/fastvol`: downloads, the identifier index and
the `isfinfo` cache. It also removes the symbol tables, the kernel discovery results, the Windows
ISF choices, the scan results and the decompressed images, and clears a leftover `~/.cache/rsvol`
the same way. It deletes nothing else, so converted PDBs and python's own cache stay. Where
python's `--clear-cache` would have deleted a file in its own cache, fastvol ignores that file for
the run: it does not read python's identifier cache but chooses ISFs as python's new one would,
and it downloads a needed PDB again.

```bash
fvol --clear-cache -f <IMAGE> windows.info.Info
rm -rf ~/.cache/fastvol
```

## Why a cache cannot change output

A cache can make a run faster but cannot change its output:

- Every cache file stores its complete key and the key is compared on load, so a hash collision
  or a stale file is a miss, never a wrong answer.
- Keys identify their inputs. Image-based caches use the canonical path, size and modification
  time of the image; the scan cache adds the inode and the identity of the fastvol executable, so a
  rebuilt binary never trusts scans recorded by an older one. Symbol tables are keyed by the
  source file's URL, size and modification time and the table format version. A remembered
  failure to find a kernel ("no Linux kernel in this image") is also keyed by the fastvol
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

Each variable is read once per run. The names from before the rename, `RSVOL_*` (`RSVOL_CACHE`,
`RSVOL_THREADS`, ...), still work; when both are set, the `FASTVOL_*` one wins.

| Variable                     | Effect                                                                                 |
| ---------------------------- | -------------------------------------------------------------------------------------- |
| `FASTVOL_CACHE=<DIR>`        | Use `<DIR>` as the fastvol cache directory. An empty directory gives a cold run.       |
| `XDG_CACHE_HOME=<DIR>`       | Base directory of both the fastvol and the python volatility3 caches.                  |
| `FASTVOL_NO_SCAN_CACHE=1`    | Disable the scan cache.                                                                |
| `FASTVOL_THREADS=<N>`        | Number of worker threads. The default is every logical CPU.                            |
| `FASTVOL_POOL_SPIN_US=<N>`   | How long an idle worker thread looks for new work before it sleeps (default 20).       |
| `FASTVOL_NO_SIMD=1`          | Use the scalar search kernels for scanning instead of AVX2.                            |
| `FASTVOL_TRACE=1`            | Print timing spans to stderr.                                                          |
| `FASTVOL_VOL3_ROOT=<DIR>`    | Use the symbol directories of the python volatility3 checkout at `<DIR>`.              |
| `FASTVOL_NO_PY_IDENT_SEED=1` | Build the identifier index without python's identifier cache, in search path order.    |
| `FASTVOL_LAZY_ISF=0`         | Build every symbol table in full before the plugin runs.                               |
| `FASTVOL_DEFERRED_ISFB=<M>`  | How the binary table of a lazily loaded ISF is written: `helper` (default), `thread` (by the run itself, before it exits) or `off`. |
| `FASTVOL_PREBUILD=<N>`       | Binary tables of other ISFs the helper builds after a run (default 3, `0`: none).      |
| `FASTVOL_STREAM_ISF=0`       | Decode a lazily loaded `.xz` ISF before indexing it, instead of while.                 |
| `FASTVOL_RANGED_DOWNLOAD=0`  | Download PDBs in one request, like python.                                             |
| `FASTVOL_PDB_ISF_WRITE=sync` | Write a converted PDB's `.json.xz` before the plugin runs, like python.                |
