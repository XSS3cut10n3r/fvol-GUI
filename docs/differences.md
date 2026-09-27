# Known differences from python volatility3

For a given image, plugin and set of arguments, fastvol prints what python volatility3 2.28.2
prints, byte for byte, and dumping plugins write the same files. This page lists every known
exception. Most come from python itself: output that changes from one python run to the next, or
behaviour that depends on the python runtime or installation.

Applies to fastvol 0.1.0, which reproduces volatility3 2.28.2.

- **Nondeterministic python output.** Some plugins print the contents of a python `set`, whose
  order changes from one python run to the next.
  - `windows.windows.Windows` orders sibling windows by the heap addresses of python objects.
    fastvol prints the same rows in list order. The parity check compares sorted output for this
    plugin, see [bench/nondeterministic.txt](../bench/nondeterministic.txt).
  - `linux.mountinfo.MountInfo --mount-format`, `windows.malware.svcdiff.SvcDiff` and
    `windows.strings.Strings` depend on python's randomized string hashing. fastvol reproduces the
    order of a python run with `PYTHONHASHSEED=0`; set that variable when you compare.
  - Sets of integers, as in `psxview` and `pstree`, iterate in a fixed order in CPython. fastvol
    reproduces that order exactly, so these plugins match without any setting.
  - When several ISFs on the search path carry the same kernel banner or PDB identifier, python
    loads the one its identifier cache lists last. A cache python builds from scratch (its
    first run, or `--clear-cache`) lists new files in the order of a python `set` of their
    URLs, which depends on the randomized string hashing. fastvol follows an existing python
    cache exactly, and for a new one reproduces a python run with `PYTHONHASHSEED=0`.
- **Loading a configuration with `-c`.** fastvol takes the plugin options, the image location and
  the swap files from the file and finds the kernel in the image again, where python builds the
  layers and the symbol table the file describes. A file written by `--save-config`, by python
  or by fastvol, for the same image and symbol files gives the same output either way, but a file
  edited by hand to name another DTB, kernel offset or ISF is not followed.
- **`timeliner.Timeliner --record-config`** records each plugin that ran with the configuration
  `--save-config` would write for it. python's timeliner builds its plugins in one shared
  configuration, where plugins with the same class name, such as `windows.pslist.PsList` and
  `linux.pslist.PsList`, share one subtree and a layer stacked for one plugin is reused by the
  next, so its `config.json` can hold a few more keys, for example the other plugin's options.
- **Plugin discovery order.** python runs the `timeliner.Timeliner` plugins and lists
  `frameworkinfo.FrameworkInfo` components in the directory order of its installation, which
  depends on the file system. fastvol uses the order of the reference installation, so python on
  another file system can print a different timeline. `frameworkinfo` describes fastvol: the plugin
  list is the plugins fastvol registers.
- **Program name.** Usage lines print the name of the executable, normally `usage: fvol`, where
  python prints `usage: vol` (`usage: vol.py` when started as `python vol.py`).
- **Progress and logging.** fastvol prints no progress output on stderr. `-v` prints only the
  reason kernel discovery failed, and `-l <FILE>` writes only the "Logging started" line.
- **Options that need python.** `-p/--plugin-dirs` cannot load python plugins; fastvol warns and
  ignores it. `--parallelism` is accepted and has no effect, since fastvol always uses every core
  unless `FASTVOL_THREADS` says otherwise.
- **YARA.** Rules that `import` a module such as `pe` fail with "modules are not supported", and
  `--yara-compiled-file` is not supported. Plain rules, strings and conditions work.
- **Compressed images that do not decompress.** A `.gz`, `.bz2` or `.xz` image that is corrupt,
  truncated or not compressed despite its name stops fastvol before the plugin runs, with the
  decoder's error on stderr and python's "Unsatisfied requirement" message. python opens such a
  file lazily and fails while reading it, so plugins that accept the bare file, such as
  `layerwriter.LayerWriter`, print the decoder's error or a traceback instead. Valid compressed
  images give python's output.
- **Corrupt circular lists.** Where python would loop forever on a smeared structure, such as a
  cyclic subsection list in `windows.dumpfiles.DumpFiles`, fastvol stops with an error.
- **`isfinfo.IsfInfo`** leaves the `hash` column empty for rows it adds to python's identifier
  cache, and skips files that make python crash. With `--live` and no python volatility3
  installation to point at, see `FASTVOL_VOL3_ROOT`, it lists the symbol files shipped with
  volatility3 under `embedded:///` URLs instead of python's installation paths.
- **Python version.** The reference is CPython 3.14. Under CPython 3.13, python volatility3
  itself prints some values differently, for example the year 144 as `144` instead of `0144`.
