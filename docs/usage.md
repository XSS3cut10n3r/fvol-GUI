# Using rsvol

Task-oriented guides for the `vol` command line. They assume you know what a memory image and a
volatility3 plugin are. For the browser interface, see [web-ui.md](web-ui.md).

Applies to rsvol 0.1.0, which reproduces volatility3 2.28.2.

- [Run a plugin](#run-a-plugin)
- [Analyze a Windows image](#analyze-a-windows-image)
- [Analyze a Linux image](#analyze-a-linux-image)
- [Analyze a macOS image](#analyze-a-macos-image)
- [Control where symbol files are found](#control-where-symbol-files-are-found)
- [Extract files from memory](#extract-files-from-memory)
- [Get machine-readable output](#get-machine-readable-output)
- [Filter rows and hide columns](#filter-rows-and-hide-columns)
- [Build a timeline](#build-a-timeline)
- [Search memory with YARA rules or regular expressions](#search-memory-with-yara-rules-or-regular-expressions)
- [Save and reuse a configuration](#save-and-reuse-a-configuration)
- [Troubleshoot a run that finds no kernel](#troubleshoot-a-run-that-finds-no-kernel)

## Run a plugin

Global options go before the plugin name and plugin options after it:

```bash
vol [GLOBAL OPTIONS] -f <IMAGE> <PLUGIN> [PLUGIN OPTIONS]
```

List the plugins and the global options with `vol -h`, and the options of one plugin with
`vol <PLUGIN> -h`:

```bash
vol windows.pslist.PsList -h
```

```text
Volatility 3 Framework 2.28.2
usage: vol windows.pslist.PsList [-h] [--physical] [--pid [PID ...]] [--dump]

Lists the processes present in a particular windows memory image.

options:
  -h, --help       show this help message and exit
  --physical       Display physical offsets instead of virtual
  --pid [PID ...]  Process ID to include (all other processes are excluded)
  --dump           Extract listed processes
```

Any unique prefix of a plugin name works, so `windows.pslist` runs `windows.pslist.PsList`.

`-f` takes the image file, and the format is detected from its contents. For a VMware image,
pass the `.vmem` file and keep the `.vmss` or `.vmsn` file of the same name next to it.

The exit status is 0 on success, 1 when the plugin cannot run or fails, and 2 for a usage error.
rsvol prints no progress output, so `-q` is accepted but changes nothing.

## Analyze a Windows image

1. Identify the kernel. The first run on an image finds the kernel, reads the PDB name, GUID and
   age of `ntkrnlmp.pdb`, downloads the PDB from the Microsoft symbol server with `curl` and
   converts it to a symbol file:

   ```bash
   vol -f <IMAGE> windows.info.Info
   ```

   The converted file is stored in `~/.cache/volatility3/symbols/windows/`, where python
   volatility3 finds it as well. Later runs on any image of the same Windows build need no
   network.

2. Run the plugins you need. A typical triage sequence:

   ```bash
   vol -f <IMAGE> windows.pstree.PsTree
   vol -f <IMAGE> windows.cmdline.CmdLine
   vol -f <IMAGE> windows.netscan.NetScan
   vol -f <IMAGE> windows.malware.malfind.Malfind
   vol -f <IMAGE> windows.registry.hivelist.HiveList
   ```

3. If the system had a page file and you have it, add it so that paged-out memory can be read:

   ```bash
   vol -f <IMAGE> --single-swap-locations <PAGEFILE> windows.pslist.PsList
   ```

### Use Windows symbols without network access

Run with `--offline -v` to learn which symbol file is missing:

```bash
vol --offline -v -f <IMAGE> windows.info.Info
```

```text
automagic: Unsatisfied requirement: offline mode: not downloading ntkrnlmp.pdb 8E3373D6124E747F0E72EF8E02E676B31
```

The last characters after the 32-digit GUID are the age, `1` here. Copy the matching symbol file
from a machine that has it, for example from its `~/.cache/volatility3/symbols/windows/`, into a
symbol directory with this layout:

```text
<SYMBOL_DIR>/windows/ntkrnlmp.pdb/8E3373D6124E747F0E72EF8E02E676B3-1.json.xz
```

Then pass the directory with `-s`:

```bash
vol --offline -s <SYMBOL_DIR> -f <IMAGE> windows.info.Info
```

The file name layout is the fast path. A Windows symbol file anywhere below a symbol directory is
also found, because rsvol reads the PDB identity from the file's metadata.

## Analyze a Linux image

Linux plugins need a symbol file generated from the exact kernel build of the image.

1. Read the kernel version from the image:

   ```bash
   vol -f <IMAGE> banners.Banners
   ```

   ```text
   Offset	Banner

   0x10a00200	Linux version 5.15.0-191-generic (buildd@lcy02-amd64-042) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04.3) 11.4.0, ...
   ```

2. Get the debug kernel with DWARF information and the `System.map` for that exact version. For
   Ubuntu these come from the `linux-image-unsigned-<VERSION>-dbgsym` package and the matching
   kernel package.

3. Generate the symbol file with [dwarf2json](https://github.com/volatilityfoundation/dwarf2json)
   and put it in a symbol directory:

   ```bash
   mkdir -p <SYMBOL_DIR>/linux
   dwarf2json linux --elf <VMLINUX> --system-map <SYSTEM_MAP> | xz > <SYMBOL_DIR>/linux/<NAME>.json.xz
   ```

4. Run the plugins with `-s`:

   ```bash
   vol -s <SYMBOL_DIR> -f <IMAGE> linux.pslist.PsList
   vol -s <SYMBOL_DIR> -f <IMAGE> linux.bash.Bash
   vol -s <SYMBOL_DIR> -f <IMAGE> linux.sockstat.Sockstat
   ```

rsvol picks the symbol file whose `linux_banner` equals the banner in memory, wherever it lies
below the symbol directory. The `linux/` subdirectory is a convention, not a requirement.

The first run with a new symbol directory reads every symbol file in it once to index the
banners. Later runs look the banner up in the index.

## Analyze a macOS image

macOS works like Linux: the symbol file must match the kernel's `version` string. The Volatility
Foundation publishes symbol packs for released macOS kernels.

```bash
vol -s <SYMBOL_DIR> -f <IMAGE> mac.pslist.PsList
```

A symbol pack can stay zipped: rsvol reads symbol files inside `.zip` archives found in a symbol
directory.

## Control where symbol files are found

rsvol searches for symbol files, called ISF files, in this order:

1. The directories given with `-s`, separated by semicolons.
2. A `symbols` directory next to the `vol` executable.
3. The symbol files that ship with volatility3. They cover generic, Windows and Linux helper
   tables, not OS kernels. A copy of them is compiled into the binary. When a python volatility3
   installation is found, its `symbols` and `framework/symbols` directories are searched as well,
   so that file URLs printed by plugins such as `windows.info.Info` match python's. rsvol looks
   for the installation in `RSVOL_VOL3_ROOT`, then for a `volatility3` checkout in a parent
   directory of the executable.
4. python's download directory, `~/.cache/volatility3/symbols`, or
   `$XDG_CACHE_HOME/volatility3/symbols` when that variable is set.

File names may end in `.json`, `.json.xz`, `.json.gz` or `.json.bz2`, and may sit inside `.zip`
archives.

Linux and macOS kernel ISFs are found by the kernel banner. When several ISFs on the search path
carry the same banner, rsvol loads the one python volatility3 would load, which it learns from
python's identifier cache, `~/.cache/volatility3/identifier.cache` or the one under
`--cache-path`. Without that file, or with `RSVOL_NO_PY_IDENT_SEED=1`, the last one in search
order wins.

To use a remote list of symbol files, pass its URL with `-u`. rsvol downloads the list and the
files it needs once, with `curl`, and keeps them in `~/.cache/rsvol/remote/`:

```bash
vol -u <ISF_LIST_URL> -f <IMAGE> linux.pslist.PsList
```

`--offline` prevents every download, including PDB files for Windows.

## Extract files from memory

Plugins that write files put them in the current directory, or in the directory given with `-o`,
which must exist. Each plugin prints the name of every file it wrote in its `File output` column.

```bash
mkdir -p <OUTPUT_DIR>
vol -f <IMAGE> -o <OUTPUT_DIR> windows.pslist.PsList --pid 828 --dump
```

```text
PID	PPID	ImageFileName	Offset(V)	Threads	Handles	SessionId	Wow64	CreateTime	ExitTime	File output

828	684	svchost.exe	0xe485b863e080	17	-	0	False	2026-09-14 02:53:46.000000 UTC	N/A	828.svchost.exe.0x7ff6e7390000.dmp
```

Common ways to extract data:

| Goal                                 | Command                                                             |
| ------------------------------------ | ------------------------------------------------------------------- |
| Process executables                  | `windows.pslist.PsList --pid <PID> --dump`                          |
| DLLs of a process                    | `windows.dlllist.DllList --pid <PID> --dump`                        |
| A PE file at an address              | `windows.pedump.PEDump --pid <PID> --base <ADDRESS>`                |
| Kernel drivers                       | `windows.modules.Modules --dump`                                    |
| Cached files, optionally by name     | `windows.dumpfiles.DumpFiles --filter <REGEX> --ignore-case`        |
| Process memory regions               | `windows.vadinfo.VadInfo --pid <PID> --dump`                        |
| Suspicious regions found by malfind  | `windows.malware.malfind.Malfind --dump`                            |
| Linux process ELF mappings           | `linux.elfs.Elfs --pid <PID> --dump`                                |
| Linux page cache as a tarball        | `linux.pagecache.RecoverFs --compression-format xz`                 |
| The physical memory layer            | `layerwriter.LayerWriter`                                           |

File names are the ones python volatility3 chooses. When a name is taken, a counter goes before
the extension: `name-1.dmp`, `name-2.dmp`. Files are created with mode 0600, minus the umask.

## Get machine-readable output

Choose a renderer with `-r`:

| Renderer  | Output                                                             |
| --------- | ------------------------------------------------------------------ |
| `quick`   | Tab-separated text, streamed. The default.                         |
| `pretty`  | Aligned columns, printed when the plugin finishes.                 |
| `csv`     | Comma-separated values with a `TreeDepth` column.                  |
| `json`    | One JSON array; child rows are nested under `__children`.          |
| `jsonl`   | One JSON object per line.                                          |
| `mermaid` | A Mermaid graph of tree-shaped output such as `pstree`.            |
| `none`    | Nothing; useful to time a plugin or to only write files.           |

With `csv`, `json`, `jsonl` and `mermaid` the version banner goes to stderr, so stdout holds only
the data:

```bash
vol -f <IMAGE> -r json windows.pslist.PsList --pid 4 2>/dev/null
```

```json
[
  {
    "CreateTime": "2026-09-14T02:53:44+00:00",
    "ExitTime": null,
    "File output": "Disabled",
    "Handles": null,
    "ImageFileName": "System",
    "Offset(V)": 251262917058624,
    "PID": 4,
    "PPID": 0,
    "SessionId": null,
    "Threads": 134,
    "Wow64": false,
    "__children": []
  }
]
```

In JSON, addresses are numbers, and values that could not be read are `null`.

## Filter rows and hide columns

`--filters` keeps the rows that match a pattern. Its form is `[+-]<COLUMN>,<PATTERN>[!]`:

- `<COLUMN>` is matched case-insensitively against a part of a column name. Without it, the
  pattern may match in any column.
- `<PATTERN>` is a substring, or a python regular expression when it ends in `!`.
- A leading `-` keeps the rows that do not match.

Repeat the option to add filters. A row is kept when at least one filter accepts it. Write an
excluding filter as `--filters=-...`, because a separate argument that starts with `-` is read as
an option:

```bash
vol -f <IMAGE> --filters 'ImageFileName,^svc!' windows.pslist.PsList
vol -f <IMAGE> --filters=-ImageFileName,svchost windows.pslist.PsList
```

`--hide-columns` takes a list of column name prefixes. Because the list ends only at the next
option, put another option after it, or the plugin name is taken as a column:

```bash
vol -f <IMAGE> --hide-columns Offset Threads Handles -r quick windows.pslist.PsList
```

## Build a timeline

`timeliner.Timeliner` runs every plugin that reports timestamps and merges their events in time
order. `--create-bodyfile` also writes `volatility.body` for tools that read the bodyfile format,
and `--plugin-filter` limits the run to plugins whose names contain a substring:

```bash
vol -f <IMAGE> -o <OUTPUT_DIR> timeliner.Timeliner --create-bodyfile
vol -f <IMAGE> timeliner.Timeliner --plugin-filter windows.registry
```

## Search memory with YARA rules or regular expressions

```bash
# a string, a rule file, or a regular expression over physical memory
vol -f <IMAGE> yarascan.YaraScan --yara-string 'evil.example'
vol -f <IMAGE> yarascan.YaraScan --yara-file <RULES.yar>
vol -f <IMAGE> regexscan.RegExScan --pattern '[a-z0-9.]+\.onion'

# the same inside process memory
vol -f <IMAGE> windows.vadyarascan.VadYaraScan --pid <PID> --yara-file <RULES.yar>
```

Rules that use `import` and precompiled rule files are not supported.

## Save and reuse a configuration

`--save-config <FILE>` writes the plugin configuration of a run as JSON, and `-c <FILE>` loads
it again. Default options can also be set in `~/.config/volatility3/vol.json`, as with python
volatility3:

```bash
vol -f <IMAGE> --save-config pslist.json windows.pslist.PsList --pid 4
vol -f <IMAGE> -c pslist.json windows.pslist.PsList
```

## Troubleshoot a run that finds no kernel

When the kernel or its symbols cannot be found, the plugin stops with "Unable to validate the
plugin requirements". Add `-v` to see why:

```bash
vol -v -f <IMAGE> linux.pslist.PsList
```

```text
automagic: No Linux banners found - if this is a linux plugin, please check your symbol files location
```

| Message                                          | What to do                                                    |
| ------------------------------------------------ | ------------------------------------------------------------- |
| `No Linux banners found`                         | Add a symbol directory with a matching ISF using `-s`.        |
| `offline mode: not downloading <PDB> <GUID><AGE>` | Allow network access, or provide the Windows ISF with `-s`.  |
| `download of ... failed`                         | Check network access to `msdl.microsoft.com`.                 |
| `cannot run curl`                                | Install `curl`, or provide the Windows ISF with `-s`.         |
| `File does not exist`                            | Check the path given to `-f`.                                 |

To rule out a stale cache, run once with `--clear-cache`.
