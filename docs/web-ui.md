# The web UI: `fvol serve`

`fvol serve` runs a small web server inside the `fvol` binary and serves an analysis workspace for
one memory image. It is part of fastvol only; python volatility3 has no equivalent command.

This page has two parts. The [tutorial](#tutorial-a-first-session) walks through a first
session. The [reference](#reference) lists the options, keyboard shortcuts, HTTP API and the
security model.

Applies to fastvol 0.1.0.

## Tutorial: a first session

In this tutorial you open a Windows image in the browser, look at its processes, inspect one
process, read memory at an address and export a result. You need a built `fvol` binary, a Windows
memory image and a browser on the same machine. Linux and macOS images work the same way once you
add their symbol directory with `-s`.

### 1. Start the server

```bash
fvol serve -f <IMAGE>
```

```text
fastvol web UI · Volatility 3 Framework 2.28.2
  image   /cases/memory-dirty.raw (5.0 GiB)
  output  /cases/vol-serve-output
  open    http://127.0.0.1:8765/#token=1c5fa1176bd21e349985b1160bfc6ac6
Anyone with this URL can read the image. Press Ctrl+C to stop.
```

The server starts analysing the image right away: it maps the file, finds the kernel and loads
its symbols in the background.

### 2. Open the workspace

Copy the `open` URL into your browser. The page stores the token and removes it from the address
bar.

The overview tab shows what fastvol found: the operating system, kernel base, DTB, the symbol file
and the layers of the image. Next to it are quick actions for the plugins most analysts run first.
On the left is the process tree.

### 3. Explore the process tree

Each process in the tree has a lifeline on the time axis of the capture, from its creation to its
exit or to the capture time. Processes that look out of place carry a hint, such as an unexpected
parent, a second instance of a process that is normally unique, or a process started shortly
before the capture.

Press `T` and type `svchost` to filter the tree. Use the arrow keys to move and press `Enter` on
a process to open its process view.

### 4. Look at one process

The process view shows the process's parent, children, lifetime and command line, and has a tab
for each plugin that can be limited to one PID: handles, DLLs, memory regions, environment,
network, threads, injected code and more. Open a tab to run its plugin for this process only.

In any table, move with the arrow keys, press `Enter` for the details of a row, `S` to sort by
the current column and `F` to filter it. Filters accept text, `=exact`, `!not`, comparisons such
as `>0x10` and `/regex/`.

### 5. Run any plugin

Press `Ctrl+K` to open the plugin palette, type `netscan` and choose `windows.netscan.NetScan`.
Plugins with options show a form first; integer fields accept python syntax such as `0x1000`, and
PID fields offer the process list.

The run appears in the history rail. Rows stream in while the plugin runs, and a large result
stays fast because the browser holds only the rows on screen.

### 6. Read memory at an address

In a result with addresses, put the cursor on an address column and press `H`. The memory viewer
opens at that address. It shows a hex dump with a data inspector. Press `Enter` on a pointer to
follow it, `Backspace` to go back and `D` to disassemble from the cursor.

### 7. Export a result

Use the export menu of a result tab to download the visible columns of the current view as CSV,
TSV, JSON, JSON Lines or Markdown. The `fvol -r ...` entries download what the command line prints
for the same plugin and options instead. Files that a plugin wrote, such as dumped executables,
are listed with the run and can be downloaded one by one or as a zip.

Stop the server with `Ctrl+C`. The results of this session are gone, but the files plugins wrote
stay in `vol-serve-output/`, and the fastvol caches make the next session on the same image start
immediately.

For more, read the [reference](#reference) below, and [usage.md](usage.md) for symbol setup.

## Reference

### Command line

```text
fvol serve [-h] [-f FILE] [--host HOST] [--port PORT] [-s SYMBOL_DIRS] [-o OUTPUT_DIR]
           [--offline] [-u URL] [--cache-path PATH] [--token TOKEN] [--allow-host NAME]
           [--max-conns N] [--parallel N] [--max-memory SIZE]
```

| Option                   | Default              | Meaning                                                                  |
| ------------------------ | -------------------- | ------------------------------------------------------------------------ |
| `-f, --file FILE`        | none                 | Image to open. Without it, open one from the UI.                         |
| `--host HOST`            | `127.0.0.1`          | IP address to listen on. `localhost` means `127.0.0.1`.                  |
| `--port PORT`            | 8765                 | Port. Without the option, the first free port from 8765 to 8784 is used, then any free port. `0` means any free port. |
| `-s, --symbol-dirs DIRS` | none                 | Semicolon-separated symbol directories, as for `fvol`.                    |
| `-o, --output-dir DIR`   | `./vol-serve-output` | Root of the per-run output directories.                                  |
| `--offline`              | off                  | Never download symbols.                                                  |
| `-u, --remote-isf-url URL` | none               | Remote symbol file list, as for `fvol`.                                   |
| `--cache-path PATH`      | python's default     | python volatility3 cache path, as for `fvol`.                             |
| `--token TOKEN`          | random               | Fixed access token: at least 16 printable characters, without `;`, `,` or quotes. |
| `--allow-host NAME`      | none                 | Also accept requests whose `Host` header is `NAME`, for example behind a reverse proxy. Repeatable. |
| `--max-conns N`          | 512                  | Concurrent HTTP connections, between 8 and 4096.                         |
| `--parallel N`           | 3                    | Plugins that may run at the same time, between 1 and 64.                 |
| `--max-memory SIZE`      | `3G`                 | Memory for stored result rows across all runs, such as `2G` or `512M`. Rows past the budget are counted but not kept; exports through the `fvol` renderer stay complete. |

### Output files

Every run of a plugin that writes files gets its own directory below the output root, named
`run-<NNNN>-<plugin>`. Exports through the `fvol` renderer use `export-<NNNN>-<N>`. Downloads are
served only from these directories.

### Keyboard shortcuts

Press `?` in the UI for this list.

| Where          | Keys                         | Action                                                   |
| -------------- | ---------------------------- | -------------------------------------------------------- |
| Anywhere       | `Ctrl+K`                     | Run a plugin                                             |
|                | `/`                          | Filter the current table                                 |
|                | `T`                          | Filter the process tree                                  |
|                | `O`                          | Overview                                                 |
|                | `M`                          | Memory viewer at an address                              |
|                | `Alt+1` to `Alt+9`           | Go to tab N                                              |
|                | `[` and `]`                  | Previous and next tab                                    |
|                | `Alt+W`                      | Close the tab                                            |
|                | `Shift+T`                    | Light or dark theme                                      |
|                | `?`                          | Shortcut help                                            |
| Result table   | arrows, `PgUp`, `PgDn`       | Move; `Ctrl+Home` and `Ctrl+End` go to the first and last row |
|                | `Enter`                      | Row details                                              |
|                | `C`, `Shift+C`               | Copy the cell, or the row as TSV                         |
|                | `S`, `Shift+S`               | Sort by the column; again to reverse; with Shift, add a sort key |
|                | `F`                          | Column filter: `text`, `=exact`, `!not`, `>0x10`, `<=5`, `/regex/`, `-` for empty |
|                | `H`                          | Open the address under the cursor in the memory viewer   |
|                | `P`                          | Open the row's process                                   |
| Process tree   | arrows                       | Move, collapse, expand                                   |
|                | `Enter`                      | Open the process view                                    |
|                | `*`                          | Expand everything                                        |
|                | `a` to `z`                   | Jump to a process by name                                |
| Memory viewer  | `G`                          | Go to an address                                         |
|                | `Enter`                      | Follow the pointer under the cursor                      |
|                | `Backspace`                  | Back                                                     |
|                | `D`                          | Disassemble from the cursor                              |
|                | `Shift+Left`, `Shift+Right`  | Select a range; `C` copies it as hex                     |

### HTTP API

The API exists for the UI and for scripts. Every call under `/api/` needs the token in an
`X-Vol-Token` header or an `Authorization: Bearer <TOKEN>` header. Bodies are JSON.

| Method and path                      | Purpose                                                            |
| ------------------------------------ | ------------------------------------------------------------------ |
| `GET /api/session`                   | Current image, analysis state, OS, and the facts of the overview   |
| `POST /api/session`                  | Open another image: `{"file": "<PATH>", "symbol_dirs": ["<DIR>"]}` |
| `GET /api/plugins`                   | Every plugin with its options                                      |
| `GET /api/runs`                      | All runs                                                           |
| `POST /api/runs`                     | Start a run: `{"plugin": "<NAME>", "args": {"<option>": <value>}}` |
| `GET /api/runs/<ID>`                 | One run's status and columns                                       |
| `DELETE /api/runs/<ID>`              | Remove a run                                                       |
| `POST /api/runs/<ID>/cancel`         | Cancel a run                                                       |
| `POST /api/runs/<ID>/view`           | Create a sorted and filtered view of the rows                      |
| `GET /api/runs/<ID>/rows`            | A page of rows: `from`, `count` up to 5000, optional `view`        |
| `GET /api/runs/<ID>/stream`          | Every row as NDJSON while the plugin produces it                   |
| `GET /api/runs/<ID>/export`          | The rows as `format=csv`, `tsv`, `json`, `jsonl` or `md`           |
| `GET /api/runs/<ID>/vol`             | The plugin's `fvol` command-line output for `renderer=<NAME>`       |
| `GET /api/runs/<ID>/files`           | Files the run wrote                                                |
| `GET /api/runs/<ID>/files/<NAME>`    | Download one file                                                  |
| `GET /api/runs/<ID>/files.zip`       | Download all files as a zip                                        |
| `GET /api/mem`                       | Read memory: `layer` = `phys`, `kernel` or `pid:<PID>`, `addr`, `len` up to 256 KiB |
| `GET /api/disasm`                    | Disassemble: `layer`, `addr`, `len` up to 16 KiB, optional `arch`  |
| `GET /api/fs`                        | List a directory for the open-image dialog: names and sizes        |
| `POST /api/ticket`                   | A single-use link for one GET URL, valid for 60 seconds            |
| `GET /api/events`                    | NDJSON stream of session and run changes                           |
| `GET /api/stats`                     | Run count and memory use                                           |

Example: start a run and fetch the command-line output of it.

```bash
TOKEN=<TOKEN>
curl -s -H "X-Vol-Token: $TOKEN" -X POST \
  -d '{"plugin": "windows.pslist.PsList", "args": {"pid": [4]}}' \
  http://127.0.0.1:8765/api/runs
curl -s -H "X-Vol-Token: $TOKEN" "http://127.0.0.1:8765/api/runs/1/vol?renderer=csv"
```

```text
TreeDepth,PID,PPID,ImageFileName,Offset(V),Threads,Handles,SessionId,Wow64,CreateTime,ExitTime,File output
0,4,0,System,0xe485b4eaa040,134,-,N/A,False,2026-09-14 02:53:44.000000 UTC,N/A,Disabled
```

The `vol` endpoint runs the plugin again with the command-line renderer, so its output is the
same as `fvol -r csv` would print.

### Security model

A memory image holds passwords, keys and private data, so the server is built to be reachable
only by the person who started it.

- **Loopback by default.** The server listens on 127.0.0.1. With `--host 0.0.0.0` or another
  address, it prints a warning: traffic is plain HTTP, so anyone on the network path can read it.
  To reach a remote server, prefer an SSH tunnel such as `ssh -L 8765:127.0.0.1:8765 <HOST>`.
- **Access token.** A random 128-bit token from `/dev/urandom` is required on every API call, in
  a request header. There is no cookie, because cookies are shared between all ports of a host.
  The token is compared in constant time, and repeated failures are slowed down.
- **Token handling in the browser.** The token travels in the URL fragment, which browsers never
  send to servers or put in `Referer` headers. The page moves it into the browser storage of that
  exact origin and removes it from the address bar. Downloads that cannot carry a header use
  single-use tickets that expire after 60 seconds and are bound to one URL.
- **DNS rebinding.** Requests are accepted only when the `Host` header names the address the
  server listens on or `localhost`, plus any `--allow-host` names. Other names get status 421.
- **Cross-site requests.** Requests marked by the browser as cross-site, or with a foreign
  `Origin`, are refused. The server sends no CORS headers, and pages are served with a strict
  Content Security Policy, `X-Frame-Options: DENY` and `Referrer-Policy: no-referrer`.
- **No external content.** The UI's HTML, JavaScript, CSS and font are compiled into the binary.
  The page loads nothing from other hosts.
- **Request limits.** Request heads are limited to 16 KiB and 64 headers, bodies to 1 MiB and JSON
  nesting to 32 levels. A request must arrive within 10 seconds, idle connections close after 30
  seconds, and long-lived streams have their own cap.
- **Files.** Plugins write only into their run's output directory, and downloads are limited to
  names in a fresh listing of that directory: no paths, no `..`, no symbolic links.

What the token grants: whoever holds it can read the open image and can open any other file that
the server's user can read, list directories and read that file's bytes in the memory viewer.
Treat the URL like a password, and run `fvol serve` as a user that can read only what you intend
to analyse.
