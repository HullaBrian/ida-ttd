# ida-ttd

Analyze time travel debugging traces inside IDA Pro: Microsoft TTD recordings
(`.run`), and Sogen recordings (`.sogttd`) with the Sogen backend.

A TTD recording contains every instruction a process executed, so the answer to
"where did this pointer come from" or "what wrote these bytes" is already in the
file. This plugin makes that recording navigable from the standard IDA debugger
UI: step forwards and backwards, jump to any point on the timeline, and run
queries across the whole execution.

That matters most for code that is not in the binary you started with. Packed,
injected and JIT-generated code only exists at runtime, and a recording of it is
often the only artifact you have. `ida-ttd` disassembles that code, names it,
shows which parts actually ran, and reconstructs the memory regions it lived in
along with their protections.

Built against the IDA SDK 9.4. Each kind of recording is read by a backend, a
DLL of its own behind a small C interface (`src/abi/ida_ttd_backend.h`): the
Microsoft one uses the TTD Replay SDK, the Sogen one Sogen's trace reader.

## Features

**Navigation**

- Replay a trace forwards and backwards, including reverse-continue,
  step out backwards, and run to cursor in either direction.
- Timeline view of thread and module events, and jump to an exact
  `Sequence:Steps` position.
- Position bookmarks with names and comments, saved in the database. A
  bookmark made in a different recording (re-recorded since, or a fork) is
  greyed out rather than taken to a position it does not name.

**Code discovery**

- Runtime-only code is disassembled a whole function at a time, using the PE
  exception table for module code and the recorded execution for everything
  else. Self-modified regions are re-analyzed when their bytes change.
- Your names, prototypes, comments and decompiler variables on functions
  outside the modules are kept in the database and come back in later
  sessions, wherever the same code is at the same address.
- Symbols come from each module's export table read out of the trace, so names
  work with no symbol server. PDB names load on top when available: the
  exact PDB each recorded module was built with is downloaded and read in
  the background, and its function names are filled in a few at a time while
  you look at a stop, so neither a slow symbol server nor a big PDB holds up
  a step. **TTD > Annotate database > Load full symbols for this module**
  applies a module's whole PDB (types and prototypes too) through IDA's PDB
  plugin.
- Execution coverage colors the instructions that actually ran, in both the
  disassembly and the decompiler.
- Indirect calls are resolved to the targets they really reached and written
  back as comments and cross-references -- on request, or automatically for
  each function you stop in. A call that always reached one API gets its
  prototype, and so does the global function pointer it went through (named
  after the API, e.g. `pInternetConnectA`), so the decompiler shows the
  arguments with their names and types.

**Trace-wide queries**

- Find every call to a function, or to a wildcard pattern such as
  `kernel32!Virtual*`, with arguments and return values. Windows and native
  APIs are decoded from Microsoft's Win32 metadata and phnt's headers (the
  indexes [ttd-capa-cpp](https://github.com/HullaBrian/ttd-capa-cpp) builds):
  flags by name, strings, buffers at their real length, and out parameters as
  the callee filled them in.
- Find every read, write or execute of an address or range.
- The memory map at the current position: every region with its base, size,
  protection, type and use -- module sections, stacks, TEBs, the PEB, heaps,
  and what the program allocated -- following the playhead as you step.
- The memory timeline: every allocation, protection change and free, with each
  live region exposed as an IDA segment carrying its real permissions.
- Every syscall the program made, with its result and arguments.
- Every handle the program opened and closed -- files, registry keys,
  sockets, pipes, processes, threads, sections and the rest -- with its name,
  where it was opened and where it was closed.
- Where a value came from (Ctrl+Shift+W), as a graph: a register or memory
  followed back through the instructions that copied it -- moves, pushes and
  pops, string and SSE copies -- and through computations made from a single
  value (`lea rax, [rdi+0Dh]`, `inc rdi`). Every value an instruction combined
  is followed in turn, down to the constants, syscalls and untouched memory it
  was made of. Double-click a value to go to where it was written.
- A memory heatmap: which pages the program read, wrote and ran from, and when.
  Drag across it, or type a start and end position, to count a shorter span
  at full resolution; Back and Whole recording zoom out again.
- A Python API (`import ida_ttd`) over all of it, for scripts and AI agents;
  see [docs/python.md](docs/python.md).
- Self-modifying code: every instruction the program wrote before running it,
  with the write that made it.
- Strings and buffers recovered from the recording's memory writes: every
  string the program had in memory and every buffer it filled, with when and
  by what. Nothing is re-run: the scan reads the writes the recording holds.
  (A Sogen recording old enough not to store its written bytes is replayed in
  Sogen's emulator instead, which needs its registry hives.)

**Sogen recordings only**

- Fork the recording: TTD > Forks > Fork here makes the current position a fork.
  Change registers (the registers window) and memory (the hex view, or Edit >
  Patch program) as on a live target; the views show the changes there, and
  the toolbar says "(fork)". TTD > Forks > Record fork... replays the program to the
  fork, applies them, and lets it run on into a new recording, which opens
  like any other. Fork here is also on the context menu of the disassembly,
  pseudocode, hex view and registers.
- Fork manager (TTD menu and toolbar): the recording and every fork recorded
  from it, and from its forks, as a tree, each with the changes it was made
  with. Double-click one to switch this IDA to it (the replay restarts on it,
  in the same database) or open it in a new IDA; right-click to copy its path
  or remove a fork from the graph (its file is kept). Right-click the
  recording being replayed to fork at the current position, then record or
  discard the fork from the same menu.
- Network access for forks: off by default, when the program gets a
  loopback-only network where no host name resolves. The Record fork dialog
  (and the `sogen_network` setting) can give the program the real network
  from the fork's position on; the replay up to the position stays offline
  either way, since the recording's own results stand in for what the
  network answered then. A connection the program had open at the fork's
  position is closed for the fork (it reads as reset by the other end).
  While a fork records, a window shows how long it has run and Sogen's log
  as it comes, with Pause (the program stands still until Resume) and Stop
  recording (the fork ends there and keeps what ran). The dialog's "Sogen's
  log to the Output window" (the `sogen_log` setting at first) also prints
  the whole log there.
- Record a program (TTD > Backends > Record a program with Sogen..., in any
  database): run an executable from its start in Sogen's emulator and record
  it into a new `.sogttd`, without Sogen's own tools. It starts from the
  database's executable; you choose its arguments, working directory, an
  emulation root or the registry hives it runs against, the instruction
  limit, network access and an administrator's token. It runs headless (a
  program's windows are not shown). A recording made with network access
  keeps what the network answered, so its replays (the scans, and forks up
  to their position) need no network and see the same traffic. An emulation root is Sogen's folder
  holding `filesys\` (the program's drives: `filesys\c` is its C:) and
  `registry\` (its hives). A program recorded in one must be inside its
  `filesys` folder, since that is all it sees: the dialog copies a program
  from elsewhere into the root, to a guest folder you name (`C:\ida-ttd`
  at first), and asks before replacing a different file there. The
  emulation root it starts with is the `sogen_emulation_root` setting. The
  output file is named after the program and the time
  (`name-YYYYMMDD-HHMMSS.sogttd`), so recording again makes a new file.
  While it records, the same window as a fork's shows how long it has
  been running and Sogen's log, with Pause and Stop recording. With "Sogen's log to the Output window"
  (the `sogen_log` setting at first) the Output window also gets the whole
  log; it always says how long the recording took. The program starts
  at the current date and time (otherwise 1 January 1970, the
  `sogen_start_now` setting), so date checks such as certificate validity
  behave as on a real machine; the clock then advances with the
  instructions run, and replays and forks see the same dates. The checkpoint
  interval and what is recorded (reads, writes, instruction fetches) are
  settings, and apply to forks too. With `sogen_log` on, the Output window
  also names each service the program messaged that Sogen does not emulate,
  usually where a program that fails silently stopped. For WinINet
  programs, an emulation root needs `Windows\SystemResources\wininet.dll.mun`
  (Sogen's `create-root.bat` copies it since `f848464d`).

The value origin graph and the fork manager are drawn by the plugin's own graph
window (IDAPython with PySide6, like the call tree and the heatmap): drag to
pan, Ctrl+wheel to zoom, F to fit, double-click or right-click a node. Without
IDAPython the fork manager uses IDA's graph viewer.

Replaying a recording made against the host (without an emulation root) runs
the program's file operations on your machine again (it creates, changes and
deletes the same files), so the replay features ask before doing it, and so
does recording a program without an emulation root. The network is reached
only where you allow it: a fork past its position, or a new recording.

**Opening traces**

- Open a `.run` or `.sogttd` file directly from `File > Open`. The recorded program's image
  is read out of the trace, so no copy of the original binary is needed.
- Or attach a trace to a database you already have.

## Requirements

- IDA Pro 9.4, Windows x64. The plugin is built against the 9.4 SDK.
- For Microsoft TTD recordings, Microsoft's replay runtime (`TTDReplay.dll`,
  `TTDReplayCPU.dll`), which comes with WinDbg. Microsoft does not allow anyone
  else to distribute it, so it is not included; the plugin gets it for you
  (Installation, step 2).

## Installation

Paths below are relative to your IDA user directory, `%APPDATA%\Hex-Rays\IDA Pro`
(or the first folder in `%IDAUSR%` if you set it).

1. Install the plugin with HCLI:

   ```
   hcli plugin install ida-ttd
   ```

   This puts it in `plugins\ida-ttd\`: `ida-ttd.dll`, the `ida-ttd-backends`
   folder with `ida-ttd-msttd.dll` (the Microsoft TTD backend), the
   `ida-ttd-data` folder with the API metadata (`win32-index.bin`,
   `phnt-index.bin`) that decodes API calls' arguments, and the
   `ida-ttd-python` folder with the `ida_ttd` Python module, and
   `ida-ttd-loader-setup`, which copies the trace loader (`ttd-loader.dll`,
   what makes `File > Open` recognize a recording) into `loaders\` the next
   time IDA starts. HCLI can only install into the plugin's own folder, so that
   copy is the plugin's doing; the output window says when it happens.
   Uninstalling the plugin leaves `loaders\ttd-loader.dll` behind; delete it by
   hand.

   Without HCLI, download `ida-ttd.zip` from the
   [latest release](https://github.com/HullaBrian/ida-ttd/releases) and extract
   it into `plugins\`: it holds one `ida-ttd` folder.
2. Get the TTD replay runtime: choose **TTD > Backends > Install the TTD runtime (WinDbg)...** (or run
   `import ida_ttd_runtime; ida_ttd_runtime.install_runtime()` in IDAPython). If WinDbg is installed,
   its `amd64\ttd` folder is copied; run it again after WinDbg updates. If not,
   it shows WinDbg's license and, once you accept it, downloads WinDbg's x64
   package (about 390 MB) from Microsoft. Either way the result goes in
   `ida-ttd\windbg\`. Then start the debugger. The TTD menu is there with no
   database open too (once IDA has been restarted after installing the
   plugin), so this can be done before opening anything.

   WinDbg's license allows commercial use. The standalone TTD package's license
   does not, which is why the plugin never uses it.

   To do it by hand instead, copy WinDbg's `amd64\ttd` folder to
   `ida-ttd\windbg\amd64\ttd`, or `TTDReplay.dll` and `TTDReplayCPU.dll` from
   it next to `ida.exe`.
3. Sogen recordings need nothing more: the package includes the Sogen
   backend (`ida-ttd-backends\ida-ttd-sogen.dll`). **TTD > Backends > Install
   the Sogen backend...** installs another build of it (yours, from
   [docs/building-the-sogen-backend.md](docs/building-the-sogen-backend.md))
   into `ida-ttd\backends\`, where it takes the place of the packaged one;
   delete it from there to go back. The replay features (forks, recovered strings
   and buffers) of a recording from Sogen before 2026-10-21 also need the
   registry hives it ran against: the very files Sogen was given when it
   recorded, since a new copy of the same registry is not the same. Newer
   recordings carry what they read of them and need none. For a recording
   made against the host, keep the hives in a `registry` folder beside it, or
   in `ida-ttd\registry\`, and they are found and checked; one made in an
   emulation root uses the root's own `registry` folder, and the plugin asks
   where the root is when it is not where it was. A recording made against
   the host replays only on a machine with the same Windows build, normally
   the one it was recorded on. Hives hold that machine's password hashes, so
   share them with care. Recordings from Sogen before 2026-11-07 (trace format
   8) open and answer every query, but cannot be forked with this backend:
   their checkpoints hold an older emulator state. Record them again (TTD >
   Backends > Record a program with Sogen...) to fork them.

Everything you add yourself lives in the `ida-ttd` folder of the IDA user
directory, never in `plugins\ida-ttd\`: HCLI replaces that folder on every
upgrade, so anything added to it is lost.

```
%APPDATA%\Hex-Rays\IDA Pro\
  plugins\ida-ttd\     the plugin package (HCLI's; replaced on upgrade)
  loaders\             ttd-loader.dll, copied there by the plugin
  ida-ttd\             yours; upgrades leave it alone
    windbg\              the TTD runtime, copied from WinDbg
    backends\            a Sogen backend of your own, if any
    registry\            registry hives for Sogen replays and forks
```

Earlier versions used `plugins\ida-ttd-backends\` for these. It is still
searched, and the installers move what they find there.

The output window names each backend as it loads, and says why when one does
not.

If you installed the trace loader by hand into IDA's own `loaders` folder (beside
`ida.exe`), the setup component leaves it alone and installs no second copy.

### Settings

Nothing is asked during installation; every setting has a default. Change
them in **TTD > Settings...**, which opens the IDA Settings Editor
(`hcli plugin install ida-settings-editor`), or from the command line with
`hcli plugin config ida-ttd set KEY VALUE`. Changes apply from the next stop
of the replay. The editor has no sections, so each setting's label starts
with its section.

| Section | Key | Default | |
| --- | --- | --- | --- |
| Replay | `replay_on_open` | `true` | start the replay when a recording's database opens (off: Debugger > Start process) |
| Symbols | `symbol_downloads` | `true` | download system DLLs' PDBs in the background |
| | `symbol_server` | `https://msdl.microsoft.com/download/symbols` | where from |
| Analysis | `auto_coverage` | `true` | measure and colour each function the first time the replay stops in it |
| | `auto_callsites` | `false` | comment its indirect calls with where they went, likewise |
| Memory map | `memmap_flag_code` | `true` | colour executable regions outside every loaded module |
| Sogen | `fork_instructions` | `1000000` | the Fork dialog's default length (0: to the end) |
| | `registry_folder` | (none) | another folder to look in for a recording's registry hives |
| | `sogen_emulation_root` | (none) | the emulation root the Record dialog starts with, and the one a recording made in a root is replayed in when the root it was made in is not on this machine |
| | `sogen_network` | `false` | give forks (past their position) and new recordings the real network; the dialogs start from it |
| | `sogen_checkpoint_interval` | `500000` | instructions between a new recording's or fork's checkpoints (0: Sogen's default) |
| | `sogen_record_reads` | `true` | keep memory reads in new recordings and forks (off: much smaller, no read queries) |
| | `sogen_record_writes` | `true` | keep memory writes (off: no write queries, strings, buffers or self-modifying code) |
| | `sogen_record_executes` | `true` | keep instruction fetches (off: no coverage or execute breakpoints) |
| | `sogen_elevated` | `false` | record programs with an administrator's token: the program sees itself elevated, but its operations on this machine's files keep IDA's rights (forks keep their recording's token) |
| | `sogen_log` | `false` | print Sogen's emulator log and the program's console output in the Output window while a fork, scan or recording runs, and the messages sent to services Sogen does not emulate (the recording window shows it either way) |
| | `sogen_start_now` | `true` | start new recordings at the date and time recording begins rather than 1 January 1970; replays and forks see the same dates |
| Diagnostics | `diagnostics_log` | `true` | write `%TEMP%\ida-ttd-diag.log` |

Settings are read through the `ida-settings` Python package, which HCLI
installs with the plugin. Without it (a hand install), the defaults apply.

## Usage

### Open a trace directly

`File > Open` the `.run` (or `.sogttd`) file and choose **Microsoft TTD trace
(.run)** (or **Sogen recording**). IDA builds a database from the recording and
starts replaying it.

To open the database without replaying, turn off the `replay_on_open` setting
(**TTD > Settings...**). **Debugger > Start process** (F9) starts the replay
later.

If the trace has no index yet, you are asked whether to build one. Building can
take several minutes. Declining still gives you a database with the right
addresses, names and permissions, and the index is built when you start the
replay instead.

### Attach a trace to an existing database

1. Open the IDB for the recorded binary.
2. `Debugger > Switch debugger` and choose **TTD trace replayer**.
3. Start debugging and give the trace file as the application.

### Move through the recording

Use the normal debugger controls to step forward. The TTD toolbar adds the
backward equivalents, run to cursor in both directions, a live position readout
and the bookmark buttons. The queries are on the top-level **TTD** menu.

### Find where a buffer came from

Right-click an address and choose **Find memory accesses**, or press
`Ctrl+Shift+M` and enter a range. Every read, write and execute anywhere in the
recording is listed with its position, thread and instruction. Double-click a
row to travel to that moment.

### Find every call to an API

Press `Ctrl+Shift+F` and enter a pattern such as `kernel32!Virtual*`. The results
list each call with its arguments and return value. Double-click to travel to
the call.

### Map allocated memory

Run **TTD > Memory > Memory map** for the address space at the current position: each
region's base, size, protection, type and use, with writable-and-executable
memory in bold and executable memory outside every loaded module (code the
program allocated or mapped itself) coloured; the `memmap_flag_code` setting
turns the colour off. It follows the playhead as you step. Double-click a region to go
to it, or its "Allocated at" position to travel there (Ctrl+E does the same from any
column).

**TTD > Memory > Memory timeline** lists every allocation, protection change
and free in order, with the program code that requested it (the first frame
outside library code) and the whole recorded call chain, innermost first: when
one call of the program (loading a DLL, its malloc) is behind many changes, the
library frames inside it and the program's frames beyond it tell them apart.
The chain holds the innermost frame in each library module crossed and every
frame in the program, up to eight. Building it replays the
recording once and is saved in the database. Regions live at the current
position become named IDA segments with their real permissions, so an RWX
buffer is visible as one.

### Keep your work on code outside the modules

Memory no module covers (allocations, mapped views, the code a packer or
loader wrote) exists in IDA only while the replay runs: IDA deletes those
segments when the session ends, and rebuilds them when a travel changes the
memory map. What you set on a function there is kept in the database instead:
its bounds, name, prototype (calling convention, return and parameter types and
names), comments, labels, and in the decompiler its variable names, types and
comments and its pseudocode comments. When a function starts at the same
address again, in a later session or after a travel, whether you define it or
the plugin does when you stop in it, all of that comes back.

A kept function comes back only where its bytes are the same as when you worked
on it, so a region freed and reused for other code, or an unpacker's next stage
at the same address, is never given the wrong names; each version of the code
keeps its own. Work on a function is saved before every movement, when the
session ends and when the database is saved.

### Re-read memory the database got wrong

IDA caches the bytes at an address the first time it shows them. A range read
before its module was mapped, or before the write that produced its contents was
replayed, keeps that first answer.

Select the range, right-click it and choose **TTD > Re-read memory from the recording**.
The cached bytes are discarded, the range is rebuilt from the recording's
writes, and it is disassembled again.

### Default shortcuts

| Action | Shortcut |
| --- | --- |
| Find calls to this function | `Ctrl+Shift+C` |
| Find calls by name/pattern | `Ctrl+Shift+F` |
| Find memory accesses | `Ctrl+Shift+M` |
| Analyze whole function | `Ctrl+Shift+A` |
| Timeline | `Ctrl+Shift+T` |
| Go to position | `Ctrl+Shift+G` |
| Bookmark this position | `Ctrl+Shift+B` |

Stepping keeps IDA's usual shortcuts (`F7`, `F8`, `Ctrl+F7`, `F4`) and their
backward variants. Continue backwards and step out backwards are on the TTD
toolbar.

## Building from source

Requires Visual Studio 2022 or later with the C++ desktop workload. The
project uses whichever toolset is installed.

```
git clone --recurse-submodules https://github.com/HullaBrian/ida-ttd
cd ida-ttd
nuget install msbuild\packages.config -OutputDirectory packages
msbuild ida-ttd.slnx -p:Configuration=Release -p:Platform=x64 -m:1
```

Build serially (`-m:1`): parallel compiler instances racing on the shared PDB
can produce a `C1041` error. Output is `build\Release\ida-ttd.dll`,
`build\Release\ttd-loader.dll`, `build\Release\ida-ttd-loader-setup.dll` and
`build\Release\backends\ida-ttd-msttd.dll`. Only the Microsoft backend needs the
TTD Replay SDK restored by `nuget`; the plugin and the loader need the IDA SDK
alone. `python scripts\package.py` then builds `dist\ida-ttd.zip`, the package
HCLI installs (`hcli plugin install dist\ida-ttd.zip`).

The Sogen backend is not in the solution, since it needs a Sogen build:
[docs/building-the-sogen-backend.md](docs/building-the-sogen-backend.md).
`build\Release\ittd-probe.exe` drives any backend DLL outside IDA and checks it
against the interface (`ittd-probe <backend.dll> <trace> [export|0xADDR]`).

## Repository layout

```
src/abi/           the C interface between the core and a backend DLL
src/core/          ITraceBackend and positions; BackendModule, which adapts a
                   backend DLL to it; abi_export, which does the reverse for a
                   backend written in C++
src/backend-msttd/ ida-ttd-msttd.dll: Microsoft TTD, the only code that sees
                   the TTD Replay SDK
src/backend-sogen/ ida-ttd-sogen.dll: Sogen, against Sogen's trace reader
src/common/        the trace link record, PE parsing and symbols, strings
src/debugger/      the IDA debugger session over ITraceBackend: modules,
                   memory, code layout, registers, calling conventions
src/analysis/      whole-trace analyses -- call tracing, coverage, memory
                   search, memory map, indirect calls, bookmarks -- each a
                   backend query run behind a wait box
src/ui/            choosers, action handlers, pseudocode highlighting
src/plugin/        the plugmod_t, the event listeners, the actions, the toolbar
                   and the ttd("...") script API (docs/scripting.md)
src/loader/        ttd-loader.dll, which makes File > Open recognise a trace
src/setup/         ida-ttd-loader-setup.dll, which copies the loader into
                   loaders\ for an HCLI install
src/tools/         ittd-probe, a backend checker that runs outside IDA
msbuild/           the project files and the settings they share
```

`src/` is the single include root, so every local include names its folder
(`#include "debugger/trace_manager.h"`) and a header's home is visible wherever
it is used.

## License

ida-ttd is dual-licensed: use it under the Apache License 2.0
([LICENSE](LICENSE)) or the GNU GPL version 2
([LICENSES/GPL-2.0-only.txt](LICENSES/GPL-2.0-only.txt)), whichever you
choose (`Apache-2.0 OR GPL-2.0-only`). The GPL option is there so the plugin
can ship together with the Sogen backend.

Exceptions:

- The Sogen backend (`src/backend-sogen/sogen_backend.cpp`, and the
  `ida-ttd-sogen.dll` built from it) is GPL-2.0-only, because Sogen and
  Unicorn are. The package carries its license, notices and where its source
  is in `ida-ttd-backends\ida-ttd-sogen-licenses\`; the source itself is
  `ida-ttd-sogen-source.zip` on the same release.
- The API metadata loader (`src/common/apimeta/`, from ttd-capa-cpp) and the
  Material Symbols icons are Apache-2.0; the Codicons are CC BY 4.0.
- The backend ABI header is CC0.

The API metadata in `data/` is derived from win32metadata and phnt, both MIT.
Third-party notices are in [THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt),
which the package carries too. [docs/licensing.md](docs/licensing.md) has the
details.
