> [!Warning]
> Claude was used to program this project. I performed testing for my own use cases, but
> you may run into issues. If you do, feel free to open an issue on this repository!

# ida-ttd

ida-ttd is an IDA Pro plugin that allows you to interact with time travel debugging (TTD)
recordings from multiple TTD backends (Microsoft and Sogen) and holistically analyze 
traces using a multitude of TTD analysis techniques.

## Overview

Time Travel Debugging (TTD) is a technique that records binary execution and, in some cases, 
memory accesses (ie reads, writes, executes). Using it grants reverse engineers the ability 
to efficiently analyze a process's historical behavior and spend less time fighting typical 
dynamic analysis headaches. Additionally, TTD extends analysis capabilities in a number of 
ways, especially when it comes to higher level questions about *what* a process did.

ida-ttd registers a custom debugger and loader which allows IDA to perform analysis. 

------ 

A time travel recording holds every instruction a process executed, so the
answer to "where did this pointer come from" or "what wrote these bytes" is
already in the file. ida-ttd makes that recording an IDA debugger session: the
usual debugger controls move through it in either direction, the disassembly,
decompiler, registers and hex views show the program as it was at that moment,
and the **TTD** menu runs queries across the whole recording.

This matters most for code that is not in the binary you started with. Packed,
injected and JIT-generated code exists only at runtime, and a recording of it
is often the only artifact you have. ida-ttd disassembles that code, names it,
shows which parts actually ran, and rebuilds the memory regions it lived in
with their protections. Navigation and queries read the recording rather than
running the sample again (only a Sogen fork or replay you ask for does), so
every analysis gives the same answer each time.

What you get:

- **Reverse debugging** in IDA's debugger UI: step, step over, step out, run to
  cursor and continue, backwards as well as forwards; a timeline; bookmarks.
- **Runtime code recovery**: unpacked and injected code disassembled a function
  at a time, with symbols from the recorded modules and their PDBs, and your
  work on it kept in the database.
- **Whole-recording queries**: every call to an API with decoded arguments,
  every access to an address, every syscall and handle, the memory map and its
  history, where a value came from, strings and buffers, self-modifying code,
  execution coverage and a memory heatmap.
- **Forks** (Sogen recordings): change registers or memory at any position and
  let the program run on from there into a new recording.
- **A Python API** (`import ida_ttd`) over all of it, for scripts and AI agents.

## Features

### Navigation

- Replay a recording forwards and backwards, including reverse-continue, step
  out backwards, and run to cursor in either direction.
- A timeline of thread and module events, and jump to an exact
  `Sequence:Steps` position.
- Position bookmarks with names and comments, saved in the database. A
  bookmark made in a different recording (re-recorded since, or a fork) is
  greyed out rather than taken to a position it does not name.

### Code discovery

- Runtime-only code is disassembled a whole function at a time, using the PE
  exception table for module code and the recorded execution for everything
  else. Self-modified regions are re-analyzed when their bytes change.
- Your names, prototypes, comments and decompiler variables on functions
  outside the modules are kept in the database and come back in later
  sessions, wherever the same code is at the same address.
- Symbols come from each module's export table read out of the recording, so
  names work with no symbol server. PDB names load on top when available: the
  exact PDB each recorded module was built with is downloaded and read in the
  background, a few names at a time while you look at a stop, so neither a
  slow symbol server nor a big PDB holds up a step. **TTD > Annotate database >
  Load full symbols for this module** applies a module's whole PDB (types and
  prototypes too) through IDA's PDB plugin.
- Execution coverage colors the instructions that actually ran, in both the
  disassembly and the decompiler. Where the decompiler made a whole `if` out
  of one conditional move (`cmovcc`), its body is colored only if the move
  happened at least once, since the instruction runs either way.
- Indirect calls are resolved to the targets they really reached and written
  back as comments and cross-references, on request or automatically for each
  function you stop in. A call that always reached one API gets its
  prototype, and so does the global function pointer it went through (named
  after the API, e.g. `pInternetConnectA`), so the decompiler shows the
  arguments with their names and types.

### Whole-recording queries

- **Calls**: every call to a function, or to a pattern such as
  `kernel32!Virtual*`, with arguments and return values. Windows and native
  APIs are decoded from Microsoft's Win32 metadata and phnt's headers: flags
  by name, strings, buffers at their real length, and out parameters as the
  callee filled them in.
- **Memory accesses**: every read, write or execute of an address or range.
- **Memory map** at the current position: every region with its base, size,
  protection, type and use (module sections, stacks, TEBs, the PEB, heaps, and
  what the program allocated), following the playhead as you step.
- **Memory timeline**: every allocation, protection change and free, with each
  live region exposed as an IDA segment carrying its real permissions.
- **Syscalls**: every one the program made, with its result and arguments.
- **Handles**: every file, registry key, socket, pipe, process, thread, section
  and other handle the program opened and closed, with its name and where it
  was opened and closed.
- **Value origin** (`Ctrl+Shift+W`), as a graph: a register or memory followed
  back through the instructions that copied it (moves, pushes and pops,
  string and SSE copies) and through computations made from a single value
  (`lea rax, [rdi+0Dh]`, `inc rdi`). Every value an instruction combined is
  followed in turn, down to the constants, syscalls and untouched memory it
  was made of. Double-click a value to go to where it was written.
- **Memory heatmap**: which pages the program read, wrote and ran from, and
  when. Drag across it, or type a start and end position, to count a shorter
  span at full resolution; Back and Whole recording zoom out again.
- **Self-modifying code**: every instruction the program wrote before running
  it, with the write that made it.
- **Strings and buffers** recovered from the recording's memory writes: every
  string the program had in memory and every buffer it filled, with when and
  by what. Nothing is re-run: the scan reads the writes the recording holds.
  (A Sogen recording old enough not to store its written bytes is replayed in
  Sogen's emulator instead, which needs its registry hives.)

### Sogen recordings only

- **Forks.** **TTD > Forks > Fork here** makes the current position a fork.
  Change registers (the registers window) and memory (the hex view, or Edit >
  Patch program) as on a live target; the views show the changes, and the
  toolbar says "(fork)". **TTD > Forks > Record fork...** replays the program
  to the fork, applies the changes, and lets it run on into a new recording,
  which opens like any other. Fork here is also on the context menu of the
  disassembly, pseudocode, hex view and registers.
- **Fork manager** (TTD menu and toolbar): the recording and every fork made
  from it, and from its forks, as a tree, each with the changes it was made
  with. Double-click one to switch this IDA to it (the replay restarts on it,
  in the same database) or open it in a new IDA; right-click to copy its path,
  remove a fork from the tree (its file is kept), or fork, record or discard
  at the current position.
- **Network access for forks** is off by default: the program gets a
  loopback-only network where no host name resolves. The Record fork dialog
  (and the `sogen_network` setting) can give it the real network from the
  fork's position on; the replay up to that position stays offline either
  way, since the recording's own results stand in for what the network
  answered then. A connection open at the fork's position reads as reset by
  the other end.
- **Record a program** (**TTD > Backends > Record a program with Sogen...**, in
  any database): run an executable from its start in Sogen's emulator and
  record it into a new `.sogttd`, without Sogen's own tools. You choose its
  arguments, working directory, an emulation root or registry hives, the
  instruction limit, network access and an administrator's token. It runs
  headless (the program's windows are not shown), and the file is named
  after the program and the time (`name-YYYYMMDD-HHMMSS.sogttd`).
  - A recording made with network access keeps what the network answered, so
    its replays (the scans, and forks up to their position) need no network.
  - An *emulation root* is Sogen's folder holding `filesys\` (the program's
    drives: `filesys\c` is its C:) and `registry\` (its hives). A program
    recorded in one must be inside its `filesys` folder, so the dialog copies
    it there, to a guest folder you name (`C:\ida-ttd` at first), and asks
    before replacing a different file. For WinINet programs the root needs
    `Windows\SystemResources\wininet.dll.mun` (Sogen's `create-root.bat`
    copies it since `f848464d`).
  - The program starts at the current date and time (or 1 January 1970, the
    `sogen_start_now` setting), so date checks such as certificate validity
    behave as on a real machine; the clock then advances with the
    instructions run, and replays and forks see the same dates.
- While a fork or a new recording runs, a window shows how long it has run
  and Sogen's log as it comes, with **Pause** and **Stop recording** (which
  keeps what ran). With the `sogen_log` setting the Output window also gets
  the whole log, including each service the program messaged that Sogen does
  not emulate, which is usually where a program that fails silently stopped.

**Running on your machine.** Replaying a Sogen recording that was made against
the host (without an emulation root) repeats the program's file operations on
your machine (it creates, changes and deletes the same files), so the replay
features ask first, as does recording a program without an emulation root. The
network is reached only where you allow it: a fork past its position, or a new
recording.

The value origin graph, the fork manager, the call tree and the heatmap are
the plugin's own windows (IDAPython with PySide6): drag to pan, Ctrl+wheel to
zoom, F to fit, double-click or right-click a node. Without IDAPython the fork
manager uses IDA's graph viewer.

## Requirements

- IDA Pro 9.5 on Windows x64. The plugin is built against the 9.5 SDK and
  does not load in 9.4 (the debugger interface changed version).
- For Microsoft TTD recordings, Microsoft's replay runtime (`TTDReplay.dll`,
  `TTDReplayCPU.dll`), which comes with WinDbg. Microsoft does not allow anyone
  else to distribute it, so it is not included; the plugin fetches it for you
  (Installation, step 2).
- For Sogen recordings, nothing more: the Sogen backend is in the package.

## Installation

Paths below are relative to your IDA user directory,
`%APPDATA%\Hex-Rays\IDA Pro` (or the first folder in `%IDAUSR%` if you set it).

### 1. Install the plugin

With [HCLI](https://hcli.docs.hex-rays.com/) (or IDA's plugin manager):

```
hcli plugin install ida-ttd
```

Without HCLI, download `ida-ttd.zip` from the
[latest release](https://github.com/HullaBrian/ida-ttd/releases) and extract it
into `plugins\`: it holds one `ida-ttd` folder.

Then restart IDA. On that start the plugin copies its file loader
(`ttd-loader.dll`, which lets **File > Open** recognize a recording) into
`loaders\`, and the Output window says so. HCLI can only install into the
plugin's own folder, which is why the plugin makes that copy itself;
uninstalling leaves `loaders\ttd-loader.dll` behind, so delete it by hand. If
you installed the loader yourself into IDA's own `loaders` folder (beside
`ida.exe`), it is left alone and no second copy is made.

### 2. Get the TTD replay runtime (Microsoft recordings)

Choose **TTD > Backends > Install the TTD runtime (WinDbg)...**. The TTD menu
is there with no database open, so this can be done before opening anything.
(From IDAPython: `import ida_ttd_runtime; ida_ttd_runtime.install_runtime()`.)

- If WinDbg is installed, its `amd64\ttd` folder is copied. Run it again after
  WinDbg updates.
- If not, it shows WinDbg's license and, once you accept it, downloads WinDbg's
  x64 package (about 390 MB) from Microsoft.

Either way the runtime goes in `ida-ttd\windbg\`. WinDbg's license allows
commercial use; the standalone TTD package's license does not, which is why
the plugin never uses it. To do it by hand, copy WinDbg's `amd64\ttd` folder
to `ida-ttd\windbg\amd64\ttd`, or put `TTDReplay.dll` and `TTDReplayCPU.dll`
from it next to `ida.exe`.

### 3. Sogen recordings (optional extras)

Sogen recordings open with no further setup. Two things only some users need:

- **Your own build of the Sogen backend.** **TTD > Backends > Install the Sogen
  backend...** installs one (built as
  [docs/building-the-sogen-backend.md](docs/building-the-sogen-backend.md)
  describes) into `ida-ttd\backends\`, where it takes the place of the
  packaged one. Delete it from there to go back.
- **Registry hives for older recordings.** The replay features (forks,
  recovered strings and buffers) of a recording made by Sogen before
  2026-10-21 need the exact registry hives it ran against; a new copy of the
  same registry is not the same. Newer recordings carry what they read and
  need none. Keep the hives in a `registry` folder beside the recording, or in
  `ida-ttd\registry\`, and they are found and checked; a recording made in an
  emulation root uses the root's own `registry` folder, and the plugin asks
  where the root is if it has moved. Hives hold that machine's password
  hashes, so share them with care.

A recording made against the host replays only on a machine with the same
Windows build, normally the one it was recorded on. Recordings from Sogen
before 2026-11-07 (trace format 8) open and answer every query but cannot be
forked by this backend, since their checkpoints hold an older emulator state:
record them again (**TTD > Backends > Record a program with Sogen...**) to
fork them.

### Where things live

Everything you add yourself goes in the `ida-ttd` folder of the IDA user
directory, never in `plugins\ida-ttd\`: HCLI replaces that folder on every
upgrade.

```
%APPDATA%\Hex-Rays\IDA Pro\
  plugins\ida-ttd\     the plugin package (HCLI's; replaced on upgrade)
    ida-ttd.dll
    ida-ttd-backends\    the Microsoft TTD and Sogen backends
    ida-ttd-data\        API metadata that decodes call arguments
    ida-ttd-python\      the ida_ttd Python module
    ida-ttd-loader-setup\  copies the loader into loaders\
  loaders\             ttd-loader.dll, copied there by the plugin
  ida-ttd\             yours; upgrades leave it alone
    windbg\              the TTD runtime, copied from WinDbg
    backends\            a Sogen backend of your own, if any
    registry\            registry hives for Sogen replays and forks
```

Earlier versions used `plugins\ida-ttd-backends\` for these; it is still
searched, and the installers move what they find there. The Output window
names each backend as it loads, and says why when one does not.

## Usage

### Open a recording

**File > Open** the `.run` or `.sogttd` file and choose **Microsoft TTD trace
(.run)** or **Sogen recording**. IDA builds a database from the recording and
starts replaying it. The recorded program's image is read out of the
recording, so no copy of the original binary is needed.

If the recording has no index yet, you are asked whether to build one,
which can take several minutes. Declining still gives you a database with the
right addresses, names and permissions; the index is then built when you start
the replay.

To open the database without replaying, turn off the `replay_on_open` setting;
**Debugger > Start process** (F9) starts the replay later.

### Attach a recording to an existing database

1. Open the database for the recorded binary.
2. **Debugger > Switch debugger** and choose **TTD trace replayer**.
3. Start debugging and give the recording as the application.

### Move through the recording

The normal debugger controls step forward (`F7`, `F8`, `Ctrl+F7`, `F4`). The
TTD toolbar adds their backward equivalents, continue and step out backwards,
run to cursor in both directions, a live position readout and the bookmark
buttons. The queries are on the top-level **TTD** menu.

### Example: find what wrote a buffer

Right-click an address and choose **Find memory accesses**, or press
`Ctrl+Shift+M` and enter a range. Every read, write and execute anywhere in the
recording is listed with its position, thread and instruction. Double-click a
row to travel to that moment, then press `Ctrl+Shift+W` on the register that
was stored to see where its value came from.

### Example: find every call to an API

Press `Ctrl+Shift+F` and enter a pattern such as `kernel32!Virtual*`. Each call
is listed with its decoded arguments and return value; double-click one to
travel to it.

### Example: find unpacked code

Open **TTD > Memory > Memory map** for the address space at the current
position: each region's base, size, protection, type and use, with
writable-and-executable memory in bold and executable memory outside every
loaded module (code the program allocated or mapped itself) colored. It
follows the playhead as you step. Double-click a region to go to it, or its
"Allocated at" position to travel there (`Ctrl+E` does the same from any
column).

**TTD > Memory > Memory timeline** lists every allocation, protection change
and free in order, with the program code that requested it (the first frame
outside library code) and the recorded call chain, innermost first, up to
eight frames. Building it replays the recording once and is saved in the
database. Regions live at the current position become named IDA segments with
their real permissions, so an RWX buffer is visible as one.

### Example: script it

```python
import ida_ttd

s = ida_ttd.Session()                    # the TTD session in this IDA
s.start()                                # replay this database's recording
s.goto("1A:2F")                          # any position
s.step(back=True)                        # one instruction backwards
hex(s.reg("rax")), s.read(s.reg("rsp"), 0x40)

for c in s.calls_to("kernel32!CreateFileW"):
    print(c)                             # arguments and return value
s.accesses(0x1234, 0x1238, "w")          # every write to those bytes
s.origin("rax")                          # where rax's value came from
[c["name"] for c in s.syscalls()]
```

The same module opens a recording headless with no debugger (`Recording`), and
works in idat, idalib and an MCP server's Python, which makes it the way to give
an AI agent the recording. [docs/scripting.md](docs/scripting.md) is the
guide to the module and the reference for the `ttd("...")` IDC command
underneath it.

### Keep your work on code outside the modules

Memory no module covers (allocations, mapped views, the code a packer wrote)
exists in IDA only while the replay runs: IDA deletes those segments when the
session ends, and rebuilds them when a travel changes the memory map. What you
set on a function there is kept in the database instead: its bounds, name,
prototype, comments, labels, and in the decompiler its variable names, types
and comments. When a function starts at the same address again, in a later
session or after a travel, all of that comes back.

A kept function comes back only where its bytes are the same as when you worked
on it, so a region freed and reused for other code, or an unpacker's next stage
at the same address, is never given the wrong names; each version of the code
keeps its own. Work is saved before every movement, when the session ends and
when the database is saved.

### Re-read memory IDA cached too early

IDA caches the bytes at an address the first time it shows them, so a range
read before its module was mapped, or before the write that produced it was
replayed, keeps that first answer. Select the range, right-click it and choose
**TTD > Re-read memory from the recording**: the cached bytes are discarded,
the range is rebuilt from the recording's writes, and it is disassembled again.

### Default shortcuts

| Action | Shortcut |
| --- | --- |
| Find calls to this function | `Ctrl+Shift+C` |
| Find calls by name/pattern | `Ctrl+Shift+F` |
| Find memory accesses | `Ctrl+Shift+M` |
| Where did this value come from | `Ctrl+Shift+W` |
| Analyze whole function | `Ctrl+Shift+A` |
| Timeline | `Ctrl+Shift+T` |
| Go to position | `Ctrl+Shift+G` |
| Bookmark this position | `Ctrl+Shift+B` |

## Settings

Nothing is asked during installation; every setting has a default. Change them
in **TTD > Settings...**, which opens the IDA Settings Editor
(`hcli plugin install ida-settings-editor`), or with
`hcli plugin config ida-ttd set KEY VALUE`. Changes apply from the next stop of
the replay. Settings are read through the `ida-settings` Python package, which
HCLI installs with the plugin; without it (a hand install) the defaults apply.

| Section | Key | Default | |
| --- | --- | --- | --- |
| Replay | `replay_on_open` | `true` | start the replay when a recording's database opens (off: Debugger > Start process) |
| Symbols | `symbol_downloads` | `true` | download system DLLs' PDBs in the background |
| | `symbol_server` | `https://msdl.microsoft.com/download/symbols` | where from |
| Analysis | `auto_coverage` | `true` | measure and color each function the first time the replay stops in it |
| | `auto_callsites` | `false` | comment its indirect calls with where they went, likewise |
| Memory map | `memmap_flag_code` | `true` | color executable regions outside every loaded module |
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

## Building from source

Requires Visual Studio 2022 or later with the C++ desktop workload.

```
git clone --recurse-submodules https://github.com/HullaBrian/ida-ttd
cd ida-ttd
nuget install msbuild\packages.config -OutputDirectory packages
msbuild ida-ttd.slnx -p:Configuration=Release -p:Platform=x64 -m:1
python scripts\package.py
```

Build serially (`-m:1`): parallel compiler instances racing on the shared PDB
can produce a `C1041` error. The output is in `build\Release\` (`ida-ttd.dll`,
`ttd-loader.dll`, `ida-ttd-loader-setup.dll`, and
`backends\ida-ttd-msttd.dll`). Only the Microsoft backend needs the TTD Replay
SDK restored by `nuget`; the plugin and the loader need the IDA SDK alone.
`scripts\package.py` builds `dist\ida-ttd.zip`, the package HCLI installs
(`hcli plugin install dist\ida-ttd.zip`).

The Sogen backend is not in the solution, since it needs a Sogen build:
[docs/building-the-sogen-backend.md](docs/building-the-sogen-backend.md).
`build\Release\ittd-probe.exe` drives any backend DLL outside IDA and checks it
against the interface (`ittd-probe <backend.dll> <trace> [export|0xADDR]`).

### Repository layout

```
src/abi/           the C interface between the plugin and a backend DLL
src/core/          ITraceBackend and positions; the adapters between it and
                   the C interface
src/backend-msttd/ ida-ttd-msttd.dll: Microsoft TTD, the only code that sees
                   the TTD Replay SDK
src/backend-sogen/ ida-ttd-sogen.dll: Sogen, against Sogen's trace reader
src/common/        shared helpers: PE parsing, symbols, string scanning, the
                   API metadata loader
src/debugger/      the IDA debugger session: modules, memory, code layout,
                   registers, calling conventions
src/analysis/      whole-recording analyses, each a backend query run behind a
                   wait box
src/ui/            choosers, action handlers, pseudocode highlighting
src/plugin/        the plugmod_t, events, actions, menus, the toolbar and the
                   ttd("...") script API
src/loader/        ttd-loader.dll, which makes File > Open recognize a recording
src/setup/         ida-ttd-loader-setup.dll, which copies the loader into
                   loaders\ for an HCLI install
src/tools/         ittd-probe, a backend checker that runs outside IDA
scripts/           the Python API, the PySide6 windows, packaging
msbuild/           the project files and the settings they share
```

## Credits

ida-ttd is written and maintained by **HullaBrian**
([GitHub](https://github.com/HullaBrian)). Bug reports and feature requests are
welcome on the [issue tracker](https://github.com/HullaBrian/ida-ttd/issues).

It builds on the work of others:

- [Sogen](https://github.com/momo5502/sogen) by momo5502 and its
  contributors: the Windows emulator, trace format and reader behind
  `.sogttd` recordings, replays and forks. The backend is built from the
  [TTD-Club fork](https://github.com/TTD-Club/sogen).
- Microsoft's Time Travel Debugging and its
  [TTD Replay SDK](https://www.nuget.org/packages/Microsoft.TimeTravelDebugging.Apis),
  which read `.run` recordings.
- [win32metadata](https://github.com/microsoft/win32metadata) (through
  [win32json](https://github.com/marlersoft/win32json)) and
  [phnt](https://github.com/winsiderss/phnt), the sources of the API argument
  decoding, indexed by [ttd-capa-cpp](https://github.com/HullaBrian/ttd-capa-cpp).
- [Unicorn](https://github.com/unicorn-engine/unicorn) and
  [Capstone](https://github.com/capstone-engine/capstone), inside the Sogen
  backend.
- [Codicons](https://github.com/microsoft/vscode-codicons) and
  [Material Symbols](https://github.com/google/material-design-icons), the
  toolbar and menu icons.
- Hex-Rays, for IDA Pro and its SDK.

## License

ida-ttd is dual-licensed: use it under the Apache License 2.0
([LICENSE](LICENSE)) or the GNU GPL version 2
([LICENSES/GPL-2.0-only.txt](LICENSES/GPL-2.0-only.txt)), whichever you
choose (`Apache-2.0 OR GPL-2.0-only`). The GPL option is there so the plugin
can ship together with the Sogen backend.

Exceptions:

- The Sogen backend (`src/backend-sogen/`, and the `ida-ttd-sogen.dll` built
  from it) is GPL-2.0-only, because Sogen and Unicorn are. The package carries
  its license, notices and where its source is in
  `ida-ttd-backends\ida-ttd-sogen-licenses\`; the source itself is
  `ida-ttd-sogen-source.zip` on the same release.
- The API metadata loader (`src/common/apimeta/`, from ttd-capa-cpp) and the
  Material Symbols icons are Apache-2.0; the Codicons are CC BY 4.0.
- The backend ABI header is CC0.

The API metadata in `data/` is derived from win32metadata and phnt, both MIT.
Third-party notices are in [THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt),
which the package carries too. [docs/licensing.md](docs/licensing.md) has the
details.
