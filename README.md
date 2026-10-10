# ida-ttd

Analyze Microsoft Time Travel Debugging traces inside IDA Pro.

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

Built against the IDA SDK 9.4 and the Microsoft TTD Replay SDK.

## Features

**Navigation**

- Replay a `.run` trace forwards and backwards, including reverse-continue,
  step out backwards, and run to cursor in either direction.
- Timeline view of thread and module events, and jump to an exact
  `Sequence:Steps` position.
- Position bookmarks with names and comments, saved in the database.

**Code discovery**

- Runtime-only code is disassembled a whole function at a time, using the PE
  exception table for module code and the recorded execution for everything
  else. Self-modified regions are re-analyzed when their bytes change.
- Symbols come from each module's export table read out of the trace, so names
  work with no symbol server. PDB symbols load on top when available.
- Execution coverage colors the instructions that actually ran, in both the
  disassembly and the decompiler.
- Indirect calls are resolved to the targets they really reached and written
  back as comments and cross-references.

**Trace-wide queries**

- Find every call to a function, or to a wildcard pattern such as
  `kernel32!Virtual*`, with arguments and return values.
- Find every read, write or execute of an address or range.
- Reconstruct the process memory map: every allocation, protection change and
  free, with each live region exposed as an IDA segment carrying its real
  permissions.

**Opening traces**

- Open a `.run` file directly from `File > Open`. The recorded program's image
  is read out of the trace, so no copy of the original binary is needed.
- Or attach a trace to a database you already have.

## Requirements

- IDA Pro 9.4, Windows x64. The plugin is built against the 9.4 SDK.
- `TTDReplay.dll` and `TTDReplayCPU.dll`. These are not redistributed here.
  Take them from a WinDbg installation (under `...\amd64\ttd\`) or from the
  Microsoft `Get-Ttd.ps1` download script.

## Installation

1. Download `ida-ttd.zip` from the
   [latest release](https://github.com/HullaBrian/ida-ttd/releases) and extract
   `ida-ttd.dll` into your IDA `plugins` directory.
2. Copy `TTDReplay.dll` and `TTDReplayCPU.dll` into the IDA install root, next
   to `ida.exe`.
3. Optional: copy `ttd-loader.dll` into your IDA `loaders` directory. This is
   what makes `File > Open` recognize a `.run` file. Everything else works
   without it.

## Usage

### Open a trace directly

`File > Open` the `.run` file and choose **Microsoft TTD trace (.run)**. IDA
builds a database from the recording and offers to start replaying it.

If the trace has no index yet, you are asked whether to build one. Building can
take several minutes. Declining still gives you a database with the right
addresses, names and permissions, and the index is built when you start the
replay instead.

### Attach a trace to an existing database

1. Open the IDB for the recorded binary.
2. `Debugger > Switch debugger` and choose **TTD trace replayer**.
3. Start debugging and give the `.run` file as the application.

### Move through the recording

Use the normal debugger controls to step forward. The TTD toolbar adds the
backward equivalents, a live position readout, and the query actions. Everything
is also on the top-level **TTD** menu.

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

Run **TTD > Memory map**. The plugin replays the recording once and lists every
allocation, protection change and free, with the code that requested it. Regions
live at the current position become named IDA segments with their real
permissions, so an RWX buffer is visible as one. The map is saved in the
database.

### Default shortcuts

| Action | Shortcut |
| --- | --- |
| Find all calls to this function | `Ctrl+Shift+C` |
| Find calls by name/pattern | `Ctrl+Shift+F` |
| Find memory accesses | `Ctrl+Shift+M` |
| Analyze whole function | `Ctrl+Shift+A` |
| Timeline | `Ctrl+Shift+T` |
| Go to position | `Ctrl+Shift+G` |
| Bookmark this position | `Ctrl+Shift+B` |

Stepping keeps IDA's usual shortcuts (`F7`, `F8`, `Ctrl+F7`, `F4`) and their
backward variants. Continue backwards and step out backwards are on the TTD
toolbar and menu.

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
can produce a `C1041` error. Output is `build\Release\ida-ttd.dll` and
`build\Release\ttd-loader.dll`.

## Repository layout

```
src/common/     opening a recording, the .run link record, PE and symbol
                reading -- the part the plugin and the loader both use
src/debugger/   the IDA debugger backend: engine and cursor ownership, trace
                navigation, registers, calling conventions
src/analysis/   whole-trace passes -- call tracing, coverage, memory search,
                memory map, indirect calls, bookmarks -- and the shared replay
                sweep driver they all run on
src/ui/         choosers, action handlers, pseudocode highlighting
src/plugin/     the plugmod_t, the event listeners, the actions and the toolbar
src/loader/     ttd-loader.dll, which makes File > Open recognise a .run
msbuild/        the two project files and the settings they share
```

`src/` is the single include root, so every local include names its folder
(`#include "debugger/trace_manager.h"`) and a header's home is visible wherever
it is used.

## License

Apache 2.0. See [LICENSE](LICENSE).
