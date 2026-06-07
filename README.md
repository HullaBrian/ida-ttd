# ida-ttd

An IDA Pro 9.x plugin that registers a debugger backend for navigating Microsoft
**Time Travel Debugging (TTD)** traces (`.run` files). Load a trace into IDA and
step **forwards and backwards**, inspect registers and memory, set breakpoints
(mapped to TTD memory watchpoints), jump to arbitrary timeline positions, get
functions disassembled and named automatically (including runtime-only shellcode),
and run trace-wide queries — all from the standard IDA debugger UI.

Built against the official IDA SDK (9.3) and the official Microsoft TTD Replay
SDK (`Microsoft.TimeTravelDebugging.Apis`).

---

## Features

### Navigation
- Load a `.run` trace as a debugger "process" and replay it forwards **and
  backwards** (reverse-continue is TTD's headline capability).
- A dedicated **TTD toolbar** with Microsoft **codicon** icons, grouped
  forward / backward:
  - **Forward:** Continue, Step into, Step over, Run until return, Run to cursor
  - **Backward:** Continue backwards, Step into backwards, Step over backwards,
    Step out backwards, Run to cursor backwards
  - IDA has no native "continue backwards" / "step out backwards", so those two
    are provided by the plugin.
- x86 and x64 register views; memory served from the recorded trace.
- Breakpoints mapped to TTD execute/read/write memory watchpoints.
- Thread and module debug events synthesized while navigating.

### Timeline & positions
- **TTD timeline** chooser (thread create/exit, module load/unload, exceptions);
  double-click an entry to jump there.
- **Go to position** — enter a `Sequence:Steps` value to time-travel.
- **Live position readout** on the toolbar (`TTD <Seq>:<Steps>`); **click it to
  copy the current position to the clipboard**.

### Symbols
Two complementary sources stack on top of each other, both applied automatically:

- **Offline export names.** Each module's PE export table is parsed directly out
  of the trace (read at the module's recorded load position), naming every export
  at its runtime VA — works with **no symbol server / no network**.
- **PDB symbols (silent).** The plugin drives IDA's PDB plugin per module to load
  internal/non-exported names, **without the per-module "load symbols?" prompt**.
  When offline or the PDB can't be found, it logs a one-line note to the Output
  window instead of popping a dialog for every module.

Both run on module load and again on every stop, so modules you *time-travel into*
(loaded later in the trace) also get named. The call-stack view refreshes as
symbols arrive.

### Automatic disassembly of runtime-only code
When you jump or step to code that isn't in the static database — system DLLs,
JIT, **unpacked / shellcode regions** — the plugin lays out the **whole enclosing
function** automatically (the way WinDbg/Binary Ninja do), not one instruction at
a time. It uses the cheapest correct source available:

- **Modules:** the x64 PE exception table (`.pdata` / `RUNTIME_FUNCTION`) gives
  exact `[start, end)` bounds for every function — recovered from the on-disk PE,
  so it works without symbols. The whole function is disassembled at once.
- **Dynamic code (no module, no `.pdata`):** the plugin finds a real instruction
  boundary at/above the PC from the execution trace (cheap *forward* replay) and
  runs IDA's recursive-descent analysis from there, so branches and the code
  *above* the PC are laid out too — important for stepping backward.
- **Self-modifying / reused regions:** if the bytes at a previously-disassembled
  location have changed (unpacking, or time-travel to a position where the same
  address holds different code), that function is re-disassembled.

For the rare case where automatic analysis can't reach a function, **Analyze whole
function** (`Ctrl+Shift+A`, also on the TTD menu / right-click) does a deeper,
trace-walking analysis behind a cancellable progress box.

### Memory accuracy
Memory is reconstructed with TTD's **global** query policy, so reads return the
correct value from the most recent write *anywhere* in the trace (matching what
WinDbg / Binary Ninja show) rather than only memory the current thread touched
near the current position. Time-travel jumps invalidate IDA's memory cache so the
views show the bytes at the new position, not the previous one.

### Trace-wide call queries
- **Find all calls to this function** (one click, right-click a function): sweeps
  the entire recording and lists every call with its arguments and return value.
- **Find calls by name/pattern** (`Ctrl+Shift+F`): trace every function matching a
  wildcard such as `kernel32!Virtual*` or `*Alloc` in a single sweep.
- Results open in a **Tracing events** chooser:
  - Columns: **Start**, **End** (call/return positions), **Thread**,
    **Function**, the **arguments**, and **Return**.
  - With a single matched function, arguments are split into one column **per
    parameter** (named from the signature). With several functions, arguments are
    condensed into one labeled column.
  - Double-click a row to time-travel to that call.
  - Multiple events tabs can be open at once (each is an independent snapshot).

---

## Building

Requirements:

- Visual Studio 2022+ with the C++ desktop workload (toolset v143/v145).
- The IDA SDK 9.3, expected at `References/idasdk93/src` (already in this repo).
- The TTD Replay NuGet package, restored into `packages/` (already present:
  `packages/Microsoft.TimeTravelDebugging.Apis.0.9.5`).

Steps:

1. Open `ida-ttd.slnx` in Visual Studio, **or** build with MSBuild:
   ```
   msbuild ida-ttd\ida-ttd.vcxproj /p:Configuration=Release /p:Platform=x64 /t:Build /m:1
   ```
   Build **serial** (`/m:1`): parallel `cl` instances racing on the shared PDB can
   produce a `C1041` error.
2. If NuGet packages are not restored, run **Restore NuGet Packages** /
   `nuget restore`.
3. Output is `ida-ttd\x64\Release\ida-ttd.dll`.

The project is x64-only because IDA 9.x is a 64-bit application. The TTD SDK
`.props` file (imported by the project) wires up the SDK include path and the
x64 `TTDReplay.lib` import-library path; the project links `ida.lib` and
`TTDReplay.lib`. If you see `unresolved external symbol CreateReplayEngine`, the
`.props` import or `TTDReplay.lib` reference is missing.

---

## Installation

1. Copy `ida-ttd.dll` into your IDA `plugins\` directory
   (e.g. `C:\Program Files\IDA Professional 9.3\plugins\`).
2. Obtain the Microsoft TTD **runtime** DLLs — `TTDReplay.dll` and
   `TTDReplayCPU.dll`. These are **not** in the NuGet package; get them from a
   WinDbg / WinDbg Preview installation (under `...\amd64\ttd\`) or via the TTD
   `Get-Ttd.ps1` download script. Place both DLLs in the **IDA install root**
   (next to `ida.exe`) — the reliable location on the DLL search path.
3. (Optional, for internal PDB symbols) configure IDA's symbol path / symbol
   server the same way you would for WinDbg. Without it, offline export names
   still apply.

---

## Usage

1. Open the IDB for the binary you recorded (or create a fresh one — a fresh IDB
   avoids any stale state and is recommended for malware).
2. **Debugger → Switch debugger…** and choose **TTD trace replayer**.
3. Start debugging; when asked for the application, point it at the `.run` trace
   file.
4. The **TTD toolbar** holds the movement buttons, the position readout, and the
   query actions. A top-level **TTD** menu mirrors them.

### Default shortcuts
| Action | Shortcut |
| --- | --- |
| Find all calls to this function | `Ctrl+Shift+C` |
| Find calls by name/pattern | `Ctrl+Shift+F` |
| Analyze whole function | `Ctrl+Shift+A` |
| TTD timeline | `Ctrl+Shift+T` |
| Go to position | `Ctrl+Shift+G` |

Continue backwards and Step out backwards are on the toolbar / TTD menu. Native
step actions keep their usual IDA shortcuts (`F7`, `F8`, `Ctrl+F7`, `F4`, and the
backward variants).

---

## Architecture (source map)

`ida-ttd/`
- `plugin.{h,cpp}` — the plugmod_t; hooks `HT_IDD` (debugger events), `HT_DBG`
  (symbol/PDB resolution, per-stop disassembly, toolbar rebuild, call-stack
  refresh), `HT_UI` (disassembly popup), `HT_IDB` (refresh call stack when names
  change). Registers actions, builds the TTD toolbar, manages the codicon icons.
- `trace_manager.{h,cpp}` — owns the TTD replay engine + cursor; translates IDA
  debugger events into trace navigation; the on-stop disassembly engine
  (`.pdata` whole-function, dynamic-code recursive descent, SMC re-analysis);
  symbol/PDB resolution; the deep "analyze whole function" walk.
- `registers.{h,cpp}` — register class definitions + context↔regval marshalling;
  advertises `DBG_RESMOD_*` so IDA drives the native movement buttons.
- `symbols.{h,cpp}` — PE export-table parsing (names) and `.pdata` exception-table
  parsing (function bounds), from guest memory and the on-disk PE.
- `callconv.{h,cpp}` — calling-convention argument/return extraction (x86/x64).
- `tracer.{h,cpp}` — the call-sweep engine (`FunctionTracer`) and its events.
- `ui.{h,cpp}` — choosers (Timeline, Traced functions, Tracing events) and all
  action handlers.
- `event_queue.{h,cpp}` — synthesizes IDA `debug_event_t`s as we navigate.
- `icons.hh` — embedded codicon SVG glyphs.

---

## Notes for future analysis sessions

**Symbol naming.** Names stack: offline PE-export names (always, no network) +
PDB names (loaded silently, needs IDA's symbol path/server). If a call shows
`sub_…`/`loc_…`, the target is either not an export (only a PDB would name it) and
no PDB was available, or its module wasn't loaded at the current position.
Resolution re-runs on every stop, so stepping to where the module is mapped names
it. Offline PDB failures are logged to the Output window, not shown as dialogs.

**On-stop disassembly.** The per-stop path defines the whole enclosing function
(`.pdata` bounds for modules; trace-seeded recursive descent for dynamic code) and
is cached per function, so revisiting it is free. It must stay **replay-light** —
the dynamic-code path uses *forward* replay only (cheap). The deep **Analyze whole
function** action is the one place that walks the trace **backward**, behind a
cancellable wait box.

**Performance — backward replay is expensive.** A single backward step is cheap,
but in TTD each `ReplayBackward(1)` re-seeks toward a keyframe, so doing it
hundreds/thousands of times in a loop is `O(n × keyframe-distance)` and freezes the
UI. Never add a backward walk to the per-stop handler; that regression has bitten
this project before.

**Analysis cascade.** `add_func()` on a function full of `call`s would, with IDA's
`AF_PROC` flag, recursively create and fully analyze every callee across whole
modules — making navigation crawl. The plugin clears `AF_PROC`/`AF_PROCPTR` for the
session (restored on exit) and defines only the function you're looking at. Don't
re-enable per-callee auto-analysis during a session.

**Memory reconstruction.** TTD records memory *accesses*, not snapshots, so a
byte's value at a position is the last recorded write before it; never-accessed
bytes are reconstructed. The plugin uses the **GloballyAggressive** policy to fill
in as much as possible (like WinDbg). A genuinely-zero region usually means you
time-traveled to *before* it was written — step forward past the write to see it.

**Index files.** Memory accuracy needs an index (`.idx`) next to the `.run`. The
plugin builds one on first load if missing (can take a while for large traces). If
loading fails immediately, the TTD runtime DLLs aren't findable by IDA — see
*Installation* step 2.

**Debugger desktop / toolbar.** IDA uses a separate "debugger desktop" once a
session starts; the TTD toolbar is (re)built when the session's process starts so
it lands in that desktop. If the toolbar ever looks broken after an aborted
session, reset the desktop (**Windows → Reset desktop**) and reselect the TTD
debugger.

**Call-sweep matching.** The tracer matches the *runtime* callee VA. Because a user
usually clicks an **import thunk** or **import data slot**, target resolution
follows thunks (`calc_thunk_func_target`) and reads the **live IAT pointer**.
Pattern matching (`module!glob`) matches against IDB symbol names, so the relevant
module's exports must already be named (they will be, once loaded).
