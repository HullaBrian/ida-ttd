# ida-ttd

An IDA Pro 9.x plugin that registers a debugger backend for navigating Microsoft
**Time Travel Debugging (TTD)** traces (`.run` files). Load a trace into IDA and
step **forwards and backwards**, inspect registers and memory, set breakpoints
(mapped to TTD memory watchpoints), jump to arbitrary timeline positions, resolve
symbols offline, and run trace-wide queries — all from the standard IDA debugger
UI.

Built against the official IDA SDK (9.3) and the official Microsoft TTD Replay
SDK (`Microsoft.TimeTravelDebugging.Apis`).

---

## Features

### Navigation
- Load a `.run` trace as a debugger "process" and replay it.
- Native IDA debug-movement buttons, re-skinned with Microsoft **codicon** icons
  and grouped forward / backward:
  - Continue, Step into, Step over, Run until return, Run to cursor
  - Continue **backwards**, Step into backwards, Step over backwards,
    Run to cursor backwards
- **Backward** stepping and reverse-continue (TTD's headline capability).
- x86 and x64 register views; memory served from the recorded trace.
- Breakpoints mapped to TTD execute/read/write memory watchpoints.
- Thread and module debug events synthesized while navigating.

### Timeline & positions
- **TTD timeline** chooser (thread create/exit, module load/unload, exceptions);
  double-click an entry to jump there.
- **Go to position** — enter a `Sequence:Steps` value to time-travel.
- **Live position readout** on the TTD toolbar (`TTD <Seq>:<Steps>`); **click it
  to copy the current position to the clipboard**.

### Symbols (offline-first)
- Export names are resolved by parsing each module's **PE export table directly
  out of the trace's guest memory** — no symbol server required. IDA's PDB
  symbols still apply on top when available.
- Runs automatically: on module load **and** on every stop (so modules you
  time-travel into, which loaded late, get named too).

### Disassembly of runtime-only code
- Code that only exists at runtime (system DLLs not in the IDB, JIT/unpacked
  regions) is disassembled on each stop. The current instruction and the block
  below it are laid out from the exact RIP boundary (cheap, no popups).
- **Analyze whole function** (on demand): walks the trace backward to find the
  enclosing function's entry and defines the whole function (see *Notes*).

### Trace-wide call queries
- **Find all calls to this function** (one click, right-click a function): sweeps
  the entire recording and lists every call with its arguments and return value.
- **Find calls by name/pattern**: trace every function matching a wildcard such
  as `kernel32!Virtual*` or `*Alloc` in a single sweep.
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

---

## Usage

1. Open the IDB for the binary you recorded (or create a fresh one).
2. **Debugger → Switch debugger…** and choose **TTD trace replayer**.
3. Start debugging; when asked for the application, point it at the `.run` trace
   file.
4. A **TTD toolbar** appears for the duration of the session with the movement
   buttons, the position readout, and the query actions. A top-level **TTD**
   menu mirrors them.

### Default shortcuts
| Action | Shortcut |
| --- | --- |
| Continue backwards | (toolbar / menu) |
| Find all calls to this function | `Ctrl+Shift+C` |
| Find calls by name/pattern | `Ctrl+Shift+F` |
| Analyze whole function | `Ctrl+Shift+A` |
| TTD timeline | `Ctrl+Shift+T` |
| Go to position | `Ctrl+Shift+G` |

(Native step actions keep their usual IDA shortcuts: `F7`, `F8`, `Ctrl+F7`, `F4`,
and the backward variants.)

---

## Architecture (source map)

`ida-ttd/`
- `plugin.{h,cpp}` — the plugmod_t; hooks `HT_IDD` (debugger events), `HT_DBG`
  (symbol resolution + per-stop analysis + position readout), `HT_UI`
  (disassembly popup). Registers actions, builds/tears down the TTD toolbar.
- `trace_manager.{h,cpp}` — owns the TTD replay engine + cursor; translates IDA
  debugger events into trace navigation; symbol resolution; per-stop disassembly;
  the deep "analyze whole function" walk.
- `registers.{h,cpp}` — register class definitions + context↔regval marshalling;
  advertises `DBG_RESMOD_*` so IDA drives the native movement buttons.
- `symbols.{h,cpp}` — PE export-table parsing out of guest memory.
- `callconv.{h,cpp}` — calling-convention argument/return extraction (x86/x64).
- `tracer.{h,cpp}` — the call-sweep engine (`FunctionTracer`) and its events.
- `ui.{h,cpp}` — choosers (Timeline, Traced functions, Tracing events) and all
  action handlers.
- `event_queue.{h,cpp}` — synthesizes IDA `debug_event_t`s as we navigate.
- `icons.hh` — embedded codicon SVG glyphs.

---

## Notes for future analysis sessions

**How symbol naming works (and its limits).** Names come from two sources that
stack: (1) our offline PE-export parser, which names exported functions at their
runtime VAs from the trace's own memory — works with no network/symbol server;
(2) IDA's PDB symbols on top, which add internal/non-exported names when a symbol
server is reachable. If a call shows `call loc_…`/`sub_…` instead of a name, the
target is either **not an export** (only PDBs would name it) or its module isn't
loaded at the current position. Resolution re-runs on every stop, so simply
stepping to a point where the module is mapped will name it.

**Disassembling runtime-only code.** On each stop the plugin lays out the
instruction at RIP and the block below it. It deliberately does **not** lay out
the lines *above* RIP or auto-define the enclosing function — that requires
walking the trace, which is expensive (see below). Lines above the current
instruction get disassembled as you step onto them. To get the *whole* enclosing
function defined and named, use **Analyze whole function** (`Ctrl+Shift+A`,
toolbar, or right-click). It walks the current thread backward to the call that
entered the frame and defines everything; cancel the wait box if a giant function
takes too long.

**Performance gotcha — backward replay is not free.** A single backward step is
cheap, but in TTD each `ReplayBackward(1)` re-seeks toward a keyframe, so doing it
hundreds/thousands of times in a loop is `O(n × keyframe-distance)` and will
freeze the UI for tens of seconds. Therefore: **per-stop work must stay
replay-free**, and anything that walks the trace (like *Analyze whole function*)
must be **explicit, one-shot, and behind a cancellable wait box** — never
automatic per stop. Do not "improve" the per-stop handler by adding a backward
walk; that regression has bitten this project before.

**Self-modifying code.** The disassembly/analysis classifies call/ret by reading
*current* memory at historical PCs, which assumes code bytes don't change over
time. True for ordinary system DLLs; SMC/packed regions may mis-classify.

**Stale instructions in an older IDB.** Earlier builds used a byte-guessing
heuristic that could leave mis-aligned instructions in the database. The current
code clears any overlapping item before defining an instruction at a real
boundary, so garbage self-heals as you revisit it — but if an IDB looks messy,
analyzing a trace into a **fresh IDB** starts clean.

**Index files.** Memory accuracy requires an index (`.idx`) next to the `.run`.
The plugin builds one automatically on first load if missing (can take a while
for large traces). If trace loading fails immediately, the TTD runtime DLLs are
most likely not findable by IDA — see *Installation* step 2.

**Call-sweep matching.** The call tracer matches the *runtime* callee VA. Because
a user usually clicks an **import thunk** or **import data slot**, target
resolution follows thunks (`calc_thunk_func_target`) and reads the **live IAT
pointer**. Pattern matching (`module!glob`) matches against IDB symbol names, so
the relevant module's exports must already be named (they will be, once loaded).
