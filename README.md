# ida-ttd

An IDA Pro 9.x plugin that registers a debugger backend for navigating Microsoft
**Time Travel Debugging (TTD)** traces (`.run` files). It lets you load a trace
into IDA and step **forwards and backwards**, inspect registers and memory, set
breakpoints (mapped to TTD memory watchpoints), and jump to arbitrary timeline
positions — all from the standard IDA debugger UI.

Built against the official IDA SDK (9.3) and the official Microsoft TTD Replay
SDK (`Microsoft.TimeTravelDebugging.Apis`).

## Features

- Load a `.run` trace as a debugger "process".
- Forward/backward single-step and run (reverse-continue).
- x86 and x64 register views.
- Memory reads served from the recorded trace.
- Breakpoints mapped to TTD execute/read/write memory watchpoints.
- Thread and module debug events synthesized while navigating.
- **TTD timeline** chooser (thread create/exit, module load/unload, exceptions)
  with jump-to-position, plus a **Go to position** (`Sequence:Steps`) action and
  a **Step backwards** action on the Debug toolbar.

## Building

Requirements:

- Visual Studio 2022+ with the C++ desktop workload (toolset v143/v145).
- The IDA SDK 9.3, expected at `References/idasdk93/src` (already in this repo).
- The TTD Replay NuGet package, restored into `packages/` (already present:
  `packages/Microsoft.TimeTravelDebugging.Apis.0.9.5`).

Steps:

1. Open `ida-ttd.slnx` in Visual Studio (or build with MSBuild).
2. If NuGet packages are not restored, run **Restore NuGet Packages** /
   `nuget restore`.
3. Build **Release | x64**. The output is `ida-ttd.dll`.

The project is x64-only because IDA 9.x is a 64-bit application. The TTD SDK
`.props` file (imported by the project) wires up the SDK include path and the
x64 `TTDReplay.lib` import-library path; the project links `ida.lib` and
`TTDReplay.lib`. If you see `unresolved external symbol CreateReplayEngine`,
the `.props` import or `TTDReplay.lib` reference is missing.

## Installation

1. Copy `ida-ttd.dll` into your IDA `plugins\` directory
   (e.g. `C:\Program Files\IDA Professional 9.3\plugins\`).
2. Obtain the Microsoft TTD **runtime** DLLs — `TTDReplay.dll` and
   `TTDReplayCPU.dll`. These are **not** in the NuGet package; get them from a
   WinDbg / WinDbg Preview installation (under `...\amd64\ttd\`) or via the TTD
   `Get-Ttd.ps1` download script. Place both DLLs in the **IDA install root**
   (next to `ida.exe`) — that is the reliable location on the DLL search path.

## Usage

1. Open the IDB for the binary you recorded (or create a fresh one).
2. **Debugger → Switch debugger…** and choose **TTD trace replayer**.
3. Start debugging; when asked for the application, point it at the `.run`
   trace file.
4. Use the standard debugger controls to step. The **Debug toolbar** gains three
   extra buttons:
   - **Step backwards** (`Ctrl+Shift+F7`)
   - **TTD timeline** (`Ctrl+Shift+T`) — double-click an entry to jump there.
   - **Go to position** (`Ctrl+Shift+G`) — enter a `Sequence:Steps` value.

## Notes / limitations

- Memory accuracy requires an index (`.idx`) next to the `.run`. The plugin
  builds one automatically on first load if it is missing (this can take a while
  for large traces).
- If trace loading fails immediately, the TTD runtime DLLs are most likely not
  findable by IDA — see Installation step 2.
