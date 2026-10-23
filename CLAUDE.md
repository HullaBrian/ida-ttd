# ida-ttd

An IDA Pro 9.4 plugin (C++, Windows x64) that turns a time-travel recording into
an IDA debugger session: step forwards and backwards, jump to any position, and
run whole-recording queries (calls, coverage, memory accesses, syscalls, memory
map, self-modifying code, strings, buffers, forks). Two kinds of recording:

- **Microsoft TTD** (`.run`), read through the TTD Replay SDK
  (NuGet `Microsoft.TimeTravelDebugging.Apis`, version pinned in
  `msbuild/Directory.Build.props`).
- **Sogen** (`.sogttd`), read through Sogen's trace reader
  (github.com/momo5502/sogen, `src/windows-ttd`). Sogen can also *replay* a
  recording in its emulator, which is what forking uses.

README.md is the user-facing description (features, usage, build, layout).
`docs/` holds design notes; `docs/scripting.md` and `docs/licensing.md`
(what each binary contains and the terms it ships under) are current, while
`session-handoff.md`, `modular-backends.md` and `code-review.md` are historical
and may be out of date.

**Local setup** (where things live on this machine and on the test machine,
reference material, test recordings) is in `CLAUDE.local.md`, which is
git-ignored. Read it if it exists; keep machine-specific paths out of this file.

## Architecture

```
IDA  <->  plugin (ida-ttd.dll)  <->  ITraceBackend  <->  backend DLL (C ABI)
                                      core/backend.h       src/abi/ida_ttd_backend.h
```

- **`src/abi/ida_ttd_backend.h`**: the versioned C interface every backend DLL
  exports (`ittd_*` types, count-then-fill queries, `ITTD_CAP_*` capability
  bits). Backends are found in `$IDAUSR\ida-ttd\backends\` (user-installed),
  then `plugins\ida-ttd-backends\` and `plugins\ida-ttd\ida-ttd-backends\`
  (`load_backend_modules`).
- **`src/core/`**: `ITraceBackend` / `ITraceCursor` (`backend.h`), the
  backend-neutral `Position` (`position.h`; shown as `HI:LO` hex), `BackendModule`
  (adapts a DLL to `ITraceBackend`) and `abi_export` (the reverse: wraps a C++
  `ITraceBackend` as the C ABI, used by the MS backend).
- **`src/backend-msttd/`**: the only code that sees the TTD Replay SDK. It does
  not link `ida.lib` (`msttd_ida_shim.cpp` supplies the few kernel functions
  `qstring` needs), so `ittd-probe` can run it outside IDA. Whole-recording
  queries are replays with engine callbacks/watchpoints (`msttd_sweep`).
  Syscalls come from `KernelCall` gaps (`msttd_syscalls`); the memory map is built
  from those syscalls (`msttd_memmap`); strings, buffers and self-modifying code
  come from two write-watchpoint replays (`msttd_scans`).
- **`src/backend-sogen/sogen_backend.cpp`**: one file, implements the C ABI
  directly against Sogen's reader. Not in the solution (see Building).
- **`src/common/`**: shared helpers. `write_scans.h` is header-only and
  standard-library-only on purpose: the string and buffer scanners, shared by
  both backends (the Sogen backend builds without the rest of the plugin).
  They implement `docs/scan-rules.md`, Sogen's rules written down as
  behaviour, and were written from that document, not ported: Sogen is
  GPL-2.0 and the Microsoft backend that compiles them ships under
  Apache-2.0. Never copy code from Sogen into anything outside
  `src/backend-sogen/`; change a rule in the document, then the code.
  `write_scans.h` is Apache-2.0 OR GPL-2.0-only and `sogen_backend.cpp`
  GPL-2.0-only (SPDX headers); everything else stays Apache-2.0, so code
  shared with the Sogen backend must not pull in more of the plugin.
- **`src/common/apimeta/`** + **`data/*.bin`**: the Win32/phnt API metadata
  indexes and their loader, ported from ttd-capa-cpp (same author, Apache-2.0;
  keep them close to the original). `debugger/apidecode` decodes a call's
  arguments from them; the build copies `data/` to `ida-ttd-data/` beside the
  plugin, which is where the plugin looks.
- **`src/debugger/`**: the IDA debugger over one backend. `TraceManager` owns
  the session (cursor, pending movement requests, event queue to IDA);
  `ModuleRegistry` (modules, exports, PDBs, function bounds), `MemoryReader`
  (recording first, then the on-disk image, then placeholder zeros),
  `SegmentLayout` (what `ev_get_memory_info` reports).
- **`src/analysis/`**: whole-recording analyses, each a backend query run behind
  a cancellable wait box (`query_runner`), writing results to the database
  where relevant (netnode stores; `trace_store` stamps which recording they came
  from).
- **`src/ui/`**: choosers (one per listing), action handlers (`ui.h` declares
  them and the `actions::` ids), pseudocode painting (`decompiler.cpp`), SVG
  icons (`icons.hh`, Material Symbols / codicons). The call tree is a PySide6
  widget run through IDAPython (`calltree_py.hh`).
- **`src/plugin/`**: the `plugmod_t`. `plugin.cpp` holds the action table
  (`build_action_table`: label, handler, shortcut, tooltip, icon, menu group,
  submenu: adding a command is a handler + one row), menu/submenu/toolbar
  construction, context-menu attachment (`ui_finish_populating_widget_popup`),
  and the after-stop work (`do_after_stop`, run from a timer after IDA's own
  stop handling). `script_api.cpp` is the `ttd("cmd args")` IDC function.
- **`scripts/ida_ttd.py`**: the Python API (`Session`, `Recording`, `call`).
  The build copies it to `ida-ttd-python/` beside the plugin, and the plugin
  puts that folder on IDAPython's `sys.path` when it loads.
- **`scripts/ida_ttd_runtime.py`**: TTD > Backends > Install the TTD runtime
  (WinDbg), and Install the Sogen backend (from a file the user picks, into
  `$IDAUSR\ida-ttd\backends\`). The TTD menu is rebuilt whole
  (`Plugin::rebuild_ttd_menu`) whenever its contents change: session items,
  then the replay-start items, then Backends, which every database has. Copies `amd64\ttd` out of an installed WinDbg, or shows WinDbg's
  license and downloads its x64 package from Microsoft (HTTP range reads of
  the bundle), into `$IDAUSR\ida-ttd\windbg\`, where the MS
  backend looks. Copied beside `ida_ttd.py`. Everything below
  `install_runtime()` runs without IDA, for testing.
- **`src/loader/`**: `ttd-loader.dll`, so File > Open accepts a recording.
- **`src/setup/`**: `ida-ttd-loader-setup.dll`, a `PLUGIN_FIX` component of the
  HCLI package that copies the bundled `ttd-loader.dll` into
  `$IDAUSR\loaders\` as IDA starts (HCLI installs only into
  `plugins\ida-ttd\`, and IDA finds loaders only in `loaders\`). It stays
  loaded in the GUI to show TTD > Backends while no database is open (the
  main plugin, and its menu, load only with a database).
- **`scripts/package.py`**: builds `dist\ida-ttd.zip`, the HCLI package (an
  `ida-ttd/` suite folder, with the setup component and its generated
  `ida-plugin.json`). The release workflow runs it, then `hcli plugin lint`.
- **`src/tools/ittd_probe.c`**: drives any backend DLL through the ABI outside
  IDA and checks its promises.

`src/` is the include root: includes always name the folder
(`#include "debugger/trace_manager.h"`).

## Building

Visual Studio 2022+ with the C++ desktop workload; the TTD Replay SDK is
restored with `nuget install msbuild\packages.config -OutputDirectory packages`.

```
msbuild msbuild\ida-ttd.vcxproj      -p:Configuration=Release -p:Platform=x64
msbuild msbuild\backend-msttd.vcxproj -p:Configuration=Release -p:Platform=x64
msbuild msbuild\ittd-probe.vcxproj   -p:Configuration=Release -p:Platform=x64
msbuild msbuild\ttd-loader.vcxproj   -p:Configuration=Release -p:Platform=x64
msbuild msbuild\ida-ttd-loader-setup.vcxproj -p:Configuration=Release -p:Platform=x64
python scripts\package.py
```

Output goes to `build\Release\` (backends in `build\Release\backends\`). New
source files: add them to the `.vcxproj` (CRLF files), then run
`python msbuild/gen_filters.py`.

The **Sogen backend** needs a Sogen source tree and a CMake build of it
(`docs/building-the-sogen-backend.md`). Build it with `-t:Rebuild`: MSBuild does
not relink when Sogen's libraries change. Don't build in a Sogen checkout someone
is working in: use a snapshot (`git archive` + a CMake configure with
`-DFETCHCONTENT_FULLY_DISCONNECTED=ON`) and pass
`-p:SogenRoot=<snapshot> -p:SogenBuild=<build>`.

## Testing

1. **Backend changes: `ittd-probe`, locally, no IDA.**
   `build\Release\ittd-probe.exe build\Release\backends\ida-ttd-msttd.dll <trace.run>`
   (or `ida-ttd-sogen.dll` with a `.sogttd`). The probe ends with
   "N check(s) failed".
   Environment switches: `ITTD_PROBE_FORK_REGISTRY=<hives dir>` enables the scan
   and fork sections; `ITTD_PROBE_SCAN_DUMP=<prefix>` writes every recovered
   string/buffer to TSV for diffing before/after a change;
   `ITTD_PROBE_MAP_DUMP=1` dumps the memory map; `ITTD_PROBE_FIND=<text>` searches
   recovered strings.
2. **Plugin/UI changes: in IDA through the `ida` MCP**, which may run on a
   different machine than the source. The user installs builds by hand:
   tell them which DLLs changed with their sha256, then verify the installed
   hashes from inside IDA before testing. Drive the plugin with
   `idc.eval_idc('ttd("cmd")')` (JSON back; `ttd("help")` lists commands);
   `scripts/selftest.py` is the end-to-end suite. Release the MCP lease
   (`close_database`) when done, or the DLLs stay locked.

There is no unit-test suite; correctness is checked against known recordings
(e.g. the sample program stores 0x2222222222222222 over 0x1111111111111111) and
by comparing MS and Sogen recordings of the same program.

## Pitfalls

- **HCLI replaces `plugins\ida-ttd\` on every upgrade.** Nothing the user adds
  (the TTD runtime DLLs, a Sogen backend, its `registry\` folder) may be
  expected to live there. They go in `$IDAUSR\ida-ttd\` (`windbg\`,
  `backends\`, `registry\`; `user_data_dir()` in `core/backend_module.h`),
  outside `plugins\` since none of them is a plugin. The old
  `plugins\ida-ttd-backends\` is still searched.
  `hcli plugin lint` exits 0 even on errors; read its output.
- **Never ship or fetch Microsoft's TTD runtime any other way.** Its terms
  forbid redistribution, and the standalone TTD package's terms forbid
  commercial use; WinDbg's do not. So it comes from WinDbg only, on the
  user's machine, after they accept WinDbg's license. A DLL in an installed
  package's folder (`WindowsApps`) cannot be loaded from IDA (access denied),
  only read, so it is copied out.
- **Never poll IDA's windows from a thread inside the IDA process** (e.g. an
  `EnumWindows` loop on a Python thread): it deadlocked the user's IDA.
- **Never call `ida_dbg.set_debugger_options(0)`** to read the options: it
  replaces them, and there is no getter.
- Debugger segments (the system DLLs of an MS recording) and anything painted on
  them vanish when the session ends; database-backed state must not assume they
  persist.
- IDA moves its views to the instruction pointer after a stop, so anything that
  positions a view after a travel must run from `do_after_stop`, not inline.
- Wait boxes only appear after a grace period while the UI pumps; long
  synchronous work (e.g. loading a PDB) looks like a hang instead.
- Shell edits: don't pass code containing backslashes (`\n` in C strings,
  Windows paths) through bash heredocs; they get mangled. Use the Edit/Write
  tools or a script file.

## Conventions

- **Code style**: IDA SDK style: 4-space indent, `if ( x )` with inner spaces,
  braces on their own lines, `m_` members, `qstring`/`qvector` in plugin code
  and `std::` in backends. Comments explain *why* in full sentences, and are
  dense; match the surrounding file.
- **User-facing text** (menus, tooltips, messages, README) is plain and
  specific; the README is kept in step with features.
- **Git**: work directly on `main` (the user prefers few branches). Commit with a
  short imperative subject and a prose body explaining the change. The user
  pushes (`git push origin main`); don't push. `TODO.txt` (the user's
  feature/bug list with a dated Done section) stays untracked; update it when
  finishing an item.
