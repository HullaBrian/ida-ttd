# Making ida-ttd work against more than one kind of recording

The plugin is written against the Microsoft TTD Replay SDK throughout. The goal
is a core plugin that knows how to be an IDA debugger over *a* recording, and
one module per kind of recording behind an interface: a Microsoft TTD backend
and a backend for [Sogen](https://github.com/momo5502/sogen)'s own
time-travel traces (`.sogttd`, `src/windows-ttd` in that repo).

This document is the plan. The interface it describes is already in
`src/core/backend.h` and `src/core/position.h` on this branch (see
[What is landed](#what-is-landed-on-this-branch) at the end); nothing is wired
to it yet.

## 1. Where the coupling actually is

Measured on this branch, 13,000 lines over 57 files. 31 of those files mention
no TTD type at all; the coupling is concentrated:

| File | TTD references | Lines |
| --- | --- | --- |
| `debugger/trace_manager.cpp` | 92 | 3,179 |
| `debugger/trace_manager.h` | 35 | 464 |
| `analysis/memmap.cpp` | 30 | 1,354 |
| `common/symbols.cpp` | 20 | 642 |
| `analysis/memsearch.cpp` | 14 | 167 |
| `loader/ldr_main.cpp` | 13 | 524 |
| `debugger/callconv.cpp` | 13 | 223 |
| `analysis/tracer.cpp` | 11 | 465 |
| `analysis/coverage.cpp` | 11 | 364 |
| `analysis/callsites.cpp` | 5 | 284 |

Separately, `TTD::Replay::Position` is used as a value in 95 places — 44 of them
inside `trace_manager.cpp`, the rest one to three per file, in the listings,
the bookmark store and the memory map. It is stored in the database by
`bookmarks.cpp` and `memmap.cpp`. **Abstracting the position is the single
change that touches the most files**, and nothing else can start until it is
done.

So the work is not evenly spread. `trace_manager.cpp` is most of it, and it is
also the file the existing code review (`docs/code-review.md` §3.3) already
wants split into eight responsibilities. Those two jobs are the same job, which
is why §3.3, §3.4 and §3.8 of that review were deliberately left open on the
cleanup branch: the shape `ReplaySession` and `Navigator` should take is decided
by what a second backend needs from them.

## 2. The two backends are not alike, and that decides the interface

This is the central design point. Microsoft TTD and Sogen answer the same
questions by opposite means.

Microsoft TTD is a **replay engine**. "Every write to this buffer" means: arm a
memory watchpoint, replay the recording forward, collect callbacks. That is why
`analysis/` is built out of five whole-trace sweeps on a worker thread behind a
cancellable wait box.

Sogen's trace is an **index**. Every access the run made is in the file with its
value, and the page index says which chunks can contain a given address. The
same question is `trace::accesses(address, size, first, last, kind_mask)` — a
read, not a replay. Conversely, *landing* the debugger on a position is
expensive for Sogen (restore a checkpoint, re-execute up to 500,000
instructions) and cheap for Microsoft.

Sogen's own measurements (`docs/ttd-poc.md` in that repo, 2026-10-08, on a
30M-instruction trace against Microsoft's 6.9M-instruction trace of the same
program — so Sogen's queries cover 4× the events):

| | Microsoft | Sogen cold | Sogen prepared |
| --- | --- | --- | --- |
| All accesses to `.data` | 89 ms | 72 ms | 77 ms |
| Execute watchpoint, backward | 568–614 ms | 164 ms | 124 ms |
| Read/write watchpoint, backward | 71–615 ms | 5–193 ms | 2–193 ms |
| All executions of `RtlAllocateHeap` | 100 ms | 383 ms | 303 ms |
| Seek to a random position | 34–40 ms | 215 ms | 36 ms |
| Registers at a position | 34–40 ms | 6–8 ms | — |
| Value of a qword at a position | 31–39 ms | 139–208 ms | 26–32 ms |

Two consequences for the interface:

1. **Express the whole-trace work as questions, not as mechanisms.** An
   interface with `add_watchpoint()` and `replay_forward()` would force the
   Sogen backend to pretend to replay. `query_accesses(lo, hi, kinds, when,
   out, progress)` lets each backend answer the way it can. The worker thread
   and wait box then belong to the *Microsoft* backend, not to the core — what
   the core owns is a `ProgressSink` the backend reports into, which it happens
   to implement with a wait box.

2. **A backend may want a one-off preparation step.** Microsoft builds a memory
   index if the `.run` has none; Sogen fills keyframes (`prepare_keyframes`,
   5.6 s on eight emulators for that trace) and its seeks go from 215 ms to
   36 ms. Same shape, same place in the session: `ITraceBackend::prepare()`,
   offered when a session starts, declinable.

### What each one cannot do

The capability flags in `backend.h` are not speculative; they come from real
gaps.

- **Microsoft has no recorded memory map.** The Replay SDK reports no
  protections and no region list, which is why `analysis/memmap.cpp` is 1,354
  lines of watching `NtAllocateVirtualMemory` and friends and recovering their
  out-parameters. Sogen records every mapping change (`mapping_changes()`,
  format section 14) and every dispatched syscall with its result. The memory
  map *model* — the change timeline, folding it to a position, exposing live
  regions as segments — is shared; only the acquisition differs.
- **Microsoft has no recorded symbols.** `common/symbols.cpp` parses each
  module's export directory and `.pdata` out of guest memory. Sogen stores
  every module's export directory in the trace (sections 11 and 12, forwarders
  resolved) and answers `symbol_at(address, step)` directly.
- **Sogen has no call/return callback.** Microsoft's engine reports call and
  return pairs, which the call tracer, the indirect-call pass and the memory map
  all use. Sogen has an execute event per instruction instead, so calls are
  derived from the execute stream — which is *cheaper* for the indirect-call
  question (an execute at X whose instruction is an indirect call, followed by
  an execute at the target) but needs work for return matching, and
  `trace::calls()` currently takes an export *name* rather than an address.
- **Sogen cannot show bytes no access touched** (their issue #28), where
  Microsoft serves them from the module image. The core already fills such holes
  from the on-disk PE (`ModuleImage` in `common/symbols.h`); that logic is
  backend-independent and moves to the core, where it covers both.

## 3. The licensing constraint, and why the Sogen backend goes out of process

**Sogen is GPL-2.0-only. ida-ttd is Apache-2.0. The IDA SDK is proprietary.**

Linking Sogen's code into the plugin DLL runs into two separate problems:

1. Apache-2.0 and GPL-2.0-*only* are generally held to be incompatible, so
   there is no licence the combined binary could be distributed under.
2. More seriously, a DLL containing GPL-2.0 code *and* linked against the
   proprietary IDA SDK is a GPL violation on its own. The IDA SDK is not a
   system library, so the usual exception does not apply.

There is a second, independent reason to keep it out of process: in-process
means building Sogen. That is CMake, 17 submodules (Unicorn, zstd, Capstone,
SDL, Vulkan-Headers, FEX, …) and the whole `windows-emulator` target, linked
into an MSBuild-built IDA plugin — because `cpu_view`, which is how registers
at a position are obtained, needs a backend CPU.

So: **the Sogen backend DLL contains no Sogen code.** It speaks a protocol to a
server process built from the Sogen tree. The GPL code stays in its own
program, the Apache core stays Apache, and neither links the other.

The latency case for this is also good. Every query above costs 10–400 ms;
a length-prefixed frame over a pipe costs microseconds. IPC is noise against
the work.

I am not a lawyer, and this is the one decision in this document that is not
mine to make — see [Open questions](#9-open-questions).

## 4. The design

### Position

`src/core/position.h`. Two 64-bit words, ordered lexicographically, with three
sentinels (`none`, `begin`, `end`) a backend translates explicitly.

Two words because that is what both backends need and no more — Microsoft's
`(Sequence, Steps)` pair and Sogen's single instruction counter — and because a
position has to be cheap to copy (every row of every listing holds one),
trivially comparable, and storable in a netnode blob. An opaque handle would
mean a backend call to read a bookmark back.

The core never interprets the words. It compares them, stores them, and asks the
backend to `format_position` / `parse_position` — which is also how the "Go to
position" dialog stops saying "Sequence:Steps" to a backend that numbers
positions differently.

### Capabilities

`struct Capabilities` in `backend.h`. The core checks before offering a command,
so an action is never registered that would only apologise. Flags come from §2:
`access_queries`, `call_queries`, `mapping_changes`, `syscalls`,
`recorded_exports`, `cheap_seek`, `reverse_step`.

### The interfaces

Four, rather than one god-interface, along the seams `trace_manager.cpp`
already has:

- **`ITraceBackend`** — identity (`id`, `can_open`, `file_filter`), session
  (`open`/`close`/`info`/`capabilities`/`prepare`), positions, enumeration
  (`modules`, `threads`, `timeline`), the whole-trace queries, and symbols.
- **`ITraceCursor`** — a movable viewpoint: `position`, `seek`, `thread_id`,
  `program_counter`, `stack_pointer`, `read_registers`, `read_memory`,
  `live_threads`. The core makes one for the debugger's playhead and one per
  concurrent query, so a query never moves what the user is looking at.
- **`INavigator`** — `step`/`step_over`/`step_out`/`run`/`run_to`/`seek_to`,
  each forward or backward, plus `set_breakpoints`. Stepping is a strategy, not
  a primitive: "step over backwards" to a replay engine is *rewind, notice we
  landed in a callee that had just returned, rewind out of it* (which is what
  `TraceManager::navigate_over_backward` does today), and to an indexed trace it
  is a read of the previous execute event at this frame's depth. Each backend
  implements the whole family because each has a cheap route the other does not.
- **`ProgressSink`** — `report(percent)` / `cancelled()`. The core implements it
  with a wait box on the main thread; a backend only calls it, from whatever
  thread it likes.

Two deliberate choices worth defending:

- `read_registers` fills IDA's own `regval_t` array rather than a neutral
  register struct. The IDA layout is the lingua franca here, and a neutral
  struct would only be translated twice. (`debugger/registers.cpp` already
  splits this way: `configure_debugger` is pure IDA and becomes core;
  `fill_regvals(CROSS_PLATFORM_CONTEXT…)` is Microsoft's and goes with it.)
- `read_memory` returns a `known` mask per byte. That is exactly the shape of
  Sogen's `memory_at`, which returns `vector<optional<uint8_t>>`, and it is what
  the core needs in order to fill the holes from the module image.

### Where today's code goes

| Today | Goes to | Note |
| --- | --- | --- |
| `ui/`, `plugin/`, `analysis/trace_store.*`, `debugger/event_queue.*` | core | no TTD references already |
| `analysis/{bookmarks,coverage,memsearch,callsites,tracer}.*` | core | rewritten against the queries |
| `analysis/memmap.*` | split | the model, folding and persistence to core; `build_memory_map`'s syscall watching to the Microsoft backend |
| `analysis/sweep.*` | Microsoft backend | it *is* the replay mechanism |
| `debugger/registers.*` | split | `configure_debugger` core, `fill_regvals` Microsoft |
| `debugger/callconv.*` | core | reads guest memory; rewrite against `ITraceCursor` |
| `common/trace_link.*` | core | plus a backend-id field, see below |
| `common/symbols.*` | split | `load_module_image`, `read_module_image_rva`, `parse_pdata_functions_from_file` are pure PE work and go to core; `apply_module_exports` and `parse_pdata_functions` read guest memory through a TTD cursor and go to the Microsoft backend, behind `module_symbols()` / `module_functions()` |
| `common/trace_open.*` | Microsoft backend | engine creation and index build |
| `debugger/trace_manager.*` | split | see below |
| `loader/ldr_main.cpp` | split | the IDA loader shell to core, driven by `can_open`; the PE-from-the-recording reads to the backend |

`trace_manager.cpp` becomes, in the core: `ReplaySession` (the IDA debugger
protocol and session lifetime), `ModuleRegistry` (the span table, `.pdata`
ranges, symbol state), `MemoryReader` (`on_read_memory` and the image fill),
`SegmentLayout` (the memory map and its two layout caches), `CodeAnalyzer` (the
per-stop disassembly pipeline) and `Navigator`'s core half (the pending-request
state). In the Microsoft backend: cursor and engine ownership, the `navigate_*`
family, `reconstruct_region`, the frame search. This is `docs/code-review.md`
§3.3 with the dotted lines drawn in.

### Choosing a backend, and the database

`BackendRegistry` (already on this branch) holds one instance of each backend
compiled into the build and answers `for_file(path)` by asking each `can_open`
in registration order. The loader and the debugger both go through it, so
`File > Open` on a `.run` or a `.sogttd` reaches the right backend with no
separate menu entry.

Backends are **compiled in, not loaded at runtime**. A build without Sogen
support contains no Sogen client code rather than a module that fails to load,
which matters because the two have unrelated dependencies.

One database belongs to one recording *and* one backend. Positions from
different backends are not comparable, and a Sogen trace is of an emulated run —
the real system DLLs, but mapped by Sogen's own loader, so the bases do not
match a native recording of the same program. Therefore:

- `TraceLink` grows a `backend_id` field.
- `analysis/trace_store.*` (landed on the cleanup branch) already refuses
  results stamped with a different recording; the stamp gains the backend id, so
  a bookmark taken in a `.run` session is not offered in a `.sogttd` one.
- Attaching a trace from backend B to a database built by backend A is refused
  with an explanation, not attempted.

## 5. Layout and project files

```
src/
  core/                      ida-ttd-core.vcxproj       (StaticLibrary)
    backend.h  position.h  backend_registry.*
    session/     ReplaySession, Navigator, ModuleRegistry, MemoryReader,
                 SegmentLayout, CodeAnalyzer, event_queue, registers, callconv
    analysis/    bookmarks, coverage, memsearch, callsites, tracer,
                 the memory-map model
    ui/          choosers, actions, decompiler, names, clipboard, scope
    common/      pch, trace_link, module images, PE-from-file
    plugin/      the plugmod_t, listeners, actions, toolbar
  backend-msttd/             ida-ttd-msttd.vcxproj      (StaticLibrary)
    msttd_backend.*  msttd_cursor.*  msttd_navigator.*
    sweep.*  trace_open.*  guest_pe.*  registers_msttd.*  memmap_syscalls.*
  backend-sogen/             ida-ttd-sogen.vcxproj      (StaticLibrary)
    sogen_backend.*  sogen_cursor.*  sogen_navigator.*
    protocol.*  server_process.*
  plugin/                    ida-ttd.vcxproj            (DynamicLibrary)
    dllmain.cpp  backends.cpp   -- links core + the enabled backends
  loader/                    ttd-loader.vcxproj         (DynamicLibrary)
tools/
  sogen-ttd-server/          the GPL-2.0 server; see below
```

Each component carries its own project file, as asked. That is a change from the
cleanup branch, which put both project files in `msbuild/`; with five projects
and three of them owning a source tree, living next to the sources reads better.
`msbuild/common.props` and `Directory.Build.props` stay shared, and
`Directory.Build.props` moves to the repository root so every project inherits
it.

Which backends a build contains is one property:

```
msbuild ida-ttd.slnx -p:Configuration=Release -p:Backends=msttd;sogen
```

`src/plugin/backends.cpp` references the enabled registrations, and
`ida-ttd.vcxproj` adds each enabled backend's `.lib` conditionally. A static
library whose only reference is a file-scope registration object gets dropped by
the linker, so the reference has to be explicit — hence `backends.cpp` rather
than relying on `REGISTER_TTD_BACKEND` alone.

## 6. The Sogen protocol

### The server

Two routes, in the order I would try them:

**(a) A Python server over stdio.** Sogen's Python bindings
(`SOGEN_ENABLE_PYTHON_BINDINGS`, `sogen.ttd`) already expose the entire surface
this needs: `Trace` with `accesses` / `next_access` / `previous_access` /
`history` / `events` / `calls` / `find_exports` / `symbol` / `module_at` /
`thread_at` / `syscalls` / `mapping_changes` / `memory_at` / `read_memory` /
`cpu_at` / `self_modifying_code`, plus `Replay` with `seek` / `run_to` /
`prepare_seeks`. A ~400-line script is the whole server, it tracks Sogen's trace
format for free, and it needs no change to the Sogen repo.

**(b) A native `sogen-ttd-server` target in the Sogen tree**, linking
`windows-ttd` directly. Lower latency and no Python dependency, but it needs a
PR to Sogen and a CMake build of it on the user's machine.

Start with (a). Per-query cost is 10–400 ms of real work, so the interpreter and
the pipe are not what anyone will notice. Move to (b) only if measurement says
otherwise.

### The wire

Length-prefixed frames: a 4-byte little-endian length, then a JSON object,
then an optional binary payload whose length the object gives. JSON keeps it
debuggable; the payload keeps megabytes of memory and millions of access
records out of JSON.

Every request carries an `id`; responses and `progress` notifications carry it
back, so a long query can report while the client stays responsive and can send
`cancel`.

```
-> {"id":7,"op":"open","path":"C:/t/sample.sogttd"}
<- {"id":7,"ok":true,"is64":true,"fingerprint":"0x...","first":0,
    "last":30183325,"main_module":"sample.exe","caps":{...}}

-> {"id":8,"op":"accesses","addr":"0x140005000","size":8,"kinds":6,
    "from":0,"to":null}
<- {"id":8,"progress":41}
<- {"id":8,"ok":true,"count":280,"payload":6720}      + 6720 bytes of records
```

Operations, one per interface method: `open` `close` `info` `prepare`
`modules` `threads` `timeline` `seek` `regs` `mem` `accesses` `next_access`
`prev_access` `executed` `calls` `indirect` `symbols` `functions`
`mapping_changes` `syscalls` `cancel`.

Fixed-layout binary records for the bulk replies (`Access` is 40 bytes;
`CallEvent` 48), so a million-row answer is a memcpy and not a parse.

The server owns one `Trace` and a pool of `Replay` emulators; the client's
cursors map to positions it passes on each request, so the client holds no
server-side state beyond the open trace.

## 7. Phases

Each lands on its own and leaves the plugin working.

**Phase 0 — the interface.** `core/position.h`, `core/backend.h`,
`core/backend_registry.*`. No behaviour. *Landed on this branch.*

**Phase 1 — abstract the position.** Change the stores, the listings and the UI
to `idattd::Position`, converting at the `TraceManager` boundary. 95 call sites,
mechanical, no behaviour change. Bookmark and memory-map blobs keep their layout
(two 64-bit words either way), so existing databases still read. This is the
prerequisite for everything and the largest single diff.

**Phase 2 — split `TraceManager`.** `docs/code-review.md` §3.3 and §3.4, with
the core/backend line from §4 above as the guide. Still one backend; the split
is justified by itself.

**Phase 3 — `ITraceBackend` behind the Microsoft implementation.** Define the
interface for real, have `MsTtdBackend` implement it, and make `ReplaySession`
drive it. Convert the five analyses to the queries, one at a time; each is
independently landable. At the end of this phase there is one backend and no
Microsoft type outside `backend-msttd/`, which `grep` can check.

**Phase 4 — the folder and project split.** Mechanical once phase 3 is done:
move files, add three project files, add `-p:Backends=`.

**Phase 5 — the Sogen backend.** The protocol, the Python server, the client.
Order the operations by what unblocks the most: `open`/`info`/`modules`/`seek`/
`regs`/`mem` gives a working read-only debugger; `accesses` then gives memory
search and coverage at once; `mapping_changes`/`syscalls` gives the memory map
with none of the syscall-watching code.

**Phase 6 — what only one backend can do.** Sogen's recorded syscall list,
`self_modifying_code()`, and its replay scans for strings and buffers have no
Microsoft equivalent and want UI of their own, gated on the capability flags.

Phases 1–3 are worth doing whether or not a second backend ever lands: they are
the open items of the existing code review.

## 8. Risks

- **Phase 1 is wide and shallow, phase 3 is narrow and deep.** Phase 1 cannot
  really go wrong but touches everything; phase 3 is where the per-stop
  disassembly pipeline, the frame search and the pending-request state have to
  keep behaving. That pipeline's ordering constraints currently live only in
  prose comments, and this is the moment to write them down as asserts.
- **Nothing here is testable without IDA.** The repository has no tests. Before
  phase 3 it would be worth having a headless harness (the IDA SDK's `idalib`
  is in the submodule) that opens a recording and walks positions, so the
  navigation family can be checked without a human driving the UI.
- **Sogen's trace format is moving.** It is at version 8, with sections added
  as recently as last week. The protocol insulates the plugin from that — which
  is another argument for IPC — but the server has to track it.
- **Sogen records an emulated run**, roughly 4× the instructions of a native
  one, with its own loader and environment. Expect addresses and module sets not
  to match a Microsoft recording of the same binary. The backend-id stamp (§4)
  is what keeps that from being silently confusing.

## 9. Open questions

1. **Licensing.** §3 argues the Sogen backend has to be out of process. If you
   would rather relicense ida-ttd (yours to do) or accept in-process linking,
   the design changes substantially — say so before phase 5. This is the only
   question that blocks a phase.
2. **Who ships the server?** A Python script in `tools/` here, or a target in
   the Sogen tree? (a) can land without coordinating with anyone; (b) is faster
   and is arguably where it belongs.
3. **One plugin or two?** This plan has one `ida-ttd.dll` that picks a backend
   from the file. The alternative — one plugin DLL per backend, each registering
   its own `debugger_t` — is more IDA-native and lets a user install only what
   they want, but two loaded plugins would both try to register the same action
   ids and menu, which needs per-backend prefixes. I think one plugin is right;
   it is worth saying so out loud.
4. **Do you want phases 1–3 regardless?** They are the open items of
   `docs/code-review.md` and stand on their own. If a second backend is
   uncertain, they are still the next thing to do.

## What is landed on this branch

- `src/core/position.h` — the backend-neutral position and position range.
- `src/core/backend.h` — `Capabilities`, `TraceInfo`, `ModuleInfo`,
  `ThreadInfo`, `TraceEvent`, `Access`, `CallEvent`, `QueryResult`,
  `ProgressSink`, `ITraceCursor`, `INavigator`, `ITraceBackend`.
- `src/core/backend_registry.{h,cpp}` — the registry, `for_file`, `by_id`,
  `file_filters`, and `REGISTER_TTD_BACKEND`.

They compile and are in the project. Nothing uses them, by design: phase 1
comes first, and the interface is here so phase 1 has something to aim at.
