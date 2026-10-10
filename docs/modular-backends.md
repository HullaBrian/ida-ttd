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

## 3. Licensing, and why each backend is its own DLL

**Sogen is GPL-2.0-only. ida-ttd is Apache-2.0. The IDA SDK is proprietary.**

Putting Sogen's code in the plugin DLL runs into two separate problems:

1. Apache-2.0 and GPL-2.0-*only* are generally held to be incompatible, so
   there is no licence the combined binary could be distributed under.
2. More seriously, a DLL containing GPL-2.0 code *and* linked against the
   proprietary IDA SDK violates the GPL on its own. The IDA SDK is not a system
   library, so the usual exception does not apply. This one does not go away by
   choosing a licence; it is a property of the link.

### The arrangement

Each backend is a separate DLL, and **the boundary between the core and a
backend carries no IDA types and no C++ types**. That is
`src/abi/ida_ttd_backend.h`: a flat C ABI of fixed-layout structs,
caller-provided buffers and a table of function pointers, published under
CC0 so the interface's licence constrains nobody's implementation.

The consequences are what matter:

- **A backend never links the IDA SDK.** It never sees an `ea_t`, a `qstring`
  or a `regval_t`, and never calls into IDA. Problem (2) above disappears
  entirely — this is the decisive point, and it is why the ABI is C rather
  than the C++ interface an in-process design would have used.
- **A backend never links the core either.** It exports one function and
  includes one public-domain header. So there is no Apache/GPL link to
  reconcile, and problem (1) reduces to the familiar question of whether a
  plugin is a derivative of its host.
- **On that question**, the mitigations are the conventional ones and they all
  apply here: the ABI is general rather than contrived (the Microsoft backend
  uses the same one, so it was not shaped to get around anything), it is
  published and versioned independently, the GPL backend is distributed under
  GPL-2.0 with source by whoever ships it, and the user installs it themselves
  — the GPL restricts distribution, not use, and nobody distributes the
  combination.
- **It is also what you asked for on its own merits**: users install the
  backends they want, a backend they do not have costs them nothing, and each
  backend's third-party dependencies stay inside it.

**I am not a lawyer and this is not legal advice.** If you want certainty
rather than a well-trodden arrangement, the fallback is out-of-process: the
Sogen backend DLL stays Apache-2.0, contains no Sogen code, and talks to a
server process built from the Sogen tree. That makes the boundary unarguable at
the cost of a protocol, a second process and a build of Sogen as an executable
rather than a library. The design below does not depend on which you pick —
only `src/backend-sogen/` differs.

### What this costs

- **C ABI discipline.** No exceptions across the boundary (a backend catches
  everything and returns a status code), no `std::` types, no shared allocator,
  no shared CRT. All results go into caller-allocated arrays of POD via the
  count-then-fill pattern. This is a real constraint on how backends are
  written, and it is the price of the two properties above.
- **Versioning.** `ITTD_ABI_VERSION` has to be bumped for any
  non-additive change, and the core has to report a mismatch by name rather
  than calling through a table it does not understand. The entry point takes
  the version for exactly this reason.
- **One indirection on the hot path.** `cursor_read_memory` is called for every
  disassembly line, register dereference and stack row. It is a function-pointer
  call into a buffer the caller owns, so there is no marshalling — the cost is
  the call itself, which is nothing against a memory query.
- **Registers needed a canonical form.** An in-process backend could fill IDA's
  `regval_t` array directly; a DLL cannot see that type. So the ABI defines
  `ittd_regs` (x86-64 general, segment, flags, xmm, plus a `have` mask) and the
  core maps it onto IDA's register table. Both engines have something close
  already — Microsoft's `CROSS_PLATFORM_CONTEXT`, Sogen's `save_registers` blob
  — so neither pays much.

### Where backends live

Not in IDA's `plugins/` directory: IDA globs that for plugins and would try to
load a backend as one. The core looks in `plugins/ida-ttd-backends/` instead,
loads every DLL there, calls `ida_ttd_backend(ITTD_ABI_VERSION)`, and keeps the
ones that answer. A module that fails to load, or answers for a version the
core does not speak, is named in the output window and skipped.

### Building the Sogen backend

`ida-ttd-sogen.dll` links Sogen's `windows-ttd` and nothing of ida-ttd's.
That means a CMake build of Sogen, which today pulls in `windows-emulator` and
therefore Unicorn, Capstone, SDL and the rest — for code that only ever reads a
trace file.

It does not have to. The reader half of `windows-ttd` is already emulator-free
*in implementation*: no `trace::` member function touches `windows_emulator`,
`memory_manager`, `mapped_module` or `save_registers`. Those uses are all in
`recorder` and the replay verifiers, which merely share the header, and the two
emulator-dependent types the reader holds (`view_engine`, `keyframe_store`) are
both held by `shared_ptr` — one is already forward-declared.

So the first item in [sogen-ttd-requests.md](sogen-ttd-requests.md) is a
reader-only CMake target. With it, the backend DLL is a small link against the
trace reader and zstd. Without it, the backend still works but is a large
binary and a long build, which is a worse thing to ask a user to install.

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

`BackendRegistry` (already on this branch) holds one instance of every backend
module that loaded, and answers `for_file(path)` by asking each `can_open` in
load order. The plugin and the loader both go through it, so `File > Open` on a
`.run` or a `.sogttd` reaches the right backend with no separate menu entry and
no extra question for the user.

`can_open` is therefore asked of every backend for every file IDA opens, which
is why the ABI says it must be cheap and must not open the recording: a
signature read at most.

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
  abi/
    ida_ttd_backend.h        the C ABI; CC0, included by core and every backend
  core/                      ida-ttd-core.vcxproj       (StaticLibrary)
    backend.h  position.h  backend_registry.*
    backend_module.*         loads a DLL, adapts the C ABI to ITraceBackend
    session/     ReplaySession, Navigator, ModuleRegistry, MemoryReader,
                 SegmentLayout, CodeAnalyzer, event_queue, registers, callconv
    analysis/    bookmarks, coverage, memsearch, callsites, tracer,
                 the memory-map model
    ui/          choosers, actions, decompiler, names, clipboard, scope
    common/      pch, trace_link, module images, PE-from-file
    plugin/      the plugmod_t, listeners, actions, toolbar
  plugin/                    ida-ttd.vcxproj            (DynamicLibrary)
    dllmain.cpp              -> plugins/ida-ttd.dll, links core only
  loader/                    ttd-loader.vcxproj         (DynamicLibrary)
    ldr_main.cpp             -> loaders/ttd-loader.dll, links core only
  backend-msttd/             ida-ttd-msttd.vcxproj      (DynamicLibrary)
    entry.c  msttd_backend.*  msttd_cursor.*  msttd_navigator.*
    sweep.*  trace_open.*  guest_pe.*  regs.*  memmap_syscalls.*
                             -> plugins/ida-ttd-backends/ida-ttd-msttd.dll
  backend-sogen/             ida-ttd-sogen.vcxproj      (DynamicLibrary)
    entry.c  sogen_backend.*  sogen_cursor.*  sogen_navigator.*
                             -> plugins/ida-ttd-backends/ida-ttd-sogen.dll
```

Each component carries its own project file, as asked. That is a change from
the cleanup branch, which put both project files in `msbuild/`; with five
projects and three of them owning a source tree, living next to the sources
reads better. `Directory.Build.props` moves to the repository root so every
project inherits it, and `msbuild/common.props` stays shared.

Two things worth noticing about this layout:

- **The core no longer needs the TTD Replay SDK.** Today every project imports
  the `Microsoft.TimeTravelDebugging.Apis` NuGet package. After the split only
  `backend-msttd` does, so building the core, the plugin and the loader needs
  nothing but the IDA SDK.
- **`ida-ttd.dll` gets small.** It is `dllmain.cpp` plus the core library: the
  debugger, the UI and the backend loader, with no knowledge of any recording
  format.

`backend-sogen` is the only project that cannot be built from this repository
alone — it needs a Sogen checkout. It is excluded from the default solution
build and takes a `-p:SogenRoot=` to build, so a normal build of ida-ttd never
depends on Sogen being present.

## 6. The Sogen backend

With the DLL arrangement there is no protocol and no server: the backend links
Sogen's trace reader and calls it directly. What the backend does is translate,
in both directions.

### The easy direction

Most of the ABI maps straight onto something Sogen already has:

| ABI | Sogen |
| --- | --- |
| `cursor_read_memory` | `trace::memory_at(pos, addr, size)` — returns `vector<optional<uint8_t>>`, which is exactly the buffer-plus-known-mask shape the ABI asks for |
| `cursor_regs` | `trace::cpu_at(pos)`, then `read_register` per register |
| `query_accesses` | `trace::accesses(addr, size, first, last, kind_mask)` |
| `query_executed` | the same with `kind_mask = execute` |
| `modules` | `trace::modules()` |
| `threads` | `trace::threads()` |
| `module_symbols` | `module_entry::exports`, already resolved, forwarders included |
| `query_mapping_changes` | `trace::mapping_changes()` plus `trace::syscalls()` |
| `prepare` | `prepare_keyframes` |
| `nav_run_to` | `next_access` / `previous_access` with `execute`, then seek |
| `format_position` | the instruction counter in decimal |

`query_mapping_changes` deserves a note: this is the one where Sogen replaces
1,354 lines of watching `NtAllocateVirtualMemory` and recovering its
out-parameters with a table read. The memory-map *model* — the change
timeline, folding it to a position, exposing live regions as segments — stays
in the core and is shared.

### The parts that need work

- **`query_calls` and `query_indirect`.** `trace::calls()` takes an export
  *name* and returns the callee's first instruction, so neither the call site
  nor the matching return comes with it. Both are requested in
  [sogen-ttd-requests.md](sogen-ttd-requests.md) §3 and §4; until they land the
  backend derives them from the execute stream itself, or reports the
  capability as absent and the core greys the commands out. §4 argues this is
  the query where Sogen should beat Microsoft TTD by the widest margin, so it
  is worth having properly rather than approximated.
- **Argument and return values.** `cpu_at` is 6 ms, which is fine once and
  expensive 5,000 times over a call listing. Requests §7 asks for a batch form.
- **Holes in memory reads.** Sogen cannot show bytes no access touched (their
  issue #28); the core's module-image fill covers the image-backed ones, and
  the rest render as unknown.
- **Cancellation.** None of Sogen's long calls can be interrupted today
  (requests §2). Until they can, the backend has to either block without a
  working Cancel or bound the work it asks for.

### Order of work

`open` / `info` / `modules` / `cursor_seek` / `cursor_regs` /
`cursor_read_memory` gives a working read-only debugger — stepping by seek, a
disassembly, registers and memory. `query_accesses` then lights up memory
search and coverage at once, because both go through it. `query_mapping_changes`
gives the memory map with none of the syscall-watching code. The call queries
come last, and are where the SDK requests matter.

## 7. Phases

Each lands on its own and leaves the plugin working.

**Phase 0 — the interfaces.** `abi/ida_ttd_backend.h` (the C ABI),
`core/position.h`, `core/backend.h`, `core/backend_registry.*`. No behaviour.
*Landed on this branch.*

**Phase 1 — abstract the position.** *Landed on this branch.* The stores, the
listings and the UI use `idattd::Position`, converting at the `TraceManager`
boundary through `debugger/msttd_position.h`. `src/ui`, `src/plugin`,
`src/core` and `src/abi` now contain no Microsoft TTD type at all. Bookmark
blobs are unchanged; memory-map blobs moved to version 7 because they can hold
an absent position, whose bit pattern differs between the two representations.

**Phase 2 — split `TraceManager`.** `docs/code-review.md` §3.3 and §3.4, with
the core/backend line from §4 above as the guide. Still one backend; the split
is justified by itself.

*§3.4 is landed as phase 2a*: the eleven mutually exclusive request flags are
one `PendingRequest`, which is also the shape `INavigator` needs -- its request
kinds are the navigator's methods.

*Four of the six classes are landed as phase 2b*: `ModuleRegistry`,
`MemoryReader`, `CodeAnalyzer` and `SegmentLayout`. `trace_manager.cpp` is
1,446 lines, down from 3,179, and its header 243 from 484. Each was verified
line-for-line against the file it came out of, and each takes the execution
cursor as a parameter rather than keeping a pointer to it -- that cursor is
destroyed and recreated per session, and a stored pointer is the kind of thing
that works until the second trace.

What is left of the split is `Navigator` (the `navigate_*` family, the pending
request, the watchpoint bookkeeping) and, once that leaves, `ReplaySession` --
whatever remains, which is the IDA debugger protocol and the engine's lifetime.
`Navigator` is deliberately last: it is both the most entangled with the cursor
and the part phase 3 reshapes most, since its methods are `INavigator`'s.

**Phase 3 — `ITraceBackend` behind the Microsoft implementation.** Have
`MsTtdBackend` implement the core-side interface and make `ReplaySession` drive
it, still in one binary. Convert the five analyses to the queries, one at a
time; each is independently landable. By the end of this phase the Microsoft
code is reached only through the interface, which is what makes phase 4 a move
rather than a rewrite.

**Phase 4 — the folder and project split, and the C ABI.** Move the files, add
the project files, and put `BackendModule` between the core and the C ABI:
`MsTtdBackend` stops implementing `ITraceBackend` directly and starts exporting
`ida_ttd_backend`, with the adapter in the core translating. The step that
proves it is `grep`: no Microsoft TTD type, and no TTD NuGet import, anywhere
outside `src/backend-msttd/`.

**Phase 5 — the Sogen backend.** A second DLL against the same ABI, in the
order given in §6. The ABI having been exercised by the Microsoft backend
through phase 4 is the point: by the time Sogen arrives, the boundary has
already been proven by one implementation.

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
  as recently as last week. The backend DLL absorbs that: it is rebuilt against
  a Sogen checkout, and the core never sees a trace structure. What the core
  does see is the ABI, which is versioned separately and should move far more
  slowly.
- **The C ABI is a commitment.** Once a backend exists that the core does not
  build, the ABI cannot be changed casually. Bumping `ITTD_ABI_VERSION` is
  cheap while both backends live here; it stops being cheap the moment someone
  else ships one. Worth getting the hot calls — `cursor_read_memory`,
  `cursor_regs`, `query_accesses` — right before publishing it anywhere.
- **Sogen records an emulated run**, roughly 4× the instructions of a native
  one, with its own loader and environment. Expect addresses and module sets not
  to match a Microsoft recording of the same binary. The backend-id stamp (§4)
  is what keeps that from being silently confusing.

## 9. Open questions

1. **Who ships the Sogen backend?** It is a GPL-2.0 binary built against a
   Sogen checkout, so it cannot be a release asset of an Apache-2.0 repository
   without being clearly separated: its own release, its own licence file, its
   own source link. The alternatives are a separate repository, or a target in
   the Sogen tree. Something has to be decided before the first release that
   includes it; nothing before then.
2. **The SDK requests.** [sogen-ttd-requests.md](sogen-ttd-requests.md) is
   written to be handed over as-is. §1 (a reader-only target) is the one that
   decides whether the backend is a reasonable thing to ship; the rest are
   improvements. Worth sending early, since §1 is a header reshuffle and the
   answer shapes phase 5.
3. **One plugin or several?** This plan has one `ida-ttd.dll` that picks a
   backend from the file, so there is one `debugger_t`, one action set and one
   toolbar however many backends are installed. The alternative — one plugin
   DLL per backend — is more IDA-native but two loaded plugins would both
   register the same action ids and menu. One plugin plus loadable backends
   gives the modularity without that, which is what §3 assumes.

## What is landed on this branch

- `src/abi/ida_ttd_backend.h` — the C ABI between the core and a backend DLL:
  positions, capability bits, the trace/module/thread/access/call/mapping
  structs, the canonical register set, the progress sink, and the function
  table. CC0, so a backend's licence is its own business.
- `src/core/position.h` — the backend-neutral position and position range.
- `src/core/backend.h` — the core-side C++ view of the same interface:
  `Capabilities`, `TraceInfo`, `ModuleInfo`, `ThreadInfo`, `TraceEvent`,
  `Access`, `CallEvent`, `QueryResult`, `ProgressSink`, `ITraceCursor`,
  `INavigator`, `ITraceBackend`. Kept close in shape to the ABI so the adapter
  stays a translation.
- `src/core/backend_registry.{h,cpp}` — which backends are available and which
  one owns a given file.
- `docs/sogen-ttd-requests.md` — the SDK changes a Sogen backend wants, written
  to be handed to that project.

The interfaces compile and are in the project; nothing is wired to them yet,
since that is phase 3.

Phases 1 and 2a are landed on top of them:

- `src/core/position.{h,cpp}` is in use throughout the core, and the one place
  a position is formatted or parsed is the one phase 3 routes through the
  active backend.
- `src/debugger/msttd_position.h` converts at the engine boundary, and the
  `TtdPosition` alias marks every line that is Microsoft-specific.
- `TraceManager::PendingRequest` replaces the eleven request flags.
- `debugger/{module_registry,memory_reader,code_analyzer,segment_layout}.*`
  are four of the six classes `TraceManager` becomes.

Release and Debug both build clean at every commit.
