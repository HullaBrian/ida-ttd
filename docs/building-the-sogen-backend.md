# Building and testing the Sogen backend

`ida-ttd-sogen.dll` reads Sogen time-travel traces (`.sogttd`) for ida-ttd. It
is a separate DLL behind the C ABI in `src/abi/ida_ttd_backend.h`, and it links
Sogen's trace reader and `cpu_view`, which are GPL-2.0-only. The DLL it
produces is therefore a GPL-2.0 binary
([modular-backends.md](modular-backends.md) §3). It is not part of
`ida-ttd.slnx`, so building ida-ttd never needs Sogen.

The core does not load backends yet (that is phase 4 of the plan). Until it
does, the backend is exercised with `ittd-probe`, which is in the solution.

## 1. Build Sogen's reader and view

From a Visual Studio x64 developer prompt, against a Sogen checkout on
`ttd/next` (`%SOGEN%`) and a build directory of your choosing
(`%SOGEN_BUILD%`):

Use `ttd/next` at `ada569b0` or later. Before it, reading a page of memory
walked every recorded access to it -- tens to hundreds of milliseconds on a
hot code page -- and IDA reads whole modules after their symbols load; with
it, a page is read from the checkpoint and the writes since, in tens of
microseconds. The backend reports ITTD_CAP_CHEAP_READS only for recordings
with checkpoint memory, so an older recording still opens, more slowly.

To update an existing build after pulling Sogen, reconfigure with
`-DFETCHCONTENT_FULLY_DISCONNECTED=ON` -- otherwise CMake tries to update the
dependencies it fetched, which can fail on long paths -- and build the same
target again.

```bat
cmake -S %SOGEN% -B %SOGEN_BUILD% -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo ^
      -DSOGEN_BUILD_STATIC=ON -DSOGEN_BUILD_TOOLS=OFF -DSOGEN_ENABLE_PYTHON_BINDINGS=OFF ^
      -DSOGEN_ENABLE_RUST_CODE=OFF -DSOGEN_DISABLE_FEX=ON -DSOGEN_ENABLE_SDL3=OFF ^
      -DSOGEN_ENABLE_LTO=OFF
cmake --build %SOGEN_BUILD% --target windows-ttd-view
```

That builds 129 objects (most of them Unicorn) into ten static libraries under
`%SOGEN_BUILD%\artifacts`, with no windows-emulator, SDL, FEX or Rust.

- **The cache values matter.** `backend-sogen.vcxproj` compiles Sogen's headers
  with the defines this configuration produces (`SOGEN_BUILD_STATIC=1`,
  `SOGEN_ENABLE_RUST_CODE=0`, ...). A different configuration needs the same
  change there.
- **Sogen must be the top-level CMake project.** Its build uses
  `CMAKE_SOURCE_DIR` throughout, so it cannot be pulled in with
  `add_subdirectory`; that is why the backend links the built libraries rather
  than building Sogen itself.
- **Do not point this at a checkout someone is working in.** Building writes
  nothing into the source tree, but a tree in the middle of an edit may not
  build. A clean checkout of a commit (`git archive`, plus the `deps`
  submodules) is what this was tested with.

## 2. Build the backend and the probe

```bat
msbuild msbuild\backend-sogen.vcxproj -p:Configuration=Release -p:Platform=x64 ^
        -p:SogenRoot=%SOGEN% -p:SogenBuild=%SOGEN_BUILD%
msbuild ida-ttd.slnx -p:Configuration=Release -p:Platform=x64 -m:1
```

The backend lands in `build\Release\backends\ida-ttd-sogen.dll`. Once the core
loads backends, it goes in IDA's `plugins\ida-ttd-backends\`.

## 3. Probe a trace

```bat
build\Release\ittd-probe.exe build\Release\backends\ida-ttd-sogen.dll trace.sogttd [EXPORT]
```

`ittd-probe` loads any backend through the ABI and prints what it reports. It
also checks the promises the ABI makes about positions, because getting those
wrong is silent in the UI:

- **Accesses:** at an access's position, RIP is the instruction that did it.
- **Calls:** at `pos` RIP is the call site, at `entry_pos` the target, and at
  `ret_pos` it is just past the site.
- **Steps and runs:** a step moves one position, and running backward to an
  address lands on its last execution.
- **Batch registers:** `regs_at`, given positions in reverse order, agrees with
  the cursor.

It exits 0 when every check passes. It is written in C, which also keeps the
ABI header honest about being C.

## Results

Run on 2026-10-12 against Sogen `ttd/next` at `f2461773`, Release.

**`view.sogttd`** (test-sample, 31.4M positions, recorded 2026-10-09):

| Check | Result |
| --- | --- |
| open | 21 ms |
| registers at a position (`cpu_view`) | 21 ms cold |
| 16 bytes at RIP (`memory_at`) | 0.3 ms, all known |
| `calls_to(ntdll!RtlAllocateHeap)` | 3,383 calls, 2,765 with a return, 4.8 s |
| `regs_at`, 200 entry positions | 4.9 ms each |
| indirect branches in test-sample.exe | 329 edges, 2.7 s |
| exceptions | 5, 1.1 s |
| step over a call (forward) | 0.2 ms, lands on the paired return |
| position checks | all pass |

**`regions.sogttd`** (test-sample, 33.7M positions, recorded 2026-10-12 with
the thread stacks and memory map sections): all checks pass.

| Check | Result |
| --- | --- |
| memory map | 1,621 entries (33 at the start), 0.1 ms; 3 mapped files; 1 RWX private allocation, attributed to its syscall |
| `calls_to(ntdll!RtlAllocateHeap)` | 4,100 calls, 3,462 with a return, 2.3 s |
| `regs_at`, 200 entry positions | 2.5 ms each |
| indirect branches in test-sample.exe | 766 edges, 0.5 s |
| the stack page above RSP mid-trace | 4,096 of 4,096 bytes known |

A smaller recording of `ttd-step-sample` (`cli.sogttd`, 5.9M positions)
passes as well: 436 map entries, 2 RWX allocations.

**`bench.sogttd`** (recorded 2026-10-08, before register snapshots): queries
work, but every register read fails, because `cpu_view` needs snapshots. A trace
that old can be searched but not debugged. The backend reports the reason
through `last_error`, and the core should say so rather than show empty
registers.

## What it does not do yet

| | Why |
| --- | --- |
| `nav_step_over` backward, `nav_step_out` | Both need the entry of the current frame, which no single reader query gives. Forward step over is done: it pairs the call with its `ret` through `calls_to` (0.2 ms, exact under recursion) |
| `module_functions` | Sogen records no `.pdata`; the core reads it from the file on disk |
| Thread stacks and the module machine | Read when the trace has them (sections 15 and 16); the test traces predate both |
| `prepare` | Nothing to prepare: a seek is a `cpu_view`, with no keyframes |
