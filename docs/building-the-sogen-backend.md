# Building and testing the Sogen backend

`ida-ttd-sogen.dll` reads Sogen time-travel traces (`.sogttd`) for ida-ttd. It
is a separate DLL behind the C ABI in `src/abi/ida_ttd_backend.h`, and it links
Sogen's trace reader and `cpu_view`, and for forks and the replay scans
Sogen's replay, recorder and Windows emulator, all GPL-2.0-only. The DLL it
produces is therefore a GPL-2.0 binary
([modular-backends.md](modular-backends.md) §3). It is not part of
`ida-ttd.slnx`, so building ida-ttd never needs Sogen. Releases build it from
the commit in `msbuild/sogen.pin` (`.github/workflows/release.yml`) and ship
it in the plugin package; `scripts/sogen_dist.py` writes the licenses that go
beside it and the source archive that goes on the release
([licensing.md](licensing.md)). A local build goes in the package the same
way: run `sogen_dist.py` after building, then `package.py`.

The core does not load backends yet (that is phase 4 of the plan). Until it
does, the backend is exercised with `ittd-probe`, which is in the solution.

## 1. Build Sogen's reader and view

From a Visual Studio x64 developer prompt, against a Sogen checkout on
`ttd/next` (`%SOGEN%`) and a build directory of your choosing
(`%SOGEN_BUILD%`):

Use `ttd/next` at `86158936` or later. Before `ada569b0`, reading a page of
memory walked every recorded access to it -- tens to hundreds of
milliseconds on a hot code page -- and IDA reads whole modules after their
symbols load; since, a page comes from the checkpoint and the writes since,
in tens of microseconds. `86158936` walks those writes backward, so a busy
heap page is quick too, keeps four decoded checkpoints, and reads memory
committed but never written as zero rather than unknown. The backend reports ITTD_CAP_CHEAP_READS only for recordings
with checkpoint memory, so an older recording still opens, more slowly.

To update an existing build after pulling Sogen, reconfigure with
`-DFETCHCONTENT_FULLY_DISCONNECTED=ON` -- otherwise CMake tries to update the
dependencies it fetched, which can fail on long paths -- and build the same
target again.

```bat
cmake -S %SOGEN% -B %SOGEN_BUILD% -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo ^
      -DSOGEN_BUILD_STATIC=ON -DSOGEN_BUILD_TOOLS=OFF -DSOGEN_ENABLE_PYTHON_BINDINGS=OFF ^
      -DSOGEN_ENABLE_RUST_CODE=OFF -DSOGEN_DISABLE_FEX=ON -DSOGEN_ENABLE_SDL3=OFF ^
      -DSOGEN_ENABLE_LTO=OFF -DSOGEN_ENABLE_SCCACHE=OFF
cmake --build %SOGEN_BUILD% --target windows-ttd windows-ttd-view
```

That builds about 260 objects into 22 static libraries under
`%SOGEN_BUILD%\artifacts`: the reader and view, plus the replay and recorder
(`windows-ttd`), the Windows emulator and what it links (mbedTLS, the
disassembler, the process manager). No SDL, FEX or Rust. The backend imports
nothing beyond the CRT, Winsock, crypt32 and bcrypt -- in particular not the
Windows Hypervisor Platform -- and is about 15 MB.

Until 2026-10-13 the backend needed only `windows-ttd-view`; a build of just
that target no longer links. After updating Sogen, rebuilding only
`windows-ttd-view` does link, against the old `windows-ttd.lib` and
`windows-emulator.lib`, and the result reads every register as zero: always
build `windows-ttd`.

Since 2026-10-14 the backend needs `ttd/next` at `9fa4e1a3` or later, for
`cpu_views_at` (registers at many positions, each register snapshot interval
replayed once for all of them) and `cpu_view::read_register`.

Since 2026-11-09 it is built from TTD-Club/sogen `main` at `253c9488`
(`msbuild/sogen.pin`), and needs it or later:

- **Use a fresh build directory.** Unicorn is now built for x86 and AArch64
  (`UNICORN_ARCH "x86;aarch64"`, a cache value): an older build directory
  keeps `x86`, and the backend then fails to link `uc_init_aarch64`. The
  backend links `aarch64-softmmu.lib` and `iphlpapi.lib` as well.
- `windows_emulator::emu()` is the architecture-neutral `guest_machine`
  now; the backend reaches registers through `x64_emu()`.
- The trace format is version 9. Version 8 recordings (Sogen before
  2026-11-07) still open and answer every query, but cannot be forked: their
  checkpoints hold the old emulator state, and the replay stops with
  "Reading from serialized buffer mismatches written data!".
- `emulator_settings::disable_logging` is no longer read; the backend
  silences the logger itself (and forwards it when asked, `ittd_fork_settings::log`).
- Pass `-DSOGEN_ENABLE_SCCACHE=OFF` to build without sccache even where it
  is installed.

Since 2026-11-11 the pin is `f848464d` (`ttd/next`; `main` is still at
`253c9488`). Nothing in the build changes; what does:

- `emulator_settings::relative_time_start`: where a relative-time run's
  system time starts. `record_program` sets it from
  `ittd_record_request::start_time`. The emulator's saved state carries it,
  so replays and forks start at the recording's own date and need nothing
  set. A program sees the start plus Sogen's simulated uptime (about 44
  minutes), not the start itself.
- That saved state grew without a trace format change: v9 recordings made
  before `f848464d` still open and answer every query, but **do not fork**
  ("Reading from serialized buffer mismatches written data!").
- A message to a port Sogen does not emulate is reported once per
  connection through `on_generic_access` ("Rejecting message to unknown
  port"). The backend passes that one, and "Opening unsupported device", to
  the emulator log (`sogen_log`), and none of the other generic accesses.
- A checkpoint holding a file open in a folder deleted later now restores
  (the folders are recreated too).
- `create-root.bat` copies each collected DLL's `SystemResources\<dll>.mun`.
  WinINet's start-up fails without `wininet.dll.mun`, so an emulation root
  made before this needs it copied in, or the root made again.

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

`-t:Rebuild` because MSBuild does not notice when Sogen's libraries change --
neither by name nor by full path -- and would keep a backend linked against
the old reader. It is one source file.

```bat
msbuild msbuild\backend-sogen.vcxproj -t:Rebuild -p:Configuration=Release -p:Platform=x64 ^
        -p:SogenRoot=%SOGEN% -p:SogenBuild=%SOGEN_BUILD%
msbuild ida-ttd.slnx -p:Configuration=Release -p:Platform=x64 -m:1
```

The backend lands in `build\Release\backends\ida-ttd-sogen.dll`. It goes in
`ida-ttd\backends\` under the IDA user directory (**TTD > Backends > Install
the Sogen backend...** puts it there): not the plugin's `plugins\ida-ttd\`,
which HCLI replaces on upgrade, and not under `plugins\`, since it is not a
plugin.

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

- **Syscalls:** in position order and named, and RIP at a sampled syscall's
  position is a `syscall` instruction.
- **Self-modifying code:** RIP at a hit's write position is the writer, and at
  its first-run position the written instruction.

With `ITTD_PROBE_FORK_REGISTRY` naming a folder of registry hives, it also
replays: a fork in the middle of the recording with a changed register,
recorded into `ITTD_PROBE_FORK_OUT` (default `fork.sogttd`) and opened again
(it starts at the fork's position, with the parent's RIP and the changed
register), a second fork with the recording settings (writes and executes
only, a shorter checkpoint interval, the log callback; `ITTD_PROBE_NET=1`
opens the network past the position, `ITTD_PROBE_FORK_AT` and
`ITTD_PROBE_FORK_MAX` move it and set its length), and the string and buffer
scans (a sampled string is in memory at or just after its position: the scan
gives the step after the completing write, as Sogen's scanner does, and a
string that lived one step is gone a step later). It also checks that a
recording made against the host is not replayed without
`ITTD_FORK_ALLOW_HOST`. The reference traces were all recorded against the
host, so these runs re-run their file operations on the machine running the
probe.

`ITTD_PROBE_RECORD=<exe>` first records that program from its start into the
TRACE path (`record_program`, against the host with the hives in
`ITTD_PROBE_FORK_REGISTRY`, or in `ITTD_PROBE_RECORD_ROOT`;
`ITTD_PROBE_RECORD_ARGS`, `ITTD_PROBE_RECORD_MAX`, `ITTD_PROBE_NET`,
`ITTD_PROBE_LOG=1` to print the emulator's log), then probes the result.
`ITTD_PROBE_PEEK=ADDR,POS` lists what touched 32 bytes at ADDR in the 200
steps before POS and shows them around it.

It exits 0 when every check passes. It is written in C, which also keeps the
ABI header honest about being C.

## 4. Registry hives for replay

Forks and the replay scans run the program again in Sogen's emulator, which
reads the registry the recording ran against: `HARDWARE`, `NTUSER.DAT`,
`SOFTWARE` and `SYSTEM`, and `SAM` and `SECURITY` when they were there
(Sogen's `grab-registry.bat` captures them; an emulation root's `registry`
folder has them).

**Recordings that carry their hives** (Sogen since `8a9fb161`, 2026-10-21)
hold the parts of the hive files the run read, and replay with no hive files
at all (`replay_env` reports `registry_carried`). The backend still loads the
recording's own hive files when they are found, so a fork that reads further
than the recording did can go on; without them, such a fork fails saying it
needs them.

**Older recordings** need the very files the recorder was given: the
manifest holds a fingerprint of them (`registry`), and a new capture of the
same machine gives other bytes. The backend checks a folder against it
(`check_registry`, Sogen's `registry_fingerprint`) and refuses other hives
unless `ITTD_FORK_ANY_REGISTRY` is given.

Where the hives are looked for depends on how the recording was made:

- **In an emulation root:** Sogen loads `<root>\registry` and ignores any
  other folder, so the plugin asks for the root itself when it is elsewhere on
  this machine (`ittd_fork_settings::emulation_root`; `root=DIR` in scripts).
- **Against the host:** the plugin looks, in order, in the folder last chosen,
  a `registry` folder beside the recording, and `ida-ttd\registry\` under the
  IDA user directory, and uses the first that holds the recording's own hives
  (`an.registry` lists them). Given no folder (`ittd-probe` without
  `ITTD_PROBE_FORK_REGISTRY`), the backend looks in a `registry` folder next
  to `ida-ttd-sogen.dll`.

A recording made against the host also replays only on a Windows build like
the one it ran on: what the program loads or reads after the first checkpoint
(further DLLs, NLS files, fonts) comes from this machine. The manifest's
`system_dlls` (ntdll, kernel32, kernelbase) stands in for that; `replay_env`
says when it differs, and the Registry hives dialog says so. Record in an
emulation root when a recording has to travel.

`SAM` and `SECURITY`, with `SYSTEM`, hold the recording machine's local
password hashes. Sogen no longer requires them, and a recording that carries
its hives holds only their 340-byte headers unless the program opened them;
delete them from a root you mean to share.

## Results

Run on 2026-11-11 against `f848464d`, Release, on the `ttd-traces`
recordings made that day with Sogen's analyzer (host mode, test-sample with
the network live) and on a program recorded with `record_program`: 0 checks
failed. The 2026-11-09 recordings fail only their forks, as expected.

| Check | ttd-step-sample (5.9M) | test-sample (31.5M) |
| --- | --- | --- |
| syscalls | 577, all named | 5,493, all named |
| self-modifying code | 11 hits, 0.6 s | 1 hit, 3.2 s |
| fork in the middle, open | 360 ms | 464 ms |
| strings (8+ characters) | 27,804, 1.6 s | 122,571, 9.0 s |
| buffers | 515 | 936 |
| checkpoint intervals verified | 11 of 11 | 61 of 63 |

test-sample's two failing intervals are around 20,000,000. Before it, a
replay cannot map a file the program has just created (forks from
19,975,579 to 20,000,000 fail). After it, the state at 20,500,000 differs
slightly, and forks still work. The 2026-11-09 recording gave 35
self-modifying hits: Windows updated the system DLLs in between, and a host
recording runs on this machine's DLLs.

**Start time.** A program printing `GetSystemTime` and `QueryInterruptTime`
around `Sleep(60000)`, recorded with `start_time` at the current time, saw
2026-11-11 18:44:58 and then 18:46:10. Without it, it saw 1970-01-01 00:43:53
and 00:45:05. The interrupt time moved 72 s in both.

Run on 2026-11-09 against TTD-Club/sogen `253c9488`, Release, on recordings
made with the backend's own `record_program` (`ITTD_PROBE_RECORD`, offline,
against the host, hives from the emulation root's `registry`). All checks
pass; the 2026-10-21 v8 recording gives the same strings, buffers and
self-modifying code as before, byte for byte, and only its fork fails.

| Check | ttd-step-sample (6.0M) | test-sample (30.8M, offline) |
| --- | --- | --- |
| record from the start | 1.6 s | 9.3 s |
| syscalls | 578, all named | 5,156, all named |
| self-modifying code | 11 hits, 0.6 s | 1 hit, 3.3 s |
| fork in the middle, open | 380 ms | 551 ms |
| strings (8+ characters) | 28,076, 1.6 s | 122,137, 9.1 s |
| buffers | 520 | 926 |

test-sample's reference recording was made with `--network live --root-mode
rw`; offline it takes other paths (fewer syscalls, one self-modifying hit).

**Network access.** A program that resolves `example.com` and connects:
recorded offline, the lookup fails (11001); a fork of that recording from
near its start with `ITTD_NET_LIVE` resolves and connects, and so does a new
recording with it. The replay to the fork's position stays offline.

Run on 2026-10-13 against Sogen `ttd/next` at `86158936`, Release, with the
backend linking `windows-ttd`:

| Check | ttd-step-sample (5.9M) | test-sample (33M) |
| --- | --- | --- |
| syscalls | 572, all named | 5,698, all named |
| self-modifying code | 4 hits, 0.5 s | 8 hits, 3.5 s |
| fork in the middle, open | 214 ms | 216 ms |
| record 20,000 instructions | 0.3 s | 0.6 s |
| strings (8+ characters) | 28,257, 3.5 s | 135,029, 21 s |
| buffers | 500, 1.4 s | 978, 8.4 s |

Earlier results:

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

Stepping is complete: step over and step out in both directions walk the
thread's instructions back to the call that entered a frame, and pair it
with its `ret` through `calls_to`.

| | Why |
| --- | --- |
| `module_functions` | Sogen records no `.pdata`; the core reads it from the file on disk |
| `prepare` | Nothing to prepare: a seek is a `cpu_view`, with no keyframes |
