> [!Warning]
> Claude was used to write this project's code. I performed testing for my own use cases, but
> you may run into issues. If you do, feel free to open an issue on this repository!

# ida-ttd

ida-ttd is an IDA Pro plugin that allows you to interact with time travel debugging (TTD)
recordings from multiple TTD backends (Microsoft and Sogen) and holistically analyze 
traces using a multitude of TTD analysis techniques.

For detailed installation and usage instructions, see the [wiki](https://github.com/HullaBrian/ida-ttd/wiki).

## Overview

Time Travel Debugging (TTD) is a technique that records binary execution and, in some cases, 
memory accesses (ie reads, writes, executes). Using it grants reverse engineers the ability 
to efficiently analyze a process's historical behavior and spend less time fighting typical 
dynamic analysis headaches. Additionally, TTD extends analysis capabilities in a number of 
ways, especially when it comes to higher level questions about *what* a process did.

The core ida-ttd plugin sits between IDA Pro and several "backend" TTD providers, which allows 
for general TTD techniques to be implemented and work with multiple TTD implementations. Below 
are some of the features:
- Reverse trace navigation
- Bookmarks
- Function calls
  - Find calls to functions based on pattern (ie `kernel32!Virtual*`)
  - Find all calls to a given function
  - Call tree of a given function
- Memory accesses (reads, writes, and/or executes)
- Historical value tracing
- Syscall recovery with parameters
- Handle recovery
- Memory map reconstruction
  - Region timeline (allocations, maps, frees, protection changes)
  - Regions at timestamp
  - Heatmap
- General analysis
  - String/buffer recovery
  - Self-modifying code
- Annotation
  - Indirect call resolution
  - Instruction/Pseudocode execution highlighting
- Python API

Currently supported providers include [Microsoft's TTD](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/time-travel-debugging-overview) 
and a [custom fork of Sogen](https://github.com/TTD-Club/sogen) which supports TTD. Currently, the custom Sogen 
fork contains more features than Microsoft TTD. It allows for forks to be created in the recording, which overcomes 
one of the biggest challenges TTD has faced - immutability. With forks, you can modify register/memory value 
(or both) and re-record a trace.

### Plugin Installation Structure

Below is the structure of the plugin's installation files.

```
%APPDATA%\Hex-Rays\IDA Pro\
  plugins\ida-ttd\     the plugin package (hcli's; replaced on upgrade)
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
  decoding.
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
- The API metadata loader and the
  Material Symbols icons are Apache-2.0; the Codicons are CC BY 4.0.
- The backend ABI header is CC0.

The API metadata in `data/` is derived from win32metadata and phnt, both MIT.
Third-party notices are in [THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt),
which the package carries too. [docs/licensing.md](docs/licensing.md) has the
details.
