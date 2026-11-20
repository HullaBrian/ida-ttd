> [!Warning]
> Claude was used to write this project's code. I performed testing for my own use cases, but
> you may run into issues. If you do, feel free to open an issue on this repository!

# ida-ttd

ida-ttd is an IDA Pro plugin that turns a time travel debugging (TTD) recording into an IDA
debugger session: step forwards and backwards, jump to any point, and ask questions about the
whole recording. It reads [Microsoft TTD](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/time-travel-debugging-overview)
recordings (`.run`) and recordings from a [custom fork of Sogen](https://github.com/TTD-Club/sogen)
(`.sogttd`).

The [wiki](https://github.com/HullaBrian/ida-ttd/wiki) has the full instructions.

## Overview

- Reverse navigation: step, step over, step out, continue and run to cursor, backwards too
- Bookmarks and a timeline of thread and module events
- Every call to a function or pattern (`kernel32!Virtual*`), with decoded arguments and return values
- Every read, write or execute of an address range
- Where a value came from, traced back through the instructions that set it
- Syscalls, handles, the memory map and its timeline, a memory heatmap
- Recovered strings and buffers, self-modifying code
- Indirect calls resolved, and executed code highlighted in the disassembly and the decompiler
- A Python API

Sogen recordings can also be **forked**: change registers or memory at any point and record what
the program does next, then compare the two runs. See
[Sogen TTD Features](https://github.com/HullaBrian/ida-ttd/wiki/Sogen-TTD-Features).

## Installation

Requires IDA Pro 9.5 on Windows x64.

```
hcli plugin install ida-ttd
```

Or extract `ida-ttd.zip` from the [latest release](https://github.com/HullaBrian/ida-ttd/releases)
into `%APPDATA%\Hex-Rays\IDA Pro\plugins\`. Restart IDA once, so **File > Open** recognizes
recordings.

Microsoft recordings need the TTD runtime first:
[Microsoft TTD](https://github.com/HullaBrian/ida-ttd/wiki#microsoft-ttd). To build the plugin
yourself, see [Building from Source](https://github.com/HullaBrian/ida-ttd/wiki#building-from-source).

## Usage examples

Each feature is described on
[Features and Usage](https://github.com/HullaBrian/ida-ttd/wiki/Features-and-Usage).

**Open a recording.** **File > Open** a `.run` or `.sogttd` file; the original binary is not
needed. The TTD toolbar adds the backward controls, and the queries are on the **TTD** menu.

**Find what wrote a buffer.** Right-click the address and choose **Find memory accesses**
(`Ctrl+Shift+M`). Double-click a write to travel there, then press `Ctrl+Shift+W` on the stored
register to see where its value came from.

**Find every call to an API.** Press `Ctrl+Shift+F` and enter `kernel32!CreateFileW`.
Double-click a call to travel to it.

**Find unpacked code.** Open **TTD > Memory > Memory map**: executable memory outside every loaded
module is colored. Double-click its "Allocated at" position to travel to the allocation.

**Script it** ([Scripting](https://github.com/HullaBrian/ida-ttd/wiki/Scripting)):

```python
import ida_ttd
s = ida_ttd.Session()
s.start()                                   # replay this database's recording
s.step(back=True)                           # one instruction backwards
for c in s.calls_to("kernel32!CreateFileW"):
    print(c["pos"], c["args"], c["ret"])
s.origin("rax")                             # where rax's value came from
```

| Shortcut | Action |
| --- | --- |
| `Ctrl+Shift+F` | Find calls by name or pattern |
| `Ctrl+Shift+C` | Find calls to this function |
| `Ctrl+Shift+M` | Find memory accesses |
| `Ctrl+Shift+W` | Where did this value come from |
| `Ctrl+Shift+G` | Go to position |
| `Ctrl+Shift+B` | Bookmark this position |

## Future Work/Ideas
- Function/memory query language
- Linux support for Sogen recordings (MS recordings will never work unless there's official support from Microsoft)

## Credits

ida-ttd is written and maintained by **HullaBrian** ([GitHub](https://github.com/HullaBrian)).
Bug reports and feature requests are welcome on the
[issue tracker](https://github.com/HullaBrian/ida-ttd/issues).

It builds on:

- [Sogen](https://github.com/momo5502/sogen) by momo5502 and its contributors, the emulator and
  trace format behind `.sogttd` recordings (built from the [TTD-Club fork](https://github.com/TTD-Club/sogen)).
- Microsoft's [TTD Replay SDK](https://www.nuget.org/packages/Microsoft.TimeTravelDebugging.Apis),
  which reads `.run` recordings.
- [win32metadata](https://github.com/microsoft/win32metadata) (through
  [win32json](https://github.com/marlersoft/win32json)) and [phnt](https://github.com/winsiderss/phnt),
  for decoding API arguments.
- [Unicorn](https://github.com/unicorn-engine/unicorn) and
  [Capstone](https://github.com/capstone-engine/capstone), inside the Sogen backend.
- [Codicons](https://github.com/microsoft/vscode-codicons) and
  [Material Symbols](https://github.com/google/material-design-icons), the icons.
- Hex-Rays, for IDA Pro and its SDK.

## License

`Apache-2.0 OR GPL-2.0-only` ([LICENSE](LICENSE), [LICENSES/GPL-2.0-only.txt](LICENSES/GPL-2.0-only.txt)).
The Sogen backend (`src/backend-sogen/`, `ida-ttd-sogen.dll`) is GPL-2.0-only, as Sogen and
Unicorn are; its source is `ida-ttd-sogen-source.zip` on each release. Third-party notices:
[THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt). Details: [docs/licensing.md](docs/licensing.md).
