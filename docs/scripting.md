# Driving ida-ttd from a script

The plugin registers one IDC function:

```
ttd("command arg arg ...")   ->   JSON string
```

Anything that can evaluate IDC can drive it: IDAPython, the IDC command line,
or an MCP server that runs Python inside IDA. It exists so the plugin can be
tested by a script instead of by someone describing what they saw. The
`scripts/ida_ttd.py` module wraps it for Python.

```python
import ida_ttd                       # or exec() the file's source
ida_ttd.ensure_loaded()              # an idalib worker may not load plugins itself
ida_ttd.call("backends")
ida_ttd.call("drv.open", r"C:\traces\run.sogttd")
ida_ttd.call("drv.seek", "f4240")    # 1,000,000: numbers are hex
r = ida_ttd.call("drv.regs")["regs"]
ida_ttd.h(r["rip"])
```

## Conventions

- **Arguments** are separated by spaces. Write one that contains spaces in
  double quotes. Numbers are hex, with or without `0x`.
- **A trailing `back`** makes a movement go backwards.
- **Answers** are JSON objects with `"ok"`; a failure also carries `"error"`.
  Addresses and positions are strings (`"0x..."`, or the backend's own position
  text), so 64-bit values survive a JSON reader that uses doubles.
- **Lists** stop at a `MAX` argument (default 0x200 entries, written `200`, as
  every number is hex) and say how many there were in `count`.

## Two ways in

**`drv.*`: a recording opened straight through a backend, with no debugger
session.** These exercise the backend DLLs and the core's adapter in-process,
headless or not:

| Command | |
| --- | --- |
| `drv.open PATH [BACKEND]` | open through the backend that claims the file, or the one named |
| `drv.info` | trace info and capabilities |
| `drv.modules`, `drv.threads [live]`, `drv.timeline [MAX]` | enumeration |
| `drv.seek POS\|first\|last`, `drv.pos` | the cursor |
| `drv.step`, `drv.over`, `drv.out`, `drv.run`, `drv.runto EA` | movement, each `[back]` |
| `drv.bp EA...` | replace the execute breakpoints |
| `drv.regs`, `drv.read EA [SIZE]` | state at the cursor; unknown bytes are `??` |
| `drv.accesses LO HI [rwx] [MAX]`, `drv.calls EA [MAX]`, `drv.indirect LO HI [jumps]`, `drv.exceptions`, `drv.syscalls [MAX]`, `drv.map [MAX]`, `drv.symbols BASE [MAX]` | whole-trace queries |
| `drv.close` | |

**The debugger session:** what a user sees, through IDA's own debugger
machinery.

| Command | |
| --- | --- |
| `start [TIMEOUT]` | start the replay this database was made from; wait for the first stop |
| `step`, `over`, `out`, `run` | each `[back]`; waits for the stop and says where |
| `runto EA [back]`, `goto POS` | |
| `wait [TIMEOUT]` | wait for a stop (seconds, hex) |
| `regs`, `read EA [SIZE]`, `segments [MAX]` | what IDA shows |
| `state` | process state, whether a session is up, where |
| `stop` | end the session |

**`an.*`: the analyses**, inside a session, run by the same functions as their
UI actions, so they show the same wait boxes and write the same things into the
database. The scope is given here instead of in a dialog.

| Command | |
| --- | --- |
| `an.search LO HI [rwx] [MAX]` | Search memory accesses |
| `an.coverage LO HI [COLOR]` | measure coverage and colour what ran |
| `an.callsites LO HI` | annotate indirect calls; lists the comments it wrote |
| `an.trace EA [MAX]` | find all calls to a function, with arguments and return values |
| `an.memmap [MAX]` | build the memory map; the regions as they stand at the playhead |
| `an.syscalls [MAX]` | the recording's syscalls (Sogen), with result and first four arguments |
| `an.selfmod [MAX]` | code the program wrote and then ran (Sogen), with the write and the first run |
| `an.strings [MIN [MAX]] [registry=DIR] [strict]` | replay the recording (Sogen) and list the strings it had in memory; MIN and MAX in hex |
| `an.buffers [MAX] [registry=DIR] [strict]` | replay the recording (Sogen) and list the buffers it filled |
| `an.fork PATH N [registry=DIR] [strict] [REG=V ...] [mem:EA=HEX ...]` | fork the recording at the playhead (Sogen): replay to it, apply the changes, record N (hex) instructions (0: to the end) into PATH |

`help` lists every command with its arguments, and `backends` lists the loaded
backend DLLs.

## From the IDA MCP

The MCP runs Python against a GUI database when IDA is open, and in a headless
idalib worker otherwise. Both work, and a debugger session starts in a headless
worker too: `open_database` on a trace runs the loader, then `start` replays it.
In either:

```python
exec(open(r"C:\path\to\ida-ttd\scripts\ida_ttd.py").read())
ensure_loaded()
call("state")
```

`ensure_loaded()` loads `ida-ttd` from IDA's plugins directory when the worker
has not. The plugin must be installed there, along with any backends in
`plugins\ida-ttd-backends`.

The MCP server can run on another machine than the one with the source: paths
are the IDA machine's. A plain `idc.eval_idc('ttd("...")')` works without the
helper module, since the plugin is loaded in the worker either way.

## The self-test

`scripts/selftest.py` drives a full session over the reference sample in the
`ttd-traces` folder and checks every movement and analysis against what that
program is known to do: 24 checks, the same for a Microsoft and a Sogen
recording of it. Open either trace, then `exec` the file and call `run()`.

## When IDA hangs

A frozen IDA cannot be asked what it is doing, so the plugin writes what takes
long to `%TEMP%\ida-ttd-diag.log`: every backend call over 200 ms with its
arguments, slow reads IDA makes, and the session's phases (start, each resume
and stop, the symbol work for each module), each line with a timestamp and the
thread. The previous session's log is kept as `ida-ttd-diag.prev.log`. Read it
from another process -- a second MCP worker can, while the first is stuck.

`ttd("state")` also returns an `event_log`: the last events handed to IDA, the
resumes received and the breakpoint updates IDA made, which is how a movement
that IDA drives itself (step over backwards) can be followed.
