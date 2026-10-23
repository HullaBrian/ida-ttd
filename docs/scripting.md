# Driving ida-ttd from a script

The plugin registers one IDC function:

```
ttd("command arg arg ...")   ->   JSON string
```

Anything that can evaluate IDC can drive it: IDAPython, the IDC command line,
or an MCP server that runs Python inside IDA -- a person's script or an AI
agent's. The `ida_ttd` Python module wraps it.

## The Python module

[python.md](python.md) is the guide to it; this is the short version.

The module is `scripts/ida_ttd.py`, installed as
`plugins\ida-ttd-python\ida_ttd.py`. The plugin puts that folder on
IDAPython's `sys.path` when it loads, so `import ida_ttd` works in the
console, in a script and in an MCP server's Python. Where the plugin is not
loaded, exec() the file and call `ensure_loaded()`.

```python
import ida_ttd

s = ida_ttd.Session()                # the TTD debugger session in this IDA
s.start()                            # replay this database's recording
s.position, hex(s.pc)
s.step(); s.step_over(back=True); s.goto("1A:2F")
s.regs()["rax"]                      # ints, not strings
s.read(s.reg("rsp"), 0x40)           # bytes
[c["name"] for c in s.syscalls()]
s.calls_to("kernel32!CreateFileW")   # each call, with arguments and return value
s.accesses(0x1234, 0x1238, "w")      # every write to those bytes
s.origin("rax")                      # where rax's value came from, hop by hop
s.origin(0x1234, 8)                  # ... or 8 bytes of memory
s.inputs(hop["by_pos"])              # what the instruction that computed it read
s.origin("r8", at=hop["by_pos"])     # ... and where one of those came from
s.origin_graph("rax")                # every chain at once: nodes and edges
s.show_origin_graph("rax")           # ... in the graph window
s.handles(); s.memory_map(); s.self_modifying()
s.strings(8); s.buffers(); s.call_tree(); s.heat()

with ida_ttd.Recording(r"C:\traces\run.sogttd") as r:   # no debugger at all
    r.seek("first"); r.step(); r.regs(); r.read(0x401000, 16)
    r.breakpoints((0x404000, 8, "w")); r.run()
```

Answers come back as Python values: every `"0x..."` string becomes an int,
memory becomes `bytes`. Positions stay strings in the recording's own syntax
and are passed back as they are. A failure raises `ida_ttd.TtdError` with
the plugin's reason. Below the classes, `ida_ttd.call(command, *args)` sends
any command and returns its JSON answer as a dict:

```python
ida_ttd.call("backends")
ida_ttd.call("drv.seek", "f4240")    # 1,000,000: numbers are hex
```

## Conventions

- **Arguments** are separated by spaces. Write one that contains spaces in
  double quotes, which may also sit inside a word:
  `registry="C:\Program Files\x"`. Numbers are hex, with or without `0x`.
- **A trailing `back`** makes a movement go backwards.
- **Sogen replays** (`an.strings`, `an.buffers`, `an.fork`, `an.forkrecord`)
  take `registry=DIR` (the hives, for a recording made against the host),
  `root=DIR` (the emulation root, where it is elsewhere on this machine),
  `host` (consent to replay a host recording), `strict`, and `anyregistry`
  (replay with hives that are not the recording's).
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
| `an.calltree [MAX]` | the calls the function at the playhead made during this run of it, nested (depth), from its entry to its return |
| `an.syscalls [MAX]` | the recording's syscalls (Sogen), with result and first four arguments |
| `an.selfmod [MAX]` | code the program wrote and then ran (Sogen), with the write and the first run |
| `an.registry` | where the recording's registry hives are looked for (the chosen folder, `registry\` beside the recording, the emulation root's, `ida-ttd\registry`), whether each holds the recording's own hives, and the folder a replay would use |
| `an.strings [MIN [MAX]] [registry=DIR] [strict]` | replay the recording (Sogen) and list the strings it had in memory; MIN and MAX in hex |
| `an.buffers [MAX] [registry=DIR] [strict]` | replay the recording (Sogen) and list the buffers it filled |
| `switch PATH [TIMEOUT]` | end the session and replay PATH (a fork of the recording) in this database, as the Fork manager's "Switch here" does |
| `an.forks` | the forks recorded in this database (the Fork manager's graph): path, parent, position, changes |
| `an.forget PATH` | take a fork out of the graph; its file stays |
| `an.forkhere` | make the playhead a fork (TTD > Fork here); change it with IDA's own calls (`ida_dbg.set_reg_val`, `ida_dbg.write_dbg_memory`), which only succeed at the fork's position |
| `an.forkdraft` | the fork being prepared: its position, whether the playhead is there, and its register and memory changes |
| `an.forkrecord PATH N [registry=DIR] [strict] [host]` | record the fork being prepared: replay to it, apply its changes, record N (hex) instructions (0: to the end) into PATH. The error says `(needs host)`, `(needs registry=DIR)` or `(wrong hives: ...)` when that is what stopped it; `anyregistry` replays with hives that are not the recording's |
| `an.forkdiscard` | drop the fork being prepared |
| `an.fork PATH N [registry=DIR] [strict] [REG=V ...] [mem:EA=HEX ...]` | fork the recording at the playhead (Sogen): replay to it, apply the changes, record N (hex) instructions (0: to the end) into PATH |

`help` lists every command with its arguments, `backends` lists the loaded
backend DLLs, and `settings` shows the plugin's settings as it holds them
(TTD > Settings...; read again first if they changed).

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
has not. The plugin must be installed there (`plugins\ida-ttd\`, where HCLI puts
it), and any extra backends in `ida-ttd\backends\` in the IDA user directory.

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
