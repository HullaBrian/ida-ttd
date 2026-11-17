# Scripting ida-ttd

Everything the TTD menu does can be done from a script: move through the
recording, read registers and memory, and run every whole-recording analysis.
It works the same in IDA's console, in a script file, in idat and idalib, and
in an MCP server's Python, which makes it the way to give an AI agent the
recording.

There are two layers. The plugin registers one IDC function,

```
ttd("command arg arg ...")   ->   JSON string
```

and the `ida_ttd` Python module wraps it, with the answers as Python values.
Use the module from Python; the [commands](#the-ttd-commands) underneath are
for what it does not cover and for anything else that can evaluate IDC.

## The Python module

### Setting up

The module is `scripts/ida_ttd.py`, installed as
`plugins\ida-ttd\ida-ttd-python\ida_ttd.py` beside the plugin. When the plugin
loads it puts that folder on IDAPython's `sys.path`, so there is nothing else
to do:

```python
import ida_ttd
```

Where the plugin is not loaded yet (an idalib worker may not load plugins on its
own), run the file and load it:

```python
import os
exec(open(os.path.expandvars(r"%APPDATA%\Hex-Rays\IDA Pro\plugins\ida-ttd\ida-ttd-python\ida_ttd.py")).read())
ensure_loaded()
```

### Two ways in

- **`Session`** drives the TTD debugger session in this IDA: the same replay
  the toolbar steps through, over the recording this database was opened from.
  Moving it moves IDA's views; the analyses are the TTD menu's, writing what
  they write into the database.
- **`Recording`** opens a recording through its backend with no debugger at
  all: a cursor of its own, nothing shown, nothing written. For reading another
  recording, or working headless.

### Values

- **Numbers** -- addresses, register values, sizes, results -- are ints. The
  fields each answer lists in its `"_hex"` are converted, recursively, so text
  that happens to read `"0x41"` stays text.
- **Memory** is `bytes`. Bytes the recording does not hold read as zero.
- **Positions** stay strings in the recording's own syntax: `"1A:2F"`
  (Sequence:Steps) for Microsoft TTD, a decimal step count for Sogen. Pass them
  back exactly as you got them.
- **Arguments you pass** may be ints: they are sent in hex, the plugin's number
  syntax. Positions are the exception and go as written.
- **Failures** raise `ida_ttd.TtdError` with the plugin's reason.

## A session

```python
import ida_ttd
s = ida_ttd.Session()

s.start()                       # replay this database's recording, wait for the first stop
s.position                      # "11:0"
hex(s.pc)

s.step()                        # one instruction forward
s.step(back=True)               # and back
s.step_over(); s.step_out(back=True)
s.run_to(0x7FF6A0011234)        # forward to an address
s.run(back=True)                # back to the previous breakpoint, or the start
s.goto("3A:46")                 # any position

s.regs()                        # {"rax": 0x..., "rbx": ..., "rip": ..., "efl": ...}
s.reg("rsp")
s.read(s.reg("rsp"), 0x40)      # bytes, as IDA reads them here
s.segments()                    # IDA's segments, debugger ones included
s.stop()                        # end the session
```

Every movement waits for the stop and returns where it stopped.

## Whole-recording questions

Each runs the analysis behind the TTD menu entry of the same name and returns a
list of dicts. They read the whole recording, so the first call can take
seconds (minutes on a long recording); several keep their answer, in the
session or in the database, and answer at once the next time.

| Call | Each entry | Notes |
| --- | --- | --- |
| `s.syscalls(limit)` | `pos`, `tid`, `number`, `name`, `result`, `args` (the first four) | |
| `s.calls_to(target, limit)` | `func`, `name`, `pos`, `end`, `tid`, `args`, `ret` | `target` is an address or `"module!Glob*"`. Arguments follow a prototype you set in IDA (Y) first, then the Win32/phnt metadata where it has the function, then IDA's own or guessed type: each is text (`"PAGE_READWRITE"`, `"0x1524B8F8A0 -> 2"`) or, where it is a plain number, an int |
| `s.accesses(lo, hi, kinds, limit)` | `pos`, `pc`, `addr`, `size`, `tid`, `kind` | every read (`"r"`), write (`"w"`) and execute (`"x"`) of `[lo, hi)`; `hi` defaults to `lo + 1` |
| `s.origin(what, size, at, through)` | `what`, `value`, `at`, `kind`, `by_pos`, `by_pc`, `insn`, `note` | where a value came from, as of the current position or `at`; see below |
| `s.origin_graph(what, size, at, max_nodes)` | `nodes` (as `origin`, plus `combined`), `edges` (`from`, `to`, `input`), `truncated` | every chain at once; see below |
| `s.inputs(at)` | `what`, `value`, `address`, and `reg` or `addr` and `size` | what the instruction about to run at `at` (default: the current position) read |
| `s.handles(limit)` | `handle`, `type`, `name`, `opened`, `by`, `closed` | every handle the program opened and closed; `opened` is empty for one opened before the recording, `closed` for one still open at the end |
| `s.memory_map(limit)` | `base`, `size`, `protect`, `type`, `use`, `since` | the address space at the current position |
| `s.self_modifying(limit)` | `address`, `size`, `written`, `writer`, `first_run`, `runs` | code the program wrote and then ran |
| `s.strings(min_length, limit)` | `pos`, `address`, `wide`, `text` | every string the program had in memory |
| `s.buffers(limit)` | `address`, `size`, `kind`, `first`, `last`, `writer`, `writes`, `preview` | every buffer it filled |
| `s.call_tree(limit)` | `pos`, `depth`, `site`, `target`, `ret`, `call` | the calls the function at the current position made in this run of it; `call` is false for a function reached by a jump (a tail call) |
| `s.heat()` | see below | the memory heatmap's counts |

`limit` defaults to everything worth having; pass a number to cut a long
answer short.

### Where a value came from

```python
s.goto("3A:46")
for hop in s.origin("rax"):         # or s.origin(0x1524B8F8D8, 8) for memory
    print(hop["what"], hex(hop["value"]), hop["kind"], hop["by_pos"], hop["insn"], hop["note"])
```

```
rax                      0x1585a77d940  copied  3A:38  mov rax, rbx           copied from rbx
rbx                      0x1585a77d940  copied  3A:2B  mov rbx, [rsp+48h]     copied from [0x1524B8F8D8], 8 bytes
[0x1524B8F8D8], 8 bytes  0x1585a77d940  copied  3A:B   mov [rsp+10h], rbx     copied from rbx
...
```

Each hop is one instruction that set the value; `by_pos` is where it ran
(before it ran -- `s.goto(hop["by_pos"])` lands on it). The chain goes on while
the instructions only copy the value (moves, push and pop, string and SSE
copies), and through computations made from a single value (`lea rax,
[rdi+0Dh]`, `inc rdi`, `add [mem], 2`): such a hop is `computed`, its note
naming the value followed ("computed from rdi"). `through=False` stops at every
computation instead. The stack pointer is not followed. The chain ends with
`kind` saying why:

| `kind` | The value was |
| --- | --- |
| `computed` | made by the instruction from several values, or a register it changed on the side |
| `constant` | an immediate in the code, or a register zeroed by combining it with itself (`xor eax, eax`) |
| `system` | a syscall's result, or memory a syscall wrote (`note` names it) |
| `unchanged` | never changed in what was searched: since the thread began, or from the start of the recording |

Registers are named as in IDA (`rax`, `eax`, `al`, `r12d`, `xmm0`); memory is an
address and a size up to 64 bytes.

A chain that ends at `computed` is where the value was made from several
values. `s.inputs(hop["by_pos"])` lists what that instruction read, as it stood
just before it ran: its operands (memory as the recording has the read), the
implicit ones of `mul`, `div`, `cdq` and the like, then the registers that only
formed an address (`address` true). Each is a chain of its own, from the same
position:

```python
hop = s.origin("rax")[-1]           # lea rax, [rdi+0Dh], inc rdi, then sub rdi, rcx
for i in s.inputs(hop["by_pos"]):
    print(i["what"], hex(i["value"]), "(address)" if i["address"] else "")
s.origin("rdi", at=hop["by_pos"])   # follow one of them
```

For memory, pass the input's address and size: `s.origin(i["addr"], i["size"], at=...)`.

Or every chain at once, as the value origin graph draws it:

```python
g = s.origin_graph("rax")           # max_nodes=60 by default
for e in g["edges"]:
    used, made = g["nodes"][e["from"]], g["nodes"][e["to"]]
    print(used["what"], "<-", made["what"], made["insn"], made["kind"])
s.show_origin_graph("rax")          # the window, without the prompt
```

`nodes` are hops as `origin()` gives them, `[0]` the value asked about; each edge
goes from the hop that used a value to the hop that set it (`input` true for
one of several values an instruction combined). A value reached twice is one
node. `truncated` says the limit cut it short.

### The heatmap

```python
h = s.heat()
h["page_shift"], h["slices"]        # 12 (4 KiB pages), 256 slices of time
h["starts"][10]                     # the position slice 10 begins at
for page in h["pages"]:             # one per page touched, in address order
    base = page["page"] << h["page_shift"]
    for slice_, reads, writes, executes in page["cells"]:
        ...
```

## A recording without the debugger

```python
with ida_ttd.Recording(r"C:\traces\sample.run") as r:
    r.info                          # what opening it reported: the backend and the recording
    r.modules(); r.threads(); r.timeline()

    r.seek("first")                 # or "last", or a position
    r.step(); r.step_over(back=True)
    r.where()                       # pos, tid, pc, sp
    r.regs()["rip"]
    r.read(0x7FF6A0010000, 16)
    r.instructions(8)               # the next 8 on this thread

    r.breakpoints(0x7FF6A0011234, (0x1524B8F8D8, 8, "w"))   # execute, and a write watch
    r.run()                         # to the first of them

    r.accesses(lo, hi, "rwx")
    r.calls_to(0x7FFB386A1420)
    r.syscalls(); r.exceptions(); r.memory_changes()
```

One recording at a time: a second `Recording` closes the first, which then
raises instead of driving the new one. `close()` it, or use `with`. It has a
backend instance of its own, so it can be the same recording the session is
replaying.

## Examples

**Every file the program opened, and whether it closed it:**

```python
for h in s.handles():
    if h["type"] == "File":
        print(h["name"], h["opened"], h["closed"] or "still open")
```

**Every call that made memory executable, with its caller's position:**

```python
for c in s.calls_to("kernelbase!VirtualProtect*"):
    if "EXECUTE" in str(c["args"][2]):
        print(c["pos"], c["args"])
```

**Where the bytes of a buffer came from** -- the writes to it, then the origin
of the first one:

```python
buf = 0x1585A786000
writes = s.accesses(buf, buf + 16, "w")
s.goto(writes[-1]["pos"])           # at the last write
s.step()                            # just after it
print(s.origin(buf, 8)[-1])         # where the chain ends
```

**Strings the program decoded at runtime**, the ones not in any module:

```python
images = [(r["base"], r["base"] + r["size"]) for r in s.memory_map() if r["type"] == "Image"]
for st in s.strings(8):
    if not any(lo <= st["address"] < hi for lo, hi in images):
        print(st["pos"], hex(st["address"]), st["text"])
```

## For AI agents

- Start with `s.state()` and `s.position`: a session may not be running
  (`s.start()`), and where it is matters to every question about "now".
- Prefer the whole-recording questions over stepping: one `s.accesses(...)` or
  `s.calls_to(...)` answers what a thousand steps would, in one replay.
- `s.origin(...)` is the tool for "where did this value come from"; follow
  `by_pos` with `s.goto` to look around the instruction that set it.
- The first call of an analysis can take minutes on a long recording, and IDA
  does nothing else meanwhile (the GIL is let go while it waits, so other
  Python threads keep running). Pass a small `limit` while exploring, and give
  the call a long timeout.
- Positions are opaque: compare them only through the plugin (`s.goto`), never
  as numbers.

## The ttd() commands

Every method of the module is one command. `ida_ttd.call(command, *args)` sends
any of them and returns its JSON answer as a dict, for what the classes do not
cover; `ida_ttd.py()` converts an answer's `"0x..."` values as the classes do:

```python
ida_ttd.call("help")                    # every command and its arguments
ida_ttd.call("backends")
ida_ttd.call("an.coverage", lo, hi)     # color what ran in [lo, hi)
ida_ttd.call("drv.seek", "f4240")       # 1,000,000: numbers are hex
ida_ttd.py(ida_ttd.call("an.memmap"))
```

Without the module, from IDC or any Python: `idc.eval_idc('ttd("state")')`
returns the same JSON as a string.

### Conventions

- **Arguments** are separated by spaces. Write one that contains spaces in
  double quotes, which may also sit inside a word:
  `registry="C:\Program Files\x"`. Numbers are hex, with or without `0x`,
  addresses and counts alike (`an.strings 10` is sixteen characters); `0n`
  marks a decimal one, as in WinDbg (`0n10` is ten).
- **A trailing `back`** makes a movement go backwards, and `timeout=N`
  (seconds; a minute by default) bounds how long it waits for the stop. An
  answer with `"timed_out"` means the replay is still moving. A movement
  takes no other word: a typo is an error, not some other movement.
- **Sogen replays** (`an.strings`, `an.buffers`, `an.fork`, `an.forkrecord`)
  take `registry=DIR` (the hives, for a recording made against the host),
  `root=DIR` (the emulation root, where it is elsewhere on this machine),
  `host` (consent to replay a host recording), `strict`, and `anyregistry`
  (replay with hives that are not the recording's). Any other word is an
  error, so a misspelt option is not silently ignored.
- **Answers** are JSON objects with `"ok"`; a failure also carries `"error"`.
  Addresses and positions are strings (`"0x..."`, or the backend's own position
  text), so 64-bit values survive a JSON reader that uses doubles. Each
  object lists the keys it wrote as `"0x..."` numbers in `"_hex"`.
- **`drv.open`** answers with a `handle`. One recording is open for `drv.*`
  at a time: a second `drv.open` closes the first, and a Python `Recording`
  whose handle is no longer the open one raises instead of driving the new
  recording.
- **Lists** stop at a `MAX` argument (default 0x200 entries, written `200`, as
  every number is hex) and say how many there were in `count`.

### A recording without a session: drv.*

A recording opened straight through a backend, with no debugger session (what
`Recording` uses). These exercise the backend DLLs and the core's adapter
in-process, headless or not:

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

### The debugger session

What a user sees, through IDA's own debugger machinery (what `Session` uses):

| Command | |
| --- | --- |
| `start [TIMEOUT]` | start the replay this database was made from; wait for the first stop |
| `step`, `over`, `out`, `run` | each `[back] [timeout=N]`; waits for the stop and says where |
| `runto EA [back] [timeout=N]`, `goto POS [timeout=N]` | |
| `wait [TIMEOUT]` | wait for a stop (seconds, hex; `timeout=N` also works here and for `start` and `switch`) |
| `regs`, `read EA [SIZE]`, `segments [MAX]` | what IDA shows |
| `state` | process state, whether a session is up, where |
| `stop` | end the session |

### The analyses: an.*

Inside a session, run by the same functions as their UI actions, so they show
the same wait boxes and write the same things into the database. The scope is
given here instead of in a dialog.

| Command | |
| --- | --- |
| `an.search LO HI [rwx] [MAX]` | Search memory accesses |
| `an.coverage LO HI [COLOR]` | measure coverage and color what ran |
| `an.callsites LO HI` | annotate indirect calls; lists the comments it wrote |
| `an.trace EA [MAX]` | find all calls to a function, with arguments and return values |
| `an.memmap [MAX] [rebuild]` | the session's memory map, the one IDA's segments and the Memory map window use: built (and saved) if the database has none, again with `rebuild`; the regions as they stand at the playhead |
| `an.calltree [MAX]` | the calls the function at the playhead made during this run of it, nested (depth), from its entry to its return |
| `an.syscalls [MAX]` | the recording's syscalls (Sogen), with result and first four arguments |
| `an.selfmod [MAX]` | code the program wrote and then ran (Sogen), with the write and the first run |
| `an.registry` | where the recording's registry hives are looked for (the chosen folder, `registry\` beside the recording, the emulation root's, `ida-ttd\registry`), whether each holds the recording's own hives, and the folder a replay would use |
| `an.strings [MIN [MAX]] [registry=DIR] [strict] [host]` | replay the recording (Sogen) and list the strings it had in memory; MIN and MAX in hex |
| `an.buffers [MAX] [registry=DIR] [strict] [host]` | replay the recording (Sogen) and list the buffers it filled |
| `switch PATH [TIMEOUT]` | end the session and replay PATH (a fork of the recording) in this database, as the Fork manager's "Switch here" does |
| `an.forks` | the forks recorded in this database (the Fork manager's graph): path, parent, position, changes |
| `an.forget PATH` | take a fork out of the graph; its file stays |
| `an.forkhere` | make the playhead a fork (TTD > Fork here); change it with IDA's own calls (`ida_dbg.set_reg_val`, `ida_dbg.write_dbg_memory`), which only succeed at the fork's position |
| `an.forkdraft` | the fork being prepared: its position, whether the playhead is there, and its register and memory changes |
| `an.forkrecord PATH N [registry=DIR] [strict] [host]` | record the fork being prepared: replay to it, apply its changes, record N (hex) instructions (0: to the end) into PATH. The error says `(needs host)`, `(needs registry=DIR)` or `(wrong hives: ...)` when that is what stopped it; `anyregistry` replays with hives that are not the recording's |
| `an.forkdiscard` | drop the fork being prepared |
| `an.fork PATH N [registry=DIR] [strict] [host] [REG=V ...] [mem:EA=HEX ...]` | fork the recording at the playhead (Sogen): replay to it, apply the changes, record N (hex) instructions (0: to the end) into PATH |
| `an.record PROGRAM PATH [N] [args="..."] [cwd=DIR] [registry=DIR] [root=DIR] [host] ...` | run PROGRAM from its start in Sogen's emulator and record N (hex; none or 0: until it exits) instructions into PATH (TTD > Backends > Record a program with Sogen). Works with no recording open. With `root=DIR`, `place=GUESTDIR` (such as `C:\ida-ttd`) copies a program from outside the root into it first, and `replace` overwrites a different file already there. Without `root=DIR` it runs against this machine's files and needs `host`; the hives are `registry=DIR`, else the first known folder holding some. `start=now`, `start=1970` or `start=YYYY-MM-DDTHH:MM:SS` (UTC) is the date the program starts at (default: the `sogen_start_now` setting). The error says `(needs host or root=DIR)` or `(needs registry=DIR)` |

The fork, scan and record commands also take the recording options, over the
Sogen settings: `net` / `nonet` (the real network for the program, from a
fork's position on or from a new recording's start; scans stay offline),
`ckpt=N` (instructions between checkpoints, hex), `access=rwx` (what a new
recording or fork keeps: any of `r`ead, `w`rite, e`x`ecute), `elevated` (an
administrator's token, new recordings only) and `log` (Sogen's emulator log
and the program's console output to the output window).

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
program is known to do: 28 checks, the same for a Microsoft and a Sogen
recording of it. Open either trace, then `exec` the file and call `run()`; on
a Sogen recording, `run_sogen()` also checks the Sogen-only commands (syscalls,
self-modifying code, recovered strings and forks).

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
