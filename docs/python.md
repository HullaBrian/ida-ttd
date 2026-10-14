# Scripting ida-ttd from Python

Everything the TTD menu does can be done from IDAPython through one module,
`ida_ttd`: move through the recording, read registers and memory, and run every
whole-recording analysis, with the answers as Python values. It works the same
in IDA's console, in a script file, in idat and idalib, and in an MCP server's
Python, which makes it the way to give an AI agent the recording.

This page is the guide. [scripting.md](scripting.md) is the reference for the
`ttd("...")` commands underneath.

## Setting up

The module is `scripts/ida_ttd.py`, installed as
`plugins\ida-ttd-python\ida_ttd.py` beside the plugin. When the plugin loads it
puts that folder on IDAPython's `sys.path`, so there is nothing else to do:

```python
import ida_ttd
```

Where the plugin is not loaded yet (an idalib worker may not load plugins on its
own), run the file and load it:

```python
exec(open(r"C:\Program Files\IDA Professional 9.4\plugins\ida-ttd-python\ida_ttd.py").read())
ensure_loaded()
```

## Two ways in

- **`Session`** drives the TTD debugger session in this IDA: the same replay
  the toolbar steps through, over the recording this database was opened from.
  Moving it moves IDA's views; the analyses are the TTD menu's, writing what
  they write into the database.
- **`Recording`** opens a recording through its backend with no debugger at
  all: a cursor of its own, nothing shown, nothing written. For reading another
  recording, or working headless.

## Values

- **Numbers** -- addresses, register values, sizes, results -- are ints. Every
  `"0x..."` in the plugin's answer is converted, recursively.
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
| `s.calls_to(target, limit)` | `func`, `name`, `pos`, `end`, `tid`, `args`, `ret` | `target` is an address or `"module!Glob*"`. Arguments are decoded from the Win32/phnt metadata where it has the function, else from IDA's types: each is text (`"PAGE_READWRITE"`, `"0x1524B8F8A0 -> 2"`) or, where it is a plain number, an int |
| `s.accesses(lo, hi, kinds, limit)` | `pos`, `pc`, `addr`, `size`, `tid`, `kind` | every read (`"r"`), write (`"w"`) and execute (`"x"`) of `[lo, hi)`; `hi` defaults to `lo + 1` |
| `s.origin(what, size)` | `what`, `value`, `at`, `kind`, `by_pos`, `by_pc`, `insn`, `note` | where a value came from; see below |
| `s.handles(limit)` | `handle`, `type`, `name`, `opened`, `by`, `closed` | every handle the program opened and closed; `opened` is empty for one opened before the recording, `closed` for one still open at the end |
| `s.memory_map(limit)` | `base`, `size`, `protect`, `type`, `use`, `since` | the address space at the current position |
| `s.self_modifying(limit)` | `address`, `size`, `written`, `writer`, `first_run`, `runs` | code the program wrote and then ran |
| `s.strings(min_length, limit)` | `pos`, `address`, `wide`, `text` | every string the program had in memory |
| `s.buffers(limit)` | `address`, `size`, `kind`, `first`, `last`, `writer`, `writes`, `preview` | every buffer it filled |
| `s.call_tree(limit)` | `pos`, `depth`, `site`, `target`, `ret` | the calls the function at the current position made in this run of it |
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
copies) and ends with `kind` saying why:

| `kind` | The value was |
| --- | --- |
| `computed` | made by the instruction (arithmetic, a `lea`, a register changed on the side) |
| `constant` | an immediate in the code |
| `system` | a syscall's result, or memory a syscall wrote (`note` names it) |
| `unchanged` | never changed in what was searched: since the thread began, or from the start of the recording |

Registers are named as in IDA (`rax`, `eax`, `al`, `r12d`, `xmm0`); memory is an
address and a size up to 64 bytes.

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

One recording at a time; `close()` it, or use `with`.

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

## Underneath

Every method is one `ttd()` command. `ida_ttd.call(command, *args)` sends any of
them and returns its JSON answer as a dict, for what the classes do not cover:

```python
ida_ttd.call("help")                # every command and its arguments
ida_ttd.call("backends")
ida_ttd.call("an.coverage", lo, hi) # colour what ran in [lo, hi)
ida_ttd.py(ida_ttd.call("an.memmap"))   # py() converts an answer's "0x..." values
```

From IDC, or without the module: `idc.eval_idc('ttd("state")')` returns the
same JSON as a string.

## For AI agents

- Start with `s.state()` and `s.position`: a session may not be running
  (`s.start()`), and where it is matters to every question about "now".
- Prefer the whole-recording questions over stepping: one `s.accesses(...)` or
  `s.calls_to(...)` answers what a thousand steps would, in one replay.
- `s.origin(...)` is the tool for "where did this value come from"; follow
  `by_pos` with `s.goto` to look around the instruction that set it.
- The first call of an analysis can take minutes on a long recording, and IDA
  does nothing else meanwhile. Pass a small `limit` while exploring, and give
  the call a long timeout.
- Positions are opaque: compare them only through the plugin (`s.goto`), never
  as numbers.
