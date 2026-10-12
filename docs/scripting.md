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
| `drv.accesses LO HI [rwx] [MAX]`, `drv.calls EA [MAX]`, `drv.indirect LO HI [jumps]`, `drv.exceptions`, `drv.map [MAX]`, `drv.symbols BASE [MAX]` | whole-trace queries |
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

`help` lists every command with its arguments, and `backends` lists the loaded
backend DLLs.

## From the IDA MCP

The MCP runs Python against a GUI database when IDA is open, and in a headless
idalib worker otherwise. In either, either:

```python
exec(open(r"C:\path\to\ida-ttd\scripts\ida_ttd.py").read())
ensure_loaded()
call("state")
```

`ensure_loaded()` loads `ida-ttd` from IDA's plugins directory when the worker
has not. The plugin must be installed there, along with any backends in
`plugins\ida-ttd-backends`.
