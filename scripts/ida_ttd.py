"""Drive the ida-ttd plugin from Python inside IDA.

Installed in ida-ttd-python/ beside the plugin DLL, which the plugin puts on
sys.path when it loads. In the IDAPython console, a script, or an MCP
server's Python:

    import ida_ttd
    s = ida_ttd.Session()                # the TTD debugger session in this IDA
    s.start()                            # replay the recording this database is for
    s.position, hex(s.pc)
    s.step(); s.step(back=True)
    s.goto("1A:2F")
    s.regs()["rax"]
    s.read(s.reg("rsp"), 0x40)           # bytes
    for c in s.syscalls(): print(c["name"], hex(c["result"]))
    s.origin("rax")                      # where the value in rax came from
    s.origin(0x1234, 8)                  # ... or the 8 bytes at 0x1234
    s.handles(); s.memory_map(); s.calls_to("kernel32!CreateFileW")

    r = ida_ttd.Recording(r"C:\\traces\\run.sogttd")   # a recording, no debugger
    r.seek("first"); r.step(); r.regs(); r.read(0x401000, 16)

Underneath is one IDC function, ttd("command args..."), which answers in
JSON. call() sends a command and returns the answer as a dict; the classes
turn answers into Python values (addresses and numbers as ints, bytes as
bytes). Positions stay strings in the recording's own syntax
("Sequence:Steps" for Microsoft TTD, a step count for Sogen) and are passed
back unchanged. A failure raises TtdError with the plugin's reason.
call("help") lists every command; docs/scripting.md describes them.

It works the same in the GUI, in idat, and in an idalib worker. Without the
plugin loaded, exec() this file's source and call ensure_loaded().
"""

import json
import re

import ida_expr
import ida_idaapi
import ida_loader


class TtdError(RuntimeError):
    """The plugin answered {"ok": false, "error": ...}."""


def _quote(arg):
    s = str(arg)
    if not s or any(c in s for c in ' \t"'):
        if '"' in s:
            raise ValueError("arguments cannot contain double quotes: %r" % s)
        return '"%s"' % s
    return s


def _arg(v):
    """A command argument: ints go as hex, the plugin's number syntax."""
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, int):
        return "%X" % v
    return v


def loaded():
    """Whether the plugin's ttd() function exists in this IDA."""
    rv = ida_expr.idc_value_t()
    return ida_expr.eval_idc_expr(rv, ida_idaapi.BADADDR, 'ttd("help")') is None


def ensure_loaded(plugin="ida-ttd"):
    """Load the plugin if this IDA has not (an idalib worker may not load
    plugins on its own). 'plugin' is a name in IDA's plugins directory or a
    full path to the DLL."""
    if loaded():
        return True
    ida_loader.load_plugin(plugin)
    return loaded()


def raw(line):
    """Send one command line and return the parsed answer, failed or not."""
    rv = ida_expr.idc_value_t()
    # json.dumps writes a valid IDC string literal for anything a command
    # line contains: quotes and backslashes are escaped the same way.
    err = ida_expr.eval_idc_expr(rv, ida_idaapi.BADADDR,
                                 "ttd(%s)" % json.dumps(line, ensure_ascii=False))
    if err is not None:
        raise TtdError("ttd() is not available (%s); is the plugin loaded? "
                       "Try ensure_loaded()." % err)
    return json.loads(rv.c_str())


def call(command, *args):
    """Run a command; return its answer, or raise TtdError."""
    line = " ".join([command] + [_quote(_arg(a)) for a in args])
    answer = raw(line)
    if not answer.get("ok"):
        raise TtdError("%s: %s" % (command, answer.get("error", "failed")))
    return answer


def h(value):
    """An answer's "0x..." string as an int."""
    return int(value, 16)


_HEX = re.compile(r"^0x[0-9a-fA-F]+$")


# Keys whose values are free text (recovered strings, names, paths, notes,
# messages), kept as they are even when one reads "0x41": a string the
# program wrote is not a number. Every other "0x..." value is an address or
# a number the plugin wrote in hex.
_TEXT_KEYS = frozenset((
    "text", "preview", "name", "path", "file", "dir", "comment", "note", "notice",
    "error", "why", "command", "commands", "trace", "main_module", "backend_name",
    "label", "title", "status", "filter", "symbol_server", "emulation_root",
    "registry_folder", "registry_hint", "chosen_root", "event_log", "windows_version",
))


def py(value):
    """An answer with every "0x..." string turned into an int, recursively,
    except under keys that hold free text (_TEXT_KEYS)."""
    if isinstance(value, dict):
        return {k: v if k in _TEXT_KEYS else py(v) for k, v in value.items()}
    if isinstance(value, list):
        return [py(v) for v in value]
    if isinstance(value, str) and _HEX.match(value):
        return int(value, 16)
    return value


def _bytes(text):
    """The plugin's hex dump ("??" for unknown bytes, read as 0) as bytes."""
    return bytes(0 if text[i:i + 2] == "??" else int(text[i:i + 2], 16)
                 for i in range(0, len(text) - 1, 2))


def _kinds(kinds):
    return "".join(k for k in kinds.lower() if k in "rwx") or "rw"


class Session(object):
    """The TTD debugger session in this IDA: the recording this database was
    opened from, replayed through IDA's debugger. Movements wait for the stop;
    the analyses are the TTD menu's, without their windows."""

    # ---- state and movement ----------------------------------------------
    def start(self, timeout=120):
        """Start the replay (if it is not running) and wait for the first stop."""
        return py(call("start", timeout))

    def stop(self):
        """End the session."""
        return py(call("stop"))

    def state(self):
        return py(call("state"))

    @property
    def position(self):
        """Where the replay is, in the recording's own position syntax."""
        return call("state").get("pos")

    @property
    def pc(self):
        return h(call("state")["pc"])

    def _move(self, what, back, *args):
        return py(call(what, *(list(args) + (["back"] if back else []))))

    def step(self, back=False):
        return self._move("step", back)

    def step_over(self, back=False):
        return self._move("over", back)

    def step_out(self, back=False):
        return self._move("out", back)

    def run(self, back=False):
        """To the next breakpoint, or the edge of the recording."""
        return self._move("run", back)

    def run_to(self, ea, back=False):
        return self._move("runto", back, ea)

    def goto(self, position):
        # A position is passed as written: Sogen's are decimal step counts.
        return py(call("goto", str(position)))

    # ---- what is there -----------------------------------------------------
    def regs(self):
        """The registers IDA shows, by lower-case name."""
        return py(call("regs")["regs"])

    def reg(self, name):
        return self.regs()[name.lower()]

    def read(self, ea, size=0x40):
        """Memory as IDA reads it at the current position."""
        return _bytes(call("read", ea, size)["bytes"])

    def segments(self, limit=400):
        return py(call("segments", limit)["segments"])

    # ---- whole-recording questions -----------------------------------------
    def syscalls(self, limit=100000):
        """Every syscall: position, thread, number, name, result, arguments."""
        return py(call("an.syscalls", limit)["syscalls"])

    def calls_to(self, target, limit=10000):
        """Every call to a function (an address, or "module!Glob*") with its
        arguments and return value."""
        return py(call("an.trace", target, limit)["calls"])

    def accesses(self, lo, hi=None, kinds="rw", limit=10000):
        """Every read, write or execute ("r", "w", "x") of [lo, hi)."""
        hi = lo + 1 if hi is None else hi
        return py(call("an.search", lo, hi, _kinds(kinds), limit)["accesses"])

    def origin(self, what, size=8, at=None, through=True):
        """Where a value came from: what is a register name ("rax", "xmm0") or
        an address (with 'size' bytes), as of the current position, or of
        'at' (a position) when given. The chain of hops back to where the
        value was made, the first hop first. It goes through computations
        made from a single value; through=False stops at every computation."""
        tail = (["from=" + at] if at else []) + ([] if through else ["stop"])
        if isinstance(what, str):
            return py(call("an.origin", what, *tail)["chain"])
        return py(call("an.origin", "mem", what, size, *tail)["chain"])

    def origin_graph(self, what, size=8, at=None, max_nodes=60):
        """Every chain at once, as the value origin graph draws it: at each
        instruction that combined several values, each value it read is
        followed (address registers and rsp are not). 'nodes' are hops as
        origin() gives them, [0] the value asked about; each of 'edges' goes
        'from' the hop that used a value 'to' the hop that set it ('input':
        one of several the instruction read). 'truncated' when max_nodes cut
        it short."""
        tail = (["from=" + at] if at else []) + ["max=%x" % max_nodes]
        if isinstance(what, str):
            return py(call("an.origingraph", what, *tail))
        return py(call("an.origingraph", "mem", what, size, *tail))

    def show_origin_graph(self, what, size=8, at=None):
        """Open the value origin graph window for a value, as the TTD menu
        does, without asking for it."""
        tail = ["from=" + at] if at else []
        if isinstance(what, str):
            return call("ui.origingraph", what, *tail)
        return call("ui.origingraph", "mem", what, size, *tail)

    def inputs(self, at=None):
        """The values the instruction about to run at 'at' (default: the
        current position) read: each has 'what', 'value', 'address' (true for
        a register that only formed an address), and 'reg', or 'addr' and
        'size'. Pass a hop's 'by_pos' to continue a chain that ended at a
        computation, then origin(..., at=that by_pos) on the input."""
        r = call("an.inputs", at) if at else call("an.inputs")
        return py(r["inputs"])

    def handles(self, limit=100000):
        """The handles the program opened and closed."""
        return py(call("an.handles", limit)["handles"])

    def memory_map(self, limit=100000):
        """The regions at the current position: base, size, protection, type, use."""
        return py(call("an.regions", limit)["regions"])

    def self_modifying(self, limit=100000):
        return py(call("an.selfmod", limit)["hits"])

    def strings(self, min_length=8, limit=100000):
        return py(call("an.strings", min_length, limit)["strings"])

    def buffers(self, limit=100000):
        return py(call("an.buffers", limit)["buffers"])

    def call_tree(self, limit=100000):
        """The calls the function at the current position made in this run of it."""
        return py(call("an.calltree", limit)["calls"])

    def heat(self):
        """The memory heatmap's counts: per page, per slice of time,
        [slice, reads, writes, executes]."""
        call("an.heat")
        return call("ui.heat")["heat"]


class Recording(object):
    """A recording opened through its backend, without the debugger: a cursor
    to move and read at, and the backend's queries. One at a time; close() it,
    or use it as a context manager."""

    def __init__(self, path, backend=None):
        args = [path] + ([backend] if backend else [])
        self.info = py(call("drv.open", *args))

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        call("drv.close")

    # ---- the cursor --------------------------------------------------------
    def where(self):
        """The cursor: position, thread, pc, sp."""
        return py(call("drv.pos"))

    @property
    def position(self):
        return call("drv.pos")["pos"]

    def seek(self, position):
        """A position, or "first" / "last"."""
        return py(call("drv.seek", str(position)))

    def step(self, back=False):
        return py(call("drv.step", *(["back"] if back else [])))

    def step_over(self, back=False):
        return py(call("drv.over", *(["back"] if back else [])))

    def step_out(self, back=False):
        return py(call("drv.out", *(["back"] if back else [])))

    def run(self, back=False):
        """To a breakpoint set with breakpoints(), or the edge."""
        return py(call("drv.run", *(["back"] if back else [])))

    def run_to(self, ea, back=False):
        return py(call("drv.runto", ea, *(["back"] if back else [])))

    def breakpoints(self, *bps):
        """Replace the breakpoints: addresses, or (ea, size, "rwx") tuples."""
        args = []
        for b in bps:
            if isinstance(b, tuple):
                args.append("%X:%X:%s" % (b[0], b[1], _kinds(b[2])))
            else:
                args.append(_arg(b))
        return py(call("drv.bp", *args))

    def regs(self):
        return py(call("drv.regs")["regs"])

    def read(self, ea, size=0x40):
        """Memory at the cursor; bytes the recording does not have read as 0."""
        return _bytes(call("drv.read", ea, size)["bytes"])

    def instructions(self, n=16):
        return py(call("drv.insns", n)["instructions"])

    # ---- the recording -------------------------------------------------------
    def modules(self):
        return py(call("drv.modules")["modules"])

    def threads(self, live=False):
        return py(call("drv.threads", *(["live"] if live else []))["threads"])

    def timeline(self, limit=10000):
        return py(call("drv.timeline", limit)["events"])

    def accesses(self, lo, hi=None, kinds="rw", limit=10000):
        hi = lo + 1 if hi is None else hi
        return py(call("drv.accesses", lo, hi, _kinds(kinds), limit)["accesses"])

    def calls_to(self, ea, limit=10000):
        return py(call("drv.calls", ea, limit)["calls"])

    def syscalls(self, limit=100000):
        return py(call("drv.syscalls", limit)["syscalls"])

    def exceptions(self):
        return py(call("drv.exceptions")["exceptions"])

    def memory_changes(self, limit=100000):
        return py(call("drv.map", limit)["changes"])
