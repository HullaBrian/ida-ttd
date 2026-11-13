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


def py(value):
    """An answer with its numbers as ints, recursively. The plugin writes a
    number as a "0x..." string and lists its key in the object's "_hex", so
    only those are converted: text that happens to read "0x41" (a string the
    program wrote, a name) stays text. "_hex" itself is dropped."""
    if isinstance(value, dict):
        hexed = set(value.get("_hex", ()))
        out = {}
        for k, v in value.items():
            if k == "_hex":
                continue
            if k in hexed:
                out[k] = [int(x, 16) for x in v] if isinstance(v, list) else int(v, 16)
            else:
                out[k] = py(v)
        return out
    if isinstance(value, list):
        return [py(v) for v in value]
    return value


def _bytes(text):
    """The plugin's hex dump ("??" for unknown bytes, read as 0) as bytes."""
    return bytes(0 if text[i:i + 2] == "??" else int(text[i:i + 2], 16)
                 for i in range(0, len(text) - 1, 2))


def _kinds(kinds):
    """Access kinds as the plugin takes them: any of "r", "w", "x"."""
    k = kinds.lower()
    if not k or any(c not in "rwx" for c in k):
        raise ValueError("access kinds are the letters r, w and x: %r" % kinds)
    return k


def _record_options(net, checkpoint_interval, access, elevated, log):
    """The recording options as an.fork / an.record words; None keeps the
    Sogen setting."""
    words = []
    if net is not None:
        words.append("net" if net else "nonet")
    if checkpoint_interval is not None:
        words.append("ckpt=%X" % checkpoint_interval)
    if access is not None:
        words.append("access=" + _kinds(access))
    if elevated:
        words.append("elevated")
    if log:
        words.append("log")
    return words


def record(program, path, max_instructions=0, args=None, cwd=None, registry=None,
           root=None, host=False, net=None, checkpoint_interval=None, access=None,
           elevated=False, log=False, place=None, replace=False, start=None):
    """Run 'program' from its start in Sogen's emulator and record it into
    'path' (TTD > Backends > Record a program with Sogen), with no recording
    open. Without 'root' (an emulation root) it runs against this machine's
    files, which needs host=True; 'registry' is the hives folder (default:
    the first known one). net, checkpoint_interval, access ("rwx") default to
    the Sogen settings. With a root, 'place' (a guest folder such as
    "C:\\ida-ttd") copies a program from outside the root into it first;
    replace=True overwrites a different file already there. 'start' is
    "now", "1970" or a UTC "YYYY-MM-DDTHH:MM:SS", the date the program
    starts at (default: the sogen_start_now setting). Returns
    {"instructions", "cancelled", "path", "network", "program", "placed"}."""
    words = [program, path]
    if max_instructions:
        words.append(max_instructions)
    for key, value in (("args", args), ("cwd", cwd), ("registry", registry), ("root", root),
                       ("place", place), ("start", start)):
        if value:
            words.append("%s=%s" % (key, value))
    if host:
        words.append("host")
    if replace:
        words.append("replace")
    words += _record_options(net, checkpoint_interval, access, elevated, log)
    return py(call("an.record", *words))


class Session(object):
    """The TTD debugger session in this IDA: the recording this database was
    opened from, replayed through IDA's debugger. Movements wait for the stop;
    the analyses are the TTD menu's, without their windows."""

    # ---- state and movement ----------------------------------------------
    def start(self, timeout=120):
        """Start the replay and wait for the first stop. Fails when a
        debugging session is already running."""
        return py(call("start", "timeout=%X" % timeout))

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

    # Each movement waits for the stop, 'timeout' seconds at most (the
    # answer then has "timed_out", and the replay is still moving).
    def _move(self, what, back, timeout, *args):
        words = list(args) + (["back"] if back else [])
        if timeout is not None:
            words.append("timeout=%X" % timeout)
        return py(call(what, *words))

    def step(self, back=False, timeout=None):
        return self._move("step", back, timeout)

    def step_over(self, back=False, timeout=None):
        return self._move("over", back, timeout)

    def step_out(self, back=False, timeout=None):
        return self._move("out", back, timeout)

    def run(self, back=False, timeout=None):
        """To the next breakpoint, or the edge of the recording."""
        return self._move("run", back, timeout)

    def run_to(self, ea, back=False, timeout=None):
        return self._move("runto", back, timeout, ea)

    def goto(self, position, timeout=None):
        # A position is passed as written: Sogen's are decimal step counts.
        words = [str(position)] + ([] if timeout is None else ["timeout=%X" % timeout])
        return py(call("goto", *words))

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

    # The handle of the recording drv.* drives now: opening another closes
    # this one in the plugin, so an older object must refuse to go on.
    _current = None

    def __init__(self, path, backend=None):
        args = [path] + ([backend] if backend else [])
        self.info = py(call("drv.open", *args))
        self._handle = self.info.get("handle")
        Recording._current = self._handle

    def _call(self, command, *args):
        if self._handle is None or Recording._current != self._handle:
            raise TtdError("%s: this Recording was closed, or another one was opened "
                           "since (one at a time)" % command)
        return call(command, *args)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        """Close it; closing one already closed, or superseded, does nothing."""
        if self._handle is not None and Recording._current == self._handle:
            call("drv.close")
            Recording._current = None
        self._handle = None

    # ---- the cursor --------------------------------------------------------
    def where(self):
        """The cursor: position, thread, pc, sp."""
        return py(self._call("drv.pos"))

    @property
    def position(self):
        return self._call("drv.pos")["pos"]

    def seek(self, position):
        """A position, or "first" / "last"."""
        return py(self._call("drv.seek", str(position)))

    def step(self, back=False):
        return py(self._call("drv.step", *(["back"] if back else [])))

    def step_over(self, back=False):
        return py(self._call("drv.over", *(["back"] if back else [])))

    def step_out(self, back=False):
        return py(self._call("drv.out", *(["back"] if back else [])))

    def run(self, back=False):
        """To a breakpoint set with breakpoints(), or the edge."""
        return py(self._call("drv.run", *(["back"] if back else [])))

    def run_to(self, ea, back=False):
        return py(self._call("drv.runto", ea, *(["back"] if back else [])))

    def breakpoints(self, *bps):
        """Replace the breakpoints: addresses, or (ea, size, "rwx") tuples."""
        args = []
        for b in bps:
            if isinstance(b, tuple):
                args.append("%X:%X:%s" % (b[0], b[1], _kinds(b[2])))
            else:
                args.append(_arg(b))
        return py(self._call("drv.bp", *args))

    def regs(self):
        return py(self._call("drv.regs")["regs"])

    def read(self, ea, size=0x40):
        """Memory at the cursor; bytes the recording does not have read as 0."""
        return _bytes(self._call("drv.read", ea, size)["bytes"])

    def instructions(self, n=16):
        return py(self._call("drv.insns", n)["instructions"])

    # ---- the recording -------------------------------------------------------
    def modules(self):
        return py(self._call("drv.modules")["modules"])

    def threads(self, live=False):
        return py(self._call("drv.threads", *(["live"] if live else []))["threads"])

    def timeline(self, limit=10000):
        return py(self._call("drv.timeline", limit)["events"])

    def accesses(self, lo, hi=None, kinds="rw", limit=10000):
        hi = lo + 1 if hi is None else hi
        return py(self._call("drv.accesses", lo, hi, _kinds(kinds), limit)["accesses"])

    def calls_to(self, ea, limit=10000):
        return py(self._call("drv.calls", ea, limit)["calls"])

    def syscalls(self, limit=100000):
        return py(self._call("drv.syscalls", limit)["syscalls"])

    def exceptions(self):
        return py(self._call("drv.exceptions")["exceptions"])

    def memory_changes(self, limit=100000):
        return py(self._call("drv.map", limit)["changes"])
