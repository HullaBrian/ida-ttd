"""Drive the ida-ttd plugin from Python inside IDA.

The plugin registers one IDC function, ttd("command args..."), which answers
with JSON. This module wraps it:

    import ida_ttd
    ida_ttd.call("state")
    ida_ttd.call("drv.open", r"C:\\traces\\run.sogttd")
    ida_ttd.call("drv.seek", "1000")
    ida_ttd.call("drv.regs")["regs"]["rip"]

It works the same in the GUI, in idat, and in an idalib worker such as the one
an MCP server runs Python in -- which is the point: the plugin can be tested
by a script instead of by a person describing what they saw.

Numbers in arguments are hex. Addresses and positions in answers are strings
("0x...") so 64-bit values survive JSON. A failure raises TtdError with the
plugin's reason. call("help") lists the commands; docs/scripting.md describes
them.

Nothing here needs anything beyond IDAPython. To use it from an MCP session
without installing the file, exec() its source.
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
    line = " ".join([command] + [_quote(a) for a in args])
    answer = raw(line)
    if not answer.get("ok"):
        raise TtdError("%s: %s" % (command, answer.get("error", "failed")))
    return answer


def h(value):
    """An answer's "0x..." string as an int."""
    return int(value, 16)
