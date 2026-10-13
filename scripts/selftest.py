"""End-to-end self-test of ida-ttd, run inside IDA (GUI or an idalib worker).

Drives a real debugger session over the reference sample -- the program in
the ttd-traces folder that stores 0x2222222222222222 over 0x1111111111111111
at image base + 0x70A8 -- and checks every movement and analysis against
what that program is known to do. The same checks hold for a Microsoft
recording and a Sogen one of it.

Open the trace (File > Open, or the MCP's open_database), then:

    exec(open(r"...\\scripts\\selftest.py").read())
    run()                    # base of the recorded image, from the database

Each line of the result is "ok" or "FAIL" with the check's name.

On a Sogen recording, run_sogen() also checks the Sogen-only commands
(syscalls, self-modifying code, and with a registry folder recovered strings
and a fork); see its docstring.
"""
import json
import time

import ida_nalt
import idc


def T(cmd):
    return json.loads(idc.eval_idc('ttd(%s)' % json.dumps(cmd)))


def run(base=None):
    B = base if base is not None else ida_nalt.get_imagebase()
    G = B + 0x70A8                       # the global the sample overwrites
    res, fails = [], []

    def chk(name, cond, detail=""):
        res.append(("ok  " if cond else "FAIL") + " " + name + (" " + str(detail) if detail != "" else ""))
        if not cond:
            fails.append(name)

    def pc(r):
        return int(r["pc"], 16) if r.get("pc") else None

    t0 = time.time()
    r = T("start B4")
    chk("start", r.get("ok") and r.get("process_state") == -1, r.get("pos"))
    r = T("runto %X" % (B + 0x14E7))
    chk("runto the store", pc(r) == B + 0x14E7, r.get("pos"))
    chk("old value before it", T("read %X 8" % G).get("bytes") == "1111111111111111")
    r = T("step")
    chk("step", pc(r) == B + 0x14EE)
    chk("new value after it", T("read %X 8" % G).get("bytes") == "2222222222222222")
    r = T("step back")
    chk("step back", pc(r) == B + 0x14E7)

    r = T("runto %X back" % (B + 0x14D0))
    chk("runto backwards", pc(r) == B + 0x14D0)
    call_pos = r.get("pos")
    r = T("over")
    chk("step over a call", pc(r) == B + 0x14D6)
    r = T("over back")
    chk("step back over the call", pc(r) == B + 0x14D0 and r.get("pos") == call_pos, (r.get("pos"), r.get("pc")))

    T("runto %X" % (B + 0x14E7))
    r = T("out")
    chk("step out of main", pc(r) == B + 0x196F, r.get("pc"))
    r = T("step")
    chk("step after it", pc(r) == B + 0x1971, r.get("pc"))
    # The CRT's entry tail-jumps to the function that called main, so the call
    # that entered its frame is the system's call of the entry point.
    r = T("out back")
    lp = pc(r) or 0
    chk("step out backwards lands on a call outside the image",
        not (B <= lp < B + 0xB000) and idc.print_insn_mnem(lp) == "call", r.get("pc"))
    r = T("runto %X" % (B + 0x13F0))
    chk("runto main", pc(r) == B + 0x13F0)
    r = T("out back")
    chk("step out backwards from main's entry lands on the call", pc(r) == B + 0x196A, r.get("pc"))

    # A write breakpoint on the global, as a user sets one: it stops on the
    # store itself, running forward from main and backward from past it.
    import ida_dbg
    import ida_idd
    T("runto %X" % (B + 0x13F0))
    chk("write breakpoint accepted", ida_dbg.add_bpt(G, 8, ida_idd.BPT_WRITE))
    r = T("run")
    chk("write breakpoint stops on the store", pc(r) == B + 0x14E7, r.get("pc"))
    T("step")
    T("step")
    r = T("run back")
    chk("... and running back into it too", pc(r) == B + 0x14E7, r.get("pc"))
    ida_dbg.del_bpt(G)

    a = T("an.search %X %X rw" % (G, G + 8))
    chk("memory search: one write, one read", a.get("count") == 2 and a["accesses"][0]["kind"] == "Write")
    a = T("an.coverage %X %X" % (B + 0x1000, B + 0x2578))
    chk("coverage", a.get("executed", 0) > 600, a.get("executed"))
    a = T("an.callsites %X %X" % (B + 0x1000, B + 0x2578))
    chk("indirect call sites", a.get("sites") == 24, a.get("sites"))
    a = T("an.trace %X 5" % (B + 0x13F0))
    chk("trace main: argc 1, returns 0",
        a.get("count") == 1 and a["calls"][0]["args"][0] == "0x1" and a["calls"][0]["ret"] == "(int)0x0")
    a = T("an.memmap 4")
    chk("memory map", a.get("changes", 0) > 50, a.get("changes"))

    r = T("state")
    chk("still responsive", r.get("session") and r.get("process_state") == -1)
    r = T("stop")
    chk("stop", r.get("process_state") == 0, r.get("process_state"))
    res.append("%.1f s, %d failed" % (time.time() - t0, len(fails)))
    return res


def run_sogen(registry=None, host=False, fork_path=None):
    """The Sogen-only commands, on a Sogen recording of the same sample.

    registry: a folder of registry hives (SYSTEM, SOFTWARE, ...) for the checks
    that replay the program -- recovered strings and a fork; without it those
    are skipped. host: allow replaying a recording made against the host,
    which runs the program's file and network operations on this machine
    again (the reference recordings were made that way). fork_path: where the
    fork goes (default: next to the database).
    """
    import os
    res, fails = [], []

    def chk(name, cond, detail=""):
        res.append(("ok  " if cond else "FAIL") + " " + name + (" " + str(detail) if detail != "" else ""))
        if not cond:
            fails.append(name)

    t0 = time.time()
    r = T("start B4")
    chk("start", r.get("ok") and r.get("process_state") == -1, r.get("pos"))

    s = T("an.syscalls 5")
    chk("syscalls listed and named", s.get("ok") and s.get("count", 0) > 0 and s["syscalls"][0]["name"] != "",
        (s.get("count"), s.get("error")))
    chk("syscall arguments read", s.get("ok") and "args" in s["syscalls"][0], s.get("error"))

    m = T("an.selfmod 5")
    chk("self-modifying code search runs", m.get("ok"), (m.get("count"), m.get("error")))

    if registry:
        extra = ' registry="%s"%s' % (registry, " host" if host else "")
        st = T("an.strings 8 5" + extra)
        chk("strings recovered by a replay", st.get("ok") and st.get("count", 0) > 0,
            (st.get("count"), st.get("error")))
        T("runto %X" % (ida_nalt.get_imagebase() + 0x13F0))
        path = fork_path or os.path.join(os.path.dirname(idc.get_idb_path()), "selftest-fork.sogttd")
        f = T('an.fork "%s" 4E20 rax=1%s' % (path, extra))
        chk("a fork records", f.get("ok") and f.get("instructions") == 0x4E20 and os.path.exists(path),
            (f.get("instructions"), f.get("error")))
        # The fork as the GUI makes it: fork here, change a register and the
        # global through IDA's own debugger calls, record.
        import ida_dbg
        B = ida_nalt.get_imagebase()
        G = B + 0x70A8
        T("runto %X" % (B + 0x14E7))
        T("an.forkhere")
        ok_reg = ida_dbg.set_reg_val("RAX", 0x1234)
        ok_mem = ida_dbg.write_dbg_memory(G, bytes.fromhex("33" * 8)) == 8
        d = T("an.forkdraft")
        chk("fork here takes IDA's register and memory writes",
            ok_reg and ok_mem and len(d.get("regs", [])) == 1 and len(d.get("memory", [])) == 1, d)
        chk("... and shows them there",
            ida_dbg.get_reg_val("RAX") == 0x1234 and idc.read_dbg_memory(G, 8) == bytes.fromhex("33" * 8))
        T("step")
        moved = idc.read_dbg_memory(G, 8)
        chk("elsewhere the recording is read-only",
            moved == bytes.fromhex("22" * 8) and ida_dbg.write_dbg_memory(G, bytes.fromhex("44")) != 1, moved)
        T("step back")
        chk("back at the fork the changes show again", idc.read_dbg_memory(G, 8) == bytes.fromhex("33" * 8))
        path2 = path.replace(".sogttd", "-draft.sogttd")
        f = T('an.forkrecord "%s" 4E20%s' % (path2, extra))
        chk("the fork records with its changes",
            f.get("ok") and f.get("regs") == 1 and f.get("writes") == 1 and os.path.exists(path2),
            (f.get("instructions"), f.get("error")))
        T("an.forkdiscard")
        chk("discarding it shows the recording again", idc.read_dbg_memory(G, 8) == bytes.fromhex("11" * 8))

        # The Fork manager's list, and switching the replay to the fork and
        # back, in this database.
        forks = T("an.forks").get("forks", [])
        mine = [x for x in forks if os.path.normcase(x["path"]) == os.path.normcase(path2)]
        chk("the fork is in the fork list, with its parent and change",
            len(mine) == 1 and mine[0]["changes"] == "rax=0x1234, 8 bytes at 0x%X" % G, mine)
        parent = mine[0]["parent"] if mine else ""
        sw = T('switch "%s"' % path2)
        chk("switching replays the fork in this database",
            sw.get("ok") and os.path.normcase(sw.get("trace", "")) == os.path.normcase(path2)
            and sw.get("pc") and int(sw["pc"], 16) == B + 0x14E7
            and ida_dbg.get_reg_val("RAX") == 0x1234 and idc.read_dbg_memory(G, 8) == bytes.fromhex("33" * 8),
            (sw.get("trace"), sw.get("pc"), sw.get("error")))
        sw = T('switch "%s"' % parent)
        chk("... and back to the recording", sw.get("ok") and os.path.normcase(sw.get("trace", "")) == os.path.normcase(parent),
            (sw.get("trace"), sw.get("error")))
        for x in (path, path2):
            T('an.forget "%s"' % x)
    else:
        res.append("skip strings and fork: no registry folder given")

    r = T("stop")
    chk("stop", r.get("process_state") == 0, r.get("process_state"))
    res.append("%.1f s, %d failed" % (time.time() - t0, len(fails)))
    return res
