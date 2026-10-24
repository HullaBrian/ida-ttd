"""End-to-end self-test of ida-ttd, run inside IDA (GUI or an idalib worker).

Drives a real debugger session over the reference sample (the program in the
ttd-traces folder that stores 0x2222222222222222 over 0x1111111111111111 in a
global) and checks every movement and analysis against what it is known to
do. The same checks hold for Microsoft and Sogen recordings of it.

The addresses are found in the database, not hard-coded, because recordings
of more than one build exist: the store is the instruction that writes the
register loaded with the constant, main is the function holding it, and so
on (sample_addresses).

Open the trace (File > Open, or the MCP's open_database), then:

    exec(open(r"...\\scripts\\selftest.py").read())
    run()

Each line of the result is "ok" or "FAIL" with the check's name.

On a Sogen recording, run_sogen() also checks the Sogen-only commands
(syscalls, self-modifying code, and with a registry folder recovered strings
and a fork); see its docstring.
"""
import json
import os
import time

import ida_bytes
import ida_funcs
import ida_nalt
import ida_segment
import idautils
import idc


def T(cmd):
    return json.loads(idc.eval_idc('ttd(%s)' % json.dumps(cmd)))


def sample_addresses():
    """The sample's landmarks in this database, as a dict:

    store      the instruction that writes 0x2222222222222222 over the global
    next       the instruction after it
    glob       the global
    main       the function holding the store
    call       the last call in main before the store; after_call follows it
    crt_call   the CRT's call of main; crt_next and crt_next2 follow it
    text       (start, end) of .text
    """
    text = ida_segment.get_segm_by_name(".text")
    data = ida_bytes.get_bytes(text.start_ea, text.end_ea - text.start_ea) or b""
    # mov reg, 2222222222222222h: REX.W (48, or 49 for r8-r15), B8+r, imm64.
    i = data.find(bytes.fromhex("22" * 8))
    if i < 2:
        raise RuntimeError("the constant 0x2222222222222222 is not in .text: not the reference sample")
    load = text.start_ea + i - 2
    reg = idc.print_operand(load, 0)
    store = load
    while True:
        store = idc.next_head(store, text.end_ea)
        if store == idc.BADADDR:
            raise RuntimeError("no store of %s after %X" % (reg, load))
        if idc.print_insn_mnem(store) == "mov" and idc.print_operand(store, 1) == reg \
                and idc.get_operand_type(store, 0) == idc.o_mem:
            break
    glob = idc.get_operand_value(store, 0)
    main = ida_funcs.get_func(store).start_ea
    call = store
    while True:
        call = idc.prev_head(call, main)
        if call == idc.BADADDR:
            raise RuntimeError("no call in main before the store")
        if idc.print_insn_mnem(call) == "call":
            break
    crt = [x for x in idautils.CodeRefsTo(main, 0) if idc.print_insn_mnem(x) == "call"]
    if len(crt) != 1:
        raise RuntimeError("main is called from %d places, not one" % len(crt))
    crt_next = idc.next_head(crt[0], text.end_ea)
    return {
        "store": store, "next": idc.next_head(store, text.end_ea), "glob": glob, "main": main,
        "call": call, "after_call": idc.next_head(call, text.end_ea),
        "crt_call": crt[0], "crt_next": crt_next, "crt_next2": idc.next_head(crt_next, text.end_ea),
        "text": (text.start_ea, text.end_ea),
    }


def run():
    A = sample_addresses()
    B = ida_nalt.get_imagebase()
    G = A["glob"]
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
    r = T("runto %X" % A["store"])
    chk("runto the store", pc(r) == A["store"], r.get("pos"))
    chk("old value before it", T("read %X 8" % G).get("bytes") == "1111111111111111")
    r = T("step")
    chk("step", pc(r) == A["next"])
    chk("new value after it", T("read %X 8" % G).get("bytes") == "2222222222222222")
    r = T("step back")
    chk("step back", pc(r) == A["store"])

    r = T("runto %X back" % A["call"])
    chk("runto backwards", pc(r) == A["call"])
    call_pos = r.get("pos")
    r = T("over")
    chk("step over a call", pc(r) == A["after_call"])
    r = T("over back")
    chk("step back over the call", pc(r) == A["call"] and r.get("pos") == call_pos, (r.get("pos"), r.get("pc")))

    T("runto %X" % A["store"])
    r = T("out")
    chk("step out of main", pc(r) == A["crt_next"], r.get("pc"))
    r = T("step")
    chk("step after it", pc(r) == A["crt_next2"], r.get("pc"))
    # The CRT's entry tail-jumps to the function that called main, so the call
    # that entered its frame is the system's call of the entry point.
    r = T("out back")
    lp = pc(r) or 0
    image_end = max(idc.get_segm_end(s) for s in idautils.Segments() if B <= s < B + 0x100000)
    chk("step out backwards lands on a call outside the image",
        not (B <= lp < image_end) and idc.print_insn_mnem(lp) == "call", r.get("pc"))
    r = T("runto %X" % A["main"])
    chk("runto main", pc(r) == A["main"])
    r = T("out back")
    chk("step out backwards from main's entry lands on the call", pc(r) == A["crt_call"], r.get("pc"))

    # A write breakpoint on the global, as a user sets one: it stops on the
    # store itself, running forward from main and backward from past it.
    import ida_dbg
    import ida_idd
    T("runto %X" % A["main"])
    chk("write breakpoint accepted", ida_dbg.add_bpt(G, 8, ida_idd.BPT_WRITE))
    r = T("run")
    chk("write breakpoint stops on the store", pc(r) == A["store"], r.get("pc"))
    T("step")
    T("step")
    r = T("run back")
    chk("... and running back into it too", pc(r) == A["store"], r.get("pc"))
    ida_dbg.del_bpt(G)

    lo, hi = A["text"]
    a = T("an.search %X %X rw" % (G, G + 8))
    chk("memory search: one write, one read", a.get("count") == 2 and a["accesses"][0]["kind"] == "Write")
    a = T("an.coverage %X %X" % (lo, hi))
    chk("coverage", a.get("executed", 0) > 600, a.get("executed"))
    # 24 in the first build of the sample, 25 in the second.
    a = T("an.callsites %X %X" % (lo, hi))
    chk("indirect call sites", a.get("sites", 0) >= 24, a.get("sites"))
    a = T("an.trace %X 5" % A["main"])
    # The return value reads "(int)0x0" when main has no type in the database
    # and "(__int64)0" once IDA has guessed one (decompiling it does): compare
    # the number, not the text.
    ret = a["calls"][0]["ret"] if a.get("count") == 1 else ""
    chk("trace main: argc 1, returns 0",
        a.get("count") == 1 and a["calls"][0]["args"][0] == "0x1" and int(ret.rpartition(")")[2], 0) == 0, ret)
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
    that replay the program (recovered strings, forks); without it they are
    skipped. host: allow replaying a recording made against the host, which
    reruns the program's file and network operations on this machine (the
    reference recordings were made that way). fork_path: where the fork goes
    (default: next to the database).
    """
    A = sample_addresses()
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
        T("runto %X" % A["main"])
        path = fork_path or os.path.join(os.path.dirname(idc.get_idb_path()), "selftest-fork.sogttd")
        f = T('an.fork "%s" 4E20 rax=1%s' % (path, extra))
        chk("a fork records", f.get("ok") and f.get("instructions") == 0x4E20 and os.path.exists(path),
            (f.get("instructions"), f.get("error")))
        # The fork as the GUI makes it: fork here, change a register and the
        # global through IDA's own debugger calls, record.
        import ida_dbg
        G = A["glob"]
        T("runto %X" % A["store"])
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
            and sw.get("pc") and int(sw["pc"], 16) == A["store"]
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
