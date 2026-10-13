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
