// The drv.* script commands: a recording opened through a backend, with
// no debugger session, to exercise the backend and the core's adapter.
#include "plugin/script_internal.h"
#include "core/backend_registry.h"
#include "core/backend_module.h"
#include "analysis/query_runner.h"

namespace idattd
{
    Driver g_drv;

    static ITraceBackend &drv()
    {
        if ( g_drv.backend == nullptr || !g_drv.backend->is_open() )
            fail("no recording is open for drv.*; use 'drv.open PATH'");
        return *g_drv.backend;
    }

    static const char *stop_name(StopReason r)
    {
        switch ( r )
        {
            case StopReason::Stepped:       return "stepped";
            case StopReason::Breakpoint:    return "breakpoint";
            case StopReason::TraceBoundary: return "boundary";
            default:                        return "failed";
        }
    }

    static qstring regs_json(const ittd_regs &r)
    {
        static const char *gp[ITTD_REG_GP_COUNT] = {
            "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip",
        };
        JObj o;
        if ( (r.have & ITTD_REGS_GP) == 0 )
            return o.boolean("known", false).done();
        for ( int i = 0; i < ITTD_REG_GP_COUNT; i++ )
            o.hex(gp[i], r.gp[i]);
        o.hex("rflags", r.rflags).hex("fs_base", r.fs_base).hex("gs_base", r.gs_base);
        return o.done();
    }

    qstring bytes_json(const uint8_t *buf, const uint8_t *known, size_t n)
    {
        // Hex pairs, "??" for a byte the recording does not account for.
        qstring s;
        for ( size_t i = 0; i < n; i++ )
        {
            if ( known != nullptr && known[i] == ITTD_KNOWN_NO )
                s.append("??");
            else
                s.cat_sprnt("%02x", buf[i]);
        }
        qstring j;
        json_escape(&j, s.c_str());
        return j;
    }

    static qstring position_text(ITraceBackend &b, Position p) { return b.format_position(p); }
    static Position from_abi_position(ittd_position p) { return Position{ p.hi, p.lo }; }

    // ------------------------------------------------------------------ drv.*

    static void cmd_drv_open(const Args &a, JObj &out)
    {
        const qstring &path = a.at(0);
        g_drv.close();
        load_backend_modules();
        ITraceBackend *kind = a.count() > 1 ? BackendRegistry::instance().by_id(a.at(1).c_str())
                                            : BackendRegistry::instance().for_file(path.c_str());
        if ( kind == nullptr )
            fail("no loaded backend handles %s", path.c_str());
        g_drv.owned = kind->new_instance();
        if ( g_drv.owned == nullptr )
            fail("the %s backend cannot open a recording beside the debugger's", kind->id());
        ITraceBackend *b = g_drv.owned.get();
        qstring err;
        if ( !b->open(path.c_str(), &err) )
        {
            qstring id = b->id();
            g_drv.close();
            fail("%s could not open %s: %s", id.c_str(), path.c_str(), err.c_str());
        }
        // As a session does: without it a Microsoft trace has no memory
        // index and reads come back mostly empty.
        prepare_backend(b);
        g_drv.backend = b;
        g_drv.path    = path;
        g_drv.cursor  = b->make_cursor();
        if ( g_drv.cursor )
            g_drv.nav = b->make_navigator(g_drv.cursor.get());
        // Every other drv.* command needs both; do not leave it half-usable.
        if ( !g_drv.cursor || !g_drv.nav )
        {
            qstring id = b->id();
            g_drv.close();
            fail("%s opened the recording but made no cursor", id.c_str());
        }
        g_drv.cursor->seek(b->info().first);
        g_drv.handle++;
        out.str("backend", b->id()).num("handle", (int64_t)g_drv.handle);
    }

    static void cmd_drv_info(const Args &, JObj &out)
    {
        ITraceBackend &b = drv();
        const TraceInfo &ti = b.info();
        const Capabilities &c = b.capabilities();
        JObj caps;
        caps.boolean("access_queries", c.access_queries).boolean("call_queries", c.call_queries)
            .boolean("mapping_changes", c.mapping_changes).boolean("syscalls", c.syscalls)
            .boolean("recorded_exports", c.recorded_exports)
            .boolean("batch_regs", c.batch_regs)
            .boolean("reverse_step", c.reverse_step).boolean("exceptions", c.exceptions)
            .boolean("cheap_reads", c.cheap_reads).boolean("self_modifying", c.self_modifying)
            .boolean("fork", c.fork).boolean("replay_scans", c.replay_scans);
        out.str("backend", b.id()).str("backend_name", ti.backend_name).str("path", g_drv.path)
           .str("main_module", ti.main_module).boolean("is64", ti.is64)
           .hex("fingerprint", ti.fingerprint)
           .str("first", position_text(b, ti.first)).str("last", position_text(b, ti.last))
           .str("position_syntax", b.position_syntax()).raw("capabilities", caps.done());
    }

    static void cmd_drv_modules(const Args &, JObj &out)
    {
        ITraceBackend &b = drv();
        JArr arr;
        for ( const ModuleInfo &m : b.modules() )
        {
            JObj o;
            o.str("name", m.name).str("path", m.path).hex("base", m.base).hex("size", m.size)
             .num("machine", m.machine).str("loaded", position_text(b, m.loaded))
             .str("unloaded", position_text(b, m.unloaded));
            arr.add(o.done());
        }
        out.raw("modules", arr.done());
    }

    static qstring thread_json(ITraceBackend &b, const ThreadInfo &t)
    {
        JObj o;
        o.num("tid", t.tid).str("name", t.name).str("created", position_text(b, t.created))
         .str("exited", position_text(b, t.exited)).hex("teb", t.teb)
         .hex("stack_base", t.stack_base).hex("stack_limit", t.stack_limit);
        return o.done();
    }

    static void cmd_drv_threads(const Args &a, JObj &out)
    {
        ITraceBackend &b = drv();
        bool live = a.count() > 0 && a.at(0) == "live";
        JArr arr;
        for ( const ThreadInfo &t : live ? g_drv.cursor->live_threads() : b.threads() )
            arr.add(thread_json(b, t));
        out.raw("threads", arr.done());
    }

    static void cmd_drv_timeline(const Args &a, JObj &out)
    {
        ITraceBackend &b = drv();
        uint64_t max = a.u64_or(0, 200);
        std::vector<TraceEvent> ev = b.timeline();
        JArr arr;
        for ( size_t i = 0; i < ev.size() && i < max; i++ )
        {
            JObj o;
            o.str("pos", position_text(b, ev[i].pos)).str("what", ev[i].what)
             .num("kind", ev[i].kind).num("tid", ev[i].tid);
            arr.add(o.done());
        }
        out.num("count", (int64_t)ev.size()).raw("events", arr.done());
    }

    static void cursor_state(JObj &out)
    {
        ITraceBackend &b = drv();
        ittd_regs r;
        out.str("pos", position_text(b, g_drv.cursor->position()))
           .num("tid", g_drv.cursor->thread_id());
        if ( g_drv.cursor->read_registers(&r) )
            out.hex("pc", r.gp[ITTD_REG_RIP]).hex("sp", r.gp[ITTD_REG_RSP]);
    }

    static void cmd_drv_pos(const Args &, JObj &out) { cursor_state(out); }

    static void cmd_drv_seek(const Args &a, JObj &out)
    {
        ITraceBackend &b = drv();
        Position p;
        if ( a.at(0) == "first" )
            p = b.info().first;
        else if ( a.at(0) == "last" )
            p = b.info().last;
        else if ( !b.parse_position(a.at(0).c_str(), &p) )
            fail("'%s' is not a position (%s)", a.at(0).c_str(), b.position_syntax());
        if ( !g_drv.cursor->seek(p) )
            fail("could not seek to %s", a.at(0).c_str());
        cursor_state(out);
    }

    static void movement(const char *what, StopReason r, JObj &out)
    {
        out.str("movement", what).str("stop", stop_name(r));
        cursor_state(out);
    }

    static void cmd_drv_step(const Args &a, JObj &out)
    { drv(); movement("step", g_drv.nav->step(!a.back()), out); }
    static void cmd_drv_over(const Args &a, JObj &out)
    { drv(); movement("over", g_drv.nav->step_over(!a.back()), out); }
    static void cmd_drv_out(const Args &a, JObj &out)
    { drv(); movement("out", g_drv.nav->step_out(!a.back()), out); }
    static void cmd_drv_run(const Args &a, JObj &out)
    { drv(); movement("run", g_drv.nav->run(!a.back()), out); }
    static void cmd_drv_runto(const Args &a, JObj &out)
    { drv(); movement("runto", g_drv.nav->run_to((ea_t)a.u64(0), !a.back()), out); }

    static void query_status(const QueryResult &r, JObj &out);

    // EA, or EA:SIZE:KINDS with KINDS any of r, w, x.
    static Breakpoint parse_bp(const qstring &spec)
    {
        Breakpoint b;
        qstring rest = spec;
        size_t c1 = rest.find(':');
        qstring ea = c1 == qstring::npos ? rest : rest.substr(0, c1);
        uint64_t v = 0;
        if ( !parse_u64(ea, &v) )
            fail("'%s' is not a breakpoint (EA or EA:SIZE:rwx)", spec.c_str());
        b.addr = (ea_t)v;
        if ( c1 == qstring::npos )
            return b;
        qstring tail = rest.substr(c1 + 1);
        size_t c2 = tail.find(':');
        qstring sz = c2 == qstring::npos ? tail : tail.substr(0, c2);
        if ( !parse_u64(sz, &v) || v == 0 )
            fail("'%s': bad size", spec.c_str());
        b.size = v;
        qstring k = c2 == qstring::npos ? qstring("w") : tail.substr(c2 + 1);
        b.kinds = rwx_mask(k, ACCESS_READ, ACCESS_WRITE, ACCESS_EXEC);
        if ( b.kinds == 0 )
            fail("'%s': kinds are r, w and x", spec.c_str());
        return b;
    }

    static void cmd_drv_bp(const Args &a, JObj &out)
    {
        drv();
        std::vector<Breakpoint> v;
        for ( size_t i = 0; i < a.count(); i++ )
            v.push_back(parse_bp(a.at(i)));
        g_drv.nav->set_breakpoints(v);
        out.num("breakpoints", (int64_t)v.size());
    }

    static void cmd_drv_insns(const Args &a, JObj &out)
    {
        ITraceBackend &b = drv();
        uint64_t n = a.u64_or(0, 0x20);
        // Bounded like drv.read's size: every instruction becomes a JSON object.
        if ( n == 0 || n > 0x10000 )
            fail("list at most 0x10000 instructions");
        // To the end of the recording: the backend stops after 'n', and a
        // position window would mean something different to each backend.
        Position from = g_drv.cursor->position();
        Position to   = Position::end();
        std::vector<Access> v;
        query_status(b.query_instructions(PositionRange{ from, to }, g_drv.cursor->thread_id(),
                                          (size_t)n, &v, nullptr), out);
        JArr arr;
        for ( const Access &x : v )
        {
            JObj o;
            o.str("pos", position_text(b, x.pos)).hex("pc", x.pc).num("size", x.size).num("tid", x.tid);
            arr.add(o.done());
        }
        out.raw("instructions", arr.done());
    }

    static void cmd_drv_regs(const Args &, JObj &out)
    {
        drv();
        ittd_regs r;
        if ( !g_drv.cursor->read_registers(&r) )
        {
            BackendModule *m = dynamic_cast<BackendModule *>(g_drv.backend);
            fail("no registers here%s%s", m != nullptr ? ": " : "",
                 m != nullptr ? m->last_error().c_str() : "");
        }
        cursor_state(out);
        out.raw("regs", regs_json(r));
    }

    static void cmd_drv_read(const Args &a, JObj &out)
    {
        drv();
        uint64_t ea = a.u64(0), size = a.u64_or(1, 0x40);
        if ( size == 0 || size > 0x10000 )
            fail("read at most 0x10000 bytes");
        std::vector<uint8_t> buf((size_t)size), known;
        size_t n = g_drv.cursor->read_memory((ea_t)ea, buf.data(), buf.size(), &known);
        out.hex("ea", ea).num("size", (int64_t)size).num("known", (int64_t)n)
           .raw("bytes", bytes_json(buf.data(), known.data(), buf.size()));
    }

    static void query_status(const QueryResult &r, JObj &out)
    {
        if ( !r.ran )
            fail("the backend did not run that query");
        out.boolean("truncated", r.truncated).boolean("cancelled", r.cancelled);
    }

    static void cmd_drv_accesses(const Args &a, JObj &out)
    {
        ITraceBackend &b = drv();
        uint64_t lo = a.u64(0), hi = a.u64(1);
        uint8_t kinds = rwx_mask(a.count() > 2 ? a.at(2) : qstring("rwx"),
                                 ACCESS_READ, ACCESS_WRITE, ACCESS_EXEC);
        uint64_t max = a.u64_or(3, 200);
        std::vector<Access> v;
        query_status(b.query_accesses((ea_t)lo, (ea_t)hi, kinds, PositionRange{}, &v, nullptr), out);
        JArr arr;
        for ( size_t i = 0; i < v.size() && i < max; i++ )
        {
            JObj o;
            o.str("pos", position_text(b, v[i].pos)).hex("pc", v[i].pc).hex("addr", v[i].addr)
             .num("size", v[i].size).num("tid", v[i].tid)
             .str("kind", v[i].kind == ACCESS_READ ? "r" : v[i].kind == ACCESS_WRITE ? "w" : "x");
            arr.add(o.done());
        }
        out.num("count", (int64_t)v.size()).raw("accesses", arr.done());
    }

    static void cmd_drv_calls(const Args &a, JObj &out)
    {
        ITraceBackend &b = drv();
        uint64_t target = a.u64(0), max = a.u64_or(1, 200);
        std::vector<CallEvent> v;
        query_status(b.query_calls({ (ea_t)target }, PositionRange{}, &v, nullptr), out);
        JArr arr;
        for ( size_t i = 0; i < v.size() && i < max; i++ )
        {
            JObj o;
            o.str("pos", position_text(b, v[i].pos)).str("entry", position_text(b, v[i].entry_pos))
             .str("ret", position_text(b, v[i].ret_pos)).hex("site", v[i].site)
             .num("tid", v[i].tid).boolean("is_call", v[i].is_call);
            arr.add(o.done());
        }
        out.num("count", (int64_t)v.size()).raw("calls", arr.done());
    }

    static void cmd_drv_indirect(const Args &a, JObj &out)
    {
        ITraceBackend &b = drv();
        bool jumps = a.count() > 2 && a.at(2) == "jumps";
        std::map<ea_t, std::vector<IndirectTarget>> m;
        query_status(b.query_indirect_targets({ { (ea_t)a.u64(0), (ea_t)a.u64(1) } }, jumps, &m, nullptr), out);
        JArr arr;
        for ( const auto &[site, targets] : m )
            for ( const IndirectTarget &t : targets )
            {
                JObj o;
                o.hex("site", site).hex("target", t.target).num("hits", (int64_t)t.hits)
                 .str("first", position_text(b, t.first)).boolean("is_call", t.is_call);
                arr.add(o.done());
            }
        out.num("sites", (int64_t)m.size()).raw("edges", arr.done());
    }

    static void cmd_drv_exceptions(const Args &, JObj &out)
    {
        ITraceBackend &b = drv();
        std::vector<ExceptionEvent> v;
        query_status(b.query_exceptions(&v, nullptr), out);
        JArr arr;
        for ( const ExceptionEvent &e : v )
        {
            JObj o;
            o.str("pos", position_text(b, e.pos)).str("raised", position_text(b, e.raise_pos))
             .hex("code", e.code).hex("address", e.address).num("tid", e.tid)
             .hex("info0", e.information[0]).hex("info1", e.information[1]);
            arr.add(o.done());
        }
        out.raw("exceptions", arr.done());
    }

    static void cmd_drv_syscalls(const Args &a, JObj &out)
    {
        ITraceBackend &b = drv();
        uint64_t max = a.u64_or(0, 200);
        std::vector<SyscallEvent> v;
        query_status(b.query_syscalls(&v, nullptr), out);
        JArr arr;
        for ( size_t i = 0; i < v.size() && i < max; i++ )
        {
            JObj o;
            o.str("pos", position_text(b, v[i].pos)).num("tid", v[i].tid)
             .hex("number", v[i].number).str("name", v[i].name).hex("result", v[i].result);
            arr.add(o.done());
        }
        out.num("count", (int64_t)v.size()).raw("syscalls", arr.done());
    }

    static void cmd_drv_map(const Args &a, JObj &out)
    {
        ITraceBackend &b = drv();
        uint64_t max = a.u64_or(0, 200);
        std::vector<ittd_mapping_change> v;
        std::vector<qstring> files;
        query_status(b.query_mapping_changes(&v, &files, nullptr), out);
        JArr arr;
        for ( size_t i = 0; i < v.size() && i < max; i++ )
        {
            const ittd_mapping_change &m = v[i];
            JObj o;
            o.str("pos", position_text(b, from_abi_position(m.pos)))
             .str("call", position_text(b, from_abi_position(m.call_pos)))
             .hex("base", m.base).hex("size", m.size).num("kind", m.kind).hex("flags", m.flags)
             .hex("state", m.state).hex("type", m.mem_type).hex("protect", m.protect)
             .hex("alloc_base", m.alloc_base).hex("alloc_protect", m.alloc_protect)
             .num("region_type", m.region_type)
             .str("file", m.file > 0 && m.file <= files.size() ? files[m.file - 1] : qstring());
            arr.add(o.done());
        }
        out.num("count", (int64_t)v.size()).raw("changes", arr.done());
    }

    static void cmd_drv_symbols(const Args &a, JObj &out)
    {
        ITraceBackend &b = drv();
        uint64_t max = a.u64_or(1, 200);
        std::vector<ITraceBackend::Symbol> v = b.module_symbols((ea_t)a.u64(0));
        JArr arr;
        for ( size_t i = 0; i < v.size() && i < max; i++ )
        {
            JObj o;
            o.hex("ea", v[i].ea).str("name", v[i].name);
            arr.add(o.done());
        }
        out.num("count", (int64_t)v.size()).raw("symbols", arr.done());
    }

    static void cmd_drv_close(const Args &, JObj &) { g_drv.close(); }

    // ------------------------------------------------------------------ commands

    static const Command DRV_COMMANDS[] = {
        { "drv.open",       cmd_drv_open,       "PATH [BACKEND] open a recording through a backend, no debugger" },
        { "drv.close",      cmd_drv_close,      "close it" },
        { "drv.info",       cmd_drv_info,       "trace info and capabilities" },
        { "drv.modules",    cmd_drv_modules,    "modules" },
        { "drv.threads",    cmd_drv_threads,    "[live] threads, or those alive at the cursor" },
        { "drv.timeline",   cmd_drv_timeline,   "[MAX] timeline events" },
        { "drv.pos",        cmd_drv_pos,        "the cursor's position, thread, pc and sp" },
        { "drv.seek",       cmd_drv_seek,       "POS|first|last move the cursor" },
        { "drv.step",       cmd_drv_step,       "[back]" },
        { "drv.over",       cmd_drv_over,       "[back]" },
        { "drv.out",        cmd_drv_out,        "[back]" },
        { "drv.run",        cmd_drv_run,        "[back] to a breakpoint set with drv.bp" },
        { "drv.runto",      cmd_drv_runto,      "EA [back]" },
        { "drv.bp",         cmd_drv_bp,         "EA|EA:SIZE:rwx ... replace the breakpoints" },
        { "drv.insns",      cmd_drv_insns,      "[N] the next N instructions on the cursor's thread" },
        { "drv.regs",       cmd_drv_regs,       "registers at the cursor" },
        { "drv.read",       cmd_drv_read,       "EA [SIZE] memory at the cursor, ?? where unknown" },
        { "drv.accesses",   cmd_drv_accesses,   "LO HI [rwx] [MAX] accesses to [LO, HI)" },
        { "drv.calls",      cmd_drv_calls,      "EA [MAX] calls to a function" },
        { "drv.indirect",   cmd_drv_indirect,   "LO HI [jumps] indirect branch targets from [LO, HI)" },
        { "drv.exceptions", cmd_drv_exceptions, "dispatched exceptions" },
        { "drv.syscalls",   cmd_drv_syscalls,   "[MAX] dispatched syscalls" },
        { "drv.map",        cmd_drv_map,        "[MAX] memory map changes" },
        { "drv.symbols",    cmd_drv_symbols,    "BASE [MAX] a module's recorded exports" },
    };

    std::span<const Command> drv_commands() { return DRV_COMMANDS; }
}
