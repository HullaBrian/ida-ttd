#include "plugin/script_api.h"
#include "plugin/plugin.h"
#include "ui/ui.h"
#include "core/backend_registry.h"
#include "core/backend_module.h"
#include "analysis/memsearch.h"
#include "analysis/query_runner.h"
#include "analysis/coverage.h"
#include "analysis/callsites.h"
#include "analysis/tracer.h"
#include "analysis/memmap.h"
#include "analysis/syscalls.h"
#include "analysis/fork.h"
#include "analysis/fork_registry.h"
#include "analysis/replay_scans.h"
#include "analysis/calltree.h"

#include <expr.hpp>

namespace idattd
{
    // ------------------------------------------------------------------ JSON
    //
    // Just enough to write answers: objects, arrays, strings, numbers. Numbers
    // that are addresses or positions go out as "0x..." strings, because a
    // 64-bit value does not survive a JSON reader that parses into doubles.

    static void json_escape(qstring *out, const char *s)
    {
        out->append('"');
        for ( const unsigned char *p = (const unsigned char *)s; *p != 0; p++ )
        {
            switch ( *p )
            {
                case '"':  out->append("\\\""); break;
                case '\\': out->append("\\\\"); break;
                case '\n': out->append("\\n");  break;
                case '\r': out->append("\\r");  break;
                case '\t': out->append("\\t");  break;
                default:
                    if ( *p < 0x20 )
                        out->cat_sprnt("\\u%04x", *p);
                    else
                        out->append((char)*p);
            }
        }
        out->append('"');
    }

    class JObj
    {
    public:
        JObj &raw(const char *key, const qstring &json)
        {
            sep();
            json_escape(&m_s, key);
            m_s.append(':');
            m_s.append(json);
            return *this;
        }
        JObj &str(const char *key, const char *v)
        {
            qstring j;
            json_escape(&j, v != nullptr ? v : "");
            return raw(key, j);
        }
        JObj &str(const char *key, const qstring &v) { return str(key, v.c_str()); }
        JObj &num(const char *key, int64_t v)
        {
            qstring j;
            j.sprnt("%lld", (long long)v);
            return raw(key, j);
        }
        JObj &hex(const char *key, uint64_t v)
        {
            qstring j;
            j.sprnt("\"0x%llX\"", (unsigned long long)v);
            return raw(key, j);
        }
        JObj &boolean(const char *key, bool v) { return raw(key, qstring(v ? "true" : "false")); }
        qstring done() const
        {
            qstring s = "{";
            s.append(m_s);
            s.append('}');
            return s;
        }

    private:
        void sep() { if ( !m_s.empty() ) m_s.append(','); }
        qstring m_s;
    };

    class JArr
    {
    public:
        void add(const qstring &json)
        {
            if ( !m_s.empty() )
                m_s.append(',');
            m_s.append(json);
            m_n++;
        }
        size_t size() const { return m_n; }
        qstring done() const
        {
            qstring s = "[";
            s.append(m_s);
            s.append(']');
            return s;
        }

    private:
        qstring m_s;
        size_t  m_n = 0;
    };

    // ------------------------------------------------------------------ input

    static std::vector<qstring> tokenize(const char *line)
    {
        std::vector<qstring> out;
        const char *p = line;
        while ( *p != '\0' )
        {
            while ( *p == ' ' || *p == '\t' )
                p++;
            if ( *p == '\0' )
                break;
            // Quotes may sit anywhere in a word, so registry="C:\Program Files\x"
            // is one argument.
            qstring tok;
            bool quoted = false;
            for ( ; *p != '\0' && (quoted || (*p != ' ' && *p != '\t')); p++ )
            {
                if ( *p == '"' )
                    quoted = !quoted;
                else
                    tok.append(*p);
            }
            out.push_back(tok);
        }
        return out;
    }

    static bool parse_u64(const qstring &s, uint64_t *out)
    {
        const char *p = s.c_str();
        if ( p[0] == '0' && (p[1] == 'x' || p[1] == 'X') )
            p += 2;
        if ( *p == '\0' )
            return false;
        char *end = nullptr;
        *out = strtoull(p, &end, 16);
        return end != nullptr && *end == '\0';
    }

    // Thrown for a bad command; turned into {"ok":false,"error":...}.
    struct ScriptError
    {
        qstring what;
    };

    [[noreturn]] static void fail(const char *fmt, ...)
    {
        va_list va;
        va_start(va, fmt);
        ScriptError e;
        e.what.vsprnt(fmt, va);
        va_end(va);
        throw e;
    }

    struct Args
    {
        std::vector<qstring> v;     // v[0] is the command

        size_t count() const { return v.size() - 1; }
        const qstring &at(size_t i) const
        {
            if ( i + 1 >= v.size() )
                fail("'%s' needs more arguments; see 'help'", v[0].c_str());
            return v[i + 1];
        }
        uint64_t u64(size_t i) const
        {
            uint64_t x = 0;
            if ( !parse_u64(at(i), &x) )
                fail("'%s' is not a hex number", at(i).c_str());
            return x;
        }
        uint64_t u64_or(size_t i, uint64_t dflt) const { return i < count() ? u64(i) : dflt; }
        // A trailing "back" (or "backward") makes a movement go backwards.
        bool back() const
        {
            for ( size_t i = 1; i < v.size(); i++ )
                if ( v[i] == "back" || v[i] == "backward" || v[i] == "backwards" )
                    return true;
            return false;
        }
    };

    // ------------------------------------------------------------------ state

    static Plugin *g_plugin = nullptr;

    // A recording opened straight through a backend, with no debugger session:
    // what the drv.* commands work on. It exercises a backend and the core's
    // adapter in-process, headless or not.
    struct Driver
    {
        ITraceBackend *backend = nullptr;
        CursorPtr      cursor;
        std::unique_ptr<INavigator> nav;
        qstring        path;

        void close()
        {
            nav.reset();
            cursor.reset();
            if ( backend != nullptr )
                backend->close();
            backend = nullptr;
            path.clear();
        }
    };
    static Driver g_drv;

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

    static qstring bytes_json(const uint8_t *buf, const uint8_t *known, size_t n)
    {
        // Hex pairs, "??" for a byte the recording does not account for.
        qstring s;
        for ( size_t i = 0; i < n; i++ )
        {
            if ( known != nullptr && known[i] == 0 )
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
        ITraceBackend *b = a.count() > 1 ? BackendRegistry::instance().by_id(a.at(1).c_str())
                                         : BackendRegistry::instance().for_file(path.c_str());
        if ( b == nullptr )
            fail("no loaded backend handles %s", path.c_str());
        qstring err;
        if ( !b->open(path.c_str(), &err) )
            fail("%s could not open %s: %s", b->id(), path.c_str(), err.c_str());
        // As a debugger session would: without it a Microsoft trace has no
        // memory index, and reads come back mostly empty.
        prepare_backend(b);
        g_drv.backend = b;
        g_drv.path    = path;
        g_drv.cursor  = b->make_cursor();
        if ( !g_drv.cursor )
            fail("%s opened the recording but made no cursor", b->id());
        g_drv.nav = b->make_navigator(g_drv.cursor.get());
        g_drv.cursor->seek(b->info().first);
        out.str("backend", b->id());
    }

    static void cmd_drv_info(const Args &, JObj &out)
    {
        ITraceBackend &b = drv();
        const TraceInfo &ti = b.info();
        const Capabilities &c = b.capabilities();
        JObj caps;
        caps.boolean("access_queries", c.access_queries).boolean("call_queries", c.call_queries)
            .boolean("mapping_changes", c.mapping_changes).boolean("syscalls", c.syscalls)
            .boolean("recorded_exports", c.recorded_exports).boolean("cheap_seek", c.cheap_seek)
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
            o.str("pos", position_text(b, ev[i].pos)).str("what", ev[i].what);
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
        b.kinds = 0;
        qstring k = c2 == qstring::npos ? qstring("w") : tail.substr(c2 + 1);
        if ( k.find('r') != qstring::npos ) b.kinds |= ACCESS_READ;
        if ( k.find('w') != qstring::npos ) b.kinds |= ACCESS_WRITE;
        if ( k.find('x') != qstring::npos ) b.kinds |= ACCESS_EXEC;
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
        // To the end of the recording: the backend stops after 'n', and a
        // window in positions would mean something different to each backend.
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
        uint8_t kinds = 0;
        qstring k = a.count() > 2 ? a.at(2) : qstring("rwx");
        if ( k.find('r') != qstring::npos ) kinds |= ACCESS_READ;
        if ( k.find('w') != qstring::npos ) kinds |= ACCESS_WRITE;
        if ( k.find('x') != qstring::npos ) kinds |= ACCESS_EXEC;
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

    // ------------------------------------------------------------------ session

    static TraceManager &mgr() { return g_plugin->manager(); }

    static void need_session()
    {
        if ( get_process_state() == DSTATE_NOTASK || !mgr().is_active() )
            fail("no replay session is running; use 'start'");
    }

    // Wait for the debugger to stop again, and say where.
    static void wait_stop(const Args &a, size_t timeout_arg, JObj &out)
    {
        int timeout = (int)a.u64_or(timeout_arg, 0x3C);   // seconds, hex like every number
        // WFNE_SILENT: a script has nobody to answer a modal box.
        dbg_event_code_t code = wait_for_next_event(WFNE_SUSP | WFNE_SILENT, timeout);
        out.num("event", code);
        if ( code == DEC_TIMEOUT )
            out.boolean("timed_out", true);
        if ( mgr().is_active() )
        {
            out.str("pos", format_position(mgr().current_position()))
               .hex("pc", mgr().current_pc_ea());
            thid_t tid = get_current_thread();
            out.num("tid", tid);
        }
        out.num("process_state", get_process_state());
    }

    static void cmd_state(const Args &, JObj &out)
    {
        out.num("process_state", get_process_state()).boolean("session", mgr().is_active())
           .boolean("actions_visible", g_plugin->actions_visible());
        if ( mgr().is_active() )
            out.str("pos", format_position(mgr().current_position())).hex("pc", mgr().current_pc_ea())
               .str("trace", mgr().trace_path());
        out.str("drv_backend", g_drv.backend != nullptr ? g_drv.backend->id() : "")
           .str("last_resume", mgr().last_resume()).num("event_order", mgr().event_order());
        JArr log;
        for ( const qstring &l : mgr().event_log() )
        {
            qstring q;
            json_escape(&q, l.c_str());
            log.add(q);
        }
        out.raw("event_log", log.done());
    }

    static void cmd_start(const Args &a, JObj &out)
    {
        if ( get_process_state() != DSTATE_NOTASK )
            fail("a debugging session is already running");
        g_plugin->start_trace_session();
        wait_stop(a, 0, out);
    }

    static void cmd_wait(const Args &a, JObj &out) { wait_stop(a, 0, out); }

    // switch PATH [TIMEOUT]: end the session, if one runs, and start the
    // replay of PATH in this database -- what the Fork manager's "Switch
    // here" does, without its timer.
    static void cmd_switch(const Args &a, JObj &out)
    {
        qstring path = a.at(0);
        if ( get_process_state() != DSTATE_NOTASK )
        {
            exit_process();
            wait_for_next_event(WFNE_ANY | WFNE_SILENT, 10);
        }
        if ( get_process_state() != DSTATE_NOTASK )
            fail("the running session did not end");
        if ( !g_plugin->start_trace_at(path.c_str()) )
            fail("the TTD debugger could not be selected for %s", path.c_str());
        Args rest;
        rest.v.push_back(a.v[0]);
        for ( size_t i = 1; i < a.count(); i++ )
            rest.v.push_back(a.at(i));
        wait_stop(rest, 0, out);
        out.str("trace", mgr().trace_path());
    }

    // The switch as the Fork manager makes it: queued, from a timer and IDA's
    // request queue, returning at once. Poll "state" for the new trace.
    static void cmd_switch_ui(const Args &a, JObj &out)
    {
        g_plugin->switch_trace(a.at(0));
        out.str("queued", a.at(0));
    }

    // One movement of the real debugger session, then wait for it to stop.
    // The backward ones go the way the TTD toolbar sends them.
    static void cmd_move(const Args &a, JObj &out)
    {
        need_session();
        const qstring &c = a.v[0];
        bool back = a.back();
        if ( c == "step" )
            back ? request_step_into_backwards() : request_step_into();
        else if ( c == "over" )
            back ? request_step_over_backwards() : request_step_over();
        else if ( c == "out" )
        {
            if ( back ) { mgr().request_step_out_backward(); wait_stop(a, 99, out); return; }
            request_step_until_ret();
        }
        else if ( c == "run" )
        {
            if ( back ) { mgr().request_run(false); wait_stop(a, 99, out); return; }
            request_continue_process();
        }
        else if ( c == "runto" )
        {
            ea_t ea = (ea_t)a.u64(0);
            back ? mgr().request_run_to_cursor_backward(ea) : mgr().request_run_to_cursor_forward(ea);
            wait_stop(a, 99, out);
            return;
        }
        run_requests();
        wait_stop(a, 99, out);
    }

    static void cmd_goto(const Args &a, JObj &out)
    {
        need_session();
        Position p;
        if ( !parse_position(a.at(0).c_str(), &p) )
            fail("'%s' is not a position (%s)", a.at(0).c_str(), position_syntax());
        mgr().set_next_position(p);
        request_continue_process();
        run_requests();
        wait_stop(a, 99, out);
    }

    static void cmd_regs(const Args &, JObj &out)
    {
        need_session();
        static const char *names64[] = { "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
                                         "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
                                         "RIP", "EFL" };
        static const char *names32[] = { "EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP",
                                         "EIP", "EFL" };
        bool is64 = inf_is_64bit();
        JObj regs;
        size_t n = is64 ? qnumber(names64) : qnumber(names32);
        for ( size_t i = 0; i < n; i++ )
        {
            const char *name = is64 ? names64[i] : names32[i];
            uint64 v = 0;
            if ( get_reg_val(name, &v) )
            {
                qstring key = name;
                qstrlwr(key.begin());
                regs.hex(key.c_str(), v);
            }
        }
        out.str("pos", format_position(mgr().current_position())).raw("regs", regs.done());
    }

    static void cmd_read(const Args &a, JObj &out)
    {
        need_session();
        uint64_t ea = a.u64(0), size = a.u64_or(1, 0x40);
        if ( size == 0 || size > 0x10000 )
            fail("read at most 0x10000 bytes");
        std::vector<uint8_t> buf((size_t)size);
        ssize_t got = read_dbg_memory((ea_t)ea, buf.data(), buf.size());
        out.hex("ea", ea).num("got", got)
           .raw("bytes", bytes_json(buf.data(), nullptr, got > 0 ? (size_t)got : 0));
    }

    static void cmd_segments(const Args &a, JObj &out)
    {
        uint64_t max = a.u64_or(0, 400);
        JArr arr;
        for ( int i = 0; i < get_segm_qty() && arr.size() < max; i++ )
        {
            segment_info_t si;
            if ( !get_segment_info_by_num(&si, i, GSI_NAME | GSI_SCLASS) )
                continue;
            JObj o;
            o.str("name", si.get_name()).str("class", si.get_sclass())
             .hex("start", si.start_ea).hex("end", si.end_ea)
             .num("perm", si.get_perm()).boolean("debugger", si.is_debugger_segm());
            arr.add(o.done());
        }
        out.num("count", get_segm_qty()).raw("segments", arr.done());
    }

    static void cmd_event_order(const Args &a, JObj &out)
    {
        if ( a.count() > 0 )
            mgr().set_event_order((int)a.u64(0));
        out.num("event_order", mgr().event_order());
    }

    static void cmd_stop(const Args &, JObj &out)
    {
        if ( get_process_state() != DSTATE_NOTASK )
        {
            exit_process();
            wait_for_next_event(WFNE_ANY | WFNE_SILENT, 10);
        }
        out.num("process_state", get_process_state());
    }

    // ------------------------------------------------------------------ an.*
    //
    // The analyses, run inside the session exactly as their UI actions run
    // them -- the same functions, the same wait boxes, the same writes into
    // the database -- with the scope given here instead of in a dialog.

    static uint8_t access_mask(const Args &a, size_t i)
    {
        qstring k = a.count() > i ? a.at(i) : qstring("rwx");
        uint8_t m = 0;
        if ( k.find('r') != qstring::npos ) m |= ACC_READ;
        if ( k.find('w') != qstring::npos ) m |= ACC_WRITE;
        if ( k.find('x') != qstring::npos ) m |= ACC_EXEC;
        return m;
    }

    static void cmd_an_search(const Args &a, JObj &out)
    {
        need_session();
        ea_t lo = (ea_t)a.u64(0), hi = (ea_t)a.u64(1);
        uint64_t max = a.u64_or(3, 200);
        std::vector<MemAccess> v;
        bool truncated = false, cancelled = false;
        if ( !search_memory(&mgr(), lo, hi, access_mask(a, 2), &v, &truncated, &cancelled) )
            fail("the search did not run");
        JArr arr;
        for ( size_t i = 0; i < v.size() && i < max; i++ )
        {
            JObj o;
            o.str("pos", format_position(v[i].pos)).hex("pc", v[i].pc).hex("addr", v[i].addr)
             .num("size", v[i].size).num("tid", v[i].tid).str("kind", access_name(v[i].kind));
            arr.add(o.done());
        }
        out.boolean("truncated", truncated).boolean("cancelled", cancelled)
           .num("count", (int64_t)v.size()).raw("accesses", arr.done());
    }

    static void cmd_an_syscalls(const Args &a, JObj &out)
    {
        need_session();
        uint64_t max = a.u64_or(0, 50);
        std::vector<SyscallEvent> v;
        bool cancelled = false;
        if ( !list_syscalls(&mgr(), &v, &cancelled) )
            fail("this recording does not list its syscalls");
        std::vector<std::optional<SyscallArgs>> args;
        syscall_arguments(mgr().backend(), v, 0, (size_t)max, &args);
        JArr arr;
        for ( size_t i = 0; i < v.size() && i < max; i++ )
        {
            JObj o;
            o.str("pos", format_position(v[i].pos)).num("tid", v[i].tid)
             .hex("number", v[i].number).str("name", v[i].name).hex("result", v[i].result);
            if ( i < args.size() && args[i].has_value() )
            {
                JArr av;
                for ( uint64_t x : *args[i] )
                {
                    qstring t;
                    t.sprnt("\"0x%llX\"", (unsigned long long)x);
                    av.add(t);
                }
                o.raw("args", av.done());
            }
            arr.add(o.done());
        }
        out.boolean("cancelled", cancelled).num("count", (int64_t)v.size()).raw("syscalls", arr.done());
    }

    static void cmd_an_selfmod(const Args &a, JObj &out)
    {
        need_session();
        uint64_t max = a.u64_or(0, 50);
        std::vector<SelfModHit> v;
        bool cancelled = false;
        if ( !find_self_modifying(&mgr(), &v, &cancelled) )
            fail("this recording's backend cannot look for self-modifying code");
        JArr arr;
        for ( size_t i = 0; i < v.size() && i < max; i++ )
        {
            JObj o;
            o.hex("address", v[i].address).num("size", (int64_t)v[i].size)
             .str("written", format_position(v[i].write_pos)).hex("writer", v[i].write_ip)
             .str("first_run", format_position(v[i].execute_pos))
             .num("runs", (int64_t)v[i].executions);
            arr.add(o.done());
        }
        out.boolean("cancelled", cancelled).num("count", (int64_t)v.size()).raw("hits", arr.done());
    }

    // an.fork PATH N [registry=DIR] [strict] [REG=VALUE ...] [mem:ADDR=HEXBYTES ...]
    static void cmd_an_fork(const Args &a, JObj &out)
    {
        need_session();
        ForkRequest req;
        req.at               = mgr().current_position();
        req.path             = a.at(0);
        req.max_instructions = a.u64(1);
        qstring regs, mem;
        for ( size_t i = 2; i < a.count(); i++ )
        {
            qstring t = a.at(i);
            if ( t.starts_with("registry=") )
                req.registry_dir = t.substr(9);
            else if ( t == "strict" )
                req.strict = true;
            else if ( t == "host" )
                req.allow_host = true;
            else if ( t.starts_with("mem:") )
                mem.cat_sprnt("%s;", t.c_str() + 4);
            else
                regs.cat_sprnt("%s ", t.c_str());
        }
        qstring err;
        if ( !parse_fork_registers(regs.c_str(), &req.regs, &err)
          || !parse_fork_memory(mem.c_str(), &req.memory, &err) )
            fail(err.c_str());
        req.note = "ida-ttd script";
        ForkResult r = run_fork(&mgr(), req);
        if ( !r.ok )
            fail("the fork failed: %s", r.error.c_str());
        out.boolean("cancelled", r.cancelled).num("instructions", (int64_t)r.instructions)
           .str("at", format_position(req.at)).str("path", req.path);
    }

    static void draft_json(JObj &out)
    {
        const TraceManager::ForkDraft &d = mgr().fork_draft();
        out.boolean("forking", d.active);
        if ( !d.active )
            return;
        JArr regs, mem;
        ForkRequest req;
        mgr().fill_fork_request(&req);
        for ( const auto &[idx, v] : req.regs )
        {
            JObj o;
            o.num("reg", idx).hex("value", (uint64)v);
            regs.add(o.done());
        }
        for ( const auto &[ea, bytes] : req.memory )
        {
            JObj o;
            qstring hex;
            for ( uchar b : bytes )
                hex.cat_sprnt("%02X", b);
            o.hex("address", ea).str("bytes", hex);
            mem.add(o.done());
        }
        out.str("at", format_position(d.at)).boolean("here", mgr().at_fork_draft())
           .raw("regs", regs.done()).raw("memory", mem.done());
    }

    // an.forks: the forks this database knows of (the Fork manager's graph).
    static void cmd_an_forks(const Args &, JObj &out)
    {
        JArr arr;
        bool ok = true;
        std::vector<ForkRecord> v = load_fork_records(&ok);
        if ( !ok )
            fail("the fork list in this database could not be read");
        for ( const ForkRecord &f : v )
        {
            JObj o;
            o.str("path", f.path).str("parent", f.parent).str("at", f.at).str("changes", f.changes)
             .num("instructions", (int64_t)f.instructions);
            arr.add(o.done());
        }
        out.num("count", (int64_t)v.size()).raw("forks", arr.done());
    }

    // an.forget PATH: take a fork out of the graph.
    static void cmd_an_forget(const Args &a, JObj &out)
    {
        remove_fork_record(a.at(0).c_str());
        out.num("count", (int64_t)load_fork_records(nullptr).size());
    }

    // an.forkhere: make the current position a fork (TTD > Fork here). Its
    // registers and memory are then changed through IDA's own debugger calls.
    static void cmd_an_forkhere(const Args &, JObj &out)
    {
        need_session();
        bool shown = mgr().at_fork_draft()
                  && (!mgr().fork_draft().regs.empty() || !mgr().fork_draft().bytes.empty());
        mgr().begin_fork_draft();
        fork_draft_changed(g_plugin->action_context(), shown);
        draft_json(out);
    }

    // an.forkdraft: the fork being prepared, with its changes.
    static void cmd_an_forkdraft(const Args &, JObj &out)
    {
        need_session();
        draft_json(out);
    }

    static void cmd_an_forkdiscard(const Args &, JObj &out)
    {
        need_session();
        bool shown = mgr().at_fork_draft()
                  && (!mgr().fork_draft().regs.empty() || !mgr().fork_draft().bytes.empty());
        mgr().discard_fork_draft();
        fork_draft_changed(g_plugin->action_context(), shown);
        draft_json(out);
    }

    // an.forkrecord PATH N [registry=DIR] [strict] [host]: record the fork
    // being prepared (TTD > Record fork).
    static void cmd_an_forkrecord(const Args &a, JObj &out)
    {
        need_session();
        if ( !mgr().fork_draft().active )
            fail("there is no fork; an.forkhere first");
        ForkRequest req;
        mgr().fill_fork_request(&req);
        req.path             = a.at(0);
        req.max_instructions = a.u64(1);
        for ( size_t i = 2; i < a.count(); i++ )
        {
            const qstring &t = a.at(i);
            if ( t.starts_with("registry=") )
                req.registry_dir = t.substr(9);
            else if ( t == "strict" )
                req.strict = true;
            else if ( t == "host" )
                req.allow_host = true;
            else
                fail("'%s' is not registry=DIR, strict or host", t.c_str());
        }
        req.note = "ida-ttd script";
        ForkResult r = run_fork(&mgr(), req);
        if ( !r.ok )
        {
            ReplayBlock b = mgr().backend()->last_replay_block();
            fail("the fork failed%s: %s",
                 b == ReplayBlock::HostConsent ? " (needs host)"
                 : b == ReplayBlock::Registry ? " (needs registry=DIR)" : "",
                 r.error.c_str());
        }
        out.boolean("cancelled", r.cancelled).num("instructions", (int64_t)r.instructions)
           .str("at", format_position(req.at)).str("path", req.path)
           .num("regs", (int64_t)req.regs.size()).num("writes", (int64_t)req.memory.size());
    }

    // Trailing "registry=DIR" and "strict" words set what the replay needs.
    static ReplaySettings replay_args(const Args &a, size_t from)
    {
        ReplaySettings rs;
        rs.registry_dir = saved_registry_dir();
        for ( size_t i = from; i < a.count(); i++ )
        {
            const qstring &t = a.at(i);
            if ( t.starts_with("registry=") )
                rs.registry_dir = t.substr(9);
            else if ( t == "strict" )
                rs.strict = true;
            else if ( t == "host" )
                rs.allow_host = true;
        }
        return rs;
    }

    static size_t plain_args(const Args &a)
    {
        size_t n = 0;
        while ( n < a.count() && !a.at(n).starts_with("registry=") && a.at(n) != "strict" && a.at(n) != "host" )
            n++;
        return n;
    }

    static void cmd_an_strings(const Args &a, JObj &out)
    {
        need_session();
        size_t np = plain_args(a);
        uint32_t min_len = np > 0 ? (uint32_t)a.u64(0) : 6;
        uint64_t max = np > 1 ? a.u64(1) : 50;
        std::vector<StringHit> v;
        bool cancelled = false;
        qstring err;
        if ( !recover_strings(&mgr(), replay_args(a, np), min_len, &v, &cancelled, &err) )
            fail("the replay did not run: %s", err.c_str());
        JArr arr;
        for ( size_t i = 0; i < v.size() && i < max; i++ )
        {
            JObj o;
            o.str("pos", format_position(v[i].pos)).hex("address", v[i].address)
             .boolean("wide", v[i].wide).str("text", v[i].text);
            arr.add(o.done());
        }
        out.boolean("cancelled", cancelled).num("count", (int64_t)v.size()).raw("strings", arr.done())
           .str("notice", mgr().backend()->scan_notice());
    }

    static void cmd_an_buffers(const Args &a, JObj &out)
    {
        need_session();
        size_t np = plain_args(a);
        uint64_t max = np > 0 ? a.u64(0) : 50;
        std::vector<BufferHit> v;
        bool cancelled = false;
        qstring err;
        if ( !recover_buffers(&mgr(), replay_args(a, np), &v, &cancelled, &err) )
            fail("the replay did not run: %s", err.c_str());
        JArr arr;
        for ( size_t i = 0; i < v.size() && i < max; i++ )
        {
            JObj o;
            o.hex("address", v[i].address).hex("size", v[i].size).str("kind", v[i].kind)
             .str("first", format_position(v[i].first_pos)).str("last", format_position(v[i].last_pos))
             .hex("writer", v[i].writer_ip).num("writes", (int64_t)v[i].writes).str("preview", v[i].preview);
            arr.add(o.done());
        }
        out.boolean("cancelled", cancelled).num("count", (int64_t)v.size()).raw("buffers", arr.done())
           .str("notice", mgr().backend()->scan_notice());
    }

    static void cmd_an_calltree(const Args &a, JObj &out)
    {
        need_session();
        uint64_t max = a.u64_or(0, 50);
        CallTree t;
        qstring err;
        if ( !build_call_tree(&mgr(), &t, &err) )
            fail("the call tree did not build: %s", err.c_str());
        JArr arr;
        for ( size_t i = 0; i < t.rows.size() && i < max; i++ )
        {
            const CallTreeRow &r = t.rows[i];
            JObj o;
            o.str("pos", format_position(r.pos)).num("depth", r.depth).hex("site", r.site)
             .hex("target", r.target).str("ret", format_position(r.ret_pos)).boolean("call", r.is_call);
            arr.add(o.done());
        }
        out.hex("root", t.root).str("from", format_position(t.from)).str("to", format_position(t.to))
           .boolean("from_cursor", t.from_cursor).boolean("truncated", t.truncated)
           .boolean("cancelled", t.cancelled).num("count", (int64_t)t.rows.size()).raw("calls", arr.done());
    }

    // For the call tree window (ui/calltree_py.hh): the tree the TTD menu
    // command last built.
    static void cmd_ui_calltree(const Args &, JObj &out)
    {
        const qstring &j = call_tree_json();
        if ( j.empty() )
            fail("no call tree has been built");
        out.raw("tree", j);
    }

    // Travel the way a double-click in a list does: returns at once.
    static void cmd_ui_travel(const Args &a, JObj &out)
    {
        need_session();
        Position p;
        if ( !parse_position(a.at(0).c_str(), &p) )
            fail("'%s' is not a position (%s)", a.at(0).c_str(), position_syntax());
        mgr().set_next_position(p);
        request_continue_process();
        run_requests();
        out.str("queued", a.at(0));
    }

    static void cmd_an_coverage(const Args &a, JObj &out)
    {
        need_session();
        CoverageResult r;
        bgcolor_t color = (bgcolor_t)a.u64_or(2, COVERAGE_DEFAULT_COLOR);
        if ( !run_coverage(&mgr(), { { (ea_t)a.u64(0), (ea_t)a.u64(1) } }, color, &r) )
            fail("coverage did not run");
        out.num("executed", (int64_t)r.executed).num("colored", (int64_t)r.colored)
           .num("undefined", (int64_t)r.undefined).boolean("cancelled", r.cancelled);
    }

    static void cmd_an_callsites(const Args &a, JObj &out)
    {
        need_session();
        ea_t lo = (ea_t)a.u64(0), hi = (ea_t)a.u64(1);
        CallSiteResult r;
        if ( !annotate_indirect_calls(&mgr(), { { lo, hi } }, &r) )
            fail("the call site sweep did not run");
        // What it wrote: the repeatable comment at each annotated site.
        JArr arr;
        for ( ea_t ea = lo; ea < hi && ea != BADADDR && arr.size() < 64; ea = next_head(ea, hi) )
        {
            qstring cmt;
            if ( get_cmt(&cmt, ea, true) > 0 && strncmp(cmt.c_str(), "TTD:", 4) == 0 )
            {
                JObj o;
                o.hex("site", ea).str("comment", cmt);
                tinfo_t ct;
                qstring ts;
                if ( get_tinfo(&ct, ea) && ct.print(&ts) )
                    o.str("call_type", ts);
                arr.add(o.done());
            }
        }
        out.num("sites", (int64_t)r.sites).num("targets", (int64_t)r.targets)
           .num("polymorphic", (int64_t)r.polymorphic).num("undefined", (int64_t)r.undefined)
           .num("typed", (int64_t)r.typed)
           .boolean("truncated", r.truncated).boolean("cancelled", r.cancelled)
           .raw("annotated", arr.done());
    }

    static void cmd_an_trace(const Args &a, JObj &out)
    {
        need_session();
        FunctionTracer &tr = g_plugin->tracer();
        uint64_t max = a.u64_or(1, 40);
        tr.reset();
        // An address, or a "module!Glob*" pattern as the Trace calls by pattern
        // action takes it.
        uint64_t ea = 0;
        if ( parse_u64(a.at(0), &ea) )
            tr.add_func((ea_t)ea);
        else
            for ( ea_t f : mgr().modules().resolve_function_pattern(a.at(0).c_str()) )
                tr.add_func(f);
        out.num("traced", (int64_t)tr.count_traced());
        tr.run_sweep();
        std::vector<FunctionInvocation> v = tr.snapshot_events();
        JArr arr;
        for ( size_t i = 0; i < v.size() && i < max; i++ )
        {
            JArr args;
            for ( const qstring &s : v[i].args )
            {
                qstring q;
                json_escape(&q, s.c_str());
                args.add(q);
            }
            JObj o;
            qstring name;
            if ( get_name(&name, v[i].func_ea) <= 0 || name.empty() )
                name = mgr().modules().export_name_at(v[i].func_ea);
            o.hex("func", v[i].func_ea).str("name", name).str("pos", format_position(v[i].pos))
             .str("end", v[i].has_ret ? format_position(v[i].end_pos) : qstring())
             .num("tid", v[i].tid).raw("args", args.done()).str("ret", v[i].retval);
            arr.add(o.done());
        }
        out.num("count", (int64_t)v.size()).raw("calls", arr.done());
    }

    static void cmd_an_memmap(const Args &a, JObj &out)
    {
        need_session();
        uint64_t max = a.u64_or(0, 40);
        MemoryMap mm;
        bool cancelled = false;
        if ( !build_memory_map(&mgr(), &mm, &cancelled) )
            fail("the memory map was not built");
        // The regions as they stand at the playhead.
        std::vector<Region> regions;
        mm.state_at(mgr().current_position(), regions);
        JArr arr;
        for ( size_t i = 0; i < regions.size() && i < max; i++ )
        {
            JObj o;
            o.hex("base", regions[i].base).hex("size", (ea_t)regions[i].size)
             .hex("protect", regions[i].protect).str("origin", change_name(regions[i].origin));
            arr.add(o.done());
        }
        out.num("changes", (int64_t)mm.size()).boolean("cancelled", cancelled)
           .num("regions", (int64_t)regions.size()).raw("at_playhead", arr.done());
    }

    // What the automatic indirect-call resolution does on a stop in the
    // function at EA.
    static void cmd_an_autocalls(const Args &a, JObj &out)
    {
        need_session();
        ea_t ea = (ea_t)a.u64(0);
        func_entry_info_t fi;
        if ( !get_func_entry_info(&fi, ea) )
            fail("no function there");
        bool ok = auto_annotate_function(&mgr(), fi.start_ea, fi.end_ea);
        out.boolean("done", ok).hex("start", fi.start_ea).hex("end", fi.end_ea);
    }

    // The Memory map listing's rows. Builds the session's change timeline
    // first when it has none (as the menu does, without asking).
    static void cmd_an_regions(const Args &a, JObj &out)
    {
        need_session();
        uint64_t max = a.u64_or(0, 200);
        MemoryMap &mm = mgr().memmap_for_update();
        if ( mm.empty() )
        {
            bool cancelled = false;
            build_memory_map(&mgr(), &mm, &cancelled);
        }
        std::vector<AddressRegion> regions;
        address_space_at(&mgr(), &regions);
        JArr arr;
        for ( size_t i = 0; i < regions.size() && i < max; i++ )
        {
            const AddressRegion &r = regions[i];
            JObj o;
            o.hex("base", r.base).hex("size", (ea_t)r.size)
             .str("protect", r.reserved ? qstring("reserved")
                           : r.protect != 0 ? protection_text(r.protect) : qstring())
             .str("type", region_type_name(r.type)).str("use", r.use)
             .str("since", r.since.is_valid() ? format_position(r.since) : qstring());
            arr.add(o.done());
        }
        out.num("changes", (int64_t)mm.size()).num("count", (int64_t)regions.size())
           .raw("regions", arr.done());
    }

    // ------------------------------------------------------------------ dispatch

    using Handler = void (*)(const Args &, JObj &);
    struct Command
    {
        const char *name;
        Handler     fn;
        const char *usage;
    };

    static void cmd_help(const Args &, JObj &out);
    static void cmd_backends(const Args &, JObj &out);

    static const Command g_commands[] = {
        { "help",           cmd_help,           "this list" },
        { "state",          cmd_state,          "the debugger and session state" },
        { "backends",       cmd_backends,       "the backends loaded from plugins/ida-ttd-backends" },
        { "start",          cmd_start,          "[TIMEOUT] start the replay for this database and wait for the first stop" },
        { "wait",           cmd_wait,           "[TIMEOUT] wait for the debugger to stop" },
        { "step",           cmd_move,           "[back] one instruction" },
        { "over",           cmd_move,           "[back] step over" },
        { "out",            cmd_move,           "[back] step out" },
        { "run",            cmd_move,           "[back] to a breakpoint or the edge of the trace" },
        { "runto",          cmd_move,           "EA [back] run to an address" },
        { "goto",           cmd_goto,           "POS travel to a position" },
        { "regs",           cmd_regs,           "the registers IDA shows" },
        { "read",           cmd_read,           "EA [SIZE] debugger memory, as IDA reads it" },
        { "segments",       cmd_segments,       "[MAX] the segments, debugger ones included" },
        { "stop",           cmd_stop,           "end the session" },
        { "evorder",        cmd_event_order,    "[N] when thread/module events are reported (experimental)" },
        { "an.search",      cmd_an_search,      "LO HI [rwx] [MAX] memory search, as the dialog runs it" },
        { "an.coverage",    cmd_an_coverage,    "LO HI [COLOR] measure and colour execution coverage" },
        { "an.callsites",   cmd_an_callsites,   "LO HI annotate indirect calls, and list the comments" },
        { "an.trace",       cmd_an_trace,       "EA|module!Glob* [MAX] find all calls to a function, with arguments" },
        { "an.memmap",      cmd_an_memmap,      "[MAX] build the memory map; the regions at the playhead" },
        { "an.regions",     cmd_an_regions,     "[MAX] the Memory map listing at the playhead" },
        { "an.autocalls",   cmd_an_autocalls,   "EA resolve indirect calls in the function there, as a stop does automatically" },
        { "an.syscalls",    cmd_an_syscalls,    "[MAX] the recording's syscalls, with arguments" },
        { "an.selfmod",     cmd_an_selfmod,     "[MAX] code the program wrote and then ran" },
        { "an.calltree",    cmd_an_calltree,    "[MAX] the calls the function at the playhead made in this run of it" },
        { "an.strings",     cmd_an_strings,     "[MIN [MAX]] [registry=DIR] [strict] strings recovered by a replay" },
        { "an.buffers",     cmd_an_buffers,     "[MAX] [registry=DIR] [strict] buffers recovered by a replay" },
        { "switch",         cmd_switch,         "PATH [TIMEOUT] replay another recording (a fork) in this database" },
        { "ui.calltree",    cmd_ui_calltree,    "the call tree last built by the TTD menu (for its window)" },
        { "ui.travel",      cmd_ui_travel,      "POS travel there, returning at once (as a double-click does)" },
        { "switch.ui",      cmd_switch_ui,      "PATH the same, the way the Fork manager does it (returns at once)" },
        { "an.forks",       cmd_an_forks,       "the forks recorded in this database" },
        { "an.forget",      cmd_an_forget,      "PATH take a fork out of the fork graph" },
        { "an.forkhere",    cmd_an_forkhere,    "make this position a fork; change it with IDA's debugger calls" },
        { "an.forkdraft",   cmd_an_forkdraft,   "the fork being prepared and its changes" },
        { "an.forkdiscard", cmd_an_forkdiscard, "drop the fork being prepared" },
        { "an.forkrecord",  cmd_an_forkrecord,  "PATH N [registry=DIR] [strict] [host] record the fork being prepared" },
        { "an.fork",        cmd_an_fork,        "PATH N [registry=DIR] [strict] [REG=V ...] [mem:EA=HEX ...] fork here" },
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

    static void cmd_backends(const Args &, JObj &out)
    {
        load_backend_modules();
        JArr arr;
        for ( ITraceBackend *b : BackendRegistry::instance().all() )
        {
            JObj o;
            BackendModule *m = dynamic_cast<BackendModule *>(b);
            o.str("id", b->id()).str("name", b->display_name()).str("filter", b->file_filter())
             .str("path", m != nullptr ? m->path() : qstring("(built in)"));
            arr.add(o.done());
        }
        out.raw("backends", arr.done());
    }

    static void cmd_help(const Args &, JObj &out)
    {
        JArr arr;
        for ( const Command &c : g_commands )
        {
            qstring line = c.name;
            line.append(' ');
            line.append(c.usage);
            qstring j;
            json_escape(&j, line.c_str());
            arr.add(j);
        }
        out.raw("commands", arr.done());
    }

    static qstring dispatch(const char *line)
    {
        JObj out;
        Args a;
        a.v = tokenize(line != nullptr ? line : "");
        if ( a.v.empty() )
            a.v.push_back("help");
        try
        {
            const Command *found = nullptr;
            for ( const Command &c : g_commands )
                if ( a.v[0] == c.name )
                    found = &c;
            if ( found == nullptr )
                fail("unknown command '%s'; see 'help'", a.v[0].c_str());
            JObj body;
            found->fn(a, body);
            out.boolean("ok", true).str("command", a.v[0]);
            qstring s = out.done();
            qstring b = body.done();
            // Merge: {"ok":true,"command":...} + the command's own fields.
            s.remove_last();
            if ( b.length() > 2 )
            {
                s.append(',');
                s.append(b.c_str() + 1);
            }
            else
            {
                s.append('}');
            }
            return s;
        }
        catch ( const ScriptError &e )
        {
            out.boolean("ok", false).str("command", a.v[0]).str("error", e.what);
        }
        catch ( const std::exception &e )
        {
            out.boolean("ok", false).str("command", a.v[0]).str("error", e.what());
        }
        return out.done();
    }

    // ------------------------------------------------------------------ IDC

    static error_t idaapi idc_ttd(idc_value_t *argv, idc_value_t *res)
    {
        qstring answer = dispatch(argv[0].vtype == VT_STR ? argv[0].c_str() : "help");
        res->_set_string(answer);
        return eOk;
    }

    static const char idc_ttd_args[] = { VT_STR, 0 };
    static const ext_idcfunc_t idc_ttd_desc = { "ttd", idc_ttd, idc_ttd_args, nullptr, 0, EXTFUN_BASE };

    void install_script_api(Plugin *plugin)
    {
        g_plugin = plugin;
        if ( !add_idc_func(idc_ttd_desc) )
            msg("[ida-ttd] could not register the IDC function ttd(); scripting is unavailable.\n");
    }

    void remove_script_api()
    {
        del_idc_func("ttd");
        g_drv.close();
        g_plugin = nullptr;
    }
}
