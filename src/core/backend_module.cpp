#include "core/backend_module.h"
#include "core/backend_registry.h"
#include "core/diag.h"

#include <diskio.hpp>   // idadir, get_user_idadir

namespace idattd
{
    // ---------------------------------------------------------------- helpers

    // The core's Position and the ABI's ittd_position are the same two words
    // with the same three sentinels, so the conversion is a copy.
    static ittd_position to_abi(Position p) { return ittd_position{ p.hi, p.lo }; }
    static Position from_abi(ittd_position p) { return Position{ p.hi, p.lo }; }

    static ittd_position_range to_abi(PositionRange r)
    {
        return ittd_position_range{ to_abi(r.first), to_abi(r.last) };
    }

    // A ProgressSink as the ABI's ittd_progress. The sink's percent is
    // coarser than the ABI's permille; the sink is told only when it changes.
    struct ProgressBridge
    {
        ProgressSink *sink = nullptr;
        uint32_t      last = UINT32_MAX;
        ittd_progress abi{};

        explicit ProgressBridge(ProgressSink *s) : sink(s)
        {
            abi.ud        = this;
            abi.report    = &report;
            abi.cancelled = &cancelled;
        }
        const ittd_progress *get() const { return sink != nullptr ? &abi : nullptr; }

        static void report(void *ud, uint32_t permille)
        {
            ProgressBridge *b = static_cast<ProgressBridge *>(ud);
            uint32_t pct = permille >= 1000 ? 100 : permille / 10;
            if ( pct != b->last )
            {
                b->last = pct;
                b->sink->report(pct);
            }
        }
        static int cancelled(void *ud)
        {
            return static_cast<ProgressBridge *>(ud)->sink->cancelled() ? 1 : 0;
        }
    };

    // Whether the table has entry 'f' and fills it: entries added after the
    // first table sit past the 'size' of a backend built before them.
    #define ITTD_HAS(api, f) \
        (offsetof(ittd_backend_api, f) + sizeof((api)->f) <= (api)->size && (api)->f != nullptr)

    static QueryResult result_of(int rc, int truncated)
    {
        QueryResult r;
        r.ran       = rc == ITTD_OK || rc == ITTD_E_CANCELLED;
        r.cancelled = rc == ITTD_E_CANCELLED;
        r.truncated = truncated != 0;
        return r;
    }

    // The count-then-fill convention: ask for the count, then fill an array
    // that large. A backend answers the same count twice for an unchanged
    // recording, but if it ever grew between the calls the array is grown and
    // the fill repeated rather than the tail silently lost.
    template <typename T, typename Call>
    static int count_fill(std::vector<T> *out, Call call)
    {
        size_t n = 0;
        int rc = call((T *)nullptr, (size_t)0, &n);
        for ( int attempt = 0; rc == ITTD_OK && attempt < 3; attempt++ )
        {
            out->assign(n, T{});
            size_t got = n;
            rc = call(out->data(), out->size(), &got);
            if ( rc != ITTD_OK || got <= out->size() )
            {
                out->resize(rc == ITTD_OK ? got : 0);
                return rc;
            }
            n = got;
        }
        return rc;
    }

    // ---------------------------------------------------------------- cursor

    class ModuleCursor : public ITraceCursor
    {
    public:
        ModuleCursor(const ittd_backend_api *api, ittd_cursor *c) : m_api(api), m_c(c) {}
        ~ModuleCursor() override
        {
            if ( m_c != nullptr && m_api->cursor_close != nullptr )
                m_api->cursor_close(m_c);
        }

        ittd_cursor *handle() const { return m_c; }

        Position position() const override
        {
            ittd_position p = to_abi(Position::none());
            if ( m_api->cursor_position != nullptr )
                m_api->cursor_position(m_c, &p);
            return from_abi(p);
        }

        bool seek(Position p) override
        {
            DiagTimer diag_timer("cursor.seek");
            return m_api->cursor_seek != nullptr && m_api->cursor_seek(m_c, to_abi(p)) == ITTD_OK;
        }

        uint32_t thread_id() const override
        {
            uint32_t tid = 0;
            if ( m_api->cursor_thread != nullptr )
                m_api->cursor_thread(m_c, &tid);
            return tid;
        }

        ea_t program_counter() const override
        {
            ittd_regs r;
            return read_registers(&r) ? (ea_t)r.gp[ITTD_REG_RIP] : BADADDR;
        }

        uint64_t stack_pointer() const override
        {
            ittd_regs r;
            return read_registers(&r) ? r.gp[ITTD_REG_RSP] : 0;
        }

        bool read_registers(ittd_regs *out) const override
        {
            DiagTimer diag_timer("cursor.read_registers");
            if ( out == nullptr || m_api->cursor_regs == nullptr )
                return false;
            *out = ittd_regs{};
            return m_api->cursor_regs(m_c, out) == ITTD_OK && (out->have & ITTD_REGS_GP) != 0;
        }

        size_t read_memory(ea_t ea, void *buf, size_t size, std::vector<uint8_t> *known) override
        {
            qstring what;
            what.sprnt("%llX+%llX", (uint64_t)ea, (uint64_t)size);
            DiagTimer diag_timer("cursor.read_memory", what);
            if ( m_api->cursor_read_memory == nullptr || buf == nullptr || size == 0 )
                return 0;
            std::vector<uint8_t> local;
            std::vector<uint8_t> &k = known != nullptr ? *known : local;
            k.assign(size, 0);
            size_t n = 0;
            if ( m_api->cursor_read_memory(m_c, (uint64_t)ea, buf, k.data(), size, &n) != ITTD_OK )
            {
                k.assign(size, 0);
                return 0;
            }
            return n;
        }

        std::vector<ThreadInfo> live_threads() const override;

        bool read_thread_registers(uint32_t tid, ittd_regs *out) const override
        {
            if ( out == nullptr || !ITTD_HAS(m_api, cursor_thread_regs) )
                return false;
            *out = ittd_regs{};
            return m_api->cursor_thread_regs(m_c, tid, out) == ITTD_OK && (out->have & ITTD_REGS_GP) != 0;
        }

        size_t rebuild_range(ea_t lo, ea_t hi, bool replace) override
        {
            uint64_t n = 0;
            if ( !ITTD_HAS(m_api, cursor_rebuild_range)
              || m_api->cursor_rebuild_range(m_c, (uint64_t)lo, (uint64_t)hi, replace ? 1 : 0, &n) != ITTD_OK )
                return 0;
            return (size_t)n;
        }

    private:
        const ittd_backend_api *m_api;
        ittd_cursor            *m_c;
    };

    static ThreadInfo thread_info(const ittd_thread &t)
    {
        ThreadInfo ti;
        ti.tid         = t.tid;
        ti.created     = from_abi(t.created);
        ti.exited      = from_abi(t.exited);
        ti.name        = t.name;
        ti.teb         = (ea_t)t.teb;
        ti.teb32       = (ea_t)t.teb32;
        ti.stack_base  = (ea_t)t.stack_base;
        ti.stack_limit = (ea_t)t.stack_limit;
        return ti;
    }

    std::vector<ThreadInfo> ModuleCursor::live_threads() const
    {
        std::vector<ThreadInfo> out;
        if ( m_api->cursor_threads == nullptr )
            return out;
        std::vector<ittd_thread> v;
        if ( count_fill(&v, [&](ittd_thread *b, size_t cap, size_t *n)
                        { return m_api->cursor_threads(m_c, b, cap, n); }) == ITTD_OK )
            for ( const ittd_thread &t : v )
                out.push_back(thread_info(t));
        return out;
    }

    // ---------------------------------------------------------------- navigator

    class ModuleNavigator : public INavigator
    {
    public:
        ModuleNavigator(const ittd_backend_api *api, ittd_cursor *c) : m_api(api), m_c(c) {}

        StopReason step(bool forward) override      { return go(m_api->nav_step, forward); }
        StopReason step_over(bool forward) override { return go(m_api->nav_step_over, forward); }
        StopReason step_out(bool forward) override  { return go(m_api->nav_step_out, forward); }
        StopReason run(bool forward) override       { return go(m_api->nav_run, forward); }

        StopReason run_to(ea_t addr, bool forward) override
        {
            DiagTimer diag_timer("nav.run_to");
            int stop = ITTD_STOP_FAILED;
            if ( m_api->nav_run_to == nullptr
              || m_api->nav_run_to(m_c, (uint64_t)addr, forward ? 1 : 0, &stop) != ITTD_OK )
                return StopReason::Failed;
            return reason(stop);
        }

        StopReason seek_to(Position p) override
        {
            return m_api->cursor_seek != nullptr && m_api->cursor_seek(m_c, to_abi(p)) == ITTD_OK
                 ? StopReason::Stepped : StopReason::Failed;
        }

        bool set_breakpoints(const std::vector<Breakpoint> &bpts,
                             std::vector<bool> *accepted) override
        {
            if ( accepted != nullptr )
                accepted->assign(bpts.size(), false);
            if ( m_api->nav_breakpoints == nullptr )
                return false;
            std::vector<ittd_breakpoint> v;
            v.reserve(bpts.size());
            for ( const Breakpoint &b : bpts )
            {
                ittd_breakpoint x{};
                x.addr  = (uint64_t)b.addr;
                x.size  = b.size == 0 ? 1 : b.size;
                x.kinds = ((b.kinds & ACCESS_READ)  ? ITTD_ACCESS_READ  : 0)
                        | ((b.kinds & ACCESS_WRITE) ? ITTD_ACCESS_WRITE : 0)
                        | ((b.kinds & ACCESS_EXEC)  ? ITTD_ACCESS_EXEC  : 0);
                v.push_back(x);
            }
            // The ABI answers for the whole set.
            bool ok = m_api->nav_breakpoints(m_c, v.data(), v.size()) == ITTD_OK;
            if ( accepted != nullptr )
                accepted->assign(bpts.size(), ok);
            return ok;
        }

        qstring take_notice() override
        {
            char buf[1024] = { 0 };
            if ( !ITTD_HAS(m_api, nav_take_notice) || m_api->nav_take_notice(m_c, buf, sizeof(buf)) != ITTD_OK )
                return qstring();
            return qstring(buf);
        }

        void set_progress(ProgressSink *progress) override
        {
            if ( !ITTD_HAS(m_api, nav_set_progress) )
                return;
            m_bridge = std::make_unique<ProgressBridge>(progress);
            m_api->nav_set_progress(m_c, m_bridge->get());
        }

    private:
        using NavFn = int (*)(ittd_cursor *, int, int *);

        StopReason go(NavFn fn, bool forward)
        {
            DiagTimer diag_timer(forward ? "nav.forward" : "nav.backward");
            int stop = ITTD_STOP_FAILED;
            // NULL, or a direction the backend does not do (ITTD_E_UNSUPPORTED),
            // is a movement that did not happen.
            if ( fn == nullptr || fn(m_c, forward ? 1 : 0, &stop) != ITTD_OK )
                return StopReason::Failed;
            return reason(stop);
        }

        static StopReason reason(int stop)
        {
            switch ( stop )
            {
                case ITTD_STOP_STEPPED:    return StopReason::Stepped;
                case ITTD_STOP_BREAKPOINT: return StopReason::Breakpoint;
                case ITTD_STOP_BOUNDARY:   return StopReason::TraceBoundary;
                default:                   return StopReason::Failed;
            }
        }

        const ittd_backend_api *m_api;
        ittd_cursor            *m_c;
        std::unique_ptr<ProgressBridge> m_bridge;   // what nav_set_progress was given
    };

    // ---------------------------------------------------------------- module

    BackendModule::BackendModule(const ittd_backend_api *api, const qstring &path)
        : m_api(api), m_path(path)
    {
    }

    BackendModule::~BackendModule()
    {
        close();
    }

    static const char *or_empty(const char *s) { return s != nullptr ? s : ""; }

    const char *BackendModule::id() const
    { return m_api->id != nullptr ? or_empty(m_api->id()) : ""; }
    const char *BackendModule::display_name() const
    { return m_api->display_name != nullptr ? or_empty(m_api->display_name()) : id(); }
    const char *BackendModule::file_filter() const
    { return m_api->file_filter != nullptr ? or_empty(m_api->file_filter()) : ""; }

    bool BackendModule::can_open(const char *path) const
    {
        return path != nullptr && m_api->can_open != nullptr && m_api->can_open(path) != 0;
    }

    qstring BackendModule::last_error() const
    {
        if ( m_api->last_error == nullptr )
            return qstring();
        return qstring(or_empty(m_api->last_error(m_handle)));
    }

    bool BackendModule::open(const char *path, qstring *errbuf)
    {
        DiagTimer diag_timer("backend.open");
        close();
        if ( m_api->open == nullptr || m_api->info == nullptr )
        {
            if ( errbuf != nullptr )
                errbuf->sprnt("%s cannot open recordings", display_name());
            return false;
        }
        m_handle = m_api->open(path);
        if ( m_handle == nullptr )
        {
            if ( errbuf != nullptr )
                *errbuf = last_error();
            return false;
        }

        ittd_trace_info ti{};
        if ( m_api->info(m_handle, &ti) != ITTD_OK )
        {
            if ( errbuf != nullptr )
                *errbuf = last_error();
            close();
            return false;
        }
        m_info.is64         = ti.is64 != 0;
        m_info.fingerprint  = ti.fingerprint;
        m_info.first        = from_abi(ti.first);
        m_info.last         = from_abi(ti.last);
        m_info.main_module  = ti.main_module;
        m_info.backend_name = ti.backend_name;

        uint32_t c = ti.capabilities;
        m_caps.access_queries   = (c & ITTD_CAP_ACCESS_QUERIES) != 0;
        m_caps.call_queries     = (c & ITTD_CAP_CALL_QUERIES) != 0;
        m_caps.mapping_changes  = (c & ITTD_CAP_MAPPING_CHANGES) != 0;
        m_caps.syscalls         = (c & ITTD_CAP_SYSCALLS) != 0 && ITTD_HAS(m_api, query_syscalls);
        m_caps.recorded_exports = (c & ITTD_CAP_RECORDED_EXPORTS) != 0;
        m_caps.cheap_seek       = (c & ITTD_CAP_CHEAP_SEEK) != 0;
        m_caps.reverse_step     = (c & ITTD_CAP_REVERSE_STEP) != 0;
        m_caps.exceptions       = (c & ITTD_CAP_EXCEPTIONS) != 0;
        m_caps.self_modifying   = (c & ITTD_CAP_SELF_MODIFYING) != 0
                               && ITTD_HAS(m_api, query_self_modifying);
        m_caps.fork             = (c & ITTD_CAP_FORK) != 0
                               && ITTD_HAS(m_api, fork_open) && ITTD_HAS(m_api, fork_regs)
                               && ITTD_HAS(m_api, fork_set_regs) && ITTD_HAS(m_api, fork_write_memory)
                               && ITTD_HAS(m_api, fork_record) && ITTD_HAS(m_api, fork_close);
        m_caps.replay_scans     = (c & ITTD_CAP_REPLAY_SCANS) != 0
                               && ITTD_HAS(m_api, query_strings) && ITTD_HAS(m_api, query_buffers);
        m_caps.cheap_reads      = (c & ITTD_CAP_CHEAP_READS) != 0;
        return true;
    }

    void BackendModule::close()
    {
        DiagTimer diag_timer("backend.close");
        if ( m_handle != nullptr && m_api->close != nullptr )
            m_api->close(m_handle);
        m_handle   = nullptr;
        m_info     = TraceInfo{};
        m_caps     = Capabilities{};
        m_prepared = false;
    }

    bool BackendModule::prepare(ProgressSink *progress)
    {
        DiagTimer diag_timer("backend.prepare");
        if ( m_handle == nullptr || m_api->prepare == nullptr )
            return true;
        ProgressBridge pb(progress);
        m_prepared = m_api->prepare(m_handle, pb.get()) == ITTD_OK;
        return m_prepared;
    }

    bool BackendModule::prepared() const
    {
        if ( m_handle == nullptr )
            return false;
        if ( m_api->prepare == nullptr || m_prepared )
            return true;
        return ITTD_HAS(m_api, prepared) && m_api->prepared(m_handle) != 0;
    }

    qstring BackendModule::format_position(Position p) const
    {
        char buf[64] = { 0 };
        if ( !p.is_valid() )
            return qstring();
        if ( m_api->format_position == nullptr
          || m_api->format_position(m_handle, to_abi(p), buf, sizeof(buf)) != ITTD_OK )
        {
            qstring s;
            s.sprnt("%llX:%llX", (uint64_t)p.hi, (uint64_t)p.lo);
            return s;
        }
        return qstring(buf);
    }

    bool BackendModule::parse_position(const char *text, Position *out) const
    {
        ittd_position p{};
        if ( text == nullptr || out == nullptr || m_api->parse_position == nullptr
          || m_api->parse_position(m_handle, text, &p) != ITTD_OK )
            return false;
        *out = from_abi(p);
        return true;
    }

    const char *BackendModule::position_syntax() const
    {
        return m_api->position_syntax != nullptr ? or_empty(m_api->position_syntax(m_handle)) : "";
    }

    CursorPtr BackendModule::make_cursor()
    {
        DiagTimer diag_timer("backend.make_cursor");
        if ( m_handle == nullptr || m_api->cursor_open == nullptr )
            return nullptr;
        ittd_cursor *c = m_api->cursor_open(m_handle);
        if ( c == nullptr )
            return nullptr;
        return std::make_unique<ModuleCursor>(m_api, c);
    }

    std::unique_ptr<INavigator> BackendModule::make_navigator(ITraceCursor *cursor)
    {
        DiagTimer diag_timer("backend.make_navigator");
        // Only a cursor this module made has a handle the DLL knows.
        ModuleCursor *mc = dynamic_cast<ModuleCursor *>(cursor);
        if ( mc == nullptr )
            return nullptr;
        return std::make_unique<ModuleNavigator>(m_api, mc->handle());
    }

    std::vector<ModuleInfo> BackendModule::modules() const
    {
        DiagTimer diag_timer("backend.modules");
        std::vector<ModuleInfo> out;
        std::vector<ittd_module> v;
        if ( m_handle == nullptr || m_api->modules == nullptr
          || count_fill(&v, [&](ittd_module *b, size_t cap, size_t *n)
                        { return m_api->modules(m_handle, b, cap, n); }) != ITTD_OK )
            return out;
        for ( const ittd_module &m : v )
        {
            ModuleInfo mi;
            mi.base     = (ea_t)m.base;
            mi.size     = m.size;
            mi.name     = m.name;
            mi.path     = m.path;
            mi.loaded   = from_abi(m.loaded);
            mi.unloaded = from_abi(m.unloaded);
            mi.machine   = (uint16_t)m.machine;
            mi.timestamp = m.timestamp;
            mi.checksum  = m.checksum;
            out.push_back(mi);
        }
        return out;
    }

    std::vector<ThreadInfo> BackendModule::threads() const
    {
        DiagTimer diag_timer("backend.threads");
        std::vector<ThreadInfo> out;
        std::vector<ittd_thread> v;
        if ( m_handle == nullptr || m_api->threads == nullptr
          || count_fill(&v, [&](ittd_thread *b, size_t cap, size_t *n)
                        { return m_api->threads(m_handle, b, cap, n); }) != ITTD_OK )
            return out;
        for ( const ittd_thread &t : v )
            out.push_back(thread_info(t));
        return out;
    }

    std::vector<TraceEvent> BackendModule::timeline() const
    {
        DiagTimer diag_timer("backend.timeline");
        std::vector<TraceEvent> out;
        std::vector<ittd_trace_event> v;
        if ( m_handle == nullptr || m_api->timeline == nullptr
          || count_fill(&v, [&](ittd_trace_event *b, size_t cap, size_t *n)
                        { return m_api->timeline(m_handle, b, cap, n); }) != ITTD_OK )
            return out;
        for ( const ittd_trace_event &e : v )
        {
            TraceEvent te;
            te.pos  = from_abi(e.pos);
            te.what = e.text;
            out.push_back(te);
        }
        return out;
    }

    // The whole-trace queries all run the same way: count, fill, convert.
    // 'truncated' is the backend's own flag from the fill.

    QueryResult BackendModule::query_accesses(ea_t lo, ea_t hi, uint8_t kinds, PositionRange when,
                                              std::vector<Access> *out, ProgressSink *progress)
    {
        DiagTimer diag_timer("backend.query_accesses");
        if ( m_handle == nullptr || m_api->query_accesses == nullptr || out == nullptr )
            return QueryResult{};
        ProgressBridge pb(progress);
        int trunc = 0;
        uint32_t k = ((kinds & ACCESS_READ)  ? ITTD_ACCESS_READ  : 0)
                   | ((kinds & ACCESS_WRITE) ? ITTD_ACCESS_WRITE : 0)
                   | ((kinds & ACCESS_EXEC)  ? ITTD_ACCESS_EXEC  : 0);
        std::vector<ittd_access> v;
        int rc = count_fill(&v, [&](ittd_access *b, size_t cap, size_t *n)
        {
            return m_api->query_accesses(m_handle, (uint64_t)lo, (uint64_t)hi, k, to_abi(when),
                                         b, cap, n, &trunc, pb.get());
        });
        for ( const ittd_access &a : v )
        {
            Access x;
            x.pos  = from_abi(a.pos);
            x.tid  = a.tid;
            x.pc   = (ea_t)a.pc;
            x.addr = (ea_t)a.addr;
            x.size = a.size;
            x.kind = a.kind == ITTD_ACCESS_READ  ? ACCESS_READ
                   : a.kind == ITTD_ACCESS_WRITE ? ACCESS_WRITE : ACCESS_EXEC;
            out->push_back(x);
        }
        return result_of(rc, trunc);
    }

    QueryResult BackendModule::query_executed(const std::vector<std::pair<ea_t, ea_t>> &ranges,
                                              std::vector<ea_t> *out, ProgressSink *progress)
    {
        DiagTimer diag_timer("backend.query_executed");
        if ( m_handle == nullptr || m_api->query_executed == nullptr || out == nullptr )
            return QueryResult{};
        ProgressBridge pb(progress);
        int trunc = 0;
        std::vector<ittd_range> r;
        for ( const auto &p : ranges )
            r.push_back(ittd_range{ (uint64_t)p.first, (uint64_t)p.second });
        std::vector<uint64_t> v;
        int rc = count_fill(&v, [&](uint64_t *b, size_t cap, size_t *n)
        {
            return m_api->query_executed(m_handle, r.data(), r.size(), b, cap, n, &trunc, pb.get());
        });
        // The ABI's answer is already sorted and distinct.
        for ( uint64_t a : v )
            out->push_back((ea_t)a);
        return result_of(rc, trunc);
    }

    QueryResult BackendModule::query_calls(const std::vector<ea_t> &targets, PositionRange when,
                                           std::vector<CallEvent> *out, ProgressSink *progress)
    {
        DiagTimer diag_timer("backend.query_calls");
        if ( m_handle == nullptr || m_api->query_calls == nullptr || out == nullptr )
            return QueryResult{};
        ProgressBridge pb(progress);
        int trunc = 0;
        std::vector<uint64_t> t(targets.begin(), targets.end());
        std::vector<ittd_call> v;
        int rc = count_fill(&v, [&](ittd_call *b, size_t cap, size_t *n)
        {
            return m_api->query_calls(m_handle, t.data(), t.size(), to_abi(when),
                                      b, cap, n, &trunc, pb.get());
        });
        for ( const ittd_call &c : v )
        {
            CallEvent e;
            e.pos       = from_abi(c.pos);
            e.entry_pos = from_abi(c.entry_pos);
            e.ret_pos   = from_abi(c.ret_pos);
            e.tid       = c.tid;
            e.site      = c.site == ITTD_BADADDR ? BADADDR : (ea_t)c.site;
            e.target    = (ea_t)c.target;
            e.is_call   = (c.flags & ITTD_CALL_F_NOT_CALL) == 0;
            out->push_back(e);
        }
        return result_of(rc, trunc);
    }

    QueryResult BackendModule::query_indirect_targets(const std::vector<std::pair<ea_t, ea_t>> &ranges,
                                                      bool jumps,
                                                      std::map<ea_t, std::vector<IndirectTarget>> *out,
                                                      ProgressSink *progress)
    {
        DiagTimer diag_timer("backend.query_indirect_targets");
        if ( m_handle == nullptr || m_api->query_indirect == nullptr || out == nullptr )
            return QueryResult{};
        ProgressBridge pb(progress);
        int trunc = 0;
        std::vector<ittd_range> r;
        for ( const auto &p : ranges )
            r.push_back(ittd_range{ (uint64_t)p.first, (uint64_t)p.second });
        std::vector<ittd_call_target> v;
        int rc = count_fill(&v, [&](ittd_call_target *b, size_t cap, size_t *n)
        {
            return m_api->query_indirect(m_handle, r.data(), r.size(), jumps ? ITTD_INDIRECT_JUMPS : 0,
                                         b, cap, n, &trunc, pb.get());
        });
        for ( const ittd_call_target &c : v )
        {
            IndirectTarget t;
            t.target  = (ea_t)c.target;
            t.hits    = c.hits;
            t.first   = from_abi(c.first_pos);
            t.is_call = (c.flags & ITTD_CALL_F_NOT_CALL) == 0;
            (*out)[(ea_t)c.site].push_back(t);
        }
        return result_of(rc, trunc);
    }

    QueryResult BackendModule::query_exceptions(std::vector<ExceptionEvent> *out, ProgressSink *progress)
    {
        DiagTimer diag_timer("backend.query_exceptions");
        if ( m_handle == nullptr || m_api->query_exceptions == nullptr || out == nullptr )
            return QueryResult{};
        ProgressBridge pb(progress);
        int trunc = 0;
        std::vector<ittd_exception> v;
        int rc = count_fill(&v, [&](ittd_exception *b, size_t cap, size_t *n)
        {
            return m_api->query_exceptions(m_handle, b, cap, n, &trunc, pb.get());
        });
        for ( const ittd_exception &x : v )
        {
            ExceptionEvent e;
            e.pos            = from_abi(x.pos);
            e.raise_pos      = from_abi(x.raise_pos);
            e.tid            = x.tid;
            e.code           = x.code;
            e.flags          = x.flags;
            e.address        = (ea_t)x.address;
            e.information[0] = x.information[0];
            e.information[1] = x.information[1];
            out->push_back(e);
        }
        return result_of(rc, trunc);
    }

    QueryResult BackendModule::query_syscalls(std::vector<SyscallEvent> *out, ProgressSink *progress)
    {
        DiagTimer diag_timer("backend.query_syscalls");
        if ( m_handle == nullptr || !ITTD_HAS(m_api, query_syscalls) || out == nullptr )
            return QueryResult{};
        ProgressBridge pb(progress);
        int trunc = 0;
        std::vector<ittd_syscall> v;
        int rc = count_fill(&v, [&](ittd_syscall *b, size_t cap, size_t *n)
        {
            return m_api->query_syscalls(m_handle, b, cap, n, &trunc, pb.get());
        });
        out->reserve(v.size());
        for ( const ittd_syscall &x : v )
        {
            SyscallEvent e;
            e.pos    = from_abi(x.pos);
            e.result = x.result;
            e.number = x.number;
            e.tid    = x.tid;
            e.name   = qstring(x.name, strnlen(x.name, sizeof(x.name)));
            out->push_back(std::move(e));
        }
        return result_of(rc, trunc);
    }

    QueryResult BackendModule::query_self_modifying(std::vector<SelfModHit> *out, ProgressSink *progress)
    {
        DiagTimer diag_timer("backend.query_self_modifying");
        if ( m_handle == nullptr || !ITTD_HAS(m_api, query_self_modifying) || out == nullptr )
            return QueryResult{};
        ProgressBridge pb(progress);
        int trunc = 0;
        std::vector<ittd_selfmod> v;
        int rc = count_fill(&v, [&](ittd_selfmod *b, size_t cap, size_t *n)
        {
            return m_api->query_self_modifying(m_handle, b, cap, n, &trunc, pb.get());
        });
        out->reserve(v.size());
        for ( const ittd_selfmod &x : v )
        {
            SelfModHit h;
            h.address     = (ea_t)x.address;
            h.size        = x.size;
            h.write_pos   = from_abi(x.write_pos);
            h.write_ip    = (ea_t)x.write_ip;
            h.execute_pos = from_abi(x.execute_pos);
            h.executions  = x.executions;
            out->push_back(h);
        }
        return result_of(rc, trunc);
    }

    static ittd_fork_settings replay_settings(const ReplaySettings &s)
    {
        ittd_fork_settings fs{};
        fs.size  = sizeof(fs);
        fs.flags = (s.strict ? ITTD_FORK_STRICT : 0) | (s.allow_host ? ITTD_FORK_ALLOW_HOST : 0);
        fs.registry_dir   = s.registry_dir.empty() ? nullptr : s.registry_dir.c_str();
        fs.emulation_root = nullptr;
        return fs;
    }

    qstring BackendModule::scan_notice() const
    {
        if ( m_handle == nullptr || !ITTD_HAS(m_api, scan_notice) )
            return qstring();
        return qstring(or_empty(m_api->scan_notice(m_handle)));
    }

    int BackendModule::note_replay(int rc)
    {
        m_replayBlock = rc == ITTD_E_HOST_REPLAY ? ReplayBlock::HostConsent
                      : rc == ITTD_E_NO_REGISTRY ? ReplayBlock::Registry
                      : ReplayBlock::None;
        return rc;
    }

    QueryResult BackendModule::query_strings(const ReplaySettings &settings, uint32_t min_length,
                                             std::vector<StringHit> *out, ProgressSink *progress)
    {
        DiagTimer diag_timer("backend.query_strings", 0);
        if ( m_handle == nullptr || !ITTD_HAS(m_api, query_strings) || out == nullptr )
            return QueryResult{};
        ProgressBridge pb(progress);
        ittd_fork_settings fs = replay_settings(settings);
        int trunc = 0;
        std::vector<ittd_string_hit> v;
        int rc = count_fill(&v, [&](ittd_string_hit *b, size_t cap, size_t *n)
        {
            return m_api->query_strings(m_handle, &fs, min_length, b, cap, n, &trunc, pb.get());
        });
        note_replay(rc);
        out->reserve(v.size());
        for ( const ittd_string_hit &x : v )
        {
            StringHit h;
            h.address = (ea_t)x.address;
            h.pos     = from_abi(x.pos);
            h.wide    = x.wide != 0;
            h.length  = x.length;
            h.text    = qstring(x.text, strnlen(x.text, sizeof(x.text)));
            out->push_back(std::move(h));
        }
        return result_of(rc, trunc);
    }

    QueryResult BackendModule::query_buffers(const ReplaySettings &settings,
                                             std::vector<BufferHit> *out, ProgressSink *progress)
    {
        DiagTimer diag_timer("backend.query_buffers", 0);
        if ( m_handle == nullptr || !ITTD_HAS(m_api, query_buffers) || out == nullptr )
            return QueryResult{};
        ProgressBridge pb(progress);
        ittd_fork_settings fs = replay_settings(settings);
        int trunc = 0;
        std::vector<ittd_buffer_hit> v;
        int rc = count_fill(&v, [&](ittd_buffer_hit *b, size_t cap, size_t *n)
        {
            return m_api->query_buffers(m_handle, &fs, b, cap, n, &trunc, pb.get());
        });
        note_replay(rc);
        out->reserve(v.size());
        for ( const ittd_buffer_hit &x : v )
        {
            BufferHit h;
            h.address   = (ea_t)x.address;
            h.size      = x.size;
            h.first_pos = from_abi(x.first_pos);
            h.last_pos  = from_abi(x.last_pos);
            h.writer_ip = (ea_t)x.writer_ip;
            h.writes    = x.writes;
            h.kind      = qstring(x.kind, strnlen(x.kind, sizeof(x.kind)));
            h.preview   = qstring(x.preview, strnlen(x.preview, sizeof(x.preview)));
            out->push_back(std::move(h));
        }
        return result_of(rc, trunc);
    }

    ForkResult BackendModule::record_fork(const ForkRequest &req, ProgressSink *progress)
    {
        DiagTimer diag_timer("backend.record_fork", 0);
        ForkResult r;
        if ( m_handle == nullptr || !ITTD_HAS(m_api, fork_close) )
        {
            r.error = "this recording's backend cannot fork it";
            return r;
        }
        auto failed = [&](int rc)
        {
            r.cancelled = rc == ITTD_E_CANCELLED;
            const char *e = m_api->last_error(m_handle);
            r.error = r.cancelled ? qstring("cancelled") : qstring(e != nullptr ? e : "failed");
            return r;
        };

        ProgressBridge pb(progress);
        ittd_fork_settings fs{};
        fs.size  = sizeof(fs);
        fs.flags = (req.strict ? ITTD_FORK_STRICT : 0) | (req.allow_host ? ITTD_FORK_ALLOW_HOST : 0);
        fs.registry_dir   = req.registry_dir.empty() ? nullptr : req.registry_dir.c_str();
        fs.emulation_root = nullptr;
        ittd_fork *f = nullptr;
        int rc = note_replay(m_api->fork_open(m_handle, to_abi(req.at), &fs, pb.get(), &f));
        if ( rc != ITTD_OK || f == nullptr )
            return failed(rc);
        // Whatever happens below, the fork goes.
        struct Closer
        {
            const ittd_backend_api *api; ittd_fork *f;
            ~Closer() { api->fork_close(f); }
        } closer{ m_api, f };

        if ( !req.regs.empty() )
        {
            ittd_regs regs{};
            if ( (rc = m_api->fork_regs(f, &regs)) != ITTD_OK )
                return failed(rc);
            for ( const auto &[idx, value] : req.regs )
            {
                if ( idx == FORK_REG_RFLAGS )
                    regs.rflags = value;
                else if ( idx >= 0 && idx < ITTD_REG_GP_COUNT )
                    regs.gp[idx] = value;
            }
            regs.have = ITTD_REGS_GP;
            if ( (rc = m_api->fork_set_regs(f, &regs)) != ITTD_OK )
                return failed(rc);
        }
        for ( const auto &[ea, bytes] : req.memory )
            if ( (rc = m_api->fork_write_memory(f, (uint64_t)ea, bytes.begin(), bytes.size())) != ITTD_OK )
                return failed(rc);

        uint64_t ran = 0;
        rc = m_api->fork_record(f, req.path.c_str(), req.max_instructions,
                                req.note.c_str(), pb.get(), &ran);
        if ( rc != ITTD_OK )
            return failed(rc);
        r.ok = true;
        r.instructions = ran;
        r.cancelled = progress != nullptr && progress->cancelled();
        return r;
    }

    QueryResult BackendModule::query_mapping_changes(std::vector<ittd_mapping_change> *out,
                                                     std::vector<qstring> *files,
                                                     ProgressSink *progress)
    {
        DiagTimer diag_timer("backend.query_mapping_changes");
        if ( m_handle == nullptr || m_api->query_mapping_changes == nullptr || out == nullptr )
            return QueryResult{};
        ProgressBridge pb(progress);
        int trunc = 0;
        int rc = count_fill(out, [&](ittd_mapping_change *b, size_t cap, size_t *n)
        {
            return m_api->query_mapping_changes(m_handle, b, cap, n, &trunc, pb.get());
        });
        if ( files != nullptr && m_api->query_mapping_files != nullptr )
        {
            std::vector<ittd_name> names;
            if ( count_fill(&names, [&](ittd_name *b, size_t cap, size_t *n)
                            { return m_api->query_mapping_files(m_handle, b, cap, n); }) == ITTD_OK )
                for ( const ittd_name &n : names )
                    files->push_back(qstring(n.name));
        }
        return result_of(rc, trunc);
    }

    Position BackendModule::position_add(Position p, int64_t delta) const
    {
        DiagTimer diag_timer("backend.position_add");
        ittd_position out{};
        if ( m_handle == nullptr || m_api->position_add == nullptr
          || m_api->position_add(m_handle, to_abi(p), delta, &out) != ITTD_OK )
            return p;
        return from_abi(out);
    }

    bool BackendModule::query_frame_entry(Position at, uint32_t tid, uint64_t max_back,
                                          Position *call_pos, ea_t *entry)
    {
        DiagTimer diag_timer("backend.query_frame_entry");
        ittd_position cp{};
        uint64_t e = 0;
        if ( m_handle == nullptr || m_api->query_frame_entry == nullptr
          || m_api->query_frame_entry(m_handle, to_abi(at), tid, max_back, &cp, &e) != ITTD_OK )
            return false;
        if ( call_pos != nullptr )
            *call_pos = from_abi(cp);
        if ( entry != nullptr )
            *entry = (ea_t)e;
        return true;
    }

    QueryResult BackendModule::query_instructions(PositionRange when, uint32_t tid, size_t max,
                                                  std::vector<Access> *out, ProgressSink *progress)
    {
        DiagTimer diag_timer("backend.query_instructions");
        if ( m_handle == nullptr || m_api->query_instructions == nullptr || out == nullptr || max == 0 )
            return QueryResult{};
        // One call into a buffer of 'max': this query is capped, not counted
        // (see the ABI), because counting would cost a replay the full price.
        ProgressBridge pb(progress);
        int trunc = 0;
        std::vector<ittd_access> v(max);
        size_t n = 0;
        int rc = m_api->query_instructions(m_handle, to_abi(when), tid, v.data(), v.size(),
                                           &n, &trunc, pb.get());
        if ( rc == ITTD_OK )
        {
            for ( size_t i = 0; i < n && i < v.size(); i++ )
            {
                Access x;
                x.pos  = from_abi(v[i].pos);
                x.tid  = v[i].tid;
                x.pc   = (ea_t)v[i].pc;
                x.addr = (ea_t)v[i].addr;
                x.size = v[i].size;
                x.kind = ACCESS_EXEC;
                out->push_back(x);
            }
        }
        return result_of(rc, trunc);
    }

    QueryResult BackendModule::registers_at(const std::vector<Position> &positions,
                                            std::vector<ittd_regs> *out, ProgressSink *progress)
    {
        DiagTimer diag_timer("backend.registers_at");
        // A backend without the batch gets the cursor-per-position default.
        if ( m_handle == nullptr || m_api->regs_at == nullptr )
            return ITraceBackend::registers_at(positions, out, progress);
        ProgressBridge pb(progress);
        std::vector<ittd_position> p;
        p.reserve(positions.size());
        for ( Position x : positions )
            p.push_back(to_abi(x));
        out->assign(positions.size(), ittd_regs{});
        int rc = m_api->regs_at(m_handle, p.data(), p.size(), out->data(), pb.get());
        return result_of(rc, 0);
    }

    std::vector<ITraceBackend::Symbol> BackendModule::module_symbols(ea_t base)
    {
        DiagTimer diag_timer("backend.module_symbols");
        std::vector<Symbol> out;
        std::vector<ittd_symbol> v;
        if ( m_handle == nullptr || m_api->module_symbols == nullptr
          || count_fill(&v, [&](ittd_symbol *b, size_t cap, size_t *n)
                        { return m_api->module_symbols(m_handle, (uint64_t)base, b, cap, n); }) != ITTD_OK )
            return out;
        for ( const ittd_symbol &s : v )
        {
            Symbol sym;
            sym.ea        = (ea_t)s.ea;
            sym.name      = s.name;
            sym.is_export = s.is_export != 0;
            out.push_back(sym);
        }
        return out;
    }

    std::vector<std::pair<ea_t, ea_t>> BackendModule::module_functions(ea_t base)
    {
        DiagTimer diag_timer("backend.module_functions");
        std::vector<std::pair<ea_t, ea_t>> out;
        std::vector<ittd_range> v;
        if ( m_handle == nullptr || m_api->module_functions == nullptr
          || count_fill(&v, [&](ittd_range *b, size_t cap, size_t *n)
                        { return m_api->module_functions(m_handle, (uint64_t)base, b, cap, n); }) != ITTD_OK )
            return out;
        for ( const ittd_range &r : v )
            out.push_back({ (ea_t)r.start, (ea_t)r.end });
        return out;
    }

    // ---------------------------------------------------------------- loading

    static std::wstring widen(const qstring &s)
    {
        int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
        if ( n <= 0 )
            return std::wstring();
        std::wstring w((size_t)n - 1, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], n);
        return w;
    }

    static qstring narrow(const wchar_t *w)
    {
        int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
        qstring s;
        if ( n > 1 )
        {
            s.resize(n - 1);
            WideCharToMultiByte(CP_UTF8, 0, w, -1, s.begin(), n, nullptr, nullptr);
        }
        return s;
    }

    // Load one module and register it. Each failure is named, because a
    // backend the user installed and does not see is otherwise a mystery.
    static void load_one(const qstring &path)
    {
        // Search the module's own directory for its dependencies: a backend
        // ships what it needs next to itself (Sogen's Unicorn, in a build that
        // is not static).
        HMODULE h = LoadLibraryExW(widen(path).c_str(), nullptr,
                                   LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
        if ( h == nullptr )
        {
            msg("[ida-ttd] could not load the backend %s (error %lu).\n", path.c_str(), GetLastError());
            return;
        }
        auto entry = (ittd_entry_point)(void *)GetProcAddress(h, ITTD_ENTRY_POINT_NAME);
        if ( entry == nullptr )
        {
            msg("[ida-ttd] %s is not an ida-ttd backend (no %s); skipped.\n",
                path.c_str(), ITTD_ENTRY_POINT_NAME);
            FreeLibrary(h);
            return;
        }
        const ittd_backend_api *api = nullptr;
        try
        {
            api = entry(ITTD_ABI_VERSION);
        }
        catch ( ... )
        {
            api = nullptr;
        }
        if ( api == nullptr || api->abi_version != ITTD_ABI_VERSION || api->id == nullptr )
        {
            msg("[ida-ttd] the backend %s does not speak backend ABI version %u; skipped. "
                "It was built for a different ida-ttd.\n", path.c_str(), ITTD_ABI_VERSION);
            FreeLibrary(h);
            return;
        }

        // Its diagnostics go to the output window.
        if ( ITTD_HAS(api, set_log) )
            api->set_log([](void *, const char *line) { msg("%s", line); }, nullptr);

        auto mod = std::make_unique<BackendModule>(api, path);
        if ( BackendRegistry::instance().by_id(mod->id()) != nullptr )
        {
            msg("[ida-ttd] a backend called '%s' is already loaded; %s skipped.\n",
                mod->id(), path.c_str());
            return;     // keep the module mapped: its table may already be in use
        }
        msg("[ida-ttd] backend loaded: %s (%s) from %s\n",
            mod->display_name(), mod->id(), path.c_str());
        BackendRegistry::instance().add_backend(std::move(mod));
    }

    static void load_dir(const qstring &dir)
    {
        qstring pattern = dir;
        pattern.append("\\*.dll");
        WIN32_FIND_DATAW fd;
        HANDLE f = FindFirstFileW(widen(pattern).c_str(), &fd);
        if ( f == INVALID_HANDLE_VALUE )
            return;
        do
        {
            if ( (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 )
                continue;
            qstring path = dir;
            path.append('\\');
            path.append(narrow(fd.cFileName));
            load_one(path);
        } while ( FindNextFileW(f, &fd) );
        FindClose(f);
    }

    void load_backend_modules()
    {
        static bool done = false;
        if ( done )
            return;
        done = true;

        // Not plugins\ itself: IDA loads everything there as a plugin. And
        // both places a plugin can be: plugins\ida-ttd-backends\ beside a
        // hand-installed ida-ttd.dll, and plugins\ida-ttd\ida-ttd-backends\
        // inside the folder IDA's plugin manager installs the package into.
        // The loader looks in the same places, having no plugin path of its
        // own to go by.
        qstring user = get_user_idadir();
        user.append("\\plugins");
        qstring install = idadir(PLG_SUBDIR);

        // The user's directories first, so a backend they built themselves
        // wins over one an installation shipped (a second module with the
        // same id is skipped).
        for ( const qstring &root : { user, install } )
        {
            qstring flat = root;
            flat.append("\\ida-ttd-backends");
            load_dir(flat);
            qstring packaged = root;
            packaged.append("\\ida-ttd\\ida-ttd-backends");
            load_dir(packaged);
        }
    }
}
