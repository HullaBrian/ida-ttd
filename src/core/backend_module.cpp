#include "core/backend_module.h"
#include "core/abi_convert.h"
#include "core/backend_registry.h"
#include "core/diag.h"

#include <diskio.hpp>   // idadir, get_user_idadir

#include <atomic>

namespace idattd
{
    // ---------------------------------------------------------------- helpers

    // A ProgressSink as the ABI's ittd_progress. The sink takes percent, not
    // permille, and is told only when the percent changes.
    struct ProgressBridge
    {
        ProgressSink *sink = nullptr;
        // Atomic: the ABI lets a backend report from any of its threads.
        std::atomic<uint32_t> last{ UINT32_MAX };
        ittd_progress abi{};

        explicit ProgressBridge(ProgressSink *s) : sink(s)
        {
            abi.ud        = this;
            abi.report    = &report;
            abi.cancelled = &cancelled;
        }
        // abi.ud points at this object, so a copy would hand out a dangling one.
        ProgressBridge(const ProgressBridge &) = delete;
        ProgressBridge &operator=(const ProgressBridge &) = delete;
        const ittd_progress *get() const { return sink != nullptr ? &abi : nullptr; }

        static void report(void *ud, uint32_t permille)
        {
            ProgressBridge *b = static_cast<ProgressBridge *>(ud);
            uint32_t pct = permille >= 1000 ? 100 : permille / 10;
            if ( b->last.exchange(pct, std::memory_order_relaxed) != pct )
                b->sink->report(pct);
        }
        static int cancelled(void *ud)
        {
            return static_cast<ProgressBridge *>(ud)->sink->cancelled() ? 1 : 0;
        }
    };

    // Whether the table has entry 'f' and fills it. Entries added after the
    // first table lie past the 'size' of a backend built before them.
    #define ITTD_HAS(api, f) \
        (offsetof(ittd_backend_api, f) + sizeof((api)->f) <= (api)->size && (api)->f != nullptr)

    // A query's outcome. A cancelled query comes back three ways: as
    // ITTD_E_CANCELLED, as a prefix flagged ITTD_TRUNC_CANCELLED, or (from a
    // backend that predates that flag) as a prefix flagged like a cap. The
    // sink settles the last: a caller with its own sink (not run_query, which
    // keeps a flag of its own) would otherwise act on half an answer as if it
    // were whole.
    static QueryResult result_of(int rc, int truncated, const ProgressBridge &pb)
    {
        QueryResult r;
        r.ran       = rc == ITTD_OK || rc == ITTD_E_CANCELLED;
        r.cancelled = rc == ITTD_E_CANCELLED || truncated == ITTD_TRUNC_CANCELLED
                   || (r.ran && truncated != 0 && pb.sink != nullptr && pb.sink->cancelled());
        r.truncated = truncated != 0;
        return r;
    }

    // A query's outcome, with the backend's reason when it failed, read here
    // on the thread that ran it (QueryResult::error).
    static QueryResult finish_query(const BackendModule *m, int rc, int truncated, const ProgressBridge &pb)
    {
        QueryResult r = result_of(rc, truncated, pb);
        if ( !r.ran && rc != ITTD_E_UNSUPPORTED )
            r.error = m->last_error();
        return r;
    }

    // The count-then-fill convention: ask for the count, then fill an array
    // that large. If the count grew between the calls, the array is grown and
    // the fill repeated (up to three times); when it is still short after
    // that, the answer is what fit and '*truncated' is set. A count too large
    // to allocate fails the query instead of throwing into IDA.
    template <typename T, typename Call>
    static int count_fill(std::vector<T> *out, Call call, int *truncated = nullptr)
    {
        size_t n = 0;
        int rc = call((T *)nullptr, (size_t)0, &n);
        if ( rc != ITTD_OK )
            return rc;
        // Nothing to fill: a second call would only repeat the first.
        if ( n == 0 )
        {
            out->clear();
            return rc;
        }
        for ( int attempt = 0; attempt < 3; attempt++ )
        {
            try
            {
                out->assign(n, T{});
            }
            catch ( const std::exception & )
            {
                out->clear();
                // Close the question anyway: a backend keeps a counted answer
                // until its fill (abi_export does), and without one a large
                // answer stayed pinned until another query replaced it. A
                // fill into a buffer of no entries copies nothing.
                T none{};
                size_t ignored = 0;
                call(&none, (size_t)0, &ignored);
                return ITTD_E_FAILED;
            }
            size_t got = n;
            rc = call(out->data(), out->size(), &got);
            if ( rc != ITTD_OK || got <= out->size() )
            {
                out->resize(rc == ITTD_OK ? got : 0);
                return rc;
            }
            n = got;
        }
        // The count kept growing: keep the last fill, which is valid as far
        // as the array reached, and say it is not the whole answer.
        if ( truncated != nullptr )
            *truncated = 1;
        return rc;
    }

    // An enumeration: count and fill, then each ABI struct as its core type
    // (from_abi). 'available' is the caller's check for a handle and the
    // entry; without it, or when the count or fill fails, the list is empty.
    template <typename AbiT, typename Call>
    static auto list_from_abi(bool available, Call call)
    {
        std::vector<decltype(from_abi(std::declval<const AbiT &>()))> out;
        std::vector<AbiT> v;
        if ( !available || count_fill(&v, call) != ITTD_OK )
            return out;
        for ( const AbiT &x : v )
            out.push_back(from_abi(x));
        return out;
    }

    // Each ABI struct of a query's answer appended to 'out' as its core type.
    template <typename CoreT, typename AbiT>
    static void append_from_abi(const std::vector<AbiT> &v, std::vector<CoreT> *out)
    {
        for ( const AbiT &x : v )
            out->push_back(from_abi(x));
    }

    // A whole-recording query: count, fill, convert, finish. 'available' is
    // the caller's check for a handle, the table entry and somewhere to put
    // the answer; without it the query did not run. 'call' asks the entry
    // once, given the buffer and where the truncated flag and the progress
    // go. 'on_rc' sees the final return code first (note_replay), and
    // 'convert' then gets what the fills gathered, even from a query that
    // failed or was cancelled part way. The outcome is finish_query's, with
    // the backend's flag from the fill (or count_fill's, when the count kept
    // growing) and the backend's reason when it failed.
    template <typename AbiT, typename Call, typename Convert>
    static QueryResult run_count_query(const BackendModule *m, bool available, ProgressSink *progress,
                                       Call call, Convert convert,
                                       const std::function<void(int)> &on_rc = nullptr)
    {
        if ( !available )
            return QueryResult{};
        ProgressBridge pb(progress);
        int trunc = 0;
        std::vector<AbiT> v;
        int rc = count_fill(&v, [&](AbiT *b, size_t cap, size_t *n)
        {
            return call(b, cap, n, &trunc, pb.get());
        }, &trunc);
        if ( on_rc )
            on_rc(rc);
        convert(v);
        return finish_query(m, rc, trunc, pb);
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
            DiagTimer diag_timer("cursor.read_memory", (uint64_t)ea, (uint64_t)size);
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

    std::vector<ThreadInfo> ModuleCursor::live_threads() const
    {
        return list_from_abi<ittd_thread>(m_api->cursor_threads != nullptr,
                                          [&](ittd_thread *b, size_t cap, size_t *n)
                                          { return m_api->cursor_threads(m_c, b, cap, n); });
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
            return stop_from_abi(stop);
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
                v.push_back(to_abi(b));
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
            return fixed_str(buf);
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
            // A NULL entry, or a direction the backend does not support
            // (ITTD_E_UNSUPPORTED), is a movement that did not happen.
            if ( fn == nullptr || fn(m_c, forward ? 1 : 0, &stop) != ITTD_OK )
                return StopReason::Failed;
            return stop_from_abi(stop);
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
        m_info = from_abi(ti);

        uint32_t c = ti.capabilities;
        // Each bit only with the entries it promises, as the header says the
        // bits are for: a backend setting one without them would offer
        // commands that can only fail.
        m_caps = caps_from_abi(c);
        m_caps.access_queries  = m_caps.access_queries
                              && ITTD_HAS(m_api, query_accesses) && ITTD_HAS(m_api, query_executed);
        m_caps.call_queries    = m_caps.call_queries && ITTD_HAS(m_api, query_calls);
        m_caps.mapping_changes = m_caps.mapping_changes && ITTD_HAS(m_api, query_mapping_changes);
        m_caps.syscalls        = m_caps.syscalls && ITTD_HAS(m_api, query_syscalls);
        m_caps.batch_regs      = m_caps.batch_regs && ITTD_HAS(m_api, regs_at);
        m_caps.exceptions      = m_caps.exceptions && ITTD_HAS(m_api, query_exceptions);
        m_caps.self_modifying  = m_caps.self_modifying && ITTD_HAS(m_api, query_self_modifying);
        m_caps.fork            = m_caps.fork
                              && ITTD_HAS(m_api, fork_open) && ITTD_HAS(m_api, fork_regs)
                              && ITTD_HAS(m_api, fork_set_regs) && ITTD_HAS(m_api, fork_write_memory)
                              && ITTD_HAS(m_api, fork_record) && ITTD_HAS(m_api, fork_close);
        m_caps.replay_scans    = m_caps.replay_scans
                              && ITTD_HAS(m_api, query_strings) && ITTD_HAS(m_api, query_buffers);
        // The header promises prepare() is called only when the bit is set,
        // so a backend may leave the entry filled but meaningless for a
        // recording that needs no preparation.
        m_needs_prepare         = (c & ITTD_CAP_PREPARE) != 0 && m_api->prepare != nullptr;
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
        m_needs_prepare = false;
    }

    bool BackendModule::prepare(ProgressSink *progress)
    {
        DiagTimer diag_timer("backend.prepare");
        if ( m_handle == nullptr || !m_needs_prepare )
            return true;
        ProgressBridge pb(progress);
        m_prepared = m_api->prepare(m_handle, pb.get()) == ITTD_OK;
        return m_prepared;
    }

    bool BackendModule::prepared() const
    {
        if ( m_handle == nullptr )
            return false;
        if ( !m_needs_prepare || m_prepared )
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
        return fixed_str(buf);
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
        return list_from_abi<ittd_module>(m_handle != nullptr && m_api->modules != nullptr,
                                          [&](ittd_module *b, size_t cap, size_t *n)
                                          { return m_api->modules(m_handle, b, cap, n); });
    }

    std::vector<ThreadInfo> BackendModule::threads() const
    {
        DiagTimer diag_timer("backend.threads");
        return list_from_abi<ittd_thread>(m_handle != nullptr && m_api->threads != nullptr,
                                          [&](ittd_thread *b, size_t cap, size_t *n)
                                          { return m_api->threads(m_handle, b, cap, n); });
    }

    std::vector<TraceEvent> BackendModule::timeline() const
    {
        DiagTimer diag_timer("backend.timeline");
        return list_from_abi<ittd_trace_event>(m_handle != nullptr && m_api->timeline != nullptr,
                                               [&](ittd_trace_event *b, size_t cap, size_t *n)
                                               { return m_api->timeline(m_handle, b, cap, n); });
    }

    // The whole-trace queries all run the same way (run_count_query):
    // count, fill, convert, finish.

    QueryResult BackendModule::query_accesses(ea_t lo, ea_t hi, uint8_t kinds, PositionRange when,
                                              std::vector<Access> *out, ProgressSink *progress)
    {
        DiagTimer diag_timer("backend.query_accesses");
        uint32_t k = to_abi_kinds(kinds);
        return run_count_query<ittd_access>(this,
            m_handle != nullptr && m_api->query_accesses != nullptr && out != nullptr, progress,
            [&](ittd_access *b, size_t cap, size_t *n, int *trunc, const ittd_progress *p)
            {
                return m_api->query_accesses(m_handle, (uint64_t)lo, (uint64_t)hi, k, to_abi(when),
                                             b, cap, n, trunc, p);
            },
            [&](const std::vector<ittd_access> &v) { append_from_abi(v, out); });
    }

    QueryResult BackendModule::query_executed(const std::vector<std::pair<ea_t, ea_t>> &ranges,
                                              std::vector<ea_t> *out, ProgressSink *progress)
    {
        DiagTimer diag_timer("backend.query_executed");
        std::vector<ittd_range> r = to_abi(ranges);
        return run_count_query<uint64_t>(this,
            m_handle != nullptr && m_api->query_executed != nullptr && out != nullptr, progress,
            [&](uint64_t *b, size_t cap, size_t *n, int *trunc, const ittd_progress *p)
            {
                return m_api->query_executed(m_handle, r.data(), r.size(), b, cap, n, trunc, p);
            },
            // Already sorted and distinct. A module's worth is millions of
            // addresses: one append, not a push_back each.
            [&](const std::vector<uint64_t> &v) { out->insert(out->end(), v.begin(), v.end()); });
    }

    QueryResult BackendModule::query_calls(const std::vector<ea_t> &targets, PositionRange when,
                                           std::vector<CallEvent> *out, ProgressSink *progress)
    {
        DiagTimer diag_timer("backend.query_calls");
        std::vector<uint64_t> t(targets.begin(), targets.end());
        return run_count_query<ittd_call>(this,
            m_handle != nullptr && m_api->query_calls != nullptr && out != nullptr, progress,
            [&](ittd_call *b, size_t cap, size_t *n, int *trunc, const ittd_progress *p)
            {
                return m_api->query_calls(m_handle, t.data(), t.size(), to_abi(when), b, cap, n, trunc, p);
            },
            [&](const std::vector<ittd_call> &v) { append_from_abi(v, out); });
    }

    QueryResult BackendModule::query_indirect_targets(const std::vector<std::pair<ea_t, ea_t>> &ranges,
                                                      bool jumps,
                                                      std::map<ea_t, std::vector<IndirectTarget>> *out,
                                                      ProgressSink *progress)
    {
        DiagTimer diag_timer("backend.query_indirect_targets");
        std::vector<ittd_range> r = to_abi(ranges);
        return run_count_query<ittd_call_target>(this,
            m_handle != nullptr && m_api->query_indirect != nullptr && out != nullptr, progress,
            [&](ittd_call_target *b, size_t cap, size_t *n, int *trunc, const ittd_progress *p)
            {
                return m_api->query_indirect(m_handle, r.data(), r.size(), jumps ? ITTD_INDIRECT_JUMPS : 0,
                                             b, cap, n, trunc, p);
            },
            [&](const std::vector<ittd_call_target> &v)
            {
                for ( const ittd_call_target &c : v )
                    (*out)[(ea_t)c.site].push_back(from_abi(c));
            });
    }

    QueryResult BackendModule::query_exceptions(std::vector<ExceptionEvent> *out, ProgressSink *progress)
    {
        DiagTimer diag_timer("backend.query_exceptions");
        return run_count_query<ittd_exception>(this,
            m_handle != nullptr && m_api->query_exceptions != nullptr && out != nullptr, progress,
            [&](ittd_exception *b, size_t cap, size_t *n, int *trunc, const ittd_progress *p)
            {
                return m_api->query_exceptions(m_handle, b, cap, n, trunc, p);
            },
            [&](const std::vector<ittd_exception> &v) { append_from_abi(v, out); });
    }

    QueryResult BackendModule::query_syscalls(std::vector<SyscallEvent> *out, ProgressSink *progress)
    {
        DiagTimer diag_timer("backend.query_syscalls");
        return run_count_query<ittd_syscall>(this,
            m_handle != nullptr && ITTD_HAS(m_api, query_syscalls) && out != nullptr, progress,
            [&](ittd_syscall *b, size_t cap, size_t *n, int *trunc, const ittd_progress *p)
            {
                return m_api->query_syscalls(m_handle, b, cap, n, trunc, p);
            },
            [&](const std::vector<ittd_syscall> &v)
            {
                out->reserve(v.size());
                append_from_abi(v, out);
            });
    }

    QueryResult BackendModule::query_self_modifying(std::vector<SelfModHit> *out, ProgressSink *progress)
    {
        DiagTimer diag_timer("backend.query_self_modifying");
        return run_count_query<ittd_selfmod>(this,
            m_handle != nullptr && ITTD_HAS(m_api, query_self_modifying) && out != nullptr, progress,
            [&](ittd_selfmod *b, size_t cap, size_t *n, int *trunc, const ittd_progress *p)
            {
                return m_api->query_self_modifying(m_handle, b, cap, n, trunc, p);
            },
            [&](const std::vector<ittd_selfmod> &v)
            {
                out->reserve(v.size());
                append_from_abi(v, out);
            });
    }

    static void backend_log(void *, const char *line);

    // The emulator's log (RecordOptions::log): each line through the
    // backends' own log, which queues lines from a worker thread for the main
    // one.
    // The emulator log's last lines, for a wait box to show while the work
    // runs. Written from the backend's thread, read from the main one.
    // Enough that the recording window, which takes the new lines ten times
    // a second, loses none to a burst (Sogen logs a few dozen lines a
    // recording; guest console output can be more).
    static const size_t       LOG_TAIL_MAX = 4096;
    static std::mutex         g_tail_mtx;
    static std::deque<qstring> g_tail;
    static uint64_t           g_tail_seq = 0;

    uint64_t emulator_log_tail(size_t n, qstrvec_t *out)
    {
        std::lock_guard<std::mutex> lock(g_tail_mtx);
        if ( out != nullptr )
        {
            out->clear();
            const size_t from = g_tail.size() > n ? g_tail.size() - n : 0;
            for ( size_t i = from; i < g_tail.size(); i++ )
                out->push_back(g_tail[i]);
        }
        return g_tail_seq;
    }

    uint64_t emulator_log_since(uint64_t seq, qstrvec_t *out)
    {
        std::lock_guard<std::mutex> lock(g_tail_mtx);
        out->clear();
        // Lines logged after 'seq' that are still kept; a clear() drops
        // lines without moving the count, so never more than are there.
        const uint64_t fresh = g_tail_seq > seq ? g_tail_seq - seq : 0;
        const size_t n = (size_t)std::min<uint64_t>(fresh, g_tail.size());
        for ( size_t i = g_tail.size() - n; i < g_tail.size(); i++ )
            out->push_back(g_tail[i]);
        return g_tail_seq;
    }

    void clear_emulator_log_tail()
    {
        std::lock_guard<std::mutex> lock(g_tail_mtx);
        g_tail.clear();
    }

    // The log callback's context says whether lines also go to the output
    // window (RecordOptions::log); the wait box's tail always gets them.
    static char g_log_to_output;

    static void emulator_log(void *ctx, const char *line)
    {
        if ( line == nullptr )
            return;
        {
            std::lock_guard<std::mutex> lock(g_tail_mtx);
            g_tail.emplace_back(line);
            if ( g_tail.size() > LOG_TAIL_MAX )
                g_tail.pop_front();
            g_tail_seq++;
        }
        if ( ctx != &g_log_to_output )
            return;
        qstring text;
        text.sprnt("[emulator] %s\n", line);
        backend_log(nullptr, text.c_str());
    }

    // The ABI settings with the emulator log attached: lines go to the wait
    // box's tail always when asked for, and to the output window only with
    // RecordOptions::log. They point into 'registry_dir' and 'root', which
    // must outlive them.
    static ittd_fork_settings replay_settings(const qstring &registry_dir, const qstring &root, bool strict,
                                              bool allow_host, bool any_registry, const RecordOptions &rec)
    {
        return to_abi_settings(registry_dir, root, strict, allow_host, any_registry, rec,
                               rec.log || rec.log_tail ? emulator_log : nullptr,
                               rec.log ? &g_log_to_output : nullptr);
    }

    static ittd_fork_settings replay_settings(const ReplaySettings &s)
    {
        return replay_settings(s.registry_dir, s.emulation_root, s.strict, s.allow_host, s.any_registry, s.rec);
    }

    bool BackendModule::replay_env(ReplayEnv *out)
    {
        if ( m_handle == nullptr || !ITTD_HAS(m_api, replay_env) )
            return false;
        ittd_replay_env e{};
        e.size = sizeof(e);
        if ( m_api->replay_env(m_handle, &e) != ITTD_OK )
            return false;
        out->host            = e.host != 0;
        out->registry_known  = e.registry_known != 0;
        out->registry_carried = e.registry_carried != 0;
        out->system_dlls     = e.system_dlls;
        out->registry_hint   = fixed_str(e.registry_hint);
        out->emulation_root  = fixed_str(e.emulation_root);
        out->windows_version = fixed_str(e.windows_version);
        return true;
    }

    HiveCheck BackendModule::check_registry(const char *dir, qstring *why)
    {
        if ( m_handle == nullptr || !ITTD_HAS(m_api, check_registry) )
            return ITraceBackend::check_registry(dir, why);
        int rc = m_api->check_registry(m_handle, dir);
        switch ( rc )
        {
            case ITTD_OK:                  return HiveCheck::Match;
            case ITTD_REGISTRY_UNVERIFIED: return HiveCheck::Unverified;
            case ITTD_E_REGISTRY_MISMATCH:
                if ( why != nullptr )
                    *why = last_error();
                return HiveCheck::Mismatch;
            default:
                if ( why != nullptr )
                    *why = last_error();
                return HiveCheck::Missing;
        }
    }

    qstring BackendModule::scan_notice() const
    {
        if ( m_handle == nullptr || !ITTD_HAS(m_api, scan_notice) )
            return qstring();
        return qstring(or_empty(m_api->scan_notice(m_handle)));
    }

    // What stopped a replay, from the code it failed with: one mapping for
    // forks, scans and new recordings alike.
    static ReplayBlock replay_block_of(int rc)
    {
        return rc == ITTD_E_HOST_REPLAY       ? ReplayBlock::HostConsent
             : rc == ITTD_E_NO_REGISTRY       ? ReplayBlock::Registry
             : rc == ITTD_E_REGISTRY_MISMATCH ? ReplayBlock::RegistryMismatch
             : ReplayBlock::None;
    }

    int BackendModule::note_replay(int rc)
    {
        m_replayBlock = replay_block_of(rc);
        return rc;
    }

    QueryResult BackendModule::query_strings(const ReplaySettings &settings, uint32_t min_length,
                                             std::vector<StringHit> *out, ProgressSink *progress)
    {
        DiagTimer diag_timer("backend.query_strings", 0);
        m_replayBlock = ReplayBlock::None;
        // Points into 'settings', which outlives the query.
        ittd_fork_settings fs = replay_settings(settings);
        return run_count_query<ittd_string_hit>(this,
            m_handle != nullptr && ITTD_HAS(m_api, query_strings) && out != nullptr, progress,
            [&](ittd_string_hit *b, size_t cap, size_t *n, int *trunc, const ittd_progress *p)
            {
                return m_api->query_strings(m_handle, &fs, min_length, b, cap, n, trunc, p);
            },
            [&](const std::vector<ittd_string_hit> &v)
            {
                out->reserve(v.size());
                append_from_abi(v, out);
            },
            [&](int rc) { note_replay(rc); });
    }

    QueryResult BackendModule::query_buffers(const ReplaySettings &settings,
                                             std::vector<BufferHit> *out, ProgressSink *progress)
    {
        DiagTimer diag_timer("backend.query_buffers", 0);
        m_replayBlock = ReplayBlock::None;
        ittd_fork_settings fs = replay_settings(settings);
        return run_count_query<ittd_buffer_hit>(this,
            m_handle != nullptr && ITTD_HAS(m_api, query_buffers) && out != nullptr, progress,
            [&](ittd_buffer_hit *b, size_t cap, size_t *n, int *trunc, const ittd_progress *p)
            {
                return m_api->query_buffers(m_handle, &fs, b, cap, n, trunc, p);
            },
            [&](const std::vector<ittd_buffer_hit> &v)
            {
                out->reserve(v.size());
                append_from_abi(v, out);
            },
            [&](int rc) { note_replay(rc); });
    }

    ForkResult BackendModule::record_fork(const ForkRequest &req, ProgressSink *progress)
    {
        DiagTimer diag_timer("backend.record_fork", 0);
        m_replayBlock = ReplayBlock::None;
        ForkResult r;
        // m_caps.fork holds only when the table fills every fork_* entry.
        if ( m_handle == nullptr || !m_caps.fork )
        {
            r.error = "this recording's backend cannot fork it";
            return r;
        }
        auto failed = [&](int rc)
        {
            r.cancelled = rc == ITTD_E_CANCELLED;
            r.error = r.cancelled ? qstring("cancelled") : last_error();
            if ( r.error.empty() )
                r.error = "failed";
            return r;
        };

        ProgressBridge pb(progress);
        ittd_fork_settings fs = replay_settings(req.registry_dir, req.emulation_root, req.strict, req.allow_host,
                                                req.any_registry, req.rec);
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

    bool BackendModule::can_record() const
    {
        return ITTD_HAS(m_api, record_program);
    }

    ForkResult BackendModule::record_program(const RecordRequest &req, ProgressSink *progress)
    {
        DiagTimer diag_timer("backend.record_program", 0);
        ForkResult r;
        if ( !can_record() )
        {
            r.error = "this backend cannot record programs";
            return r;
        }
        ProgressBridge pb(progress);
        ittd_fork_settings fs = replay_settings(req.registry_dir, req.emulation_root, false, req.allow_host,
                                                false, req.rec);
        ittd_record_request rq{};
        rq.size             = sizeof(rq);
        rq.application      = req.application.c_str();
        rq.arguments        = req.arguments.empty() ? nullptr : req.arguments.c_str();
        rq.working_dir      = req.working_dir.empty() ? nullptr : req.working_dir.c_str();
        rq.out_path         = req.path.c_str();
        rq.max_instructions = req.max_instructions;
        rq.start_time       = req.start_time;
        uint64_t ran = 0;
        // Module-level: its errors are last_error(NULL), not the open
        // recording's.
        const int rc = m_api->record_program(&rq, &fs, pb.get(), &ran);
        if ( rc != ITTD_OK )
        {
            r.cancelled = rc == ITTD_E_CANCELLED;
            r.block = replay_block_of(rc);
            r.error = r.cancelled ? qstring("cancelled") : qstring(or_empty(m_api->last_error(nullptr)));
            if ( r.error.empty() )
                r.error = "failed";
            return r;
        }
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
        }, &trunc);
        if ( files != nullptr && m_api->query_mapping_files != nullptr )
        {
            std::vector<ittd_name> names;
            if ( count_fill(&names, [&](ittd_name *b, size_t cap, size_t *n)
                            { return m_api->query_mapping_files(m_handle, b, cap, n); }) == ITTD_OK )
                for ( const ittd_name &n : names )
                    files->push_back(from_abi(n));
        }
        return finish_query(this, rc, trunc, pb);
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
                                          Position *call_pos, ea_t *entry, ProgressSink *progress)
    {
        DiagTimer diag_timer("backend.query_frame_entry");
        ittd_position cp{};
        uint64_t e = 0;
        if ( m_handle == nullptr )
            return false;
        // The cancellable entry when there is a sink to answer to.
        if ( progress != nullptr && ITTD_HAS(m_api, query_frame_entry_progress) )
        {
            ProgressBridge pb(progress);
            if ( m_api->query_frame_entry_progress(m_handle, to_abi(at), tid, max_back, &cp, &e, pb.get()) != ITTD_OK )
                return false;
        }
        else if ( m_api->query_frame_entry == nullptr
               || m_api->query_frame_entry(m_handle, to_abi(at), tid, max_back, &cp, &e) != ITTD_OK )
        {
            return false;
        }
        if ( call_pos != nullptr )
            *call_pos = from_abi(cp);
        if ( entry != nullptr )
            *entry = (ea_t)e;
        return true;
    }

    static void append_heat(const std::vector<ittd_heat_cell> &v, std::vector<HeatCell> *out)
    {
        out->reserve(out->size() + v.size());
        append_from_abi(v, out);
    }

    QueryResult BackendModule::query_access_heat(uint32_t page_shift, uint32_t slices,
                                                 std::vector<HeatCell> *out, ProgressSink *progress)
    {
        DiagTimer diag_timer("backend.query_access_heat", 0);
        return run_count_query<ittd_heat_cell>(this,
            m_handle != nullptr && ITTD_HAS(m_api, query_access_heat) && out != nullptr, progress,
            [&](ittd_heat_cell *b, size_t cap, size_t *n, int *trunc, const ittd_progress *p)
            {
                return m_api->query_access_heat(m_handle, page_shift, slices, b, cap, n, trunc, p);
            },
            [&](const std::vector<ittd_heat_cell> &v) { append_heat(v, out); });
    }

    bool BackendModule::can_window_heat() const
    {
        return m_handle != nullptr && ITTD_HAS(m_api, query_access_heat_window)
            && ITTD_HAS(m_api, heat_window_slice_position);
    }

    QueryResult BackendModule::query_access_heat_window(uint32_t page_shift, uint32_t slices,
                                                        PositionRange when, std::vector<HeatCell> *out,
                                                        ProgressSink *progress)
    {
        // The whole recording goes through the original entry, which every
        // heatmap backend has and which caches its answer.
        if ( when.whole_trace() )
            return query_access_heat(page_shift, slices, out, progress);
        DiagTimer diag_timer("backend.query_access_heat_window", 0);
        const ittd_position_range w = to_abi(when);
        return run_count_query<ittd_heat_cell>(this,
            can_window_heat() && out != nullptr, progress,
            [&](ittd_heat_cell *b, size_t cap, size_t *n, int *trunc, const ittd_progress *p)
            {
                return m_api->query_access_heat_window(m_handle, page_shift, slices, w, b, cap, n, trunc, p);
            },
            [&](const std::vector<ittd_heat_cell> &v) { append_heat(v, out); });
    }

    Position BackendModule::heat_window_slice_position(uint32_t slices, uint32_t slice, PositionRange when)
    {
        if ( when.whole_trace() )
            return heat_slice_position(slices, slice);
        ittd_position p{};
        if ( !can_window_heat()
          || m_api->heat_window_slice_position(m_handle, slices, slice, to_abi(when), &p) != ITTD_OK )
            return Position::none();
        return from_abi(p);
    }

    bool BackendModule::query_out_values(const std::vector<OutSlot> &slots,
                                         std::vector<std::optional<uint64_t>> *out, ProgressSink *progress)
    {
        DiagTimer diag_timer("backend.query_out_values", 0);
        if ( m_handle == nullptr || !ITTD_HAS(m_api, query_out_values) || out == nullptr )
            return false;
        std::vector<ittd_out_slot> in(slots.size());
        for ( size_t i = 0; i < slots.size(); i++ )
            in[i] = to_abi(slots[i]);
        std::vector<uint64_t> values(slots.size(), 0);
        std::vector<uint8_t>  known(slots.size(), 0);
        ProgressBridge pb(progress);
        if ( m_api->query_out_values(m_handle, in.data(), in.size(), values.data(), known.data(), pb.get()) != ITTD_OK )
            return false;
        out->assign(slots.size(), std::nullopt);
        for ( size_t i = 0; i < slots.size(); i++ )
            if ( known[i] != 0 )
                (*out)[i] = values[i];
        return true;
    }

    Position BackendModule::heat_slice_position(uint32_t slices, uint32_t slice)
    {
        ittd_position p{};
        if ( m_handle == nullptr || !ITTD_HAS(m_api, heat_slice_position)
          || m_api->heat_slice_position(m_handle, slices, slice, &p) != ITTD_OK )
            return Position::none();
        return from_abi(p);
    }

    bool BackendModule::query_register_change(Position at, uint32_t tid, uint32_t reg, uint64_t max_back,
                                              Position *where, bool *found, ProgressSink *progress)
    {
        DiagTimer diag_timer("backend.query_register_change", 0);
        if ( m_handle == nullptr || !ITTD_HAS(m_api, query_register_change) )
            return false;
        ProgressBridge pb(progress);
        ittd_position p{};
        int f = 0;
        if ( m_api->query_register_change(m_handle, to_abi(at), tid, reg, max_back, &p, &f, pb.get()) != ITTD_OK )
            return false;
        if ( found != nullptr )
            *found = f != 0;
        if ( where != nullptr )
            *where = from_abi(p);
        return true;
    }

    QueryResult BackendModule::query_instructions(PositionRange when, uint32_t tid, size_t max,
                                                  std::vector<Access> *out, ProgressSink *progress)
    {
        DiagTimer diag_timer("backend.query_instructions");
        if ( m_handle == nullptr || m_api->query_instructions == nullptr || out == nullptr || max == 0 )
            return QueryResult{};
        // One call into a buffer of 'max': this query is capped, not counted,
        // because counting would cost a replay the full price.
        ProgressBridge pb(progress);
        int trunc = 0;
        std::vector<ittd_access> v(max);
        size_t n = 0;
        int rc = m_api->query_instructions(m_handle, to_abi(when), tid, v.data(), v.size(),
                                           &n, &trunc, pb.get());
        if ( rc == ITTD_OK )
        {
            // Every one an execution, whatever kind the backend wrote.
            for ( size_t i = 0; i < n && i < v.size(); i++ )
            {
                Access x = from_abi(v[i]);
                x.kind = ACCESS_EXEC;
                out->push_back(x);
            }
        }
        return finish_query(this, rc, trunc, pb);
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
        return finish_query(this, rc, 0, pb);
    }

    QueryResult BackendModule::read_memory_at(const std::vector<MemAt> &reads, std::vector<uint8_t> *data,
                                              std::vector<uint8_t> *known, ProgressSink *progress)
    {
        DiagTimer diag_timer("backend.read_memory_at");
        // A backend without the batch gets a cursor seeked to each position.
        if ( m_handle == nullptr || !ITTD_HAS(m_api, read_memory_at) )
            return ITraceBackend::read_memory_at(reads, data, known, progress);
        size_t total = 0;
        std::vector<ittd_mem_read> in(reads.size());
        for ( size_t i = 0; i < reads.size(); i++ )
        {
            in[i] = to_abi(reads[i]);
            total = std::max(total, reads[i].offset + reads[i].size);
        }
        data->assign(total, 0);
        known->assign(total, ITTD_KNOWN_NO);
        ProgressBridge pb(progress);
        int rc = m_api->read_memory_at(m_handle, in.data(), in.size(), data->data(), known->data(), pb.get());
        if ( rc == ITTD_E_UNSUPPORTED )
            return ITraceBackend::read_memory_at(reads, data, known, progress);
        return finish_query(this, rc, 0, pb);
    }

    // visit_positions' callback, through the C ABI: 'ud' is the VisitFn, and
    // the backend's reader is wrapped as a VisitRead for the call.
    static void visit_trampoline(void *ud, size_t index, int phase, ittd_read_fn read, void *read_ctx) noexcept
    {
        try
        {
            const ITraceBackend::VisitFn &fn = *static_cast<const ITraceBackend::VisitFn *>(ud);
            ITraceBackend::VisitRead r = [read, read_ctx](uint64_t addr, void *buf, size_t size) -> size_t
            {
                return read != nullptr ? read(read_ctx, addr, buf, size) : 0;
            };
            fn(index, phase, r);
        }
        catch ( ... )
        {
            // Nothing may unwind into the backend.
        }
    }

    QueryResult BackendModule::visit_positions(const std::vector<Position> &at, const std::vector<Position> *after,
                                               const VisitFn &fn, ProgressSink *progress)
    {
        DiagTimer diag_timer("backend.visit_positions");
        if ( m_handle == nullptr || !ITTD_HAS(m_api, visit_positions) || at.empty() )
            return QueryResult{};
        std::vector<ittd_position> a(at.size()), b;
        for ( size_t i = 0; i < at.size(); i++ )
            a[i] = to_abi(at[i]);
        if ( after != nullptr )
        {
            b.resize(at.size(), to_abi(Position::none()));
            for ( size_t i = 0; i < at.size() && i < after->size(); i++ )
                b[i] = to_abi((*after)[i]);
        }
        ProgressBridge pb(progress);
        const int rc = m_api->visit_positions(m_handle, a.data(), after != nullptr ? b.data() : nullptr, a.size(),
                                              visit_trampoline, const_cast<VisitFn *>(&fn), pb.get());
        if ( rc == ITTD_E_UNSUPPORTED )
            return QueryResult{};
        return finish_query(this, rc, 0, pb);
    }

    std::vector<ITraceBackend::Symbol> BackendModule::module_symbols(ea_t base)
    {
        DiagTimer diag_timer("backend.module_symbols");
        return list_from_abi<ittd_symbol>(m_handle != nullptr && m_api->module_symbols != nullptr,
                                          [&](ittd_symbol *b, size_t cap, size_t *n)
                                          { return m_api->module_symbols(m_handle, (uint64_t)base, b, cap, n); });
    }

    std::vector<std::pair<ea_t, ea_t>> BackendModule::module_functions(ea_t base)
    {
        DiagTimer diag_timer("backend.module_functions");
        return list_from_abi<ittd_range>(m_handle != nullptr && m_api->module_functions != nullptr,
                                         [&](ittd_range *b, size_t cap, size_t *n)
                                         { return m_api->module_functions(m_handle, (uint64_t)base, b, cap, n); });
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

    // ------------------------------------------------------- backend logging
    //
    // A backend logs from whichever thread runs its query (a run_query worker
    // or the engine's own). msg() is not called from such a thread: output can
    // reach Python (IDAPython and other plugins watch it), and a script
    // waiting on the query holds the GIL on the main thread, so the worker
    // would stall until the UI next ran Python. Lines from other threads are
    // queued and printed by the main thread: at its next log line, from
    // run_query's wait loop, or from a posted UI request.
    static DWORD                g_main_tid = 0;
    static std::mutex           g_log_mtx;
    static std::vector<qstring> g_log_queue;
    // Whether a line queued from another thread may post a PrintQueuedLines
    // request. The loader turns it off: IDA unloads ttd-loader.dll after
    // load_file, and a request still queued then would run unmapped code.
    static std::atomic<bool>    g_post_requests{ true };
    // PrintQueuedLines requests posted and not yet run. IDA owns a posted
    // request and calls its run() through a vtable in this binary, so one
    // still queued when the binary is unloaded would call unmapped code;
    // backend_log_unloading() pins the binary then.
    static std::atomic<int>     g_requests_queued{ 0 };

    // The tables of the registered modules, whose log callbacks this binary
    // sets and clears. They live in backend DLLs that are never unloaded.
    static std::vector<const ittd_backend_api *> g_log_apis;
    // Whether this binary's callback is the one installed.
    static bool                 g_log_attached = false;

    static void print_queued_lines()
    {
        std::vector<qstring> lines;
        {
            std::lock_guard<std::mutex> lock(g_log_mtx);
            lines.swap(g_log_queue);
        }
        for ( const qstring &l : lines )
            msg("%s", l.c_str());
    }

    struct PrintQueuedLines : public ui_request_t
    {
        bool idaapi run() override
        {
            g_requests_queued--;
            print_queued_lines();
            return false;
        }
    };

    static void backend_log(void *, const char *line)
    {
        if ( line == nullptr )
            return;
        if ( GetCurrentThreadId() == g_main_tid )
        {
            print_queued_lines();
            msg("%s", line);
            return;
        }
        bool first;
        {
            std::lock_guard<std::mutex> lock(g_log_mtx);
            first = g_log_queue.empty();
            g_log_queue.push_back(qstring(line));
        }
        // One request per batch; IDA owns and deletes it.
        if ( first && g_post_requests )
        {
            g_requests_queued++;
            execute_ui_requests(new PrintQueuedLines, nullptr);
        }
    }

    void flush_backend_log()
    {
        if ( GetCurrentThreadId() == g_main_tid )
            print_queued_lines();
    }

    void attach_backend_log(bool post_requests)
    {
        g_post_requests = post_requests;
        for ( const ittd_backend_api *api : g_log_apis )
            api->set_log(backend_log, nullptr);
        g_log_attached = !g_log_apis.empty();
    }

    static void clear_backend_log()
    {
        if ( !g_log_attached )
            return;
        for ( const ittd_backend_api *api : g_log_apis )
            api->set_log(nullptr, nullptr);
        g_log_attached = false;
    }

    void detach_backend_log()
    {
        clear_backend_log();
        flush_backend_log();
    }

    void backend_log_unloading()
    {
        g_post_requests = false;
        detach_backend_log();
        if ( g_requests_queued.load() <= 0 )
            return;
        // A request is still in IDA's queue and there is no withdrawing it:
        // this binary stays mapped for the rest of the process instead.
        HMODULE self = nullptr;
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                           reinterpret_cast<LPCWSTR>(&print_queued_lines), &self);
    }

    // When this binary is unloaded (the plugin at the end of a session, the
    // loader after load_file), a callback it left installed would dangle in
    // the backend, which stays loaded. This runs from the CRT's teardown,
    // where printing is unsafe, so it only clears.
    static struct BackendLogGuard
    {
        ~BackendLogGuard() { clear_backend_log(); }
    } g_log_guard;

    // Load one module and register it. Each failure is named, so an installed
    // backend that does not appear can be explained.
    static void load_one(const qstring &path)
    {
        // Search the module's own directory for its dependencies: a backend
        // ships them beside itself (Sogen's Unicorn, in a non-static build).
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
        // Any version since the last layout change will do: what was added
        // after it is read only up to the table's 'size' (ITTD_HAS), so an
        // older backend in the user's folder keeps loading after an upgrade.
        // Every entry up to set_log was in the first table of that layout and
        // is read without a size check, so a shorter table is refused.
        if ( api == nullptr || api->abi_version < ITTD_ABI_LAYOUT || api->id == nullptr
          || api->size < offsetof(ittd_backend_api, set_log) )
        {
            msg("[ida-ttd] the backend %s does not speak backend ABI version %u (or a later "
                "one with the same layout); skipped. It was built for a different ida-ttd.\n",
                path.c_str(), ITTD_ABI_VERSION);
            FreeLibrary(h);
            return;
        }

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
        // Its diagnostics go to the output window once load_backend_modules
        // or attach_backend_log installs the callback.
        if ( ITTD_HAS(api, set_log) )
            g_log_apis.push_back(api);
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

    qstring user_data_dir(const char *sub)
    {
        qstring dir = get_user_idadir();
        dir.append("\\ida-ttd");
        if ( sub != nullptr )
        {
            dir.append('\\');
            dir.append(sub);
        }
        return dir;
    }

    static void load_all_dirs()
    {
        // First the backends the user installed (TTD > Backends > Install the
        // Sogen backend puts it there), so they win over shipped ones: a
        // second module with the same id is skipped.
        load_dir(user_data_dir("backends"));

        // Then the plugin's own backend folders, never plugins\ itself (IDA
        // loads everything there as a plugin): plugins\ida-ttd-backends\
        // beside a hand-installed ida-ttd.dll (also where earlier versions put
        // the Sogen backend), and plugins\ida-ttd\ida-ttd-backends\ in the
        // HCLI package folder. The loader searches the same places, having no
        // plugin path of its own.
        qstring user = get_user_idadir();
        user.append("\\plugins");
        qstring install = idadir(PLG_SUBDIR);
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

    void load_backend_modules(bool install_log)
    {
        static bool done = false;
        if ( done )
        {
            // The loader may have pointed the shared tables elsewhere since.
            if ( install_log )
                attach_backend_log(true);
            return;
        }
        done = true;
        // Called first from the plugin's init (or the loader's accept_file),
        // on the main thread.
        g_main_tid = GetCurrentThreadId();
        load_all_dirs();
        if ( install_log )
            attach_backend_log(true);
    }
}
