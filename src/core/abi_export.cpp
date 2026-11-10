#include "core/abi_export.h"

#include <cstring>
#include <mutex>

namespace idattd
{
    // ---------------------------------------------------------------- state

    static BackendFactory g_factory = nullptr;
    static LogSetter      g_set_log = nullptr;
    static BackendPtr     g_identity;     // unopened: id, names, can_open

    // A handle's last error. The core runs queries on a worker thread while
    // the main thread reads cursors on the same handle and later reads the
    // failure reason, so the text sits behind a mutex. get() hands out a
    // per-thread copy, which another thread's failure cannot reallocate; it
    // stays valid until the same thread asks again.
    struct ErrorSlot
    {
        void set(const char *text)
        {
            std::lock_guard<std::mutex> lock(m_mtx);
            m_text = text != nullptr ? text : "";
        }
        const char *get() const
        {
            thread_local std::string copy;
            std::lock_guard<std::mutex> lock(m_mtx);
            copy = m_text;
            return copy.c_str();
        }

    private:
        mutable std::mutex m_mtx;
        std::string        m_text;
    };

    static ErrorSlot      g_error;        // last_error(NULL)

    // One answer kept between a count query's two calls.
    struct CachedAnswer
    {
        std::string           key;
        std::shared_ptr<void> data;
        int                   rc = ITTD_OK;
        int                   truncated = 0;
        int                   served = 0;
    };

    // 'cache' and 'mapping_files' are guarded by 'mtx': the core may run a
    // query on a worker while the main thread asks another on the same
    // handle. The lock is never held while a query computes, so a long query
    // does not stall the other thread and cancellation cannot deadlock on it.
    struct ExportedBackend
    {
        BackendPtr           b;
        ErrorSlot            error;
        std::mutex           mtx;
        CachedAnswer         cache;
        std::vector<qstring> mapping_files;   // from the last query_mapping_changes
    };

    struct ExportedCursor
    {
        ExportedBackend            *owner = nullptr;
        CursorPtr                   c;
        std::unique_ptr<INavigator> nav;      // made on the first movement
        std::unique_ptr<ProgressSink> nav_sink;
        // read_memory's 'known', reused between reads to avoid an allocation
        // per read; a cursor is used by one thread at a time.
        std::vector<uint8_t>        known;
    };

    static ExportedBackend *B(ittd_backend *h) { return reinterpret_cast<ExportedBackend *>(h); }
    static ExportedCursor  *C(ittd_cursor *h)  { return reinterpret_cast<ExportedCursor *>(h); }

    // ---------------------------------------------------------------- helpers

    static ittd_position to_abi(Position p) { return ittd_position{ p.hi, p.lo }; }
    static Position from_abi(ittd_position p) { return Position{ p.hi, p.lo }; }
    static PositionRange from_abi(ittd_position_range r) { return PositionRange{ from_abi(r.first), from_abi(r.last) }; }
    static ittd_position_range to_abi(PositionRange r) { return ittd_position_range{ to_abi(r.first), to_abi(r.last) }; }

    static std::vector<std::pair<ea_t, ea_t>> from_abi(const ittd_range *ranges, size_t n)
    {
        std::vector<std::pair<ea_t, ea_t>> r;
        r.reserve(n);
        for ( size_t i = 0; i < n; i++ )
            r.push_back({ (ea_t)ranges[i].start, (ea_t)ranges[i].end });
        return r;
    }

    // Into a fixed-size ABI field, cut to fit and always terminated. Not
    // qstrncpy: this file is built into a backend that does not link ida.dll.
    static void copy_str(char *dst, size_t cap, const char *src)
    {
        if ( cap == 0 )
            return;
        size_t n = src != nullptr ? strlen(src) : 0;
        if ( n >= cap )
            n = cap - 1;
        if ( n != 0 )
            memcpy(dst, src, n);
        dst[n] = '\0';
    }

    // An ittd_progress as the ProgressSink a C++ backend takes.
    class AbiSink : public ProgressSink
    {
    public:
        explicit AbiSink(const ittd_progress *p) : m_p(p) {}
        void report(uint32_t percent) override
        {
            if ( m_p != nullptr && m_p->report != nullptr )
                m_p->report(m_p->ud, percent >= 100 ? 1000 : percent * 10);
        }
        bool cancelled() override
        {
            return m_p != nullptr && m_p->cancelled != nullptr && m_p->cancelled(m_p->ud) != 0;
        }

    private:
        const ittd_progress *m_p;
    };

    // Every entry point catches: an exception must not cross the C boundary.
    //
    // A call that fails without throwing takes the backend's own reason, even
    // an empty one, so an earlier failure's reason never answers for this one
    // (the core says something generic for an empty reason). Cancelling is
    // not a failure and leaves the slot alone.
    template <typename F>
    static int guarded(ExportedBackend *h, F f)
    {
        try
        {
            // This call's reason only: the backend keeps one per thread, and
            // what an earlier call on this thread left must not answer for
            // this one (a failure that sets no reason reported a stale one).
            h->b->clear_error();
            int rc = f();
            if ( rc != ITTD_OK && rc != ITTD_E_CANCELLED )
                h->error.set(h->b->last_error().c_str());
            return rc;
        }
        catch ( const std::exception &e )
        {
            h->error.set(e.what());
        }
        catch ( ... )
        {
            h->error.set("unexpected exception in the backend");
        }
        return ITTD_E_FAILED;
    }

    // The count-then-fill convention, for answers that are cheap to produce.
    template <typename T, typename S, typename Conv>
    static int fill(const std::vector<S> &src, T *buf, size_t cap, size_t *out_count, Conv conv)
    {
        if ( out_count != nullptr )
            *out_count = src.size();
        if ( buf != nullptr )
            for ( size_t i = 0; i < src.size() && i < cap; i++ )
                buf[i] = conv(src[i]);
        return ITTD_OK;
    }

    // The same for an expensive answer: computed once for the count call,
    // handed out again for the fill, then dropped. 'key' identifies the
    // question, so a different one is never answered from the cache.
    template <typename T>
    static int answer(ExportedBackend *h, const std::string &key, T *buf, size_t cap,
                      size_t *out_count, int *out_truncated,
                      const std::function<QueryResult(std::vector<T> *)> &run)
    {
        CachedAnswer &c = h->cache;
        std::shared_ptr<void> data;
        int rc = ITTD_OK;
        int truncated = 0;
        {
            std::lock_guard<std::mutex> lock(h->mtx);
            if ( c.key == key && c.data != nullptr )
            {
                data      = c.data;
                rc        = c.rc;
                truncated = c.truncated;
            }
        }
        if ( data == nullptr )
        {
            // Computed without the lock. Two threads asking at once each
            // compute; the later store wins, and a fill that then finds
            // another key in the cache computes again, which is slow but
            // still answers its own question.
            auto v = std::make_shared<std::vector<T>>();
            QueryResult r = run(v.get());
            data      = v;
            rc        = !r.ran ? ITTD_E_UNSUPPORTED : r.cancelled ? ITTD_E_CANCELLED : ITTD_OK;
            truncated = r.truncated || r.cancelled ? 1 : 0;
            std::lock_guard<std::mutex> lock(h->mtx);
            c.key       = key;
            c.data      = data;
            c.rc        = rc;
            c.truncated = truncated;
            c.served    = 0;
        }
        // The shared_ptr keeps this answer alive even if another thread
        // replaces the cache entry meanwhile.
        const std::vector<T> &v = *std::static_pointer_cast<std::vector<T>>(data);
        if ( out_count != nullptr )
            *out_count = v.size();
        if ( out_truncated != nullptr )
            *out_truncated = truncated;
        if ( buf != nullptr )
            for ( size_t i = 0; i < v.size() && i < cap; i++ )
                buf[i] = v[i];
        // After a count and its fill, or a fill alone, the question is
        // answered. A failed count gets no fill, so it is not kept either:
        // asking again reruns the query rather than repeating the failure.
        // Nor does an empty answer: the core skips the fill when the count
        // is zero, and a kept entry would answer the next identical question
        // (a cancelled one included) without running it.
        bool failed = rc != ITTD_OK && rc != ITTD_E_CANCELLED;
        {
            std::lock_guard<std::mutex> lock(h->mtx);
            if ( c.data == data && (++c.served >= 2 || buf != nullptr || failed || v.empty()) )
            {
                c.data.reset();
                c.key.clear();
            }
        }
        // A cancelled count still reports what it gathered, as ITTD_OK with
        // the truncated flag set.
        return rc == ITTD_E_CANCELLED ? ITTD_OK : rc;
    }

    // A cache key: the query's name and the bytes of its arguments.
    struct Key
    {
        std::string s;
        explicit Key(const char *what) : s(what) {}
        template <typename T>
        Key &add(const T &v) { s.append((const char *)&v, sizeof(T)); return *this; }
        Key &add_bytes(const void *p, size_t n) { s.append((const char *)p, n); return *this; }
    };

    // One access's kind: a single ITTD_ACCESS_* value.
    static uint32_t to_abi_kind(uint8_t k)
    {
        return (k & ACCESS_READ) ? ITTD_ACCESS_READ : (k & ACCESS_WRITE) ? ITTD_ACCESS_WRITE : ITTD_ACCESS_EXEC;
    }

    // A set of ITTD_ACCESS_* bits as AccessKind bits.
    static uint8_t from_abi_kinds(uint32_t k)
    {
        return (uint8_t)(((k & ITTD_ACCESS_READ)  ? ACCESS_READ  : 0)
                       | ((k & ITTD_ACCESS_WRITE) ? ACCESS_WRITE : 0)
                       | ((k & ITTD_ACCESS_EXEC)  ? ACCESS_EXEC  : 0));
    }

    static ittd_access to_abi(const Access &a)
    {
        ittd_access x{};
        x.pos  = to_abi(a.pos);
        x.pc   = a.pc == BADADDR ? ITTD_BADADDR : (uint64_t)a.pc;
        x.addr = a.addr == BADADDR ? ITTD_BADADDR : (uint64_t)a.addr;
        x.size = a.size;
        x.kind = to_abi_kind(a.kind);
        x.tid  = a.tid;
        return x;
    }

    static ittd_thread to_abi(const ThreadInfo &t)
    {
        ittd_thread x{};
        x.tid         = t.tid;
        x.created     = to_abi(t.created);
        x.exited      = to_abi(t.exited);
        x.teb         = (uint64_t)t.teb;
        x.teb32       = (uint64_t)t.teb32;
        x.stack_base  = (uint64_t)t.stack_base;
        x.stack_limit = (uint64_t)t.stack_limit;
        copy_str(x.name, sizeof(x.name), t.name.c_str());
        return x;
    }

    static int stop_of(StopReason r)
    {
        switch ( r )
        {
            case StopReason::Stepped:       return ITTD_STOP_STEPPED;
            case StopReason::Breakpoint:    return ITTD_STOP_BREAKPOINT;
            case StopReason::TraceBoundary: return ITTD_STOP_BOUNDARY;
            default:                        return ITTD_STOP_FAILED;
        }
    }

    // ---------------------------------------------------------------- identity

    static const char *x_id()           { return g_identity->id(); }
    static const char *x_display_name() { return g_identity->display_name(); }
    static const char *x_file_filter()  { return g_identity->file_filter(); }

    static int x_can_open(const char *path)
    {
        try
        {
            return path != nullptr && g_identity->can_open(path) ? 1 : 0;
        }
        catch ( ... )
        {
            return 0;
        }
    }

    // ---------------------------------------------------------------- session

    static ittd_backend *x_open(const char *path)
    {
        try
        {
            auto h = std::make_unique<ExportedBackend>();
            h->b = g_factory();
            qstring err;
            if ( h->b == nullptr || !h->b->open(path, &err) )
            {
                g_error.set(err.empty() ? "the recording could not be opened" : err.c_str());
                return nullptr;
            }
            return reinterpret_cast<ittd_backend *>(h.release());
        }
        catch ( const std::exception &e )
        {
            g_error.set(e.what());
        }
        catch ( ... )
        {
            g_error.set("unexpected exception while opening the recording");
        }
        return nullptr;
    }

    static void x_close(ittd_backend *hb)
    {
        ExportedBackend *h = B(hb);
        if ( h == nullptr )
            return;
        try { h->b->close(); } catch ( ... ) {}
        delete h;
    }

    static const char *x_last_error(ittd_backend *hb)
    {
        return hb != nullptr ? B(hb)->error.get() : g_error.get();
    }

    static int x_info(ittd_backend *hb, ittd_trace_info *out)
    {
        ExportedBackend *h = B(hb);
        if ( h == nullptr || out == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(h, [&]()
        {
            const TraceInfo &ti = h->b->info();
            const Capabilities &c = h->b->capabilities();
            *out = ittd_trace_info{};
            out->is64        = ti.is64 ? 1 : 0;
            out->fingerprint = ti.fingerprint;
            out->first       = to_abi(ti.first);
            out->last        = to_abi(ti.last);
            copy_str(out->main_module, sizeof(out->main_module), ti.main_module.c_str());
            copy_str(out->backend_name, sizeof(out->backend_name), ti.backend_name.c_str());
            uint32_t caps = 0;
            if ( c.access_queries )   caps |= ITTD_CAP_ACCESS_QUERIES;
            if ( c.call_queries )     caps |= ITTD_CAP_CALL_QUERIES;
            if ( c.mapping_changes )  caps |= ITTD_CAP_MAPPING_CHANGES;
            if ( c.syscalls )         caps |= ITTD_CAP_SYSCALLS;
            if ( c.recorded_exports ) caps |= ITTD_CAP_RECORDED_EXPORTS;
            if ( c.cheap_seek )       caps |= ITTD_CAP_CHEAP_SEEK;
            if ( c.batch_regs )       caps |= ITTD_CAP_BATCH_REGS;
            if ( c.reverse_step )     caps |= ITTD_CAP_REVERSE_STEP;
            if ( c.exceptions )       caps |= ITTD_CAP_EXCEPTIONS;
            if ( c.self_modifying )   caps |= ITTD_CAP_SELF_MODIFYING;
            if ( c.fork )             caps |= ITTD_CAP_FORK;
            if ( c.replay_scans )     caps |= ITTD_CAP_REPLAY_SCANS;
            if ( c.cheap_reads )      caps |= ITTD_CAP_CHEAP_READS;
            if ( !h->b->prepared() )  caps |= ITTD_CAP_PREPARE;
            out->capabilities = caps;
            return ITTD_OK;
        });
    }

    static int x_prepare(ittd_backend *hb, const ittd_progress *progress)
    {
        ExportedBackend *h = B(hb);
        if ( h == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(h, [&]()
        {
            AbiSink sink(progress);
            return h->b->prepare(&sink) ? ITTD_OK : ITTD_E_FAILED;
        });
    }

    static int x_prepared(ittd_backend *hb)
    {
        ExportedBackend *h = B(hb);
        try
        {
            return h != nullptr && h->b->prepared() ? 1 : 0;
        }
        catch ( ... )
        {
            return 0;
        }
    }

    // ---------------------------------------------------------------- positions

    static int x_format_position(ittd_backend *hb, ittd_position p, char *buf, size_t buf_size)
    {
        ExportedBackend *h = B(hb);
        if ( h == nullptr || buf == nullptr || buf_size == 0 )
            return ITTD_E_BAD_ARG;
        return guarded(h, [&]()
        {
            copy_str(buf, buf_size, h->b->format_position(from_abi(p)).c_str());
            return ITTD_OK;
        });
    }

    static int x_parse_position(ittd_backend *hb, const char *text, ittd_position *out)
    {
        ExportedBackend *h = B(hb);
        if ( h == nullptr || text == nullptr || out == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(h, [&]()
        {
            Position p;
            if ( !h->b->parse_position(text, &p) )
                return ITTD_E_BAD_ARG;
            *out = to_abi(p);
            return ITTD_OK;
        });
    }

    static const char *x_position_syntax(ittd_backend *hb)
    {
        ExportedBackend *h = B(hb);
        return h != nullptr ? h->b->position_syntax() : g_identity->position_syntax();
    }

    // ---------------------------------------------------------------- cursors

    static ittd_cursor *x_cursor_open(ittd_backend *hb)
    {
        ExportedBackend *h = B(hb);
        if ( h == nullptr )
            return nullptr;
        try
        {
            auto c = std::make_unique<ExportedCursor>();
            c->owner = h;
            c->c     = h->b->make_cursor();
            if ( c->c == nullptr )
                return nullptr;
            return reinterpret_cast<ittd_cursor *>(c.release());
        }
        catch ( ... )
        {
            return nullptr;
        }
    }

    static void x_cursor_close(ittd_cursor *hc)
    {
        ExportedCursor *c = C(hc);
        if ( c == nullptr )
            return;
        try
        {
            c->nav.reset();     // before the cursor it moves
            c->c.reset();
        }
        catch ( ... )
        {
        }
        delete c;
    }

    static int x_cursor_position(ittd_cursor *hc, ittd_position *out)
    {
        ExportedCursor *c = C(hc);
        if ( c == nullptr || out == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(c->owner, [&]() { *out = to_abi(c->c->position()); return ITTD_OK; });
    }

    static int x_cursor_seek(ittd_cursor *hc, ittd_position p)
    {
        ExportedCursor *c = C(hc);
        if ( c == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(c->owner, [&]()
        {
            return c->c->seek(from_abi(p)) ? ITTD_OK : ITTD_E_NO_POSITION;
        });
    }

    static int x_cursor_thread(ittd_cursor *hc, uint32_t *out)
    {
        ExportedCursor *c = C(hc);
        if ( c == nullptr || out == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(c->owner, [&]() { *out = c->c->thread_id(); return ITTD_OK; });
    }

    static int x_cursor_regs(ittd_cursor *hc, ittd_regs *out)
    {
        ExportedCursor *c = C(hc);
        if ( c == nullptr || out == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(c->owner, [&]()
        {
            *out = ittd_regs{};
            return c->c->read_registers(out) ? ITTD_OK : ITTD_E_FAILED;
        });
    }

    static int x_cursor_thread_regs(ittd_cursor *hc, uint32_t tid, ittd_regs *out)
    {
        ExportedCursor *c = C(hc);
        if ( c == nullptr || out == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(c->owner, [&]()
        {
            *out = ittd_regs{};
            return c->c->read_thread_registers(tid, out) ? ITTD_OK : ITTD_E_UNSUPPORTED;
        });
    }

    static int x_cursor_read_memory(ittd_cursor *hc, uint64_t ea, void *buf, uint8_t *known,
                                    size_t size, size_t *out_known)
    {
        ExportedCursor *c = C(hc);
        if ( c == nullptr || (buf == nullptr && size != 0) )
            return ITTD_E_BAD_ARG;
        return guarded(c->owner, [&]()
        {
            std::vector<uint8_t> &k = c->known;
            k.clear();
            size_t n = c->c->read_memory((ea_t)ea, buf, size, &k);
            if ( known != nullptr && size != 0 )
            {
                size_t have = std::min(k.size(), size);
                if ( have != 0 )
                    memcpy(known, k.data(), have);
                if ( have < size )
                    memset(known + have, ITTD_KNOWN_NO, size - have);
            }
            if ( out_known != nullptr )
                *out_known = n;
            return ITTD_OK;
        });
    }

    static int x_cursor_threads(ittd_cursor *hc, ittd_thread *buf, size_t cap, size_t *out_count)
    {
        ExportedCursor *c = C(hc);
        if ( c == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(c->owner, [&]()
        {
            return fill(c->c->live_threads(), buf, cap, out_count,
                        [](const ThreadInfo &t) { return to_abi(t); });
        });
    }

    static int x_cursor_rebuild_range(ittd_cursor *hc, uint64_t lo, uint64_t hi, int replace,
                                      uint64_t *out_bytes)
    {
        ExportedCursor *c = C(hc);
        if ( c == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(c->owner, [&]()
        {
            size_t n = c->c->rebuild_range((ea_t)lo, (ea_t)hi, replace != 0);
            if ( out_bytes != nullptr )
                *out_bytes = n;
            return ITTD_OK;
        });
    }

    // ---------------------------------------------------------------- navigation

    static INavigator *nav(ExportedCursor *c)
    {
        if ( c->nav == nullptr )
            c->nav = c->owner->b->make_navigator(c->c.get());
        return c->nav.get();
    }

    template <typename Move>
    static int navigate(ittd_cursor *hc, int *out_stop, Move move)
    {
        ExportedCursor *c = C(hc);
        if ( c == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(c->owner, [&]()
        {
            INavigator *n = nav(c);
            if ( n == nullptr )
                return ITTD_E_UNSUPPORTED;
            StopReason r = move(n);
            if ( out_stop != nullptr )
                *out_stop = stop_of(r);
            return ITTD_OK;
        });
    }

    static int x_nav_step(ittd_cursor *c, int fwd, int *s)
    { return navigate(c, s, [&](INavigator *n) { return n->step(fwd != 0); }); }
    static int x_nav_step_over(ittd_cursor *c, int fwd, int *s)
    { return navigate(c, s, [&](INavigator *n) { return n->step_over(fwd != 0); }); }
    static int x_nav_step_out(ittd_cursor *c, int fwd, int *s)
    { return navigate(c, s, [&](INavigator *n) { return n->step_out(fwd != 0); }); }
    static int x_nav_run(ittd_cursor *c, int fwd, int *s)
    { return navigate(c, s, [&](INavigator *n) { return n->run(fwd != 0); }); }
    static int x_nav_run_to(ittd_cursor *c, uint64_t addr, int fwd, int *s)
    { return navigate(c, s, [&](INavigator *n) { return n->run_to((ea_t)addr, fwd != 0); }); }

    static int x_nav_breakpoints(ittd_cursor *hc, const ittd_breakpoint *bpts, size_t count)
    {
        ExportedCursor *c = C(hc);
        if ( c == nullptr || (bpts == nullptr && count != 0) )
            return ITTD_E_BAD_ARG;
        return guarded(c->owner, [&]()
        {
            INavigator *n = nav(c);
            if ( n == nullptr )
                return ITTD_E_UNSUPPORTED;
            std::vector<Breakpoint> v;
            for ( size_t i = 0; i < count; i++ )
            {
                Breakpoint b;
                b.addr  = (ea_t)bpts[i].addr;
                b.size  = bpts[i].size == 0 ? 1 : bpts[i].size;
                b.kinds = from_abi_kinds(bpts[i].kinds);
                v.push_back(b);
            }
            return n->set_breakpoints(v, nullptr) ? ITTD_OK : ITTD_E_FAILED;
        });
    }

    static int x_nav_take_notice(ittd_cursor *hc, char *buf, size_t buf_size)
    {
        ExportedCursor *c = C(hc);
        if ( c == nullptr || buf == nullptr || buf_size == 0 )
            return ITTD_E_BAD_ARG;
        return guarded(c->owner, [&]()
        {
            INavigator *n = nav(c);
            copy_str(buf, buf_size, n != nullptr ? n->take_notice().c_str() : "");
            return ITTD_OK;
        });
    }

    static int x_nav_set_progress(ittd_cursor *hc, const ittd_progress *progress)
    {
        ExportedCursor *c = C(hc);
        if ( c == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(c->owner, [&]()
        {
            INavigator *n = nav(c);
            if ( n == nullptr )
                return ITTD_E_UNSUPPORTED;
            if ( progress == nullptr )
            {
                n->set_progress(nullptr);
                c->nav_sink.reset();
            }
            else
            {
                c->nav_sink = std::make_unique<AbiSink>(progress);
                n->set_progress(c->nav_sink.get());
            }
            return ITTD_OK;
        });
    }

    // ---------------------------------------------------------------- enumeration

    static int x_modules(ittd_backend *hb, ittd_module *buf, size_t cap, size_t *out_count)
    {
        ExportedBackend *h = B(hb);
        if ( h == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(h, [&]()
        {
            return fill(h->b->modules(), buf, cap, out_count, [](const ModuleInfo &m)
            {
                ittd_module x{};
                x.base      = (uint64_t)m.base;
                x.size      = m.size;
                x.loaded    = to_abi(m.loaded);
                x.unloaded  = to_abi(m.unloaded);
                x.machine   = m.machine;
                x.timestamp = m.timestamp;
                x.checksum  = m.checksum;
                copy_str(x.name, sizeof(x.name), m.name.c_str());
                copy_str(x.path, sizeof(x.path), m.path.c_str());
                return x;
            });
        });
    }

    static int x_threads(ittd_backend *hb, ittd_thread *buf, size_t cap, size_t *out_count)
    {
        ExportedBackend *h = B(hb);
        if ( h == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(h, [&]()
        {
            return fill(h->b->threads(), buf, cap, out_count, [](const ThreadInfo &t) { return to_abi(t); });
        });
    }

    static int x_timeline(ittd_backend *hb, ittd_trace_event *buf, size_t cap, size_t *out_count)
    {
        ExportedBackend *h = B(hb);
        if ( h == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(h, [&]()
        {
            return fill(h->b->timeline(), buf, cap, out_count, [](const TraceEvent &e)
            {
                ittd_trace_event x{};
                x.pos  = to_abi(e.pos);
                x.kind = ITTD_EV_OTHER;
                copy_str(x.text, sizeof(x.text), e.what.c_str());
                return x;
            });
        });
    }

    // ---------------------------------------------------------------- queries

    static int x_query_accesses(ittd_backend *hb, uint64_t lo, uint64_t hi, uint32_t kinds,
                                ittd_position_range when, ittd_access *buf, size_t cap,
                                size_t *out_count, int *out_truncated, const ittd_progress *progress)
    {
        ExportedBackend *h = B(hb);
        if ( h == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(h, [&]()
        {
            Key k("accesses");
            k.add(lo).add(hi).add(kinds).add(when);
            return answer<ittd_access>(h, k.s, buf, cap, out_count, out_truncated,
                                       [&](std::vector<ittd_access> *out)
            {
                std::vector<Access> v;
                AbiSink sink(progress);
                QueryResult r = h->b->query_accesses((ea_t)lo, (ea_t)hi, from_abi_kinds(kinds),
                                                     from_abi(when), &v, &sink);
                out->reserve(v.size());
                for ( const Access &a : v )
                    out->push_back(to_abi(a));
                return r;
            });
        });
    }

    static int x_query_executed(ittd_backend *hb, const ittd_range *ranges, size_t nranges,
                                uint64_t *buf, size_t cap, size_t *out_count, int *out_truncated,
                                const ittd_progress *progress)
    {
        ExportedBackend *h = B(hb);
        if ( h == nullptr || (ranges == nullptr && nranges != 0) )
            return ITTD_E_BAD_ARG;
        return guarded(h, [&]()
        {
            Key k("executed");
            k.add_bytes(ranges, nranges * sizeof(ittd_range));
            return answer<uint64_t>(h, k.s, buf, cap, out_count, out_truncated,
                                    [&](std::vector<uint64_t> *out)
            {
                std::vector<ea_t> v;
                AbiSink sink(progress);
                QueryResult res = h->b->query_executed(from_abi(ranges, nranges), &v, &sink);
                out->assign(v.begin(), v.end());
                return res;
            });
        });
    }

    static int x_query_calls(ittd_backend *hb, const uint64_t *targets, size_t ntargets,
                             ittd_position_range when, ittd_call *buf, size_t cap,
                             size_t *out_count, int *out_truncated, const ittd_progress *progress)
    {
        ExportedBackend *h = B(hb);
        if ( h == nullptr || (targets == nullptr && ntargets != 0) )
            return ITTD_E_BAD_ARG;
        return guarded(h, [&]()
        {
            Key k("calls");
            k.add(when).add_bytes(targets, ntargets * sizeof(uint64_t));
            return answer<ittd_call>(h, k.s, buf, cap, out_count, out_truncated,
                                     [&](std::vector<ittd_call> *out)
            {
                std::vector<ea_t> t(targets, targets + ntargets);
                std::vector<CallEvent> v;
                AbiSink sink(progress);
                QueryResult r = h->b->query_calls(t, from_abi(when), &v, &sink);
                out->reserve(v.size());
                for ( const CallEvent &e : v )
                {
                    ittd_call x{};
                    x.pos       = to_abi(e.pos);
                    x.entry_pos = to_abi(e.entry_pos);
                    x.ret_pos   = to_abi(e.ret_pos);
                    x.site      = e.site == BADADDR ? ITTD_BADADDR : (uint64_t)e.site;
                    x.target    = (uint64_t)e.target;
                    x.tid       = e.tid;
                    x.flags     = e.is_call ? 0 : ITTD_CALL_F_NOT_CALL;
                    out->push_back(x);
                }
                return r;
            });
        });
    }

    static int x_query_indirect(ittd_backend *hb, const ittd_range *ranges, size_t nranges,
                                uint32_t flags, ittd_call_target *buf, size_t cap,
                                size_t *out_count, int *out_truncated, const ittd_progress *progress)
    {
        ExportedBackend *h = B(hb);
        if ( h == nullptr || (ranges == nullptr && nranges != 0) )
            return ITTD_E_BAD_ARG;
        return guarded(h, [&]()
        {
            Key k("indirect");
            k.add(flags).add_bytes(ranges, nranges * sizeof(ittd_range));
            return answer<ittd_call_target>(h, k.s, buf, cap, out_count, out_truncated,
                                            [&](std::vector<ittd_call_target> *out)
            {
                std::map<ea_t, std::vector<IndirectTarget>> m;
                AbiSink sink(progress);
                QueryResult res = h->b->query_indirect_targets(from_abi(ranges, nranges),
                                                               (flags & ITTD_INDIRECT_JUMPS) != 0, &m, &sink);
                for ( const auto &kv : m )
                    for ( const IndirectTarget &t : kv.second )
                    {
                        ittd_call_target x{};
                        x.site      = (uint64_t)kv.first;
                        x.target    = (uint64_t)t.target;
                        x.hits      = t.hits;
                        x.first_pos = to_abi(t.first);
                        x.flags     = t.is_call ? 0 : ITTD_CALL_F_NOT_CALL;
                        out->push_back(x);
                    }
                return res;
            });
        });
    }

    static int x_query_exceptions(ittd_backend *hb, ittd_exception *buf, size_t cap,
                                  size_t *out_count, int *out_truncated, const ittd_progress *progress)
    {
        ExportedBackend *h = B(hb);
        if ( h == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(h, [&]()
        {
            return answer<ittd_exception>(h, "exceptions", buf, cap, out_count, out_truncated,
                                          [&](std::vector<ittd_exception> *out)
            {
                std::vector<ExceptionEvent> v;
                AbiSink sink(progress);
                QueryResult r = h->b->query_exceptions(&v, &sink);
                out->reserve(v.size());
                for ( const ExceptionEvent &e : v )
                {
                    ittd_exception x{};
                    x.pos            = to_abi(e.pos);
                    x.raise_pos      = to_abi(e.raise_pos);
                    x.address        = (uint64_t)e.address;
                    x.information[0] = e.information[0];
                    x.information[1] = e.information[1];
                    x.code           = e.code;
                    x.flags          = e.flags;
                    x.tid            = e.tid;
                    out->push_back(x);
                }
                return r;
            });
        });
    }

    static int x_query_syscalls(ittd_backend *hb, ittd_syscall *buf, size_t cap,
                                size_t *out_count, int *out_truncated, const ittd_progress *progress)
    {
        ExportedBackend *h = B(hb);
        if ( h == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(h, [&]()
        {
            return answer<ittd_syscall>(h, "syscalls", buf, cap, out_count, out_truncated,
                                        [&](std::vector<ittd_syscall> *out)
            {
                std::vector<SyscallEvent> v;
                AbiSink sink(progress);
                QueryResult r = h->b->query_syscalls(&v, &sink);
                out->reserve(v.size());
                for ( const SyscallEvent &e : v )
                {
                    ittd_syscall x{};
                    x.pos    = to_abi(e.pos);
                    x.result = e.result;
                    x.number = e.number;
                    x.tid    = e.tid;
                    copy_str(x.name, sizeof(x.name), e.name.c_str());
                    out->push_back(x);
                }
                return r;
            });
        });
    }

    static ReplaySettings replay_settings(const ittd_fork_settings *s)
    {
        // Each field only when the caller's struct is new enough to carry it.
        auto has = [s](size_t offset, size_t size) { return s != nullptr && offset + size <= s->size; };
        ReplaySettings rs;
        if ( has(offsetof(ittd_fork_settings, emulation_root), sizeof(s->emulation_root)) )
        {
            rs.registry_dir = s->registry_dir != nullptr ? s->registry_dir : "";
            rs.emulation_root = s->emulation_root != nullptr ? s->emulation_root : "";
            rs.strict       = (s->flags & ITTD_FORK_STRICT) != 0;
            rs.allow_host   = (s->flags & ITTD_FORK_ALLOW_HOST) != 0;
            rs.any_registry = (s->flags & ITTD_FORK_ANY_REGISTRY) != 0;
        }
        if ( has(offsetof(ittd_fork_settings, log_ctx), sizeof(s->log_ctx)) )
        {
            rs.rec.network             = s->network == ITTD_NET_LIVE;
            rs.rec.access_mask         = s->access_mask;
            rs.rec.checkpoint_interval = s->checkpoint_interval;
            rs.rec.elevated            = s->elevated != 0;
            rs.rec.log                 = s->log != nullptr;
        }
        return rs;
    }

    // A replay scan's settings, for its cache key: the same scan against other
    // hives or another root is another question. The ABI 3 fields are left
    // out: a scan replays the recording itself, offline whatever 'network'
    // says, and the others shape only a new recording or the log.
    static void add_settings(Key *k, const ittd_fork_settings *s)
    {
        uint32_t flags = s != nullptr ? s->flags : 0;
        const char *reg  = s != nullptr && s->registry_dir != nullptr ? s->registry_dir : "";
        const char *root = s != nullptr && s->emulation_root != nullptr ? s->emulation_root : "";
        k->add(flags).add_bytes(reg, strlen(reg) + 1).add_bytes(root, strlen(root) + 1);
    }

    static int x_query_strings(ittd_backend *hb, const ittd_fork_settings *settings, uint32_t min_length,
                               ittd_string_hit *buf, size_t cap, size_t *out_count,
                               int *out_truncated, const ittd_progress *progress)
    {
        ExportedBackend *h = B(hb);
        if ( h == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(h, [&]()
        {
            Key k("strings");
            k.add(min_length);
            add_settings(&k, settings);
            return answer<ittd_string_hit>(h, k.s, buf, cap, out_count, out_truncated,
                                           [&](std::vector<ittd_string_hit> *out)
            {
                std::vector<StringHit> v;
                AbiSink sink(progress);
                QueryResult r = h->b->query_strings(replay_settings(settings), min_length, &v, &sink);
                out->reserve(v.size());
                for ( const StringHit &e : v )
                {
                    ittd_string_hit x{};
                    x.address = (uint64_t)e.address;
                    x.pos     = to_abi(e.pos);
                    x.wide    = e.wide ? 1 : 0;
                    x.length  = e.length;
                    copy_str(x.text, sizeof(x.text), e.text.c_str());
                    out->push_back(x);
                }
                return r;
            });
        });
    }

    static int x_query_buffers(ittd_backend *hb, const ittd_fork_settings *settings,
                               ittd_buffer_hit *buf, size_t cap, size_t *out_count,
                               int *out_truncated, const ittd_progress *progress)
    {
        ExportedBackend *h = B(hb);
        if ( h == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(h, [&]()
        {
            Key k("buffers");
            add_settings(&k, settings);
            return answer<ittd_buffer_hit>(h, k.s, buf, cap, out_count, out_truncated,
                                           [&](std::vector<ittd_buffer_hit> *out)
            {
                std::vector<BufferHit> v;
                AbiSink sink(progress);
                QueryResult r = h->b->query_buffers(replay_settings(settings), &v, &sink);
                out->reserve(v.size());
                for ( const BufferHit &e : v )
                {
                    ittd_buffer_hit x{};
                    x.address   = (uint64_t)e.address;
                    x.size      = e.size;
                    x.first_pos = to_abi(e.first_pos);
                    x.last_pos  = to_abi(e.last_pos);
                    x.writer_ip = (uint64_t)e.writer_ip;
                    x.writes    = e.writes;
                    copy_str(x.kind, sizeof(x.kind), e.kind.c_str());
                    copy_str(x.preview, sizeof(x.preview), e.preview.c_str());
                    out->push_back(x);
                }
                return r;
            });
        });
    }

    static int x_query_self_modifying(ittd_backend *hb, ittd_selfmod *buf, size_t cap,
                                      size_t *out_count, int *out_truncated,
                                      const ittd_progress *progress)
    {
        ExportedBackend *h = B(hb);
        if ( h == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(h, [&]()
        {
            return answer<ittd_selfmod>(h, "selfmod", buf, cap, out_count, out_truncated,
                                        [&](std::vector<ittd_selfmod> *out)
            {
                std::vector<SelfModHit> v;
                AbiSink sink(progress);
                QueryResult r = h->b->query_self_modifying(&v, &sink);
                out->reserve(v.size());
                for ( const SelfModHit &e : v )
                {
                    ittd_selfmod x{};
                    x.address     = (uint64_t)e.address;
                    x.size        = e.size;
                    x.write_pos   = to_abi(e.write_pos);
                    x.write_ip    = (uint64_t)e.write_ip;
                    x.execute_pos = to_abi(e.execute_pos);
                    x.executions  = e.executions;
                    out->push_back(x);
                }
                return r;
            });
        });
    }

    static int x_query_mapping_changes(ittd_backend *hb, ittd_mapping_change *buf, size_t cap,
                                       size_t *out_count, int *out_truncated,
                                       const ittd_progress *progress)
    {
        ExportedBackend *h = B(hb);
        if ( h == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(h, [&]()
        {
            return answer<ittd_mapping_change>(h, "mapping", buf, cap, out_count, out_truncated,
                                               [&](std::vector<ittd_mapping_change> *out)
            {
                AbiSink sink(progress);
                std::vector<qstring> files;
                QueryResult r = h->b->query_mapping_changes(out, &files, &sink);
                std::lock_guard<std::mutex> lock(h->mtx);
                h->mapping_files.swap(files);
                return r;
            });
        });
    }

    static int x_query_mapping_files(ittd_backend *hb, ittd_name *buf, size_t cap, size_t *out_count)
    {
        ExportedBackend *h = B(hb);
        if ( h == nullptr )
            return ITTD_E_BAD_ARG;
        std::lock_guard<std::mutex> lock(h->mtx);
        return fill(h->mapping_files, buf, cap, out_count, [](const qstring &s)
        {
            ittd_name n{};
            copy_str(n.name, sizeof(n.name), s.c_str());
            return n;
        });
    }

    static int x_module_symbols(ittd_backend *hb, uint64_t base, ittd_symbol *buf, size_t cap,
                                size_t *out_count)
    {
        ExportedBackend *h = B(hb);
        if ( h == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(h, [&]()
        {
            return fill(h->b->module_symbols((ea_t)base), buf, cap, out_count,
                        [](const ITraceBackend::Symbol &s)
            {
                ittd_symbol x{};
                x.ea        = (uint64_t)s.ea;
                x.is_export = s.is_export ? 1 : 0;
                copy_str(x.name, sizeof(x.name), s.name.c_str());
                return x;
            });
        });
    }

    static int x_module_functions(ittd_backend *hb, uint64_t base, ittd_range *buf, size_t cap,
                                  size_t *out_count)
    {
        ExportedBackend *h = B(hb);
        if ( h == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(h, [&]()
        {
            return fill(h->b->module_functions((ea_t)base), buf, cap, out_count,
                        [](const std::pair<ea_t, ea_t> &r) { return ittd_range{ (uint64_t)r.first, (uint64_t)r.second }; });
        });
    }

    static int x_regs_at(ittd_backend *hb, const ittd_position *positions, size_t count,
                         ittd_regs *out, const ittd_progress *progress)
    {
        ExportedBackend *h = B(hb);
        if ( h == nullptr || (count != 0 && (positions == nullptr || out == nullptr)) )
            return ITTD_E_BAD_ARG;
        return guarded(h, [&]()
        {
            std::vector<Position> p;
            p.reserve(count);
            for ( size_t i = 0; i < count; i++ )
                p.push_back(from_abi(positions[i]));
            std::vector<ittd_regs> v;
            AbiSink sink(progress);
            QueryResult r = h->b->registers_at(p, &v, &sink);
            for ( size_t i = 0; i < count; i++ )
                out[i] = i < v.size() ? v[i] : ittd_regs{};
            return r.cancelled ? ITTD_E_CANCELLED : ITTD_OK;
        });
    }

    static int x_query_instructions(ittd_backend *hb, ittd_position_range when, uint32_t tid,
                                    ittd_access *buf, size_t cap, size_t *out_count,
                                    int *out_truncated, const ittd_progress *progress)
    {
        ExportedBackend *h = B(hb);
        if ( h == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(h, [&]()
        {
            std::vector<Access> v;
            AbiSink sink(progress);
            QueryResult r = h->b->query_instructions(from_abi(when), tid, cap, &v, &sink);
            if ( !r.ran )
                return ITTD_E_UNSUPPORTED;
            size_t n = 0;
            for ( ; n < v.size() && n < cap; n++ )
                if ( buf != nullptr )
                    buf[n] = to_abi(v[n]);
            if ( out_count != nullptr )
                *out_count = n;
            if ( out_truncated != nullptr )
                *out_truncated = r.truncated || r.cancelled ? 1 : 0;
            return ITTD_OK;
        });
    }

    static int x_position_add(ittd_backend *hb, ittd_position p, int64_t delta, ittd_position *out)
    {
        ExportedBackend *h = B(hb);
        if ( h == nullptr || out == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(h, [&]() { *out = to_abi(h->b->position_add(from_abi(p), delta)); return ITTD_OK; });
    }

    static int x_query_frame_entry(ittd_backend *hb, ittd_position at, uint32_t tid, uint64_t max_back,
                                   ittd_position *out_call, uint64_t *out_entry)
    {
        ExportedBackend *h = B(hb);
        if ( h == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(h, [&]()
        {
            Position cp;
            ea_t e = BADADDR;
            if ( !h->b->query_frame_entry(from_abi(at), tid, max_back, &cp, &e) )
                return ITTD_E_FAILED;
            if ( out_call != nullptr )
                *out_call = to_abi(cp);
            if ( out_entry != nullptr )
                *out_entry = (uint64_t)e;
            return ITTD_OK;
        });
    }

    static int x_query_frame_entry_progress(ittd_backend *hb, ittd_position at, uint32_t tid, uint64_t max_back,
                                            ittd_position *out_call, uint64_t *out_entry,
                                            const ittd_progress *progress)
    {
        ExportedBackend *h = B(hb);
        if ( h == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(h, [&]()
        {
            Position cp;
            ea_t e = BADADDR;
            AbiSink sink(progress);
            if ( !h->b->query_frame_entry(from_abi(at), tid, max_back, &cp, &e, &sink) )
                return sink.cancelled() ? ITTD_E_CANCELLED : ITTD_E_FAILED;
            if ( out_call != nullptr )
                *out_call = to_abi(cp);
            if ( out_entry != nullptr )
                *out_entry = (uint64_t)e;
            return ITTD_OK;
        });
    }

    static int x_query_register_change(ittd_backend *hb, ittd_position at, uint32_t tid, uint32_t reg,
                                       uint64_t max_back, ittd_position *out_pos, int *out_found,
                                       const ittd_progress *progress)
    {
        ExportedBackend *h = B(hb);
        if ( h == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(h, [&]()
        {
            AbiSink sink(progress);
            Position p;
            bool found = false;
            if ( !h->b->query_register_change(from_abi(at), tid, reg, max_back, &p, &found, &sink) )
                return ITTD_E_UNSUPPORTED;
            if ( out_pos != nullptr )
                *out_pos = to_abi(p);
            if ( out_found != nullptr )
                *out_found = found ? 1 : 0;
            return ITTD_OK;
        });
    }

    static int x_query_access_heat_window(ittd_backend *hb, uint32_t page_shift, uint32_t slices,
                                          ittd_position_range when,
                                          ittd_heat_cell *buf, size_t cap, size_t *out_count,
                                          int *out_truncated, const ittd_progress *progress)
    {
        ExportedBackend *h = B(hb);
        if ( h == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(h, [&]()
        {
            // The window is part of the key, so the fill finds this window's
            // answer and not another's.
            std::string key = "heat|" + std::to_string(page_shift) + "|" + std::to_string(slices)
                            + "|" + std::to_string(when.first.hi) + ":" + std::to_string(when.first.lo)
                            + "|" + std::to_string(when.last.hi) + ":" + std::to_string(when.last.lo);
            return answer<ittd_heat_cell>(h, key, buf, cap, out_count, out_truncated,
                                          [&](std::vector<ittd_heat_cell> *out)
            {
                std::vector<HeatCell> v;
                AbiSink sink(progress);
                QueryResult r = h->b->query_access_heat_window(page_shift, slices, from_abi(when), &v, &sink);
                out->reserve(v.size());
                for ( const HeatCell &c : v )
                {
                    ittd_heat_cell x{};
                    x.page     = c.page;
                    x.slice    = c.slice;
                    x.reads    = c.reads;
                    x.writes   = c.writes;
                    x.executes = c.executes;
                    out->push_back(x);
                }
                return r;
            });
        });
    }

    static int x_query_out_values(ittd_backend *hb, const ittd_out_slot *slots, size_t count,
                                  uint64_t *values, uint8_t *known, const ittd_progress *progress)
    {
        ExportedBackend *h = B(hb);
        if ( h == nullptr || (count != 0 && (slots == nullptr || values == nullptr || known == nullptr)) )
            return ITTD_E_BAD_ARG;
        return guarded(h, [&]()
        {
            std::vector<OutSlot> in(count);
            for ( size_t i = 0; i < count; i++ )
            {
                in[i].call   = from_abi(slots[i].call);
                in[i].addr   = (ea_t)slots[i].addr;
                in[i].before = slots[i].before;
                in[i].tid    = slots[i].tid;
                in[i].width  = slots[i].width;
            }
            std::vector<std::optional<uint64_t>> v;
            AbiSink sink(progress);
            if ( !h->b->query_out_values(in, &v, &sink) )
                return ITTD_E_UNSUPPORTED;
            for ( size_t i = 0; i < count; i++ )
            {
                known[i]  = i < v.size() && v[i].has_value() ? 1 : 0;
                values[i] = known[i] ? *v[i] : 0;
            }
            return ITTD_OK;
        });
    }

    static int x_read_memory_at(ittd_backend *hb, const ittd_mem_read *reads, size_t count,
                                uint8_t *buf, uint8_t *known, const ittd_progress *progress)
    {
        ExportedBackend *h = B(hb);
        if ( h == nullptr || (count != 0 && (reads == nullptr || buf == nullptr || known == nullptr)) )
            return ITTD_E_BAD_ARG;
        return guarded(h, [&]()
        {
            std::vector<MemAt> in(count);
            for ( size_t i = 0; i < count; i++ )
            {
                in[i].pos    = from_abi(reads[i].pos);
                in[i].addr   = (ea_t)reads[i].addr;
                in[i].offset = (size_t)reads[i].offset;
                in[i].size   = (size_t)reads[i].size;
            }
            std::vector<uint8_t> data, k;
            AbiSink sink(progress);
            QueryResult r = h->b->read_memory_at(in, &data, &k, &sink);
            if ( !r.ran )
                return ITTD_E_UNSUPPORTED;
            // Only the caller's own ranges are written: the buffers between
            // them are theirs.
            for ( const MemAt &m : in )
            {
                // Written so it cannot wrap: offset + size could, for huge
                // values, and pass the check.
                if ( m.size == 0 || m.offset > data.size() || m.size > data.size() - m.offset )
                    continue;
                memcpy(buf + m.offset, data.data() + m.offset, m.size);
                memcpy(known + m.offset, k.data() + m.offset, m.size);
            }
            return r.cancelled ? ITTD_E_CANCELLED : ITTD_OK;
        });
    }

    // visit_positions' reader, through the C ABI: 'read_ctx' is the
    // backend's VisitRead for the visit being made.
    static size_t x_visit_read(void *read_ctx, uint64_t addr, void *buf, size_t size)
    {
        try
        {
            return (*static_cast<const ITraceBackend::VisitRead *>(read_ctx))(addr, buf, size);
        }
        catch ( ... )
        {
            return 0;
        }
    }

    static int x_visit_positions(ittd_backend *hb, const ittd_position *at, const ittd_position *after,
                                 size_t count, ittd_visit_fn fn, void *ud, const ittd_progress *progress)
    {
        ExportedBackend *h = B(hb);
        if ( h == nullptr || fn == nullptr || (count != 0 && at == nullptr) )
            return ITTD_E_BAD_ARG;
        return guarded(h, [&]()
        {
            std::vector<Position> a(count), b;
            for ( size_t i = 0; i < count; i++ )
                a[i] = from_abi(at[i]);
            if ( after != nullptr )
            {
                b.resize(count);
                for ( size_t i = 0; i < count; i++ )
                    b[i] = from_abi(after[i]);
            }
            AbiSink sink(progress);
            QueryResult r = h->b->visit_positions(a, after != nullptr ? &b : nullptr,
                [fn, ud](size_t index, int phase, const ITraceBackend::VisitRead &read)
                {
                    fn(ud, index, phase, x_visit_read, const_cast<ITraceBackend::VisitRead *>(&read));
                }, &sink);
            if ( !r.ran )
                return ITTD_E_UNSUPPORTED;
            return r.cancelled ? ITTD_E_CANCELLED : ITTD_OK;
        });
    }

    static int x_query_access_heat(ittd_backend *hb, uint32_t page_shift, uint32_t slices,
                                   ittd_heat_cell *buf, size_t cap, size_t *out_count,
                                   int *out_truncated, const ittd_progress *progress)
    {
        return x_query_access_heat_window(hb, page_shift, slices, to_abi(PositionRange{}),
                                          buf, cap, out_count, out_truncated, progress);
    }

    static int x_heat_window_slice_position(ittd_backend *hb, uint32_t slices, uint32_t slice,
                                            ittd_position_range when, ittd_position *out)
    {
        ExportedBackend *h = B(hb);
        if ( h == nullptr || out == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(h, [&]()
        {
            Position p = h->b->heat_window_slice_position(slices, slice, from_abi(when));
            if ( !p.is_valid() )
                return ITTD_E_FAILED;
            *out = to_abi(p);
            return ITTD_OK;
        });
    }

    static int x_heat_slice_position(ittd_backend *hb, uint32_t slices, uint32_t slice, ittd_position *out)
    {
        return x_heat_window_slice_position(hb, slices, slice, to_abi(PositionRange{}), out);
    }

    static void x_set_log(void (*log)(void *ud, const char *line), void *ud)
    {
        if ( g_set_log != nullptr )
            g_set_log(log, ud);
    }

    // ---------------------------------------------------------------- the table

    const ittd_backend_api *export_backend(BackendFactory factory, LogSetter set_log)
    {
        static ittd_backend_api a{};
        static bool built = false;
        if ( built )
            return &a;
        g_factory  = factory;
        g_set_log  = set_log;
        g_identity = factory();
        if ( g_identity == nullptr )
            return nullptr;

        a.abi_version           = ITTD_ABI_VERSION;
        a.size                  = sizeof(ittd_backend_api);
        a.id                    = x_id;
        a.display_name          = x_display_name;
        a.file_filter           = x_file_filter;
        a.can_open              = x_can_open;
        a.open                  = x_open;
        a.close                 = x_close;
        a.last_error            = x_last_error;
        a.info                  = x_info;
        a.prepare               = x_prepare;
        a.format_position       = x_format_position;
        a.parse_position        = x_parse_position;
        a.position_syntax       = x_position_syntax;
        a.cursor_open           = x_cursor_open;
        a.cursor_close          = x_cursor_close;
        a.cursor_position       = x_cursor_position;
        a.cursor_seek           = x_cursor_seek;
        a.cursor_thread         = x_cursor_thread;
        a.cursor_regs           = x_cursor_regs;
        a.cursor_read_memory    = x_cursor_read_memory;
        a.cursor_threads        = x_cursor_threads;
        a.nav_step              = x_nav_step;
        a.nav_step_over         = x_nav_step_over;
        a.nav_step_out          = x_nav_step_out;
        a.nav_run               = x_nav_run;
        a.nav_run_to            = x_nav_run_to;
        a.nav_breakpoints       = x_nav_breakpoints;
        a.modules               = x_modules;
        a.threads               = x_threads;
        a.timeline              = x_timeline;
        a.query_accesses        = x_query_accesses;
        a.query_executed        = x_query_executed;
        a.query_calls           = x_query_calls;
        a.query_indirect        = x_query_indirect;
        a.query_mapping_changes = x_query_mapping_changes;
        a.module_symbols        = x_module_symbols;
        a.module_functions      = x_module_functions;
        a.query_exceptions      = x_query_exceptions;
        a.regs_at               = x_regs_at;
        a.query_mapping_files   = x_query_mapping_files;
        a.query_instructions    = x_query_instructions;
        a.position_add          = x_position_add;
        a.query_frame_entry     = x_query_frame_entry;
        a.query_frame_entry_progress = x_query_frame_entry_progress;
        a.set_log               = x_set_log;
        a.prepared              = x_prepared;
        a.cursor_thread_regs    = x_cursor_thread_regs;
        a.cursor_rebuild_range  = x_cursor_rebuild_range;
        a.nav_take_notice       = x_nav_take_notice;
        a.nav_set_progress      = x_nav_set_progress;
        a.query_syscalls        = x_query_syscalls;
        a.query_self_modifying  = x_query_self_modifying;
        a.query_strings         = x_query_strings;
        a.query_buffers         = x_query_buffers;
        a.query_register_change = x_query_register_change;
        a.query_access_heat     = x_query_access_heat;
        a.heat_slice_position   = x_heat_slice_position;
        a.query_out_values      = x_query_out_values;
        a.read_memory_at        = x_read_memory_at;
        a.visit_positions       = x_visit_positions;
        // Only offered when the backend can count part of the recording; the
        // core reads a missing entry as "the heatmap cannot zoom".
        if ( g_identity->can_window_heat() )
        {
            a.query_access_heat_window   = x_query_access_heat_window;
            a.heat_window_slice_position = x_heat_window_slice_position;
        }
        built = true;
        return &a;
    }
}
