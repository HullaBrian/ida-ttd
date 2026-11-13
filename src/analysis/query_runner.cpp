#include "analysis/query_runner.h"
#include "core/backend_module.h"
#include "core/diag.h"

#include <expr.hpp>
#include <psapi.h>     // K32EnumProcessModules: kernel32, no psapi.lib

namespace idattd
{
    // How often the main thread looks at the worker and repaints the wait box.
    static const int POLL_MS = 100;

    namespace
    {
        // Python's GIL, released while run_query sleeps. A script that runs a
        // query (ttd() from IDAPython, an MCP server's Python) holds it on this
        // thread for the whole call, so anything else needing Python waited
        // for the UI to run Python code (a click): a sub-second query once took
        // 108 minutes. Looked up at run time, since IDA without IDAPython has
        // no python3*.dll.
        class PythonGil
        {
        public:
            PythonGil()
            {
                // Grown until every module fits: IDA with its plugins and Qt
                // loads hundreds, and Python may come late.
                std::vector<HMODULE> mods(512);
                DWORD need = 0;
                for ( ;; )
                {
                    const DWORD have = DWORD(mods.size() * sizeof(HMODULE));
                    if ( !K32EnumProcessModules(GetCurrentProcess(), mods.data(), have, &need) )
                        return;
                    if ( need <= have )
                        break;
                    mods.resize(need / sizeof(HMODULE) + 32);
                }
                size_t n = need / sizeof(HMODULE);
                for ( size_t i = 0; i < n && m_save == nullptr; i++ )
                {
                    char name[MAX_PATH];
                    if ( K32GetModuleBaseNameA(GetCurrentProcess(), mods[i], name, sizeof(name)) == 0
                      || _strnicmp(name, "python3", 7) != 0 )
                        continue;
                    auto ready   = (int (*)())GetProcAddress(mods[i], "Py_IsInitialized");
                    auto held    = (int (*)())GetProcAddress(mods[i], "PyGILState_Check");
                    auto save    = (void *(*)())GetProcAddress(mods[i], "PyEval_SaveThread");
                    auto restore = (void (*)(void *))GetProcAddress(mods[i], "PyEval_RestoreThread");
                    if ( ready != nullptr && held != nullptr && save != nullptr && restore != nullptr )
                    {
                        m_ready   = ready;
                        m_held    = held;
                        m_save    = save;
                        m_restore = restore;
                    }
                }
            }

            // The thread state to give back to resume(), or nullptr when
            // this thread did not hold the GIL.
            void *release() const
            {
                if ( m_save == nullptr || m_ready() == 0 || m_held() == 0 )
                    return nullptr;
                return m_save();
            }
            void resume(void *state) const
            {
                if ( state != nullptr )
                    m_restore(state);
            }

        private:
            int   (*m_ready)()          = nullptr;
            int   (*m_held)()           = nullptr;
            void *(*m_save)()           = nullptr;
            void  (*m_restore)(void *)  = nullptr;
        };

        // The reported percentage and the main thread's Cancel, as atomics:
        // safe from any thread.
        class AtomicSink : public ProgressSink
        {
        public:
            void report(uint32_t percent) override { m_pct.store(percent, std::memory_order_relaxed); }
            bool cancelled() override
            {
                // Paused: the thread asking (the emulator's, which asks
                // between two checkpoint intervals) waits here until Resume
                // or a stop, so the program stands still. It runs no IDA
                // code, so holding it blocks nothing on the main thread.
                if ( m_pause.load(std::memory_order_relaxed) )
                {
                    m_holding.fetch_add(1);
                    while ( m_pause.load(std::memory_order_relaxed) && !m_cancel.load(std::memory_order_relaxed) )
                        std::this_thread::sleep_for(std::chrono::milliseconds(20));
                    m_holding.fetch_sub(1);
                }
                return m_cancel.load(std::memory_order_relaxed);
            }

            uint32_t percent() const { return m_pct.load(std::memory_order_relaxed); }
            void     cancel() { m_cancel.store(true, std::memory_order_relaxed); }
            void     pause(bool on) { m_pause.store(on, std::memory_order_relaxed); }
            // A thread is held by the pause (it has taken effect).
            bool     holding() const { return m_holding.load() > 0; }

        private:
            std::atomic<uint32_t> m_pct{ 0 };
            std::atomic<bool>     m_cancel{ false };
            std::atomic<bool>     m_pause{ false };
            std::atomic<int>      m_holding{ 0 };
        };

        // A Python string literal of UTF-8 text, everything outside ASCII
        // escaped: the log carries the guest's console output, which need
        // not be valid UTF-8, and a bad byte in the source would fail the
        // whole call.
        void py_literal(qstring *out, const char *s)
        {
            qwstring w;
            utf8_utf16(&w, s);
            out->append('"');
            for ( size_t i = 0; i < w.length(); i++ )
            {
                uint32_t c = (uint16_t)w[i];
                if ( c >= 0xD800 && c < 0xDC00 && i + 1 < w.length()
                  && (uint16_t)w[i + 1] >= 0xDC00 && (uint16_t)w[i + 1] < 0xE000 )
                    c = 0x10000 + ((c - 0xD800) << 10) + ((uint16_t)w[++i] - 0xDC00);
                else if ( c >= 0xD800 && c < 0xE000 )
                    c = 0xFFFD;             // a lone surrogate Qt would refuse
                if ( c == '"' || c == '\\' )
                {
                    out->append('\\');
                    out->append((char)c);
                }
                else if ( c == '\n' )
                    out->append("\\n");
                else if ( c >= 0x20 && c < 0x7F )
                    out->append((char)c);
                else if ( c < 0x20 || c == 0x7F )
                    out->append(' ');
                else
                    out->cat_sprnt("\\U%08X", c);
            }
            out->append('"');
        }

        // The recording window (ida_ttd_qt.recording_window_*): Sogen's log
        // in a scrolling box, the running time, Pause and Stop. Only with
        // IDAPython and Qt; without them run_query uses IDA's wait box.
        class RecordingWindow
        {
        public:
            bool open(const char *title, const char *what, bool can_pause)
            {
                extlang_object_t py = find_extlang_by_name("Python");
                if ( py == nullptr || py->eval_snippet == nullptr || py->eval_expr == nullptr )
                    return false;
                qstring err;
                if ( !py->eval_snippet("import ida_ttd_qt\n", &err) )
                    return false;
                qstring expr("ida_ttd_qt.recording_window_open(");
                py_literal(&expr, title);
                expr.append(", ");
                py_literal(&expr, what);
                expr.append(can_pause ? ", True)" : ", False)");
                idc_value_t rv;
                if ( !py->eval_expr(&rv, BADADDR, expr.c_str(), &err) || rv.vtype != VT_LONG || rv.num == 0 )
                {
                    if ( !err.empty() )
                        msg("[ida-ttd] the recording window did not open (%s); using a wait box.\n", err.c_str());
                    return false;
                }
                m_py.emplace(py);
                return true;
            }

            // "stop", "pause", "resume", "" or "gone" (see the Python side).
            qstring update(const qstring &status, const qstring &lines)
            {
                if ( !m_py )
                    return qstring("gone");
                qstring expr("ida_ttd_qt.recording_window_update(");
                py_literal(&expr, status.c_str());
                expr.append(", ");
                py_literal(&expr, lines.c_str());
                expr.append(')');
                idc_value_t rv;
                qstring err;
                if ( !(*m_py)->eval_expr(&rv, BADADDR, expr.c_str(), &err) || rv.vtype != VT_STR )
                {
                    msg("[ida-ttd] the recording window failed (%s); stopping the recording.\n", err.c_str());
                    m_py.reset();
                    return qstring("gone");
                }
                return rv.qstr();
            }

            void close()
            {
                if ( m_py )
                {
                    qstring err;
                    (*m_py)->eval_snippet("ida_ttd_qt.recording_window_close()\n", &err);
                    m_py.reset();
                }
            }

            ~RecordingWindow() { close(); }

        private:
            std::optional<extlang_object_t> m_py;
        };
    }

    // Main-thread state only: run_query and movements both run there.
    static bool g_queryRunning = false;
    static bool g_traceMoving  = false;
    // The running query's sink and completion flag, for stop_running_query.
    // They live on run_query's stack and are set only while it waits.
    static AtomicSink        *g_runningSink = nullptr;
    static std::atomic<bool> *g_runningDone = nullptr;
    static bool               g_runningStopped = false;

    static const PythonGil &python_gil()
    {
        static const PythonGil gil;
        return gil;
    }

    void set_trace_moving(bool moving)
    {
        g_traceMoving = moving;
    }

    bool query_in_progress()
    {
        return g_queryRunning;
    }

    qstring clock_text(uint64 ms)
    {
        const unsigned long long s = ms / 1000;
        qstring t;
        if ( s >= 3600 )
            t.sprnt("%llu h %02llu min %02llu s", s / 3600, s / 60 % 60, s % 60);
        else if ( s >= 60 )
            t.sprnt("%llu min %02llu s", s / 60, s % 60);
        else
            t.sprnt("%llu s", s);
        return t;
    }

    // The longest log line shown whole: the wait box grows with its text.
    static const size_t LOG_LINE_CHARS = 110;

    // The wait box's text: the first line as before, then what 'show' asks
    // for. The percentage is left out while it is 0 for work that shows its
    // time instead (a recording without a limit never reports one).
    static qstring wait_text(const char *hide, const char *what, const char *ask, uint32_t percent, bool painted,
                             const QueryShow *show, uint64 elapsed_ms)
    {
        qstring t;
        t.sprnt("%s%s%s...", hide, what, ask);
        if ( painted && (show == nullptr || percent != 0) )
            t.cat_sprnt(" %u%%", percent);
        if ( show == nullptr )
            return t;
        if ( show->elapsed )
            t.cat_sprnt("\nRunning for %s", clock_text(elapsed_ms).c_str());
        if ( show->log_lines != 0 )
        {
            qstrvec_t lines;
            emulator_log_tail(show->log_lines, &lines);
            t.append("\n\nSogen's log");
            if ( lines.empty() )
                t.append("\n(nothing yet)");
            for ( qstring l : lines )
            {
                l.replace("\t", "    ");
                l.trim2();
                if ( l.length() > LOG_LINE_CHARS )
                {
                    l.resize(LOG_LINE_CHARS - 3);
                    l.append("...");
                }
                t.append('\n');
                t.append(l);
            }
        }
        return t;
    }

    QueryResult run_query(const char *what, const std::function<QueryResult(ProgressSink *)> &query,
                          bool cancellable, const QueryShow *show)
    {
        DiagTimer diag_timer("query", qstring(what));

        // The wait loop below pumps the UI and releases the GIL, so a UI
        // action, a script's ttd() call or an execute_sync request can start
        // another query (or one can start during a movement's wait box) while
        // the backend is busy. A backend is not built to be driven by two
        // replays at once, so the nested one is refused without calling it,
        // reported as not run and cancelled so callers keep nothing from it.
        if ( g_queryRunning || g_traceMoving )
        {
            msg("[ida-ttd] %s: not started, %s.\n", what,
                g_queryRunning ? "another trace query is running"
                               : "a movement through the recording is in progress");
            QueryResult refused;
            refused.cancelled = true;
            return refused;
        }
        const PythonGil &gil = python_gil();
        const char *hide = cancellable ? "" : "HIDECANCEL\n";
        const char *ask  = cancellable ? " (Cancel to stop)" : "";
        AtomicSink sink;
        QueryResult result;
        std::atomic<bool> done{ false };

        // Declared after the sink and flag it publishes, so it is destroyed
        // (and stops publishing them) first.
        struct RunningFlag
        {
            RunningFlag(AtomicSink *s, std::atomic<bool> *d)
            {
                g_queryRunning   = true;
                g_runningSink    = s;
                g_runningDone    = d;
                g_runningStopped = false;
            }
            ~RunningFlag()
            {
                g_queryRunning = false;
                g_runningSink  = nullptr;
                g_runningDone  = nullptr;
            }
        } running(&sink, &done);

        std::thread worker([&]()
        {
            // 'done' is set on every exit path, or the main thread would spin
            // forever behind the wait box.
            try
            {
                result = query(&sink);
            }
            catch ( ... )
            {
                result = QueryResult{};
            }
            done.store(true, std::memory_order_release);
        });

        const ULONGLONG started = GetTickCount64();
        // A recording gets the recording window, when there is Qt to show
        // it; everything else, and a recording without it, IDA's wait box.
        RecordingWindow win;
        const bool windowed = show != nullptr && show->log_lines != 0 && cancellable
                           && win.open(show->title != nullptr ? show->title : what, what, show->pausable);
        if ( !windowed )
            show_wait_box("%s", wait_text(hide, what, ask, 0, false, show, 0).c_str());
        uint32_t shown = 101;       // out of range, so the first poll repaints
        uint64 shown_secs = 0;
        uint64_t shown_seq = 0;
        ULONGLONG painted_at = 0;
        bool cancelled = false;
        // The window's own state: the log lines it has, and time spent
        // paused, which the running time leaves out.
        uint64_t win_seq = emulator_log_tail(0, nullptr);
        bool paused = false;
        ULONGLONG paused_at = 0, paused_ms = 0;
        while ( windowed && !done.load(std::memory_order_acquire) )
        {
            const ULONGLONG t = GetTickCount64();
            qstrvec_t fresh;
            win_seq = emulator_log_since(win_seq, &fresh);
            qstring lines;
            for ( qstring l : fresh )
            {
                l.replace("\t", "    ");
                l.trim2();
                if ( !lines.empty() )
                    lines.append('\n');
                lines.append(l);
            }
            const uint64 ran = t - started - paused_ms - (paused ? t - paused_at : 0);
            qstring status;
            if ( cancelled )
                status = "Stopping: finishing the recording...";
            else if ( paused )
                status.sprnt(sink.holding() ? "Paused after %s" : "Pausing after %s...", clock_text(ran).c_str());
            else
                status.sprnt("Running for %s", clock_text(ran).c_str());
            if ( !cancelled && sink.percent() != 0 )
                status.cat_sprnt(", %u%%", sink.percent());
            const qstring asked = win.update(status, lines);
            if ( !cancelled && (asked == "stop" || asked == "gone") )
            {
                cancelled = true;
                sink.cancel();
            }
            else if ( !cancelled && asked == "pause" && !paused )
            {
                paused    = true;
                paused_at = t;
                sink.pause(true);
            }
            else if ( !cancelled && asked == "resume" && paused )
            {
                paused     = false;
                paused_ms += t - paused_at;
                sink.pause(false);
            }
            flush_backend_log();
            void *py = gil.release();
            std::this_thread::sleep_for(std::chrono::milliseconds(POLL_MS));
            gil.resume(py);
        }
        while ( !windowed && !done.load(std::memory_order_acquire) )
        {
            // user_cancelled() is also what pumps the UI, without which the
            // wait box never appears (it shows only after a grace period while
            // messages run). So it is called every time, and its answer is
            // ignored for a box without Cancel (HIDECANCEL offers no way to
            // ask, so it reports false anyway).
            const bool asked = user_cancelled();
            if ( cancellable && !cancelled && asked )
            {
                cancelled = true;
                sink.cancel();
                replace_wait_box("HIDECANCEL\nStopping...");
            }
            if ( !cancelled )
            {
                const uint32_t now = sink.percent();
                const ULONGLONG t = GetTickCount64();
                const uint64 secs = show != nullptr && show->elapsed ? (t - started) / 1000 : 0;
                const uint64_t seq = show != nullptr && show->log_lines != 0 ? emulator_log_tail(0, nullptr) : 0;
                // New log lines repaint at most four times a second: a busy
                // log would otherwise repaint at every poll.
                if ( now != shown || secs != shown_secs || (seq != shown_seq && t - painted_at >= 250) )
                {
                    replace_wait_box("%s", wait_text(hide, what, ask, now, true, show, t - started).c_str());
                    shown      = now;
                    shown_secs = secs;
                    shown_seq  = seq;
                    painted_at = t;
                }
            }
            flush_backend_log();
            void *py = gil.release();
            std::this_thread::sleep_for(std::chrono::milliseconds(POLL_MS));
            gil.resume(py);
        }
        worker.join();
        flush_backend_log();
        if ( windowed )
            win.close();
        else
            hide_wait_box();
        // Stopped because the session ended under it: whatever the worker
        // got is from a backend that is gone, so callers must keep nothing.
        if ( g_runningStopped )
        {
            result.ran = false;
            cancelled  = true;
        }
        if ( cancelled )
            result.cancelled = true;
        return result;
    }

    void stop_running_query()
    {
        if ( !g_queryRunning || g_runningSink == nullptr || g_runningDone == nullptr )
            return;
        // This runs nested inside run_query's wait loop (the session ended
        // from a UI action, a script or an execute_sync request it pumped).
        // The worker never calls IDA or Python, so blocking the main thread
        // until it returns cannot deadlock; a query that cannot stop
        // part-way (preparing the recording) is simply waited for.
        msg("[ida-ttd] the session is ending: stopping the running trace query.\n");
        g_runningStopped = true;
        g_runningSink->cancel();
        const PythonGil &gil = python_gil();
        while ( !g_runningDone->load(std::memory_order_acquire) )
        {
            flush_backend_log();
            void *py = gil.release();
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            gil.resume(py);
        }
    }

    // Visible top-level windows of the calling thread. Called only on the main
    // thread for its own windows; asking about another thread's would send
    // cross-thread messages.
    static int visible_thread_windows()
    {
        int n = 0;
        EnumThreadWindows(GetCurrentThreadId(), [](HWND h, LPARAM p) -> BOOL
        {
            if ( IsWindowVisible(h) )
                ++*reinterpret_cast<int *>(p);
            return TRUE;
        }, reinterpret_cast<LPARAM>(&n));
        return n;
    }

    void show_wait_box_now(const char *text)
    {
        const int before = visible_thread_windows();
        show_wait_box("%s", text);
        const ULONGLONG until = GetTickCount64() + 2000;
        while ( visible_thread_windows() <= before && GetTickCount64() < until )
        {
            user_cancelled();       // runs the message loop
            std::this_thread::sleep_for(std::chrono::milliseconds(15));
        }
        repaint_wait_box();
    }

    void repaint_wait_box()
    {
        for ( int i = 0; i < 3; i++ )
            user_cancelled();
    }

    bool prepare_backend(ITraceBackend *backend)
    {
        if ( backend == nullptr )
            return false;
        if ( backend->prepared() )
            return true;
        bool ok = false;
        run_query("Preparing the recording", [&](ProgressSink *p)
        {
            ok = backend->prepare(p);
            QueryResult r;
            r.ran = true;
            return r;
        }, false);
        return ok;
    }

    WaitBoxSink::WaitBoxSink(const char *what) : m_what(what)
    {
        show_wait_box("%s (Cancel to stop)...", m_what.c_str());
    }

    WaitBoxSink::~WaitBoxSink()
    {
        hide_wait_box();
    }

    void WaitBoxSink::report(uint32_t percent)
    {
        if ( percent != m_shown )
        {
            replace_wait_box("%s (Cancel to stop)... %u%%", m_what.c_str(), percent);
            m_shown = percent;
        }
    }

    bool WaitBoxSink::cancelled()
    {
        return user_cancelled();
    }
}
