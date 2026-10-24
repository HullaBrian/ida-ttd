#include "analysis/query_runner.h"
#include "core/backend_module.h"
#include "core/diag.h"

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
            bool cancelled() override { return m_cancel.load(std::memory_order_relaxed); }

            uint32_t percent() const { return m_pct.load(std::memory_order_relaxed); }
            void     cancel() { m_cancel.store(true, std::memory_order_relaxed); }

        private:
            std::atomic<uint32_t> m_pct{ 0 };
            std::atomic<bool>     m_cancel{ false };
        };
    }

    // Main-thread state only: run_query and movements both run there.
    static bool g_queryRunning = false;
    static bool g_traceMoving  = false;

    void set_trace_moving(bool moving)
    {
        g_traceMoving = moving;
    }

    bool query_in_progress()
    {
        return g_queryRunning;
    }

    QueryResult run_query(const char *what, const std::function<QueryResult(ProgressSink *)> &query,
                          bool cancellable)
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
        struct RunningFlag
        {
            RunningFlag()  { g_queryRunning = true; }
            ~RunningFlag() { g_queryRunning = false; }
        } running;

        static const PythonGil gil;
        const char *hide = cancellable ? "" : "HIDECANCEL\n";
        const char *ask  = cancellable ? " (Cancel to stop)" : "";
        AtomicSink sink;
        QueryResult result;
        std::atomic<bool> done{ false };

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

        show_wait_box("%s%s%s...", hide, what, ask);
        uint32_t shown = 101;       // out of range, so the first poll repaints
        bool cancelled = false;
        while ( !done.load(std::memory_order_acquire) )
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
                uint32_t now = sink.percent();
                if ( now != shown )
                {
                    replace_wait_box("%s%s%s... %u%%", hide, what, ask, now);
                    shown = now;
                }
            }
            flush_backend_log();
            void *py = gil.release();
            std::this_thread::sleep_for(std::chrono::milliseconds(POLL_MS));
            gil.resume(py);
        }
        worker.join();
        flush_backend_log();
        hide_wait_box();
        if ( cancelled )
            result.cancelled = true;
        return result;
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
