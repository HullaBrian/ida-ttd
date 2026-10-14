#include "analysis/query_runner.h"

namespace idattd
{
    // How often the main thread looks at the worker and repaints the wait box.
    static const int POLL_MS = 100;

    namespace
    {
        // Two atomics: the percentage the query reports, and the Cancel the
        // main thread passes in. Safe from any thread.
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

    QueryResult run_query(const char *what, const std::function<QueryResult(ProgressSink *)> &query,
                          bool cancellable)
    {
        const char *hide = cancellable ? "" : "HIDECANCEL\n";
        const char *ask  = cancellable ? " (Cancel to stop)" : "";
        AtomicSink sink;
        QueryResult result;
        std::atomic<bool> done{ false };

        std::thread worker([&]()
        {
            // 'done' is set on every exit path: the main thread spins on it and
            // would otherwise wait forever behind a wait box.
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
            if ( cancellable && !cancelled && user_cancelled() )
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
            std::this_thread::sleep_for(std::chrono::milliseconds(POLL_MS));
        }
        worker.join();
        hide_wait_box();
        if ( cancelled )
            result.cancelled = true;
        return result;
    }

    // Visible top-level windows of the calling thread. Only ever asked about
    // the main thread's own windows, from the main thread: asking another
    // thread's would be a cross-thread message.
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
