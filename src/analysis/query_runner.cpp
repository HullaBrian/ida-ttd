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

    QueryResult run_query(const char *what, const std::function<QueryResult(ProgressSink *)> &query)
    {
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

        show_wait_box("%s (Cancel to stop)...", what);
        uint32_t shown = 101;       // out of range, so the first poll repaints
        bool cancelled = false;
        while ( !done.load(std::memory_order_acquire) )
        {
            if ( !cancelled && user_cancelled() )
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
                    replace_wait_box("%s (Cancel to stop)... %u%%", what, now);
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
}
