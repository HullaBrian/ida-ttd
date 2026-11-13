#pragma once

#include "common/pch.h"
#include "analysis/query_runner.h"

#include <expr.hpp>

namespace idattd
{
    // What run_query shows while a query's worker runs: IDA's wait box, or
    // for a recording the recording window (scripts/ida_ttd_qt.py, the
    // recording_window_* functions: Sogen's log in a scrolling box, the
    // running time, Pause and Stop), when IDAPython's Qt is there to show it.
    //
    // run_query (analysis/query_runner.cpp) owns the worker, the sink and the
    // GIL; this owns everything the user sees and turns their clicks into
    // requests. Main thread only.
    class QueryProgressView
    {
    public:
        // What the user asked for since the last poll().
        enum Ask
        {
            ASK_NONE,
            ASK_STOP,       // Cancel, Stop, or the window closed: end the query
            ASK_PAUSE,
            ASK_RESUME,
        };

        // Shows the wait box or the recording window at once.
        QueryProgressView(const char *what, bool cancellable, const QueryShow *show);
        ~QueryProgressView();

        // One turn of the wait loop: repaint what changed (the percentage,
        // the running time, new log lines) and pump the UI. 'percent' is the
        // backend's progress; 'holding' says a pause has taken effect.
        Ask poll(uint32_t percent, bool holding);

        // Take the box or window down. Also done by the destructor.
        void close();

    private:
        void open_wait_box();
        Ask  poll_window(bool holding);
        Ask  poll_wait_box(uint32_t percent);
        qstring wait_text(uint32_t percent, bool painted, uint64 elapsed_ms) const;

        qstring          m_what;
        bool             m_cancellable;
        const QueryShow *m_show;
        ULONGLONG        m_started;
        bool             m_windowed  = false;
        bool             m_closed    = false;
        // Stop was asked for: the status says so and no more is asked.
        bool             m_cancelled = false;
        // The recording window: the Python it runs in, the log lines it has,
        // and the time spent paused, which the running time leaves out.
        std::optional<extlang_object_t> m_py;
        uint64_t         m_winSeq    = 0;
        bool             m_paused    = false;
        ULONGLONG        m_pausedAt  = 0;
        ULONGLONG        m_pausedMs  = 0;
        // The wait box: what it shows now.
        uint32_t         m_shown     = 101;     // out of range, so the first poll repaints
        uint64           m_shownSecs = 0;
        uint64_t         m_shownSeq  = 0;
        ULONGLONG        m_paintedAt = 0;
    };
}
