#pragma once

#include "common/pch.h"
#include "core/backend.h"

namespace idattd
{
    // Run a whole-trace query behind a cancellable wait box.
    //
    // 'query' runs on a worker thread (a query can take minutes, and on the
    // main thread it would block repaints and Cancel). The main thread owns
    // the wait box, shows the percentage reported through the ProgressSink
    // and passes Cancel back through it. The sink only touches atomics, so a
    // backend may call it from any thread, including the engine's replay
    // threads. The query itself must not call IDA.
    //
    // 'what' is the wait-box line without punctuation or percentage, e.g.
    // "Measuring execution coverage".
    //
    // 'cancellable' false hides Cancel, for work that cannot stop part-way
    // (building Microsoft's memory index).
    //
    // One query at a time: the wait loop pumps the UI, so another query can
    // be asked for while one runs, or while a movement's wait box is up. Such
    // a query is refused without calling the backend (a message says why) and
    // comes back with 'ran' false and 'cancelled' true.
    //
    // 'show', when given, adds lines under that one while the work runs.
    // With log lines, and IDAPython's Qt to show it, a recording window
    // takes the wait box's place: the whole log in a scrolling box, the
    // running time, and Stop (ending the work as Cancel would) and Pause
    // buttons instead of Cancel.
    struct QueryShow
    {
        bool        elapsed   = false;   // "Running for 1 min 05 s"
        size_t      log_lines = 0;       // the emulator log's last lines (emulator_log_tail)
        const char *title     = nullptr; // the window's title; nullptr: 'what'
        // Pause holds the thread that asks whether to cancel until Resume,
        // which for a recording is the emulator's, between two checkpoint
        // intervals.
        bool        pausable  = false;
    };
    QueryResult run_query(const char *what, const std::function<QueryResult(ProgressSink *)> &query,
                          bool cancellable = true, const QueryShow *show = nullptr);

    // A running time to the second: "45 s", "3 min 07 s", "2 h 05 min 09 s".
    qstring clock_text(uint64 ms);

    // A query is running (run_query is waiting for it).
    bool query_in_progress();
    // Cancel the running query, if any, and block until its worker returns:
    // for the session's end, which can run nested inside run_query's wait
    // loop and must not close the backend under the worker. That run_query
    // then reports the query as not run and cancelled.
    void stop_running_query();
    // TraceManager marks a movement through the recording, during which
    // run_query refuses to start.
    void set_trace_moving(bool moving);

    // One stage of a multi-call query: the stage's 0..100 maps onto [lo, hi]
    // of the whole, so the bar does not restart per call. Cancel passes
    // straight through.
    class StageSink : public ProgressSink
    {
    public:
        StageSink(ProgressSink *outer, uint32_t lo, uint32_t hi)
            : m_outer(outer), m_lo(lo), m_hi(hi) {}
        void report(uint32_t percent) override
        {
            if ( m_outer != nullptr )
                m_outer->report(m_lo + (m_hi - m_lo) * std::min<uint32_t>(percent, 100) / 100);
        }
        bool cancelled() override { return m_outer != nullptr && m_outer->cancelled(); }

    private:
        ProgressSink *m_outer;
        uint32_t      m_lo;
        uint32_t      m_hi;
    };

    // show_wait_box() for work that then blocks the UI thread without pumping
    // it (applying a PDB). IDA shows a wait box only after a grace delay and
    // while its message loop runs, so this pumps until the box is on screen
    // (two seconds at most). 'text' is show_wait_box's, prefixes included.
    void show_wait_box_now(const char *text);
    // Let a box already shown repaint after replace_wait_box().
    void repaint_wait_box();

    // Prepare the open recording (ITraceBackend::prepare) behind a wait box,
    // unless it already is. True when it is prepared afterwards.
    bool prepare_backend(ITraceBackend *backend);

    // A sink for work on the main thread (a movement), which can show IDA's
    // wait box itself. The box appears only after IDA's grace delay; Cancel
    // is user_cancelled().
    class WaitBoxSink : public ProgressSink
    {
    public:
        explicit WaitBoxSink(const char *what);
        ~WaitBoxSink() override;
        void report(uint32_t percent) override;
        bool cancelled() override;

    private:
        qstring  m_what;
        uint32_t m_shown = 101;
    };
}
