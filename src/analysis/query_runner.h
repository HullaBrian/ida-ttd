#pragma once

#include "common/pch.h"
#include "core/backend.h"

namespace idattd
{
    // Run a whole-trace query behind a cancellable wait box.
    //
    // 'query' runs on a worker thread and is handed a ProgressSink; the main
    // thread owns the wait box, shows the percentage the query reports and
    // passes Cancel back through the sink. The sink only stores and reads
    // atomics, so a backend may call it from any thread -- the engine's own
    // replay threads included -- and the query must not touch IDA itself.
    //
    // Why a worker: a query can take minutes, and on the main thread IDA's
    // message loop would be blocked for all of it -- no repaint, no Cancel.
    //
    // 'what' is the wait-box line with no punctuation and no percentage, e.g.
    // "Measuring execution coverage".
    //
    // 'cancellable' false shows no Cancel, for work that cannot stop part-way
    // (building Microsoft's memory index).
    QueryResult run_query(const char *what, const std::function<QueryResult(ProgressSink *)> &query,
                          bool cancellable = true);

    // One stage of a query that makes several backend calls in turn: the
    // stage's own 0..100 is reported as [lo, hi] of the whole, so the bar
    // does not start over at each call, and Cancel passes straight through.
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

    // show_wait_box() for work that then blocks the UI thread without
    // pumping it (applying a PDB): IDA shows a wait box only after a grace
    // delay and only while its message loop runs, so a box shown just before
    // such work never appears. This pumps until it is on screen (two seconds
    // at most). 'text' is show_wait_box's, prefixes included.
    void show_wait_box_now(const char *text);
    // Let a box already shown repaint after replace_wait_box().
    void repaint_wait_box();

    // Prepare the open recording (ITraceBackend::prepare) unless it already
    // is, behind a wait box. True when it is prepared afterwards.
    bool prepare_backend(ITraceBackend *backend);

    // A sink for work that runs on the main thread -- a movement -- and so
    // can show IDA's wait box itself. The box appears only if the work takes
    // longer than IDA's grace delay; Cancel is user_cancelled().
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
