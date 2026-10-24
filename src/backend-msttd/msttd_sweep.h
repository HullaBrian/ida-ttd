#pragma once

#include "backend-msttd/msttd_pch.h"
#include "core/backend.h"

namespace idattd
{
    // Replay a Microsoft recording from 'first' to 'last' on 'cursor' for a
    // query, with progress and Cancel through 'progress' (nothing of IDA's).
    //
    // The caller owns the cursor and what the sweep looks for (watchpoints,
    // event mask, callbacks), set before and detached after. This adds what
    // every sweep needs: sequential replay (callbacks write unsynchronized
    // state, and the engine's default dispatches them from several threads),
    // a worker thread, the percentage, and InterruptReplay on Cancel.
    //
    // The progress callback is installed here; the caller must not set one.
    // Returns true when the replay ran to the end, false when it was stopped.
    bool msttd_sweep(TTD::Replay::ICursorView *cursor, TTD::Replay::Position first,
                     TTD::Replay::Position last, ProgressSink *progress);

    // One stage of a query made of several (replays, a scan of the modules),
    // reported as its share of one percentage: 'span' percent from 'from'.
    class ScaledProgress : public ProgressSink
    {
    public:
        ScaledProgress(ProgressSink *to, uint32_t from, uint32_t span) : m_to(to), m_from(from), m_span(span) {}
        void report(uint32_t pct) override
        {
            if ( m_to != nullptr )
                m_to->report(m_from + pct * m_span / 100);
        }
        bool cancelled() override { return m_to != nullptr && m_to->cancelled(); }
    private:
        ProgressSink *m_to;
        uint32_t      m_from, m_span;
    };
}
