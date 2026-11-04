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

    // Independent work on 'items' things that each need the engine at a
    // position of their own (a seek costs about 15 ms however near, so a
    // query that visits thousands of positions spends minutes seeking). The
    // engine serves separate cursors concurrently, so the items are shared
    // out in contiguous stretches between worker threads, each making its
    // own cursors: work(begin, end, done, stop) does [begin, end), adds one
    // to 'done' per item and returns early once 'stop' is set. At least
    // 'min_per_worker' items a worker, since a cursor costs something to
    // make. Progress and Cancel through 'progress' from the calling thread.
    // An exception from 'work' ends that worker only. Returns false when
    // cancelled.
    using ParallelWork = std::function<void(size_t begin, size_t end, std::atomic<size_t> &done,
                                            const std::atomic<bool> &stop)>;
    bool msttd_parallel(size_t items, size_t min_per_worker, ProgressSink *progress, const ParallelWork &work);

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
