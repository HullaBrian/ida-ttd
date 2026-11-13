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

    // What one replay arms on a cursor (its flags, event mask, watchpoints
    // and callbacks), taken off again when this goes out of scope or at
    // disarm(). The engine keeps a pointer to each callable, not a copy, so
    // a callback left set when its lambda dies is called through a dangling
    // pointer by the next replay on that cursor; declaring the lambdas
    // before this object makes the order right by construction. The event
    // mask is put back as it was, so a cursor reused for one slot after
    // another (query_out_values) keeps its own. Replays run through sweep()
    // (msttd_sweep), or straight on cursor() when no progress is wanted.
    class ArmedSweep
    {
    public:
        // A call/return callback needs no event: that sweep leaves the mask
        // alone.
        ArmedSweep(TTD::Replay::ICursorView *cursor, TTD::Replay::ReplayFlags flags);
        ArmedSweep(TTD::Replay::ICursorView *cursor, TTD::Replay::ReplayFlags flags,
                   TTD::Replay::EventMask events);
        ~ArmedSweep() { disarm(); }
        ArmedSweep(const ArmedSweep &) = delete;
        ArmedSweep &operator=(const ArmedSweep &) = delete;

        // Removed again at disarm().
        bool watch(const TTD::Replay::MemoryWatchpointData &wp);

        template <typename F> void on_watchpoint(F &f)
        {
            m_cursor->SetMemoryWatchpointCallback(f);
            m_watchCb = true;
        }
        template <typename F> void on_call_return(F &f)
        {
            m_cursor->SetCallReturnCallback(f);
            m_callRetCb = true;
        }
        template <typename F> void on_gap(F &f, TTD::Replay::GapKindMask kinds, TTD::Replay::GapEventMask events)
        {
            m_cursor->SetGapKindMask(kinds);
            m_cursor->SetGapEventMask(events);
            m_cursor->SetGapEventCallback(f);
            m_gapCb = true;
        }

        bool sweep(TTD::Replay::Position first, TTD::Replay::Position last, ProgressSink *progress)
        {
            return msttd_sweep(m_cursor, first, last, progress);
        }
        TTD::Replay::ICursorView *cursor() const { return m_cursor; }

        // Everything off, now rather than at the end of the scope: before the
        // cursor is used for something else.
        void disarm();

    private:
        TTD::Replay::ICursorView *m_cursor;
        TTD::Replay::EventMask    m_oldEvents;
        std::vector<TTD::Replay::MemoryWatchpointData> m_watched;
        bool m_watchCb   = false;
        bool m_callRetCb = false;
        bool m_gapCb     = false;
        bool m_events    = false;   // the mask was set, and is put back
        bool m_armed     = true;
    };

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
