#include "backend-msttd/msttd_sweep.h"

#include <condition_variable>

#include <condition_variable>

using namespace TTD;
using namespace TTD::Replay;

namespace idattd
{
    static const int POLL_MS = 50;

    bool msttd_sweep(ICursorView *cursor, TTD::Replay::Position first, TTD::Replay::Position last,
                     ProgressSink *progress)
    {
        if ( cursor == nullptr )
            return false;

        // Filtering is the caller's choice (a maskable watchpoint lets the
        // engine skip segments, a call/return callback does not), so only the
        // sequential bit is added.
        cursor->SetReplayFlags(cursor->GetReplayFlags() | ReplayFlags::ReplaySegmentsSequentially);

        // A percentage over sequence numbers, the only monotonic measure the
        // progress callback gives. It runs on the engine's threads, so it only
        // stores a number.
        const uint64_t from = first.IsValid() && first != TTD::Replay::Position::Min ? (uint64_t)first.Sequence : 0;
        // 'last' may be Position::Max; the cursor clamps a seek to the trace's
        // real end, which is the number a percentage needs. A real position
        // already says it: the seek (about 17 ms) is only for Max, since
        // callers such as query_register_change run many short sweeps.
        uint64_t to = 0;
        if ( last.IsValid() && last != TTD::Replay::Position::Max )
        {
            to = (uint64_t)last.Sequence;
        }
        else
        {
            cursor->SetPosition(last);
            to = (uint64_t)cursor->GetPosition().Sequence;
        }
        std::atomic<uint32_t> pct{ 0 };
        auto on_progress = [&pct, from, to](TTD::Replay::Position const &p) noexcept
        {
            uint64_t seq = (uint64_t)p.Sequence;
            if ( to > from )
                pct.store((uint32_t)(seq >= to ? 100 : seq <= from ? 0 : (seq - from) * 100 / (to - from)),
                          std::memory_order_relaxed);
        };
        cursor->SetReplayProgressCallback(on_progress);
        cursor->SetPosition(first);

        std::mutex              mu;
        std::condition_variable cv;
        bool                    done = false;
        std::thread worker([cursor, last, &mu, &cv, &done]()
        {
            try { cursor->ReplayForward(last); } catch ( ... ) {}
            {
                std::lock_guard<std::mutex> lock(mu);
                done = true;
            }
            cv.notify_one();
        });

        // Woken as soon as the replay ends, not at the next poll: callers such
        // as query_register_change run many short sweeps in a row, and a fixed
        // sleep would cost each one a whole interval.
        bool stopped = false;
        uint32_t shown = 101;
        std::unique_lock<std::mutex> lock(mu);
        while ( !done )
        {
            lock.unlock();
            if ( !stopped && progress != nullptr && progress->cancelled() )
            {
                stopped = true;
                cursor->InterruptReplay();
            }
            uint32_t now = pct.load(std::memory_order_relaxed);
            if ( progress != nullptr && now != shown )
            {
                progress->report(now);
                shown = now;
            }
            lock.lock();
            cv.wait_for(lock, std::chrono::milliseconds(POLL_MS), [&done] { return done; });
        }
        lock.unlock();
        worker.join();
        cursor->SetReplayProgressCallback(nullptr, 0);
        return !stopped;
    }

    ArmedSweep::ArmedSweep(ICursorView *cursor, ReplayFlags flags)
        : m_cursor(cursor), m_oldEvents(cursor->GetEventMask())
    {
        m_cursor->SetReplayFlags(flags);
    }

    ArmedSweep::ArmedSweep(ICursorView *cursor, ReplayFlags flags, EventMask events)
        : ArmedSweep(cursor, flags)
    {
        m_cursor->SetEventMask(events);
        m_events = true;
    }

    bool ArmedSweep::watch(const MemoryWatchpointData &wp)
    {
        if ( !m_cursor->AddMemoryWatchpoint(wp) )
            return false;
        try
        {
            m_watched.push_back(wp);
        }
        catch ( ... )
        {
            // Not removable later, so not left behind either.
            m_cursor->RemoveMemoryWatchpoint(wp);
            return false;
        }
        return true;
    }

    void ArmedSweep::disarm()
    {
        if ( !m_armed )
            return;
        m_armed = false;
        if ( m_watchCb )
            m_cursor->SetMemoryWatchpointCallback(nullptr, 0);
        if ( m_callRetCb )
            m_cursor->SetCallReturnCallback(nullptr, 0);
        if ( m_gapCb )
            m_cursor->SetGapEventCallback(nullptr, 0);
        for ( const MemoryWatchpointData &wp : m_watched )
            m_cursor->RemoveMemoryWatchpoint(wp);
        m_watched.clear();
        if ( m_events )
            m_cursor->SetEventMask(m_oldEvents);
    }

    // More workers than this gain little (measured: 16 workers on a 24-thread
    // machine cut 41 s of seeks and reads to 3 s) and each cursor holds its
    // own cache.
    static const size_t kMaxWorkers = 16;

    bool msttd_parallel(size_t items, size_t min_per_worker, ProgressSink *progress, const ParallelWork &work)
    {
        if ( items == 0 )
            return true;
        size_t workers = std::max<size_t>(1, std::thread::hardware_concurrency());
        workers = std::min(workers, kMaxWorkers);
        workers = std::min(workers, std::max<size_t>(1, items / std::max<size_t>(1, min_per_worker)));

        std::atomic<size_t> done{ 0 };
        std::atomic<size_t> finished{ 0 };
        std::atomic<bool>   stop{ false };
        std::mutex              mu;
        std::condition_variable cv;
        std::vector<std::thread> pool;
        pool.reserve(workers);
        for ( size_t w = 0; w < workers; w++ )
        {
            const size_t begin = items * w / workers, end = items * (w + 1) / workers;
            pool.emplace_back([&, begin, end]()
            {
                try { work(begin, end, done, stop); } catch ( ... ) {}
                {
                    std::lock_guard<std::mutex> lock(mu);
                    finished++;
                }
                cv.notify_one();
            });
        }
        bool stopped = false;
        std::unique_lock<std::mutex> lock(mu);
        while ( finished.load() < workers )
        {
            lock.unlock();
            if ( progress != nullptr )
            {
                if ( !stopped && progress->cancelled() )
                {
                    stopped = true;
                    stop = true;
                }
                progress->report(uint32_t(std::min(done.load(), items) * 100 / items));
            }
            lock.lock();
            cv.wait_for(lock, std::chrono::milliseconds(POLL_MS), [&] { return finished.load() >= workers; });
        }
        lock.unlock();
        for ( std::thread &t : pool )
            t.join();
        return !stopped;
    }
}
