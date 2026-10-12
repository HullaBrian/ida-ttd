#include "backend-msttd/msttd_sweep.h"

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

        // Whether filtering is on is the caller's to choose -- a maskable
        // watchpoint lets the engine skip segments, a call/return callback gives
        // it nothing to filter on -- so only the sequential bit is added.
        cursor->SetReplayFlags(cursor->GetReplayFlags() | ReplayFlags::ReplaySegmentsSequentially);

        // A percentage over the sequence numbers, the only monotonic measure
        // the progress callback reports. It runs on the engine's threads, so it
        // only stores a number.
        const uint64_t from = first.IsValid() && first != TTD::Replay::Position::Min ? (uint64_t)first.Sequence : 0;
        // 'last' may be Position::Max; the cursor clamps a seek to the trace's
        // real end, which is the number a percentage needs.
        cursor->SetPosition(last);
        const uint64_t to   = (uint64_t)cursor->GetPosition().Sequence;
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

        std::atomic<bool> done{ false };
        std::thread worker([cursor, last, &done]()
        {
            try { cursor->ReplayForward(last); } catch ( ... ) {}
            done.store(true, std::memory_order_release);
        });

        bool stopped = false;
        uint32_t shown = 101;
        while ( !done.load(std::memory_order_acquire) )
        {
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
            std::this_thread::sleep_for(std::chrono::milliseconds(POLL_MS));
        }
        worker.join();
        cursor->SetReplayProgressCallback(nullptr, 0);
        return !stopped;
    }
}
