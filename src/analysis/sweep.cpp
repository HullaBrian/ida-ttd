#include "analysis/sweep.h"
#include "debugger/trace_manager.h"

using namespace TTD;
using namespace TTD::Replay;

namespace idattd
{
    // How often the main thread looks at the worker and repaints the wait box.
    static const int POLL_MS = 100;

    SweepOutcome run_replay_sweep(TraceManager *mgr, ICursorView *cursor, const char *what)
    {
        SweepOutcome out;
        if ( mgr == nullptr || cursor == nullptr )
            return out;

        // Segments must replay one at a time. The engine's default is to replay
        // several at once and dispatch the callbacks from all of those threads,
        // and every sweep's callback writes unsynchronized state. Enforced here
        // rather than trusted to each caller, since forgetting it corrupts
        // results silently. Whether filtering is on is the caller's to choose --
        // a maskable watchpoint lets the engine skip segments, a call/return
        // callback gives it nothing to filter on -- so that bit is left as set.
        cursor->SetReplayFlags(cursor->GetReplayFlags()
                             | ReplayFlags::ReplaySegmentsSequentially);

        // A percentage needs the trace's length. Sequence numbers are the only
        // monotonic measure the progress callback reports.
        const uint64_t last_seq = (uint64_t)mgr->last_position().Sequence;
        std::atomic<uint32_t> pct{ 0 };
        std::atomic<bool>     done{ false };

        auto on_progress = [&pct, last_seq](Position const &p) noexcept
        {
            if ( last_seq > 0 )
            {
                uint64_t seq = (uint64_t)p.Sequence;
                pct.store((uint32_t)(seq >= last_seq ? 100 : seq * 100 / last_seq),
                          std::memory_order_relaxed);
            }
        };
        cursor->SetReplayProgressCallback(on_progress);
        cursor->SetPosition(Position::Min);

        std::thread worker([cursor, &done]()
        {
            // 'done' is set on every exit path: the main thread spins on it and
            // would otherwise wait forever behind a wait box.
            try { cursor->ReplayForward(); } catch ( ... ) {}
            done.store(true, std::memory_order_release);
        });

        show_wait_box("%s (Cancel to stop)...", what);
        uint32_t shown = 101;       // out of range, so the first poll repaints
        while ( !done.load(std::memory_order_acquire) )
        {
            if ( !out.cancelled && user_cancelled() )
            {
                out.cancelled = true;
                replace_wait_box("HIDECANCEL\nFinishing the current segment...");
                cursor->InterruptReplay();
            }
            if ( !out.cancelled )
            {
                uint32_t now = pct.load(std::memory_order_relaxed);
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

        cursor->SetReplayProgressCallback(nullptr, 0);
        out.ran = true;
        return out;
    }
}
