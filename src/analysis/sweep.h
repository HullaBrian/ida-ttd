#pragma once

#include "common/pch.h"

namespace idattd
{
    class TraceManager;

    struct SweepOutcome
    {
        bool ran       = false;   // the replay was started at all
        bool cancelled = false;   // the user stopped it part-way through
    };

    // Replay the whole recording on 'cursor', behind a cancellable wait box that
    // shows how far through the trace the replay has got.
    //
    // The caller owns the cursor and everything about what the sweep is looking
    // for -- replay flags, watchpoints, event mask and its own callbacks, all set
    // before calling, and detached after. This owns only the three things every
    // sweep needs identically: the worker thread, the progress readout and
    // Cancel.
    //
    // ReplayForward must not run on the main thread. It can take minutes, and
    // IDA's message loop would be blocked for all of it: no repaint, no Cancel.
    // So it runs on a worker while the main thread owns the wait box.
    //
    // The progress callback is installed here, and the caller must therefore not
    // set one. TTD dispatches it from its own replay threads, so it only
    // publishes a percentage and never touches IDA -- calling replace_wait_box()
    // from there deadlocks IDA outright.
    //
    // 'what' is the wait-box line with no punctuation and no percentage, e.g.
    // "Measuring execution coverage".
    SweepOutcome run_replay_sweep(TraceManager *mgr,
                                  TTD::Replay::ICursorView *cursor,
                                  const char *what);
}
