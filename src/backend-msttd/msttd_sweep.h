#pragma once

#include "backend-msttd/msttd_pch.h"
#include "core/backend.h"

namespace idattd
{
    // Replay a Microsoft recording from 'first' to 'last' on 'cursor', for a
    // query: progress and Cancel through 'progress', and nothing of IDA's.
    //
    // The caller owns the cursor and everything about what the sweep looks
    // for -- watchpoints, event mask, its own callbacks -- set before calling
    // and detached after. This owns only what every sweep needs identically:
    // sequential replay (each sweep's callback writes unsynchronized state, and
    // the engine's default dispatches callbacks from several threads at once),
    // a worker thread for the replay, the percentage, and InterruptReplay on
    // Cancel.
    //
    // The progress callback is installed here, so the caller must not set one.
    // Returns true when the replay ran to the end, false when it was stopped.
    bool msttd_sweep(TTD::Replay::ICursorView *cursor, TTD::Replay::Position first,
                     TTD::Replay::Position last, ProgressSink *progress);
}
