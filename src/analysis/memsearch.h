#pragma once

#include "common/pch.h"
#include "core/position.h"

namespace idattd
{
    class TraceManager;

    // What a search is looking for. These are the plugin's own bits, not the engine's:
    // the dialog speaks in these and only the sweep translates them.
    enum : uint8_t
    {
        ACC_READ  = 1,
        ACC_WRITE = 2,
        ACC_EXEC  = 4,
    };

    // One recorded touch of the watched range.
    struct MemAccess
    {
        Position pos{};
        uint32_t tid  = 0;
        ea_t     pc   = BADADDR;   // the instruction that did it
        ea_t     addr = BADADDR;   // the address it touched
        uint32_t size = 0;
        uint8_t  kind = 0;         // one of ACC_*
    };

    // Replay the recording and collect every access to [lo, hi) matching 'mask'.
    //
    // A watchpoint is a maskable event, so the engine skips the stretches that
    // cannot touch the range instead of replaying all of it. Runs behind a
    // cancellable wait box.
    //
    // Returns false when it could not run at all. 'truncated' means the record
    // cap was hit and the results are the first N; 'cancelled' means the user
    // stopped it, and both leave 'out' holding what was gathered so far.
    bool search_memory(TraceManager *mgr, ea_t lo, ea_t hi, uint8_t mask,
                       std::vector<MemAccess> *out, bool *truncated, bool *cancelled);

    // Human-readable name for an ACC_* value ("Read", "Write", "Execute").
    const char *access_name(uint8_t kind);
}
