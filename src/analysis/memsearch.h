#pragma once

#include "common/pch.h"
#include "core/position.h"

namespace idattd
{
    class TraceManager;

    // What a search looks for: the plugin's own bits, not the engine's (equal
    // to the core's ACCESS_* values).
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

    // Replay the recording and collect every access to [lo, hi) matching
    // 'mask'. A watchpoint is maskable, so the engine skips stretches that
    // cannot touch the range. Behind a cancellable wait box.
    //
    // False when it could not run. 'truncated' (the record cap was hit) and
    // 'cancelled' both leave 'out' holding what was gathered.
    bool search_memory(TraceManager *mgr, ea_t lo, ea_t hi, uint8_t mask,
                       std::vector<MemAccess> *out, bool *truncated, bool *cancelled);

    // Human-readable name for an ACC_* value ("Read", "Write", "Execute").
    const char *access_name(uint8_t kind);
}
