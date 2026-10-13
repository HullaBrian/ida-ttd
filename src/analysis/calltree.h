#pragma once

#include "common/pch.h"
#include "core/backend.h"

namespace idattd
{
    class TraceManager;

    // One call made while the function at the cursor ran, nested by when it
    // returned.
    struct CallTreeRow
    {
        Position pos;               // at the call
        Position ret_pos;           // just after its return; none() if it never returned
        ea_t     site    = BADADDR; // the call instruction
        ea_t     target  = BADADDR; // where it went
        int      depth   = 0;       // 0: made by the function itself
        bool     is_call = true;    // false: reached by a jump
    };

    struct CallTree
    {
        ea_t     root = BADADDR;    // the function whose run this is
        Position from;              // its entry (or the cursor, if not found)
        Position to;                // its return (or the end of the recording)
        uint32_t tid = 0;
        bool     from_cursor = false;   // the entry was not found: the tree starts here
        bool     truncated   = false;
        bool     cancelled   = false;
        std::vector<CallTreeRow> rows;  // in the order they were made
    };

    // Every call the function the cursor is in made during this run of it, on
    // the cursor's thread: from the call that entered the frame to its return.
    // Behind a cancellable wait box. False with 'err' set when it could not run.
    bool build_call_tree(TraceManager *mgr, CallTree *out, qstring *err);

    // Nest calls by their positions: 'calls' on one thread, in any order.
    // Exposed for tests.
    void nest_calls(const std::vector<CallEvent> &calls, std::vector<CallTreeRow> *rows, size_t max_rows,
                    bool *truncated);
}
