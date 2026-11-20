#pragma once

#include "common/pch.h"

namespace idattd
{
    // Which recording the analysis results kept in the database belong to.
    //
    // A database outlives any one trace. After the binary is recorded again,
    // an "already measured" mark or an indirect-call target describes an
    // execution that no longer exists, yet looks valid. MemoryMap carries its
    // own fingerprint; this is the same check for stores made of a few
    // netnode tags.
    //
    // The plugin sets this when a session starts and clears it when one ends.
    // Zero means no trace is loaded, and then nothing is discarded: stored
    // results are only judged against an open recording.
    void     set_current_trace(uint64_t fingerprint);
    uint64_t current_trace();

    // Has 'node' been written against the loaded recording? False only when
    // it holds results from a different one; true when it matches, when it is
    // empty or unstamped, and when no trace is loaded.
    bool trace_store_matches(netnode &node);

    // Record the loaded recording as the one 'node' now holds results for.
    void trace_store_stamp(netnode &node);

    // Delete every alt and blob in 'node' under each of 'tags', then stamp it
    // with the loaded recording. Only for contents that can simply be thrown
    // away: a store that also wrote comments or colors must undo those first.
    void trace_store_reset(netnode &node, const uchar *tags, size_t ntags);
}
