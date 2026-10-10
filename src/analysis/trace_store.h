#pragma once

#include "common/pch.h"

namespace idattd
{
    // Which recording the analysis results kept in the database belong to.
    //
    // A database outlives any one trace. The same binary can be recorded again,
    // and then an "already measured" mark or a recorded indirect-call target
    // describes an execution that no longer exists -- while looking exactly like
    // one that does. MemoryMap carries a fingerprint of its own for this reason;
    // this is the same check for the stores that are only a few netnode tags.
    //
    // The plugin sets this when a session starts and clears it when one ends.
    // Zero means no trace is loaded, and then nothing is ever discarded: a
    // stored result is only judged against a recording that is actually open.
    void     set_current_trace(uint64_t fingerprint);
    uint64_t current_trace();

    // Has 'node' been written against the loaded recording?
    //
    // False when it holds results from a different one. True when it matches,
    // when the node is empty, and when no trace is loaded -- in the last two
    // cases there is nothing to disbelieve.
    bool trace_store_matches(netnode &node);

    // Record the loaded recording as the one 'node' now holds results for.
    void trace_store_stamp(netnode &node);

    // Delete every value stored in 'node' under each of 'tags', alts and blobs
    // alike, and stamp it with the loaded recording. For a store whose contents
    // can simply be thrown away; one whose contents also sit in the database as
    // comments or colours has to undo those itself first.
    void trace_store_reset(netnode &node, const uchar *tags, size_t ntags);
}
