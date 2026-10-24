#include "analysis/trace_store.h"

namespace idattd
{
    // The fingerprint's tag. It must not collide with any store's own tags;
    // none uses 'z'.
    static const uchar TS_FP_TAG = 'z';
    static const nodeidx_t TS_FP_VALUE   = 0;   // alt 0 -> the fingerprint
    static const nodeidx_t TS_FP_PRESENT = 1;   // alt 1 -> it has been written

    // Not in the database: it describes the session.
    static uint64_t g_current_trace = 0;

    void set_current_trace(uint64_t fingerprint)
    {
        g_current_trace = fingerprint;
    }

    uint64_t current_trace()
    {
        return g_current_trace;
    }

    bool trace_store_matches(netnode &node)
    {
        if ( g_current_trace == 0 || node == BADNODE )
            return true;                // nothing to judge it against
        // A fingerprint of zero is a legal value, so presence is recorded
        // separately rather than inferred from the value being non-zero.
        if ( node.altval(TS_FP_PRESENT, TS_FP_TAG) == 0 )
            return true;                // written before this check existed
        return (uint64_t)node.altval(TS_FP_VALUE, TS_FP_TAG) == g_current_trace;
    }

    void trace_store_stamp(netnode &node)
    {
        if ( g_current_trace == 0 || node == BADNODE )
            return;
        node.altset(TS_FP_VALUE, (nodeidx_t)g_current_trace, TS_FP_TAG);
        node.altset(TS_FP_PRESENT, 1, TS_FP_TAG);
    }

    void trace_store_reset(netnode &node, const uchar *tags, size_t ntags)
    {
        if ( node == BADNODE )
            return;
        for ( size_t t = 0; t < ntags; t++ )
        {
            const uchar tag = tags[t];
            // Deleting invalidates the iteration: read the next index first.
            for ( nodeidx_t i = node.altfirst(tag); i != BADNODE; )
            {
                nodeidx_t next = node.altnext(i, tag);
                node.altdel(i, tag);
                i = next;
            }
            for ( nodeidx_t i = node.supfirst(tag); i != BADNODE; )
            {
                nodeidx_t next = node.supnext(i, tag);
                node.supdel(i, tag);
                i = next;
            }
        }
        trace_store_stamp(node);
    }
}
