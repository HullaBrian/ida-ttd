#include "analysis/memsearch.h"
#include "analysis/query_runner.h"
#include "debugger/trace_manager.h"

namespace idattd
{
    const char *access_name(uint8_t kind)
    {
        switch ( kind )
        {
            case ACC_READ:  return "Read";
            case ACC_WRITE: return "Write";
            case ACC_EXEC:  return "Execute";
            default:        return "?";
        }
    }

    bool search_memory(TraceManager *mgr, ea_t lo, ea_t hi, uint8_t mask,
                       std::vector<MemAccess> *out, bool *truncated, bool *cancelled)
    {
        if ( out != nullptr )
            out->clear();
        if ( truncated != nullptr )
            *truncated = false;
        if ( cancelled != nullptr )
            *cancelled = false;

        if ( mgr == nullptr || !mgr->is_active() || mgr->backend() == nullptr )
        {
            warning("Memory searching is only available while replaying a trace.");
            return false;
        }
        if ( lo >= hi || mask == 0 )
        {
            warning("Nothing to search for: give a non-empty range and at least "
                    "one of read, write or execute.");
            return false;
        }

        ITraceBackend *backend = mgr->backend();
        std::vector<Access> found;
        QueryResult qr = run_query("Searching the recording for accesses", [&](ProgressSink *p)
        {
            return backend->query_accesses(lo, hi, mask, PositionRange{}, &found, p);
        });
        if ( !qr.ran )
        {
            warning("This recording's backend could not search for accesses.");
            return false;
        }

        // ACC_* and ACCESS_* are the same bits.
        std::vector<MemAccess> hits;
        hits.reserve(found.size());
        for ( const Access &x : found )
        {
            MemAccess a;
            a.pos  = x.pos;
            a.tid  = x.tid;
            a.pc   = x.pc;
            a.addr = x.addr;
            a.size = x.size;
            a.kind = x.kind;
            hits.push_back(a);
        }

        if ( out != nullptr )
            *out = std::move(hits);
        if ( truncated != nullptr )
            *truncated = qr.truncated;
        if ( cancelled != nullptr )
            *cancelled = qr.cancelled;
        return true;
    }
}
