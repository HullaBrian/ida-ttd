#include "analysis/memsearch.h"
#include "analysis/sweep.h"
#include "debugger/msttd_position.h"
#include "debugger/trace_manager.h"

using namespace TTD;
using namespace TTD::Replay;

namespace idattd
{
    // A watched range with a busy loop over it can produce millions of hits.
    // Cap what we keep: past a certain point the answer is "this is touched
    // constantly", and an unbounded vector grown from inside a noexcept callback
    // is the shape of bug that takes the whole process down.
    static const size_t kMaxHits = 200000;

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

    // The engine reports more access types than the three a reader thinks in.
    // CodeFetch is an execute; Overwrite is a write. The rest describe how the
    // recording stored a value rather than what the program did, so they are not
    // accesses to report.
    static uint8_t kind_of(DataAccessType t)
    {
        switch ( t )
        {
            case DataAccessType::Read:      return ACC_READ;
            case DataAccessType::Write:
            case DataAccessType::Overwrite: return ACC_WRITE;
            case DataAccessType::Execute:
            case DataAccessType::CodeFetch: return ACC_EXEC;
            default:                        return 0;
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

        if ( mgr == nullptr || !mgr->is_active() )
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

        UniqueCursor cur = mgr->make_cursor();
        if ( !cur )
        {
            warning("Could not create a replay cursor for the search.");
            return false;
        }

        std::vector<MemAccess> hits;
        bool hit_cap = false;

        auto on_hit = [&hits, &hit_cap, mask](ICursorView::MemoryWatchpointResult const &w,
                                              IThreadView const *t) noexcept -> bool
        {
            // noexcept: an allocation that throws in here terminates the process,
            // so the cap is enforced before growing and the growth is guarded.
            uint8_t k = kind_of(w.AccessType);
            if ( k == 0 || (k & mask) == 0 )
                return false;
            if ( hits.size() >= kMaxHits )
            {
                hit_cap = true;
                return false;
            }
            try
            {
                MemAccess a;
                a.pos  = to_core(t->GetPosition());
                a.tid  = (uint32_t)t->GetThreadInfo().UniqueId;
                a.pc   = (ea_t)(uint64_t)t->GetProgramCounter();
                a.addr = (ea_t)(uint64_t)w.Address;
                a.size = (uint32_t)w.Size;
                a.kind = k;
                hits.push_back(a);
            }
            catch ( ... )
            {
            }
            // Reject the hit: we are collecting them, not stopping on them.
            return false;
        };

        // Sequential replay is load-bearing: the engine's default dispatches this
        // callback from several threads at once and 'hits' is not synchronized.
        // Segment filtering is deliberately left on (no
        // ReplayAllSegmentsWithoutFiltering) -- a watchpoint is a maskable event,
        // so the engine can skip the parts of the recording that never touch the
        // range, which is what makes a narrow search fast.
        cur->SetReplayFlags(ReplayFlags::ReplaySegmentsSequentially);

        DataAccessMask am = DataAccessMask::None;
        if ( (mask & ACC_READ) != 0 )
            am |= DataAccessMask::Read;
        if ( (mask & ACC_WRITE) != 0 )
            am |= DataAccessMask::Write | DataAccessMask::Overwrite;
        if ( (mask & ACC_EXEC) != 0 )
            am |= DataAccessMask::Execute | DataAccessMask::CodeFetch;

        MemoryWatchpointData wp{};
        wp.Address    = GuestAddress{ (uint64_t)lo };
        wp.Size       = (uint64_t)(hi - lo);
        wp.AccessMask = am;
        cur->AddMemoryWatchpoint(wp);
        cur->SetMemoryWatchpointCallback(on_hit);
        cur->SetEventMask(EventMask::MemoryWatchpoint);

        SweepOutcome swept = run_replay_sweep(mgr, cur.get(),
                                              "Searching the recording for accesses");

        cur->SetMemoryWatchpointCallback(nullptr, 0);
        cur.reset();

        // Parallel replay is off, so hits arrive in order per segment, but sort
        // anyway: the list is read as a timeline and that must not depend on how
        // the engine happened to schedule the work. Sorting on the whole tuple
        // rather than the position alone also groups the duplicates together for
        // the pass below.
        auto key = [](const MemAccess &a)
        {
            return std::tie(a.pos, a.addr, a.kind, a.size, a.tid);
        };
        std::sort(hits.begin(), hits.end(),
                  [&key](const MemAccess &a, const MemAccess &b) { return key(a) < key(b); });

        // One access can be reported twice. The watchpoint asks for Write and
        // Overwrite, and for Execute and CodeFetch, because a recording may
        // describe the same event under either name -- and when it uses both,
        // the two collapse to the same row here. Same position, same address,
        // same size, same kind, same thread is the same event.
        hits.erase(std::unique(hits.begin(), hits.end(),
                               [&key](const MemAccess &a, const MemAccess &b)
                               { return key(a) == key(b); }),
                   hits.end());

        if ( out != nullptr )
            *out = std::move(hits);
        if ( truncated != nullptr )
            *truncated = hit_cap;
        if ( cancelled != nullptr )
            *cancelled = swept.cancelled;
        return true;
    }
}
