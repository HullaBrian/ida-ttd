// The whole-trace queries of the Microsoft backend: each one a replay with a
// watchpoint or the call/return callback armed, moved here from the analysis
// that used to drive it (memsearch, coverage, callsites, tracer). What is left
// in those analyses is what they do with the answer in IDA.
//
// Every callback below runs on the engine's replay thread and is noexcept:
// it writes plain memory only, caps what it keeps, and guards its growth, so
// an allocation failure stops the recording instead of terminating IDA.

#include "backend-msttd/msttd_backend.h"
#include "backend-msttd/msttd_sweep.h"

using namespace TTD;
using namespace TTD::Replay;

namespace idattd
{
    static TtdPosition range_first(PositionRange when)
    {
        return when.first == Position::begin() ? TtdPosition::Min : from_core(when.first);
    }

    static TtdPosition range_last(PositionRange when)
    {
        return when.last == Position::end() ? TtdPosition::Max : from_core(when.last);
    }

    // The position of the instruction after the one at 'p', on the same
    // thread: between two sequence points the steps are one thread's, so it
    // is one step on. Not when the instruction at 'p' is the last before a
    // sequence point -- the next one is then in a later sequence -- which a
    // call or a return rarely is; finding it exactly would cost a seek per
    // call, and a query can return millions of them.
    static Position next_on_thread(const TtdPosition &p)
    {
        TtdPosition n = p;
        n.Steps = (StepCount)((uint64_t)p.Steps + 1);
        return to_core(n);
    }

    //=======================================================================
    // Accesses to a range
    //=======================================================================

    // A watched range with a busy loop over it can produce millions of hits.
    // Past a certain point the answer is "this is touched constantly".
    static const size_t kMaxHits = 200000;

    // The engine reports more access types than the three a reader thinks in.
    // CodeFetch is an execute; Overwrite is a write. The rest describe how the
    // recording stored a value rather than what the program did.
    static uint8_t kind_of(DataAccessType t)
    {
        switch ( t )
        {
            case DataAccessType::Read:      return ACCESS_READ;
            case DataAccessType::Write:
            case DataAccessType::Overwrite: return ACCESS_WRITE;
            case DataAccessType::Execute:
            case DataAccessType::CodeFetch: return ACCESS_EXEC;
            default:                        return 0;
        }
    }

    QueryResult MsTtdBackend::query_accesses(ea_t lo, ea_t hi, uint8_t kinds, PositionRange when,
                                             std::vector<Access> *out, ProgressSink *progress)
    {
        QueryResult r;
        if ( !m_engine || out == nullptr || lo >= hi || kinds == 0 )
            return r;
        UniqueCursor cur = new_engine_cursor();
        if ( !cur )
            return r;

        std::vector<Access> hits;
        bool hit_cap = false;
        auto on_hit = [&hits, &hit_cap, kinds](ICursorView::MemoryWatchpointResult const &w,
                                               IThreadView const *t) noexcept -> bool
        {
            uint8_t k = kind_of(w.AccessType);
            if ( k == 0 || (k & kinds) == 0 )
                return false;
            if ( hits.size() >= kMaxHits )
            {
                hit_cap = true;
                return false;
            }
            try
            {
                Access a;
                a.pos  = to_core(t->GetPosition());
                a.tid  = (uint32_t)t->GetThreadInfo().Id;
                a.pc   = (ea_t)(uint64_t)t->GetProgramCounter();
                a.addr = (ea_t)(uint64_t)w.Address;
                a.size = (uint32_t)w.Size;
                a.kind = k;
                hits.push_back(a);
            }
            catch ( ... )
            {
            }
            return false;       // collecting them, not stopping on them
        };

        // Segment filtering is left on: a watchpoint is a maskable event, so
        // the engine skips the parts of the recording that never touch the
        // range, which is what makes a narrow search fast.
        cur->SetReplayFlags(ReplayFlags::ReplaySegmentsSequentially);
        DataAccessMask am = DataAccessMask::None;
        if ( kinds & ACCESS_READ )
            am |= DataAccessMask::Read;
        if ( kinds & ACCESS_WRITE )
            am |= DataAccessMask::Write | DataAccessMask::Overwrite;
        if ( kinds & ACCESS_EXEC )
            am |= DataAccessMask::Execute | DataAccessMask::CodeFetch;
        MemoryWatchpointData wp{};
        wp.Address    = GuestAddress{ (uint64_t)lo };
        wp.Size       = (uint64_t)(hi - lo);
        wp.AccessMask = am;
        cur->AddMemoryWatchpoint(wp);
        cur->SetMemoryWatchpointCallback(on_hit);
        cur->SetEventMask(EventMask::MemoryWatchpoint);

        bool complete = msttd_sweep(cur.get(), range_first(when), range_last(when), progress);
        cur->SetMemoryWatchpointCallback(nullptr, 0);

        // A timeline must not depend on how the engine scheduled the work, and
        // sorting on the whole tuple groups duplicates for the pass below.
        auto key = [](const Access &a) { return std::tie(a.pos, a.addr, a.kind, a.size, a.tid); };
        std::sort(hits.begin(), hits.end(), [&key](const Access &a, const Access &b) { return key(a) < key(b); });
        // One access can be reported twice: the watchpoint asks for Write and
        // Overwrite, Execute and CodeFetch, because a recording may describe
        // the same event under either name.
        hits.erase(std::unique(hits.begin(), hits.end(),
                               [&key](const Access &a, const Access &b) { return key(a) == key(b); }),
                   hits.end());
        out->insert(out->end(), hits.begin(), hits.end());

        r.ran       = true;
        r.cancelled = !complete;
        r.truncated = hit_cap;
        return r;
    }

    //=======================================================================
    // Executed addresses
    //=======================================================================
    QueryResult MsTtdBackend::query_executed(const std::vector<std::pair<ea_t, ea_t>> &ranges,
                                             std::vector<ea_t> *out, ProgressSink *progress)
    {
        QueryResult r;
        if ( !m_engine || out == nullptr )
            return r;

        // Sorted, merged spans, so the callback's lookup is a binary search.
        std::vector<std::pair<ea_t, ea_t>> spans;
        for ( const auto &x : ranges )
            if ( x.first < x.second )
                spans.push_back(x);
        std::sort(spans.begin(), spans.end());
        std::vector<std::pair<ea_t, ea_t>> merged;
        for ( const auto &x : spans )
        {
            if ( !merged.empty() && x.first <= merged.back().second )
                merged.back().second = std::max(merged.back().second, x.second);
            else
                merged.push_back(x);
        }
        if ( merged.empty() )
            return r;

        UniqueCursor cur = new_engine_cursor();
        if ( !cur )
            return r;

        // One bit per byte of scope: compact where a set of millions of
        // addresses is not.
        struct Bin
        {
            ea_t lo = 0, hi = 0;
            std::vector<uint8_t> bits;
        };
        std::vector<Bin> bins(merged.size());
        for ( size_t i = 0; i < merged.size(); i++ )
        {
            bins[i].lo = merged[i].first;
            bins[i].hi = merged[i].second;
            bins[i].bits.assign((size_t)(((uint64_t)(merged[i].second - merged[i].first) + 7) / 8), 0);
        }

        // Cached last hit: consecutive instructions almost always land in the
        // same span, so the search is only paid at module changes.
        Bin *cache = nullptr;
        auto on_exec = [&bins, &cache](ICursorView::MemoryWatchpointResult const &w,
                                       IThreadView const *) noexcept -> bool
        {
            uint64_t a = (uint64_t)w.Address;
            Bin     *b = cache;
            if ( b == nullptr || a < (uint64_t)b->lo || a >= (uint64_t)b->hi )
            {
                size_t lo = 0, hi = bins.size();
                while ( lo < hi )
                {
                    size_t mid = lo + (hi - lo) / 2;
                    if ( a < (uint64_t)bins[mid].lo )
                        hi = mid;
                    else
                        lo = mid + 1;
                }
                if ( lo == 0 )
                    return false;
                b = &bins[lo - 1];
                if ( a >= (uint64_t)b->hi )
                    return false;
                cache = b;
            }
            uint64_t off = a - (uint64_t)b->lo;
            b->bits[(size_t)(off >> 3)] |= (uint8_t)(1u << (off & 7));
            // Counting executions, not stopping on them: accepting would end
            // the replay at the first instruction that ran.
            return false;
        };

        // Segment filtering stays on: a narrow scope lets the engine skip the
        // parts of the recording that never touch it.
        cur->SetReplayFlags(ReplayFlags::ReplaySegmentsSequentially);
        for ( const auto &x : merged )
        {
            MemoryWatchpointData wp{};
            wp.Address    = GuestAddress{ (uint64_t)x.first };
            wp.Size       = (uint64_t)(x.second - x.first);
            wp.AccessMask = DataAccessMask::Execute;
            cur->AddMemoryWatchpoint(wp);
        }
        cur->SetMemoryWatchpointCallback(on_exec);
        cur->SetEventMask(EventMask::MemoryWatchpoint);

        bool complete = msttd_sweep(cur.get(), TtdPosition::Min, TtdPosition::Max, progress);
        cur->SetMemoryWatchpointCallback(nullptr, 0);

        for ( const Bin &b : bins )
            for ( size_t i = 0; i < b.bits.size(); i++ )
                if ( b.bits[i] != 0 )
                    for ( int k = 0; k < 8; k++ )
                        if ( b.bits[i] & (1u << k) )
                            out->push_back(b.lo + (ea_t)(i * 8 + k));

        r.ran       = true;
        r.cancelled = !complete;
        return r;
    }

    //=======================================================================
    // Where calls from a range went
    //=======================================================================
    static const size_t kMaxTargetsPerSite = 16;
    static const size_t kMaxSites          = 20000;

    // Every call made from inside 'ranges', with each target it reached. The
    // engine says where a call went, not whether it was indirect -- that is a
    // property of the instruction, which this backend does not decode -- so
    // direct calls are reported too and the caller keeps the indirect ones.
    // Indirect jumps are not reported: the engine has no callback for them.
    QueryResult MsTtdBackend::query_indirect_targets(const std::vector<std::pair<ea_t, ea_t>> &ranges,
                                                     bool jumps,
                                                     std::map<ea_t, std::vector<IndirectTarget>> *out,
                                                     ProgressSink *progress)
    {
        qnotused(jumps);
        QueryResult r;
        if ( !m_engine || out == nullptr )
            return r;
        std::vector<std::pair<ea_t, ea_t>> spans;
        for ( const auto &x : ranges )
            if ( x.first < x.second )
                spans.push_back(x);
        std::sort(spans.begin(), spans.end());
        if ( spans.empty() )
            return r;
        UniqueCursor cur = new_engine_cursor();
        if ( !cur )
            return r;

        struct Seen
        {
            uint64_t hits = 0;
            Position first;
        };
        std::map<ea_t, std::map<ea_t, Seen>> seen;
        bool hit_cap = false;

        auto in_scope = [&spans](ea_t a) noexcept -> bool
        {
            size_t lo = 0, hi = spans.size();
            while ( lo < hi )
            {
                size_t mid = lo + (hi - lo) / 2;
                if ( a < spans[mid].first )
                    hi = mid;
                else
                    lo = mid + 1;
            }
            return lo != 0 && a < spans[lo - 1].second;
        };

        auto on_call_ret = [&](GuestAddress target, GuestAddress fall_through, IThreadView const *t) noexcept
        {
            if ( (uint64_t)fall_through == 0 )
                return;                         // a return, not a call
            // The callback fires on the call instruction, so the thread's
            // program counter is the call site.
            ea_t site = (ea_t)(uint64_t)t->GetProgramCounter();
            if ( !in_scope(site) )
                return;
            try
            {
                auto it = seen.find(site);
                if ( it == seen.end() )
                {
                    if ( seen.size() >= kMaxSites )
                    {
                        hit_cap = true;
                        return;
                    }
                    it = seen.emplace(site, std::map<ea_t, Seen>()).first;
                }
                // A site that reaches a great many targets is a dispatcher, and
                // listing hundreds of them helps nobody. Keep the first few.
                ea_t tgt = (ea_t)(uint64_t)target;
                auto tt = it->second.find(tgt);
                if ( tt == it->second.end() )
                {
                    if ( it->second.size() >= kMaxTargetsPerSite )
                        return;
                    tt = it->second.emplace(tgt, Seen{ 0, to_core(t->GetPosition()) }).first;
                }
                tt->second.hits++;
            }
            catch ( ... )
            {
            }
        };

        // A call/return callback is not a maskable event, so there is nothing
        // for segment filtering to work with.
        cur->SetReplayFlags(ReplayFlags::ReplayAllSegmentsWithoutFiltering
                          | ReplayFlags::ReplaySegmentsSequentially);
        cur->SetCallReturnCallback(on_call_ret);
        bool complete = msttd_sweep(cur.get(), TtdPosition::Min, TtdPosition::Max, progress);
        cur->SetCallReturnCallback(nullptr, 0);

        for ( const auto &[site, targets] : seen )
            for ( const auto &[tgt, s] : targets )
            {
                IndirectTarget it;
                it.target  = tgt;
                it.hits    = s.hits;
                it.first   = s.first;
                it.is_call = true;
                (*out)[site].push_back(it);
            }

        r.ran       = true;
        r.cancelled = !complete;
        r.truncated = hit_cap;
        return r;
    }

    //=======================================================================
    // Calls to functions
    //=======================================================================
    QueryResult MsTtdBackend::query_calls(const std::vector<ea_t> &targets, PositionRange when,
                                          std::vector<CallEvent> *out, ProgressSink *progress)
    {
        QueryResult r;
        if ( !m_engine || out == nullptr )
            return r;
        UniqueCursor sweep = new_engine_cursor();
        if ( !sweep )
            return r;

        const std::set<ea_t> wanted(targets.begin(), targets.end());
        struct Rec
        {
            CallEvent ev;
            uint64_t  retAddr;
        };
        std::vector<Rec> recs;
        std::map<uint32_t, std::vector<size_t>> inflight;   // per-thread call stack

        // A broad pattern over a long trace produces tens of millions of hits.
        static const size_t kMaxRecords = 2000000;
        bool truncated = false;

        auto on_call_ret = [&](GuestAddress instr, GuestAddress fall_through, IThreadView const *t) noexcept
        {
            uint32_t tid = (uint32_t)t->GetThreadInfo().Id;
            if ( (uint64_t)fall_through != 0 )
            {
                // CALL: instr == callee.
                ea_t callee = (ea_t)(uint64_t)instr;
                if ( !wanted.empty() && wanted.find(callee) == wanted.end() )
                    return;
                if ( recs.size() >= kMaxRecords )
                {
                    truncated = true;
                    return;
                }
                Rec rec{};
                // The callback fires at the call instruction: this position is
                // the ABI's 'pos', where a call's arguments are read with the
                // call-site layout of the stack.
                rec.ev.pos       = to_core(t->GetPosition());
                rec.ev.entry_pos = next_on_thread(t->GetPosition());
                rec.ev.ret_pos   = Position::none();
                rec.ev.tid       = tid;
                rec.ev.site      = (ea_t)(uint64_t)t->GetProgramCounter();
                rec.ev.target    = callee;
                rec.ev.is_call   = true;
                rec.retAddr      = (uint64_t)fall_through;
                try
                {
                    inflight[tid].push_back(recs.size());
                    recs.push_back(rec);
                }
                catch ( ... )
                {
                    truncated = true;
                }
            }
            else
            {
                // RET: instr == the address being returned to. Pair it with the
                // most recent in-flight call on this thread expecting it. The
                // calls above that one left without returning (an exception,
                // a longjmp, a tail jump out): with every call listed, leaving
                // them on top would keep every outer call from pairing.
                auto it = inflight.find(tid);
                if ( it != inflight.end() )
                {
                    std::vector<size_t> &stack = it->second;
                    for ( size_t k = stack.size(); k-- > 0; )
                    {
                        size_t idx = stack[k];
                        if ( (uint64_t)instr != recs[idx].retAddr )
                            continue;
                        // The callback fires at the ret; ret_pos is just
                        // after it, back at the return address.
                        recs[idx].ev.ret_pos = next_on_thread(t->GetPosition());
                        stack.resize(k);
                        break;
                    }
                }
            }
        };

        sweep->SetReplayFlags(ReplayFlags::ReplayAllSegmentsWithoutFiltering
                            | ReplayFlags::ReplaySegmentsSequentially);
        sweep->SetCallReturnCallback(on_call_ret);
        bool complete = msttd_sweep(sweep.get(), range_first(when), range_last(when), progress);
        sweep->SetCallReturnCallback(nullptr, 0);

        out->reserve(out->size() + recs.size());
        for ( const Rec &rec : recs )
            out->push_back(rec.ev);
        r.ran       = true;
        r.cancelled = !complete;
        r.truncated = truncated;
        return r;
    }
}
