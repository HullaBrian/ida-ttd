#include "analysis/callsites.h"
#include "analysis/sweep.h"
#include "analysis/trace_store.h"
#include "debugger/trace_manager.h"

using namespace TTD;
using namespace TTD::Replay;

namespace idattd
{
    // Where the annotations are recorded, so they can be taken back off again.
    // An alt keyed by the call site marks it as ours; a blob at the same index
    // holds that site's targets, which is what a cross-reference removal needs.
    // Targets are capped at 16, so a site's blob always fits one supval and can
    // never run into the next site's.
    static const char  CS_NODE[]  = "$ ida-ttd callsites";
    static const uchar CS_SITE_TAG = 'S';   // alt <site> -> 1
    static const uchar CS_TGTS_TAG = 'T';   // blob at <site> -> u64 targets

    static const size_t kMaxTargetsPerSite = 16;
    static const size_t kMaxSites          = 20000;

    // Is this a call whose target is not written in the instruction? Direct
    // calls already have a cross-reference and need nothing from a recording.
    static bool is_indirect_call(const insn_t &insn)
    {
        if ( !is_call_insn(insn) )
            return false;
        const op_t &op = insn.ops[0];
        return op.type != o_near && op.type != o_far;
    }

    // "kernel32!VirtualAllocStub (0x7FF610DB1389)". The address is always there:
    // a name can be missing, stale or shared, and the address is what you paste
    // into a goto box. The module prefix is what tells two same-named exports
    // from different DLLs apart.
    static qstring target_name(TraceManager *mgr, ea_t ea)
    {
        qstring name;
        if ( get_name(&name, ea) > 0 && !name.empty() )
        {
            qstring dem;
            if ( demangle_name(&dem, name.c_str(), 0) > 0 && !dem.empty() )
                name = dem;
        }

        qstring mod = mgr != nullptr ? mgr->modules().name_at(ea) : qstring();
        qstring out;
        if ( !name.empty() && !mod.empty() )
            out.sprnt("%s!%s (0x%llX)", mod.c_str(), name.c_str(), (uint64_t)ea);
        else if ( !name.empty() )
            out.sprnt("%s (0x%llX)", name.c_str(), (uint64_t)ea);
        else if ( !mod.empty() )
            out.sprnt("%s!0x%llX", mod.c_str(), (uint64_t)ea);
        else
            out.sprnt("0x%llX", (uint64_t)ea);
        return out;
    }

    static void remember(ea_t site, const std::vector<ea_t> &targets)
    {
        netnode nn(CS_NODE, 0, true);
        if ( nn == BADNODE )
            return;
        trace_store_stamp(nn);
        nn.altset((nodeidx_t)site, 1, CS_SITE_TAG);
        std::vector<uint64_t> raw;
        raw.reserve(targets.size());
        for ( ea_t t : targets )
            raw.push_back((uint64_t)t);
        nn.setblob(raw.data(), raw.size() * sizeof(uint64_t), (nodeidx_t)site, CS_TGTS_TAG);
    }

    bool annotate_indirect_calls(TraceManager *mgr,
                                 const std::vector<std::pair<ea_t, ea_t>> &ranges,
                                 CallSiteResult *out)
    {
        CallSiteResult res;
        if ( out != nullptr )
            *out = res;
        if ( mgr == nullptr || !mgr->is_active() )
        {
            warning("This is only available while replaying a trace.");
            return false;
        }

        // Sorted, merged scope so the callback's lookup is a binary search.
        std::vector<std::pair<ea_t, ea_t>> spans;
        for ( const auto &r : ranges )
            if ( r.first < r.second )
                spans.push_back(r);
        std::sort(spans.begin(), spans.end());
        if ( spans.empty() )
        {
            warning("Nothing to annotate: the chosen scope covers no addresses.");
            return false;
        }

        UniqueCursor cur = mgr->make_cursor();
        if ( !cur )
        {
            warning("Could not create a replay cursor for the sweep.");
            return false;
        }

        // Annotations recorded against a different recording describe calls that
        // this one did not make. They cannot just be forgotten -- the comments
        // and cross-references they wrote are in the database and the store is
        // the only record of which ones were ours -- so they are taken back off
        // before this sweep writes its own.
        {
            netnode nn(CS_NODE);
            if ( nn != BADNODE && !trace_store_matches(nn) )
            {
                size_t stale = clear_indirect_call_annotations();
                if ( stale != 0 )
                    msg("[ida-ttd] indirect calls: removed %d annotation(s) left "
                        "from a different recording of this program.\n", (int)stale);
            }
        }

        std::map<ea_t, std::set<ea_t>> seen;   // call site -> targets it reached
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

        auto on_call_ret = [&seen, &hit_cap, &in_scope](
                GuestAddress target, GuestAddress fall_through,
                IThreadView const *t) noexcept
        {
            if ( (uint64_t)fall_through == 0 )
                return;                         // a return, not a call
            // The callback fires on the call instruction, so the thread's program
            // counter is the call site and the first argument is where it went.
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
                    it = seen.emplace(site, std::set<ea_t>()).first;
                }
                // A site that reaches a great many targets is a dispatcher, and
                // listing hundreds of them helps nobody. Keep the first few.
                if ( it->second.size() < kMaxTargetsPerSite )
                    it->second.insert((ea_t)(uint64_t)target);
            }
            catch ( ... )
            {
            }
        };

        // Sequential replay keeps the callback single-threaded: 'seen' is an
        // unsynchronized map and the engine's default is to replay several
        // segments in parallel. ReplayAllSegmentsWithoutFiltering because a
        // call/return callback is not a maskable event, so there is nothing for
        // segment filtering to work with -- the same pair the whole-trace call
        // sweep in tracer.cpp uses.
        cur->SetReplayFlags(ReplayFlags::ReplayAllSegmentsWithoutFiltering
                          | ReplayFlags::ReplaySegmentsSequentially);
        cur->SetCallReturnCallback(on_call_ret);

        SweepOutcome swept = run_replay_sweep(mgr, cur.get(),
                                              "Watching where indirect calls go");

        cur->SetCallReturnCallback(nullptr, 0);
        cur.reset();

        // ---- write the answers into the database ----
        show_wait_box("HIDECANCEL\nAnnotating call sites...");
        for ( const auto &kv : seen )
        {
            ea_t site = kv.first;
            insn_t insn;
            // Only annotate an address that is still an indirect call: a direct
            // call already names its target, and an address IDA no longer has
            // code at is not a call site.
            if ( decode_insn(&insn, site) <= 0 || !is_indirect_call(insn) )
                continue;

            std::vector<ea_t> targets(kv.second.begin(), kv.second.end());
            if ( targets.empty() )
                continue;

            // decode_insn() will happily decode bytes that are not a defined
            // instruction, and a cross-reference from an address with no item at
            // it is rejected outright ("bad call add_cref: no defined item at
            // 'from'"). Define the instruction first, and if the address still
            // will not become one, annotate nothing there.
            if ( !is_code(get_flags(site)) || get_item_head(site) != site )
                create_insn(site);
            if ( !is_code(get_flags(site)) || get_item_head(site) != site )
            {
                res.undefined++;
                continue;
            }

            qstring cmt;
            if ( targets.size() == 1 )
            {
                cmt.sprnt("TTD: calls %s", target_name(mgr, targets[0]).c_str());
            }
            else
            {
                cmt.sprnt("TTD: calls %d different targets:", (int)targets.size());
                for ( ea_t t : targets )
                {
                    cmt.append("\n  ");
                    cmt.append(target_name(mgr, t));
                }
                res.polymorphic++;
            }
            set_cmt(site, cmt.c_str(), true);

            // The cross-reference is the part that makes this more than a note:
            // it puts the target in the xref list and joins the graph up.
            for ( ea_t t : targets )
                add_cref(site, t, fl_CN);

            remember(site, targets);
            res.sites++;
            res.targets += targets.size();
        }
        hide_wait_box();

        res.truncated = hit_cap;
        res.cancelled = swept.cancelled;
        if ( out != nullptr )
            *out = res;
        return true;
    }

    size_t clear_indirect_call_annotations()
    {
        netnode nn(CS_NODE);
        if ( nn == BADNODE )
            return 0;

        size_t n = 0;
        show_wait_box("HIDECANCEL\nRemoving indirect call annotations...");
        for ( nodeidx_t i = nn.altfirst(CS_SITE_TAG); i != BADNODE; )
        {
            nodeidx_t next = nn.altnext(i, CS_SITE_TAG);
            ea_t site = (ea_t)i;

            // Only the cross-references we added come off; anything else at this
            // site was not ours to remove.
            bytevec_t blob;
            if ( nn.getblob(&blob, i, CS_TGTS_TAG) > 0 )
            {
                size_t count = blob.size() / sizeof(uint64_t);
                const uint64_t *t = (const uint64_t *)blob.begin();
                for ( size_t k = 0; k < count; k++ )
                    del_cref(site, (ea_t)t[k], false);
            }
            set_cmt(site, "", true);
            nn.delblob(i, CS_TGTS_TAG);
            nn.altdel(i, CS_SITE_TAG);
            n++;
            i = next;
        }
        hide_wait_box();
        return n;
    }
}
