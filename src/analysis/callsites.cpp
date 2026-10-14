#include "analysis/callsites.h"
#include "analysis/query_runner.h"
#include "analysis/trace_store.h"
#include "debugger/trace_manager.h"
#include "debugger/module_registry.h"

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
    static const uchar CS_TYPE_TAG = 'Y';   // alt <site> -> 1: we set its call type

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

    // The prototype of a called function: its own type when the database has
    // one (from a PDB, or set by the user), else the type library's entry for
    // its name -- an API export such as CreateFileW. IDA names a second
    // export of a name already taken with a "_0"-style suffix, which is not
    // part of the API's name.
    static bool callee_type(ea_t target, tinfo_t *out)
    {
        if ( get_tinfo(out, target) && out->is_func() )
            return true;
        qstring name;
        if ( get_name(&name, target) <= 0 || name.empty() )
            return false;
        for ( int pass = 0; pass < 2; pass++ )
        {
            const type_t *type = nullptr;
            const p_list *fields = nullptr;
            if ( get_named_type(get_idati(), name.c_str(), NTF_SYMU, &type, &fields) > 0
              && out->deserialize(get_idati(), &type, &fields) && out->is_func() )
                return true;
            ssize_t us = name.rfind('_');
            if ( us <= 0 || (size_t)us + 1 >= name.length() )
                return false;
            for ( size_t k = (size_t)us + 1; k < name.length(); k++ )
                if ( name[k] < '0' || name[k] > '9' )
                    return false;
            name.resize((size_t)us);
        }
        return false;
    }

    static void remember_type(ea_t site)
    {
        netnode nn(CS_NODE, 0, true);
        if ( nn != BADNODE )
            nn.altset((nodeidx_t)site, 1, CS_TYPE_TAG);
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

    // Take off annotations a different recording of this program left. They
    // cannot just be forgotten -- the comments and cross-references they wrote
    // are in the database and the store is the only record of which ones were
    // ours -- so they come off before a sweep writes its own.
    static void clear_stale_annotations()
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

    // Call site -> the targets it reached.
    typedef std::map<ea_t, std::set<ea_t>> SiteTargets;

    // Replay the recording and gather the indirect calls made from inside
    // 'spans' (sorted). False when the backend could not answer.
    static bool collect_sites(TraceManager *mgr, const std::vector<std::pair<ea_t, ea_t>> &spans,
                              SiteTargets *seen, QueryResult *qr_out)
    {
        ITraceBackend *backend = mgr->backend();
        std::map<ea_t, std::vector<IndirectTarget>> found;
        QueryResult qr = run_query("Watching where indirect calls go", [&](ProgressSink *p)
        {
            return backend->query_indirect_targets(spans, false, &found, p);
        });
        if ( !qr.ran )
        {
            if ( qr_out != nullptr )
                *qr_out = qr;
            return false;
        }

        // A backend may report direct calls too (the decode below drops them),
        // so the caps apply to what survives that.
        for ( const auto &kv : found )
        {
            if ( seen->size() >= kMaxSites )
            {
                qr.truncated = true;
                break;
            }
            insn_t insn;
            if ( decode_insn(&insn, kv.first) <= 0 || !is_indirect_call(insn) )
                continue;
            // A site that reaches a great many targets is a dispatcher, and
            // listing hundreds of them helps nobody. Keep the most frequent few.
            std::vector<IndirectTarget> v = kv.second;
            std::stable_sort(v.begin(), v.end(), [](const IndirectTarget &x, const IndirectTarget &y)
                             { return x.hits > y.hits; });
            std::set<ea_t> &dst = (*seen)[kv.first];
            for ( const IndirectTarget &t : v )
            {
                if ( dst.size() >= kMaxTargetsPerSite )
                    break;
                if ( t.is_call && t.target != BADADDR )
                    dst.insert(t.target);
            }
        }
        if ( qr_out != nullptr )
            *qr_out = qr;
        return true;
    }

    // Write the answers for the sites in [lo, hi) into the database.
    static void write_annotations(TraceManager *mgr, const SiteTargets &seen,
                                  ea_t lo, ea_t hi, CallSiteResult *res)
    {
        for ( auto it = seen.lower_bound(lo); it != seen.end() && it->first < hi; ++it )
        {
            ea_t site = it->first;
            insn_t insn;
            // Only annotate an address that is still an indirect call: a direct
            // call already names its target, and an address IDA no longer has
            // code at is not a call site.
            if ( decode_insn(&insn, site) <= 0 || !is_indirect_call(insn) )
                continue;

            std::vector<ea_t> targets(it->second.begin(), it->second.end());
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
                res->undefined++;
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
                res->polymorphic++;
            }
            set_cmt(site, cmt.c_str(), true);

            // The cross-reference is the part that makes this more than a note:
            // it puts the target in the xref list and joins the graph up.
            for ( ea_t t : targets )
                add_cref(site, t, fl_CN);

            // The call type, for a site with one target and nothing set there.
            tinfo_t existing, proto;
            if ( targets.size() == 1 && !get_tinfo(&existing, site)
              && callee_type(targets[0], &proto) && set_tinfo(site, &proto) )
            {
                remember_type(site);
                res->typed++;
            }

            remember(site, targets);
            res->sites++;
            res->targets += targets.size();
        }
    }

    bool annotate_indirect_calls(TraceManager *mgr,
                                 const std::vector<std::pair<ea_t, ea_t>> &ranges,
                                 CallSiteResult *out)
    {
        CallSiteResult res;
        if ( out != nullptr )
            *out = res;
        if ( mgr == nullptr || !mgr->is_active() || mgr->backend() == nullptr )
        {
            warning("This is only available while replaying a trace.");
            return false;
        }

        // Sorted scope, as the backend is handed it.
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

        clear_stale_annotations();

        SiteTargets seen;
        QueryResult qr;
        if ( !collect_sites(mgr, spans, &seen, &qr) )
        {
            warning("This recording's backend could not report indirect call targets.");
            return false;
        }

        show_wait_box("HIDECANCEL\nAnnotating call sites...");
        write_annotations(mgr, seen, 0, BADADDR, &res);
        hide_wait_box();

        res.truncated = qr.truncated;
        res.cancelled = qr.cancelled;
        if ( out != nullptr )
            *out = res;
        return true;
    }

    //=======================================================================
    // Automatic resolution in the function you stop in
    //=======================================================================
    // The sweep cannot be narrowed (see annotate_indirect_calls), so one is
    // paid per module rather than per function: the first stop in a module
    // collects every indirect call made from it, and each function stopped in
    // afterwards is annotated from that. Code in no module is one more scope:
    // everything between the modules.
    static const nodeidx_t CS_AUTO_IDX = 0;
    static const uchar     CS_AUTO_TAG = 'A';

    struct AutoScope
    {
        bool        ran = false;
        SiteTargets sites;
    };
    static std::map<ea_t, AutoScope> g_autoScopes;   // module base, or 0
    static std::set<ea_t>            g_autoDone;     // functions annotated

    bool callsites_auto_enabled()
    {
        netnode nn(CS_NODE);
        return nn != BADNODE && nn.altval(CS_AUTO_IDX, CS_AUTO_TAG) == 2;   // off by default
    }

    void set_callsites_auto_enabled(bool on)
    {
        netnode nn(CS_NODE, 0, true);
        if ( nn != BADNODE )
            nn.altset(CS_AUTO_IDX, on ? 2 : 1, CS_AUTO_TAG);
    }

    bool callsites_function_done(ea_t start)
    {
        return g_autoDone.find(start) != g_autoDone.end();
    }

    void callsites_session_ended()
    {
        g_autoScopes.clear();
        g_autoDone.clear();
    }

    bool auto_annotate_function(TraceManager *mgr, ea_t start, ea_t end)
    {
        if ( mgr == nullptr || !mgr->is_active() || mgr->backend() == nullptr || end <= start )
            return false;

        // The scope the function belongs to.
        const ModuleRegistry &mods = mgr->modules();
        ea_t key = 0;
        std::vector<std::pair<ea_t, ea_t>> spans;
        ea_t mlo = 0, mhi = 0;
        if ( mods.range_at(start, mlo, mhi) )
        {
            key = mlo;
            spans.push_back({ mlo, mhi });
        }
        else
        {
            const ea_t HI = mgr->is64() ? (ea_t)0x7FFFFFFFFFFFull : (ea_t)0xFFFFFFFFull;
            ea_t cur = 0x10000;
            for ( const ModuleRegistry::Span &sp : mods.spans() )
            {
                if ( sp.base > cur )
                    spans.push_back({ cur, sp.base });
                if ( sp.end > cur )
                    cur = sp.end;
            }
            if ( cur < HI )
                spans.push_back({ cur, HI });
        }

        AutoScope &sc = g_autoScopes[key];
        if ( !sc.ran )
        {
            clear_stale_annotations();
            QueryResult qr;
            if ( !collect_sites(mgr, spans, &sc.sites, &qr) || qr.cancelled )
            {
                // Keep nothing from a sweep that did not finish.
                sc.sites.clear();
                return false;
            }
            sc.ran = true;
        }

        CallSiteResult res;
        write_annotations(mgr, sc.sites, start, end, &res);
        g_autoDone.insert(start);
        if ( res.sites != 0 )
            msg("[ida-ttd] resolved %d indirect call(s) in the function at %a.\n",
                (int)res.sites, start);
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
            if ( nn.altval(i, CS_TYPE_TAG) != 0 )
            {
                del_tinfo(site);
                nn.altdel(i, CS_TYPE_TAG);
            }
            nn.delblob(i, CS_TGTS_TAG);
            nn.altdel(i, CS_SITE_TAG);
            n++;
            i = next;
        }
        hide_wait_box();
        // What was annotated automatically is gone, so stopping there again
        // should put it back.
        g_autoDone.clear();
        return n;
    }
}
