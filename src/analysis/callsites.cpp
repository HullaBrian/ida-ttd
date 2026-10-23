#include "analysis/callsites.h"
#include "analysis/query_runner.h"
#include "analysis/trace_store.h"
#include "debugger/trace_manager.h"
#include "debugger/module_registry.h"
#include "plugin/settings.h"

#include <intel.hpp>

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
    static const uchar CS_TYPE_TAG = 'Y';   // alt <site> -> 1: its call type was set here
    // alt <site> -> the function pointer the call loads, plus one, whose type
    // the annotation set (and, under CS_PNAME_TAG, whose name).
    static const uchar CS_PTR_TAG   = 'P';
    static const uchar CS_PNAME_TAG = 'N';  // alt <site> -> 1: the pointer was renamed too

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
    // Make sure the database has the Windows SDK type library, which holds
    // the prototypes of user-mode APIs. Databases made by ttd-loader before it
    // added one have only whatever IDA guessed, often the kernel DDK's, where
    // no user-mode API is found. Loaded once, the way IDA's PE loader would
    // have; true when it was missing and is now there.
    static bool add_sdk_til()
    {
        const til_t *ti = get_idati();
        for ( int i = 0; ti != nullptr && i < ti->nbases; i++ )
            if ( ti->base[i] != nullptr && ti->base[i]->name != nullptr
              && strncmp(ti->base[i]->name, "mssdk", 5) == 0 )
                return false;           // already there: nothing to retry
        const char *name = inf_is_64bit() ? "mssdk64_win10" : "mssdk_win10";
        if ( add_til(name, ADDTIL_DEFAULT) != ADDTIL_OK )
            return false;
        msg("[ida-ttd] loaded the %s type library for API prototypes (this "
            "database did not have the Windows SDK's).\n", name);
        return true;
    }

    static bool callee_type(TraceManager *mgr, ea_t target, tinfo_t *out)
    {
        if ( get_tinfo(out, target) && out->is_func() )
            return true;
        // IDA's name for the target, or the export the recording names there
        // ("WININET!InternetConnectA", module dropped). The second matters on
        // recordings whose system DLLs are debugger segments: one not loaded
        // where the user stands has no segment, so no name, and the call
        // would go untyped although the recording knows exactly what it is.
        qstring name;
        if ( get_name(&name, target) <= 0 || name.empty() )
        {
            name = mgr != nullptr ? mgr->modules().export_name_at(target) : qstring();
            size_t bang = name.find('!');
            if ( bang != qstring::npos )
                name.remove(0, bang + 1);
        }
        if ( name.empty() )
            return false;
        for ( int pass = 0; pass < 2; pass++ )
        {
            const type_t *type = nullptr;
            const p_list *fields = nullptr;
            if ( get_named_type(get_idati(), name.c_str(), NTF_SYMU, &type, &fields) > 0
              && out->deserialize(get_idati(), &type, &fields) && out->is_func() )
                return true;
            // Not found, and the SDK library was missing: try again with it.
            if ( add_sdk_til() )
            {
                pass--;
                continue;
            }
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

    // The global function pointer an indirect call loads its target from:
    // "call cs:off_X", or "mov reg, cs:off_X" a few instructions before a
    // "call reg" with nothing in between writing reg. BADADDR for anything
    // else (a register computed some other way, a vtable slot, the stack).
    //
    // That pointer is where an analyst puts the type by hand. The decompiler
    // prints the call through it, so a pointer typed as the API types every
    // call made through it, names the arguments, and survives re-decompiling
    // the function; the call-instruction type covers one site only.
    static ea_t loaded_pointer(const insn_t &call)
    {
        const op_t &op = call.ops[0];
        if ( op.type == o_mem )
            return op.addr;
        if ( op.type != o_reg )
            return BADADDR;
        ea_t ea = call.ea;
        for ( int back = 0; back < 8; back++ )
        {
            // Only straight-line code: a jump target in between could reach
            // the call with something else in the register.
            if ( has_xref(get_flags(ea)) && back != 0 )
                return BADADDR;
            insn_t prev;
            ea_t p = decode_prev_insn(&prev, ea);
            if ( p == BADADDR )
                return BADADDR;
            ea = p;
            const op_t &dst = prev.ops[0];
            bool writes_reg = dst.type == o_reg && dst.reg == op.reg;
            if ( !writes_reg )
            {
                if ( is_call_insn(prev) )
                    return BADADDR;     // clobbers the volatile registers
                continue;
            }
            if ( prev.itype == NN_mov && prev.ops[1].type == o_mem )
                return prev.ops[1].addr;
            return BADADDR;             // reg comes from somewhere else
        }
        return BADADDR;
    }

    // Type the function pointer the call at 'site' loads as a pointer to
    // 'proto', and give it the API's name when it only has a dummy one, so
    // the pseudocode reads "pInternetConnectA(hInternet: ...)". Nothing is
    // done to a pointer that already has a type (someone else's work), or
    // that calls elsewhere in the recording reached a different target
    // through ('ptr_targets': every pointer's targets, over every site).
    static bool type_pointer(ea_t site, const insn_t &call, ea_t target,
                             const tinfo_t &proto, TraceManager *mgr,
                             const std::map<ea_t, std::set<ea_t>> &ptr_targets)
    {
        ea_t ptr = loaded_pointer(call);
        if ( ptr == BADADDR || get_segment_ea(ptr) == BADADDR )
            return false;
        auto pt_it = ptr_targets.find(ptr);
        if ( pt_it == ptr_targets.end() || pt_it->second.size() != 1 )
            return false;
        tinfo_t existing;
        if ( get_tinfo(&existing, ptr) )
            return false;
        tinfo_t pt;
        if ( !pt.create_ptr(proto) || !set_tinfo(ptr, &pt) )
            return false;
        netnode nn(CS_NODE, 0, true);
        if ( nn == BADNODE )
            return true;
        nn.altset((nodeidx_t)site, (nodeidx_t)(ptr + 1), CS_PTR_TAG);

        if ( !has_user_name(get_flags(ptr)) )      // off_X, qword_X: IDA's own
        {
            qstring api;
            if ( get_name(&api, target) <= 0 || api.empty() )
            {
                api = mgr != nullptr ? mgr->modules().export_name_at(target) : qstring();
                size_t bang = api.find('!');
                if ( bang != qstring::npos )
                    api.remove(0, bang + 1);
            }
            // Without IDA's "_0"-style suffix, which it gives a second export
            // of a name already taken (kernel32's VirtualAlloc_0 forwards to
            // kernelbase's) and which is not part of the API's name. Kept
            // only when the plain name is already used in the database.
            qstring plain = api;
            ssize_t us = plain.rfind('_');
            if ( us > 0 && (size_t)us + 1 < plain.length() )
            {
                bool digits = true;
                for ( size_t k = (size_t)us + 1; k < plain.length() && digits; k++ )
                    digits = plain[k] >= '0' && plain[k] <= '9';
                if ( digits )
                    plain.resize((size_t)us);
            }
            for ( const qstring &cand : { plain, api } )
            {
                if ( cand.empty() )
                    continue;
                qstring pname;
                pname.sprnt("p%s", cand.c_str());
                if ( get_name_ea(BADADDR, pname.c_str()) == BADADDR
                  && set_name(ptr, pname.c_str(), SN_NOWARN | SN_NOCHECK) )
                {
                    nn.altset((nodeidx_t)site, 1, CS_PNAME_TAG);
                    break;
                }
            }
        }
        return true;
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
        for ( auto &kv : found )
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
            std::vector<IndirectTarget> &v = kv.second;
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
        // Which targets were reached through each global function pointer,
        // over every site seen, not just those in [lo, hi): a pointer is only
        // typed as one API when every call through it went there.
        std::map<ea_t, std::set<ea_t>> ptr_targets;
        for ( const auto &kv : seen )
        {
            insn_t call;
            if ( decode_insn(&call, kv.first) <= 0 )
                continue;
            ea_t ptr = loaded_pointer(call);
            if ( ptr != BADADDR )
                ptr_targets[ptr].insert(kv.second.begin(), kv.second.end());
        }

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

            // The call type, for a site with one target: on the call
            // instruction when nothing is set there, and on the function
            // pointer it loads (see loaded_pointer).
            tinfo_t existing, proto;
            if ( targets.size() == 1 && callee_type(mgr, targets[0], &proto) )
            {
                bool typed = false;
                if ( !get_tinfo(&existing, site) && set_tinfo(site, &proto) )
                {
                    remember_type(site);
                    typed = true;
                }
                insn_t call;
                if ( decode_insn(&call, site) > 0 && type_pointer(site, call, targets[0], proto, mgr, ptr_targets) )
                    typed = true;
                if ( typed )
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
        // 0 = never set, 1 = off, 2 = on. Never set: the auto_callsites
        // setting (off unless changed).
        netnode nn(CS_NODE);
        nodeidx_t v = nn != BADNODE ? nn.altval(CS_AUTO_IDX, CS_AUTO_TAG) : 0;
        return v == 0 ? settings().auto_callsites : v == 2;
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
            // User space between the modules: from the lowest address
            // Windows maps (64 KiB) to the top of user space.
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

            // Only the cross-references the annotation added come off; anything
            // else at this site belongs to the user or to IDA.
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
            // The pointer's type and name, when this site set them. Several
            // sites can load one pointer; the first to be cleared undoes it,
            // and the others find nothing left to undo.
            nodeidx_t ptr1 = nn.altval(i, CS_PTR_TAG);
            if ( ptr1 != 0 )
            {
                ea_t ptr = (ea_t)(ptr1 - 1);
                del_tinfo(ptr);
                if ( nn.altval(i, CS_PNAME_TAG) != 0 )
                    set_name(ptr, "", SN_NOWARN);
                nn.altdel(i, CS_PTR_TAG);
                nn.altdel(i, CS_PNAME_TAG);
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
