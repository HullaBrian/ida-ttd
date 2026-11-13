#include "analysis/callsites.h"
#include "analysis/query_runner.h"
#include "analysis/trace_store.h"
#include "debugger/trace_manager.h"
#include "debugger/module_registry.h"
#include "debugger/apidecode.h"
#include "plugin/settings.h"

#include <intel.hpp>

namespace idattd
{
    // A record of the annotations, so they can be removed. An alt keyed by the
    // call site marks it as the plugin's; a blob at the same index holds its
    // targets, for removing the cross-references. Targets are capped at 16,
    // so a site's blob fits one supval and never runs into the next site's.
    static const char  CS_NODE[]  = "$ ida-ttd callsites";
    static const uchar CS_SITE_TAG = 'S';   // alt <site> -> 1
    static const uchar CS_TGTS_TAG = 'T';   // blob at <site> -> u64 targets
    static const uchar CS_TYPE_TAG = 'Y';   // alt <site> -> 1: its call type was set here
    // alt <site> -> the function pointer the call loads, plus one, whose type
    // was set here (and its name, when CS_PNAME_TAG is set).
    static const uchar CS_PTR_TAG   = 'P';
    static const uchar CS_PNAME_TAG = 'N';  // alt <site> -> 1: the pointer was renamed too
    // How the note an annotation adds to a site's repeatable comment begins,
    // so the note can be told from the user's own text there.
    static const char  CS_NOTE_PREFIX[] = "TTD: calls ";

    static const size_t kMaxTargetsPerSite = 16;
    static const size_t kMaxSites          = 20000;

    // A call whose target is not in the instruction. Direct calls already have
    // a cross-reference.
    static bool is_indirect_call(const insn_t &insn)
    {
        if ( !is_call_insn(insn) )
            return false;
        const op_t &op = insn.ops[0];
        return op.type != o_near && op.type != o_far;
    }

    // "kernel32!VirtualAllocStub (0x7FF610DB1389)". The address is always
    // shown (a name can be missing, stale or shared); the module prefix tells
    // same-named exports of different DLLs apart.
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

    // Make sure the database has the Windows SDK type library (user-mode API
    // prototypes). Databases made by older ttd-loader builds may have only
    // what IDA guessed, often the kernel DDK's. True when it was missing and
    // is now loaded.
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

    static bool named_type(qstring name, tinfo_t *out);

    // The export the recording names at 'ea' ("WININET!InternetConnectA"),
    // module dropped; empty when none.
    static qstring export_name(TraceManager *mgr, ea_t ea)
    {
        qstring name = mgr != nullptr ? mgr->modules().export_name_at(ea) : qstring();
        size_t bang = name.find('!');
        if ( bang != qstring::npos )
            name.remove(0, bang + 1);
        return name;
    }

    // The prototype of a called function: its own type (from a PDB or the
    // user), else the type library's entry for its name, as for an API export
    // such as CreateFileW.
    static bool callee_type(TraceManager *mgr, ea_t target, tinfo_t *out)
    {
        if ( get_tinfo(out, target) && out->is_func() )
            return true;
        // The export the recording names there first, then IDA's name. The
        // export is the API's own name: IDA's may come from a PDB that calls
        // it something else (kernel32's VirtualAlloc is VirtualAllocStub
        // there), which no type library knows, and a system DLL that is a
        // debugger segment not loaded at the playhead has no IDA name at all.
        const qstring exp = export_name(mgr, target);
        qstring ida;
        if ( get_name(&ida, target) <= 0 )
            ida.qclear();
        if ( !exp.empty() && named_type(exp, out) )
            return true;
        return !ida.empty() && ida != exp && named_type(ida, out);
    }

    // The prototype for an API by name: the type library's entry, else one
    // built from the API metadata. A "_0"-style suffix IDA adds to a second
    // export of a taken name is not part of the API's name and is dropped.
    static bool named_type(qstring name, tinfo_t *out)
    {
        if ( name.empty() )
            return false;
        const qstring full_name = name;
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
                break;
            bool digits = true;
            for ( size_t k = (size_t)us + 1; k < name.length(); k++ )
                if ( name[k] < '0' || name[k] > '9' )
                    digits = false;
            if ( !digits )
                break;
            name.resize((size_t)us);
        }
        // No type library has it (mssdk has kernel32's names but not ntdll's
        // Rtl ones, such as RtlAddVectoredExceptionHandler): build the
        // prototype from the API metadata, phnt's for native calls.
        // api_signature drops the "_0" suffix itself.
        const win32meta::FuncSig *sig = api_signature(full_name.c_str());
        return sig != nullptr && api_prototype(*sig, inf_is_64bit(), out) && out->is_func();
    }

    static void remember_type(ea_t site)
    {
        netnode nn(CS_NODE, 0, true);
        if ( nn != BADNODE )
            nn.altset((nodeidx_t)site, 1, CS_TYPE_TAG);
    }

    // The global function pointer an indirect call loads its target from:
    // "call cs:off_X", or "mov reg, cs:off_X" shortly before a "call reg" with
    // nothing writing reg in between. BADADDR otherwise (computed register,
    // vtable slot, stack).
    //
    // Typing that pointer as the API types every call through it and survives
    // re-decompiling; a call-instruction type covers one site only.
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
            // Straight-line code only: a jump target in between could reach
            // the call with another value in the register.
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

    // Type the function pointer loaded at 'site' as a pointer to 'proto', and
    // give it the API's name when it has only a dummy one, so the pseudocode
    // reads "pInternetConnectA(hInternet: ...)". Skipped when the pointer
    // already has a type, or when calls through it reached several targets
    // ('ptr_targets': each pointer's targets over every site).
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
            // The export's name first, as for its type (callee_type).
            qstring api = export_name(mgr, target);
            if ( api.empty() && get_name(&api, target) <= 0 )
                api.qclear();
            // Drop IDA's "_0"-style suffix for a second export of a taken name
            // (kernel32's VirtualAlloc_0 forwards to kernelbase's), unless the
            // plain name is already used.
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

        // The blob is the only record of which cross-references the
        // annotation added, so a target an earlier annotation of this site
        // listed and this one does not (another scope's sweep, a re-run) has
        // its cross-reference removed before the blob forgets it.
        bytevec_t old;
        if ( nn.getblob(&old, (nodeidx_t)site, CS_TGTS_TAG) > 0 )
        {
            size_t count = old.size() / sizeof(uint64_t);
            const uint64_t *t = (const uint64_t *)old.begin();
            for ( size_t k = 0; k < count; k++ )
                if ( std::find(targets.begin(), targets.end(), (ea_t)t[k]) == targets.end() )
                    del_cref(site, (ea_t)t[k], false);
        }

        std::vector<uint64_t> raw;
        raw.reserve(targets.size());
        for ( ea_t t : targets )
            raw.push_back((uint64_t)t);
        nn.setblob(raw.data(), raw.size() * sizeof(uint64_t), (nodeidx_t)site, CS_TGTS_TAG);
    }

    // Remove annotations left by a different recording before a sweep writes
    // its own. They cannot just be forgotten: their comments and
    // cross-references stay in the database, and the store is the only record
    // of which ones the plugin wrote.
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

        // A backend may report direct calls too; the decode below drops them
        // before the caps apply.
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
            // A site with very many targets is a dispatcher: keep the most
            // frequent few.
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

    // The repeatable comment's own text, without the note an annotation added.
    // The note is the block starting at a line "TTD: calls" and running over
    // the indented target lines after it; everything else is the user's and
    // is kept.
    static qstring without_ttd_note(const qstring &cmt)
    {
        qstring out;
        bool in_note = false;
        size_t start = 0;
        while ( start <= cmt.length() )
        {
            size_t nl = cmt.find('\n', start);
            if ( nl == qstring::npos )
                nl = cmt.length();
            qstring line = cmt.substr(start, nl);
            if ( strncmp(line.c_str(), CS_NOTE_PREFIX, sizeof(CS_NOTE_PREFIX) - 1) == 0 )
                in_note = true;
            else if ( in_note && strncmp(line.c_str(), "  ", 2) != 0 )
                in_note = false;
            if ( !in_note )
            {
                if ( !out.empty() )
                    out.append('\n');
                out.append(line);
            }
            start = nl + 1;
        }
        // Blank lines left where the note was are not the user's.
        while ( !out.empty() && (out[out.length() - 1] == '\n' || out[out.length() - 1] == ' ') )
            out.remove_last();
        return out;
    }

    qstring ttd_call_note(const qstring &cmt)
    {
        qstring out;
        bool in_note = false;
        size_t start = 0;
        while ( start <= cmt.length() )
        {
            size_t nl = cmt.find('\n', start);
            if ( nl == qstring::npos )
                nl = cmt.length();
            qstring line = cmt.substr(start, nl);
            if ( strncmp(line.c_str(), CS_NOTE_PREFIX, sizeof(CS_NOTE_PREFIX) - 1) == 0 )
                in_note = true;
            else if ( in_note && strncmp(line.c_str(), "  ", 2) != 0 )
                break;                          // the note has ended
            if ( in_note )
            {
                if ( !out.empty() )
                    out.append('\n');
                out.append(line);
            }
            start = nl + 1;
        }
        return out;
    }

    // Put the annotation's note on 'site' after the user's own repeatable
    // comment, replacing a note an earlier annotation left. An empty 'note'
    // removes it and leaves the user's text alone.
    static void set_ttd_note(ea_t site, const qstring &note)
    {
        qstring cur;
        get_cmt(&cur, site, true);
        qstring cmt = without_ttd_note(cur);
        if ( !note.empty() )
        {
            if ( !cmt.empty() )
                cmt.append('\n');
            cmt.append(note);
        }
        if ( cmt != cur )
            set_cmt(site, cmt.c_str(), true);
    }

    // Global function pointer -> the targets reached through it.
    typedef std::map<ea_t, std::set<ea_t>> PtrTargets;

    // Targets reached through each global function pointer over every site
    // seen, not just the ones being written: a pointer is typed only when
    // every call through it went to one API. A decode per site, so built once
    // per sweep (an automatic scope is a whole module, up to kMaxSites).
    static PtrTargets pointer_targets(const SiteTargets &seen)
    {
        PtrTargets out;
        for ( const auto &kv : seen )
        {
            insn_t call;
            if ( decode_insn(&call, kv.first) <= 0 )
                continue;
            ea_t ptr = loaded_pointer(call);
            if ( ptr != BADADDR )
                out[ptr].insert(kv.second.begin(), kv.second.end());
        }
        return out;
    }

    // Write the answers for the sites in [lo, hi) into the database.
    static void write_annotations(TraceManager *mgr, const SiteTargets &seen,
                                  const PtrTargets &ptr_targets,
                                  ea_t lo, ea_t hi, CallSiteResult *res)
    {
        for ( auto it = seen.lower_bound(lo); it != seen.end() && it->first < hi; ++it )
        {
            ea_t site = it->first;
            insn_t insn;
            // Only an address that still decodes as an indirect call.
            if ( decode_insn(&insn, site) <= 0 || !is_indirect_call(insn) )
                continue;

            std::vector<ea_t> targets(it->second.begin(), it->second.end());
            if ( targets.empty() )
                continue;

            // decode_insn() decodes undefined bytes too, but add_cref rejects a
            // source with no item ("no defined item at 'from'"). Define the
            // instruction first; if that fails, skip the site.
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
                cmt.sprnt("%s%s", CS_NOTE_PREFIX, target_name(mgr, targets[0]).c_str());
            }
            else
            {
                cmt.sprnt("%s%d different targets:", CS_NOTE_PREFIX, (int)targets.size());
                for ( ea_t t : targets )
                {
                    cmt.append("\n  ");
                    cmt.append(target_name(mgr, t));
                }
                res->polymorphic++;
            }
            set_ttd_note(site, cmt);

            // The cross-reference puts the target in the xref list and joins
            // up the graph.
            for ( ea_t t : targets )
                add_cref(site, t, fl_CN);

            // For a single-target site, the call type: on the instruction when
            // it has none, and on the pointer it loads (see loaded_pointer).
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
        // Why it did not run goes in out->error: a dialog raised here would
        // hang a script (ttd("an.callsites")).
        auto refuse = [&](const char *why)
        {
            if ( out != nullptr )
                out->error = why;
            return false;
        };
        if ( out != nullptr )
            *out = res;
        if ( mgr == nullptr || !mgr->is_active() || mgr->backend() == nullptr )
            return refuse("This is only available while replaying a trace.");

        // Sorted scope, as the backend is handed it.
        std::vector<std::pair<ea_t, ea_t>> spans;
        for ( const auto &r : ranges )
            if ( r.first < r.second )
                spans.push_back(r);
        std::sort(spans.begin(), spans.end());
        if ( spans.empty() )
            return refuse("Nothing to annotate: the chosen scope covers no addresses.");

        clear_stale_annotations();

        SiteTargets seen;
        QueryResult qr;
        if ( !collect_sites(mgr, spans, &seen, &qr) )
            return refuse("This recording's backend could not report indirect call targets.");

        show_wait_box("HIDECANCEL\nAnnotating call sites...");
        write_annotations(mgr, seen, pointer_targets(seen), 0, BADADDR, &res);
        hide_wait_box();

        res.truncated = qr.truncated;
        res.cancelled = qr.cancelled;
        if ( out != nullptr )
            *out = res;
        return true;
    }

    //=======================================================================
    // Automatic resolution in the function stopped in
    //=======================================================================
    // The sweep cannot be narrowed (see annotate_indirect_calls), so it runs
    // once per module: the first stop in a module collects all its indirect
    // calls, and later functions there are annotated from that. Code in no
    // module (everything between modules) is one more scope.

    struct AutoScope
    {
        bool        ran = false;
        SiteTargets sites;
        PtrTargets  ptrs;       // pointer_targets(sites), made with them
    };
    static std::map<ea_t, AutoScope> g_autoScopes;   // module base, or 0
    static std::set<ea_t>            g_autoDone;     // functions annotated

    // The auto_callsites setting. The old per-database answer (alt 0, tag 'A',
    // of CS_NODE) is no longer read.
    bool callsites_auto_enabled()
    {
        return settings().auto_callsites;
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
            // User space between modules, from 64 KiB (the lowest address
            // Windows maps) to the top of user space.
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
            sc.ptrs = pointer_targets(sc.sites);
            sc.ran = true;
        }

        CallSiteResult res;
        write_annotations(mgr, sc.sites, sc.ptrs, start, end, &res);
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

            // Only the cross-references the annotation added come off.
            bytevec_t blob;
            if ( nn.getblob(&blob, i, CS_TGTS_TAG) > 0 )
            {
                size_t count = blob.size() / sizeof(uint64_t);
                const uint64_t *t = (const uint64_t *)blob.begin();
                for ( size_t k = 0; k < count; k++ )
                    del_cref(site, (ea_t)t[k], false);
            }
            set_ttd_note(site, qstring());
            if ( nn.altval(i, CS_TYPE_TAG) != 0 )
            {
                del_tinfo(site);
                nn.altdel(i, CS_TYPE_TAG);
            }
            // The pointer's type and name, when this site set them (only the
            // site that set them records it).
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
        // Let the automatic pass annotate those functions again.
        g_autoDone.clear();
        return n;
    }
}
