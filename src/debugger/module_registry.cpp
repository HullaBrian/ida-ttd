#include "debugger/module_registry.h"
#include "debugger/msttd_position.h"
#include "common/trace_open.h"
#include "common/symsrv.h"

using namespace TTD;
using namespace TTD::Replay;

namespace idattd
{
    // Shell-style glob, case-insensitive: '*' any run, '?' one character.
    static bool wildcard_match(const char *pat, const char *str)
    {
        const char *star = nullptr;
        const char *ss   = str;
        const char *p    = pat;
        const char *s    = str;
        while ( *s != '\0' )
        {
            if ( *p == '?' || tolower((unsigned char)*p) == tolower((unsigned char)*s) )
            {
                p++;
                s++;
            }
            else if ( *p == '*' )
            {
                star = p++;
                ss   = s;
            }
            else if ( star != nullptr )
            {
                p = star + 1;
                s = ++ss;
            }
            else
            {
                return false;
            }
        }
        while ( *p == '*' )
            p++;
        return *p == '\0';
    }

    static bool image_matches_module(const ModuleImage &img, const Module &m)
    {
        if ( m.Timestamp != 0 && img.timestamp != 0 && img.timestamp != m.Timestamp )
            return false;
        if ( m.Checksum != 0 && img.checksum != 0 && img.checksum != m.Checksum )
            return false;
        return true;
    }

    void ModuleRegistry::bind(IReplayEngine *engine, bool is64, const char *target_name)
    {
        reset();
        m_engine     = engine;
        m_is64       = is64;
        m_targetName = target_name != nullptr ? target_name : "";
    }

    void ModuleRegistry::reset()
    {
        m_engine = nullptr;
        m_spans.clear();
        m_spanCount  = (size_t)-1;
        m_spanEngine = nullptr;
        m_resolvedBases.clear();
        m_pdbBases.clear();
        m_funcRanges.clear();
        m_moduleImages.clear();
        m_symCursor.reset();
        m_targetName.clear();
    }

    //=======================================================================
    // The table
    //=======================================================================
    const std::vector<ModuleRegistry::Span> &ModuleRegistry::spans() const
    {
        size_t n = m_engine != nullptr ? m_engine->GetModuleCount() : 0;
        if ( n == m_spanCount && m_engine == m_spanEngine )
            return m_spans;

        m_spans.clear();
        if ( m_engine != nullptr )
        {
            const Module *list = m_engine->GetModuleList();
            m_spans.reserve(n);
            for ( size_t i = 0; i < n; i++ )
            {
                Span s;
                s.base = (ea_t)(uint64_t)list[i].Address;
                s.end  = s.base + (ea_t)list[i].Size;

                std::string bn = base_name(to_utf8(list[i].pName, list[i].NameLength));
                s.file = bn.c_str();

                // The segment identifier keeps the extension -- "kernel32_dll"
                // says more than "kernel32" -- but a segment name has to be a
                // legal IDA name, so anything else becomes an underscore.
                std::string ident = bn;
                for ( char &c : ident )
                    if ( !qisalnum(c) && c != '_' )
                        c = '_';
                s.ident = ident.c_str();

                // The display name drops the extension, the way a debugger
                // writes "kernel32!Foo".
                size_t dot = bn.rfind('.');
                if ( dot != std::string::npos && dot != 0 )
                    bn.resize(dot);
                s.name = bn.c_str();

                m_spans.push_back(std::move(s));
            }
            std::sort(m_spans.begin(), m_spans.end());
        }
        m_spanCount  = n;
        m_spanEngine = m_engine;
        return m_spans;
    }

    size_t ModuleRegistry::index_at(ea_t ea) const
    {
        const std::vector<Span> &v = spans();
        Span probe;
        probe.base = ea;
        // Last module whose base <= ea, then check ea falls inside it.
        auto it = std::upper_bound(v.begin(), v.end(), probe);
        if ( it == v.begin() )
            return (size_t)-1;
        --it;
        if ( ea >= it->base && ea < it->end )
            return (size_t)(it - v.begin());
        return (size_t)-1;
    }

    bool ModuleRegistry::range_at(ea_t ea, ea_t &lo, ea_t &hi) const
    {
        size_t idx = index_at(ea);
        if ( idx == (size_t)-1 )
            return false;
        lo = spans()[idx].base;
        hi = spans()[idx].end;
        return true;
    }

    qstring ModuleRegistry::name_at(ea_t ea) const
    {
        size_t idx = index_at(ea);
        return idx == (size_t)-1 ? qstring() : spans()[idx].name;
    }

    qstring ModuleRegistry::ident_at(ea_t ea) const
    {
        size_t idx = index_at(ea);
        return idx == (size_t)-1 ? qstring() : spans()[idx].ident;
    }

    std::vector<std::pair<ea_t, ea_t>> ModuleRegistry::ranges() const
    {
        std::vector<std::pair<ea_t, ea_t>> out;
        for ( const Span &s : spans() )
            out.push_back({ s.base, s.end });
        return out;
    }

    std::vector<ModuleRegistry::Load> ModuleRegistry::loads() const
    {
        std::vector<Load> out;
        if ( m_engine == nullptr )
            return out;

        size_t n = m_engine->GetModuleLoadedEventCount();
        const ModuleLoadedEvent *evs = m_engine->GetModuleLoadedEventList();
        out.reserve(n);
        for ( size_t i = 0; i < n; i++ )
        {
            const Module *m = evs[i].pModule;
            if ( m == nullptr )
                continue;
            Load ml;
            ml.base = (ea_t)(uint64_t)m->Address;
            ml.size = m->Size;
            ml.name = base_name(to_utf8(m->pName, m->NameLength)).c_str();
            ml.pos  = to_core(evs[i].Position);
            out.push_back(std::move(ml));
        }
        return out;
    }

    bool ModuleRegistry::is_library_address(ea_t ea) const
    {
        if ( m_engine == nullptr )
            return false;
        size_t idx = index_at(ea);
        if ( idx == (size_t)-1 )
            return false;
        // Module 0 in the engine's list is the analysed binary; everything else
        // is library or system code. spans() is sorted by base, so the base is
        // what identifies it, not the index.
        ea_t main_base = m_engine->GetModuleCount() > 0
                       ? (ea_t)(uint64_t)m_engine->GetModuleList()[0].Address
                       : BADADDR;
        return spans()[idx].base != main_base;
    }

    const Module *ModuleRegistry::record_at(ea_t base) const
    {
        if ( m_engine == nullptr || base == BADADDR )
            return nullptr;
        size_t n = m_engine->GetModuleCount();
        const Module *list = m_engine->GetModuleList();
        for ( size_t i = 0; i < n; i++ )
            if ( (ea_t)(uint64_t)list[i].Address == base )
                return &list[i];
        return nullptr;
    }

    bool ModuleRegistry::function_range_at(ea_t pc, ea_t &start, ea_t &end) const
    {
        if ( m_engine == nullptr )
            return false;

        size_t mi = index_at(pc);
        if ( mi == (size_t)-1 )
            return false;

        auto it = m_funcRanges.find(spans()[mi].base);
        if ( it == m_funcRanges.end() )
            return false;

        // Last range whose start <= pc, then verify pc is within it.
        const std::vector<std::pair<ea_t, ea_t>> &v = it->second;
        auto up = std::upper_bound(v.begin(), v.end(), std::make_pair(pc, (ea_t)BADADDR));
        if ( up == v.begin() )
            return false;
        --up;
        if ( pc >= up->first && pc < up->second )
        {
            start = up->first;
            end   = up->second;
            return true;
        }
        return false;
    }

    std::vector<ea_t> ModuleRegistry::resolve_function_pattern(const char *pattern) const
    {
        std::vector<ea_t> out;
        if ( m_engine == nullptr || pattern == nullptr )
            return out;

        // Split an optional "module!" qualifier off the name pattern.
        std::string pat = pattern;
        std::string modpat, namepat;
        size_t bang = pat.find('!');
        if ( bang != std::string::npos )
        {
            modpat  = pat.substr(0, bang);
            namepat = pat.substr(bang + 1);
        }
        else
        {
            namepat = pat;
        }
        if ( namepat.empty() )
            return out;

        std::set<ea_t> seen;
        size_t nn = get_nlist_size();
        for ( size_t i = 0; i < nn; i++ )
        {
            const char *nm = get_nlist_name(i);
            if ( nm == nullptr || !wildcard_match(namepat.c_str(), nm) )
                continue;
            ea_t ea = get_nlist_ea(i);

            if ( !modpat.empty() )
            {
                // The table already holds each name with and without its
                // extension, so a module filter is one binary search and two
                // string compares rather than a scan of the module list.
                size_t idx = index_at(ea);
                if ( idx == (size_t)-1 )
                    continue;
                const Span &s = spans()[idx];
                if ( !wildcard_match(modpat.c_str(), s.file.c_str())
                  && !wildcard_match(modpat.c_str(), s.name.c_str()) )
                    continue;
            }

            ea_t fstart = get_func_start(ea);
            ea_t key = fstart != BADADDR ? fstart : ea;
            if ( seen.insert(key).second )
                out.push_back(key);
        }
        return out;
    }

    //=======================================================================
    // Naming
    //=======================================================================
    void ModuleRegistry::resolve_symbols(ea_t base)
    {
        if ( m_engine == nullptr || base == BADADDR )
            return;
        if ( !m_resolvedBases.insert(base).second )
            return;     // already attempted for this module

        // Find the load event for the module at this base, so the scratch
        // cursor can be parked exactly where the image is recorded as mapped.
        size_t n = m_engine->GetModuleLoadedEventCount();
        const ModuleLoadedEvent *list = m_engine->GetModuleLoadedEventList();
        const ModuleLoadedEvent *hit = nullptr;
        for ( size_t i = 0; i < n; i++ )
        {
            if ( list[i].pModule != nullptr
              && (ea_t)(uint64_t)list[i].pModule->Address == base )
            {
                hit = &list[i];
                break;
            }
        }

        if ( !m_symCursor )
            m_symCursor = UniqueCursor{ m_engine->NewCursor() };
        if ( !m_symCursor )
            return;

        m_symCursor->SetPosition(hit != nullptr ? hit->Position : TtdPosition::Min);
        size_t named = apply_module_exports(m_symCursor.get(), base, m_is64);

        // Recover this module's function boundaries from its .pdata exception
        // table, so a whole function can be laid out (including code before the
        // current PC) when the user steps into runtime-only code -- no symbols,
        // no replay. Prefer the on-disk PE, which is complete; fall back to
        // recorded memory, since TTD may not have captured the .pdata section.
        std::string modpath = hit != nullptr && hit->pModule != nullptr
                            ? to_utf8(hit->pModule->pName, hit->pModule->NameLength)
                            : std::string();
        std::vector<std::pair<ea_t, ea_t>> franges;
        // Only trust the on-disk PE when its headers match the module recorded
        // in the trace; otherwise fall through to the copy in guest memory,
        // which is always correct if sometimes incomplete.
        const Module *mrec = hit != nullptr ? hit->pModule : record_at(base);
        size_t nfunc = parse_pdata_functions_from_file(
                           modpath.c_str(), base, m_is64,
                           mrec != nullptr ? mrec->Timestamp : 0,
                           mrec != nullptr ? mrec->Checksum  : 0,
                           franges);
        if ( nfunc == 0 )
            nfunc = parse_pdata_functions(m_symCursor.get(), base, m_is64, franges);
        if ( nfunc > 0 )
            m_funcRanges[base] = std::move(franges);

        msg("[ida-ttd] %s @ 0x%llX: %u export(s), %u function range(s)\n",
            base_name(modpath).c_str(), (uint64_t)base, (unsigned)named, (unsigned)nfunc);
    }

    void ModuleRegistry::resolve_loaded(ICursorView *cursor)
    {
        if ( cursor == nullptr )
            return;
        size_t n = cursor->GetModuleCount();
        const ModuleInstance *list = cursor->GetModuleList();
        for ( size_t i = 0; i < n; i++ )
            if ( list[i].pModule != nullptr )
                resolve_symbols((ea_t)(uint64_t)list[i].pModule->Address);
    }

    void ModuleRegistry::load_pdb(ea_t base)
    {
        if ( base == BADADDR || m_engine == nullptr )
            return;

        // Never fetch a PDB for the analysed binary itself (module 0). IDA
        // already owns that file's database -- its own symbols and analysis --
        // and asking the PDB plugin only triggers a redundant, possibly
        // networked, symbol-server lookup for the very file being analysed.
        // Matched by base, which is authoritative, so a name mismatch cannot
        // let it slip through.
        if ( m_engine->GetModuleCount() > 0
          && (ea_t)(uint64_t)m_engine->GetModuleList()[0].Address == base )
            return;

        if ( !m_pdbBases.insert(base).second )
            return;     // already requested for this module

        const Module *m = record_at(base);
        std::string   path = m != nullptr ? to_utf8(m->pName, m->NameLength) : std::string();
        if ( path.empty() )
            return;

        // The same refusal again by name, for the input file: a database opened
        // against a trace of a differently-based copy would miss the check above.
        if ( _stricmp(base_name(path).c_str(), m_targetName.c_str()) == 0 )
            return;

        // Which PDB this module was actually built with, read from the image as
        // the recording had it mapped. The copy of the DLL on this machine cannot
        // answer that: it is often a different build, and ntdll on a machine
        // patched since the recording is the usual case. Its symbols would
        // describe code this recording never ran.
        GuestPdbInfo pdb;
        if ( !pdb_identity(base, &pdb) )
        {
            // No debug directory in the recorded image, or the headers were never
            // recorded. Nothing to look up and nothing to tell the user.
            return;
        }

        switch ( fetch_pdb(pdb.name.c_str(), pdb.signature.c_str(), base) )
        {
            case FetchState::Cached:
                apply_pdb(base, path, pdb);
                break;
            case FetchState::Fetching:
                // A worker has it. apply_finished_pdbs() picks it up at the next
                // stop; nothing blocks here, which is the whole point.
                break;
            case FetchState::Failed:
                report_missing_pdb(path, pdb);
                break;
        }
    }

    void ModuleRegistry::apply_pdb(ea_t base, const std::string &path, const GuestPdbInfo &pdb)
    {
        // Drive the PDB plugin with PDB_CC_USER_WITH_DATA (3): it reads the
        // load address and path from the "$ pdb" netnode and applies symbols
        // without the "load symbols?" prompt the automatic DOPT_LOAD_DINFO path
        // shows.
        //
        // It resolves the PDB through _NT_SYMBOL_PATH, which symsrv_install_path()
        // put our store at the front of, so this finds a local file rather than
        // going to the network from the main thread.
        static const char *PDB_NODE_NAME = "$ pdb";
        const int PDB_DLLBASE_NODE_IDX  = 0;
        const int PDB_DLLNAME_NODE_IDX  = 0;
        const int PDB_CC_USER_WITH_DATA = 3;
        netnode pdbnode;
        pdbnode.create(PDB_NODE_NAME);
        pdbnode.altset(PDB_DLLBASE_NODE_IDX, base);
        pdbnode.supset(PDB_DLLNAME_NODE_IDX, path.c_str(), path.size() + 1);

        // Suppress the plugin's dialogs while it runs: when the PDB cannot be
        // matched it would otherwise pop an error or file-locate dialog for
        // every module. With 'batch' set those become log lines, and the miss is
        // reported to the output window here instead.
        //
        // Restored by a scope guard: 'batch' is a global that changes how IDA
        // reports every subsequent error, so an early return or a throw out of
        // the plugin must not leave it stuck on.
        struct BatchGuard
        {
            bool saved;
            BatchGuard() : saved(batch) { batch = true; }
            ~BatchGuard() { batch = saved; }
        } batch_guard;
        bool ran = load_and_run_plugin("pdb", PDB_CC_USER_WITH_DATA);

        // The plugin writes its success flag back into the same netnode slot.
        if ( ran && pdbnode.altval(PDB_DLLBASE_NODE_IDX) != 0 )
        {
            msg("[ida-ttd] PDB symbols applied for %s (%s).\n",
                base_name(path).c_str(), pdb.name.c_str());
            return;
        }
        report_missing_pdb(path, pdb);
    }

    // Say which PDB is wanted and where it lives. Only the recording knows: the
    // identity comes from the CodeView record of the image as it was mapped, and
    // that is the one thing a mismatched local DLL cannot tell the user.
    void ModuleRegistry::report_missing_pdb(const std::string &path, const GuestPdbInfo &pdb)
    {
        msg("[ida-ttd] PDB symbols not resolved for %s.\n"
            "           The matching symbols are %s %s:\n"
            "           https://msdl.microsoft.com/download/symbols/%s/%s/%s\n"
            "           Save that file, then File > Load file > PDB file.\n",
            base_name(path).c_str(),
            pdb.name.c_str(), pdb.signature.c_str(),
            pdb.name.c_str(), pdb.signature.c_str(), pdb.name.c_str());
    }

    void ModuleRegistry::apply_finished_pdbs()
    {
        std::vector<FetchResult> done;
        if ( symsrv_take_completed(&done) == 0 )
            return;

        for ( const FetchResult &r : done )
        {
            const Module *m = record_at(r.base);
            std::string   path = m != nullptr ? to_utf8(m->pName, m->NameLength)
                                              : std::string();
            if ( path.empty() )
                continue;

            if ( r.path.empty() )
            {
                msg("[ida-ttd] could not download %s for %s: %s.\n",
                    r.name.c_str(), base_name(path).c_str(), r.error.c_str());
                continue;
            }

            GuestPdbInfo pdb;
            if ( pdb_identity(r.base, &pdb) )
                apply_pdb(r.base, path, pdb);
        }
    }

    // Which PDB the module at 'base' was built with, read from the image as the
    // recording had it mapped.
    bool ModuleRegistry::pdb_identity(ea_t base, GuestPdbInfo *out)
    {
        if ( m_engine == nullptr || out == nullptr )
            return false;

        // Read it where the module is known to be mapped: its load event.
        // Reading at the playhead would fail for a module unloaded since.
        const ModuleLoadedEvent *hit = nullptr;
        size_t n = m_engine->GetModuleLoadedEventCount();
        const ModuleLoadedEvent *list = m_engine->GetModuleLoadedEventList();
        for ( size_t i = 0; i < n; i++ )
        {
            if ( list[i].pModule != nullptr
              && (ea_t)(uint64_t)list[i].pModule->Address == base )
            {
                hit = &list[i];
                break;
            }
        }

        if ( !m_symCursor )
            m_symCursor = UniqueCursor{ m_engine->NewCursor() };
        if ( !m_symCursor )
            return false;
        m_symCursor->SetPosition(hit != nullptr ? hit->Position : TtdPosition::Min);
        return read_guest_pdb_info(m_symCursor.get(), base, out);
    }

    //=======================================================================
    // On-disk images
    //=======================================================================
    const ModuleImage *ModuleRegistry::image_for(ea_t ea, ea_t &base_out)
    {
        if ( m_engine == nullptr )
            return nullptr;

        // Which loaded module, if any, contains 'ea'? A binary search: this
        // runs once per gap of every memory read.
        size_t mi = index_at(ea);
        if ( mi == (size_t)-1 )
            return nullptr;
        ea_t base = spans()[mi].base;

        base_out = base;
        auto it = m_moduleImages.find(base);
        if ( it != m_moduleImages.end() )
            return it->second.ok ? &it->second : nullptr;

        // Only resolve the path on a cache miss: it costs a UTF-8 conversion.
        const Module *m = record_at(base);
        std::string   path = m != nullptr ? to_utf8(m->pName, m->NameLength) : std::string();

        ModuleImage img;
        load_module_image(path.c_str(), img);   // img.ok == false on failure

        // The path was recorded on the machine that made the trace. The file at
        // that path on this machine may be a different build of the same DLL --
        // a different patch level of ntdll is the common case -- and its bytes
        // would then be served as ground truth for disassembly with nothing to
        // say they are wrong. The trace records the image's timestamp and
        // checksum, so refuse anything that does not match.
        if ( img.ok && m != nullptr && !image_matches_module(img, *m) )
        {
            msg("[ida-ttd] image fallback for %s @ 0x%llX: rejected, the on-disk "
                "file is a different build (trace %08X/%08X, file %08X/%08X).\n",
                base_name(path).c_str(), (uint64_t)base,
                m->Timestamp, m->Checksum, img.timestamp, img.checksum);
            img = ModuleImage{};     // ok == false: never consulted again
        }
        else
        {
            msg("[ida-ttd] image fallback for %s @ 0x%llX: %s\n",
                base_name(path).c_str(), (uint64_t)base,
                img.ok ? "loaded" : "file unavailable / not a PE");
        }

        it = m_moduleImages.emplace(base, std::move(img)).first;
        return it->second.ok ? &it->second : nullptr;
    }
}
