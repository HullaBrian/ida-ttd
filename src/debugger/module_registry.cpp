#include "debugger/module_registry.h"
#include "common/strings.h"
#include "common/symsrv.h"

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

    void ModuleRegistry::bind(ITraceBackend *backend, bool is64, const char *target_name)
    {
        reset();
        m_backend    = backend;
        m_is64       = is64;
        m_targetName = target_name != nullptr ? target_name : "";
        if ( m_backend == nullptr )
            return;

        m_modules = m_backend->modules();

        // The table: one span per distinct base, sorted.
        std::set<ea_t> seen;
        for ( const ModuleInfo &m : m_modules )
        {
            if ( m.base == BADADDR || !seen.insert(m.base).second )
                continue;
            Span s;
            s.base = m.base;
            s.end  = m.base + (ea_t)m.size;

            std::string bn = base_name(m.path.empty() ? m.name.c_str() : m.path.c_str());
            s.file = bn.c_str();

            // The segment identifier keeps the extension -- "kernel32_dll"
            // says more than "kernel32" -- but a segment name has to be a
            // legal IDA name, so anything else becomes an underscore.
            std::string ident = bn;
            for ( char &c : ident )
                if ( !qisalnum(c) && c != '_' )
                    c = '_';
            s.ident = ident.c_str();

            // The display name drops the extension, the way a debugger writes
            // "kernel32!Foo".
            size_t dot = bn.rfind('.');
            if ( dot != std::string::npos && dot != 0 )
                bn.resize(dot);
            s.name = bn.c_str();
            m_spans.push_back(std::move(s));
        }
        std::sort(m_spans.begin(), m_spans.end());

        // The analysed binary: the module the recording names as its main
        // one, else the first loaded.
        const char *main = m_backend->info().main_module.c_str();
        for ( const ModuleInfo &m : m_modules )
            if ( main[0] != '\0' && _stricmp(m.name.c_str(), main) == 0 )
            {
                m_mainBase = m.base;
                break;
            }
        if ( m_mainBase == BADADDR && !m_modules.empty() )
            m_mainBase = m_modules.front().base;
    }

    void ModuleRegistry::reset()
    {
        m_symCursor.reset();
        m_backend = nullptr;
        m_modules.clear();
        m_spans.clear();
        m_mainBase = BADADDR;
        m_resolvedBases.clear();
        m_pdbBases.clear();
        m_funcRanges.clear();
        m_moduleImages.clear();
        m_targetName.clear();
    }

    //=======================================================================
    // The table
    //=======================================================================
    size_t ModuleRegistry::index_at(ea_t ea) const
    {
        const std::vector<Span> &v = m_spans;
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
        lo = m_spans[idx].base;
        hi = m_spans[idx].end;
        return true;
    }

    qstring ModuleRegistry::name_at(ea_t ea) const
    {
        size_t idx = index_at(ea);
        return idx == (size_t)-1 ? qstring() : m_spans[idx].name;
    }

    qstring ModuleRegistry::ident_at(ea_t ea) const
    {
        size_t idx = index_at(ea);
        return idx == (size_t)-1 ? qstring() : m_spans[idx].ident;
    }

    std::vector<std::pair<ea_t, ea_t>> ModuleRegistry::ranges() const
    {
        std::vector<std::pair<ea_t, ea_t>> out;
        for ( const Span &s : m_spans )
            out.push_back({ s.base, s.end });
        return out;
    }

    std::vector<ModuleRegistry::Load> ModuleRegistry::loads() const
    {
        std::vector<Load> out;
        out.reserve(m_modules.size());
        for ( const ModuleInfo &m : m_modules )
        {
            Load ml;
            ml.base = m.base;
            ml.size = m.size;
            ml.name = m.name;
            ml.pos  = m.loaded;
            out.push_back(std::move(ml));
        }
        return out;
    }

    std::vector<const ModuleInfo *> ModuleRegistry::loaded_at(Position pos) const
    {
        std::vector<const ModuleInfo *> out;
        for ( const ModuleInfo &m : m_modules )
        {
            bool after_load = !m.loaded.is_valid() || m.loaded <= pos;
            bool before_unload = !m.unloaded.is_valid() || pos < m.unloaded;
            if ( after_load && before_unload )
                out.push_back(&m);
        }
        return out;
    }

    const ModuleInfo *ModuleRegistry::record_at(ea_t base) const
    {
        if ( base == BADADDR )
            return nullptr;
        for ( const ModuleInfo &m : m_modules )
            if ( m.base == base )
                return &m;
        return nullptr;
    }

    const ModuleInfo *ModuleRegistry::main_module() const
    {
        return record_at(m_mainBase);
    }

    bool ModuleRegistry::is_library_address(ea_t ea) const
    {
        size_t idx = index_at(ea);
        if ( idx == (size_t)-1 )
            return false;
        return m_spans[idx].base != m_mainBase;
    }

    bool ModuleRegistry::function_range_at(ea_t pc, ea_t &start, ea_t &end) const
    {
        size_t mi = index_at(pc);
        if ( mi == (size_t)-1 )
            return false;

        auto it = m_funcRanges.find(m_spans[mi].base);
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
        if ( m_backend == nullptr || pattern == nullptr )
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
                const Span &s = m_spans[idx];
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
    GuestRead ModuleRegistry::read_at_load(ea_t base)
    {
        if ( m_backend == nullptr )
            return GuestRead{};
        if ( !m_symCursor )
            m_symCursor = m_backend->make_cursor();
        if ( !m_symCursor )
            return GuestRead{};
        const ModuleInfo *m = record_at(base);
        m_symCursor->seek(m != nullptr && m->loaded.is_valid() ? m->loaded : m_backend->info().first);
        return guest_read(m_symCursor.get());
    }

    void ModuleRegistry::resolve_symbols(ea_t base)
    {
        if ( m_backend == nullptr || base == BADADDR )
            return;
        if ( !m_resolvedBases.insert(base).second )
            return;     // already attempted for this module

        const ModuleInfo *rec = record_at(base);
        std::string modpath = rec != nullptr ? rec->path.c_str() : "";

        // Names: the recording's own export list when the backend keeps one,
        // otherwise the image's export directory read where it is mapped.
        size_t named = 0;
        if ( m_backend->capabilities().recorded_exports )
        {
            for ( const ITraceBackend::Symbol &s : m_backend->module_symbols(base) )
                if ( s.is_export && apply_export_name(s.ea, s.name.c_str()) )
                    named++;
        }
        else
        {
            GuestRead rd = read_at_load(base);
            if ( rd )
                named = apply_module_exports(rd, base, m_is64);
        }

        // Function boundaries, so a whole function can be laid out (including
        // code before the current PC) when the user steps into runtime-only
        // code: from the backend if it knows them, else the module's .pdata --
        // from the on-disk file when it is the build the recording ran (it is
        // complete), from recorded memory otherwise (always right, sometimes
        // incomplete).
        std::vector<std::pair<ea_t, ea_t>> franges = m_backend->module_functions(base);
        size_t nfunc = franges.size();
        if ( nfunc == 0 )
        {
            uint32_t ts = rec != nullptr ? rec->timestamp : 0;
            uint32_t cs = rec != nullptr ? rec->checksum : 0;
            if ( ts == 0 && cs == 0 )
            {
                GuestPeInfo pe;
                GuestRead rd = read_at_load(base);
                if ( rd && read_guest_pe_info(rd, base, &pe) )
                {
                    ts = pe.timestamp;
                    cs = pe.checksum;
                }
            }
            nfunc = parse_pdata_functions_from_file(modpath.c_str(), base, m_is64, ts, cs, franges);
        }
        if ( nfunc == 0 )
        {
            GuestRead rd = read_at_load(base);
            if ( rd )
                nfunc = parse_pdata_functions(rd, base, m_is64, franges);
        }
        if ( nfunc > 0 )
        {
            std::sort(franges.begin(), franges.end());
            m_funcRanges[base] = std::move(franges);
        }

        msg("[ida-ttd] %s @ 0x%llX: %u export(s), %u function range(s)\n",
            base_name(modpath).c_str(), (uint64_t)base, (unsigned)named, (unsigned)nfunc);
    }

    void ModuleRegistry::resolve_loaded(Position pos)
    {
        for ( const ModuleInfo *m : loaded_at(pos) )
            resolve_symbols(m->base);
    }

    void ModuleRegistry::load_pdb(ea_t base)
    {
        if ( base == BADADDR || m_backend == nullptr )
            return;

        // Never fetch a PDB for the analysed binary itself. IDA already owns
        // that file's database, and asking the PDB plugin only triggers a
        // redundant, possibly networked, lookup for the very file being
        // analysed. Matched by base, which is authoritative.
        if ( base == m_mainBase )
            return;

        if ( !m_pdbBases.insert(base).second )
            return;     // already requested for this module

        const ModuleInfo *m = record_at(base);
        std::string path = m != nullptr ? m->path.c_str() : "";
        if ( path.empty() )
            return;

        // The same refusal again by name, for the input file: a database opened
        // against a trace of a differently-based copy would miss the check above.
        if ( _stricmp(base_name(path).c_str(), m_targetName.c_str()) == 0 )
            return;

        // Which PDB this module was actually built with, read from the image as
        // the recording had it mapped. The copy of the DLL on this machine cannot
        // answer that: it is often a different build, and its symbols would
        // describe code this recording never ran.
        GuestPdbInfo pdb;
        if ( !pdb_identity(base, &pdb) )
            return;     // no debug directory recorded: nothing to look up

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
            const ModuleInfo *m = record_at(r.base);
            std::string path = m != nullptr ? m->path.c_str() : "";
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

    bool ModuleRegistry::pdb_identity(ea_t base, GuestPdbInfo *out)
    {
        GuestRead rd = read_at_load(base);
        return rd && read_guest_pdb_info(rd, base, out);
    }

    //=======================================================================
    // On-disk images
    //=======================================================================
    const ModuleImage *ModuleRegistry::image_for(ea_t ea, ea_t &base_out)
    {
        if ( m_backend == nullptr )
            return nullptr;

        // Which loaded module, if any, contains 'ea'? A binary search: this
        // runs once per gap of every memory read.
        size_t mi = index_at(ea);
        if ( mi == (size_t)-1 )
            return nullptr;
        ea_t base = m_spans[mi].base;

        base_out = base;
        auto it = m_moduleImages.find(base);
        if ( it != m_moduleImages.end() )
            return it->second.ok ? &it->second : nullptr;

        const ModuleInfo *m = record_at(base);
        std::string path = m != nullptr ? m->path.c_str() : "";

        ModuleImage img;
        load_module_image(path.c_str(), img);   // img.ok == false on failure

        // The path was recorded on the machine that made the trace. The file at
        // that path here may be a different build of the same DLL -- a different
        // patch level of ntdll is the common case -- and its bytes would then be
        // served as ground truth with nothing to say they are wrong. So the
        // image's timestamp and checksum must match the recording's: the
        // backend's, else the recorded headers'.
        uint32_t ts = m != nullptr ? m->timestamp : 0;
        uint32_t cs = m != nullptr ? m->checksum : 0;
        if ( img.ok && ts == 0 && cs == 0 )
        {
            GuestPeInfo pe;
            GuestRead rd = read_at_load(base);
            if ( rd && read_guest_pe_info(rd, base, &pe) )
            {
                ts = pe.timestamp;
                cs = pe.checksum;
            }
        }
        bool mismatch = img.ok
                     && ((ts != 0 && img.timestamp != 0 && img.timestamp != ts)
                      || (cs != 0 && img.checksum != 0 && img.checksum != cs));
        if ( mismatch )
        {
            msg("[ida-ttd] image fallback for %s @ 0x%llX: rejected, the on-disk "
                "file is a different build (trace %08X/%08X, file %08X/%08X).\n",
                base_name(path).c_str(), (uint64_t)base, ts, cs, img.timestamp, img.checksum);
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
