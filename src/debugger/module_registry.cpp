#include "debugger/module_registry.h"
#include "core/diag.h"
#include "common/strings.h"
#include "common/symsrv.h"
#include "common/local_path.h"
#include "analysis/query_runner.h"

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

            // The segment identifier keeps the extension ("kernel32_dll" says
            // more than "kernel32"); anything not legal in an IDA name becomes
            // an underscore.
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
        m_pdbRetried.clear();
        // Waits for any read still running (std::async futures join); a read
        // takes milliseconds.
        m_publics.clear();
        m_funcRanges.clear();
        m_funcTried.clear();
        m_exports.clear();
        m_loadImage.clear();
        m_loadImageTried.clear();
        m_lastImageLoad = (size_t)-1;
        m_moduleImages.clear();
        m_targetName.clear();
    }

    //=======================================================================
    // The table
    //=======================================================================
    size_t ModuleRegistry::index_at(ea_t ea) const
    {
        const std::vector<Span> &v = m_spans;
        // Last module whose base <= ea, then check ea falls inside it.
        auto it = std::upper_bound(v.begin(), v.end(), ea,
                                   [](ea_t a, const Span &s) { return a < s.base; });
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

        // Worked out on first use when the backend's reads are not cheap.
        const_cast<ModuleRegistry *>(this)->function_ranges(m_spans[mi].base);
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
            // Import slots and CFG pointers are named data (__imp_memset,
            // __guard_dispatch_icall_fptr); followed, they would list calls to
            // another module's functions under this module's pattern.
            if ( is_data(get_flags(ea)) || strncmp(nm, "__imp_", 6) == 0 || strncmp(nm, "__guard_", 8) == 0 )
                continue;

            if ( !modpat.empty() )
            {
                // The table holds each name with and without its extension,
                // so this is one binary search and two compares.
                size_t idx = index_at(ea);
                if ( idx == (size_t)-1 )
                    continue;
                const Span &s = m_spans[idx];
                if ( !wildcard_match(modpat.c_str(), s.file.c_str())
                  && !wildcard_match(modpat.c_str(), s.name.c_str()) )
                    continue;
            }

            // A name inside a function is a label (a funclet, a jump target
            // the PDB named), not a function to trace; tracing the enclosing
            // function listed its calls under the pattern.
            ea_t fstart = get_func_start(ea);
            if ( fstart != BADADDR && fstart != ea )
                continue;
            if ( seen.insert(ea).second )
                out.push_back(ea);
        }

        // IDA names a module only once it is mapped where the user is, so a
        // module loaded later (kernel32, seen from the very start) has no
        // names yet. Its exports are known anyway: the recording's list, or
        // the export directory read where it loaded.
        ModuleRegistry *self = const_cast<ModuleRegistry *>(this);
        for ( const Span &s : m_spans )
        {
            if ( !modpat.empty()
              && !wildcard_match(modpat.c_str(), s.file.c_str())
              && !wildcard_match(modpat.c_str(), s.name.c_str()) )
                continue;
            for ( const auto &e : self->exports_of(s.base) )
                if ( wildcard_match(namepat.c_str(), e.second.c_str()) && seen.insert(e.first).second )
                    out.push_back(e.first);
        }
        return out;
    }

    qstring ModuleRegistry::export_name_at(ea_t ea)
    {
        size_t idx = index_at(ea);
        if ( idx == (size_t)-1 )
            return qstring();
        // Stable-sorted by address, so of several names at 'ea' this is the
        // first the module lists.
        const std::vector<std::pair<ea_t, std::string>> &v = exports_of(m_spans[idx].base);
        auto it = std::lower_bound(v.begin(), v.end(), ea,
                                   [](const std::pair<ea_t, std::string> &e, ea_t a) { return e.first < a; });
        if ( it == v.end() || it->first != ea )
            return qstring();
        qstring out;
        out.sprnt("%s!%s", m_spans[idx].name.c_str(), it->second.c_str());
        return out;
    }

    const std::vector<std::pair<ea_t, std::string>> &ModuleRegistry::exports_of(ea_t base)
    {
        auto it = m_exports.find(base);
        if ( it != m_exports.end() )
            return it->second;
        std::vector<std::pair<ea_t, std::string>> &v = m_exports[base];
        if ( m_backend->capabilities().recorded_exports )
        {
            for ( const ITraceBackend::Symbol &s : m_backend->module_symbols(base) )
                if ( s.is_export )
                    v.emplace_back(s.ea, s.name.c_str());
        }
        else
        {
            const ModuleInfo *m = record_at(base);
            const uint32_t MACHINE_AMD64 = 0x8664;    // IMAGE_FILE_MACHINE_AMD64
            bool is64 = m != nullptr && m->machine != 0 ? m->machine == MACHINE_AMD64 : m_is64;
            GuestRead rd = read_at_load(base);
            if ( rd )
                read_guest_exports(rd, base, is64, &v);
        }
        // export_name_at looks names up by address once per decoded call.
        std::stable_sort(v.begin(), v.end(),
                         [](const std::pair<ea_t, std::string> &a, const std::pair<ea_t, std::string> &b)
                         { return a.first < b.first; });
        return v;
    }

    //=======================================================================
    // Naming
    //=======================================================================
    GuestRead ModuleRegistry::read_at_load(ea_t base)
    {
        return read_at_record(record_at(base));
    }

    GuestRead ModuleRegistry::read_at_record(const ModuleInfo *m)
    {
        if ( m_backend == nullptr )
            return GuestRead{};
        if ( !m_symCursor )
            m_symCursor = m_backend->make_cursor();
        if ( !m_symCursor )
            return GuestRead{};
        m_symCursor->seek(m != nullptr && m->loaded.is_valid() ? m->loaded : m_backend->info().first);
        return guest_read(m_symCursor.get());
    }

    void ModuleRegistry::resolve_symbols(ea_t base)
    {
        // Called per mapped module on every stop, so a module already done
        // returns before any logging.
        if ( m_backend == nullptr || base == BADADDR || m_resolvedBases.count(base) != 0 )
            return;
        // Not before the module has a segment: names on memory IDA lacks are
        // dropped, and marking the module done would leave it unnamed for the
        // session. The next stop tries again (resolve_loaded).
        if ( get_segment_ea(base) == BADADDR )
            return;
        m_resolvedBases.insert(base);

        qstring what;
        what.sprnt("%a", base);
        diag("module symbols begin %s", what.c_str());
        DiagTimer diag_timer("module symbols", what);

        const ModuleInfo *rec = record_at(base);
        std::string modpath = rec != nullptr ? rec->path.c_str() : "";

        // Names: the recording's export list when the backend keeps one, else
        // the image's export directory read where it is mapped.
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

        // Function bounds: now when reads are cheap, else when a stop first
        // asks (function_range_at), since they can mean reading the whole
        // .pdata out of the recording.
        size_t nfunc = 0;
        if ( m_backend->capabilities().cheap_reads )
            nfunc = function_ranges(base);

        msg("[ida-ttd] %s @ 0x%llX: %u export(s)%s\n",
            base_name(modpath).c_str(), (uint64_t)base, (unsigned)named,
            m_backend->capabilities().cheap_reads ? qstring().sprnt(", %u function range(s)", (unsigned)nfunc).c_str()
                                                  : "");
    }

    // Function bounds, so a whole function (including code before the PC) can
    // be laid out: from the backend if it knows them, else the module's
    // .pdata, read from the on-disk file when it is the recorded build
    // (complete), otherwise from recorded memory (right, sometimes
    // incomplete). Once per module; returns how many.
    size_t ModuleRegistry::function_ranges(ea_t base)
    {
        if ( !m_funcTried.insert(base).second )
        {
            auto it = m_funcRanges.find(base);
            return it != m_funcRanges.end() ? it->second.size() : 0;
        }
        DiagTimer diag_timer("function ranges");
        const ModuleInfo *rec = record_at(base);
        std::string modpath = rec != nullptr ? rec->path.c_str() : "";
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
        return nfunc;
    }

    void ModuleRegistry::resolve_loaded(Position pos)
    {
        for ( const ModuleInfo *m : loaded_at(pos) )
            resolve_symbols(m->base);
    }

    void ModuleRegistry::load_pdb(ea_t base, bool stopped_here)
    {
        if ( base == BADADDR || m_backend == nullptr )
            return;
        // Naming from a PDB reads through the module, which without cheap
        // reads is seconds per module, and a recording loads dozens. Then
        // only the module a stop lands in gets its PDB.
        if ( !stopped_here && !m_backend->capabilities().cheap_reads )
            return;

        // Never for the analysed binary: IDA already has its database, and a
        // lookup would be redundant and possibly networked. Matched by base,
        // which is authoritative.
        if ( base == m_mainBase )
            return;

        if ( !m_pdbBases.insert(base).second )
            return;     // already requested for this module

        const ModuleInfo *m = record_at(base);
        std::string path = m != nullptr ? m->path.c_str() : "";
        if ( path.empty() )
            return;

        // Again by name, for a trace of a copy loaded at another base.
        if ( _stricmp(base_name(path).c_str(), m_targetName.c_str()) == 0 )
            return;

        // The PDB identity comes from the image as recorded. The local copy
        // of the DLL is often a different build whose symbols would describe
        // code this recording never ran.
        GuestPdbInfo pdb;
        if ( !pdb_identity(base, &pdb) )
            return;     // no debug directory recorded: nothing to look up

        switch ( fetch_pdb(pdb.name.c_str(), pdb.signature.c_str(), base) )
        {
            case FetchState::Cached:
                start_publics(base, symbol_store_path(pdb.name.c_str(), pdb.signature.c_str()).c_str());
                break;
            case FetchState::Fetching:
                // A worker has it; advance_pdbs() picks it up when it lands.
                break;
            case FetchState::Failed:
                report_missing_pdb(path, pdb);
                break;
            case FetchState::Off:
                break;      // the user turned downloads off: nothing to say per module
        }
    }

    void ModuleRegistry::apply_pdb(ea_t base, const std::string &path, const GuestPdbInfo &pdb)
    {
        DiagTimer diag_timer("apply PDB", qstring(pdb.name.c_str()));
        // PDB_CC_USER_WITH_DATA (3): the PDB plugin reads the load address
        // and path from the "$ pdb" netnode and applies symbols without the
        // "load symbols?" prompt of the DOPT_LOAD_DINFO path.
        //
        // It resolves the PDB through _NT_SYMBOL_PATH, which starts with the
        // plugin's store (symsrv_install_path()), so it finds a local file
        // instead of going to the network from the main thread.
        static const char *PDB_NODE_NAME = "$ pdb";
        const int PDB_DLLBASE_NODE_IDX  = 0;
        const int PDB_DLLNAME_NODE_IDX  = 0;
        const int PDB_CC_USER_WITH_DATA = 3;
        //
        // The plugin opens the file named here. The module path is the
        // recording's, so a UNC or device path (which would make Windows
        // contact another host) is never handed over; the PDB in the store,
        // which the plugin also accepts, stands in for it. So does a local
        // path with no file behind it.
        std::string input = path;
        if ( !is_local_drive_path(input.c_str()) || !qfileexist(input.c_str()) )
            input = symbol_store_path(pdb.name.c_str(), pdb.signature.c_str()).c_str();
        if ( input.empty() )
        {
            report_missing_pdb(path, pdb);
            return;
        }
        netnode pdbnode;
        pdbnode.create(PDB_NODE_NAME);
        pdbnode.altset(PDB_DLLBASE_NODE_IDX, base);
        pdbnode.supset(PDB_DLLNAME_NODE_IDX, input.c_str(), input.size() + 1);

        // 'batch' turns the plugin's error and file-locate dialogs for an
        // unmatched PDB into log lines; the miss is reported here instead.
        // A scope guard restores it: 'batch' is a global affecting all later
        // error reporting, so a return or throw must not leave it on.
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
            keep_names_only(base);
            return;
        }
        report_missing_pdb(path, pdb);
    }

    // The PDB plugin queues every function it names for analysis, which reads
    // nearly all of a library's code. Without cheap reads that freezes IDA for
    // minutes (ntdll's 600 pages at tens of milliseconds each), so the names
    // are kept and the queued work dropped. CodeAnalyzer lays out code the
    // user stops in anyway.
    void ModuleRegistry::keep_names_only(ea_t base)
    {
        if ( m_backend == nullptr || m_backend->capabilities().cheap_reads )
            return;
        const ModuleInfo *m = record_at(base);
        if ( m == nullptr || m->size == 0 )
            return;
        ea_t end = (ea_t)(base + m->size);
        static const atype_t queues[] = {
            AU_UNK, AU_CODE, AU_WEAK, AU_PROC, AU_TAIL, AU_FCHUNK, AU_USED,
            AU_USD2, AU_TYPE, AU_LIBF, AU_LBF2, AU_LBF3, AU_CHLB, AU_FINAL,
        };
        for ( atype_t q : queues )
            auto_unmark(base, end, q);
    }

    // Say which PDB is wanted and where it lives. The identity comes from the
    // recorded image's CodeView record, which a mismatched local DLL cannot
    // provide.
    void ModuleRegistry::report_missing_pdb(const std::string &path, const GuestPdbInfo &pdb)
    {
        msg("[ida-ttd] PDB symbols not resolved for %s.\n"
            "           The matching symbols are %s %s:\n"
            "           %s/%s/%s/%s\n"
            "           Save that file, then File > Load file > PDB file.\n",
            base_name(path).c_str(),
            pdb.name.c_str(), pdb.signature.c_str(), symsrv_server_url().c_str(),
            pdb.name.c_str(), pdb.signature.c_str(), pdb.name.c_str());
    }

    void ModuleRegistry::start_publics(ea_t base, const std::string &pdb_path)
    {
        // The read touches only the file, so it runs on its own thread. The
        // job is heap-allocated and freed only after its future completes, so
        // the worker's pointer stays valid.
        auto job = std::make_unique<PublicsJob>();
        job->base     = base;
        job->pdb_name = base_name(pdb_path);
        PublicsJob *j = job.get();
        std::wstring wpath = to_wstring(pdb_path.c_str());
        j->reading = std::async(std::launch::async, [j, wpath]()
        {
            return read_pdb_publics(wpath.c_str(), j->pubs, &j->error);
        });
        m_publics.push_back(std::move(job));
    }

    // Name publics from the jobs that have been read until 'deadline' (a
    // GetTickCount value) passes. False when it ran out of time with names
    // still to set.
    bool ModuleRegistry::apply_publics_slice(DWORD deadline, size_t &named)
    {
        for ( size_t i = 0; i < m_publics.size(); )
        {
            PublicsJob &j = *m_publics[i];
            if ( j.reading.valid() )
            {
                if ( j.reading.wait_for(std::chrono::seconds(0)) != std::future_status::ready )
                {
                    i++;
                    continue;               // still reading
                }
                if ( !j.reading.get() )
                {
                    // Point to the full PDB load instead (an OMAP image needs
                    // IDA's own reader, which handles the rearrangement).
                    const ModuleInfo *m = record_at(j.base);
                    msg("[ida-ttd] could not read the names in %s for %s (%s). "
                        "TTD > Annotate database > Load full symbols for this module loads it "
                        "through IDA's PDB plugin instead.\n",
                        j.pdb_name.c_str(),
                        m != nullptr ? base_name(m->path.c_str()).c_str() : "?",
                        j.error.c_str());
                    m_publics.erase(m_publics.begin() + i);
                    continue;
                }
            }

            // Names on memory without a segment are dropped, so a module not
            // mapped here waits for a stop where it is.
            if ( get_segment_ea(j.base) == BADADDR )
            {
                i++;
                continue;
            }

            // The deadline is checked every 64 names, not every one.
            while ( j.next < j.pubs.size() )
            {
                for ( size_t k = 0; k < 64 && j.next < j.pubs.size(); k++, j.next++ )
                {
                    const PdbPublic &pub = j.pubs[j.next];
                    if ( apply_export_name((ea_t)(j.base + pub.rva), pub.name.c_str()) )
                    {
                        j.named++;
                        named++;
                    }
                }
                if ( j.next < j.pubs.size() && (LONG)(GetTickCount() - deadline) >= 0 )
                    return false;
            }

            const ModuleInfo *m = record_at(j.base);
            msg("[ida-ttd] PDB names applied for %s (%s): %u name(s).\n",
                m != nullptr ? base_name(m->path.c_str()).c_str() : "?",
                j.pdb_name.c_str(), (unsigned)j.named);
            m_publics.erase(m_publics.begin() + i);
        }
        return true;
    }

    size_t ModuleRegistry::advance_pdbs(int budget_ms)
    {
        DWORD deadline = GetTickCount() + (DWORD)(budget_ms > 0 ? budget_ms : 1);

        // Finished downloads: read their names in the background.
        std::vector<FetchResult> done;
        if ( symsrv_take_completed(&done) != 0 )
        {
            for ( const FetchResult &r : done )
            {
                const ModuleInfo *m = record_at(r.base);
                std::string path = m != nullptr ? m->path.c_str() : "";
                if ( path.empty() )
                    continue;
                if ( r.path.empty() )
                {
                    // Retried once, at the next stop in the module: a server
                    // that did not answer during a burst of requests usually
                    // does a moment later.
                    const bool retry = m_pdbRetried.insert(r.base).second;
                    if ( retry )
                        m_pdbBases.erase(r.base);
                    msg("[ida-ttd] could not download %s for %s: %s.%s\n",
                        r.name.c_str(), base_name(path).c_str(), r.error.c_str(),
                        retry ? " It is asked for again at the next stop in that module." : "");
                    continue;
                }
                start_publics(r.base, r.path.c_str());
            }
        }

        size_t named = 0;
        if ( !m_publics.empty() )
        {
            DiagTimer diag_timer("PDB names");
            apply_publics_slice(deadline, named);
        }
        return named;
    }

    bool ModuleRegistry::pdbs_pending() const
    {
        return !m_publics.empty() || symsrv_pending() != 0;
    }

    bool ModuleRegistry::load_full_pdb(ea_t ea)
    {
        ea_t lo = 0, hi = 0;
        if ( m_backend == nullptr || !range_at(ea, lo, hi) )
        {
            msg("[ida-ttd] 0x%llX is in no module of this recording.\n", (uint64_t)ea);
            return false;
        }
        const ModuleInfo *m = record_at(lo);
        std::string path = m != nullptr ? m->path.c_str() : "";
        GuestPdbInfo pdb;
        if ( path.empty() || !pdb_identity(lo, &pdb) )
        {
            msg("[ida-ttd] the recording has no debug directory for the module at "
                "0x%llX, so there is no PDB to load.\n", (uint64_t)lo);
            return false;
        }
        // An explicit request asks again even if the background path already
        // did; marking the base stops that path from asking too.
        m_pdbBases.insert(lo);
        switch ( fetch_pdb(pdb.name.c_str(), pdb.signature.c_str(), lo) )
        {
            case FetchState::Cached:
            {
                qstring text;
                text.sprnt("HIDECANCEL\nLoading symbols for %s...", base_name(path).c_str());
                show_wait_box_now(text.c_str());
                apply_pdb(lo, path, pdb);
                hide_wait_box();
                return true;
            }
            case FetchState::Fetching:
                msg("[ida-ttd] %s for %s is still downloading; ask again once it is done "
                    "(its names are applied by themselves when it lands).\n",
                    pdb.name.c_str(), base_name(path).c_str());
                return false;
            case FetchState::Failed:
            default:
                report_missing_pdb(path, pdb);
                return false;
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
    const ModuleImage *ModuleRegistry::image_for(ea_t ea, Position pos, ea_t &base_out)
    {
        if ( m_backend == nullptr )
            return nullptr;

        // The load mapped at 'ea' at 'pos', by the same rule as loaded_at.
        // The module table spans the whole recording, so without the
        // position a read before a module's load or after its unload would
        // be served from its file as if it were mapped. This runs once per
        // gap of every memory read: the last match is tried first, and the
        // scan over every load (a few hundred at most) only on a miss.
        auto live = [&](const ModuleInfo &m)
        {
            return m.base != BADADDR
                && ea >= m.base && ea - m.base < (ea_t)m.size
                && (!m.loaded.is_valid() || m.loaded <= pos)
                && (!m.unloaded.is_valid() || pos < m.unloaded);
        };
        size_t li = (size_t)-1;
        if ( m_lastImageLoad < m_modules.size() && live(m_modules[m_lastImageLoad]) )
        {
            li = m_lastImageLoad;
        }
        else
        {
            for ( size_t i = 0; i < m_modules.size(); i++ )
            {
                if ( live(m_modules[i]) )
                {
                    li = i;
                    break;
                }
            }
        }
        if ( li == (size_t)-1 )
            return nullptr;
        m_lastImageLoad = li;

        const ModuleInfo *m = &m_modules[li];
        ea_t base = m->base;
        base_out = base;

        if ( m_loadImage.size() != m_modules.size() )
        {
            m_loadImage.assign(m_modules.size(), nullptr);
            m_loadImageTried.assign(m_modules.size(), 0);
        }
        if ( m_loadImageTried[li] != 0 )
            return m_loadImage[li];
        m_loadImageTried[li] = 1;

        std::string path = m->path.c_str();
        qstring key;
        key.sprnt("%s|%llX|%llX|%08X|%08X", path.c_str(), (uint64_t)base, (uint64_t)m->size,
                  m->timestamp, m->checksum);
        auto it = m_moduleImages.find(key);
        if ( it != m_moduleImages.end() )
        {
            m_loadImage[li] = it->second.ok ? &it->second : nullptr;
            return m_loadImage[li];
        }

        ModuleImage img;
        load_module_image(path.c_str(), img);   // img.ok == false on failure

        // The path was recorded on another machine, where the file may be a
        // different build (commonly another ntdll patch level) whose bytes
        // would be served as truth. So the timestamp and checksum must match
        // the recording's: the backend's, else the recorded headers'.
        uint32_t ts = m->timestamp;
        uint32_t cs = m->checksum;
        if ( img.ok && ts == 0 && cs == 0 )
        {
            GuestPeInfo pe;
            GuestRead rd = read_at_record(m);
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

        it = m_moduleImages.emplace(key, std::move(img)).first;
        m_loadImage[li] = it->second.ok ? &it->second : nullptr;
        return m_loadImage[li];
    }
}
