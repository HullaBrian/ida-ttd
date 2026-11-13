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

    // A path under the Windows directory, as the recording machine wrote it:
    // "C:\Windows\System32\ntdll.dll", "\SystemRoot\...", with or without a
    // "\??\" or "\\?\" prefix. Such a module is the OS's own, never packed.
    static bool is_system_path(const char *path)
    {
        if ( path == nullptr )
            return false;
        std::string p = path;
        for ( char &c : p )
            c = (char)tolower((unsigned char)c);
        if ( p.rfind("\\??\\", 0) == 0 || p.rfind("\\\\?\\", 0) == 0 )
            p.erase(0, 4);
        if ( p.rfind("\\systemroot\\", 0) == 0 )
            return true;
        return p.size() > 3 && p[1] == ':' && p.compare(2, 9, "\\windows\\") == 0;
    }

    // A fingerprint of a module's exception table as it stands where 'rd'
    // reads: the directory entry and the table's first and last 4 KiB. A
    // packer writes the real table whole when it unpacks, so this changes
    // when it does, at three small reads rather than the whole table. Zero
    // when the headers cannot be read.
    static uint64_t table_stamp(const GuestRead &rd, ea_t base, bool is64)
    {
        if ( !rd || base == BADADDR || !is64 )
            return 0;
        const uint64_t b = (uint64_t)base;
        IMAGE_DOS_HEADER dos{};
        if ( !pe_read_val(rd, b, &dos) || dos.e_magic != IMAGE_DOS_SIGNATURE
          || dos.e_lfanew < 0 || (uint32_t)dos.e_lfanew > 0x10000000u )
            return 0;
        IMAGE_NT_HEADERS64 nt{};
        if ( !pe_read_val(rd, b + (uint32_t)dos.e_lfanew, &nt) || nt.Signature != IMAGE_NT_SIGNATURE
          || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC
          || nt.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXCEPTION )
            return 0;
        const IMAGE_DATA_DIRECTORY &dd = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

        uint64_t h = 1469598103934665603ULL;
        auto mix = [&](const uint8_t *p, size_t n)
        {
            for ( size_t i = 0; i < n; i++ )
            {
                h ^= p[i];
                h *= 1099511628211ULL;
            }
        };
        mix((const uint8_t *)&dd, sizeof(dd));
        const size_t PIECE = 4096;
        uint8_t buf[PIECE];
        if ( dd.VirtualAddress != 0 && dd.Size != 0 )
        {
            size_t n = dd.Size < PIECE ? dd.Size : PIECE;
            mix(buf, rd(b + dd.VirtualAddress, buf, n));
            if ( dd.Size > PIECE )
                mix(buf, rd(b + dd.VirtualAddress + dd.Size - PIECE, buf, PIECE));
        }
        return h | 1;   // a readable table is never zero
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
        m_names.resize(m_modules.size());

        // One span per distinct base, over every load there; std::map keeps
        // them sorted.
        std::map<ea_t, Span> spans;
        for ( size_t li = 0; li < m_modules.size(); li++ )
        {
            const ModuleInfo &m = m_modules[li];
            std::string bn = base_name(m.path.empty() ? m.name.c_str() : m.path.c_str());
            LoadNames &ln = m_names[li];
            ln.file = bn.c_str();
            // The display name drops the extension, the way a debugger writes
            // "kernel32!Foo".
            std::string disp = bn;
            size_t dot = disp.rfind('.');
            if ( dot != std::string::npos && dot != 0 )
                disp.resize(dot);
            ln.name = disp.c_str();
            if ( m.base == BADADDR )
                continue;

            Span &s = spans[m.base];
            if ( s.loads.empty() )
            {
                s.base = m.base;
                s.file = ln.file;
                s.name = ln.name;
                // The segment identifier keeps the extension ("kernel32_dll"
                // says more than "kernel32"); anything not legal in an IDA
                // name becomes an underscore.
                std::string ident = bn;
                for ( char &c : ident )
                    if ( !qisalnum(c) && c != '_' )
                        c = '_';
                s.ident = ident.c_str();
            }
            ea_t end = m.base + (ea_t)m.size;
            if ( end > s.end )
                s.end = end;
            s.loads.push_back(li);
        }
        ea_t reach = 0;
        for ( auto &kv : spans )
        {
            reach = std::max(reach, kv.second.end);
            m_spanReach.push_back(reach);
            m_spans.push_back(std::move(kv.second));
        }

        // The analysed binary: the module the recording names as its main
        // one, else the first loaded.
        const char *main = m_backend->info().main_module.c_str();
        for ( size_t li = 0; li < m_modules.size() && main[0] != '\0'; li++ )
            if ( _stricmp(m_modules[li].name.c_str(), main) == 0 )
            {
                m_mainLoad = li;
                break;
            }
        if ( m_mainLoad == NONE && !m_modules.empty() )
            m_mainLoad = 0;
    }

    void ModuleRegistry::reset()
    {
        m_symCursor.reset();
        m_symAt   = Position::none();
        m_backend = nullptr;
        m_now     = Position::none();
        m_modules.clear();
        m_names.clear();
        m_spans.clear();
        m_spanReach.clear();
        m_mainLoad = NONE;
        m_namedBy.clear();
        m_pdbBases.clear();
        m_pdbRetried.clear();
        // Waits for any read still running (std::async futures join); a read
        // takes milliseconds.
        m_publics.clear();
        m_lastImageLoad = NONE;
        m_images.clear();
        m_targetName.clear();
    }

    //=======================================================================
    // The spans
    //=======================================================================
    size_t ModuleRegistry::index_at(ea_t ea) const
    {
        // From the last span whose base <= ea down, while an earlier span can
        // still reach ea: a span inside a larger, earlier one does not hide
        // the larger one's addresses past its own end.
        auto it = std::upper_bound(m_spans.begin(), m_spans.end(), ea,
                                   [](ea_t a, const Span &s) { return a < s.base; });
        for ( size_t i = (size_t)(it - m_spans.begin()); i-- > 0; )
        {
            if ( m_spanReach[i] <= ea )
                break;
            if ( ea < m_spans[i].end )
                return i;
        }
        return NONE;
    }

    bool ModuleRegistry::range_at(ea_t ea, ea_t &lo, ea_t &hi) const
    {
        size_t idx = index_at(ea);
        if ( idx == NONE )
            return false;
        lo = m_spans[idx].base;
        hi = m_spans[idx].end;
        return true;
    }

    qstring ModuleRegistry::ident_at(ea_t ea) const
    {
        size_t idx = index_at(ea);
        return idx == NONE ? qstring() : m_spans[idx].ident;
    }

    std::vector<std::pair<ea_t, ea_t>> ModuleRegistry::ranges() const
    {
        std::vector<std::pair<ea_t, ea_t>> out;
        for ( const Span &s : m_spans )
            out.push_back({ s.base, s.end });
        return out;
    }

    //=======================================================================
    // Loads
    //=======================================================================
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

    // Load 'li' is mapped over 'ea' at 'pos'. The rule loaded_at uses.
    bool ModuleRegistry::live(size_t li, ea_t ea, Position pos) const
    {
        const ModuleInfo &m = m_modules[li];
        return m.base != BADADDR
            && ea >= m.base && ea - m.base < (ea_t)m.size
            && (!m.loaded.is_valid() || m.loaded <= pos)
            && (!m.unloaded.is_valid() || pos < m.unloaded);
    }

    size_t ModuleRegistry::load_index_at(ea_t ea, Position pos) const
    {
        if ( !pos.is_valid() )
            return NONE;
        // The spans that hold 'ea', innermost first (see index_at), and in
        // each the load mapped at 'pos'.
        auto it = std::upper_bound(m_spans.begin(), m_spans.end(), ea,
                                   [](ea_t a, const Span &s) { return a < s.base; });
        for ( size_t i = (size_t)(it - m_spans.begin()); i-- > 0; )
        {
            if ( m_spanReach[i] <= ea )
                break;
            const Span &s = m_spans[i];
            if ( ea >= s.end )
                continue;
            for ( size_t li : s.loads )
                if ( live(li, ea, pos) )
                    return li;
        }
        return NONE;
    }

    // The load mapped at 'ea' at 'pos', else the first load at the span
    // holding 'ea' that covers it: an address the user looks at where its
    // module is not mapped (before its load) still belongs to it.
    size_t ModuleRegistry::load_for(ea_t ea, Position pos) const
    {
        size_t li = load_index_at(ea, pos);
        if ( li != NONE )
            return li;
        size_t idx = index_at(ea);
        if ( idx == NONE )
            return NONE;
        for ( size_t k : m_spans[idx].loads )
            if ( ea - m_modules[k].base < (ea_t)m_modules[k].size )
                return k;
        return m_spans[idx].loads.front();
    }

    const ModuleInfo *ModuleRegistry::load_at(ea_t ea, Position pos) const
    {
        size_t li = load_index_at(ea, pos);
        return li == NONE ? nullptr : &m_modules[li];
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

    size_t ModuleRegistry::record_index(ea_t base) const
    {
        if ( base == BADADDR )
            return NONE;
        auto it = std::lower_bound(m_spans.begin(), m_spans.end(), base,
                                   [](const Span &s, ea_t b) { return s.base < b; });
        if ( it == m_spans.end() || it->base != base )
            return NONE;
        for ( size_t li : it->loads )
            if ( m_now.is_valid() && live(li, base, m_now) )
                return li;
        return it->loads.front();
    }

    const ModuleInfo *ModuleRegistry::record_at(ea_t base) const
    {
        size_t li = record_index(base);
        return li == NONE ? nullptr : &m_modules[li];
    }

    const ModuleInfo *ModuleRegistry::main_module() const
    {
        return m_mainLoad == NONE ? nullptr : &m_modules[m_mainLoad];
    }

    bool ModuleRegistry::is_main_load(size_t li) const
    {
        if ( li == m_mainLoad )
            return true;
        if ( m_mainLoad == NONE || li == NONE )
            return false;
        // The analysed binary unloaded and loaded again at its base.
        const ModuleInfo &a = m_modules[li];
        const ModuleInfo &m = m_modules[m_mainLoad];
        return a.base == m.base && _stricmp(a.path.c_str(), m.path.c_str()) == 0;
    }

    qstring ModuleRegistry::name_at(ea_t ea, Position pos) const
    {
        size_t li = load_for(ea, pos);
        return li == NONE ? qstring() : m_names[li].name;
    }

    bool ModuleRegistry::is_library_address(ea_t ea) const
    {
        size_t li = load_for(ea, m_now);
        return li != NONE && !is_main_load(li);
    }

    //=======================================================================
    // Images
    //=======================================================================
    ModuleRegistry::Image &ModuleRegistry::image_of(size_t li)
    {
        LoadNames &ln = m_names[li];
        if ( ln.image != nullptr )
            return *ln.image;
        const ModuleInfo &m = m_modules[li];

        // The backend's timestamp and checksum, else the recorded headers'.
        uint32_t ts = m.timestamp;
        uint32_t cs = m.checksum;
        if ( ts == 0 && cs == 0 )
        {
            GuestPeInfo pe;
            GuestRead rd = read_at_record(li);
            if ( rd && read_guest_pe_info(rd, m.base, &pe) )
            {
                ts = pe.timestamp;
                cs = pe.checksum;
            }
        }
        ln.timestamp = ts;
        ln.checksum  = cs;

        // Paths compare without case, as Windows does. An image with no
        // identity at all is shared only by loads at the same base, which
        // is what every cache was keyed by before.
        std::string path = m.path.empty() ? m.name.c_str() : m.path.c_str();
        for ( char &c : path )
            c = (char)tolower((unsigned char)c);
        qstring key;
        if ( ts == 0 && cs == 0 )
            key.sprnt("%s|%llX|@%llX", path.c_str(), (uint64_t)m.size, (uint64_t)m.base);
        else
            key.sprnt("%s|%llX|%08X|%08X", path.c_str(), (uint64_t)m.size, ts, cs);
        Image &img = m_images[key];
        img.system = is_system_path(m.path.c_str());
        ln.image = &img;
        return img;
    }

    const std::vector<std::pair<ea_t, std::string>> &ModuleRegistry::exports_of(size_t li)
    {
        Image &img = image_of(li);
        if ( img.exports_read )
            return img.exports;
        img.exports_read = true;
        const ModuleInfo &m = m_modules[li];
        std::vector<std::pair<ea_t, std::string>> v;
        if ( m_backend->capabilities().recorded_exports )
        {
            for ( const ITraceBackend::Symbol &s : m_backend->module_symbols(m.base) )
                if ( s.is_export )
                    v.emplace_back(s.ea, s.name.c_str());
        }
        else
        {
            const uint32_t MACHINE_AMD64 = 0x8664;    // IMAGE_FILE_MACHINE_AMD64
            bool is64 = m.machine != 0 ? m.machine == MACHINE_AMD64 : m_is64;
            GuestRead rd = read_at_record(li);
            if ( rd )
                read_guest_exports(rd, m.base, is64, &v);
        }
        // Kept as RVAs, so another load of the image at another base shares
        // them; wrapping arithmetic keeps even an address below the base
        // exact.
        for ( auto &e : v )
            e.first -= m.base;
        // export_name_at looks names up by address once per decoded call.
        std::stable_sort(v.begin(), v.end(),
                         [](const std::pair<ea_t, std::string> &a, const std::pair<ea_t, std::string> &b)
                         { return a.first < b.first; });
        img.exports = std::move(v);
        return img.exports;
    }

    // Function bounds, so a whole function (including code before the PC) can
    // be laid out: from the backend if it knows them, else the module's
    // .pdata, read from the on-disk file when it is the recorded build
    // (complete), otherwise from recorded memory (right, sometimes
    // incomplete). Once per image.
    void ModuleRegistry::function_ranges(size_t li)
    {
        Image &img = image_of(li);
        if ( img.funcs_tried )
            return;
        img.funcs_tried = true;
        DiagTimer diag_timer("function ranges");
        const ModuleInfo &m = m_modules[li];
        const ea_t base = m.base;
        std::vector<std::pair<ea_t, ea_t>> franges = m_backend->module_functions(base);
        if ( franges.empty() )
            parse_pdata_functions_from_file(m.path.c_str(), base, m_is64,
                                            m_names[li].timestamp, m_names[li].checksum, franges);
        if ( franges.empty() )
        {
            img.funcs_from_memory = true;
            GuestRead rd = read_at_record(li);
            if ( rd )
            {
                parse_pdata_functions(rd, base, m_is64, franges);
                img.table_stamp = table_stamp(rd, base, m_is64);
            }
        }
        for ( auto &f : franges )
        {
            f.first  -= base;
            f.second -= base;
        }
        std::sort(franges.begin(), franges.end());
        img.funcs = std::move(franges);
    }

    bool ModuleRegistry::function_range_at(ea_t pc, Position pos, ea_t &start, ea_t &end) const
    {
        size_t li = load_for(pc, pos);
        if ( li == NONE )
            return false;
        // Worked out on first use when the backend's reads are not cheap.
        ModuleRegistry *self = const_cast<ModuleRegistry *>(this);
        self->function_ranges(li);
        const std::vector<std::pair<ea_t, ea_t>> &v = m_names[li].image->funcs;
        const ea_t base = m_modules[li].base;
        const ea_t rva  = pc - base;

        // Last range whose start <= rva, then verify rva is within it.
        auto up = std::upper_bound(v.begin(), v.end(), std::make_pair(rva, (ea_t)BADADDR));
        if ( up == v.begin() )
            return false;
        --up;
        if ( rva >= up->first && rva < up->second )
        {
            start = base + up->first;
            end   = base + up->second;
            return true;
        }
        return false;
    }

    bool ModuleRegistry::has_function_table(ea_t ea) const
    {
        size_t li = load_for(ea, m_now);
        if ( li == NONE )
            return false;
        ModuleRegistry *self = const_cast<ModuleRegistry *>(this);
        self->function_ranges(li);
        return !m_names[li].image->funcs.empty();
    }

    bool ModuleRegistry::refresh_function_ranges(ea_t pc, ITraceCursor *now)
    {
        if ( now == nullptr )
            return false;
        const Position pos = now->position();
        ea_t s, e;
        size_t li = load_for(pc, pos);
        if ( li == NONE || function_range_at(pc, pos, s, e) )
            return false;
        Image &img = *m_names[li].image;     // function_range_at identified it
        if ( !img.funcs_from_memory || img.system )
            return false;
        const ea_t base = m_modules[li].base;
        GuestRead rd = guest_read(now);
        // A leaf function misses on every stop in it: the table is parsed
        // again only once its bytes have changed.
        uint64_t stamp = table_stamp(rd, base, m_is64);
        if ( stamp == img.table_stamp )
            return false;
        img.table_stamp = stamp;
        std::vector<std::pair<ea_t, ea_t>> v;
        if ( parse_pdata_functions(rd, base, m_is64, v) == 0 )
            return false;
        for ( auto &f : v )
        {
            f.first  -= base;
            f.second -= base;
        }
        std::sort(v.begin(), v.end());
        if ( v == img.funcs )
            return false;
        img.funcs = std::move(v);
        msg("[ida-ttd] %s: its exception table changed after it loaded (unpacked code): "
            "%u function range(s) now.\n", m_names[li].file.c_str(), (unsigned)img.funcs.size());
        return true;
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

        // The table holds each name with and without its extension, so this
        // is two compares.
        auto module_matches = [&](size_t li)
        {
            return modpat.empty()
                || wildcard_match(modpat.c_str(), m_names[li].file.c_str())
                || wildcard_match(modpat.c_str(), m_names[li].name.c_str());
        };

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
                size_t li = load_for(ea, m_now);
                if ( li == NONE || !module_matches(li) )
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
        // the export directory read where it loaded. Once per image at each
        // base it took.
        ModuleRegistry *self = const_cast<ModuleRegistry *>(this);
        std::set<std::pair<ea_t, const Image *>> done;
        for ( size_t li = 0; li < m_modules.size(); li++ )
        {
            const ea_t base = m_modules[li].base;
            if ( base == BADADDR || !module_matches(li)
              || !done.insert({ base, &self->image_of(li) }).second )
                continue;
            for ( const auto &e : self->exports_of(li) )
                if ( wildcard_match(namepat.c_str(), e.second.c_str()) && seen.insert(base + e.first).second )
                    out.push_back(base + e.first);
        }
        return out;
    }

    qstring ModuleRegistry::export_name_at(ea_t ea, Position pos)
    {
        size_t li = load_for(ea, pos);
        if ( li == NONE )
            return qstring();
        // Stable-sorted by RVA, so of several names at 'ea' this is the first
        // the module lists.
        const std::vector<std::pair<ea_t, std::string>> &v = exports_of(li);
        const ea_t rva = ea - m_modules[li].base;
        auto it = std::lower_bound(v.begin(), v.end(), rva,
                                   [](const std::pair<ea_t, std::string> &e, ea_t a) { return e.first < a; });
        if ( it == v.end() || it->first != rva )
            return qstring();
        qstring out;
        out.sprnt("%s!%s", m_names[li].name.c_str(), it->second.c_str());
        return out;
    }

    //=======================================================================
    // Naming
    //=======================================================================
    GuestRead ModuleRegistry::read_at_record(size_t li)
    {
        if ( m_backend == nullptr )
            return GuestRead{};
        if ( !m_symCursor )
            m_symCursor = m_backend->make_cursor();
        if ( !m_symCursor )
            return GuestRead{};
        const Position at = li != NONE && m_modules[li].loaded.is_valid()
                          ? m_modules[li].loaded : m_backend->info().first;
        // A seek is dear on some backends (Microsoft TTD: about 15 ms), and a
        // load's headers, exports and table are read one after another.
        if ( at != m_symAt )
            m_symAt = m_symCursor->seek(at) ? at : Position::none();
        return guest_read(m_symCursor.get());
    }

    void ModuleRegistry::resolve_symbols(ea_t base)
    {
        size_t li = record_index(base);
        if ( li != NONE )
            resolve_load(li);
    }

    // Take the names of the image that held 'base' off its exports, where
    // they are still what it set: another image now holds the base, and its
    // own names cannot replace ones that are there (apply_export_name).
    void ModuleRegistry::unname_exports(ea_t base, const Image &img)
    {
        size_t removed = 0;
        for ( const auto &e : img.exports )
        {
            const ea_t ea = base + e.first;
            qstring cur;
            if ( get_name(&cur, ea) > 0 && cur == e.second.c_str() && set_name(ea, "", SN_NOWARN) )
                removed++;
        }
        diag("module symbols: %u name(s) of the image unloaded at 0x%llX removed",
             (unsigned)removed, (uint64_t)base);
    }

    void ModuleRegistry::resolve_load(size_t li)
    {
        // Called per mapped module on every stop, so a module already done
        // returns before any logging.
        const ModuleInfo &m = m_modules[li];
        const ea_t base = m.base;
        if ( m_backend == nullptr || base == BADADDR )
            return;
        auto named = m_namedBy.find(base);
        if ( named != m_namedBy.end() && named->second == m_names[li].image )
            return;
        // Not before the module has a segment: names on memory IDA lacks are
        // dropped, and marking the module done would leave it unnamed for the
        // session. The next stop tries again (resolve_loaded).
        if ( get_segment_ea(base) == BADADDR )
            return;
        Image &img = image_of(li);
        if ( named != m_namedBy.end() && named->second == &img )
            return;

        qstring what;
        what.sprnt("%a", base);
        diag("module symbols begin %s", what.c_str());
        DiagTimer diag_timer("module symbols", what);

        // Another image named this base before (a DLL unloaded, another
        // mapped there): its names go, and the new one's PDB may be asked for.
        if ( named != m_namedBy.end() )
        {
            msg("[ida-ttd] %s now holds 0x%llX; naming it in place of the module that held it before.\n",
                m_names[li].file.c_str(), (uint64_t)base);
            unname_exports(base, *named->second);
            m_pdbBases.erase(base);
            m_pdbRetried.erase(base);
        }
        m_namedBy[base] = &img;

        // Names: the recording's export list when the backend keeps one, else
        // the image's export directory read where it is mapped.
        size_t nnamed = 0;
        for ( const auto &e : exports_of(li) )
            if ( apply_export_name(base + e.first, e.second.c_str()) )
                nnamed++;

        // Function bounds: now when reads are cheap, else when a stop first
        // asks (function_range_at), since they can mean reading the whole
        // .pdata out of the recording.
        const bool cheap = m_backend->capabilities().cheap_reads;
        if ( cheap )
            function_ranges(li);

        msg("[ida-ttd] %s @ 0x%llX: %u export(s)%s\n",
            m_names[li].file.c_str(), (uint64_t)base, (unsigned)nnamed,
            cheap ? qstring().sprnt(", %u function range(s)", (unsigned)img.funcs.size()).c_str() : "");
    }

    void ModuleRegistry::resolve_loaded(Position pos)
    {
        for ( size_t li = 0; li < m_modules.size(); li++ )
        {
            const ModuleInfo &m = m_modules[li];
            bool after_load = !m.loaded.is_valid() || m.loaded <= pos;
            bool before_unload = !m.unloaded.is_valid() || pos < m.unloaded;
            if ( after_load && before_unload )
                resolve_load(li);
        }
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
        // lookup would be redundant and possibly networked. Matched by load,
        // which is authoritative.
        const size_t li = record_index(base);
        if ( li == NONE || is_main_load(li) )
            return;

        if ( !m_pdbBases.insert(base).second )
            return;     // already requested for this module

        std::string path = m_modules[li].path.c_str();
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
        const size_t li = m_backend != nullptr ? load_for(ea, m_now) : NONE;
        if ( li == NONE )
        {
            msg("[ida-ttd] 0x%llX is in no module of this recording.\n", (uint64_t)ea);
            return false;
        }
        const ea_t lo = m_modules[li].base;
        std::string path = m_modules[li].path.c_str();
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

        // The load mapped at 'ea' at 'pos'. The spans cover the whole
        // recording, so without the position a read before a module's load or
        // after its unload would be served from its file as if it were
        // mapped. This runs once per gap of every memory read: the last match
        // is tried first.
        size_t li = NONE;
        if ( m_lastImageLoad != NONE && live(m_lastImageLoad, ea, pos) )
            li = m_lastImageLoad;
        else
            li = load_index_at(ea, pos);
        if ( li == NONE )
            return nullptr;
        m_lastImageLoad = li;

        const ModuleInfo &m = m_modules[li];
        base_out = m.base;
        Image &img = image_of(li);
        if ( img.file_tried )
            return img.file.ok ? &img.file : nullptr;
        img.file_tried = true;

        std::string path = m.path.c_str();
        ModuleImage file;
        load_module_image(path.c_str(), file);   // file.ok == false on failure

        // The path was recorded on another machine, where the file may be a
        // different build (commonly another ntdll patch level) whose bytes
        // would be served as truth. So the timestamp and checksum must match
        // the recording's: the backend's, else the recorded headers'
        // (image_of worked out which).
        const uint32_t ts = m_names[li].timestamp;
        const uint32_t cs = m_names[li].checksum;
        bool mismatch = file.ok
                     && ((ts != 0 && file.timestamp != 0 && file.timestamp != ts)
                      || (cs != 0 && file.checksum != 0 && file.checksum != cs));
        if ( mismatch )
        {
            msg("[ida-ttd] image fallback for %s @ 0x%llX: rejected, the on-disk "
                "file is a different build (trace %08X/%08X, file %08X/%08X).\n",
                base_name(path).c_str(), (uint64_t)m.base, ts, cs, file.timestamp, file.checksum);
            file = ModuleImage{};     // ok == false: never consulted again
        }
        else
        {
            msg("[ida-ttd] image fallback for %s @ 0x%llX: %s\n",
                base_name(path).c_str(), (uint64_t)m.base,
                file.ok ? "loaded" : "file unavailable / not a PE");
        }
        img.file = std::move(file);
        return img.file.ok ? &img.file : nullptr;
    }
}
