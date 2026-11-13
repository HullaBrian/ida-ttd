#include "analysis/memmap.h"
#include "analysis/query_runner.h"
#include "debugger/trace_manager.h"
#include "common/symbols.h"
#include "common/dbstore.h"

namespace idattd
{
    //=======================================================================
    // Page protections
    //=======================================================================
    // PAGE_* values spelled out rather than taken from <windows.h>: they are the
    // recording's ABI, not this build's headers.
    enum : uint32_t
    {
        P_NOACCESS           = 0x001,
        P_READONLY           = 0x002,
        P_READWRITE          = 0x004,
        P_WRITECOPY          = 0x008,
        P_EXECUTE            = 0x010,
        P_EXECUTE_READ       = 0x020,
        P_EXECUTE_READWRITE  = 0x040,
        P_EXECUTE_WRITECOPY  = 0x080,
        P_GUARD              = 0x100,
        P_NOCACHE            = 0x200,
        P_WRITECOMBINE       = 0x400,
        P_ACCESS_MASK        = 0x0FF,
    };

    // MEM_* states of an RC_STATE entry, likewise spelled out.
    enum : uint32_t
    {
        M_COMMIT             = 0x01000,
        M_FREE               = 0x10000,
    };

    // NtFreeVirtualMemory's FreeType, carried in an RC_FREE's 'protect'.
    enum : uint32_t
    {
        MEM_DECOMMIT_TYPE    = 0x4000,
        MEM_RELEASE_TYPE     = 0x8000,
    };

    uchar protection_perm(uint32_t protect)
    {
        uint32_t a = protect & P_ACCESS_MASK;
        uchar p = 0;
        if ( (a & (P_EXECUTE | P_EXECUTE_READ | P_EXECUTE_READWRITE | P_EXECUTE_WRITECOPY)) != 0 )
            p |= SEGPERM_EXEC;
        // PAGE_EXECUTE alone is execute-without-read, so it is in neither list
        // below.
        if ( (a & (P_READONLY | P_READWRITE | P_WRITECOPY
                 | P_EXECUTE_READ | P_EXECUTE_READWRITE | P_EXECUTE_WRITECOPY)) != 0 )
            p |= SEGPERM_READ;
        if ( (a & (P_READWRITE | P_WRITECOPY | P_EXECUTE_READWRITE | P_EXECUTE_WRITECOPY)) != 0 )
            p |= SEGPERM_WRITE;
        return p;
    }

    qstring protection_text(uint32_t protect)
    {
        uchar p = protection_perm(protect);
        qstring s;
        s.append((p & SEGPERM_READ)  != 0 ? 'R' : '-');
        s.append((p & SEGPERM_WRITE) != 0 ? 'W' : '-');
        s.append((p & SEGPERM_EXEC)  != 0 ? 'X' : '-');
        if ( (protect & P_ACCESS_MASK) == P_NOACCESS )
            s = "none";
        if ( (protect & P_GUARD) != 0 )
            s.append(" guard");
        return s;
    }

    const char *change_name(uint8_t kind)
    {
        switch ( kind )
        {
            case RC_ALLOC:     return "Allocate";
            case RC_PROTECT:   return "Protect";
            case RC_FREE:      return "Free";
            case RC_MAPVIEW:   return "Map view";
            case RC_UNMAPVIEW: return "Unmap view";
            case RC_STATE:     return "Now";
            default:           return "?";
        }
    }

    //=======================================================================
    // Folding the timeline into a region set
    //=======================================================================
    typedef std::map<ea_t, Region> LiveMap;

    // Remove [lo, hi) from the live set, keeping the parts of overlapping
    // regions outside it. This keeps the set non-overlapping and makes a
    // free-then-reallocate at one address come out right.
    static void carve(LiveMap &live, ea_t lo, ea_t hi, std::vector<Region> *removed)
    {
        if ( hi <= lo )
            return;
        // Start at the last region beginning at or before 'lo', the only one
        // before 'lo' that can reach into the range.
        LiveMap::iterator it = live.upper_bound(lo);
        if ( it != live.begin() )
            --it;

        while ( it != live.end() && it->first < hi )
        {
            Region r = it->second;
            if ( r.end() <= lo )
            {
                ++it;
                continue;
            }
            it = live.erase(it);
            if ( removed != nullptr )
                removed->push_back(r);

            if ( r.base < lo )
            {
                Region head = r;
                head.size = (uint64_t)(lo - r.base);
                live[head.base] = head;
            }
            if ( r.end() > hi )
            {
                Region tail = r;
                tail.base = hi;
                tail.size = (uint64_t)(r.end() - hi);
                live[tail.base] = tail;
            }
        }
    }

    static void apply_change(LiveMap &live, const RegionChange &c)
    {
        // A call on another process changed that process's map, not this one
        // (it stays in the listing).
        if ( c.other_process || c.base == BADADDR )
            return;

        switch ( c.kind )
        {
            case RC_ALLOC:
            case RC_MAPVIEW:
            {
                if ( c.size == 0 )
                    return;
                carve(live, c.base, (ea_t)(c.base + c.size), nullptr);
                Region r;
                r.base    = c.base;
                r.size    = c.size;
                r.protect = c.protect;
                r.origin  = c.kind;
                r.type    = c.kind == RC_MAPVIEW ? ITTD_REGION_MAPPED : ITTD_REGION_PRIVATE;
                r.since   = c.call_pos.is_valid() ? c.call_pos : c.pos;
                r.alloc   = c.base;
                live[r.base] = r;
                break;
            }

            case RC_PROTECT:
            {
                if ( c.size == 0 )
                    return;
                ea_t lo = c.base, hi = (ea_t)(c.base + c.size);
                std::vector<Region> hit;
                carve(live, lo, hi, &hit);
                if ( hit.empty() )
                {
                    // A protection change on memory no watched call allocated.
                    // Inside a module that is ordinary (the loader fixing up
                    // sections). Outside one it may be a payload whose
                    // allocation was not recovered, so it makes a region.
                    if ( c.in_module )
                        return;
                    Region r;
                    r.base    = lo;
                    r.size    = c.size;
                    r.protect = c.protect;
                    r.origin  = RC_PROTECT;
                    r.since   = c.call_pos.is_valid() ? c.call_pos : c.pos;
                    r.alloc   = lo;
                    live[r.base] = r;
                    return;
                }
                // Parts outside the range keep their protection; the part
                // inside takes the new one.
                for ( const Region &r : hit )
                {
                    if ( r.base < lo )
                    {
                        Region head = r;
                        head.size = (uint64_t)(lo - r.base);
                        live[head.base] = head;
                    }
                    if ( r.end() > hi )
                    {
                        Region tail = r;
                        tail.base = hi;
                        tail.size = (uint64_t)(r.end() - hi);
                        live[tail.base] = tail;
                    }
                    ea_t ilo = r.base > lo ? r.base : lo;
                    ea_t ihi = r.end() < hi ? r.end() : hi;
                    if ( ihi > ilo )
                    {
                        Region mid = r;
                        mid.base    = ilo;
                        mid.size    = (uint64_t)(ihi - ilo);
                        mid.protect = c.protect;
                        live[mid.base] = mid;
                    }
                }
                break;
            }

            case RC_STATE:
            {
                // The range is now what the entry says, whatever it was before.
                if ( c.size == 0 )
                    return;
                std::vector<Region> was;
                carve(live, c.base, (ea_t)(c.base + c.size), &was);
                if ( c.state == M_FREE )
                    return;
                Region r;
                r.base    = c.base;
                r.size    = c.size;
                // Reserved memory has no access at all until committed.
                r.protect = c.state == M_COMMIT ? c.protect : (uint32_t)P_NOACCESS;
                r.origin  = c.region_type == ITTD_REGION_MAPPED || c.region_type == ITTD_REGION_SECTION
                          ? RC_MAPVIEW : RC_ALLOC;
                r.type     = c.region_type;
                r.reserved = c.state != M_COMMIT;
                r.alloc    = c.alloc_base != 0 ? c.alloc_base : c.base;
                // A commit or protection change inside a region keeps the
                // position the region first appeared at.
                r.since    = c.pos;
                for ( const Region &w : was )
                    if ( w.base <= r.base && w.type == r.type && w.since.is_valid() && w.since < r.since )
                        r.since = w.since;
                live[r.base] = r;
                break;
            }

            case RC_FREE:
            case RC_UNMAPVIEW:
            {
                // A decommit leaves the range reserved, not free.
                const bool decommit = c.kind == RC_FREE && (c.protect & MEM_DECOMMIT_TYPE) != 0
                                   && (c.protect & MEM_RELEASE_TYPE) == 0;
                std::vector<Region> gone;
                if ( c.size != 0 )
                {
                    carve(live, c.base, (ea_t)(c.base + c.size), &gone);
                    // carve() keeps the parts outside the range; only the
                    // parts inside are reserved now.
                    for ( Region &g : gone )
                    {
                        ea_t lo = g.base > c.base ? g.base : c.base;
                        ea_t hi = g.end() < (ea_t)(c.base + c.size) ? g.end() : (ea_t)(c.base + c.size);
                        g.base = lo;
                        g.size = hi > lo ? (uint64_t)(hi - lo) : 0;
                    }
                }
                else
                {
                    // Size zero acts on the whole region (MEM_RELEASE, every
                    // unmap, a whole-region decommit): every piece of the
                    // allocation holding the address, which protection
                    // changes may have split.
                    LiveMap::iterator it = live.upper_bound(c.base);
                    if ( it == live.begin() )
                        return;
                    --it;
                    if ( it->second.end() <= c.base )
                        return;
                    const ea_t alloc = it->second.alloc != 0 ? it->second.alloc : it->second.base;
                    for ( it = live.lower_bound(alloc); it != live.end(); )
                    {
                        const ea_t a = it->second.alloc != 0 ? it->second.alloc : it->second.base;
                        if ( a != alloc )
                        {
                            // Pieces of one allocation are contiguous, so
                            // the first foreign region past the address ends
                            // it; one before the address is just skipped.
                            if ( it->first > c.base )
                                break;
                            ++it;
                            continue;
                        }
                        gone.push_back(it->second);
                        it = live.erase(it);
                    }
                }
                if ( decommit )
                {
                    for ( Region g : gone )
                    {
                        if ( g.size == 0 )
                            continue;
                        g.protect  = P_NOACCESS;
                        g.reserved = true;
                        live[g.base] = g;
                    }
                }
                break;
            }

            default:
                break;
        }
    }

    size_t MemoryMap::count_at(const Position &pos) const
    {
        if ( !pos.is_valid() )
            return m_changes.size();
        auto it = std::upper_bound(m_changes.begin(), m_changes.end(), pos,
                                   [](const Position &p, const RegionChange &c) { return p < c.pos; });
        return (size_t)(it - m_changes.begin());
    }

    size_t MemoryMap::checkpoint_every() const
    {
        const size_t MIN_EVERY = 256;
        const size_t MAX_CHECKPOINTS = 64;
        size_t every = m_changes.size() / MAX_CHECKPOINTS;
        return every < MIN_EVERY ? MIN_EVERY : every;
    }

    void MemoryMap::state_upto(size_t n, std::vector<Region> &out) const
    {
        out.clear();
        if ( n > m_changes.size() )
            n = m_changes.size();

        // Moving forward from the cache is the common case (a step crosses few
        // changes, if any). A change cannot be undone without knowing what it
        // displaced, so moving backward starts again from the last checkpoint
        // at or before 'n'.
        if ( !m_liveValid || n < m_liveIdx )
        {
            auto it = std::upper_bound(m_checkpoints.begin(), m_checkpoints.end(), n,
                                       [](size_t k, const std::pair<size_t, LiveMap> &c) { return k < c.first; });
            if ( it != m_checkpoints.begin() )
            {
                --it;
                m_live    = it->second;
                m_liveIdx = it->first;
            }
            else
            {
                m_live.clear();
                m_liveIdx = 0;
            }
        }

        // Every multiple of 'every' up to the last checkpoint has one (the
        // fold only ever walks forward through them), so a checkpoint is
        // added only past the last.
        const size_t every = checkpoint_every();
        while ( m_liveIdx < n )
        {
            apply_change(m_live, m_changes[m_liveIdx]);
            m_liveIdx++;
            if ( m_liveIdx % every == 0
              && (m_checkpoints.empty() || m_checkpoints.back().first < m_liveIdx) )
                m_checkpoints.emplace_back(m_liveIdx, m_live);
        }
        m_liveValid = true;

        out.reserve(m_live.size());
        for ( const auto &kv : m_live )
            out.push_back(kv.second);
    }

    void MemoryMap::drop_fold()
    {
        m_live.clear();
        m_liveIdx   = 0;
        m_liveValid = false;
        m_checkpoints.clear();
    }

    void MemoryMap::set_changes(std::vector<RegionChange> v)
    {
        m_changes = std::move(v);
        drop_fold();
        std::stable_sort(m_changes.begin(), m_changes.end(),
                         [](const RegionChange &a, const RegionChange &b)
                         { return a.pos < b.pos; });
    }

    void MemoryMap::clear()
    {
        m_changes.clear();
        drop_fold();
    }

    //=======================================================================
    // Persistence
    //=======================================================================
    static const char  MM_NODE[]  = "$ ida-ttd memmap";
    static const uchar MM_TAG     = 'M';
    static const uint32_t MM_MAGIC   = 0x50414D54;   // 'TMAP'
    // A map of any other version is rebuilt, not shown:
    // 10: the chain keeps every frame in the program and outside modules,
    //     so the listing can tell callers of one allocation helper apart.
    // 9: a Microsoft TTD change with no call chain carries its calling
    //    instruction as a one-frame chain, so a v8 map shows no caller there.
    // 8: RC_STATE entries, with their state, region type and allocation base.
    // 7: positions are stored as the core's two words, whose "no position"
    //    marker differs from the one Microsoft TTD used, so a v6 map would
    //    read an absent call position back as a real one.
    // 6: the chain keeps module boundaries rather than the innermost frames.
    // 5: the called export. 4: the call chain. 3: the call position.
    // 2: RegionChange::pc is the caller, and the stack-argument offset comes
    //    from the stack rather than being assumed, so an older map can hold a
    //    wrong Protect value.
    static const uint32_t MM_VERSION = 10;
    // A recording that allocates in a loop can produce very many changes; past
    // this cap more rows add nothing, and the blob must fit the database.
    static const size_t MM_MAX_ITEMS = 200000;

    // The blob: PluginNode's header (u32 magic, u32 version, u64 fingerprint),
    // then the changes.
    void MemoryMap::save(uint64_t fingerprint) const
    {
        PluginNode node(MM_NODE);
        if ( m_changes.empty() )
        {
            node.erase(MM_TAG);
            return;
        }

        BlobWriter w;
        size_t n = m_changes.size() < MM_MAX_ITEMS ? m_changes.size() : MM_MAX_ITEMS;
        if ( n < m_changes.size() )
        {
            msg("[ida-ttd] memory map: storing %d of %d change(s); the rest will "
                "not survive reopening the database.\n",
                (int)n, (int)m_changes.size());
        }
        w.u64((uint64_t)n);
        for ( size_t i = 0; i < n; i++ )
        {
            const RegionChange &c = m_changes[i];
            w.u64(c.pos.hi);
            w.u64(c.pos.lo);
            w.u64(c.call_pos.hi);
            w.u64(c.call_pos.lo);
            w.u32(c.tid);
            w.u64((uint64_t)c.pc);
            w.u64((uint64_t)c.api);
            w.u8(c.kind);
            w.u64((uint64_t)c.base);
            w.u64(c.size);
            w.u32(c.protect);
            w.u8((uint8_t)((c.exact ? 1 : 0) | (c.other_process ? 2 : 0) | (c.in_module ? 4 : 0)));
            uint8_t nc = c.chain_n <= RegionChange::MAX_CHAIN
                       ? c.chain_n : (uint8_t)RegionChange::MAX_CHAIN;
            w.u8(nc);
            for ( uint8_t k = 0; k < nc; k++ )
                w.u64((uint64_t)c.chain[k]);
            w.u32(c.state);
            w.u32(c.region_type);
            w.u64((uint64_t)c.alloc_base);
        }
        node.put(MM_TAG, MM_MAGIC, MM_VERSION, w, fingerprint);
    }

    bool MemoryMap::load(uint64_t fingerprint)
    {
        clear();

        // get() refuses a map built from a different recording.
        std::vector<uchar> blob;
        if ( !PluginNode(MM_NODE).get(MM_TAG, MM_MAGIC, MM_VERSION, fingerprint, &blob) )
            return false;

        BlobReader r(blob.data(), blob.size());
        bool ok = true;
        uint64_t count = r.u64();
        if ( count > MM_MAX_ITEMS )
            ok = false;

        std::vector<RegionChange> v;
        if ( ok )
        {
            v.reserve((size_t)count);
            for ( uint64_t i = 0; i < count && r.ok(); i++ )
            {
                RegionChange c;
                c.pos.hi      = r.u64();
                c.pos.lo      = r.u64();
                c.call_pos.hi = r.u64();
                c.call_pos.lo = r.u64();
                c.tid          = r.u32();
                c.pc           = (ea_t)r.u64();
                c.api          = (ea_t)r.u64();
                c.kind         = r.u8();
                c.base         = (ea_t)r.u64();
                c.size         = r.u64();
                c.protect      = r.u32();
                uint8_t f      = r.u8();
                c.exact         = (f & 1) != 0;
                c.other_process = (f & 2) != 0;
                c.in_module     = (f & 4) != 0;
                uint8_t nc      = r.u8();
                if ( nc > RegionChange::MAX_CHAIN )
                {
                    ok = false;             // corrupt: refuse the whole blob
                    break;
                }
                for ( uint8_t k = 0; k < nc && r.ok(); k++ )
                    c.chain[k] = (ea_t)r.u64();
                c.chain_n = nc;
                c.state       = r.u32();
                c.region_type = r.u32();
                c.alloc_base  = (ea_t)r.u64();
                if ( c.kind < RC_COUNT )
                    v.push_back(c);
            }
            ok = ok && r.ok();
        }

        if ( !ok )
            return false;
        // Through set_changes, which sorts by position (state_at() relies on
        // it) and resets the cache.
        set_changes(std::move(v));
        return true;
    }

    void MemoryMap::erase()
    {
        PluginNode(MM_NODE).erase(MM_TAG);
    }

    //=======================================================================
    // Building the map
    //=======================================================================
    bool build_memory_map(TraceManager *mgr, MemoryMap *out, bool *cancelled, qstring *error)
    {
        if ( out != nullptr )
            out->clear();
        if ( cancelled != nullptr )
            *cancelled = false;

        // Failures are said in 'error', never in a dialog: the caller (a UI
        // action, or a script that a dialog would hang) decides how to show
        // them.
        qstring ignored;
        if ( error == nullptr )
            error = &ignored;
        if ( mgr == nullptr || !mgr->is_active() || mgr->backend() == nullptr )
        {
            *error = "the memory map can only be built while replaying a trace";
            return false;
        }
        ITraceBackend *backend = mgr->backend();

        std::vector<ittd_mapping_change> found;
        std::vector<qstring> files;
        QueryResult qr = run_query("Building the memory map", [&](ProgressSink *p)
        {
            return backend->query_mapping_changes(&found, &files, p);
        });
        if ( !qr.ran )
        {
            *error = !mgr->is_active() || mgr->backend() != backend
                   ? "the replay session ended while the memory map was built"
                   : "the memory map could not be built for this recording (the output window has the details)";
            return false;
        }

        std::vector<RegionChange> changes;
        changes.reserve(found.size());
        for ( const ittd_mapping_change &m : found )
        {
            // Skip unknown kinds before the narrowing below could alias them.
            if ( m.kind > ITTD_MAP_STATE )
                continue;
            RegionChange c;
            c.pos      = Position{ m.pos.hi, m.pos.lo };
            c.call_pos = Position{ m.call_pos.hi, m.call_pos.lo };
            c.tid      = m.tid;
            c.api      = m.api == ITTD_BADADDR ? BADADDR : (ea_t)m.api;
            c.chain_n  = (uint8_t)std::min<uint32_t>(m.chain_n, RegionChange::MAX_CHAIN);
            for ( uint8_t k = 0; k < c.chain_n; k++ )
                c.chain[k] = m.chain[k] == ITTD_BADADDR ? BADADDR : (ea_t)m.chain[k];
            // The caller, for the listing: the innermost frame of the chain.
            c.pc       = c.chain_n > 0 ? c.chain[0] : BADADDR;
            c.kind     = m.kind == ITTD_MAP_STATE ? (uint8_t)RC_STATE : (uint8_t)m.kind;
            c.base         = (ea_t)m.base;
            c.size          = m.size;
            c.protect       = m.protect;
            c.exact         = (m.flags & ITTD_MAP_F_EXACT) != 0;
            c.other_process = (m.flags & ITTD_MAP_F_OTHER_PROCESS) != 0;
            c.in_module     = (m.flags & ITTD_MAP_F_IN_MODULE) != 0;
            c.state         = m.state;
            c.region_type   = m.region_type;
            c.alloc_base    = (ea_t)m.alloc_base;
            changes.push_back(c);
        }

        // Name what the listing shows, once per module: the stub called and
        // the code that wanted the memory. Modules are otherwise named only
        // when stopped in, which most of these never were.
        //
        // A PDB only where that code is in a library: there exports name the
        // wrong function (allocations come from internal helpers). Applying a
        // PDB blocks IDA (combase's takes a dozen seconds), so libraries the
        // chains merely pass through get exports only, for the call chain
        // column.
        {
            std::set<ea_t> exports, pdbs;
            for ( const RegionChange &c : changes )
            {
                ea_t lo = 0, hi = 0;
                if ( c.api != BADADDR && mgr->modules().range_at(c.api, lo, hi) )
                    exports.insert(lo);
                for ( uint8_t k = 0; k < c.chain_n; k++ )
                    if ( c.chain[k] != BADADDR && mgr->modules().range_at(c.chain[k], lo, hi) )
                        exports.insert(lo);
                ea_t origin = chain_origin(mgr, c);
                if ( origin != BADADDR && mgr->modules().range_at(origin, lo, hi) )
                {
                    exports.insert(lo);
                    if ( mgr->modules().is_library_address(origin) )
                        pdbs.insert(lo);
                }
            }
            if ( !exports.empty() )
            {
                show_wait_box_now("HIDECANCEL\nNaming the code the memory calls came from...");
                size_t done = 0;
                for ( ea_t b : exports )
                {
                    replace_wait_box("HIDECANCEL\nNaming the code the memory calls came from: %s (%u of %u)...",
                                     mgr->modules().name_at(b).c_str(), (unsigned)++done,
                                     (unsigned)exports.size());
                    repaint_wait_box();
                    mgr->modules().resolve_symbols(b);
                    if ( pdbs.count(b) != 0 )
                        mgr->modules().load_pdb(b);    // silent and deduplicated
                }
                hide_wait_box();
            }
        }

        if ( out != nullptr )
            out->set_changes(std::move(changes));
        if ( cancelled != nullptr )
            *cancelled = qr.cancelled;
        if ( qr.truncated )
            msg("[ida-ttd] memory map: hit the change limit; the map is incomplete.\n");
        return true;
    }

    bool session_memory_map(TraceManager *mgr, bool rebuild, bool *cancelled, qstring *error)
    {
        if ( cancelled != nullptr )
            *cancelled = false;
        if ( mgr == nullptr || !mgr->is_active() )
            return build_memory_map(mgr, nullptr, cancelled, error);    // says why
        if ( !rebuild && !mgr->memmap_for_update().empty() )
            return true;
        // Built aside, so a failure keeps the map the session had.
        MemoryMap fresh;
        bool stopped = false;
        if ( !build_memory_map(mgr, &fresh, &stopped, error) )
            return false;
        // The build pumps the UI, so the session may have ended meanwhile.
        if ( !mgr->is_active() )
        {
            if ( error != nullptr )
                *error = "the replay session ended while the memory map was built";
            return false;
        }
        if ( cancelled != nullptr )
            *cancelled = stopped;
        MemoryMap &map = mgr->memmap_for_update();
        map = std::move(fresh);
        if ( map.empty() )
            return true;
        if ( !stopped )
            map.save(mgr->trace_fingerprint());
        else
            msg("[ida-ttd] memory map: the sweep was cancelled, so the partial "
                "map is used for this session but not saved.\n");
        // The regions at the current position may be new to IDA (it had all
        // of user space as one segment, or an older map's regions).
        invalidate_dbgmem_config();
        refresh_idaview_anyway();
        return true;
    }

    ea_t chain_origin(TraceManager *mgr, const RegionChange &c)
    {
        if ( mgr == nullptr || c.chain_n == 0 )
            return BADADDR;

        // The first frame that is not library code: the analysed binary, or an
        // address in no module (code the recording allocated and ran, the case
        // that matters most in malware).
        for ( uint8_t k = 0; k < c.chain_n; k++ )
        {
            if ( c.chain[k] != BADADDR && !mgr->modules().is_library_address(c.chain[k]) )
                return c.chain[k];
        }

        // All library code: take the first frame outside the syscall caller's
        // module (for a heap allocation, the CRT's malloc rather than ntdll).
        ea_t lo0 = 0, hi0 = 0;
        if ( !mgr->modules().range_at(c.chain[0], lo0, hi0) )
            return c.chain[c.chain_n - 1];
        for ( uint8_t k = 1; k < c.chain_n; k++ )
        {
            ea_t lo = 0, hi = 0;
            if ( c.chain[k] != BADADDR
              && mgr->modules().range_at(c.chain[k], lo, hi) && lo != lo0 )
            {
                return c.chain[k];
            }
        }
        // The whole chain is in one module (a DLL allocating for itself): the
        // outermost recorded frame is the best answer.
        return c.chain[c.chain_n - 1];
    }

    uint64_t trace_fingerprint(TraceManager *mgr)
    {
        return mgr != nullptr ? mgr->trace_fingerprint() : 0;
    }
}
