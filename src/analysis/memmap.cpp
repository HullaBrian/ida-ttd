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
    // PAGE_* values, spelled out rather than taken from <windows.h>, so that what
    // is decoded here is the recording's ABI and not this build's headers.
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

    uchar protection_perm(uint32_t protect)
    {
        uint32_t a = protect & P_ACCESS_MASK;
        uchar p = 0;
        if ( (a & (P_EXECUTE | P_EXECUTE_READ | P_EXECUTE_READWRITE | P_EXECUTE_WRITECOPY)) != 0 )
            p |= SEGPERM_EXEC;
        // PAGE_EXECUTE alone is execute-without-read, which is why it is absent
        // from both lists below.
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

    // Remove [lo, hi) from the live set, keeping whatever of each overlapping
    // region falls outside it. This is what makes a free-then-reallocate at the
    // same address come out right, and it is why the region set can never
    // contain two regions that overlap.
    static void carve(LiveMap &live, ea_t lo, ea_t hi, std::vector<Region> *removed)
    {
        if ( hi <= lo )
            return;
        // Start at the last region beginning at or before 'lo': it is the only
        // one before 'lo' that can reach into the range.
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
        // A call that targeted another process changed that process's map, not
        // this one. It stays in the listing, where seeing it is the point.
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
                    // A protection change on memory no watched call ever
                    // allocated. Inside a module that is ordinary (a loader
                    // fixing up its own sections) and the module already has
                    // segments of its own. Outside one it is the interesting
                    // case -- a payload whose allocation was not recovered --
                    // so it stands up a region rather than being lost.
                    if ( c.in_module )
                        return;
                    Region r;
                    r.base    = lo;
                    r.size    = c.size;
                    r.protect = c.protect;
                    r.origin  = RC_PROTECT;
                    r.since   = c.call_pos.is_valid() ? c.call_pos : c.pos;
                    live[r.base] = r;
                    return;
                }
                // Put back the parts outside the changed range with the
                // protection they had, and the part inside with the new one.
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
                if ( c.size != 0 )
                {
                    carve(live, c.base, (ea_t)(c.base + c.size), nullptr);
                    return;
                }
                // A size of zero means "release the whole thing", which is what
                // MEM_RELEASE and every unmap do. Drop the region containing the
                // address rather than guessing an extent.
                LiveMap::iterator it = live.upper_bound(c.base);
                if ( it == live.begin() )
                    return;
                --it;
                if ( it->second.end() > c.base )
                    live.erase(it);
                break;
            }

            default:
                break;
        }
    }

    void MemoryMap::state_at(const Position &pos, std::vector<Region> &out) const
    {
        out.clear();

        // Replaying forward from where the cache already stands is the common
        // case by far -- stepping crosses a handful of changes, if any. Only a
        // jump backward has to start over, because a change cannot be undone
        // without knowing what it displaced.
        // An invalid position on either side means "the whole timeline", which
        // sorts after every real one -- so it can be reached from anywhere, and
        // nothing can be reached from it.
        bool backward = pos.is_valid() && (!m_livePos.is_valid() || pos < m_livePos);
        if ( !m_liveValid || backward )
        {
            m_live.clear();
            m_liveIdx = 0;
        }

        while ( m_liveIdx < m_changes.size() )
        {
            const RegionChange &c = m_changes[m_liveIdx];
            if ( pos.is_valid() && c.pos > pos )
                break;
            apply_change(m_live, c);
            m_liveIdx++;
        }
        m_livePos   = pos;
        m_liveValid = true;

        out.reserve(m_live.size());
        for ( const auto &kv : m_live )
            out.push_back(kv.second);
    }

    void MemoryMap::set_changes(std::vector<RegionChange> v)
    {
        m_changes = std::move(v);
        m_live.clear();
        m_liveIdx   = 0;
        m_liveValid = false;
        std::stable_sort(m_changes.begin(), m_changes.end(),
                         [](const RegionChange &a, const RegionChange &b)
                         { return a.pos < b.pos; });
    }

    void MemoryMap::clear()
    {
        m_changes.clear();
        m_live.clear();
        m_liveIdx   = 0;
        m_liveValid = false;
    }

    //=======================================================================
    // Persistence
    //=======================================================================
    static const char  MM_NODE[]  = "$ ida-ttd memmap";
    static const uchar MM_TAG     = 'M';
    static const uint32_t MM_MAGIC   = 0x50414D54;   // 'TMAP'
    // A map of any other version is rebuilt rather than shown:
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
    static const uint32_t MM_VERSION = 9;
    // A recording that allocates in a loop can produce a great many changes.
    // Past this there is nothing left to learn from another row, and the blob
    // has to fit in the database.
    static const size_t MM_MAX_ITEMS = 200000;

    // The blob is the header PluginNode writes (u32 magic, u32 version, u64
    // trace fingerprint) followed by the changes.
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

        // A map built from a different recording would show addresses and
        // positions that mean nothing here. get() refuses it rather than
        // mislead.
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
        // Through set_changes so the sort and the cache reset cannot diverge:
        // state_at() walks m_changes assuming it is ordered by position.
        set_changes(std::move(v));
        return true;
    }

    void MemoryMap::erase()
    {
        PluginNode(MM_NODE).erase(MM_TAG);
    }

    bool MemoryMap::stored()
    {
        // Any fingerprint: this only asks whether a map of this version is
        // there at all.
        std::vector<uchar> blob;
        return PluginNode(MM_NODE).get(MM_TAG, MM_MAGIC, MM_VERSION, 0, &blob);
    }

    //=======================================================================
    // Building the map
    //=======================================================================
    bool build_memory_map(TraceManager *mgr, MemoryMap *out, bool *cancelled)
    {
        if ( out != nullptr )
            out->clear();
        if ( cancelled != nullptr )
            *cancelled = false;

        if ( mgr == nullptr || !mgr->is_active() || mgr->backend() == nullptr )
        {
            warning("The memory map can only be built while replaying a trace.");
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
            warning("The memory map could not be built for this recording.\n\n"
                    "For a Microsoft TTD trace this happens when ntdll's export "
                    "table was never read during recording; for another kind of "
                    "recording, its backend may not record the memory map. The "
                    "output window has the details.");
            return false;
        }

        std::vector<RegionChange> changes;
        changes.reserve(found.size());
        for ( const ittd_mapping_change &m : found )
        {
            // A kind this build does not know, checked before the narrowing
            // below could fold it onto one it does.
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

        // Name what the listing shows, once per module: the routine called
        // (an ntdll stub, which its exports name) and the code that wanted
        // the memory. The plugin names a module when you stop inside it, and
        // you have never stopped in most of these.
        //
        // A PDB only where that code is in a library. There exports alone
        // name the wrong function -- the code that allocates is usually an
        // internal helper -- but applying one blocks IDA for as long as it
        // takes (combase's, a dozen seconds), so the libraries the chains
        // merely pass through get none.
        {
            std::set<ea_t> exports, pdbs;
            for ( const RegionChange &c : changes )
            {
                ea_t lo = 0, hi = 0;
                if ( c.api != BADADDR && mgr->modules().range_at(c.api, lo, hi) )
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

    ea_t chain_origin(TraceManager *mgr, const RegionChange &c)
    {
        if ( mgr == nullptr || c.chain_n == 0 )
            return BADADDR;

        // The frame worth naming is the first one that is not library code:
        // either the analysed binary, or -- the case that matters most when
        // reading a recording of malware -- an address in no module at all,
        // which is code the recording allocated and ran.
        for ( uint8_t k = 0; k < c.chain_n; k++ )
        {
            if ( c.chain[k] != BADADDR && !mgr->modules().is_library_address(c.chain[k]) )
                return c.chain[k];
        }

        // Everything is library code. Then the useful frame is the first one
        // that left the module the syscall's own caller sits in: for a heap
        // allocation that is the CRT's malloc rather than ntdll's internals.
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
        // The whole chain lived in one module -- an allocation a DLL made
        // entirely for itself. The outermost frame recorded is the most that
        // can be said, and saying it beats leaving the column empty.
        return c.chain[c.chain_n - 1];
    }

    uint64_t trace_fingerprint(TraceManager *mgr)
    {
        return mgr != nullptr ? mgr->trace_fingerprint() : 0;
    }
}
