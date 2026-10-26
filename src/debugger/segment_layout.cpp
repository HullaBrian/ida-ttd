#include "debugger/segment_layout.h"

namespace idattd
{
    void SegmentLayout::bind(ModuleRegistry *modules, bool is64)
    {
        reset();
        m_modules = modules;
        m_is64    = is64;
    }

    void SegmentLayout::reset()
    {
        m_modules = nullptr;
        m_map.clear();
        m_lastLayout.qclear();
        m_haveLayout = false;
        m_foldLayout.qclear();
        m_foldValid  = false;
        m_foldConst  = false;
    }

    const meminfo_vec_t &SegmentLayout::build(Position now) const
    {
        // Start above the low 64 KiB, which Windows never maps. Otherwise IDA
        // treats small integers as pointers and dereferences them recursively
        // in the register and stack views.
        const ea_t  LO   = 0x10000;
        const ea_t  HI   = m_is64 ? (ea_t)0x7FFFFFFFFFFFull : (ea_t)0xFFFFFFFFull;
        const uchar BITS = m_is64 ? 2 : 1;

        if ( m_foldValid && (m_foldConst || now == m_foldPos) )
            return m_foldLayout;

        meminfo_vec_t *out = &m_foldLayout;
        out->qclear();
        m_foldValid = false;

        // Named pieces of the address space, gathered first so they can be
        // sorted and the gaps filled in one pass.
        struct Named
        {
            ea_t    lo = 0, hi = 0;
            qstring name;
            qstring sclass;
            uchar   perm = 0;
            bool operator<(const Named &o) const { return lo < o.lo; }
        };
        std::vector<Named> named;

        // ---- the regions the recording built ------------------------------
        //
        // A region starting inside a module is skipped: splitting the module's
        // segment would make IDA rebuild it and discard its code. The map's
        // value is the memory no module covers, where RWX allocations and
        // manually mapped payloads live.
        std::vector<Region> regs;
        if ( !m_map.empty() && now.is_valid() )
            m_map.state_at(now, regs);

        for ( const Region &r : regs )
        {
            ea_t lo = r.base < LO ? LO : r.base;
            ea_t hi = r.end() > HI ? HI : (ea_t)r.end();
            if ( hi <= lo )
                continue;
            ea_t mlo = 0, mhi = 0;
            if ( m_modules->range_at(lo, mlo, mhi) )
                continue;

            uchar perm = protection_perm(r.protect);
            Named nm;
            nm.lo   = lo;
            nm.hi   = hi;
            nm.perm = perm;
            nm.name.sprnt("%s_%a",
                          r.origin == RC_MAPVIEW ? "view"
                        : r.origin == RC_PROTECT ? "prot" : "alloc", lo);
            nm.sclass = (perm & SEGPERM_EXEC) != 0 ? "CODE" : "DATA";
            named.push_back(nm);
        }
        std::sort(named.begin(), named.end());
        size_t nregions = named.size();

        // ---- every module the recording ever loaded -----------------------
        //
        // Without these, kernelbase code would sit in a segment called "TTD"
        // (the filler below).
        //
        // From the registry (every module in the recording), not the playhead
        // (modules mapped now). IDA rebuilds its debugger segments whenever
        // the layout changes, discarding their code, and a per-position list
        // changes on every load, so stepping through startup would keep
        // throwing away fresh disassembly.
        //
        // Read and execute only: per-section protections are not tracked, and
        // marking every module writable would bury the RWX allocations this
        // exists to show.
        {
            for ( const ModuleRegistry::Span &sp : m_modules->spans() )
            {
                ea_t mlo = sp.base;
                ea_t mhi = sp.end;
                if ( mlo < LO ) mlo = LO;
                if ( mhi > HI ) mhi = HI;
                if ( mhi <= mlo )
                    continue;

                qstring ident = sp.ident;
                if ( ident.empty() )
                    ident.sprnt("mod_%a", mlo);

                // A region is more specific than its module, so the module
                // claims only what the regions leave.
                ea_t cur = mlo;
                for ( size_t k = 0; k < nregions && cur < mhi; k++ )
                {
                    // Copies, not references: the push_back below can
                    // reallocate this vector.
                    ea_t rlo = named[k].lo;
                    ea_t rhi = named[k].hi;
                    if ( rhi <= cur )
                        continue;
                    if ( rlo >= mhi )
                        break;
                    if ( rlo > cur )
                    {
                        Named nm;
                        nm.lo     = cur;
                        nm.hi     = rlo;
                        nm.name   = ident;
                        nm.sclass = "CODE";
                        nm.perm   = SEGPERM_READ | SEGPERM_EXEC;
                        named.push_back(nm);
                    }
                    cur = rhi > cur ? rhi : cur;
                }
                if ( cur < mhi )
                {
                    Named nm;
                    nm.lo     = cur;
                    nm.hi     = mhi;
                    nm.name   = ident;
                    nm.sclass = "CODE";
                    nm.perm   = SEGPERM_READ | SEGPERM_EXEC;
                    named.push_back(nm);
                }
            }
        }

        std::sort(named.begin(), named.end());

        // ---- emit, filling every gap --------------------------------------
        //
        // The filler is required: stacks, heaps, the PEB and TEBs may be in no
        // region and no module, and IDA does not read memory outside the
        // layout, which would break the stack and register views.
        auto filler = [&](ea_t lo, ea_t hi)
        {
            if ( hi <= lo )
                return;
            memory_info_t mi;
            mi.start_ea = lo;
            mi.end_ea   = hi;
            mi.name     = "TTD";
            mi.bitness  = BITS;
            mi.perm     = SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC;
            out->push_back(mi);
        };

        ea_t cur = LO;
        for ( const Named &nm : named )
        {
            // Modules can overlap where a recording reused an address; the
            // first emitted keeps the space.
            if ( nm.hi <= cur )
                continue;
            ea_t lo = nm.lo < cur ? cur : nm.lo;
            if ( lo >= nm.hi )
                continue;
            filler(cur, lo);

            memory_info_t mi;
            mi.start_ea = lo;
            mi.end_ea   = nm.hi;
            mi.name     = nm.name;
            mi.sclass   = nm.sclass;
            mi.bitness  = BITS;
            mi.perm     = nm.perm;
            out->push_back(mi);
            cur = nm.hi;
        }
        filler(cur, HI);

        m_foldPos    = now;
        m_foldValid  = true;
        // Only the regions vary with the position, and without a map there
        // are none. map_for_update() drops the fold.
        m_foldConst  = m_map.empty();
        return m_foldLayout;
    }

    ssize_t SegmentLayout::on_get_memory_info(Position now, meminfo_vec_t *ranges)
    {
        const meminfo_vec_t &layout = build(now);

        // Rebuilding IDA's debugger segments is not cheap; report no change
        // when there is none.
        if ( m_haveLayout && layout == m_lastLayout )
            return DRC_NOCHG;

        // Logged because a layout change makes IDA rebuild every debugger
        // segment and discard their code: these lines explain disappearing
        // disassembly.
        if ( m_haveLayout )
        {
            msg("[ida-ttd] memory layout changed (%d ranges); IDA is rebuilding "
                "its debugger segments.\n", (int)layout.size());
            m_changes++;
        }

        m_lastLayout = layout;
        m_haveLayout = true;
        *ranges = layout;
        return DRC_OK;
    }

    void SegmentLayout::refresh(Position now)
    {
        // Without a memory map the layout is the same everywhere and build()
        // answers from its cache. With one, a travel can cross an allocation
        // or a free.
        if ( !m_haveLayout || build(now) == m_lastLayout )
            return;
        // Documented as slow, hence the comparison above.
        invalidate_dbgmem_config();
    }

}
