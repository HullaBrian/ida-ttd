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

    void SegmentLayout::build(Position now, meminfo_vec_t *out) const
    {
        // Start above the Windows null page (the low 64 KiB is always reserved /
        // unmapped). Excluding it stops IDA from treating small integers (0, 1, ...)
        // as valid TTD pointers and recursively dereferencing them in the
        // register/stack views.
        const ea_t  LO   = 0x10000;
        const ea_t  HI   = m_is64 ? (ea_t)0x7FFFFFFFFFFFull : (ea_t)0xFFFFFFFFull;
        const uchar BITS = m_is64 ? 2 : 1;

        if ( m_foldValid && (m_foldConst || now == m_foldPos) )
        {
            *out = m_foldLayout;
            return;
        }

        out->qclear();

        // Named pieces of the address space, gathered before anything is
        // emitted so they can be sorted and the gaps filled in one pass.
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
        // A region inside a module is skipped: the module already has a segment,
        // and splitting it would make IDA rebuild that segment and discard the
        // code defined in it. What the map adds that a module cannot is the
        // memory a module does not cover, which is where an RWX allocation or a
        // manually mapped payload lives.
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
        // Without these a function in kernelbase reads as being in a segment
        // called "TTD", because everything unnamed falls into the filler below.
        //
        // Taken from the module registry, which lists every module across the
        // whole recording, NOT from the playhead, which lists only those mapped
        // right now. That difference matters more than the extra entries cost:
        // IDA rebuilds its debugger segments whenever this layout changes, and
        // rebuilding one discards the code it had defined there. A per-position
        // list changes on every module load, so stepping through startup would
        // repeatedly throw away the disassembly it had just produced.
        //
        // Read and execute, not read/write/execute: per-section protections are
        // not tracked, and marking every module writable would bury the RWX
        // allocations this feature exists to make visible.
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

                // A discovered region is more specific than the module it sits
                // in, so the module only claims what the regions leave.
                ea_t cur = mlo;
                for ( size_t k = 0; k < nregions && cur < mhi; k++ )
                {
                    // Copy the bounds rather than hold a reference: the push_back
                    // below appends to this same vector, and a reallocation there
                    // would leave the reference pointing at freed memory. Reading
                    // a garbage end through it left the rest of the module unnamed,
                    // so a DLL showed up as its header followed by unnamed filler.
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
        // The filler is not optional. Stacks, heaps, the PEB and the TEB are
        // never created by a call we watch and belong to no module, so reporting
        // only what we can name would make IDA stop reading them and break the
        // stack and register views. What the names add is description, never
        // less reachability than before.
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
            // Two modules can overlap in a recording that reused an address;
            // whatever was emitted first keeps the space.
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

        m_foldLayout = *out;
        m_foldPos    = now;
        m_foldValid  = true;
        // Only the regions vary with the position, and with no map there are
        // none. Changing the map goes through map_for_update(), which drops the
        // fold.
        m_foldConst  = m_map.empty();
    }

    ssize_t SegmentLayout::on_get_memory_info(Position now, meminfo_vec_t *ranges)
    {
        meminfo_vec_t layout;
        build(now, &layout);

        // Rebuilding IDA's debugger segments is not cheap, and stepping inside
        // one region changes nothing about the layout. Say so.
        if ( m_haveLayout && layout == m_lastLayout )
            return DRC_NOCHG;

        // Worth saying out loud: IDA rebuilds every debugger segment when the
        // layout changes, and rebuilding one discards the code defined in it.
        // A run of these lines is the explanation for disassembly disappearing.
        if ( m_haveLayout )
            msg("[ida-ttd] memory layout changed (%d ranges); IDA is rebuilding "
                "its debugger segments.\n", (int)layout.size());

        m_lastLayout = layout;
        m_haveLayout = true;
        *ranges = layout;
        return DRC_OK;
    }

    void SegmentLayout::refresh(Position now)
    {
        // Without a memory map the layout is the same at every position (the
        // modules come from the whole recording) and build() answers from its
        // cache. With one, time travel can cross an allocation or a free.
        if ( !m_haveLayout )
            return;
        meminfo_vec_t layout;
        build(now, &layout);
        if ( layout == m_lastLayout )
            return;
        // Documented as slow, which is exactly why it is behind the comparison
        // rather than called on every stop.
        invalidate_dbgmem_config();
    }

}
