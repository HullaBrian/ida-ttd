#include "debugger/segment_layout.h"
#include "debugger/msttd_position.h"

using namespace TTD;
using namespace TTD::Replay;

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
    }

    void SegmentLayout::build(ICursorView *playhead, meminfo_vec_t *out) const
    {
        // Start above the Windows null page (the low 64 KiB is always reserved /
        // unmapped). Excluding it stops IDA from treating small integers (0, 1, ...)
        // as valid TTD pointers and recursively dereferencing them in the
        // register/stack views.
        const ea_t  LO   = 0x10000;
        const ea_t  HI   = m_is64 ? (ea_t)0x7FFFFFFFFFFFull : (ea_t)0xFFFFFFFFull;
        const uchar BITS = m_is64 ? 2 : 1;

        TtdPosition now = playhead != nullptr ? playhead->GetPosition()
                                                      : TtdPosition::Invalid;
        if ( m_foldValid && now == m_foldPos )
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
        std::vector<Region> regs;
        if ( !m_map.empty() && playhead != nullptr )
            m_map.state_at(to_core(now), regs);

        for ( const Region &r : regs )
        {
            ea_t lo = r.base < LO ? LO : r.base;
            ea_t hi = r.end() > HI ? HI : (ea_t)r.end();
            if ( hi <= lo )
                continue;
            uchar perm = protection_perm(r.protect);
            Named nm;
            nm.lo   = lo;
            nm.hi   = hi;
            nm.perm = perm;
            // Name it after the module it belongs to when it belongs to one --
            // a mapped view of kernel32 reads far better as "kernel32_dll" than
            // as "view_7FFA...". The address is kept as a suffix because one
            // module can hold several regions with different protections once a
            // VirtualProtect has split it.
            qstring mod = m_modules->ident_at(lo);
            if ( !mod.empty() )
                nm.name.sprnt("%s_%a", mod.c_str(), lo);
            else
                nm.name.sprnt("%s_%a",
                              r.origin == RC_MAPVIEW ? "view"
                            : r.origin == RC_PROTECT ? "prot" : "alloc", lo);
            nm.sclass = (perm & SEGPERM_EXEC) != 0 ? "CODE" : "DATA";
            named.push_back(nm);
        }
        std::sort(named.begin(), named.end());
        size_t nregions = named.size();

        // ---- the modules mapped at this position --------------------------
        //
        // Without these every module falls into the generic filler below, so a
        // function in kernelbase reads as being in a segment called "TTD". The
        // recording knows exactly where each module is; there is no reason to
        // make the user guess.
        //
        // Read and execute, not read/write/execute: we do not track a module's
        // per-section protections, and marking every module writable would bury
        // the RWX allocations this whole feature exists to make visible.
        if ( playhead != nullptr )
        {
            size_t n = playhead->GetModuleCount();
            const ModuleInstance *list = playhead->GetModuleList();
            for ( size_t i = 0; i < n; i++ )
            {
                const Module *m = list[i].pModule;
                if ( m == nullptr )
                    continue;
                ea_t mlo = (ea_t)(uint64_t)m->Address;
                ea_t mhi = mlo + (ea_t)m->Size;
                if ( mlo < LO ) mlo = LO;
                if ( mhi > HI ) mhi = HI;
                if ( mhi <= mlo )
                    continue;

                qstring ident = m_modules->ident_at(mlo);
                if ( ident.empty() )
                    ident.sprnt("mod_%a", mlo);

                // A discovered region is more specific than the module it sits
                // in, so the module only claims what the regions leave.
                ea_t cur = mlo;
                for ( size_t k = 0; k < nregions && cur < mhi; k++ )
                {
                    const Named &r = named[k];
                    if ( r.hi <= cur )
                        continue;
                    if ( r.lo >= mhi )
                        break;
                    if ( r.lo > cur )
                    {
                        Named nm;
                        nm.lo     = cur;
                        nm.hi     = r.lo;
                        nm.name   = ident;
                        nm.sclass = "CODE";
                        nm.perm   = SEGPERM_READ | SEGPERM_EXEC;
                        named.push_back(nm);
                    }
                    cur = r.hi > cur ? r.hi : cur;
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
    }

    ssize_t SegmentLayout::on_get_memory_info(ICursorView *playhead, meminfo_vec_t *ranges)
    {
        meminfo_vec_t layout;
        build(playhead, &layout);

        // Rebuilding IDA's debugger segments is not cheap, and stepping inside
        // one region changes nothing about the layout. Say so.
        if ( m_haveLayout && layout == m_lastLayout )
            return DRC_NOCHG;

        m_lastLayout = layout;
        m_haveLayout = true;
        *ranges = layout;
        return DRC_OK;
    }

    void SegmentLayout::refresh(ICursorView *playhead)
    {
        // The layout is no longer a constant even without a memory map: it
        // names the modules mapped at the current position, and time travel can
        // cross a module load or unload.
        if ( !m_haveLayout )
            return;
        meminfo_vec_t now;
        build(playhead, &now);
        if ( now == m_lastLayout )
            return;
        // Documented as slow, which is exactly why it is behind the comparison
        // rather than called on every stop.
        invalidate_dbgmem_config();
    }

}
