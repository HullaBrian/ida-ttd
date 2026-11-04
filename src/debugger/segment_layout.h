#pragma once

#include "common/pch.h"
#include "analysis/memmap.h"
#include "debugger/module_registry.h"

namespace idattd
{
    // What IDA is told the recorded process's address space looks like.
    //
    // Without a reconstructed memory map this is one flat range over user
    // space with the modules named inside it. With one, every region the
    // recording allocated becomes a segment with its real permissions, so an
    // RWX buffer shows as one.
    //
    // Two caches:
    //
    //   - The folded map. Folding the map's change timeline up to a position
    //     is not free, and a stop asks twice (did the layout change, then the
    //     layout itself), so it is folded once per position.
    //   - The layout IDA was last given. Rebuilding IDA's debugger segments
    //     is documented as slow, so an unchanged layout is reported as
    //     unchanged.
    //
    // Time travel is why: IDA assumes memory only changes going forward, but
    // here an address can be in a different region, with different
    // permissions, at another position.
    class SegmentLayout
    {
    public:
        void bind(ModuleRegistry *modules, bool is64);
        void reset();

        // The recording's reconstructed memory map. Empty until a sweep has
        // been run or a saved one loaded.
        const MemoryMap &map() const { return m_map; }
        // The same map, for a caller about to change it. Taking it drops the
        // cached fold, which any change makes stale, so no call site can
        // forget to.
        MemoryMap &map_for_update() { m_foldValid = false; m_foldConst = false; return m_map; }

        // ev_get_memory_info: the layout at 'now', or DRC_NOCHG when it is the
        // one IDA already has.
        ssize_t on_get_memory_info(Position now, meminfo_vec_t *ranges);
        // How often the layout IDA had was replaced (the first one aside).
        uint32_t changes() const { return m_changes; }

        // Tell IDA to re-read the layout if the one at 'now' differs from what
        // it was last given. Called on every stop, hence the comparison.
        void refresh(Position now);
        // Would refresh(now) make IDA rebuild its debugger segments?
        bool changes_at(Position now) const
        {
            return m_haveLayout && !(build(now) == m_lastLayout);
        }

    private:
        // The layout IDA should see at 'now'. The reference is to the fold
        // cache, valid until the next build() or map_for_update().
        const meminfo_vec_t &build(Position now) const;

        ModuleRegistry *m_modules = nullptr;
        bool            m_is64    = false;

        MemoryMap     m_map;
        meminfo_vec_t m_lastLayout;      // what IDA was last given
        bool          m_haveLayout = false;
        uint32_t      m_changes = 0;

        // The layout folded for one position.
        //
        // m_foldConst: the fold cannot vary with the position, which holds
        // whenever there is no memory map (the modules come from the whole
        // recording). The session then reuses one fold.
        mutable meminfo_vec_t         m_foldLayout;
        mutable Position              m_foldPos;
        mutable bool                  m_foldValid = false;
        mutable bool                  m_foldConst = false;
    };
}
