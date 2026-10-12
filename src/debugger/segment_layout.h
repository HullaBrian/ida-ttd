#pragma once

#include "common/pch.h"
#include "analysis/memmap.h"
#include "debugger/module_registry.h"

namespace idattd
{
    // What IDA is told the recorded process's address space looks like.
    //
    // Without a reconstructed memory map there is one flat range over user
    // space, with the loaded modules named inside it. With one, every region
    // the recording allocated becomes a segment carrying its real permissions,
    // so an RWX buffer is visible as one.
    //
    // Two caches sit behind that, for two different reasons:
    //
    //   - The folded map. Asking the memory map what was live at a position
    //     means replaying its change timeline up to that position, and a stop
    //     asks twice: once to decide whether the layout changed, once to hand
    //     it over. Folding once per position covers both.
    //   - The layout IDA was last given. Rebuilding IDA's debugger segments is
    //     documented as slow, and stepping within one region changes nothing
    //     about the layout, so an unchanged answer is reported as unchanged
    //     rather than handed over again.
    //
    // Time travel is what makes any of this necessary: IDA assumes process
    // memory only changes going forward, and here the same address can be in a
    // different region, with different permissions, at a different position.
    class SegmentLayout
    {
    public:
        void bind(ModuleRegistry *modules, bool is64);
        void reset();

        // The recording's reconstructed memory map. Empty until a sweep has
        // been run or a saved one loaded.
        const MemoryMap &map() const { return m_map; }
        // The same map, for a caller about to change it. Taking it invalidates
        // the fold cached for the current position, which any change makes
        // stale -- doing it here means no call site can forget.
        MemoryMap &map_for_update() { m_foldValid = false; m_foldConst = false; return m_map; }

        // ev_get_memory_info: the layout at 'playhead''s position, or DRC_NOCHG
        // when it is the one IDA already has.
        ssize_t on_get_memory_info(TTD::Replay::ICursorView *playhead,
                                   meminfo_vec_t *ranges);

        // Tell IDA to re-read the layout if the regions in force at
        // 'playhead''s position differ from the ones it was last given. Called
        // on every stop, which is why it compares before it invalidates.
        void refresh(TTD::Replay::ICursorView *playhead);

    private:
        // Compose the layout IDA should see at 'playhead''s position.
        void build(TTD::Replay::ICursorView *playhead, meminfo_vec_t *out) const;

        ModuleRegistry *m_modules = nullptr;
        bool            m_is64    = false;

        MemoryMap     m_map;
        meminfo_vec_t m_lastLayout;      // what IDA was last given
        bool          m_haveLayout = false;

        // The layout folded for one position, so a stop that asks for it twice
        // folds once.
        //
        // m_foldConst records that the fold cannot vary with the position at
        // all, which is the case whenever no memory map has been built: the
        // modules come from the whole recording rather than the position. The
        // whole session then reuses one fold.
        mutable meminfo_vec_t         m_foldLayout;
        mutable TTD::Replay::Position m_foldPos;
        mutable bool                  m_foldValid = false;
        mutable bool                  m_foldConst = false;
    };
}
