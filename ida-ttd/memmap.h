#pragma once

#include "pch.h"

namespace idattd
{
    class TraceManager;

    // The recording's memory map, reconstructed from the syscalls that built it.
    //
    // The TTD Replay SDK has no notion of a memory region: it can tell you which
    // modules were loaded and it can hand you bytes at an address, but there is
    // no page-protection field anywhere in it and no way to ask what is mapped.
    // The only way to know that a buffer was allocated read/write/execute is to
    // watch the call that made it so.
    //
    // What is kept here is a TIMELINE, not a snapshot: every allocation, every
    // protection change, every free, in the order they happened. That matters
    // because the interesting recordings are exactly the ones where an address
    // means different things at different times -- a buffer allocated RW, filled
    // in, flipped to RX and jumped into, then freed and reallocated for something
    // else. A snapshot cannot describe that; folding the timeline up to a
    // position can.

    //-----------------------------------------------------------------------
    // What one recorded change did.
    enum : uint8_t
    {
        RC_ALLOC = 0,     // NtAllocateVirtualMemory
        RC_PROTECT,       // NtProtectVirtualMemory
        RC_FREE,          // NtFreeVirtualMemory
        RC_MAPVIEW,       // NtMapViewOfSection
        RC_UNMAPVIEW,     // NtUnmapViewOfSection
        RC_COUNT
    };
    const char *change_name(uint8_t kind);

    // The frame in a call chain worth attributing the allocation to: the first
    // one that is not library code, which is the analysed binary itself or --
    // more interesting still -- code in no module at all, meaning something the
    // recording allocated and ran. Falls back to the first frame that left the
    // module the syscall's caller sits in. BADADDR when the chain says nothing.
    ea_t chain_origin(TraceManager *mgr, const struct RegionChange &c);

    // Windows page protection helpers. PAGE_* values are a stable ABI, so these
    // work on any recording regardless of what the host was built against.
    qstring protection_text(uint32_t protect);   // "RWX", "R--", "R-X (guard)", ...
    uchar   protection_perm(uint32_t protect);   // SEGPERM_* mask

    //-----------------------------------------------------------------------
    struct RegionChange
    {
        TTD::Replay::Position pos;               // where the syscall returned
        // Where it was CALLED. This is what the listing travels to: landing on
        // the return puts you inside the syscall stub, which is never the place
        // you wanted -- you wanted the code that asked for the memory.
        TTD::Replay::Position call_pos;
        uint32_t tid  = 0;
        ea_t     pc   = BADADDR;                 // the caller, for the listing
        uint8_t  kind = RC_ALLOC;
        // Runtime address of the syscall stub that was called, so the listing
        // can name it from the database (and say which ntdll it was, in a
        // recording that has both).
        ea_t     api = BADADDR;
        // The call chain that led here, innermost first. chain[0] is the
        // instruction that called the syscall; the rest are the frames further
        // out, but only where the chain CROSSES INTO ANOTHER MODULE.
        //
        // The immediate caller of a memory syscall is almost always an unnamed
        // internal helper of the DLL the stub lives in, which tells you nothing
        // about who wanted the memory. Keeping every frame instead would not
        // help: a heap allocation can be twenty frames deep in ntdll before it
        // reaches the caller that asked for memory, so a fixed number of
        // innermost frames never leaves ntdll at all. One frame per module
        // boundary is short and always reaches the interesting end.
        static const size_t MAX_CHAIN = 8;
        ea_t     chain[MAX_CHAIN] = { 0 };
        uint8_t  chain_n = 0;
        ea_t     base = BADADDR;
        uint64_t size = 0;                       // 0 on a whole-region release
        uint32_t protect = 0;                    // PAGE_* (or the free type)
        // False when the exact value the kernel wrote could not be recovered and
        // the caller's own request was snapped to page boundaries instead. That
        // is a floor, never an overstatement -- see build_memory_map.
        bool     exact = true;
        // The call targeted another process. Recorded so injection is visible in
        // the listing, but never folded into this process's map.
        bool     other_process = false;
        // The range lies inside a module the recording loaded. Only meaningful
        // for RC_PROTECT, where it decides whether a protection change with no
        // matching allocation may invent a region of its own.
        bool     in_module = false;
    };

    //-----------------------------------------------------------------------
    // One region as it stands at some position.
    struct Region
    {
        ea_t     base = 0;
        uint64_t size = 0;
        uint32_t protect = 0;
        uint8_t  origin = RC_ALLOC;   // RC_ALLOC, RC_MAPVIEW or RC_PROTECT
        ea_t     end() const { return (ea_t)(base + size); }
    };

    //-----------------------------------------------------------------------
    class MemoryMap
    {
    public:
        bool   empty() const { return m_changes.empty(); }
        size_t size() const  { return m_changes.size(); }
        const RegionChange &at(size_t i) const { return m_changes[i]; }
        void   set_changes(std::vector<RegionChange> v);
        void   clear();

        // Fold the timeline up to and including 'pos' into a sorted,
        // non-overlapping region list. An invalid position folds the whole
        // timeline.
        //
        // Called on every debugger stop, so it does not refold from the start
        // each time: the folded state is kept, and moving FORWARD only applies
        // the changes actually crossed. Moving backward has to rebuild, which is
        // the same asymmetry the trace itself has.
        void state_at(const TTD::Replay::Position &pos, std::vector<Region> &out) const;

        // ---- persistence in the database ----------------------------------
        //
        // A sweep costs a full replay, so it is paid once per trace and kept.
        // 'fingerprint' identifies the recording the map was built from: a
        // database opened against a different trace rebuilds rather than showing
        // a map whose addresses mean nothing.
        void save(uint64_t fingerprint) const;
        bool load(uint64_t fingerprint);
        static void erase();
        static bool stored();

    private:
        std::vector<RegionChange> m_changes;   // sorted by position

        // Incremental fold state. Mutable because state_at() is logically a
        // query: what it caches is derivable from m_changes alone.
        mutable std::map<ea_t, Region> m_live;
        mutable size_t                 m_liveIdx = 0;   // changes applied so far
        // An invalid position here means "every change has been applied",
        // which is what folding with no position asked for does.
        mutable TTD::Replay::Position  m_livePos = TTD::Replay::Position::Invalid;
        mutable bool                   m_liveValid = false;
    };

    //-----------------------------------------------------------------------
    // Replay the whole recording and record every allocation, protection change
    // and free it made.
    //
    // Watches ntdll's NtAllocateVirtualMemory, NtProtectVirtualMemory,
    // NtFreeVirtualMemory, NtMapViewOfSection and NtUnmapViewOfSection -- in
    // EVERY ntdll the trace loaded, because a WoW64 recording has two with
    // different calling conventions.
    //
    // Shows a cancellable progress box; safe to call from a UI action. Returns
    // false when there is no trace or nothing could be watched.
    bool build_memory_map(TraceManager *mgr, MemoryMap *out, bool *cancelled);

    // Identity of the loaded trace, for the persistence check above.
    uint64_t trace_fingerprint(TraceManager *mgr);
}
