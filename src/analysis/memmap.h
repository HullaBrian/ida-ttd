#pragma once

#include "common/pch.h"
#include "core/position.h"

namespace idattd
{
    class TraceManager;

    // The recording's memory map, reconstructed from the syscalls that built
    // it. The TTD Replay SDK reports no protections or region list, so for a
    // Microsoft recording the calls are the only source; Sogen also records
    // region state (RC_STATE).
    //
    // Held as a timeline (every allocation, protection change and free, in
    // order), not a snapshot: folding it up to a position gives the map as it
    // stood then, since an address can mean different things over time.

    // What one recorded change did.
    enum : uint8_t
    {
        RC_ALLOC = 0,     // NtAllocateVirtualMemory
        RC_PROTECT,       // NtProtectVirtualMemory
        RC_FREE,          // NtFreeVirtualMemory
        RC_MAPVIEW,       // NtMapViewOfSection
        RC_UNMAPVIEW,     // NtUnmapViewOfSection
        // Not a call but its outcome, from a backend that records region
        // bookkeeping (Sogen): [base, base + size) is now in 'state' with
        // 'protect'. Folding it overwrites the range.
        RC_STATE,
        RC_COUNT
    };
    const char *change_name(uint8_t kind);

    // The call-chain frame to attribute an allocation to: the first that is
    // not library code (the analyzed binary, or code in no module, i.e. code
    // the recording allocated and ran). Falls back to the first frame outside
    // the syscall caller's module. BADADDR when the chain is empty.
    ea_t chain_origin(TraceManager *mgr, const struct RegionChange &c);

    // Windows page protection helpers. PAGE_* values are a stable ABI, so these
    // work on any recording.
    qstring protection_text(uint32_t protect);   // "RWX", "R--", "R-X (guard)", ...
    uchar   protection_perm(uint32_t protect);   // SEGPERM_* mask

    struct RegionChange
    {
        Position pos;                            // where the syscall returned
        // Where it was called: what the listing travels to, since the return
        // lands inside the syscall stub rather than in the code that asked.
        Position call_pos;
        uint32_t tid  = 0;
        ea_t     pc   = BADADDR;                 // the caller, for the listing
        uint8_t  kind = RC_ALLOC;
        // Runtime address of the syscall stub called, so the listing can name
        // it (and tell the two ntdlls of a WoW64 recording apart).
        ea_t     api = BADADDR;
        // The call chain, innermost first: chain[0] called the syscall, then
        // one frame per module boundary crossed. A heap allocation can be
        // twenty frames deep in ntdll, so the innermost N frames would not
        // reach the code that wanted the memory.
        static const size_t MAX_CHAIN = 8;
        ea_t     chain[MAX_CHAIN] = { 0 };
        uint8_t  chain_n = 0;
        ea_t     base = BADADDR;
        uint64_t size = 0;                       // 0 on a whole-region release
        uint32_t protect = 0;                    // PAGE_* (or the free type)
        // False when the kernel's value was not recovered and the caller's
        // request was snapped to pages instead (a floor, never too large).
        bool     exact = true;
        // The call targeted another process: listed so injection is visible,
        // never folded into this process's map.
        bool     other_process = false;
        // The range lies inside a loaded module. Only used for RC_PROTECT: it
        // decides whether a change with no known allocation makes a region.
        bool     in_module = false;
        // For RC_STATE: MEM_COMMIT, MEM_RESERVE or MEM_FREE; the ITTD_REGION_*
        // kind of memory; and the allocation's base. Zero for the others.
        uint32_t state = 0;
        uint32_t region_type = 0;
        ea_t     alloc_base = 0;
    };

    // One region as it stands at some position.
    struct Region
    {
        ea_t     base = 0;
        uint64_t size = 0;
        uint32_t protect = 0;
        uint8_t  origin = RC_ALLOC;   // RC_ALLOC, RC_MAPVIEW or RC_PROTECT
        // ITTD_REGION_*: from the recording when it says (Sogen), else implied
        // by the call that made it.
        uint32_t type = 0;
        bool     reserved = false;    // reserved, not committed (when known)
        // Base of the allocation or view this is (part of): a protection
        // change splits a region into pieces, and a whole-region release must
        // drop every one of them, not just the piece holding the address.
        ea_t     alloc = 0;
        // Position of the call that made the region (what a listing travels
        // to); for RC_STATE, the position the region first appeared at.
        Position since = Position::none();
        ea_t     end() const { return (ea_t)(base + size); }
    };

    class MemoryMap
    {
    public:
        bool   empty() const { return m_changes.empty(); }
        size_t size() const  { return m_changes.size(); }
        const RegionChange &at(size_t i) const { return m_changes[i]; }
        void   set_changes(std::vector<RegionChange> v);
        void   clear();

        // How many changes lie at or before 'pos' (all of them for an invalid
        // position). Two positions with the same count fold to the same map,
        // so this is what a cache of the fold is keyed by.
        size_t count_at(const Position &pos) const;
        // Fold the first 'n' changes into a sorted, non-overlapping region
        // list. Called on stops, so the fold is cached: moving forward
        // applies only the changes crossed, and moving backward starts from
        // the nearest checkpoint before the target instead of the beginning.
        void state_upto(size_t n, std::vector<Region> &out) const;
        // The same up to and including 'pos'; an invalid position folds all
        // of it.
        void state_at(const Position &pos, std::vector<Region> &out) const
        { state_upto(count_at(pos), out); }

        // ---- persistence in the database ----------------------------------
        //
        // A sweep costs a full replay, so its result is kept. 'fingerprint'
        // names the recording it came from; against a different one the map
        // is rebuilt.
        void save(uint64_t fingerprint) const;
        bool load(uint64_t fingerprint);
        static void erase();

    private:
        std::vector<RegionChange> m_changes;   // sorted by position

        // Incremental fold state, derivable from m_changes alone (hence
        // mutable: state_at() is logically a query).
        mutable std::map<ea_t, Region> m_live;
        mutable size_t                 m_liveIdx = 0;   // changes applied so far
        mutable bool                   m_liveValid = false;
        // The fold after every checkpoint_every() changes, in order, made as
        // the fold first passes them. At most about 64, so a recording that
        // allocates in a loop does not keep thousands of copies.
        mutable std::vector<std::pair<size_t, std::map<ea_t, Region>>> m_checkpoints;
        size_t checkpoint_every() const;
        void   drop_fold();
    };

    // Ask the backend for every allocation, protection change and free
    // (ITraceBackend::query_mapping_changes): Microsoft TTD reconstructs them
    // from the memory syscalls, Sogen reads the map it recorded.
    //
    // Shows a cancellable progress box; safe from a UI action. False when
    // there is no trace or the backend could not answer.
    //
    // Modifies the database so the listing can name callers: applies export
    // names to the modules holding the called stubs and the attributed callers
    // (chain_origin), and loads PDBs for those callers in library modules.
    //
    // A failure is returned in 'error', never shown in a dialog (which would
    // hang a script): the caller shows it.
    bool build_memory_map(TraceManager *mgr, MemoryMap *out, bool *cancelled, qstring *error = nullptr);

    // The session's memory map: the one IDA's segments, the Memory map
    // listings and every script command read. Built if the session has none
    // (or 'rebuild'), then saved in the database unless cancelled, and IDA is
    // told its segments may have changed. A failed build leaves the map the
    // session had. 'error' as for build_memory_map.
    bool session_memory_map(TraceManager *mgr, bool rebuild, bool *cancelled, qstring *error = nullptr);

    // Identity of the loaded trace, for the persistence check above.
    uint64_t trace_fingerprint(TraceManager *mgr);
}
