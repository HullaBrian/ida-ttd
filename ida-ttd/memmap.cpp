#include "memmap.h"
#include "trace_manager.h"
#include "trace_open.h"
#include "symbols.h"

using namespace TTD;
using namespace TTD::Replay;

namespace idattd
{
    //=======================================================================
    // Page protections
    //=======================================================================
    // PAGE_* values, spelled out rather than taken from <windows.h>, so that what
    // is decoded here is the RECORDING's ABI and not this build's headers.
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

    //-----------------------------------------------------------------------
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

    //-----------------------------------------------------------------------
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

    //-----------------------------------------------------------------------
    const char *change_name(uint8_t kind)
    {
        switch ( kind )
        {
            case RC_ALLOC:     return "Allocate";
            case RC_PROTECT:   return "Protect";
            case RC_FREE:      return "Free";
            case RC_MAPVIEW:   return "Map view";
            case RC_UNMAPVIEW: return "Unmap view";
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

    //-----------------------------------------------------------------------
    static void apply_change(LiveMap &live, const RegionChange &c)
    {
        // A call that targeted another process changed THAT process's map, not
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
                    // case -- a payload whose allocation we could not recover --
                    // so let it stand up a region rather than be lost.
                    if ( c.in_module )
                        return;
                    Region r;
                    r.base    = lo;
                    r.size    = c.size;
                    r.protect = c.protect;
                    r.origin  = RC_PROTECT;
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

    //-----------------------------------------------------------------------
    void MemoryMap::state_at(const Position &pos, std::vector<Region> &out) const
    {
        out.clear();

        // Replaying forward from where the cache already stands is the common
        // case by far -- stepping crosses a handful of changes, if any. Only a
        // jump BACKWARD has to start over, because a change cannot be undone
        // without knowing what it displaced.
        // An invalid position on either side means "the whole timeline", which
        // sorts after every real one -- so it can be reached from anywhere, and
        // nothing can be reached from it.
        bool backward = pos.IsValid() && (!m_livePos.IsValid() || pos < m_livePos);
        if ( !m_liveValid || backward )
        {
            m_live.clear();
            m_liveIdx = 0;
        }

        while ( m_liveIdx < m_changes.size() )
        {
            const RegionChange &c = m_changes[m_liveIdx];
            if ( pos.IsValid() && c.pos > pos )
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

    //-----------------------------------------------------------------------
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

    //-----------------------------------------------------------------------
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
    // 6: the chain keeps module boundaries rather than the innermost frames.
    // 5 added the called export. 4 added the call chain, 3 the call position. 2 made RegionChange::pc the CALLER and
    // established the stack-argument offset from the stack rather than assuming
    // it, so a map written by an older build can hold a wrong Protect value.
    // Rebuild rather than show it.
    static const uint32_t MM_VERSION = 6;
    // A recording that allocates in a loop can produce a great many changes.
    // Past this there is nothing left to learn from another row, and the blob
    // has to fit in the database.
    static const size_t MM_MAX_ITEMS = 200000;

    namespace
    {
        // Little-endian writer/reader for the blob. Bounds-checked on the way in:
        // the blob is database content, and a truncated or corrupted one must
        // fail cleanly rather than walk off the end.
        struct BlobWriter
        {
            std::vector<uint8_t> b;
            void u8 (uint8_t v)  { b.push_back(v); }
            void u32(uint32_t v) { for ( int i = 0; i < 4; i++ ) b.push_back((uint8_t)(v >> (i * 8))); }
            void u64(uint64_t v) { for ( int i = 0; i < 8; i++ ) b.push_back((uint8_t)(v >> (i * 8))); }
        };

        struct BlobReader
        {
            const uint8_t *p = nullptr;
            size_t n = 0, i = 0;
            bool ok = true;
            bool have(size_t k) { if ( i + k > n ) { ok = false; return false; } return true; }
            uint8_t  u8()  { if ( !have(1) ) return 0; return p[i++]; }
            uint32_t u32() { if ( !have(4) ) return 0; uint32_t v = 0;
                             for ( int k = 0; k < 4; k++ ) v |= (uint32_t)p[i++] << (k * 8); return v; }
            uint64_t u64() { if ( !have(8) ) return 0; uint64_t v = 0;
                             for ( int k = 0; k < 8; k++ ) v |= (uint64_t)p[i++] << (k * 8); return v; }
        };
    }

    //-----------------------------------------------------------------------
    void MemoryMap::save(uint64_t fingerprint) const
    {
        netnode nn(MM_NODE, 0, true);
        if ( m_changes.empty() )
        {
            nn.delblob(0, MM_TAG);
            return;
        }

        BlobWriter w;
        w.u32(MM_MAGIC);
        w.u32(MM_VERSION);
        w.u64(fingerprint);
        size_t n = m_changes.size() < MM_MAX_ITEMS ? m_changes.size() : MM_MAX_ITEMS;
        w.u64((uint64_t)n);
        for ( size_t i = 0; i < n; i++ )
        {
            const RegionChange &c = m_changes[i];
            w.u64((uint64_t)c.pos.Sequence);
            w.u64((uint64_t)c.pos.Steps);
            w.u64((uint64_t)c.call_pos.Sequence);
            w.u64((uint64_t)c.call_pos.Steps);
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
        }
        nn.setblob(w.b.data(), w.b.size(), 0, MM_TAG);
    }

    //-----------------------------------------------------------------------
    bool MemoryMap::load(uint64_t fingerprint)
    {
        clear();
        netnode nn(MM_NODE);
        if ( nn == BADNODE )
            return false;

        size_t sz = 0;
        void *raw = nn.getblob(nullptr, &sz, 0, MM_TAG);
        if ( raw == nullptr )
            return false;

        BlobReader r;
        r.p = (const uint8_t *)raw;
        r.n = sz;

        bool ok = r.u32() == MM_MAGIC && r.u32() == MM_VERSION;
        // A map built from a DIFFERENT recording would show addresses and
        // positions that mean nothing here. Refuse it rather than mislead.
        if ( ok && r.u64() != fingerprint )
            ok = false;

        uint64_t count = ok ? r.u64() : 0;
        if ( count > MM_MAX_ITEMS )
            ok = false;

        std::vector<RegionChange> v;
        if ( ok )
        {
            v.reserve((size_t)count);
            for ( uint64_t i = 0; i < count && r.ok; i++ )
            {
                RegionChange c;
                c.pos.Sequence      = (SequenceId)r.u64();
                c.pos.Steps         = (StepCount)r.u64();
                c.call_pos.Sequence = (SequenceId)r.u64();
                c.call_pos.Steps    = (StepCount)r.u64();
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
                for ( uint8_t k = 0; k < nc && r.ok; k++ )
                    c.chain[k] = (ea_t)r.u64();
                c.chain_n = nc;
                if ( c.kind < RC_COUNT )
                    v.push_back(c);
            }
            ok = r.ok;
        }
        qfree(raw);

        if ( !ok )
            return false;
        m_changes = std::move(v);
        m_live.clear();
        m_liveIdx   = 0;
        m_liveValid = false;
        return true;
    }

    //-----------------------------------------------------------------------
    void MemoryMap::erase()
    {
        netnode nn(MM_NODE);
        if ( nn != BADNODE )
            nn.delblob(0, MM_TAG);
    }

    //-----------------------------------------------------------------------
    bool MemoryMap::stored()
    {
        netnode nn(MM_NODE);
        if ( nn == BADNODE )
            return false;
        // getblob(nullptr, &sz, ...) allocates, so the answer has to be freed
        // even when all we wanted was "is there one".
        size_t sz = 0;
        void *raw = nn.getblob(nullptr, &sz, 0, MM_TAG);
        if ( raw == nullptr )
            return false;
        qfree(raw);
        return true;
    }

    //=======================================================================
    // Building the map
    //=======================================================================
    // The syscalls that shape a process's address space, described as data.
    //
    // Every parameter of all five is a handle, a pointer or a ULONG, which is
    // what lets one uniform stack layout serve the x86 side: no parameter is
    // wider than a slot, so no argument after it is shifted.
    namespace
    {
        struct WatchDesc
        {
            const char *name;
            uint8_t     kind;
            size_t      nargs;
            int         iProc;    // ProcessHandle argument
            int         iBase;    // BaseAddress argument
            int         iSize;    // RegionSize argument, -1 when there is none
            int         iExtra;   // Protect, or FreeType, -1 when there is none
            bool        basePtr;  // BaseAddress is PVOID* rather than PVOID
            bool        deferred; // out-params the KERNEL writes, not the caller
        };

        // NtAllocateVirtualMemory(HANDLE, PVOID* Base, ULONG_PTR, PSIZE_T Size, ULONG, ULONG Protect)
        // NtProtectVirtualMemory (HANDLE, PVOID* Base, PSIZE_T Size, ULONG NewProtect, PULONG)
        // NtFreeVirtualMemory    (HANDLE, PVOID* Base, PSIZE_T Size, ULONG FreeType)
        // NtMapViewOfSection     (HANDLE Section, HANDLE Process, PVOID* Base, ULONG_PTR,
        //                         SIZE_T, PLARGE_INTEGER, PSIZE_T ViewSize, SECTION_INHERIT,
        //                         ULONG, ULONG Win32Protect)
        // NtUnmapViewOfSection   (HANDLE Process, PVOID Base)
        //
        // 'deferred' marks the two whose out-params the kernel fills in. A free's
        // are written by the CALLER before the call, so they are in the recording
        // and need none of the recovery machinery below. Note that Map's process
        // handle is its SECOND argument, not its first.
        static const WatchDesc kWatches[] =
        {
            { "NtAllocateVirtualMemory", RC_ALLOC,      6, 0, 1,  3,  5, true,  true  },
            { "NtProtectVirtualMemory",  RC_PROTECT,    5, 0, 1,  2,  3, true,  true  },
            { "NtFreeVirtualMemory",     RC_FREE,       4, 0, 1,  2,  3, true,  false },
            { "NtMapViewOfSection",      RC_MAPVIEW,   10, 1, 2,  6,  9, true,  true  },
            { "NtUnmapViewOfSection",    RC_UNMAPVIEW,  2, 0, 1, -1, -1, false, false },
        };

        static const uint64_t PAGE = 0x1000;

        // These syscalls round the caller's request to pages before writing it
        // back, so a value that is not page-granular PROVABLY did not come from
        // the kernel. That is the acceptance test -- not "is it non-zero".
        //
        // It matters because an aggressive memory query cannot tell the kernel's
        // write from the caller's own store before the call: only the latter is
        // recorded. A non-zero check passes on the caller's request and reports a
        // region short by however much the kernel rounded up, silently.
        static bool page_granular(uint64_t v) { return v != 0 && (v % PAGE) == 0; }
        static uint64_t page_floor(uint64_t v)   { return v - (v % PAGE); }
        static uint64_t page_ceiling(uint64_t v)
        {
            uint64_t r = v % PAGE;
            return r == 0 ? v : v + (PAGE - r);
        }

        // A pseudo-handle of -1 is NtCurrentProcess. Anything else names another
        // process, and the call changed THAT map rather than ours.
        static bool is_current_process(uint64_t h, bool is64)
        {
            uint64_t self = is64 ? 0xFFFFFFFFFFFFFFFFull : 0xFFFFFFFFull;
            return h == self || h == 0xFFFFFFFFFFFFFFFFull;
        }

        // One captured call, before its out-params were resolved.
        struct Rec
        {
            const WatchDesc *d = nullptr;
            bool     is64 = false;
            uint32_t tid = 0;
            ea_t     pc = BADADDR;
            ea_t     api = BADADDR;
            Position retPos;
            Position callPos;
            ea_t     chain[RegionChange::MAX_CHAIN] = { 0 };
            uint8_t  chain_n = 0;
            uint64_t pBase = 0, pSize = 0;   // addresses of the out-param slots
            uint64_t base = 0, size = 0;     // resolved values
            uint32_t extra = 0;              // protection, or free type
            bool     baseOk = false, sizeOk = false;
            bool     otherProcess = false;
        };

        // An out-param we could not read yet, retried as the same replay rolls
        // forward. The value becomes visible the moment the guest reads it back,
        // and our callbacks are already firing on that thread.
        struct Retry
        {
            uint64_t addr = 0;
            uint32_t tid = 0;
            uint32_t width = 8;
            size_t   rec = 0;
            bool     isBase = true;
            int      attempts = 0;
            bool     live = false;
        };

        struct SweepState
        {
            std::map<ea_t, const WatchDesc *> watched;
            std::map<ea_t, bool>              watchedIs64;
            ea_t  lo = BADADDR, hi = 0;      // bounds of 'watched', for a cheap reject

            std::vector<Rec> recs;
            std::map<uint32_t, std::vector<size_t>> inflight;   // per-thread call stack

            std::vector<Retry> retries;
            std::map<uint32_t, std::vector<size_t>> byThread;
            size_t outstanding = 0;

            bool truncated = false;
        };

        // Hard cap. A recording that allocates in a loop can produce millions of
        // these, and the engine's callback is noexcept -- a bad_alloc in there
        // does not unwind, it terminates the process with no message.
        static const size_t kMaxRecs = MM_MAX_ITEMS;

        // The pending frame for one in-flight call.
        struct Frame
        {
            const WatchDesc *d;
            bool     is64;
            uint64_t retAddr;
            ea_t     pc;
            ea_t     api;
            Position callPos;
            uint64_t args[12];
            ea_t     chain[RegionChange::MAX_CHAIN];
            uint8_t  chain_n;
        };

        // One entry of the per-thread shadow call stack. Every call in the
        // recording pushes one and every matching return pops it, which is what
        // makes a call chain available at the moment a watched call happens.
        struct ShadowFrame
        {
            uint64_t retAddr;   // where this call will return to
            uint64_t sp;        // the stack pointer when it was made
            ea_t     site;      // the instruction that made it
        };

        // A call depth past this is pathological, and an unbounded vector grown
        // inside a noexcept callback is the shape of bug that takes the whole
        // process down with no message.
        static const size_t kMaxDepth = 256;
    }

    //-----------------------------------------------------------------------
    template <typename V>
    static bool read_ptr(V const *v, uint64_t addr, uint32_t width, uint64_t *out) noexcept
    {
        uint64_t tmp = 0;
        MemoryBuffer mb = v->QueryMemoryBuffer(GuestAddress{ addr },
                                               BufferView{ &tmp, width });
        if ( mb.Memory.Size != width )
            return false;
        *out = tmp;
        return true;
    }

    //-----------------------------------------------------------------------
    // Read a watched call's arguments from inside the call/return callback.
    //
    // The stack pointer comes from the engine rather than from RSP/ESP in the
    // register context: that is what keeps this correct on both architectures,
    // and in a WoW64 recording where the two alternate call by call.
    //
    // Whether the CALL has already pushed its return address is asked of the
    // stack rather than assumed. It has to be: the two answers put the first
    // stack argument 8 bytes apart on x64, which for NtAllocateVirtualMemory is
    // the difference between reading Protect and reading whatever the caller
    // left in the shadow space. The SDK guide says the callback fires at the
    // call instruction; a working reference implementation says it fires at the
    // callee's first instruction. If the word at the top of the stack is the
    // return address, the push has happened.
    static void capture_args(IThreadView const *t, bool is64, size_t n,
                             uint64_t retAddr, uint64_t *out) noexcept
    {
        for ( size_t i = 0; i < n; i++ )
            out[i] = 0;

        uint64_t sp    = (uint64_t)t->GetStackPointer();
        uint32_t width = is64 ? 8 : 4;
        uint64_t top   = 0;
        bool pushed = read_ptr(t, sp, width, &top) && top == retAddr;

        if ( !is64 )
        {
            // Nothing arrives in a register: every argument was pushed, so they
            // run contiguously from just above the return address (or from the
            // stack pointer itself, if it has not been pushed yet).
            uint32_t slots[12] = { 0 };
            size_t want = n < 12 ? n : 12;
            t->QueryMemoryBuffer(GuestAddress{ sp + (pushed ? 4 : 0) },
                                 BufferView{ slots, want * sizeof(uint32_t) });
            for ( size_t i = 0; i < want; i++ )
                out[i] = slots[i];
            return;
        }

        CROSS_PLATFORM_CONTEXT ctx = t->GetCrossPlatformContext();
        const AMD64_CONTEXT &c = ctx.Amd64Context;
        const uint64_t regs[4] = { c.Rcx, c.Rdx, c.R8, c.R9 };
        for ( size_t i = 0; i < n && i < 4; i++ )
            out[i] = regs[i];
        if ( n <= 4 )
            return;
        // 0x20 bytes of shadow space precede the first stack argument, plus the
        // return address on top of it once the call has pushed one.
        uint64_t slots[12] = { 0 };
        size_t rest = n - 4;
        if ( rest > 12 )
            rest = 12;
        t->QueryMemoryBuffer(GuestAddress{ sp + (pushed ? 0x28 : 0x20) },
                             BufferView{ slots, rest * sizeof(uint64_t) });
        for ( size_t i = 0; i < rest; i++ )
            out[4 + i] = slots[i];
    }

    //-----------------------------------------------------------------------
    static bool read_ptr_policy(ICursorView const *c, uint64_t addr, uint32_t width,
                                QueryMemoryPolicy pol, uint64_t *out)
    {
        uint64_t tmp = 0;
        MemoryBuffer mb = c->QueryMemoryBuffer(GuestAddress{ addr },
                                               BufferView{ &tmp, width }, pol);
        if ( mb.Memory.Size != width )
            return false;
        *out = tmp;
        return true;
    }

    //-----------------------------------------------------------------------
    // Last resort for one out-param: replay this thread forward a bounded number
    // of steps with a Read watchpoint on the slot, and take the value the guest
    // reads back. That read is the only recorded event the kernel's write ever
    // produces.
    static bool recover_by_readback(TraceManager *mgr, const Position &from,
                                    uint32_t tid, uint64_t addr, uint32_t width,
                                    uint64_t *out)
    {
        UniqueCursor cur = mgr->make_cursor();
        if ( !cur )
            return false;

        uint64_t found = 0;
        bool     got   = false;

        auto on_read = [&](ICursorView::MemoryWatchpointResult const &,
                           IThreadView const *t) noexcept -> bool
        {
            uint64_t v = 0;
            if ( read_ptr(t, addr, width, &v) && page_granular(v) )
            {
                found = v;
                got   = true;
                return true;        // accept the hit: this ends the replay
            }
            return false;
        };

        MemoryWatchpointData wp{};
        wp.Address    = GuestAddress{ addr };
        wp.Size       = width;
        wp.AccessMask = DataAccessMask::Read;
        // Only the thread that made the call can read its own out-param, and
        // confining the replay to it keeps the step budget from being spent
        // somewhere else entirely.
        wp.ThreadId   = (UniqueThreadId)tid;
        cur->AddMemoryWatchpoint(wp);
        cur->SetMemoryWatchpointCallback(on_read);
        cur->SetEventMask(EventMask::MemoryWatchpoint);
        cur->SetReplayFlags(ReplayFlags::ReplayOnlyCurrentThread
                          | ReplayFlags::ReplaySegmentsSequentially);
        cur->SetPositionOnThread((UniqueThreadId)tid, from);
        cur->ReplayForward(Position::Max, (StepCount)0x2000);
        cur->SetMemoryWatchpointCallback(nullptr, 0);

        if ( got )
            *out = found;
        return got;
    }

    //-----------------------------------------------------------------------
    bool build_memory_map(TraceManager *mgr, MemoryMap *out, bool *cancelled)
    {
        if ( out != nullptr )
            out->clear();
        if ( cancelled != nullptr )
            *cancelled = false;

        if ( mgr == nullptr || !mgr->is_active() )
        {
            warning("The memory map can only be built while replaying a trace.");
            return false;
        }

        SweepState st;

        // ---- find the syscalls, in every ntdll the recording loaded ---------
        //
        // Every one, not the first: a WoW64 recording has a 32-bit and a 64-bit
        // ntdll under the same base name, with different calling conventions,
        // and the calls alternate between them.
        {
            UniqueCursor sym = mgr->make_cursor();
            if ( !sym )
                return false;
            for ( const TraceManager::ModuleLoad &ml : mgr->module_loads() )
            {
                if ( _stricmp(ml.name.c_str(), "ntdll.dll") != 0 )
                    continue;
                // Exports can only be read where the module is mapped.
                sym->SetPosition(ml.pos);
                GuestPeInfo pe;
                bool havePe = read_guest_pe_info(sym.get(), ml.base, &pe);
                bool is64   = havePe ? pe.is64 : mgr->is64();
                for ( const WatchDesc &d : kWatches )
                {
                    ea_t a = resolve_export_va(sym.get(), ml.base, is64, d.name);
                    if ( a == BADADDR )
                        continue;
                    st.watched[a]     = &d;
                    st.watchedIs64[a] = is64;
                    if ( st.lo == BADADDR || a < st.lo ) st.lo = a;
                    if ( a > st.hi )                     st.hi = a;
                }
            }
        }
        if ( st.watched.empty() )
        {
            warning("Could not find ntdll's memory syscalls in this recording, so "
                    "there is no way to reconstruct the memory map.\n\n"
                    "This happens when ntdll's export table was never read during "
                    "recording.");
            return false;
        }

        UniqueCursor sweep = mgr->make_cursor();
        if ( !sweep )
            return false;

        // Which module an address belongs to, answered from a table built HERE,
        // on the main thread. The callback runs on the replay worker while the
        // main thread is pumping the UI behind the wait box, and TraceManager's
        // own module lookups build a cache lazily -- walking that from two
        // threads is exactly the kind of bug that never reproduces.
        const std::vector<std::pair<ea_t, ea_t>> mods = mgr->module_ranges();

        auto module_of = [&mods](ea_t ea) noexcept -> size_t
        {
            // Last module whose base <= ea, then check ea falls inside it.
            size_t lo = 0, hi = mods.size();
            while ( lo < hi )
            {
                size_t mid = lo + (hi - lo) / 2;
                if ( mods[mid].first <= ea )
                    lo = mid + 1;
                else
                    hi = mid;
            }
            if ( lo == 0 )
                return (size_t)-1;
            --lo;
            return ea < mods[lo].second ? lo : (size_t)-1;
        };

        // ---- the sweep ------------------------------------------------------
        std::map<uint32_t, std::vector<Frame>> frames;   // per-thread watched calls

        // Every call in the recording, per thread, so a watched call can be
        // given the chain that led to it. The map lookup is cached because this
        // runs on EVERY call in the trace and threads execute in bursts.
        std::map<uint32_t, std::vector<ShadowFrame>> shadow;
        uint32_t                    lastTid   = 0xFFFFFFFF;
        std::vector<ShadowFrame>   *lastStack = nullptr;

        auto stack_for = [&shadow, &lastTid, &lastStack](uint32_t tid)
                         -> std::vector<ShadowFrame> *
        {
            if ( tid != lastTid || lastStack == nullptr )
            {
                lastStack = &shadow[tid];
                lastTid   = tid;
            }
            return lastStack;
        };

        auto retire = [&st](size_t idx) noexcept
        {
            if ( !st.retries[idx].live )
                return;
            st.retries[idx].live = false;
            if ( st.outstanding != 0 )
                st.outstanding--;
        };

        auto add_retry = [&st, &retire](uint64_t addr, uint32_t tid, uint32_t width,
                                        size_t rec, bool isBase) noexcept
        {
            try
            {
                // A wrapper reuses one stack local for every call it makes, so an
                // older request watching this slot would happily pick up a newer
                // call's value. Retire it: a missing region is a gap, a WRONG one
                // displaces a real region silently.
                auto it = st.byThread.find(tid);
                if ( it != st.byThread.end() )
                {
                    for ( size_t i : it->second )
                        if ( st.retries[i].live && st.retries[i].addr == addr )
                            retire(i);
                }
                Retry r;
                r.addr     = addr;
                r.tid      = tid;
                r.width    = width;
                r.rec      = rec;
                r.isBase   = isBase;
                r.attempts = 256;
                r.live     = true;
                st.retries.push_back(r);
                st.byThread[tid].push_back(st.retries.size() - 1);
                st.outstanding++;
            }
            catch ( ... )
            {
                st.truncated = true;
            }
        };

        auto poll_retries = [&st, &retire](IThreadView const *t, uint32_t tid) noexcept
        {
            if ( st.outstanding == 0 )
                return;
            auto it = st.byThread.find(tid);
            if ( it == st.byThread.end() )
                return;
            for ( size_t i : it->second )
            {
                Retry &r = st.retries[i];
                if ( !r.live )
                    continue;
                uint64_t v = 0;
                if ( read_ptr(t, r.addr, r.width, &v) && page_granular(v) )
                {
                    Rec &rec = st.recs[r.rec];
                    if ( r.isBase ) { rec.base = v; rec.baseOk = true; }
                    else            { rec.size = v; rec.sizeOk = true; }
                    retire(i);
                }
                else if ( --r.attempts <= 0 )
                {
                    // Past a few hundred callbacks the slot may belong to
                    // something else entirely. Hand it to the slower routes.
                    retire(i);
                }
            }
        };

        auto on_call_ret = [&](GuestAddress instr, GuestAddress fall_through,
                               IThreadView const *t) noexcept
        {
            uint32_t tid = (uint32_t)t->GetThreadInfo().UniqueId;
            try
            {
                if ( (uint64_t)fall_through != 0 )
                {
                    // A CALL. 'instr' is the callee.
                    ea_t tgt = (ea_t)(uint64_t)instr;

                    // Whichever instruction the position sits on, this lands in
                    // the CALLER: the program counter when it is not the callee
                    // itself, otherwise the address the call returns to, which is
                    // the instruction after the call site.
                    ea_t pc   = (ea_t)(uint64_t)t->GetProgramCounter();
                    ea_t site = pc != tgt ? pc : (ea_t)(uint64_t)fall_through;

                    std::vector<ShadowFrame> *sh = stack_for(tid);

                    // Drop frames the stack has already left behind.
                    //
                    // Matching returns is not enough on its own: a call that
                    // never returns, an exception unwind and a tail jump all
                    // leave a frame that no return will ever match, and without
                    // this the stack only grows -- first reporting a chain of
                    // long-dead frames, then hitting the depth cap and freezing.
                    // The stack pointer settles it. It grows downward, so a frame
                    // recorded at a lower value than the current one is below the
                    // stack pointer and cannot still be live.
                    uint64_t sp = (uint64_t)t->GetStackPointer();
                    while ( !sh->empty() && sh->back().sp < sp )
                        sh->pop_back();

                    ShadowFrame sf;
                    sf.retAddr = (uint64_t)fall_through;
                    sf.sp      = sp;
                    sf.site    = site;
                    // At the cap, slide rather than stop: the frames worth having
                    // are the innermost ones, and refusing to push would freeze
                    // the chain at whatever was there when the depth was reached.
                    if ( sh->size() >= kMaxDepth )
                        sh->erase(sh->begin());
                    sh->push_back(sf);

                    if ( tgt < st.lo || tgt > st.hi )
                    {
                        poll_retries(t, tid);
                        return;
                    }
                    auto w = st.watched.find(tgt);
                    if ( w != st.watched.end() )
                    {
                        Frame f;
                        f.d       = w->second;
                        f.is64    = st.watchedIs64[tgt];
                        f.retAddr = (uint64_t)fall_through;
                        f.pc      = site;
                        f.api     = tgt;
                        f.callPos = t->GetPosition();
                        // Innermost first, starting with the call we are on,
                        // then one frame per module the chain crosses into. The
                        // frame kept for a module is the innermost one in it,
                        // which is the code that called onward -- for the CRT
                        // that is malloc itself, and for the program its own
                        // call site.
                        f.chain_n = 0;
                        size_t lastMod = (size_t)-2;    // distinct from "none"
                        for ( size_t k = sh->size();
                              k-- > 0 && f.chain_n < RegionChange::MAX_CHAIN; )
                        {
                            ea_t   s  = (*sh)[k].site;
                            size_t mi = module_of(s);
                            if ( f.chain_n != 0 && mi == lastMod )
                                continue;
                            f.chain[f.chain_n++] = s;
                            lastMod = mi;
                        }
                        capture_args(t, f.is64, f.d->nargs, f.retAddr, f.args);
                        frames[tid].push_back(f);
                    }
                    poll_retries(t, tid);
                    return;
                }

                // A RET. 'instr' is the address being returned to. Unwind the
                // shadow stack to the frame that expected it, dropping anything
                // above -- a return can leave several frames at once when the
                // recording unwinds an exception or longjmps.
                {
                    std::vector<ShadowFrame> *sh = stack_for(tid);
                    for ( size_t k = sh->size(); k-- > 0; )
                    {
                        if ( (*sh)[k].retAddr == (uint64_t)instr )
                        {
                            sh->resize(k);
                            break;
                        }
                    }
                }

                // Pair it with the innermost in-flight watched call that
                // expected it.
                auto fit = frames.find(tid);
                if ( fit == frames.end() || fit->second.empty() )
                {
                    poll_retries(t, tid);
                    return;
                }
                Frame &f = fit->second.back();
                if ( (uint64_t)instr != f.retAddr )
                {
                    poll_retries(t, tid);
                    return;
                }
                Frame call = f;
                fit->second.pop_back();

                // NTSTATUS: anything negative failed, and a failed call changed
                // nothing.
                if ( (int32_t)(uint32_t)t->GetBasicReturnValue() < 0 )
                {
                    poll_retries(t, tid);
                    return;
                }
                if ( st.recs.size() >= kMaxRecs )
                {
                    st.truncated = true;
                    poll_retries(t, tid);
                    return;
                }

                uint32_t width = call.is64 ? 8 : 4;

                Rec rec;
                rec.d      = call.d;
                rec.is64   = call.is64;
                rec.tid    = tid;
                rec.pc     = call.pc;
                rec.api    = call.api;
                rec.retPos  = t->GetPosition();
                rec.callPos = call.callPos;
                rec.chain_n = call.chain_n;
                for ( uint8_t k = 0; k < call.chain_n; k++ )
                    rec.chain[k] = call.chain[k];
                rec.extra  = call.d->iExtra >= 0
                           ? (uint32_t)call.args[call.d->iExtra] : 0;
                rec.otherProcess = !is_current_process(call.args[call.d->iProc], call.is64);

                if ( !call.d->basePtr )
                {
                    // The address is the argument itself (an unmap).
                    rec.base   = call.args[call.d->iBase];
                    rec.baseOk = rec.base != 0;
                    rec.sizeOk = true;                 // there is no size
                    st.recs.push_back(rec);
                    poll_retries(t, tid);
                    return;
                }

                rec.pBase = call.args[call.d->iBase];
                rec.pSize = call.d->iSize >= 0 ? call.args[call.d->iSize] : 0;

                if ( rec.pBase != 0 && read_ptr(t, rec.pBase, width, &rec.base) )
                    rec.baseOk = !call.d->deferred || page_granular(rec.base);
                if ( rec.pSize == 0 )
                    rec.sizeOk = true;                 // a free may pass none
                else if ( read_ptr(t, rec.pSize, width, &rec.size) )
                    rec.sizeOk = !call.d->deferred || page_granular(rec.size);

                // A free's out-params were written by the CALLER before the call,
                // so what we just read is in the recording and is the answer.
                // Only the kernel-written ones need chasing.
                st.recs.push_back(rec);
                size_t idx = st.recs.size() - 1;
                if ( call.d->deferred )
                {
                    if ( !st.recs[idx].baseOk && rec.pBase != 0 )
                        add_retry(rec.pBase, tid, width, idx, true);
                    if ( !st.recs[idx].sizeOk && rec.pSize != 0 )
                        add_retry(rec.pSize, tid, width, idx, false);
                }
                poll_retries(t, tid);
            }
            catch ( ... )
            {
                st.truncated = true;
            }
        };

        const uint64_t lastSeq = (uint64_t)mgr->last_position().Sequence;
        std::atomic<uint32_t> pct{ 0 };
        std::atomic<bool>     done{ false };

        auto on_progress = [&pct, lastSeq](Position const &p) noexcept
        {
            if ( lastSeq > 0 )
            {
                uint64_t seq = (uint64_t)p.Sequence;
                pct.store((uint32_t)(seq >= lastSeq ? 100 : seq * 100 / lastSeq),
                          std::memory_order_relaxed);
            }
        };

        // Sequential replay is load-bearing: the default dispatches this callback
        // from several threads at once and every container above is
        // unsynchronized. Filtering is off because there is no EventMask bit for
        // call/return -- the engine has nothing to filter on and replays every
        // instruction either way.
        sweep->SetReplayFlags(ReplayFlags::ReplayAllSegmentsWithoutFiltering
                            | ReplayFlags::ReplaySegmentsSequentially);
        sweep->SetCallReturnCallback(on_call_ret);
        sweep->SetReplayProgressCallback(on_progress);
        sweep->SetPosition(Position::Min);

        bool stopped = false;
        {
            ICursorView *raw = sweep.get();
            std::thread worker([raw, &done]()
            {
                // 'done' MUST be set on every exit path: the main thread spins on
                // it and would otherwise wait forever behind a wait box.
                try { raw->ReplayForward(); } catch ( ... ) {}
                done.store(true, std::memory_order_release);
            });

            show_wait_box("Reconstructing the memory map (Cancel to stop)...");
            uint32_t shown = 101;
            while ( !done.load(std::memory_order_acquire) )
            {
                if ( !stopped && user_cancelled() )
                {
                    stopped = true;
                    replace_wait_box("HIDECANCEL\nFinishing the current segment...");
                    raw->InterruptReplay();
                }
                if ( !stopped )
                {
                    uint32_t now = pct.load(std::memory_order_relaxed);
                    if ( now != shown )
                    {
                        replace_wait_box("Reconstructing the memory map "
                                         "(Cancel to stop)... %u%%", now);
                        shown = now;
                    }
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            worker.join();
            hide_wait_box();
        }

        // Detach both callbacks before the lambdas they point at go out of scope.
        sweep->SetCallReturnCallback(nullptr, 0);
        sweep->SetReplayProgressCallback(nullptr, 0);
        sweep.reset();

        // ---- whatever the in-replay retry did not catch ----------------------
        size_t viaPolicy = 0, viaReplay = 0, snapped = 0, dropped = 0;
        {
            UniqueCursor cur;
            size_t n = st.recs.size();
            show_wait_box("Resolving %d memory call(s)... (Cancel to stop)", (int)n);
            for ( size_t i = 0; i < n; i++ )
            {
                if ( user_cancelled() )
                {
                    stopped = true;
                    break;
                }
                if ( (i & 0x3F) == 0 )
                    replace_wait_box("Resolving memory call %d of %d... "
                                     "(Cancel to stop)", (int)i + 1, (int)n);

                Rec &r = st.recs[i];
                if ( (r.baseOk && r.sizeOk) || r.d == nullptr || !r.d->deferred )
                    continue;

                uint32_t width = r.is64 ? 8 : 4;
                if ( !cur )
                    cur = mgr->make_cursor();
                if ( !cur )
                    break;
                cur->SetPosition(r.retPos);

                // InFragmentAggressive searches the whole fragment INCLUDING
                // future steps, which is where the caller's read-back usually is.
                // GloballyAggressive widens that at lower confidence. Both are
                // still only accepted when page-granular, because neither can
                // tell the kernel's write from the caller's own earlier store.
                static const QueryMemoryPolicy pols[] =
                {
                    QueryMemoryPolicy::InFragmentAggressive,
                    QueryMemoryPolicy::GloballyAggressive,
                };
                for ( QueryMemoryPolicy pol : pols )
                {
                    uint64_t v = 0;
                    if ( !r.baseOk && r.pBase != 0
                      && read_ptr_policy(cur.get(), r.pBase, width, pol, &v)
                      && page_granular(v) )
                    {
                        r.base = v; r.baseOk = true; viaPolicy++;
                    }
                    if ( !r.sizeOk && r.pSize != 0
                      && read_ptr_policy(cur.get(), r.pSize, width, pol, &v)
                      && page_granular(v) )
                    {
                        r.size = v; r.sizeOk = true; viaPolicy++;
                    }
                    if ( r.baseOk && r.sizeOk )
                        break;
                }

                if ( !r.baseOk && r.pBase != 0
                  && recover_by_readback(mgr, r.retPos, r.tid, r.pBase, width, &r.base) )
                {
                    r.baseOk = true; viaReplay++;
                }
                if ( !r.sizeOk && r.pSize != 0
                  && recover_by_readback(mgr, r.retPos, r.tid, r.pSize, width, &r.size) )
                {
                    r.sizeOk = true; viaReplay++;
                }
            }
            hide_wait_box();
        }

        // ---- turn what we have into changes ---------------------------------
        auto in_module = [&mods](ea_t lo, ea_t hi)
        {
            for ( const auto &m : mods )
                if ( lo < m.second && m.first < hi )
                    return true;
            return false;
        };

        // Apply each calling module's export names once. Without this the
        // listing can only show an address: the plugin names a module's exports
        // when you stop inside it, and you have never stopped in most of these.
        {
            std::set<ea_t> bases;
            for ( const Rec &r : st.recs )
            {
                ea_t alo = 0, ahi = 0;
                if ( r.api != BADADDR && mgr->module_range_at(r.api, alo, ahi) )
                    bases.insert(alo);
                for ( uint8_t k = 0; k < r.chain_n; k++ )
                {
                    ea_t mlo = 0, mhi = 0;
                    if ( r.chain[k] != BADADDR
                      && mgr->module_range_at(r.chain[k], mlo, mhi) )
                    {
                        bases.insert(mlo);
                    }
                }
            }
            for ( ea_t b : bases )
            {
                mgr->resolve_symbols(b, mgr->is64());
                // Exports alone are not enough here. The code that allocates is
                // usually an internal helper, and the nearest export below it
                // can be a completely unrelated function -- which is exactly how
                // an allocation gets attributed to something like
                // RtlNtStatusToDosErrorNoTeb. A PDB names the real one. Silent
                // and deduplicated; a no-op with no symbol path configured.
                mgr->load_module_pdb(b);
            }
        }

        std::vector<RegionChange> changes;
        changes.reserve(st.recs.size());
        for ( Rec &r : st.recs )
        {
            if ( r.d == nullptr )
                continue;
            bool exact = true;

            if ( !r.baseOk || (r.d->iSize >= 0 && r.d->deferred && !r.sizeOk) )
            {
                // Nothing readable at all is the only case worth giving up on:
                // without a base there is no region and without a size there is
                // nothing to bound it with.
                if ( r.base == 0 || (r.d->iSize >= 0 && r.size == 0 && r.d->deferred) )
                {
                    dropped++;
                    continue;
                }
                // What survived is the caller's own request, and the kernel's
                // answer is that request snapped to pages: the base down to the
                // page holding it, the size up to cover the last byte asked for.
                // A floor, never an overstatement.
                uint64_t nb = page_floor(r.base);
                r.size = page_ceiling(r.size + (r.base - nb));
                r.base = nb;
                exact = false;
                snapped++;
            }

            RegionChange c;
            c.pos           = r.retPos;
            c.call_pos      = r.callPos;
            c.api           = r.api;
            c.chain_n       = r.chain_n;
            for ( uint8_t k = 0; k < r.chain_n; k++ )
                c.chain[k] = r.chain[k];
            c.tid           = r.tid;
            c.pc            = r.pc;
            c.kind          = r.d->kind;
            c.base          = (ea_t)r.base;
            c.size          = r.size;
            c.protect       = r.extra;
            c.exact         = exact;
            c.other_process = r.otherProcess;
            c.in_module     = c.size != 0
                            ? in_module(c.base, (ea_t)(c.base + c.size))
                            : in_module(c.base, c.base + 1);
            changes.push_back(c);
        }

        if ( out != nullptr )
            out->set_changes(std::move(changes));
        if ( cancelled != nullptr )
            *cancelled = stopped;

        msg("[ida-ttd] memory map: %d change(s) from %d call(s); %d out-param(s) "
            "needed a re-query, %d a replay, %d region(s) fell back to the "
            "caller's request, %d call(s) unresolved.\n",
            (int)(out != nullptr ? out->size() : 0), (int)st.recs.size(),
            (int)viaPolicy, (int)viaReplay, (int)snapped, (int)dropped);
        if ( st.truncated )
            msg("[ida-ttd] memory map: hit the %d-change limit; the map is "
                "incomplete.\n", (int)kMaxRecs);
        return true;
    }

    //-----------------------------------------------------------------------
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
            if ( c.chain[k] != BADADDR && !mgr->is_library_address(c.chain[k]) )
                return c.chain[k];
        }

        // Everything is library code. Then the useful frame is the first one
        // that left the module the syscall's own caller sits in: for a heap
        // allocation that is the CRT's malloc rather than ntdll's internals.
        ea_t lo0 = 0, hi0 = 0;
        if ( !mgr->module_range_at(c.chain[0], lo0, hi0) )
            return c.chain[c.chain_n - 1];
        for ( uint8_t k = 1; k < c.chain_n; k++ )
        {
            ea_t lo = 0, hi = 0;
            if ( c.chain[k] != BADADDR
              && mgr->module_range_at(c.chain[k], lo, hi) && lo != lo0 )
            {
                return c.chain[k];
            }
        }
        // The whole chain lived in one module -- an allocation a DLL made
        // entirely for itself. The outermost frame we saw is the most that can
        // be said, and saying it beats leaving the column empty.
        return c.chain[c.chain_n - 1];
    }

    //-----------------------------------------------------------------------
    uint64_t trace_fingerprint(TraceManager *mgr)
    {
        return mgr != nullptr ? mgr->trace_fingerprint() : 0;
    }
}
