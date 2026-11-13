// The Microsoft backend's memory map, reconstructed from the syscalls that
// shape the address space, because the Replay SDK reports no protections and
// no region list. The syscalls come from the recording's kernel transitions
// (msttd_syscalls.h), so memory a program maps with its own syscalls is
// included. analysis/memmap.cpp holds the backend-independent model, fold,
// persistence and listing, and asks query_mapping_changes for the changes.
//
// Callbacks write plain memory only; Cancel and progress go through the
// ProgressSink, so nothing here touches IDA's UI.

#include "backend-msttd/msttd_backend.h"
#include "backend-msttd/msttd_sweep.h"
#include "backend-msttd/msttd_syscalls.h"
#include "backend-msttd/msttd_host.h"
#include "backend-msttd/msttd_guest.h"
#include "common/symbols.h"

using namespace TTD;
using namespace TTD::Replay;

namespace idattd
{
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
        // NtAllocateVirtualMemoryEx(HANDLE, PVOID* Base, PSIZE_T Size, ULONG, ULONG Protect, ...)
        // NtMapViewOfSectionEx   (HANDLE Section, HANDLE Process, PVOID* Base, PLARGE_INTEGER,
        //                         PSIZE_T ViewSize, ULONG, ULONG Protect, ...)
        // NtUnmapViewOfSectionEx (HANDLE Process, PVOID Base, ULONG)
        //
        // The indexes are the syscall's own arguments, as the kernel takes them.
        //
        // 'deferred' marks those whose out-params the kernel fills in. A free's
        // are written by the caller before the call, so they are recorded and
        // need no recovery. Map's process handle is its second argument.
        static const WatchDesc kWatches[] =
        {
            { "NtAllocateVirtualMemory", ITTD_MAP_ALLOC,     6, 0, 1,  3,  5, true,  true  },
            { "NtProtectVirtualMemory",  ITTD_MAP_PROTECT,   5, 0, 1,  2,  3, true,  true  },
            { "NtFreeVirtualMemory",     ITTD_MAP_FREE,      4, 0, 1,  2,  3, true,  false },
            { "NtMapViewOfSection",      ITTD_MAP_MAPVIEW,  10, 1, 2,  6,  9, true,  true  },
            { "NtUnmapViewOfSection",    ITTD_MAP_UNMAPVIEW, 2, 0, 1, -1, -1, false, false },
            { "NtAllocateVirtualMemoryEx", ITTD_MAP_ALLOC,   7, 0, 1,  2,  4, true,  true  },
            { "NtMapViewOfSectionEx",    ITTD_MAP_MAPVIEW,   9, 1, 2,  4,  6, true,  true  },
            { "NtUnmapViewOfSectionEx",  ITTD_MAP_UNMAPVIEW, 3, 0, 1, -1, -1, false, false },
        };

        static const uint64_t PAGE = 0x1000;

        // These syscalls round the request to pages before writing it back, so
        // a value that is not page-granular did not come from the kernel. That,
        // not "non-zero", is the acceptance test: an aggressive query cannot
        // tell the kernel's write from the caller's own earlier store (only the
        // latter is recorded), and accepting the request would silently report
        // a region short by the kernel's rounding.
        static bool page_granular(uint64_t v) { return v != 0 && (v % PAGE) == 0; }
        static uint64_t page_floor(uint64_t v)   { return v - (v % PAGE); }
        static uint64_t page_ceiling(uint64_t v)
        {
            uint64_t r = v % PAGE;
            return r == 0 ? v : v + (PAGE - r);
        }

        // A pseudo-handle of -1 is NtCurrentProcess. Anything else names another
        // process, and the call changed that map rather than ours.
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
            uint32_t tid = 0;                // UniqueId, for SetPositionOnThread
            uint32_t os_tid = 0;             // the OS id, which is what the core reports
            ea_t     pc = BADADDR;
            ea_t     api = BADADDR;
            TtdPosition retPos;
            TtdPosition callPos;
            ea_t     chain[ITTD_CHAIN_MAX] = { 0 };
            uint8_t  chain_n = 0;
            uint64_t pBase = 0, pSize = 0;   // addresses of the out-param slots
            uint64_t base = 0, size = 0;     // resolved values
            uint32_t extra = 0;              // protection, or free type
            bool     baseOk = false, sizeOk = false;
            bool     otherProcess = false;
        };

        // An out-param not readable yet, retried as the replay rolls forward:
        // the value becomes visible once the guest reads it back.
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
            std::vector<Rec> recs;

            std::vector<Retry> retries;
            std::map<uint32_t, std::vector<size_t>> byThread;
            size_t outstanding = 0;

            bool truncated = false;
        };

        // Hard cap: a recording that allocates in a loop can produce millions,
        // and a bad_alloc in a noexcept callback terminates the process.
        static const size_t kMaxRecs = 200000;     // the memory map's own storage cap
    }

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

    // Last resort for one out-param: replay the thread forward a bounded number
    // of steps with a Read watchpoint on the slot and take the value the guest
    // reads back, the only recorded trace of the kernel's write. 'cur' is the
    // caller's, reused across slots (a cursor per slot is not free, and there
    // can be hundreds of thousands); it is left with nothing armed. It must
    // not be one used for policy reads: a replayed cursor answers thread-locally.
    static bool recover_by_readback(ICursorView *cur, const TtdPosition &from,
                                    uint32_t tid, uint64_t addr, uint32_t width,
                                    uint64_t *out)
    {
        uint64_t found = 0;
        bool     got   = false;

        auto on_read = [&](ICursorView::MemoryWatchpointResult const &,
                           IThreadView const *t) noexcept -> bool
        {
            uint64_t v = 0;
            if ( msttd_read_word(t, addr, width, &v) && page_granular(v) )
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
        // Confined to the calling thread, which is the one that reads the
        // out-param, so the step budget is not spent elsewhere.
        wp.ThreadId   = (UniqueThreadId)tid;
        {
            ArmedSweep arm(cur, ReplayFlags::ReplayOnlyCurrentThread | ReplayFlags::ReplaySegmentsSequentially,
                           EventMask::MemoryWatchpoint);
            arm.watch(wp);
            arm.on_watchpoint(on_read);
            cur->SetPositionOnThread((UniqueThreadId)tid, from);
            cur->ReplayForward(TtdPosition::Max, (StepCount)0x2000);
        }

        if ( got )
            *out = found;
        return got;
    }

    // What syscalls wrote through out parameters (ReplayAPI.md, "the
    // kernel-write gap"). The kernel's write is not recorded where it
    // happened; the value first appears at a DataMismatch or NewData on the
    // slot, or where the program reads it. Each slot is watched on its thread
    // from the call, for a bounded number of steps. A program write first
    // means the kernel's value never surfaced: unknown, not the stale one.
    // Each slot costs a seek, so they are shared between cursors
    // (msttd_parallel).
    bool MsTtdBackend::query_out_values(const std::vector<OutSlot> &slots,
                                        std::vector<std::optional<uint64_t>> *out, ProgressSink *progress)
    {
        if ( !m_engine || out == nullptr )
            return false;
        out->assign(slots.size(), std::nullopt);
        // The slots in call order, so each worker's stretch is close together.
        std::vector<size_t> order(slots.size());
        for ( size_t i = 0; i < order.size(); i++ )
            order[i] = i;
        std::stable_sort(order.begin(), order.end(),
                         [&](size_t a, size_t b) { return slots[a].call < slots[b].call; });
        std::atomic<bool> made{ false };
        msttd_parallel(slots.size(), 8, progress,
            [&](size_t begin, size_t end, std::atomic<size_t> &done, const std::atomic<bool> &stop)
        {
            UniqueCursor cur = new_engine_cursor();
            if ( !cur )
                return;
            made = true;

            for ( size_t n = begin; n < end && !stop.load(); n++, done++ )
            {
                const size_t i = order[n];
                const OutSlot &sl = slots[i];
                if ( sl.addr == 0 || (sl.width != 4 && sl.width != 8) )
                    continue;
                // The thread that made the call, not another that had its id.
                const uint32_t utid = unique_thread_id(sl.tid, sl.call);
                if ( utid == 0 )
                    continue;
                bool        got = false;
                uint64_t    value = 0;
                TtdPosition wrote = TtdPosition::Invalid;
                auto on_hit = [&](ICursorView::MemoryWatchpointResult const &w, IThreadView const *t) noexcept -> bool
                {
                    const TtdPosition p = t->GetPosition();
                    // A write of the program's own, and nothing of the kernel's at
                    // the same position: the kernel's value is gone.
                    if ( wrote.IsValid() && !(p == wrote) )
                        return true;
                    uint64_t v = 0;
                    const bool ok = msttd_read_word(t, sl.addr, sl.width, &v);
                    switch ( w.AccessType )
                    {
                        case DataAccessType::DataMismatch:
                        case DataAccessType::NewData:
                        case DataAccessType::Read:
                            if ( ok )
                            {
                                value = v;
                                got = true;
                            }
                            return true;
                        case DataAccessType::Write:
                        case DataAccessType::Overwrite:
                            wrote = p;
                            return false;
                        default:
                            return false;
                    }
                };
                MemoryWatchpointData wp{};
                wp.Address    = GuestAddress{ (uint64_t)sl.addr };
                wp.Size       = sl.width;
                wp.AccessMask = (DataAccessMask)((uint8_t)DataAccessMask::Read | (uint8_t)DataAccessMask::Write
                                               | (uint8_t)DataAccessMask::Overwrite | (uint8_t)DataAccessMask::DataMismatch
                                               | (uint8_t)DataAccessMask::NewData);
                wp.ThreadId   = (UniqueThreadId)utid;
                {
                    ArmedSweep arm(cur.get(), ReplayFlags::ReplayOnlyCurrentThread
                                            | ReplayFlags::ReplaySegmentsSequentially,
                                   EventMask::MemoryWatchpoint);
                    arm.watch(wp);
                    arm.on_watchpoint(on_hit);
                    cur->SetPositionOnThread((UniqueThreadId)utid, from_core(sl.call));
                    cur->ReplayForward(TtdPosition::Max, (StepCount)0x4000);
                }
                if ( got )
                    (*out)[i] = value;
            }
        });
        // Cancelled, the slots not reached are unknown, as before.
        return slots.empty() || made.load();
    }

    // What the census replay settled for the map (see SyscallCensus).
    struct MemmapRecords
    {
        std::vector<Rec> recs;
        bool truncated = false;
    };

    namespace
    {
        // The census callbacks that settle each memory syscall. Everything
        // here runs on the replay thread, noexcept.
        class MemmapHooksImpl : public MemmapHooks
        {
        public:
            MemmapHooksImpl(const MsTtdBackend *backend, std::map<uint32_t, const WatchDesc *> by_number)
                : m_is64(backend->is64()), m_byNumber(std::move(by_number)) {}

            void arm(KernelCallOptions *opts) override
            {
                // One replay with the call/return callback, which both the
                // chains and the settling need.
                opts->args_wanted = [this](uint32_t n) { return desc_of(n) != nullptr; };
                opts->chains      = true;
                opts->on_syscall  = [this](const KernelCall &k, IThreadView const *t) noexcept { on_syscall(k, t); };
                opts->on_call_ret = [this](IThreadView const *t, uint32_t utid, bool is_return, uint64_t target) noexcept
                {
                    on_call_ret(t, utid, is_return, target);
                };
            }

            std::shared_ptr<const MemmapRecords> finish() override
            {
                auto r = std::make_shared<MemmapRecords>();
                r->recs      = std::move(m_st.recs);
                r->truncated = m_st.truncated;
                m_st = SweepState{};
                m_outNow.clear();
                return r;
            }

        private:
            const WatchDesc *desc_of(uint32_t n) const
            {
                auto it = m_byNumber.find(n);
                return it != m_byNumber.end() ? it->second : nullptr;
            }

            void retire(size_t idx) noexcept
            {
                if ( !m_st.retries[idx].live )
                    return;
                m_st.retries[idx].live = false;
                if ( m_st.outstanding != 0 )
                    m_st.outstanding--;
            }

            void add_retry(uint64_t addr, uint32_t tid, uint32_t width, size_t rec, bool isBase) noexcept
            {
                try
                {
                    // A wrapper reuses one stack local for every call, so an
                    // older retry on this slot would pick up a newer call's
                    // value. Retire it: a missing region is a gap, a wrong
                    // one silently displaces a real region.
                    auto it = m_st.byThread.find(tid);
                    if ( it != m_st.byThread.end() )
                    {
                        for ( size_t i : it->second )
                            if ( m_st.retries[i].live && m_st.retries[i].addr == addr )
                                retire(i);
                    }
                    Retry retry;
                    retry.addr     = addr;
                    retry.tid      = tid;
                    retry.width    = width;
                    retry.rec      = rec;
                    retry.isBase   = isBase;
                    retry.attempts = 256;
                    retry.live     = true;
                    m_st.retries.push_back(retry);
                    m_st.byThread[tid].push_back(m_st.retries.size() - 1);
                    m_st.outstanding++;
                }
                catch ( ... )
                {
                    m_st.truncated = true;
                }
            }

            // A kernel-written out-param is often not recorded when the
            // syscall returns, only once the program reads it back, so each
            // later call and return on the same thread looks again.
            void poll_retries(IThreadView const *t, uint32_t tid) noexcept
            {
                if ( m_st.outstanding == 0 )
                    return;
                auto it = m_st.byThread.find(tid);
                if ( it == m_st.byThread.end() )
                    return;
                for ( size_t i : it->second )
                {
                    Retry &retry = m_st.retries[i];
                    if ( !retry.live )
                        continue;
                    uint64_t v = 0;
                    if ( msttd_read_word(t, retry.addr, retry.width, &v) && page_granular(v) )
                    {
                        Rec &rec = m_st.recs[retry.rec];
                        if ( retry.isBase ) { rec.base = v; rec.baseOk = true; }
                        else                { rec.size = v; rec.sizeOk = true; }
                        retire(i);
                    }
                    else if ( --retry.attempts <= 0 )
                    {
                        // Past a few hundred callbacks the slot may belong to
                        // something else entirely. Hand it to the slower routes.
                        retire(i);
                    }
                }
                // Drop the settled ones: this runs on every call and return,
                // and would otherwise walk all of a thread's past retries
                // each time.
                std::vector<size_t> &mine = it->second;
                mine.erase(std::remove_if(mine.begin(), mine.end(),
                                          [this](size_t i) { return !m_st.retries[i].live; }),
                           mine.end());
            }

            void on_syscall(const KernelCall &k, IThreadView const *) noexcept
            {
                try
                {
                    if ( desc_of(k.number) != nullptr )
                        m_outNow[k.utid].push_back(k);
                }
                catch ( ... )
                {
                    m_st.truncated = true;
                }
            }

            void settle(const KernelCall &k, IThreadView const *t) noexcept
            {
                try
                {
                    const WatchDesc *d = desc_of(k.number);
                    if ( d == nullptr )
                        return;
                    // NTSTATUS: anything negative failed, and a failed call
                    // changed nothing.
                    if ( (int32_t)(uint32_t)t->GetBasicReturnValue() < 0 )
                        return;
                    if ( m_st.recs.size() >= kMaxRecs )
                    {
                        m_st.truncated = true;
                        return;
                    }
                    const bool is64 = m_is64;
                    const uint32_t width = is64 ? 8 : 4;
                    const uint64_t mask = is64 ? ~0ull : 0xFFFFFFFFull;

                    Rec rec;
                    rec.d       = d;
                    rec.is64    = is64;
                    rec.tid     = k.utid;
                    rec.os_tid  = k.tid;
                    rec.pc      = k.chain_n != 0 ? k.chain[0] : k.pc;
                    rec.api     = k.stub != BADADDR ? k.stub : k.pc;
                    rec.retPos  = t->GetPosition();
                    rec.callPos = k.pos;
                    rec.chain_n = k.chain_n;
                    for ( uint8_t i = 0; i < k.chain_n; i++ )
                        rec.chain[i] = k.chain[i];
                    rec.extra = d->iExtra >= 0 ? (uint32_t)k.args[d->iExtra] : 0;
                    rec.otherProcess = !is_current_process(k.args[d->iProc] & mask, is64);

                    if ( !d->basePtr )
                    {
                        // The address is the argument itself (an unmap).
                        rec.base   = k.args[d->iBase] & mask;
                        rec.baseOk = rec.base != 0;
                        rec.sizeOk = true;                 // there is no size
                        m_st.recs.push_back(rec);
                        return;
                    }

                    rec.pBase = k.args[d->iBase] & mask;
                    rec.pSize = d->iSize >= 0 ? k.args[d->iSize] & mask : 0;

                    if ( rec.pBase != 0 && msttd_read_word(t, rec.pBase, width, &rec.base) )
                        rec.baseOk = !d->deferred || page_granular(rec.base);
                    if ( rec.pSize == 0 )
                        rec.sizeOk = true;                 // a free may pass none
                    else if ( msttd_read_word(t, rec.pSize, width, &rec.size) )
                        rec.sizeOk = !d->deferred || page_granular(rec.size);

                    // A free's out-params were written by the caller, so what
                    // was just read is recorded and final. Only kernel-written
                    // ones need chasing.
                    m_st.recs.push_back(rec);
                    size_t idx = m_st.recs.size() - 1;
                    if ( d->deferred )
                    {
                        if ( !m_st.recs[idx].baseOk && rec.pBase != 0 )
                            add_retry(rec.pBase, k.utid, width, idx, true);
                        if ( !m_st.recs[idx].sizeOk && rec.pSize != 0 )
                            add_retry(rec.pSize, k.utid, width, idx, false);
                    }
                }
                catch ( ... )
                {
                    m_st.truncated = true;
                }
            }

            // The memory syscalls still out, per thread, innermost last
            // (m_outNow). Each is settled at the return from the call that
            // made it (the stub's return to its caller), where the result is
            // still in rax and the out-params are as the caller first sees
            // them.
            void on_call_ret(IThreadView const *t, uint32_t utid, bool is_return, uint64_t target) noexcept
            {
                poll_retries(t, utid);
                if ( !is_return )
                    return;
                auto it = m_outNow.find(utid);
                if ( it == m_outNow.end() || it->second.empty() )
                    return;
                // The innermost call this return leaves. An unwind can leave
                // several frames at once; syscalls in the frames above it
                // never came back the usual way.
                std::vector<KernelCall> &v = it->second;
                for ( size_t i = v.size(); i-- > 0; )
                {
                    if ( v[i].frame_ret != target )
                        continue;
                    settle(v[i], t);
                    v.resize(i);
                    return;
                }
            }

            const bool m_is64;
            const std::map<uint32_t, const WatchDesc *> m_byNumber;
            SweepState m_st;
            std::map<uint32_t, std::vector<KernelCall>> m_outNow;
        };
    }

    std::unique_ptr<MemmapHooks> make_memmap_hooks(const MsTtdBackend *backend, const SyscallTable &table)
    {
        // By number, not by watching ntdll's exports: a program that makes
        // its own syscalls never calls the export.
        std::map<uint32_t, const WatchDesc *> by_number;
        for ( const WatchDesc &d : kWatches )
            for ( uint32_t n : table.numbers_of(d.name) )
                by_number.emplace(n, &d);
        if ( by_number.empty() )
            return nullptr;
        return std::make_unique<MemmapHooksImpl>(backend, std::move(by_number));
    }

    QueryResult MsTtdBackend::query_mapping_changes(std::vector<ittd_mapping_change> *out,
                                                    std::vector<qstring> *files,
                                                    ProgressSink *progress)
    {
        qnotused(files);        // the syscalls do not say which file a view maps
        QueryResult r;
        if ( !m_engine || out == nullptr )
            return r;
        const std::vector<ModuleInfo> all_modules = modules();

        // ---- the syscalls, with their chains ---------------------------------
        //
        // From the census the syscall listing shares (msttd_syscalls.cpp):
        // whichever of the two runs first replays the recording, and the
        // other starts from what it kept.
        QueryResult kr;
        std::shared_ptr<const SyscallCensus> census = syscall_census(true, progress, &kr);
        if ( census != nullptr && census->memmap == nullptr )
        {
            msttd_log("[ida-ttd] memory map: could not find ntdll's memory syscalls in this "
                "recording (its export table was never read during recording).\n");
            set_error("could not find ntdll's memory syscalls in this recording "
                      "(its export table was never read during recording)");
            return r;
        }
        if ( census == nullptr || !kr.ran )
            return r;
        SweepState st;
        // A copy: the census is shared, and the passes below fill in the
        // records' values.
        st.recs      = census->memmap->recs;
        st.truncated = kr.truncated || census->memmap->truncated;
        const std::vector<std::pair<ea_t, ea_t>> mods = module_ranges(all_modules);

        // Cancelling the replay or the resolve pass leaves a partial map; the
        // caller is told so it is not saved as complete.
        bool stopped = kr.cancelled;

        // ---- whatever the in-replay retry did not catch ----------------------
        size_t snapped = 0, dropped = 0;
        std::atomic<size_t> viaPolicy{ 0 }, viaReplay{ 0 };
        {
            // The records whose kernel values the replay did not catch, each
            // needing a seek and maybe a replay of its own (17 ms and up on
            // Microsoft TTD): independent, so spread over worker cursors.
            std::vector<size_t> todo;
            for ( size_t i = 0; i < st.recs.size(); i++ )
            {
                const Rec &rc = st.recs[i];
                if ( !((rc.baseOk && rc.sizeOk) || rc.d == nullptr || !rc.d->deferred) )
                    todo.push_back(i);
            }
            const bool complete = stopped || todo.empty() || msttd_parallel(todo.size(), 8, progress,
                [&](size_t begin, size_t end, std::atomic<size_t> &done, const std::atomic<bool> &stop)
            {
                UniqueCursor cur = new_engine_cursor();
                UniqueCursor readback;      // recover_by_readback's, kept apart from 'cur'
                if ( !cur )
                    return;
                for ( size_t k = begin; k < end && !stop.load(); k++, done++ )
                {
                    Rec &rc = st.recs[todo[k]];
                    uint32_t width = rc.is64 ? 8 : 4;
                    cur->SetPosition(rc.retPos);

                    // InFragmentAggressive searches the whole fragment, including
                    // future steps where the caller's read-back usually is;
                    // GloballyAggressive widens that at lower confidence. Both are
                    // accepted only when page-granular (see page_granular).
                    static const QueryMemoryPolicy pols[] =
                    {
                        QueryMemoryPolicy::InFragmentAggressive,
                        QueryMemoryPolicy::GloballyAggressive,
                    };
                    for ( QueryMemoryPolicy pol : pols )
                    {
                        uint64_t v = 0;
                        if ( !rc.baseOk && rc.pBase != 0
                          && read_ptr_policy(cur.get(), rc.pBase, width, pol, &v)
                          && page_granular(v) )
                        {
                            rc.base = v; rc.baseOk = true; viaPolicy++;
                        }
                        if ( !rc.sizeOk && rc.pSize != 0
                          && read_ptr_policy(cur.get(), rc.pSize, width, pol, &v)
                          && page_granular(v) )
                        {
                            rc.size = v; rc.sizeOk = true; viaPolicy++;
                        }
                        if ( rc.baseOk && rc.sizeOk )
                            break;
                    }

                    if ( (rc.baseOk || rc.pBase == 0) && (rc.sizeOk || rc.pSize == 0) )
                        continue;
                    if ( !readback )
                        readback = new_engine_cursor();
                    if ( !readback )
                        continue;
                    if ( !rc.baseOk && rc.pBase != 0
                      && recover_by_readback(readback.get(), rc.retPos, rc.tid, rc.pBase, width, &rc.base) )
                    {
                        rc.baseOk = true; viaReplay++;
                    }
                    if ( !rc.sizeOk && rc.pSize != 0
                      && recover_by_readback(readback.get(), rc.retPos, rc.tid, rc.pSize, width, &rc.size) )
                    {
                        rc.sizeOk = true; viaReplay++;
                    }
                }
            });
            if ( !complete )
                stopped = true;
        }

        // ---- the records as changes -----------------------------------------
        auto in_module = [&mods](ea_t lo, ea_t hi)
        {
            for ( const auto &m : mods )
                if ( lo < m.second && m.first < hi )
                    return true;
            return false;
        };

        out->reserve(out->size() + st.recs.size());
        size_t before = out->size();
        for ( Rec &rc : st.recs )
        {
            if ( rc.d == nullptr )
                continue;
            bool exact = true;

            if ( !rc.baseOk || (rc.d->iSize >= 0 && rc.d->deferred && !rc.sizeOk) )
            {
                // Give up only when nothing was readable: no base means no
                // region, no size means nothing to bound it.
                if ( rc.base == 0 || (rc.d->iSize >= 0 && rc.size == 0 && rc.d->deferred) )
                {
                    dropped++;
                    continue;
                }
                // What survived is the caller's request; the kernel's answer is
                // that request snapped to pages (base down, end up). A floor,
                // never an overstatement.
                uint64_t nb = page_floor(rc.base);
                rc.size = page_ceiling(rc.size + (rc.base - nb));
                rc.base = nb;
                exact = false;
                snapped++;
            }
            else if ( !rc.d->deferred && rc.d->iSize >= 0 && rc.size != 0 )
            {
                // A free's base and size are the caller's request, which the
                // kernel rounds out to whole pages (base down, end up) before
                // acting on it: that rounding is the region it freed, and
                // still exact. Size 0 (the whole region) is left as it is.
                uint64_t nb = page_floor(rc.base);
                rc.size = page_ceiling(rc.size + (rc.base - nb));
                rc.base = nb;
            }

            ittd_mapping_change c{};
            Position p  = to_core(rc.retPos);
            Position cp = to_core(rc.callPos);
            c.pos      = ittd_position{ p.hi, p.lo };
            c.call_pos = ittd_position{ cp.hi, cp.lo };
            c.api      = rc.api == BADADDR ? ITTD_BADADDR : (uint64_t)rc.api;
            c.chain_n  = rc.chain_n;
            for ( uint8_t k = 0; k < rc.chain_n; k++ )
                c.chain[k] = (uint64_t)rc.chain[k];
            // No chain: the call came from a frame opened before the recording
            // began. The calling instruction is still known (the listing shows
            // it as the caller), so it becomes a one-frame chain.
            if ( c.chain_n == 0 && rc.pc != BADADDR )
            {
                c.chain[0] = (uint64_t)rc.pc;
                c.chain_n  = 1;
            }
            c.tid      = rc.os_tid;
            c.kind     = rc.d->kind;
            c.base     = rc.base;
            c.size     = rc.size;
            c.protect  = rc.extra;
            c.flags    = (exact ? ITTD_MAP_F_EXACT : 0)
                       | (rc.otherProcess ? ITTD_MAP_F_OTHER_PROCESS : 0);
            bool inmod = c.size != 0 ? in_module((ea_t)c.base, (ea_t)(c.base + c.size))
                                     : in_module((ea_t)c.base, (ea_t)c.base + 1);
            if ( inmod )
                c.flags |= ITTD_MAP_F_IN_MODULE;
            // The calling instruction, which the listing shows, rides in
            // chain[0]: it is the innermost frame of the chain.
            out->push_back(c);
        }

        // In position order, as the ABI requires: calls were recorded as they
        // returned, which interleaved threads can leave out of order.
        std::stable_sort(out->begin() + (ptrdiff_t)before, out->end(),
                         [](const ittd_mapping_change &a, const ittd_mapping_change &b)
        {
            return a.pos.hi != b.pos.hi ? a.pos.hi < b.pos.hi : a.pos.lo < b.pos.lo;
        });

        msttd_log("[ida-ttd] memory map: %d change(s) from %d call(s); %d out-param(s) "
            "needed a re-query, %d a replay, %d region(s) fell back to the "
            "caller's request, %d call(s) unresolved.\n",
            (int)(out->size() - before), (int)st.recs.size(),
            (int)viaPolicy, (int)viaReplay, (int)snapped, (int)dropped);
        r.ran       = true;
        r.cancelled = stopped;
        r.truncated = st.truncated;
        return r;
    }
}
