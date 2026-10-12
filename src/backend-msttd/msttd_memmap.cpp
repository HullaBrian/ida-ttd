// The Microsoft backend's memory map: reconstructed from the five syscalls
// that shape a process's address space, because the Replay SDK reports no
// protections and no region list. Moved here from analysis/memmap.cpp, which
// keeps the model, the fold, the persistence and the listing -- everything
// that is the same for every backend -- and now asks
// ITraceBackend::query_mapping_changes for the changes.
//
// The replay's callbacks write plain memory only; Cancel and progress come
// through the ProgressSink, so nothing here touches IDA's UI.

#include "backend-msttd/msttd_backend.h"
#include "backend-msttd/msttd_sweep.h"
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
        //
        // 'deferred' marks the two whose out-params the kernel fills in. A free's
        // are written by the caller before the call, so they are in the recording
        // and need none of the recovery machinery below. Note that Map's process
        // handle is its second argument, not its first.
        static const WatchDesc kWatches[] =
        {
            { "NtAllocateVirtualMemory", ITTD_MAP_ALLOC,     6, 0, 1,  3,  5, true,  true  },
            { "NtProtectVirtualMemory",  ITTD_MAP_PROTECT,   5, 0, 1,  2,  3, true,  true  },
            { "NtFreeVirtualMemory",     ITTD_MAP_FREE,      4, 0, 1,  2,  3, true,  false },
            { "NtMapViewOfSection",      ITTD_MAP_MAPVIEW,  10, 1, 2,  6,  9, true,  true  },
            { "NtUnmapViewOfSection",    ITTD_MAP_UNMAPVIEW, 2, 0, 1, -1, -1, false, false },
        };

        static const uint64_t PAGE = 0x1000;

        // These syscalls round the caller's request to pages before writing it
        // back, so a value that is not page-granular provably did not come from
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
        static const size_t kMaxRecs = 200000;     // the memory map's own storage cap

        // The pending frame for one in-flight call.
        struct Frame
        {
            const WatchDesc *d;
            bool     is64;
            uint64_t retAddr;
            ea_t     pc;
            ea_t     api;
            TtdPosition callPos;
            uint64_t args[12];
            ea_t     chain[ITTD_CHAIN_MAX];
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

    // Last resort for one out-param: replay this thread forward a bounded number
    // of steps with a Read watchpoint on the slot, and take the value the guest
    // reads back. That read is the only recorded event the kernel's write ever
    // produces.
    static bool recover_by_readback(const MsTtdBackend *backend, const TtdPosition &from,
                                    uint32_t tid, uint64_t addr, uint32_t width,
                                    uint64_t *out)
    {
        UniqueCursor cur = backend->new_engine_cursor();
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
        cur->ReplayForward(TtdPosition::Max, (StepCount)0x2000);
        cur->SetMemoryWatchpointCallback(nullptr, 0);

        if ( got )
            *out = found;
        return got;
    }

    // Every module as [lo, hi), sorted by base, one per distinct base.
    static std::vector<std::pair<ea_t, ea_t>> module_ranges(const std::vector<ModuleInfo> &mods)
    {
        std::map<ea_t, ea_t> m;
        for ( const ModuleInfo &mi : mods )
            m.emplace(mi.base, mi.base + (ea_t)mi.size);
        return std::vector<std::pair<ea_t, ea_t>>(m.begin(), m.end());
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

        SweepState st;

        // ---- find the syscalls, in every ntdll the recording loaded ---------
        //
        // Every one, not the first: a WoW64 recording has a 32-bit and a 64-bit
        // ntdll under the same base name, with different calling conventions,
        // and the calls alternate between them.
        {
            UniqueCursor sym = new_engine_cursor();
            if ( !sym )
                return r;
            for ( const ModuleInfo &ml : all_modules )
            {
                if ( _stricmp(ml.name.c_str(), "ntdll.dll") != 0 )
                    continue;
                // Exports can only be read where the module is mapped.
                sym->SetPosition(from_core(ml.loaded));
                GuestPeInfo pe;
                bool havePe = read_guest_pe_info(msttd_read_plain(sym.get()), ml.base, &pe);
                bool is64   = havePe ? pe.is64 : m_info.is64;
                for ( const WatchDesc &d : kWatches )
                {
                    ea_t a = resolve_export_va(msttd_read_plain(sym.get()), ml.base, is64, d.name);
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
            msg("[ida-ttd] memory map: could not find ntdll's memory syscalls in this "
                "recording (its export table was never read during recording).\n");
            return r;
        }

        UniqueCursor sweep = new_engine_cursor();
        if ( !sweep )
            return r;

        // Which module an address belongs to, answered from a table built here
        // before the replay starts: the callback runs on the replay worker, and
        // nothing it reads may be built lazily from two threads.
        const std::vector<std::pair<ea_t, ea_t>> mods = module_ranges(all_modules);

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
        // runs on every call in the trace and threads execute in bursts.
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
                // call's value. Retire it: a missing region is a gap, a wrong one
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
            uint32_t tid = (uint32_t)t->GetThreadInfo().UniqueId;   // as SetPositionOnThread wants it
            uint32_t os_tid = (uint32_t)t->GetThreadInfo().Id;
            try
            {
                if ( (uint64_t)fall_through != 0 )
                {
                    // A CALL. 'instr' is the callee.
                    ea_t tgt = (ea_t)(uint64_t)instr;

                    // Whichever instruction the position sits on, this lands in
                    // the caller: the program counter when it is not the callee
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
                              k-- > 0 && f.chain_n < ITTD_CHAIN_MAX; )
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
                rec.os_tid = os_tid;
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

                // A free's out-params were written by the caller before the call,
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

        // Sequential replay is load-bearing: the default dispatches this callback
        // from several threads at once and every container above is
        // unsynchronized. Filtering is off because there is no EventMask bit for
        // call/return -- the engine has nothing to filter on and replays every
        // instruction either way.
        sweep->SetReplayFlags(ReplayFlags::ReplayAllSegmentsWithoutFiltering
                            | ReplayFlags::ReplaySegmentsSequentially);
        sweep->SetCallReturnCallback(on_call_ret);

        bool complete = msttd_sweep(sweep.get(), TtdPosition::Min, TtdPosition::Max, progress);

        sweep->SetCallReturnCallback(nullptr, 0);
        sweep.reset();

        // Cancelling either the replay or the resolve pass below leaves a partial
        // map, which the caller is told about so it is not saved as a whole one.
        bool stopped = !complete;

        // ---- whatever the in-replay retry did not catch ----------------------
        size_t viaPolicy = 0, viaReplay = 0, snapped = 0, dropped = 0;
        {
            UniqueCursor cur;
            size_t n = st.recs.size();
            for ( size_t i = 0; i < n && !stopped; i++ )
            {
                if ( progress != nullptr && progress->cancelled() )
                {
                    stopped = true;
                    break;
                }
                if ( progress != nullptr && (i & 0x3F) == 0 )
                    progress->report((uint32_t)(i * 100 / n));

                Rec &r = st.recs[i];
                if ( (r.baseOk && r.sizeOk) || r.d == nullptr || !r.d->deferred )
                    continue;

                uint32_t width = r.is64 ? 8 : 4;
                if ( !cur )
                    cur = new_engine_cursor();
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
                  && recover_by_readback(this, r.retPos, r.tid, r.pBase, width, &r.base) )
                {
                    r.baseOk = true; viaReplay++;
                }
                if ( !r.sizeOk && r.pSize != 0
                  && recover_by_readback(this, r.retPos, r.tid, r.pSize, width, &r.size) )
                {
                    r.sizeOk = true; viaReplay++;
                }
            }
        }

        // ---- turn what we have into changes ---------------------------------
        auto in_module = [&mods](ea_t lo, ea_t hi)
        {
            for ( const auto &m : mods )
                if ( lo < m.second && m.first < hi )
                    return true;
            return false;
        };

        out->reserve(out->size() + st.recs.size());
        size_t before = out->size();
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

            ittd_mapping_change c{};
            Position p  = to_core(r.retPos);
            Position cp = to_core(r.callPos);
            c.pos      = ittd_position{ p.hi, p.lo };
            c.call_pos = ittd_position{ cp.hi, cp.lo };
            c.api      = r.api == BADADDR ? ITTD_BADADDR : (uint64_t)r.api;
            c.chain_n  = r.chain_n;
            for ( uint8_t k = 0; k < r.chain_n; k++ )
                c.chain[k] = (uint64_t)r.chain[k];
            c.tid      = r.os_tid;
            c.kind     = r.d->kind;
            c.base     = r.base;
            c.size     = r.size;
            c.protect  = r.extra;
            c.flags    = (exact ? ITTD_MAP_F_EXACT : 0)
                       | (r.otherProcess ? ITTD_MAP_F_OTHER_PROCESS : 0);
            bool inmod = c.size != 0 ? in_module((ea_t)c.base, (ea_t)(c.base + c.size))
                                     : in_module((ea_t)c.base, (ea_t)c.base + 1);
            if ( inmod )
                c.flags |= ITTD_MAP_F_IN_MODULE;
            // The calling instruction, which the listing shows, rides in
            // chain[0]: it is the innermost frame of the chain.
            out->push_back(c);
        }


        msg("[ida-ttd] memory map: %d change(s) from %d call(s); %d out-param(s) "
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
