// The Microsoft backend's syscalls (see msttd_syscalls.h): the listing, and
// the census the memory map is reconstructed from.
//
// Every callback runs on the engine's replay thread and is noexcept: it
// writes plain memory only, caps what it keeps and guards its growth, so an
// allocation failure stops collecting instead of terminating IDA.

#include "backend-msttd/msttd_syscalls.h"
#include "backend-msttd/msttd_backend.h"
#include "backend-msttd/msttd_sweep.h"
#include "backend-msttd/msttd_host.h"
#include "backend-msttd/msttd_guest.h"
#include "common/guest_pe.h"

using namespace TTD;
using namespace TTD::Replay;

namespace idattd
{
    // A program that makes syscalls in a loop can make millions. Past this
    // many the listing and the map are cut short (and say so).
    static const size_t kMaxKernelCalls = 1000000;

    // One frame of the per-thread shadow call stack, which gives a syscall
    // the chain of calls that led to it.
    struct ShadowFrame
    {
        uint64_t ret_addr;  // where this call will return to
        uint64_t sp;        // the stack pointer when it was made
        ea_t     site;      // the instruction that made it
    };
    // A call depth past this is pathological, and an unbounded vector grown
    // inside a noexcept callback is the shape of bug that takes the whole
    // process down with no message.
    static const size_t kMaxDepth = 256;

    std::vector<uint32_t> SyscallTable::numbers_of(const char *name) const
    {
        std::vector<uint32_t> out;
        for ( const auto &[n, s] : names )
            if ( s == name )
                out.push_back(n);
        return out;
    }

    // How far into a stub its syscall instruction can be: past the number,
    // a check of whether to syscall or int 2e, and the branch.
    static const ea_t kStubSpan = 0x40;

    ea_t SyscallTable::stub_of(uint32_t n, ea_t pc) const
    {
        auto [lo, hi] = stubs.equal_range(n);
        for ( auto it = lo; it != hi; ++it )
            if ( it->second <= pc && pc < it->second + kStubSpan )
                return it->second;
        return BADADDR;
    }

    // The number a stub loads, or false when it does not start like one.
    // x64: mov r10, rcx; mov eax, imm32. x86: mov eax, imm32. A stub that
    // starts with an indirect jmp was hooked when the export table was
    // read; the hook's target is decoded instead, once.
    static bool decode_stub(const GuestRead &rd, uint64_t at, bool is64, uint32_t *ssn, bool hop = true)
    {
        uint8_t b[16];
        if ( !pe_read(rd, at, b, sizeof(b)) )
            return false;
        if ( is64 && b[0] == 0x4C && b[1] == 0x8B && b[2] == 0xD1 && b[3] == 0xB8 )
        {
            memcpy(ssn, b + 4, 4);
            return true;
        }
        if ( !is64 && b[0] == 0xB8 )
        {
            memcpy(ssn, b + 1, 4);
            return true;
        }
        if ( hop && b[0] == 0xFF && b[1] == 0x25 )
        {
            int32_t disp;
            memcpy(&disp, b + 2, 4);
            uint64_t slot = is64 ? at + 6 + (int64_t)disp : (uint64_t)(uint32_t)disp;
            uint64_t target = 0;
            if ( pe_read(rd, slot, &target, is64 ? 8 : 4) )
                return decode_stub(rd, target, is64, ssn, false);
        }
        return false;
    }

    // Every complete syscall stub in a module's image, by number. x64:
    // mov r10, rcx; mov eax, n; ... syscall at +0x12. x86: mov eax, n;
    // mov edx, Wow64Transition; call edx (one stub has a call $+5 between).
    static size_t scan_stubs(ICursorView *c, const ModuleInfo &ml, bool is64,
                             std::multimap<uint32_t, ea_t> *out)
    {
        std::vector<uint8_t> img(size_t(ml.size), 0);
        const uint64_t chunk = 0x10000;
        for ( uint64_t off = 0; off < ml.size; off += chunk )
        {
            size_t n = size_t(std::min<uint64_t>(chunk, ml.size - off));
            c->QueryMemoryBuffer(GuestAddress{ ml.base + off }, BufferView{ img.data() + off, n },
                                 QueryMemoryPolicy::GloballyAggressive);
        }
        size_t found = 0;
        auto imm = [&img](size_t at) { uint32_t v; memcpy(&v, img.data() + at, 4); return v; };
        for ( size_t i = 0; i + 0x20 < img.size(); i++ )
        {
            if ( is64 )
            {
                if ( img[i] == 0x4C && img[i + 1] == 0x8B && img[i + 2] == 0xD1 && img[i + 3] == 0xB8
                  && img[i + 0x12] == 0x0F && img[i + 0x13] == 0x05 )
                {
                    out->emplace(imm(i + 4) & 0xFFFF, ml.base + i);
                    found++;
                }
                continue;
            }
            if ( img[i] != 0xB8 )
                continue;
            size_t j = i + 5;
            if ( img[j] == 0xE8 && imm(j + 1) == 0 )
                j += 5;
            if ( img[j] == 0xBA && img[j + 5] == 0xFF && img[j + 6] == 0xD2 )
            {
                out->emplace(imm(i + 1) & 0xFFFF, ml.base + i);
                found++;
            }
        }
        return found;
    }

    bool build_syscall_table(const MsTtdBackend *backend, SyscallTable *out)
    {
        out->names.clear();
        out->stubs.clear();
        UniqueCursor sym = backend->new_engine_cursor();
        if ( !sym )
            return false;
        // Every ntdll the recording loaded (a WoW64 recording has a 32-bit
        // and a 64-bit one under the same name), and win32u, whose stubs are
        // win32k's: NtUser*, NtGdi*, numbered from 0x1000.
        for ( const ModuleInfo &ml : backend->modules() )
        {
            if ( _stricmp(ml.name.c_str(), "ntdll.dll") != 0 && _stricmp(ml.name.c_str(), "win32u.dll") != 0 )
                continue;
            // Exports can only be read where the module is mapped.
            sym->SetPosition(from_core(ml.loaded));
            GuestRead rd = msttd_read_plain(sym.get());
            GuestPeInfo pe;
            bool is64 = read_guest_pe_info(rd, ml.base, &pe) ? pe.is64 : backend->is64();
            // The names, from the exports. A 32-bit stub's number carries
            // WoW64's argument-conversion index in the high word, which is
            // not part of the syscall's number.
            std::vector<std::pair<ea_t, std::string>> exports;
            read_guest_exports(rd, ml.base, is64, &exports);
            std::multimap<uint32_t, ea_t> by_export;
            for ( const auto &[ea, name] : exports )
            {
                if ( name.size() < 3 || name[0] != 'N' || name[1] != 't' )
                    continue;
                uint32_t n = 0;
                if ( !decode_stub(rd, ea, is64, &n) )
                    continue;
                out->names.emplace(n & 0xFFFF, name);
                by_export.emplace(n & 0xFFFF, ea);
            }
            // The stubs themselves, from the image: a process can point
            // its exports elsewhere (thunks in a private region), and
            // then every syscall would look like one the program made
            // itself. Some numbers have two stubs.
            size_t found = scan_stubs(sym.get(), ml, is64, &out->stubs);
            if ( found == 0 )
                out->stubs.insert(by_export.begin(), by_export.end());
        }
        return !out->names.empty();
    }

    // The syscall at a KernelCall gap: its number, and where it returns to.
    // 'ctx' is the thread's context there.
    static void read_kernel_call(IThreadView const *t, const CROSS_PLATFORM_CONTEXT &ctx, bool is64,
                                 KernelCall *k) noexcept
    {
        k->pc = (ea_t)(uint64_t)t->GetProgramCounter();
        k->sp = (uint64_t)t->GetStackPointer();
        if ( is64 )
        {
            k->number = (uint32_t)ctx.Amd64Context.Rax;
            // syscall (0F 05) and its relatives are two bytes; the kernel
            // comes back to the next instruction.
            uint8_t ins[2] = { 0, 0 };
            MemoryBuffer mb = t->QueryMemoryBuffer(GuestAddress{ (uint64_t)k->pc }, BufferView{ ins, 2 });
            if ( mb.Memory.Size == 2
              && ((ins[0] == 0x0F && (ins[1] == 0x05 || ins[1] == 0x34)) || (ins[0] == 0xCD && ins[1] == 0x2E)) )
                k->ret_pc = (uint64_t)k->pc + 2;
            return;
        }
        // The high word is WoW64's; the number is the low one, the same
        // numbering as x64's.
        k->number = (uint32_t)ctx.X86Nt5Context.Eax & 0xFFFF;
        // The gap is at WoW64's transition, which the stub called: the word
        // on top of the stack is the return into the stub, which is where
        // the kernel's answer comes back.
        uint64_t ret = 0;
        if ( msttd_read_word(t, k->sp, 4, &ret) )
            k->ret_pc = ret;
    }

    // Its arguments as the kernel takes them, after read_kernel_call.
    static void read_kernel_call_args(IThreadView const *t, const CROSS_PLATFORM_CONTEXT &ctx, bool is64,
                                      KernelCall *k) noexcept
    {
        if ( is64 )
        {
            // The stub moved rcx to r10 (syscall overwrites rcx with the
            // return address). Arguments 5 and on are where the stub's caller
            // put them, past the return address and the shadow space; the
            // stub has not touched the stack.
            const AMD64_CONTEXT &c = ctx.Amd64Context;
            const uint64_t regs[4] = { c.R10, c.Rdx, c.R8, c.R9 };
            for ( size_t i = 0; i < 4; i++ )
                k->args[i] = regs[i];
            uint64_t slots[kKernelCallArgs - 4] = { 0 };
            t->QueryMemoryBuffer(GuestAddress{ k->sp + 0x28 }, BufferView{ slots, sizeof(slots) });
            for ( size_t i = 0; i < kKernelCallArgs - 4; i++ )
                k->args[4 + i] = slots[i];
            return;
        }
        // Argument n is at [esp+8+4n], past the return into the stub and the
        // stub's own return address.
        uint32_t slots[kKernelCallArgs] = { 0 };
        t->QueryMemoryBuffer(GuestAddress{ k->sp + 8 }, BufferView{ slots, sizeof(slots) });
        for ( size_t i = 0; i < kKernelCallArgs; i++ )
            k->args[i] = slots[i];
    }

    std::vector<std::pair<ea_t, ea_t>> module_ranges(const std::vector<ModuleInfo> &mods)
    {
        std::map<ea_t, ea_t> m;
        for ( const ModuleInfo &mi : mods )
            m.emplace(mi.base, mi.base + (ea_t)mi.size);
        return std::vector<std::pair<ea_t, ea_t>>(m.begin(), m.end());
    }

    QueryResult collect_kernel_calls(const MsTtdBackend *backend, const SyscallTable &table,
                                     const KernelCallOptions &opts,
                                     std::vector<KernelCall> *out, ProgressSink *progress)
    {
        const bool chains = opts.chains;
        QueryResult r;
        UniqueCursor census = backend->new_engine_cursor();
        if ( !census || out == nullptr )
            return r;
        const bool is64 = backend->is64();

        // Which module an address belongs to, from a table built before the
        // replay: the callback runs on the replay worker, so nothing it reads
        // may be built lazily.
        const std::vector<std::pair<ea_t, ea_t>> mods = module_ranges(backend->modules());
        auto module_of = [&mods](ea_t ea) noexcept -> size_t
        {
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

        std::vector<KernelCall> calls;
        bool truncated = false;

        // ---- the census: every transition into the kernel -------------------
        //
        // The shadow call stacks, when chains are wanted: every call pushes a
        // frame and every matching return pops it. The lookup is cached: it
        // runs on every call, and threads execute in bursts.
        std::map<uint32_t, std::vector<ShadowFrame>> shadow;
        uint32_t                  lastTid   = 0xFFFFFFFF;
        std::vector<ShadowFrame> *lastStack = nullptr;
        auto stack_for = [&](uint32_t tid) -> std::vector<ShadowFrame> *
        {
            if ( tid != lastTid || lastStack == nullptr )
            {
                lastStack = &shadow[tid];
                lastTid   = tid;
            }
            return lastStack;
        };

        auto on_call_ret = [&](GuestAddress instr, GuestAddress fall_through, IThreadView const *t) noexcept
        {
            try
            {
                const uint32_t utid = (uint32_t)t->GetThreadInfo().UniqueId;
                std::vector<ShadowFrame> *sh = stack_for(utid);
                if ( (uint64_t)fall_through != 0 )
                {
                    // A call. Whichever instruction the position sits on, the
                    // site is in the caller: the program counter when it is
                    // not the callee itself, else the instruction after the
                    // call.
                    ea_t tgt  = (ea_t)(uint64_t)instr;
                    ea_t pc   = (ea_t)(uint64_t)t->GetProgramCounter();
                    ea_t site = pc != tgt ? pc : (ea_t)(uint64_t)fall_through;
                    // Frames the stack has already left behind (a call that
                    // never returned, an unwind, a tail jump) are below the
                    // stack pointer: the stack grows down.
                    uint64_t sp = (uint64_t)t->GetStackPointer();
                    while ( !sh->empty() && sh->back().sp < sp )
                        sh->pop_back();
                    // At the cap, slide rather than stop: the frames worth
                    // having are the innermost ones.
                    if ( sh->size() >= kMaxDepth )
                        sh->erase(sh->begin());
                    sh->push_back(ShadowFrame{ (uint64_t)fall_through, sp, site });
                    if ( opts.on_call_ret )
                        opts.on_call_ret(t, utid, false, (uint64_t)instr);
                    return;
                }
                // A return: unwind to the frame that expected it, dropping
                // anything above (an exception or longjmp leaves several
                // frames at once).
                for ( size_t k = sh->size(); k-- > 0; )
                {
                    if ( sh->at(k).ret_addr == (uint64_t)instr )
                    {
                        sh->resize(k);
                        break;
                    }
                }
                if ( opts.on_call_ret )
                    opts.on_call_ret(t, utid, true, (uint64_t)instr);
            }
            catch ( ... )
            {
                truncated = true;
            }
        };

        auto on_gap = [&](GapKind, GapEventType type, IThreadView const *t) noexcept -> bool
        {
            if ( type != GapEventType::KernelCall )
                return false;
            if ( calls.size() >= kMaxKernelCalls )
            {
                truncated = true;
                return false;
            }
            try
            {
                KernelCall k;
                k.pos  = t->GetPosition();
                k.utid = (uint32_t)t->GetThreadInfo().UniqueId;
                k.tid  = (uint32_t)t->GetThreadInfo().Id;
                // The number first; the arguments only for the calls the
                // caller wants them for. One context fetch serves all three.
                const CROSS_PLATFORM_CONTEXT ctx = t->GetCrossPlatformContext();
                read_kernel_call(t, ctx, is64, &k);
                ittd_regs regs;
                regs_from_context(ctx, is64, &regs);
                memcpy(k.gp, regs.gp, sizeof(k.gp));
                k.rflags = regs.rflags;
                k.name = table.name_of(k.number);
                // x86: the gap is at the transition, outside every module;
                // the stub is where it returns to.
                k.stub = table.stub_of(k.number, is64 ? k.pc : (ea_t)k.ret_pc);
                if ( !opts.args_wanted || opts.args_wanted(k.number) )
                {
                    read_kernel_call_args(t, ctx, is64, &k);
                    if ( chains )
                    {
                        // From the call into the stub (or the syscall itself,
                        // when the program made its own), then one frame per
                        // module crossed: the innermost in each, the code
                        // that called onward.
                        const std::vector<ShadowFrame> *sh = stack_for(k.utid);
                        if ( !sh->empty() )
                            k.frame_ret = sh->back().ret_addr;
                        size_t lastMod = (size_t)-2;    // distinct from "none"
                        if ( k.stub == BADADDR )
                        {
                            k.chain[k.chain_n++] = k.pc;
                            lastMod = module_of(k.pc);
                        }
                        for ( size_t i = sh->size(); i-- > 0 && k.chain_n < ITTD_CHAIN_MAX; )
                        {
                            ea_t   s  = sh->at(i).site;
                            // The stub's own call into WoW64's transition.
                            if ( k.stub != BADADDR && k.stub <= s && s < k.stub + kStubSpan )
                                continue;
                            size_t mi = module_of(s);
                            if ( k.chain_n != 0 && mi == lastMod )
                                continue;
                            k.chain[k.chain_n++] = s;
                            lastMod = mi;
                        }
                    }
                }
                calls.push_back(k);
                if ( opts.on_syscall )
                    opts.on_syscall(calls.back(), t);
            }
            catch ( ... )
            {
                truncated = true;
            }
            return false;       // collecting them, not stopping on them
        };

        census->SetGapEventCallback(on_gap);
        census->SetGapKindMask(GapKindMask::All);
        census->SetGapEventMask(GapEventMask::KernelCall);
        census->SetEventMask(EventMask::Gap);
        if ( chains )
            census->SetCallReturnCallback(on_call_ret);
        // No filtering: a call/return callback gives the engine nothing to
        // filter on, and every stretch of a recording ends in kernel calls.
        census->SetReplayFlags(ReplayFlags::ReplayAllSegmentsWithoutFiltering
                             | ReplayFlags::ReplaySegmentsSequentially);
        bool complete = msttd_sweep(census.get(), TtdPosition::Min, TtdPosition::Max, progress);
        census->SetGapEventCallback(nullptr, 0);
        if ( chains )
            census->SetCallReturnCallback(nullptr, 0);
        census.reset();
        shadow.clear();

        std::stable_sort(calls.begin(), calls.end(),
                         [](const KernelCall &a, const KernelCall &b) { return a.pos < b.pos; });

        msttd_log("[ida-ttd] syscalls: %d in the recording, %d named%s.\n",
                  (int)calls.size(),
                  (int)std::count_if(calls.begin(), calls.end(), [](const KernelCall &c) { return c.name != nullptr; }),
                  truncated ? " (cut short)" : "");
        *out = std::move(calls);
        r.ran       = true;
        r.cancelled = !complete;
        r.truncated = truncated;
        return r;
    }

    // ---- the returns: each one's result ------------------------------------
    //
    // An execute watchpoint on every instruction the kernel returns to (the
    // stubs' few, plus any code that makes its own syscalls). A thread makes
    // one syscall at a time, so a return belongs to that thread's latest call
    // before it. 'calls' is in position order. False when stopped.
    static bool collect_kernel_returns(const MsTtdBackend *backend, std::vector<CensusSyscall> *callsp,
                                       ProgressSink *progress, bool *truncatedp)
    {
        std::vector<CensusSyscall> &calls = *callsp;
        const bool is64 = backend->is64();
        bool truncated = false;
        bool complete = true;
        std::map<uint32_t, std::vector<size_t>> per_thread;
        std::set<uint64_t> ret_pcs;
        for ( size_t i = 0; i < calls.size(); i++ )
        {
            per_thread[calls[i].utid].push_back(i);
            if ( calls[i].ret_pc != 0 )
                ret_pcs.insert(calls[i].ret_pc);
        }
        if ( !ret_pcs.empty() )
        {
            UniqueCursor ret = backend->new_engine_cursor();
            if ( ret )
            {
                std::map<uint32_t, size_t> next;   // per thread: its first call not settled
                auto on_exec = [&](ICursorView::MemoryWatchpointResult const &w, IThreadView const *t) noexcept -> bool
                {
                    try
                    {
                        uint32_t utid = (uint32_t)t->GetThreadInfo().UniqueId;
                        auto pt = per_thread.find(utid);
                        if ( pt == per_thread.end() )
                            return false;
                        const std::vector<size_t> &mine = pt->second;
                        size_t &k = next[utid];
                        TtdPosition here = t->GetPosition();
                        // A call whose return was never seen (the thread
                        // ended in it) is settled by the next one starting.
                        while ( k + 1 < mine.size() && calls[mine[k + 1]].pos < here )
                            k++;
                        if ( k >= mine.size() )
                            return false;
                        CensusSyscall &c = calls[mine[k]];
                        if ( c.returned || !(c.pos < here) || c.ret_pc != (uint64_t)w.Address )
                            return false;
                        CROSS_PLATFORM_CONTEXT ctx = t->GetCrossPlatformContext();
                        c.result   = is64 ? (uint64_t)ctx.Amd64Context.Rax : (uint64_t)ctx.X86Nt5Context.Eax;
                        c.returned = true;
                        k++;
                    }
                    catch ( ... )
                    {
                        truncated = true;
                    }
                    return false;
                };
                for ( uint64_t a : ret_pcs )
                {
                    MemoryWatchpointData wp{};
                    wp.Address    = GuestAddress{ a };
                    wp.Size       = 1;
                    wp.AccessMask = DataAccessMask::Execute;
                    ret->AddMemoryWatchpoint(wp);
                }
                ret->SetMemoryWatchpointCallback(on_exec);
                ret->SetEventMask(EventMask::MemoryWatchpoint);
                ret->SetReplayFlags(ReplayFlags::ReplaySegmentsSequentially);
                complete = msttd_sweep(ret.get(), TtdPosition::Min, TtdPosition::Max, progress);
                ret->SetMemoryWatchpointCallback(nullptr, 0);
            }
        }
        *truncatedp = truncated;
        return complete;
    }

    // The registers of the syscalls in the census, so the listing's argument
    // column costs no seek per row. Capped: it is a convenience.
    static const size_t kMaxCachedRegs = 250000;

    QueryResult MsTtdBackend::registers_at(const std::vector<Position> &positions,
                                           std::vector<ittd_regs> *out, ProgressSink *progress)
    {
        QueryResult r;
        if ( !m_engine || out == nullptr )
            return r;
        r.ran = true;
        out->assign(positions.size(), ittd_regs{});
        std::lock_guard<std::mutex> lock(m_regsMtx);
        for ( size_t i = 0; i < positions.size(); i++ )
        {
            if ( progress != nullptr && (i & 0xF) == 0 )
            {
                if ( progress->cancelled() )
                {
                    r.cancelled = true;
                    break;
                }
                progress->report(uint32_t(i * 100 / positions.size()));
            }
            TtdPosition p = from_core(positions[i]);
            auto it = m_syscallRegs.find({ (uint64_t)p.Sequence, (uint64_t)p.Steps });
            ittd_regs &o = (*out)[i];
            if ( it != m_syscallRegs.end() )
            {
                memcpy(o.gp, it->second.gp, sizeof(o.gp));
                o.rflags = it->second.rflags;
                o.have   = ITTD_REGS_GP;
                continue;
            }
            // One scratch cursor for every call, rather than one per batch.
            if ( !m_regsScratch )
                m_regsScratch = new_engine_cursor();
            if ( !m_regsScratch )
                break;
            m_regsScratch->SetPosition(p);
            regs_from_context(m_regsScratch->GetCrossPlatformContext(), m_info.is64, &o);
        }
        return r;
    }

    std::shared_ptr<const SyscallCensus> MsTtdBackend::cached_census()
    {
        std::lock_guard<std::mutex> lock(m_censusMtx);
        return m_census;
    }

    std::shared_ptr<const SyscallCensus> MsTtdBackend::syscall_census(bool need_memmap, ProgressSink *progress,
                                                                      QueryResult *qr)
    {
        *qr = QueryResult{};
        if ( std::shared_ptr<const SyscallCensus> c = cached_census() )
        {
            qr->ran       = true;
            qr->truncated = c->truncated;
            return c;
        }
        auto table = std::make_shared<SyscallTable>();
        const bool named = build_syscall_table(this, table.get());
        std::unique_ptr<MemmapHooks> mm = make_memmap_hooks(this, *table);
        if ( need_memmap && mm == nullptr )
        {
            // The map has nothing to look for; a replay now would serve only
            // a listing nobody asked for.
            auto none = std::make_shared<SyscallCensus>();
            none->table = table;
            return none;
        }
        if ( !named )
            msttd_log("[ida-ttd] syscalls: no ntdll stubs were readable in this recording, so they "
                      "are listed by number only.\n");

        KernelCallOptions opts;
        opts.args_wanted = [](uint32_t) { return false; };
        if ( mm != nullptr )
            mm->arm(&opts);
        std::vector<KernelCall> calls;
        QueryResult kr = collect_kernel_calls(this, *table, opts, &calls, progress);
        if ( !kr.ran )
            return nullptr;

        auto c = std::make_shared<SyscallCensus>();
        c->table     = table;
        c->truncated = kr.truncated;
        if ( mm != nullptr )
            c->memmap = mm->finish();
        c->calls.reserve(calls.size());
        for ( const KernelCall &k : calls )
        {
            CensusSyscall s;
            s.pos    = k.pos;
            s.ret_pc = k.ret_pc;
            s.name   = k.name;
            s.utid   = k.utid;
            s.tid    = k.tid;
            s.number = k.number;
            c->calls.push_back(s);
        }
        {
            std::lock_guard<std::mutex> lock(m_regsMtx);
            m_syscallRegs.clear();
            for ( const KernelCall &k : calls )
            {
                if ( m_syscallRegs.size() >= kMaxCachedRegs )
                    break;
                SyscallRegs &sr = m_syscallRegs[{ (uint64_t)k.pos.Sequence, (uint64_t)k.pos.Steps }];
                memcpy(sr.gp, k.gp, sizeof(sr.gp));
                sr.rflags = k.rflags;
            }
        }
        *qr = kr;
        if ( !kr.cancelled )
        {
            std::lock_guard<std::mutex> lock(m_censusMtx);
            m_census = c;
        }
        return c;
    }

    QueryResult MsTtdBackend::query_syscalls(std::vector<SyscallEvent> *out, ProgressSink *progress)
    {
        QueryResult r;
        if ( !m_engine || out == nullptr )
            return r;
        // The census and the return pass cost about the same, so each is
        // half the percentage, unless the census was already taken.
        std::shared_ptr<const SyscallCensus> c = cached_census();
        const bool fresh = c == nullptr;
        if ( fresh )
        {
            ScaledProgress first(progress, 0, 50);
            c = syscall_census(false, &first, &r);
            if ( c == nullptr || !r.ran )
                return r;
        }
        else
        {
            r.ran       = true;
            r.truncated = c->truncated;
        }
        const std::vector<CensusSyscall> *calls = &c->calls;
        std::vector<CensusSyscall> with_results;
        if ( !c->results && !r.cancelled )
        {
            with_results = c->calls;
            ScaledProgress second(progress, fresh ? 50 : 0, fresh ? 50 : 100);
            bool trunc = false;
            const bool complete = collect_kernel_returns(this, &with_results, &second, &trunc);
            r.cancelled = !complete;
            r.truncated = r.truncated || trunc;
            calls = &with_results;
            if ( complete )
            {
                // Kept in place of the census without results, unless another
                // query replaced or dropped that one meanwhile.
                auto done = std::make_shared<SyscallCensus>();
                done->table             = c->table;
                done->truncated         = c->truncated;
                done->memmap            = c->memmap;
                done->results           = true;
                done->results_truncated = trunc;
                done->calls             = std::move(with_results);
                calls = &done->calls;
                std::lock_guard<std::mutex> lock(m_censusMtx);
                if ( m_census == c )
                    m_census = done;
                c = std::move(done);
            }
        }
        else if ( c->results )
        {
            r.truncated = r.truncated || c->results_truncated;
        }

        size_t returned = 0;
        for ( const CensusSyscall &s : *calls )
            returned += s.returned ? 1 : 0;
        msttd_log("[ida-ttd] syscalls: %d listed, %d with a result%s.\n",
                  (int)calls->size(), (int)returned, r.truncated ? " (cut short)" : "");
        out->reserve(out->size() + calls->size());
        for ( const CensusSyscall &s : *calls )
        {
            SyscallEvent e;
            e.pos    = to_core(s.pos);
            e.result = s.result;
            e.number = s.number;
            e.tid    = s.tid;
            if ( s.name != nullptr )
                e.name = s.name;
            out->push_back(std::move(e));
        }
        return r;
    }
}
