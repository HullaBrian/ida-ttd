// The Microsoft backend's syscalls (see msttd_syscalls.h): the listing, and
// the census the memory map is reconstructed from.
//
// Every callback below runs on the engine's replay thread and is noexcept:
// it writes plain memory only, caps what it keeps, and guards its growth, so
// an allocation failure stops the recording instead of terminating IDA.

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

    // Two replays reported as one percentage.
    class ScaledProgress : public ProgressSink
    {
    public:
        ScaledProgress(ProgressSink *to, uint32_t from, uint32_t span) : m_to(to), m_from(from), m_span(span) {}
        void report(uint32_t pct) override
        {
            if ( m_to != nullptr )
                m_to->report(m_from + pct * m_span / 100);
        }
        bool cancelled() override { return m_to != nullptr && m_to->cancelled(); }
    private:
        ProgressSink *m_to;
        uint32_t      m_from, m_span;
    };

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

    bool build_syscall_table(const MsTtdBackend *backend, SyscallTable *out)
    {
        out->names.clear();
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
            std::vector<std::pair<ea_t, std::string>> exports;
            read_guest_exports(rd, ml.base, is64, &exports);
            for ( const auto &[ea, name] : exports )
            {
                if ( name.size() < 3 || name[0] != 'N' || name[1] != 't' )
                    continue;
                uint32_t n = 0;
                if ( !decode_stub(rd, ea, is64, &n) )
                    continue;
                out->names.emplace(n, name);
                out->stubs.emplace(n, ea);
                // A 32-bit stub's number carries the argument-conversion
                // index above the low word; the register at the syscall may
                // not.
                if ( !is64 && (n & 0xFFFF) != n )
                {
                    out->names.emplace(n & 0xFFFF, name);
                    out->stubs.emplace(n & 0xFFFF, ea);
                }
            }
        }
        return !out->names.empty();
    }

    template <typename V>
    static bool read_word(V const *v, uint64_t addr, uint32_t width, uint64_t *out) noexcept
    {
        uint64_t tmp = 0;
        MemoryBuffer mb = v->QueryMemoryBuffer(GuestAddress{ addr }, BufferView{ &tmp, width });
        if ( mb.Memory.Size != width )
            return false;
        *out = tmp;
        return true;
    }

    // The syscall at a KernelCall gap: number, arguments as the kernel takes
    // them, and where it returns to.
    static void read_kernel_call(IThreadView const *t, bool is64, bool want_args, KernelCall *k) noexcept
    {
        CROSS_PLATFORM_CONTEXT ctx = t->GetCrossPlatformContext();
        k->pc = (ea_t)(uint64_t)t->GetProgramCounter();
        k->sp = (uint64_t)t->GetStackPointer();
        if ( is64 )
        {
            const AMD64_CONTEXT &c = ctx.Amd64Context;
            k->number = (uint32_t)c.Rax;
            // syscall (0F 05) and its relatives are two bytes; the kernel
            // comes back to the next instruction.
            uint8_t ins[2] = { 0, 0 };
            MemoryBuffer mb = t->QueryMemoryBuffer(GuestAddress{ (uint64_t)k->pc }, BufferView{ ins, 2 });
            if ( mb.Memory.Size == 2
              && ((ins[0] == 0x0F && (ins[1] == 0x05 || ins[1] == 0x34)) || (ins[0] == 0xCD && ins[1] == 0x2E)) )
                k->ret_pc = (uint64_t)k->pc + 2;
            if ( !want_args )
                return;
            // The stub moved rcx to r10: the syscall instruction overwrites
            // rcx with the return address. The fifth argument on is where the
            // stub's caller put it, past the return address and the shadow
            // space -- the stub has not touched the stack.
            const uint64_t regs[4] = { c.R10, c.Rdx, c.R8, c.R9 };
            for ( size_t i = 0; i < 4; i++ )
                k->args[i] = regs[i];
            uint64_t slots[kKernelCallArgs - 4] = { 0 };
            t->QueryMemoryBuffer(GuestAddress{ k->sp + 0x28 }, BufferView{ slots, sizeof(slots) });
            for ( size_t i = 0; i < kKernelCallArgs - 4; i++ )
                k->args[4 + i] = slots[i];
            return;
        }
        const X86_NT5_CONTEXT &c = ctx.X86Nt5Context;
        k->number = (uint32_t)c.Eax;
        // A 32-bit stub calls its way into the kernel (directly, or through
        // WoW64's transition), so the kernel returns where that call
        // returns: the word on top of the stack. Its arguments are where
        // the stub's caller pushed them, past the stub's own return address.
        uint64_t ret = 0;
        if ( read_word(t, k->sp, 4, &ret) )
            k->ret_pc = ret;
        if ( !want_args )
            return;
        uint32_t slots[kKernelCallArgs] = { 0 };
        t->QueryMemoryBuffer(GuestAddress{ k->sp + 8 }, BufferView{ slots, sizeof(slots) });
        for ( size_t i = 0; i < kKernelCallArgs; i++ )
            k->args[i] = slots[i];
    }

    // Every module as [lo, hi), sorted by base, one per distinct base.
    static std::vector<std::pair<ea_t, ea_t>> module_ranges(const std::vector<ModuleInfo> &mods)
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

        // Which module an address belongs to, answered from a table built here
        // before the replay starts: the callback runs on the replay worker, and
        // nothing it reads may be built lazily from two threads.
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
        // The shadow call stacks, when chains are wanted: every call in the
        // recording pushes a frame and every matching return pops it. The
        // lookup is cached because this runs on every call in the trace and
        // threads execute in bursts.
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
                // anything above -- an exception or a longjmp leaves several
                // frames at once.
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
                // caller wants them for.
                read_kernel_call(t, is64, false, &k);
                ittd_regs regs;
                regs_from_context(t->GetCrossPlatformContext(), is64, &regs);
                memcpy(k.gp, regs.gp, sizeof(k.gp));
                k.rflags = regs.rflags;
                k.name = table.name_of(k.number);
                if ( k.name == nullptr && !is64 )
                    k.name = table.name_of(k.number & 0xFFFF);
                k.stub = table.stub_of(k.number, k.pc);
                if ( k.stub == BADADDR && !is64 )
                    k.stub = table.stub_of(k.number & 0xFFFF, k.pc);
                if ( !opts.args_wanted || opts.args_wanted(k.number) )
                {
                    read_kernel_call(t, is64, true, &k);
                    if ( chains )
                    {
                        // From the call into the stub -- or the syscall
                        // itself, when the program made its own -- then one
                        // frame per module the chain crosses into: the
                        // innermost one in each, which is the code that
                        // called onward.
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
        ScaledProgress first(progress, 0, opts.results ? 70 : 100);
        bool complete = msttd_sweep(census.get(), TtdPosition::Min, TtdPosition::Max, &first);
        census->SetGapEventCallback(nullptr, 0);
        if ( chains )
            census->SetCallReturnCallback(nullptr, 0);
        census.reset();
        shadow.clear();

        std::stable_sort(calls.begin(), calls.end(),
                         [](const KernelCall &a, const KernelCall &b) { return a.pos < b.pos; });

        // ---- the returns: each one's result ----------------------------------
        //
        // An execute watchpoint on every instruction the kernel returns to --
        // the stubs' few, and those of any code that makes its own syscalls.
        // A thread makes one syscall at a time, so a return belongs to that
        // thread's oldest call still out before it.
        std::map<uint32_t, std::vector<size_t>> per_thread;
        std::set<uint64_t> ret_pcs;
        for ( size_t i = 0; i < calls.size(); i++ )
        {
            per_thread[calls[i].utid].push_back(i);
            if ( calls[i].ret_pc != 0 )
                ret_pcs.insert(calls[i].ret_pc);
        }
        if ( opts.results && complete && !ret_pcs.empty() )
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
                        KernelCall &c = calls[mine[k]];
                        if ( c.returned || !(c.pos < here) || c.ret_pc != (uint64_t)w.Address )
                            return false;
                        CROSS_PLATFORM_CONTEXT ctx = t->GetCrossPlatformContext();
                        c.result   = is64 ? (uint64_t)ctx.Amd64Context.Rax : (uint64_t)ctx.X86Nt5Context.Eax;
                        c.ret_pos  = here;
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
                ScaledProgress second(progress, 70, 30);
                complete = msttd_sweep(ret.get(), TtdPosition::Min, TtdPosition::Max, &second);
                ret->SetMemoryWatchpointCallback(nullptr, 0);
            }
        }

        size_t returned = 0;
        for ( const KernelCall &c : calls )
            returned += c.returned ? 1 : 0;
        msttd_log("[ida-ttd] syscalls: %d in the recording, %d named, %d with a result%s.\n",
                  (int)calls.size(),
                  (int)std::count_if(calls.begin(), calls.end(), [](const KernelCall &c) { return c.name != nullptr; }),
                  (int)returned, truncated ? " (cut short)" : "");
        *out = std::move(calls);
        r.ran       = true;
        r.cancelled = !complete;
        r.truncated = truncated;
        return r;
    }

    // The registers of the syscalls last listed, so the listing's argument
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

    QueryResult MsTtdBackend::query_syscalls(std::vector<SyscallEvent> *out, ProgressSink *progress)
    {
        QueryResult r;
        if ( !m_engine || out == nullptr )
            return r;
        SyscallTable table;
        if ( !build_syscall_table(this, &table) )
            msttd_log("[ida-ttd] syscalls: no ntdll stubs were readable in this recording, so they "
                      "are listed by number only.\n");
        std::vector<KernelCall> calls;
        KernelCallOptions opts;
        opts.args_wanted = [](uint32_t) { return false; };
        r = collect_kernel_calls(this, table, opts, &calls, progress);
        if ( !r.ran )
            return r;
        out->reserve(out->size() + calls.size());
        m_syscallRegs.clear();
        for ( const KernelCall &c : calls )
        {
            if ( m_syscallRegs.size() < kMaxCachedRegs )
            {
                SyscallRegs &sr = m_syscallRegs[{ (uint64_t)c.pos.Sequence, (uint64_t)c.pos.Steps }];
                memcpy(sr.gp, c.gp, sizeof(sr.gp));
                sr.rflags = c.rflags;
            }
            SyscallEvent e;
            e.pos    = to_core(c.pos);
            e.result = c.result;
            e.number = c.number;
            e.tid    = c.tid;
            if ( c.name != nullptr )
                e.name = c.name;
            out->push_back(std::move(e));
        }
        return r;
    }
}
