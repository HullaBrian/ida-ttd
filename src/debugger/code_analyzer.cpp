#include "debugger/code_analyzer.h"
#include "debugger/msttd_position.h"

using namespace TTD;
using namespace TTD::Replay;

namespace idattd
{
    void CodeAnalyzer::bind(IReplayEngine *engine, ModuleRegistry *modules,
                            MemoryReader *memory, bool is64)
    {
        reset();
        m_engine  = engine;
        m_modules = modules;
        m_memory  = memory;
        m_is64    = is64;
    }

    void CodeAnalyzer::reset()
    {
        m_engine  = nullptr;
        m_modules = nullptr;
        m_memory  = nullptr;
        m_scratch.reset();
        m_winLo          = BADADDR;
        m_winHi          = 0;
        m_calleeScanFunc = BADADDR;
        m_pdataExtended.clear();
        m_dynFuncBytes.clear();
    }

    void CodeAnalyzer::on_stop(ICursorView *playhead, ea_t pc)
    {
        analyze_current_function(playhead, pc);
    }

    ICursorView *CodeAnalyzer::scratch()
    {
        if ( m_engine == nullptr )
            return nullptr;
        if ( !m_scratch )
        {
            m_scratch = UniqueCursor{ m_engine->NewCursor() };
            if ( m_scratch )
            {
                // must be sequential. The engine's default is to replay several
                // segments in parallel and dispatch callbacks from all of those
                // threads at once; find_dynamic_function_entry's call/return
                // callback mutates an unsynchronized std::map, so the default
                // would corrupt the heap. Sequential replay keeps the callback
                // single-threaded (and chronological, which that walk also needs).
                //
                // ReplayAllSegmentsWithoutFiltering matches the whole-trace sweep
                // in tracer.cpp. Every user of this cursor wants a call/return
                // callback, which is not a maskable event, so the segment filter
                // has nothing to work with and costs ~2% either way; setting it
                // removes any question of a bounded replay skipping ahead through
                // the index and dispatching no callbacks at all.
                m_scratch->SetReplayFlags(ReplayFlags::ReplayAllSegmentsWithoutFiltering
                                          | ReplayFlags::ReplaySegmentsSequentially);
            }
        }
        return m_scratch.get();
    }

    // Define an instruction at the exact address 'ea'. Addresses passed here come
    // from the trace (real executed PCs), so they are true instruction
    // boundaries; clear any stale/garbage item overlapping ea first so we never
    // leave RIP pointing inside a wrongly-sized instruction.
    static void force_insn(ea_t ea)
    {
        flags64_t fl = get_flags(ea);
        if ( is_code(fl) && get_item_head(ea) == ea )
            return;                          // already a correct instruction head
        del_items(ea, DELIT_EXPAND);         // drop any item overlapping ea
        create_insn(ea);
    }

    // failed read never looks like a byte change.
    static uint64_t hash_mem(ea_t ea, size_t n)
    {
        uint8_t buf[64];
        if ( n > sizeof(buf) )
            n = sizeof(buf);
        if ( get_bytes(buf, (ssize_t)n, ea) != (ssize_t)n )
            return 0;
        uint64_t h = 1469598103934665603ULL;
        for ( size_t i = 0; i < n; i++ )
        {
            h ^= buf[i];
            h *= 1099511628211ULL;
        }
        return h;
    }

    ea_t CodeAnalyzer::call_target_of(ICursorView *playhead, const insn_t &insn, ea_t &slot_out)
    {
        slot_out = BADADDR;
        const op_t &op = insn.ops[0];

        // Direct: call rel32 / call far ptr. The operand carries the target.
        if ( op.type == o_near || op.type == o_far )
            return op.addr;

        // Indirect through a memory slot: "call [rip+disp]" (x64, where IDA
        // resolves the rip-relative operand into an absolute o_mem address) or
        // "call ds:xxx" (x86). That slot is an import table entry, and because we
        // are replaying a recording rather than reading a file, it already holds
        // the address the loader wrote there. Follow it.
        if ( op.type == o_mem && op.addr != BADADDR && is_loaded(op.addr) )
        {
            slot_out = op.addr;
            ea_t tgt = m_is64 ? (ea_t)get_qword(op.addr) : (ea_t)get_dword(op.addr);
            // Only trust the value if it lands inside a module the trace has
            // loaded. The slot may hold something else entirely -- it is read at
            // the CURRENT position, which can be before the loader filled the
            // import table in, and a stale or unreadable slot would otherwise send
            // add_func() off to carve a function out of garbage.
            if ( tgt != 0 && tgt != BADADDR && m_modules->index_at(tgt) != (size_t)-1 )
                return tgt;
        }

        // call rax / call [rax+8]: only the trace knows where this went, and the
        // per-stop path must not replay. Left for when execution reaches it.
        return BADADDR;
    }

    void CodeAnalyzer::define_function_at(ea_t ea)
    {
        if ( ea == BADADDR || ea == 0 )
            return;
        if ( get_segment_ea(ea) == BADADDR )
            return;                         // not mapped at this position
        if ( get_func_start(ea) == ea )
            return;                         // already a function here

        ea_t fstart, fend;
        if ( m_modules->function_range_at(ea, fstart, fend) && fstart == ea && fstart < fend )
        {
            // The module's .pdata gives exact bounds: lay the whole body out in one
            // linear pass, the same way analyze_current_function does for PC.
            ea_t ip = fstart;
            for ( int guard = 0; ip < fend && guard < 0x20000; guard++ )
            {
                if ( is_code(get_flags(ip)) )
                {
                    ea_t nxt = get_item_end(ip);
                    ip = nxt > ip ? nxt : ip + 1;
                    continue;
                }
                int len = create_insn(ip);
                ip += len > 0 ? len : 1;
            }
            add_func(fstart, fend);
        }
        else
        {
            // No .pdata (x86, dynamic code, or an address that is not a recorded
            // function head). Seed one instruction and let IDA's recursive descent
            // find the extent. AF_PROC is off, so this does not cascade into the
            // callee's own callees -- which is the whole point of doing it here.
            force_insn(ea);
            add_func(ea);
        }

        ea_t defined = get_func_start(ea);
        if ( defined == ea && m_modules->is_library_address(ea)
          && (get_func_flags(ea) & FUNC_LIB) == 0 )
        {
            set_func_flag(ea, FUNC_LIB, true);
        }
    }

    void CodeAnalyzer::define_callees(ICursorView *playhead, ea_t lo, ea_t hi)
    {
        if ( lo == BADADDR || hi <= lo )
            return;
        // Stepping inside one function re-enters this on every single stop and
        // there is nothing new to find until the function changes, so remember the
        // last one scanned. (Reset explicitly wherever a function is torn down and
        // rebuilt, so self-modifying code is rescanned.)
        if ( lo == m_calleeScanFunc )
            return;
        m_calleeScanFunc = lo;

        // Bounded on both axes so this stays a per-stop-safe cost: a cap on how
        // far we walk, and a cap on how many targets we define.
        const int MAX_ITEMS   = 0x4000;
        const int MAX_TARGETS = 64;   // more direct calls than any real function has

        std::set<ea_t> seen;
        int defined = 0;
        ea_t ip = lo;
        for ( int guard = 0; ip < hi && guard < MAX_ITEMS && defined < MAX_TARGETS; guard++ )
        {
            if ( !is_code(get_flags(ip)) )
            {
                ip++;                       // embedded data (jump table, padding)
                continue;
            }
            ea_t   nxt = get_item_end(ip);
            insn_t insn;
            if ( decode_insn(&insn, ip) > 0 && is_call_insn(insn) )
            {
                ea_t slot = BADADDR;
                ea_t tgt  = call_target_of(playhead, insn, slot);

                if ( tgt != BADADDR && seen.insert(tgt).second )
                {
                    define_function_at(tgt);
                    defined++;
                }

                // Now the slot the call reads through. Turning it into a
                // pointer-sized offset stops it rendering as "call cs:unk_X", and
                // naming it after its target turns it into the import name the
                // reader actually wants: "call cs:__imp_CreateFileW". Only touch a
                // slot that has no name and no type of its own yet.
                if ( slot != BADADDR
                  && !has_any_name(get_flags(slot)) && !is_data(get_flags(slot)) )
                {
                    if ( m_is64 ? create_qword(slot, 8) : create_dword(slot, 4) )
                        op_plain_offset(slot, 0, 0);
                    qstring tn;
                    if ( tgt != BADADDR && get_name(&tn, tgt) > 0 && !tn.empty() )
                    {
                        qstring sn;
                        sn.sprnt("__imp_%s", tn.c_str());
                        set_name(slot, sn.c_str(), SN_NOWARN | SN_FORCE | SN_NOCHECK);
                    }
                }
            }
            ip = nxt > ip ? nxt : ip + 1;
        }
    }

    // Grow an already-defined function to the end its module's exception table
    // gives it. Only ever GROWS, and only into address space nothing else claims:
    // a shorter definition is IDA having lost the flow, but a longer one may be
    // deliberate (the user joined chunks by hand), and a range another function
    // already owns is not ours to take.
    void CodeAnalyzer::extend_to_pdata_bounds(ea_t pc, const func_entry_info_t &fi)
    {
        if ( m_pdataExtended.find(fi.start_ea) != m_pdataExtended.end() )
            return;                          // considered once per function

        ea_t ps = BADADDR, pe = BADADDR;
        if ( !m_modules->function_range_at(pc, ps, pe) )
            return;                          // x86, or no .pdata for this module
        m_pdataExtended.insert(fi.start_ea);

        // The .pdata entry must describe this function's own chunk. When it starts
        // elsewhere we are inside a tail chunk, and joining chunks is a different
        // decision than extending one.
        if ( ps != fi.start_ea || pe <= fi.end_ea )
            return;

        segment_info_t seg;
        if ( !get_segment_info(&seg, pc) || pe > seg.end_ea )
            return;

        // Refuse if anything else already lives in the space we would absorb.
        for ( ea_t a = fi.end_ea; a < pe; a++ )
        {
            if ( get_func_start(a) != BADADDR )
                return;
        }

        // Lay the tail out before moving the end: set_func_end over undefined
        // bytes leaves the function containing raw data.
        for ( ea_t ip = fi.end_ea; ip < pe; )
        {
            if ( is_code(get_flags(ip)) )
            {
                ea_t nxt = get_item_end(ip);
                ip = nxt > ip ? nxt : ip + 1;
                continue;
            }
            int len = create_insn(ip);
            ip += len > 0 ? len : 1;
        }
        if ( set_func_end(fi.start_ea, pe) )
        {
            msg("[ida-ttd] extended %a..%a to %a from the module's exception "
                "table.\n", fi.start_ea, fi.end_ea, pe);
            m_calleeScanFunc = BADADDR;      // the new tail may call things
        }
    }

    void CodeAnalyzer::analyze_current_function(ICursorView *playhead, ea_t pc)
    {
        segment_info_t seg;
        if ( !get_segment_info(&seg, pc) )
            return;

        func_entry_info_t cur_fi;
        if ( get_func_entry_info(&cur_fi, pc) )
        {
            // A function IDA already defined can still be defined SHORT. Its
            // static analysis stops where it loses the flow -- at a noreturn call,
            // an opaque tail jump, embedded data -- and the tail then renders as
            // a JUMPOUT to an address outside the function. The module's exception
            // table says exactly where the function ends, and nothing was using it
            // for anything but the not-yet-defined case, so reconcile here.
            extend_to_pdata_bounds(pc, cur_fi);

            // For functions we built in dynamic memory, detect a
            // rewrite (self-modifying / reused region, or time-travel to a position
            // where the same address holds different code) by hashing the bytes and
            // comparing to definition time. If unchanged (or not ours), keep it.
            auto it = m_dynFuncBytes.find(cur_fi.start_ea);
            if ( it == m_dynFuncBytes.end() )
            {
                // Not ours / unchanged: nothing to re-disassemble, but its call
                // targets may still be undefined -- the function could have been
                // defined by the PDB plugin, or on a previous visit before a
                // callee's module was mapped. Cheap thanks to the memo below.
                define_callees(playhead, cur_fi.start_ea, cur_fi.end_ea);
                return;
            }
            uint64_t h = hash_mem(cur_fi.start_ea, 64);
            if ( h == 0 || h == it->second )
            {
                define_callees(playhead, cur_fi.start_ea, cur_fi.end_ea);
                return;
            }
            ea_t fs = cur_fi.start_ea, fe = cur_fi.end_ea;
            del_func(fs);
            del_items(fs, DELIT_EXPAND, (asize_t)(fe - fs));
            m_dynFuncBytes.erase(it);
            m_calleeScanFunc = BADADDR;     // the code changed: rescan its callees
            // fall through to re-disassemble the new code
        }

        ea_t fstart, fend;
        if ( m_modules->function_range_at(pc, fstart, fend) && fstart < fend && fend <= seg.end_ea )
        {
            // Module function with authoritative .pdata bounds: disassemble the
            // whole range. Embedded data (jump tables) can't decode -- skip a byte.
            ea_t ip = fstart;
            for ( int guard = 0; ip < fend && guard < 0x20000; guard++ )
            {
                if ( is_code(get_flags(ip)) )
                {
                    ea_t nxt = get_item_end(ip);
                    ip = nxt > ip ? nxt : ip + 1;
                    continue;
                }
                int len = create_insn(ip);
                ip += len > 0 ? len : 1;
            }
            add_func(fstart, fend);
            // Library (non-target) module code: mark it FUNC_LIB so it renders as
            // <name>+offset and is de-emphasized. The analyzed binary (module 0) is
            // the user's own code, so leave its functions normal.
            bool main_mod = false;
            if ( m_engine && m_engine->GetModuleCount() > 0 )
            {
                const Module &m0 = m_engine->GetModuleList()[0];
                ea_t b = (ea_t)(uint64_t)m0.Address;
                main_mod = pc >= b && pc < b + (ea_t)m0.Size;
            }
            if ( !main_mod && get_func_start(fstart) == fstart
              && (get_func_flags(fstart) & FUNC_LIB) == 0 )
            {
                set_func_flag(fstart, FUNC_LIB, true);
            }
            define_callees(playhead, fstart, fend);
            return;
        }

        // ---- runtime-allocated code (no module / no .pdata): shellcode, unpacked
        // code, JIT. Mirror Binary Ninja's debugger: define a function and let
        // IDA's recursive descent disassemble the whole thing (forward branches +
        // not-taken branches), seeded at the function head so the prologue and all
        // the body above PC are laid out too (so backward stepping reveals code
        // that's already there instead of one instruction at a time). ----
        //
        // Prefer the true head recovered from the trace's call/return structure
        // (the call that entered this frame). Fall back to the executed-address
        // contiguity heuristic when no enclosing call was captured -- e.g. the
        // frame was entered by a jmp/thread-start rather than a call, or the
        // entering call predates the look-back window.
        ea_t start = find_dynamic_function_entry(playhead, pc);
        if ( start == BADADDR || start > pc || get_segment_ea(start) != seg.start_ea )
            start = find_dynamic_start(playhead, pc);

        // The position-based memory query returns zero-fill for this region's
        // never-executed bytes (it's unpacked/JIT code, not a module). Rebuild the
        // real bytes from the trace's recorded writes so the whole function (not just
        // the executed path) disassembles -- this is what WinDbg shows. Bounded to a
        // window from the head; served thereafter by on_read_memory. Then invalidate
        // IDA's cache for the range so the upcoming create_insn reads the real bytes.
        ea_t rlo = start;
        ea_t rhi = (pc > start ? pc : start) + 0x2000;
        // Clamp to the enclosing segment, never widen to it: for dynamic code that
        // segment is the synthetic range covering all of user space.
        if ( rhi > seg.end_ea )
            rhi = seg.end_ea;
        if ( rhi > rlo && m_memory->reconstruct(playhead, rlo, rhi) )
            invalidate_dbgmem_contents(rlo, rhi - rlo);

        force_insn(start);                  // exact-boundary seed
        add_func(start);                    // BADADDR end -> recursive descent
        ea_t aend = (pc > start ? pc : start) + 0x2000;
        plan_and_wait(start, aend);         // force the descent synchronously, bounded

        ea_t nfs = get_func_start(pc);
        if ( nfs != BADADDR )
        {
            m_dynFuncBytes[nfs] = hash_mem(nfs, 64);
            // Give dynamic (non-module) code its OWN debug name. Debugger views
            // resolve names via the global "nearest debug name <= address" rule, so
            // without an entry here a far-below module symbol (kernel32/ntdll/the exe)
            // bleeds onto shellcode/JIT as "<unrelated>+huge_offset". A local name
            // breaks that bleed for this function's range.
            qstring nm;
            if ( get_func_name(&nm, nfs) > 0 && !nm.empty() )
                set_debug_name(nfs, nm.c_str());

            // Shellcode and unpacked code call into the real modules constantly
            // (LoadLibrary, VirtualProtect, ...). Defining those targets is what
            // turns "call unk_7FF8xxxx" into a named import.
            func_entry_info_t nfi;
            ea_t nfe = get_func_entry_info(&nfi, nfs) && nfi.end_ea > nfs
                     ? nfi.end_ea : aend;
            define_callees(playhead, nfs, nfe);
        }
        else
        {
            lay_out_window(playhead, pc);             // PC reachable only via an indirect edge
            define_callees(playhead, m_winLo, m_winHi);
        }
    }

    void CodeAnalyzer::collect_window_pcs(ICursorView *playhead, ea_t pc, std::set<ea_t> &pcs)
    {
        pcs.clear();
        if ( !m_engine || playhead == nullptr )
            return;
        if ( scratch() == nullptr )
            return;

        const uint64_t BEFORE = 64;     // instructions of context before PC
        const uint64_t AFTER  = 192;    // instructions after PC
        const ea_t     W      = 0x2000; // only collect addresses within +/-W of PC

        TtdPosition cur = playhead->GetPosition();
        uint32_t tid = (uint32_t)playhead->GetThreadInfo().UniqueId;

        // Seek a little before the current position, then replay forward (cheap --
        // no per-step keyframe re-seek like going backward).
        TtdPosition start = cur;
        start.Steps = (StepCount)((uint64_t)cur.Steps > BEFORE ? (uint64_t)cur.Steps - BEFORE : 0);
        m_scratch->SetPosition(start);

        int budget = (int)((BEFORE + AFTER) * 3) + 256;  // extra for thread interleaving
        TtdPosition prev = m_scratch->GetPosition();
        for ( int i = 0; i < budget; i++ )
        {
            if ( (uint32_t)m_scratch->GetThreadInfo().UniqueId == tid )
            {
                ea_t a = (ea_t)(uint64_t)m_scratch->GetProgramCounter();
                ea_t d = a > pc ? a - pc : pc - a;
                if ( d <= W )
                    pcs.insert(a);
            }
            m_scratch->ReplayForward(TtdPosition::Max, StepCount{ 1 });
            TtdPosition now = m_scratch->GetPosition();
            if ( now.Sequence == prev.Sequence && now.Steps == prev.Steps )
                break;                  // reached the end of the trace
            prev = now;
        }
    }

    ea_t CodeAnalyzer::find_dynamic_start(ICursorView *playhead, ea_t pc)
    {
        std::set<ea_t> pcs;
        collect_window_pcs(playhead, pc, pcs);
        if ( pcs.empty() )
            return pc;                  // nothing collected -> start at PC (BN-style)

        auto it = pcs.upper_bound(pc);  // first executed address > pc
        if ( it == pcs.begin() )
            return pc;                  // none <= pc
        --it;                           // largest executed address <= pc

        // Walk down through executed addresses while they chain by instruction
        // (gap <= max x86 insn length). A larger gap means the lower address is a
        // different basic block reached by a jump, not the linear prologue.
        ea_t lo = *it;
        while ( it != pcs.begin() )
        {
            auto pv = std::prev(it);
            if ( lo - *pv > 15 )
                break;
            lo = *pv;
            --it;
        }
        return lo;
    }

    // Recover the head of the current frame's function from the trace itself.
    // We replay forward from a position a little before the playhead up to the
    // playhead, watching the call/return structure via the engine's CallReturn
    // callback (the same primitive the tracer uses): a CALL pushes (callee,
    // return-addr) onto a per-thread frame stack, a RET pops it. When we reach
    // the current position the top of the current thread's stack is the call
    // that entered this frame, so its target is the function head -- this is the
    // "change in the callstack" boundary, the dynamic-code analogue of the
    // .pdata bounds used for module code.
    //
    // The look-back is widened until that entering CALL is captured. Each attempt
    // is one SetPosition + forward replay, which is cheap; we deliberately never
    // single-step backward (that re-seeks a keyframe per step and freezes the UI).
    ea_t CodeAnalyzer::find_dynamic_function_entry(ICursorView *playhead, ea_t pc)
    {
        // The head comes from the cursor's own position, not from 'pc'.
        qnotused(pc);
        if ( !m_engine || playhead == nullptr )
            return BADADDR;
        // scratch() replays segments SEQUENTIALLY. That is load-bearing here:
        // with the engine's default parallel replay the callback below fires from
        // several threads at once and 'stacks' is not synchronized.
        if ( scratch() == nullptr )
            return BADADDR;

        const TtdPosition cur = playhead->GetPosition();
        const uint32_t tid = (uint32_t)playhead->GetThreadInfo().UniqueId;

        struct Frame { ea_t entry; uint64_t ret; };
        std::map<uint32_t, std::vector<Frame>> stacks;

        // CALL: instr == callee (function head), fall_through == return address.
        // RET:  fall_through == 0; pop the innermost open frame on that thread.
        auto on_call_ret = [&](GuestAddress instr, GuestAddress fall_through,
                               IThreadView const *t) noexcept
        {
            uint32_t utid = (uint32_t)t->GetThreadInfo().UniqueId;
            if ( (uint64_t)fall_through != 0 )
            {
                stacks[utid].push_back(Frame{ (ea_t)(uint64_t)instr, (uint64_t)fall_through });
            }
            else
            {
                auto it = stacks.find(utid);
                if ( it != stacks.end() && !it->second.empty() )
                    it->second.pop_back();
            }
        };

        static const uint64_t kWindows[] = { 1024, 8192, 65536 };
        ea_t entry = BADADDR;
        for ( uint64_t back : kWindows )
        {
            stacks.clear();
            TtdPosition s = cur;
            s.Steps = (StepCount)((uint64_t)cur.Steps > back ? (uint64_t)cur.Steps - back : 0);
            m_scratch->SetPosition(s);
            m_scratch->SetCallReturnCallback(on_call_ret);
            m_scratch->ReplayForward(cur);                 // stop AT the playhead
            m_scratch->SetCallReturnCallback(nullptr, 0);  // detach the local lambda

            auto it = stacks.find(tid);
            if ( it != stacks.end() && !it->second.empty() )
            {
                entry = it->second.back().entry;
                break;
            }
            if ( (uint64_t)cur.Steps <= back )
                break;       // the window already reached the start of the sequence
        }
        return entry;
    }

    void CodeAnalyzer::lay_out_window(ICursorView *playhead, ea_t pc)
    {
        if ( !m_engine || playhead == nullptr )
            return;

        // Already have a laid-out window comfortably surrounding PC? Skip the
        // replay (cheap path while stepping inside the same region). The explicit
        // validity test matters: m_winLo == BADADDR means "no window", and without
        // it the +0x40 wraps to 0x3F and this test passes for every code address,
        // permanently disabling the layout pass.
        if ( m_winLo != BADADDR && m_winLo < m_winHi
          && pc >= m_winLo + 0x40 && pc + 0x40 <= m_winHi
          && is_code(get_flags(pc)) )
            return;

        std::set<ea_t> pcs;
        collect_window_pcs(playhead, pc, pcs);

        // Realize the exact executed instructions (these are real boundaries).
        for ( ea_t a : pcs )
            force_insn(a);

        if ( pcs.empty() )
        {
            force_insn(pc);             // at least the current instruction
            m_winLo = BADADDR;          // "no window" -- matches the initial state
            m_winHi = 0;
            return;
        }

        // Extend forward by linear decode from the furthest laid-out instruction
        // (exact: it starts on a real boundary) so the user can scroll ahead.
        ea_t ip = *pcs.rbegin();
        ea_t flimit = pc + 0x200;
        for ( int g = 0; ip < flimit && g < 4096; g++ )
        {
            if ( is_code(get_flags(ip)) )
            {
                ea_t nxt = get_item_end(ip);
                ip = nxt > ip ? nxt : ip + 1;
                continue;
            }
            int len = create_insn(ip);
            if ( len <= 0 )
                break;
            ip += len;
        }

        m_winLo = *pcs.begin();
        m_winHi = ip > *pcs.rbegin() ? ip : *pcs.rbegin();
    }

    // Deep, on-demand analysis: reconstruct the current thread's call structure by
    // walking the trace backward (stepping over nested calls via a call-depth
    // counter) to find the enclosing function's entry, then define it. This is the
    // expensive path the per-stop handler intentionally avoids, so it runs on a
    // private cursor behind a cancellable wait box.
    void CodeAnalyzer::analyze_whole_function(ICursorView *playhead)
    {
        if ( playhead == nullptr || !m_engine )
        {
            warning("Analysis is only available while replaying a trace.");
            return;
        }
        ea_t pc = (ea_t)(uint64_t)playhead->GetProgramCounter();
        if ( get_segment_ea(pc) == BADADDR )
            return;
        if ( get_func_start(pc) != BADADDR )
        {
            info("0x%llX is already inside a defined function.", (uint64_t)pc);
            return;
        }

        UniqueCursor cur{ m_engine->NewCursor() };
        if ( !cur )
            return;
        cur->SetPosition(playhead->GetPosition());
        uint32_t target_tid = (uint32_t)cur->GetThreadInfo().Id;

        std::vector<ea_t> frame_pcs;
        std::set<ea_t>    seen;
        frame_pcs.push_back(pc);
        seen.insert(pc);
        ea_t entry   = BADADDR;
        ea_t last_pc = pc;
        int  depth   = 0;

        const int MAX_INSN = 50000;
        const int MAX_STEP = 1000000;
        int examined = 0, steps = 0;
        bool cancelled = false;
        TtdPosition prev = cur->GetPosition();

        show_wait_box("Analyzing function from the trace (Cancel to stop)...");
        while ( examined < MAX_INSN && steps < MAX_STEP )
        {
            if ( (steps & 0x3FF) == 0 )
            {
                replace_wait_box("Analyzing function: %d instructions examined...", examined);
                if ( user_cancelled() ) { cancelled = true; break; }
            }

            cur->ReplayBackward(TtdPosition::Min, StepCount{ 1 });
            steps++;
            TtdPosition now = cur->GetPosition();
            if ( now.Sequence == prev.Sequence && now.Steps == prev.Steps )
                break;                              // reached the start of the trace
            prev = now;

            if ( (uint32_t)cur->GetThreadInfo().Id != target_tid )
                continue;
            examined++;

            ea_t   npc = (ea_t)(uint64_t)cur->GetProgramCounter();
            insn_t insn;
            bool   call = false, ret = false;
            if ( decode_insn(&insn, npc) > 0 )
            {
                call = is_call_insn(insn);
                ret  = is_ret_insn(insn);
            }

            if ( call )
            {
                if ( depth == 0 ) { entry = last_pc; break; }
                depth--;
            }
            else if ( ret )
            {
                depth++;
            }

            if ( depth == 0 && seen.insert(npc).second )
                frame_pcs.push_back(npc);
            last_pc = npc;
        }
        hide_wait_box();

        std::sort(frame_pcs.begin(), frame_pcs.end());
        for ( ea_t a : frame_pcs )
            force_insn(a);

        if ( cancelled )
        {
            msg("[ida-ttd] function analysis cancelled (%d instructions, %d defined).\n",
                examined, (int)frame_pcs.size());
        }
        else if ( entry != BADADDR )
        {
            force_insn(entry);
            add_func(entry);
            msg("[ida-ttd] defined function at 0x%llX (entry of the call at the "
                "current position; %d instructions).\n", (uint64_t)entry, examined);
            jumpto(entry);
        }
        else
        {
            warning("Could not find the function entry within %d instructions.\n"
                    "Laid out the %d instruction(s) found in this frame.",
                    examined, (int)frame_pcs.size());
        }
    }

}
