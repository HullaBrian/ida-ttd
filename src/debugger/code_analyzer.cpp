#include "debugger/code_analyzer.h"

namespace idattd
{
    // Bounds that keep the per-stop work per-stop-safe.
    static const int    MAX_LINEAR_ITEMS = 0x20000;   // items one linear layout pass creates
    static const ea_t   DYN_LAYOUT_SPAN  = 0x2000;    // bytes of dynamic code laid out past the head or pc
    static const size_t DYN_HASH_BYTES   = 64;        // bytes hashed to notice rewritten dynamic code
    static const ea_t   MAX_INSN_LEN     = 15;        // longest x86 instruction
    void CodeAnalyzer::bind(ITraceBackend *backend, ModuleRegistry *modules,
                            MemoryReader *memory, bool is64)
    {
        reset();
        m_backend = backend;
        m_modules = modules;
        m_memory  = memory;
        m_is64    = is64;
    }

    void CodeAnalyzer::reset()
    {
        m_backend = nullptr;
        m_modules = nullptr;
        m_memory  = nullptr;
        m_winLo          = BADADDR;
        m_winHi          = 0;
        m_calleeScanFunc = BADADDR;
        m_pdataExtended.clear();
        m_dynFuncBytes.clear();
    }

    void CodeAnalyzer::on_stop(ITraceCursor *playhead, ea_t pc)
    {
        analyze_current_function(playhead, pc);
    }

    // Define an instruction at the exact address 'ea'. Addresses passed here come
    // from the trace (real executed PCs), so they are true instruction
    // boundaries; any stale item overlapping ea is cleared first so RIP never
    // points inside a wrongly-sized instruction.
    static void force_insn(ea_t ea)
    {
        flags64_t fl = get_flags(ea);
        if ( is_code(fl) && get_item_head(ea) == ea )
            return;                          // already a correct instruction head
        del_items(ea, DELIT_EXPAND);         // drop any item overlapping ea
        create_insn(ea);
    }

    // Lay [lo, hi) out as code in one linear pass, skipping what already is
    // code and stepping a byte over what does not decode (jump tables and
    // other embedded data). Bounded by MAX_LINEAR_ITEMS.
    static void lay_out_linear(ea_t lo, ea_t hi)
    {
        ea_t ip = lo;
        for ( int guard = 0; ip < hi && guard < MAX_LINEAR_ITEMS; guard++ )
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
    }

    // FNV-1a of the first 'n' bytes at 'ea' (at most 64). Zero when they
    // cannot be read, which callers treat as "unchanged", so a failed read
    // never looks like a byte change.
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

    ea_t CodeAnalyzer::call_target_of(ITraceCursor *playhead, const insn_t &insn, ea_t &slot_out)
    {
        slot_out = BADADDR;
        const op_t &op = insn.ops[0];

        // Direct: call rel32 / call far ptr. The operand carries the target.
        if ( op.type == o_near || op.type == o_far )
            return op.addr;

        // Indirect through a memory slot: "call [rip+disp]" (x64, where IDA
        // resolves the rip-relative operand into an absolute o_mem address) or
        // "call ds:xxx" (x86). That slot is an import table entry, and in a
        // replay rather than a file it already holds the address the loader
        // wrote there. Follow it.
        if ( op.type == o_mem && op.addr != BADADDR && is_loaded(op.addr) )
        {
            slot_out = op.addr;
            ea_t tgt = m_is64 ? (ea_t)get_qword(op.addr) : (ea_t)get_dword(op.addr);
            // Only trust the value if it lands inside a module the trace has
            // loaded. The slot may hold something else entirely -- it is read at
            // the current position, which can be before the loader filled the
            // import table in, and a stale or unreadable slot would otherwise send
            // add_func() off to carve a function out of garbage.
            if ( tgt != 0 && tgt != BADADDR && m_modules->index_at(tgt) != (size_t)-1 )
                return tgt;
        }

        // call rax / call [rax+8]: only the trace knows where this went, and the
        // per-stop path must not replay. Left for when execution reaches it.
        return BADADDR;
    }

    bool CodeAnalyzer::define_function_at(ea_t ea)
    {
        if ( ea == BADADDR || ea == 0 )
            return true;
        if ( get_segment_ea(ea) == BADADDR )
            return false;                   // not mapped yet: worth another try
        if ( get_func_start(ea) == ea )
            return true;                    // already a function here

        ea_t fstart, fend;
        if ( m_modules->function_range_at(ea, fstart, fend) && fstart == ea && fstart < fend )
        {
            // The module's .pdata gives exact bounds: lay the whole body out in one
            // linear pass, the same way analyze_current_function does for PC.
            lay_out_linear(fstart, fend);
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
        return true;
    }

    void CodeAnalyzer::define_callees(ITraceCursor *playhead, ea_t lo, ea_t hi)
    {
        if ( lo == BADADDR || hi <= lo )
            return;
        // Stepping inside one function re-enters this on every single stop and
        // there is nothing new to find until the function changes, so remember the
        // last one scanned. (Reset explicitly wherever a function is torn down and
        // rebuilt, so self-modifying code is rescanned.)
        if ( lo == m_calleeScanFunc )
            return;
        // Remembered only when every target got defined: at the first stop of
        // a session a callee's module may not have a segment yet, and a scan
        // remembered then would leave the call undefined until the function
        // changed.
        bool complete = true;

        // Bounded on both axes so this stays a per-stop-safe cost: a cap on how
        // far the walk goes, and a cap on how many targets it defines.
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
                    if ( !define_function_at(tgt) )
                        complete = false;
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
        if ( complete )
            m_calleeScanFunc = lo;
    }

    // Only ever grows, and only into address space nothing else claims: a
    // shorter definition is IDA having lost the flow, but a longer one may be
    // deliberate (the user joined chunks by hand), and a range another
    // function already owns is not this one's to take.
    void CodeAnalyzer::extend_to_pdata_bounds(ea_t pc, const func_entry_info_t &fi)
    {
        if ( m_pdataExtended.find(fi.start_ea) != m_pdataExtended.end() )
            return;                          // considered once per function

        ea_t ps = BADADDR, pe = BADADDR;
        if ( !m_modules->function_range_at(pc, ps, pe) )
            return;                          // x86, or no .pdata for this module
        m_pdataExtended.insert(fi.start_ea);

        // The .pdata entry must describe this function's own chunk. When it starts
        // elsewhere, pc is inside a tail chunk, and joining chunks is a different
        // decision than extending one.
        if ( ps != fi.start_ea || pe <= fi.end_ea )
            return;

        segment_info_t seg;
        if ( !get_segment_info(&seg, pc) || pe > seg.end_ea )
            return;

        // Refuse if anything else already lives in the space it would absorb.
        for ( ea_t a = fi.end_ea; a < pe; a++ )
        {
            if ( get_func_start(a) != BADADDR )
                return;
        }

        // Lay the tail out before moving the end: set_func_end over undefined
        // bytes leaves the function containing raw data.
        lay_out_linear(fi.end_ea, pe);
        if ( set_func_end(fi.start_ea, pe) )
        {
            msg("[ida-ttd] extended %a..%a to %a from the module's exception "
                "table.\n", fi.start_ea, fi.end_ea, pe);
            m_calleeScanFunc = BADADDR;      // the new tail may call things
        }
    }

    void CodeAnalyzer::analyze_current_function(ITraceCursor *playhead, ea_t pc)
    {
        segment_info_t seg;
        if ( !get_segment_info(&seg, pc) )
            return;

        func_entry_info_t cur_fi;
        if ( get_func_entry_info(&cur_fi, pc) )
        {
            // A function IDA already defined can still be defined short. Its
            // static analysis stops where it loses the flow -- at a noreturn call,
            // an opaque tail jump, embedded data -- and the tail then renders as
            // a JUMPOUT to an address outside the function. The module's exception
            // table says exactly where the function ends.
            extend_to_pdata_bounds(pc, cur_fi);

            // A function this class defined in dynamic memory is checked for a
            // rewrite (self-modifying or reused region, or a travel to a
            // position where the same address holds different code) by hashing
            // its bytes against definition time. Any other, or an unchanged
            // one, is kept.
            auto it = m_dynFuncBytes.find(cur_fi.start_ea);
            if ( it == m_dynFuncBytes.end() )
            {
                // Nothing to re-disassemble, but its call targets may still be
                // undefined -- the function could have been defined by the PDB
                // plugin, or on a previous visit before a callee's module was
                // mapped. Cheap thanks to define_callees' memo.
                define_callees(playhead, cur_fi.start_ea, cur_fi.end_ea);
                return;
            }
            uint64_t h = hash_mem(cur_fi.start_ea, DYN_HASH_BYTES);
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
            // whole range.
            lay_out_linear(fstart, fend);
            add_func(fstart, fend);
            // Library (non-target) module code: mark it FUNC_LIB so it renders as
            // <name>+offset and is de-emphasized. The analyzed binary is the
            // user's own code, so its functions stay normal. (A .pdata range
            // means pc is in some module, so "not a library" is the main one.)
            if ( m_modules->is_library_address(pc) && get_func_start(fstart) == fstart
              && (get_func_flags(fstart) & FUNC_LIB) == 0 )
            {
                set_func_flag(fstart, FUNC_LIB, true);
            }
            define_callees(playhead, fstart, fend);
            return;
        }

        // ---- runtime-allocated code (no module, no .pdata): shellcode,
        // unpacked code, JIT. As Binary Ninja's debugger does, define a function
        // and let IDA's recursive descent disassemble the whole thing, seeded at
        // the function head so the prologue and the body above PC are laid out
        // too, and backward stepping finds code already there.
        //
        // The head is preferably the one recovered from the trace's call/return
        // structure (the call that entered this frame), else the
        // executed-address contiguity heuristic -- for a frame entered by a jmp
        // or a thread start, or by a call older than the look-back window.
        ea_t start = find_dynamic_function_entry(playhead, pc);
        if ( start == BADADDR || start > pc || get_segment_ea(start) != seg.start_ea )
            start = find_dynamic_start(playhead, pc);

        // The position-based memory query returns zero-fill for this region's
        // never-executed bytes. Rebuilding them from the trace's recorded writes
        // lets the whole function, not just the executed path, disassemble --
        // what WinDbg shows. Bounded to a window from the head and served
        // thereafter by on_read_memory; IDA's cache for the range is
        // invalidated so the create_insn below reads the real bytes.
        ea_t rlo  = start;
        ea_t aend = (pc > start ? pc : start) + DYN_LAYOUT_SPAN;
        ea_t rhi  = aend;
        // Clamp to the enclosing segment, never widen to it: for dynamic code that
        // segment is the synthetic range covering all of user space.
        if ( rhi > seg.end_ea )
            rhi = seg.end_ea;
        if ( rhi > rlo && m_memory->reconstruct(playhead, rlo, rhi) )
            invalidate_dbgmem_contents(rlo, rhi - rlo);

        force_insn(start);                  // exact-boundary seed
        add_func(start);                    // BADADDR end -> recursive descent
        plan_and_wait(start, aend);         // force the descent synchronously, bounded

        ea_t nfs = get_func_start(pc);
        if ( nfs != BADADDR )
        {
            m_dynFuncBytes[nfs] = hash_mem(nfs, DYN_HASH_BYTES);
            // Give dynamic (non-module) code its own debug name. Debugger views
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

    void CodeAnalyzer::collect_window_pcs(ITraceCursor *playhead, ea_t pc, std::set<ea_t> &pcs)
    {
        pcs.clear();
        if ( m_backend == nullptr || playhead == nullptr )
            return;

        const int64_t BEFORE = 64;      // instructions of context before PC
        const size_t  AFTER  = 192;     // ...and after
        const ea_t    W      = 0x2000;  // only collect addresses within +/-W of PC

        // From a little before the current position, this thread's instruction
        // stream forward: a window, read by the backend without moving the
        // playhead.
        Position from = m_backend->position_add(playhead->position(), -BEFORE);
        std::vector<Access> v;
        m_backend->query_instructions(PositionRange{ from, Position::end() }, playhead->thread_id(),
                                      (size_t)BEFORE + AFTER, &v, nullptr);
        for ( const Access &a : v )
        {
            ea_t d = a.pc > pc ? a.pc - pc : pc - a.pc;
            if ( d <= W )
                pcs.insert(a.pc);
        }
    }

    ea_t CodeAnalyzer::find_dynamic_start(ITraceCursor *playhead, ea_t pc)
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
            if ( lo - *pv > MAX_INSN_LEN )
                break;
            lo = *pv;
            --it;
        }
        return lo;
    }

    // Recover the head of the current frame's function from the trace itself:
    // the call that entered this frame went to it. This is the "change in the
    // callstack" boundary, the dynamic-code analogue of the .pdata bounds used
    // for module code. Bounded, because it runs on every stop in such code.
    ea_t CodeAnalyzer::find_dynamic_function_entry(ITraceCursor *playhead, ea_t pc)
    {
        // The head comes from the cursor's own position, not from 'pc'.
        qnotused(pc);
        if ( m_backend == nullptr || playhead == nullptr )
            return BADADDR;
        ea_t entry = BADADDR;
        if ( !m_backend->query_frame_entry(playhead->position(), playhead->thread_id(), 65536,
                                           nullptr, &entry) )
            return BADADDR;
        return entry;
    }

    void CodeAnalyzer::lay_out_window(ITraceCursor *playhead, ea_t pc)
    {
        if ( m_backend == nullptr || playhead == nullptr )
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

    // A wait box as the queries' ProgressSink. Main thread only.
    class WaitBoxProgress : public ProgressSink
    {
    public:
        explicit WaitBoxProgress(const char *what) : m_what(what) {}
        void report(uint32_t percent) override
        {
            replace_wait_box("%s (Cancel to stop)... %u%%", m_what, percent);
        }
        bool cancelled() override { return user_cancelled(); }

    private:
        const char *m_what;
    };

    // Deep, on-demand analysis: find the call that entered the current frame,
    // then lay out every instruction this frame executed from there to here --
    // the frame's own, not those of the calls it made -- and define the
    // function. The expensive path the per-stop handler avoids, so it runs
    // behind a cancellable wait box.
    void CodeAnalyzer::analyze_whole_function(ITraceCursor *playhead)
    {
        if ( playhead == nullptr || m_backend == nullptr )
        {
            warning("Analysis is only available while replaying a trace.");
            return;
        }
        ea_t pc = playhead->program_counter();
        if ( get_segment_ea(pc) == BADADDR )
            return;
        if ( get_func_start(pc) != BADADDR )
        {
            info("0x%llX is already inside a defined function.", (uint64_t)pc);
            return;
        }

        const uint64_t MAX_INSN = 50000;
        const Position here = playhead->position();
        const uint32_t tid  = playhead->thread_id();

        show_wait_box("Analyzing function from the trace (Cancel to stop)...");
        Position call_pos;
        ea_t     entry = BADADDR;
        bool found = m_backend->query_frame_entry(here, tid, MAX_INSN, &call_pos, &entry);

        // This thread's instructions from the call to here, at depth zero:
        // a call nested in between is counted in and its return out, so only
        // the frame's own instructions are laid out.
        std::vector<ea_t> frame_pcs;
        std::set<ea_t>    seen;
        frame_pcs.push_back(pc);
        seen.insert(pc);
        bool cancelled = false;
        size_t examined = 0;
        if ( found )
        {
            WaitBoxProgress wb("Analyzing function");
            std::vector<Access> v;
            QueryResult r = m_backend->query_instructions(PositionRange{ call_pos, here }, tid,
                                                          (size_t)MAX_INSN, &v, &wb);
            cancelled = r.cancelled;
            examined  = v.size();
            int depth = 0;
            // v[0] is the entering call itself: start after it.
            for ( size_t i = 1; i < v.size(); i++ )
            {
                ea_t a = v[i].pc;
                if ( depth == 0 && seen.insert(a).second )
                    frame_pcs.push_back(a);
                insn_t insn;
                if ( decode_insn(&insn, a) > 0 )
                {
                    if ( is_call_insn(insn) )
                        depth++;
                    else if ( is_ret_insn(insn) && depth > 0 )
                        depth--;
                }
            }
        }
        else
        {
            cancelled = user_cancelled();
        }
        hide_wait_box();

        std::sort(frame_pcs.begin(), frame_pcs.end());
        for ( ea_t a : frame_pcs )
            force_insn(a);

        if ( cancelled )
        {
            msg("[ida-ttd] function analysis cancelled (%d instructions, %d defined).\n",
                (int)examined, (int)frame_pcs.size());
        }
        else if ( found && entry != BADADDR )
        {
            force_insn(entry);
            add_func(entry);
            msg("[ida-ttd] defined function at 0x%llX (entry of the call that entered "
                "this frame; %d instructions).\n", (uint64_t)entry, (int)examined);
            jumpto(entry);
        }
        else
        {
            warning("Could not find the function entry within %d instructions.\n"
                    "Laid out the %d instruction(s) found in this frame.",
                    (int)MAX_INSN, (int)frame_pcs.size());
        }
    }

}
