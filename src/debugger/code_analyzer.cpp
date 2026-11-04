#include "debugger/code_analyzer.h"

namespace idattd
{
    // Bounds that keep the per-stop work cheap.
    static const int    MAX_LINEAR_ITEMS = 0x20000;   // items one linear layout pass creates
    static const ea_t   DYN_LAYOUT_SPAN  = 0x2000;    // bytes of dynamic code laid out past the head or pc
    static const size_t DYN_HASH_BYTES   = 64;        // bytes hashed to notice rewritten dynamic code
    static const ea_t   MAX_INSN_LEN     = 15;        // longest x86 instruction
    static const size_t MAX_FAILED_DYN   = 4096;      // dynamic PCs remembered as not making a function
    void CodeAnalyzer::bind(ITraceBackend *backend, ModuleRegistry *modules,
                            MemoryReader *memory, KeptFunctions *kept, bool is64)
    {
        reset();
        m_backend = backend;
        m_modules = modules;
        m_memory  = memory;
        m_kept    = kept;
        m_is64    = is64;
    }

    void CodeAnalyzer::reset()
    {
        m_backend = nullptr;
        m_modules = nullptr;
        m_memory  = nullptr;
        m_kept    = nullptr;
        m_winLo          = BADADDR;
        m_winHi          = 0;
        m_calleeScanFunc = BADADDR;
        m_pdataExtended.clear();
        m_fragmentChecked.clear();
        m_dynFuncBytes.clear();
        m_failedDyn.clear();
    }

    void CodeAnalyzer::on_stop(ITraceCursor *playhead, ea_t pc)
    {
        analyze_current_function(playhead, pc);
    }

    // Define an instruction at exactly 'ea', an executed PC and so a true
    // boundary. Any stale item overlapping it is cleared first so RIP never
    // points inside a wrongly sized instruction.
    static void force_insn(ea_t ea)
    {
        flags64_t fl = get_flags(ea);
        if ( is_code(fl) && get_item_head(ea) == ea )
            return;                          // already a correct instruction head
        del_items(ea, DELIT_EXPAND);         // drop any item overlapping ea
        create_insn(ea);
    }

    // Lay [lo, hi) out as code in one linear pass, skipping existing code and
    // stepping a byte over what does not decode (jump tables, other embedded
    // data). Bounded by MAX_LINEAR_ITEMS.
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

        // Indirect through a memory slot: "call [rip+disp]" (x64; IDA makes
        // it an absolute o_mem address) or "call ds:xxx" (x86). The slot is an
        // import entry, and in a replay it holds what the loader wrote there.
        if ( op.type == o_mem && op.addr != BADADDR && is_loaded(op.addr) )
        {
            slot_out = op.addr;
            ea_t tgt = m_is64 ? (ea_t)get_qword(op.addr) : (ea_t)get_dword(op.addr);
            // Trusted only if it lands in a recorded module: read before the
            // loader filled the import table, the slot holds something else,
            // and add_func() would carve a function out of garbage.
            if ( tgt != 0 && tgt != BADADDR && m_modules->index_at(tgt) != (size_t)-1 )
                return tgt;
        }

        // call rax / call [rax+8]: only the trace knows the target, and the
        // per-stop path must not replay. Left until execution reaches it.
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
            // .pdata gives exact bounds: lay the body out in one linear pass,
            // as analyze_current_function does for the PC.
            lay_out_linear(fstart, fend);
            add_func(fstart, fend);
        }
        else
        {
            // No .pdata (x86, dynamic code, or not a recorded function head).
            // Seed one instruction and let IDA's recursive descent find the
            // extent; with AF_PROC off it does not cascade into the callees.
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

    // An unconditional jump to an operand (not a ret, which has none): a tail
    // call when it leaves the function.
    static bool is_module_tail_jump(const insn_t &insn)
    {
        if ( (insn.get_canon_feature(PH) & CF_STOP) == 0 )
            return false;
        const optype_t t = insn.ops[0].type;
        return t == o_near || t == o_far || t == o_mem;
    }

    // Defining the targets matters for stepping from pseudocode as well: IDA
    // decides whether a step landed in code it can show before it reports
    // the stop, so before the stop's own analysis runs. A target with no
    // function (kernelbase's VirtualProtect, reached by kernel32's jmp
    // thunk) made it step back out with a breakpoint on the thunk, which
    // this thread never ran again: the step ran to the end of the recording.
    void CodeAnalyzer::define_callees(ITraceCursor *playhead, ea_t lo, ea_t hi)
    {
        if ( lo == BADADDR || hi <= lo )
            return;
        // Stepping inside one function finds nothing new until it changes, so
        // the last one scanned is remembered (and reset wherever a function is
        // rebuilt, so self-modifying code is rescanned).
        if ( lo == m_calleeScanFunc )
            return;
        // Remembered only when every target was defined: at a session's first
        // stop a callee's module may have no segment yet.
        bool complete = true;

        // Caps on how far the walk goes and how many targets it defines keep
        // this cheap enough for every stop.
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
            if ( decode_insn(&insn, ip) > 0 && (is_call_insn(insn) || is_module_tail_jump(insn)) )
            {
                ea_t slot = BADADDR;
                ea_t tgt  = call_target_of(playhead, insn, slot);
                // A tail jump's target is defined only when it is another
                // module's code (an import thunk like kernel32's
                // VirtualProtect, a jmp through its import slot). A jump
                // within the module may land in a chunk of a function.
                if ( !is_call_insn(insn) && tgt != BADADDR
                  && (m_modules->index_at(tgt) == (size_t)-1 || m_modules->index_at(tgt) == m_modules->index_at(ip)) )
                {
                    tgt  = BADADDR;
                    slot = BADADDR;
                }

                if ( tgt != BADADDR && seen.insert(tgt).second )
                {
                    if ( !define_function_at(tgt) )
                        complete = false;
                    defined++;
                }

                // The slot the call reads through: as a pointer-sized offset
                // named after its target it renders "call cs:__imp_CreateFileW"
                // instead of "call cs:unk_X". Only a slot with no name or type
                // of its own is touched.
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

    // Only grows, and only into space nothing else claims: a shorter
    // definition is IDA losing the flow, but a longer one may be deliberate
    // (chunks joined by hand), and another function's range is not this one's.
    void CodeAnalyzer::extend_to_pdata_bounds(ea_t pc, const func_entry_info_t &fi)
    {
        if ( m_pdataExtended.find(fi.start_ea) != m_pdataExtended.end() )
            return;                          // considered once per function

        ea_t ps = BADADDR, pe = BADADDR;
        if ( !m_modules->function_range_at(pc, ps, pe) )
            return;                          // x86, or no .pdata for this module
        m_pdataExtended.insert(fi.start_ea);

        // The .pdata entry must describe this function's own chunk. If it
        // starts elsewhere, pc is in a tail chunk, and joining chunks is a
        // different decision.
        if ( ps != fi.start_ea || pe <= fi.end_ea )
            return;

        segment_info_t seg;
        if ( !get_segment_info(&seg, pc) || pe > seg.end_ea )
            return;

        // Refuse if another function lives in the space it would absorb.
        for ( ea_t a = fi.end_ea; a < pe; a++ )
        {
            if ( get_func_start(a) != BADADDR )
                return;
        }

        // Lay the tail out first: set_func_end over undefined bytes leaves raw
        // data in the function.
        lay_out_linear(fi.end_ea, pe);
        if ( set_func_end(fi.start_ea, pe) )
        {
            msg("[ida-ttd] extended %a..%a to %a from the module's exception "
                "table.\n", fi.start_ea, fi.end_ea, pe);
            m_calleeScanFunc = BADADDR;      // the new tail may call things
        }
    }

    // Whether the function holding the instruction before 'ea' falls straight
    // into it: that function ends at 'ea' and flows on. Its start goes in
    // 'head', and whether its last instruction is a call in 'last_call' (it
    // could be a noreturn call IDA does not know).
    static bool falls_into(ea_t ea, ea_t seg_start, ea_t *head, bool *last_call)
    {
        func_entry_info_t prev;
        ea_t p = prev_head(ea, seg_start);
        if ( p == BADADDR || !get_func_entry_info(&prev, p) || prev.end_ea != ea
          || !is_flow(get_flags(ea)) )
            return false;
        *head = prev.start_ea;
        insn_t last;
        *last_call = decode_insn(&last, p) > 0 && is_call_insn(last);
        return true;
    }

    // A guessed start (the head of the executed run, often a loop head) moved
    // back over loose code that falls into it, to an instruction nothing
    // falls into, one something calls, or one another function jumps to (a
    // tail call): the function's real head.
    static ea_t walk_back_to_head(ea_t ea, ea_t seg_start)
    {
        ea_t h = ea;
        for ( int guard = 0; guard < 0x1000; guard++ )
        {
            const ea_t own = get_func_start(h);
            xrefblk_t xb;
            for ( bool ok = xb.first_to(h, XREF_CODE); ok; ok = xb.next_to() )
            {
                if ( xb.type == fl_CN || xb.type == fl_CF )
                    return h;
                if ( (xb.type == fl_JN || xb.type == fl_JF)
                  && get_func_start(xb.from) != BADADDR && get_func_start(xb.from) != own )
                    return h;
            }
            if ( !is_flow(get_flags(h)) )
                return h;
            ea_t p = prev_head(h, seg_start);
            if ( p == BADADDR || !is_code(get_flags(p)) || get_func_start(p) != BADADDR )
                return h;
            h = p;
        }
        return h;
    }

    // Replace the functions starting at 'head' and 'drop' (BADADDR: none) by
    // one laid out from 'head' by recursive descent. Kept only when it then
    // covers 'pc'; otherwise the old bounds are put back.
    ea_t CodeAnalyzer::redefine_from(ea_t head, ea_t drop, ea_t pc)
    {
        func_entry_info_t old_head, old_drop;
        const bool had_head = get_func_entry_info(&old_head, head) && old_head.start_ea == head;
        const bool had_drop = drop != BADADDR && get_func_entry_info(&old_drop, drop);
        if ( had_drop )
            del_func(drop);
        if ( had_head )
            del_func(head);
        force_insn(head);
        add_func(head);
        plan_and_wait(head, pc + DYN_LAYOUT_SPAN);
        if ( get_func_start(pc) == head )
        {
            m_dynFuncBytes.erase(drop);
            m_dynFuncBytes[head] = hash_mem(head, DYN_HASH_BYTES);
            m_calleeScanFunc = BADADDR;
            return head;
        }
        del_func(head);
        if ( had_head )
            add_func(old_head.start_ea, old_head.end_ea);
        if ( had_drop )
            add_func(old_drop.start_ea, old_drop.end_ea);
        return BADADDR;
    }

    ea_t CodeAnalyzer::merge_fragment(ITraceCursor *playhead, ea_t pc, const func_entry_info_t &fi)
    {
        if ( !m_fragmentChecked.insert(fi.start_ea).second )
            return BADADDR;                  // refused before
        ea_t ps, pe;
        if ( m_modules->function_range_at(pc, ps, pe) )
            return BADADDR;                  // the exception table knows better
        ea_t head = BADADDR;
        bool last_call = false;
        if ( falls_into(fi.start_ea, get_segment_ea(pc), &head, &last_call) )
        {
            // Confirmed by the call that entered this frame, when it is known.
            const ea_t entry = find_dynamic_function_entry(playhead, pc);
            if ( entry != BADADDR ? entry != head : last_call )
                return BADADDR;
        }
        else
        {
            // Loose code running into it: the head is further back.
            head = walk_back_to_head(fi.start_ea, get_segment_ea(pc));
            if ( head == fi.start_ea )
                return BADADDR;              // nothing falls into it: a real head
            const ea_t entry = find_dynamic_function_entry(playhead, pc);
            if ( entry != BADADDR && entry != head )
                return BADADDR;
        }
        ea_t got = redefine_from(head, fi.start_ea, pc);
        if ( got != BADADDR )
        {
            m_fragmentChecked.erase(fi.start_ea);   // remembered only when refused
            msg("[ida-ttd] joined the function at %a to the one at %a, which runs into it.\n",
                fi.start_ea, head);
        }
        return got;
    }

    ea_t CodeAnalyzer::extend_into(ITraceCursor *playhead, ea_t pc, ea_t seg_start)
    {
        ea_t ps, pe;
        if ( m_modules->function_range_at(pc, ps, pe) )
            return BADADDR;
        // Back over the code no function owns to where the run starts.
        ea_t r = get_item_head(pc);
        for ( int guard = 0; guard < 0x800; guard++ )
        {
            if ( !is_code(get_flags(r)) || !is_flow(get_flags(r)) )
                return BADADDR;
            ea_t p = prev_head(r, seg_start);
            if ( p == BADADDR || !is_code(get_flags(p)) )
                return BADADDR;
            if ( get_func_start(p) != BADADDR )
                break;
            r = p;
        }
        ea_t head = BADADDR;
        bool last_call = false;
        if ( !falls_into(r, seg_start, &head, &last_call) )
            return BADADDR;
        // The function before may itself be a fragment of the frame's
        // function: then both are joined.
        ea_t drop = BADADDR;
        const ea_t entry = find_dynamic_function_entry(playhead, pc);
        if ( entry != BADADDR && entry != head )
        {
            ea_t h2 = BADADDR;
            bool c2 = false;
            if ( !(entry < head && falls_into(head, seg_start, &h2, &c2) && h2 == entry) )
                return BADADDR;
            drop = head;
            head = entry;
        }
        else if ( entry == BADADDR )
        {
            if ( last_call )
                return BADADDR;
            // No entry to go by: a fragment is told by what runs into it.
            ea_t h2 = BADADDR;
            bool c2 = false;
            if ( falls_into(head, seg_start, &h2, &c2) && !c2 )
            {
                drop = head;
                head = h2;
            }
        }
        ea_t got = redefine_from(head, drop, pc);
        if ( got != BADADDR )
            msg("[ida-ttd] extended the function at %a over the code it runs into at %a.\n",
                head, r);
        return got;
    }

    ea_t CodeAnalyzer::fit_to_table(ea_t pc, const func_entry_info_t &fi, ea_t seg_end)
    {
        ea_t ps, pe, s2, e2;
        if ( !m_modules->function_range_at(pc, ps, pe) || ps >= fi.start_ea || pe > seg_end )
            return BADADDR;
        // A table entry starting at the function (a chunk of a function
        // described in pieces) is not a fragment.
        if ( m_modules->function_range_at(fi.start_ea, s2, e2) && s2 == fi.start_ea )
            return BADADDR;
        for ( ea_t ea = ps; ea != BADADDR && ea < pe; ea = next_head(ea, pe) )
            if ( get_func_start(ea) == ea )
                del_func(ea);
        lay_out_linear(ps, pe);
        if ( !add_func(ps, pe) )
            return BADADDR;
        m_dynFuncBytes.erase(fi.start_ea);
        m_calleeScanFunc = BADADDR;
        msg("[ida-ttd] the function at %a is part of %a..%a in the module's exception table; "
            "redefined it so.\n", fi.start_ea, ps, pe);
        return ps;
    }

    void CodeAnalyzer::analyze_current_function(ITraceCursor *playhead, ea_t pc)
    {
        segment_info_t seg;
        if ( !get_segment_info(&seg, pc) )
            return;

        // A packed module's real exception table appears once it unpacks.
        if ( m_modules->refresh_function_ranges(pc, playhead) )
        {
            m_pdataExtended.clear();
            m_fragmentChecked.clear();
        }

        func_entry_info_t cur_fi;
        if ( get_func_entry_info(&cur_fi, pc) )
        {
            // An existing function may be defined short: static analysis stops
            // where it loses the flow (a noreturn call, an opaque tail jump,
            // embedded data) and the tail renders as a JUMPOUT. The exception
            // table says where it really ends.
            extend_to_pdata_bounds(pc, cur_fi);

            // One that starts inside a table entry without being one is a
            // fragment of that entry's function.
            ea_t whole = fit_to_table(pc, cur_fi, seg.end_ea);
            if ( whole != BADADDR )
            {
                func_entry_info_t wfi;
                if ( get_func_entry_info(&wfi, whole) )
                    define_callees(playhead, wfi.start_ea, wfi.end_ea);
                return;
            }

            // A fragment of the function before it, cut off at a loop head.
            ea_t merged = merge_fragment(playhead, pc, cur_fi);
            if ( merged != BADADDR )
            {
                func_entry_info_t mfi;
                if ( get_func_entry_info(&mfi, merged) )
                    define_callees(playhead, mfi.start_ea, mfi.end_ea);
                return;
            }

            // A function this class defined in dynamic memory is checked for a
            // rewrite (self-modifying or reused region, or a travel to where
            // the address holds different code) by hashing its bytes. Any
            // other, or an unchanged one, is kept.
            auto it = m_dynFuncBytes.find(cur_fi.start_ea);
            if ( it == m_dynFuncBytes.end() )
            {
                // Its call targets may still be undefined (defined by the PDB
                // plugin, or on an earlier visit before a callee's module was
                // mapped). Cheap thanks to define_callees' memo.
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
            // Module function with .pdata bounds: disassemble the whole range.
            lay_out_linear(fstart, fend);
            add_func(fstart, fend);
            // Library code is marked FUNC_LIB so it renders as <name>+offset
            // and is de-emphasized; the analysed binary's functions stay
            // normal.
            if ( m_modules->is_library_address(pc) && get_func_start(fstart) == fstart
              && (get_func_flags(fstart) & FUNC_LIB) == 0 )
            {
                set_func_flag(fstart, FUNC_LIB, true);
            }
            define_callees(playhead, fstart, fend);
            return;
        }

        // ---- dynamic code (no module, no .pdata): shellcode, unpacked code,
        // JIT. As Binary Ninja's debugger does, define a function and let IDA's
        // recursive descent disassemble it, seeded at the head so the prologue
        // and the body above PC are laid out and backward steps find code.
        //
        // The head is the one recovered from the call that entered this frame,
        // else the executed-address contiguity heuristic (a frame entered by a
        // jmp or a thread start, or by a call older than the bound).
        //
        // A PC where this already failed to make a function, with the same
        // bytes, would fail again after the same bounded frame query and
        // rebuild; only the cheap window layout is repeated.
        // A function the user worked on in an earlier session (or before a
        // travel rebuilt the segments), with these bytes: defined with its
        // kept bounds, its work restored after the stop's analysis.
        if ( m_kept != nullptr )
        {
            ea_t ks = m_kept->define_at(playhead, pc);
            func_entry_info_t kfi;
            if ( ks != BADADDR && get_func_start(pc) == ks && get_func_entry_info(&kfi, ks) )
            {
                m_dynFuncBytes[ks] = hash_mem(ks, DYN_HASH_BYTES);
                qstring nm;
                if ( get_func_name(&nm, ks) > 0 && !nm.empty() )
                    set_debug_name(ks, nm.c_str());
                define_callees(playhead, kfi.start_ea, kfi.end_ea);
                return;
            }
        }

        // Code the function before it falls into: that function was cut short.
        ea_t grown = extend_into(playhead, pc, seg.start_ea);
        if ( grown != BADADDR )
        {
            func_entry_info_t gfi;
            if ( get_func_entry_info(&gfi, grown) )
                define_callees(playhead, gfi.start_ea, gfi.end_ea);
            return;
        }

        auto failed = m_failedDyn.find(pc);
        if ( failed != m_failedDyn.end() )
        {
            if ( failed->second == hash_mem(pc, DYN_HASH_BYTES) )
            {
                lay_out_window(playhead, pc);
                define_callees(playhead, m_winLo, m_winHi);
                return;
            }
            m_failedDyn.erase(failed);      // the code there changed: try again
        }

        // A frame entry inside a function that does not reach pc is the
        // function called, which then tail-jumped here (ntdll does this into
        // its leaf functions): its head is not this code's.
        ea_t start = find_dynamic_function_entry(playhead, pc);
        if ( start != BADADDR && get_func_start(start) != BADADDR && get_func_start(start) != get_func_start(pc) )
            start = BADADDR;
        if ( start == BADADDR || start > pc || get_segment_ea(start) != seg.start_ea )
            start = walk_back_to_head(find_dynamic_start(playhead, pc), seg.start_ea);

        // The position query zero-fills this region's never-executed bytes.
        // Rebuilding them from recorded writes lets the whole function
        // disassemble, not just the executed path, as in WinDbg. Bounded to a
        // window from the head; IDA's cache for it is invalidated so
        // create_insn below reads the real bytes.
        //
        // Not for a leaf function of a module with an exception table: that
        // is the module's own code, read like its other functions (recording,
        // then file), and nothing wrote it. The rebuild replays from the
        // start of the recording, found nothing there, and so ran again on
        // every step.
        ea_t rlo  = start;
        ea_t aend = (pc > start ? pc : start) + DYN_LAYOUT_SPAN;
        ea_t rhi  = aend;
        // Clamp to the segment, never widen to it: for dynamic code it can be
        // the filler covering all of user space.
        if ( rhi > seg.end_ea )
            rhi = seg.end_ea;
        if ( rhi > rlo && !m_modules->has_function_table(pc) && m_memory->reconstruct(playhead, rlo, rhi) )
            invalidate_dbgmem_contents(rlo, rhi - rlo);

        force_insn(start);                  // exact-boundary seed
        add_func(start);                    // BADADDR end -> recursive descent
        plan_and_wait(start, aend);         // force the descent synchronously, bounded

        ea_t nfs = get_func_start(pc);
        if ( nfs != BADADDR )
        {
            m_dynFuncBytes[nfs] = hash_mem(nfs, DYN_HASH_BYTES);
            // Give dynamic code its own debug name. Debugger views use the
            // nearest debug name at or below an address, so otherwise a far
            // lower module symbol shows as "<unrelated>+huge_offset".
            qstring nm;
            if ( get_func_name(&nm, nfs) > 0 && !nm.empty() )
                set_debug_name(nfs, nm.c_str());
            // A system module's leaf function is library code, as its
            // functions with table entries are.
            if ( nfs == get_func_start(nfs) && m_modules->is_library_address(nfs)
              && (get_func_flags(nfs) & FUNC_LIB) == 0 )
                set_func_flag(nfs, FUNC_LIB, true);

            // Shellcode calls into real modules constantly (LoadLibrary,
            // VirtualProtect); defining the targets turns "call unk_7FF8xxxx"
            // into a named import.
            func_entry_info_t nfi;
            ea_t nfe = get_func_entry_info(&nfi, nfs) && nfi.end_ea > nfs
                     ? nfi.end_ea : aend;
            define_callees(playhead, nfs, nfe);
        }
        else
        {
            // Remembered with a hash of the bytes, so a rewrite is retried. An
            // unreadable PC (hash 0) is not remembered; the set is bounded by
            // starting over when it fills.
            uint64_t h = hash_mem(pc, DYN_HASH_BYTES);
            if ( h != 0 )
            {
                if ( m_failedDyn.size() >= MAX_FAILED_DYN )
                    m_failedDyn.clear();
                m_failedDyn[pc] = h;
            }
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

        // This thread's instruction stream from a little before the current
        // position, read without moving the playhead.
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

        // Walk down while executed addresses chain by instruction (gap at most
        // the longest x86 instruction). A larger gap means a different block
        // reached by a jump, not the linear prologue.
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

    // The head of the current frame's function is where the call that entered
    // the frame went: the dynamic-code analogue of .pdata bounds. Bounded,
    // since it can run on every stop in such code.
    ea_t CodeAnalyzer::find_dynamic_function_entry(ITraceCursor *playhead, ea_t pc)
    {
        if ( m_backend == nullptr || playhead == nullptr )
            return BADADDR;
        ea_t entry = BADADDR;
        if ( m_backend->query_frame_entry(playhead->position(), playhead->thread_id(), 65536,
                                          nullptr, &entry) && entry != BADADDR )
            return entry;
        return stack_scan_entry(playhead, pc);
    }

    // The call is older than the bound: find its return address on the stack,
    // as a debugger's unwinder does. The first value up from rsp that follows
    // a direct call (E8 rel32) to an address at most 64 KiB below pc, in pc's
    // segment, gives the entry.
    ea_t CodeAnalyzer::stack_scan_entry(ITraceCursor *playhead, ea_t pc)
    {
        const size_t W = m_is64 ? 8 : 4;
        uint8_t stack[0x800];
        std::vector<uint8_t> known;
        if ( playhead->read_memory((ea_t)playhead->stack_pointer(), stack, sizeof(stack), &known) == 0 )
            return BADADDR;
        const ea_t seg = get_segment_ea(pc);
        for ( size_t off = 0; off + W <= sizeof(stack) && off + W <= known.size(); off += W )
        {
            if ( known[off] != ITTD_KNOWN_YES )
                continue;
            uint64_t ret = 0;
            memcpy(&ret, stack + off, W);
            if ( ret < 5 || get_segment_ea((ea_t)ret) == BADADDR )
                continue;
            uint8_t call[5];
            std::vector<uint8_t> k;
            if ( playhead->read_memory((ea_t)(ret - 5), call, sizeof(call), &k) != sizeof(call)
              || call[0] != 0xE8 )
                continue;
            int32_t rel = 0;
            memcpy(&rel, call + 1, sizeof(rel));
            const ea_t target = (ea_t)(ret + (int64_t)rel);
            if ( target <= pc && pc - target < 0x10000 && get_segment_ea(target) == seg )
                return target;
        }
        return BADADDR;
    }

    void CodeAnalyzer::lay_out_window(ITraceCursor *playhead, ea_t pc)
    {
        if ( m_backend == nullptr || playhead == nullptr )
            return;

        // A laid-out window already surrounds PC: skip the query. The validity
        // test matters: m_winLo == BADADDR means "no window", and without it
        // +0x40 wraps to 0x3F and the test passes for every code address,
        // disabling the layout for good.
        if ( m_winLo != BADADDR && m_winLo < m_winHi
          && pc >= m_winLo + 0x40 && pc + 0x40 <= m_winHi
          && is_code(get_flags(pc)) )
            return;

        std::set<ea_t> pcs;
        collect_window_pcs(playhead, pc, pcs);

        // Define the executed instructions (real boundaries).
        for ( ea_t a : pcs )
            force_insn(a);

        if ( pcs.empty() )
        {
            force_insn(pc);             // at least the current instruction
            m_winLo = BADADDR;          // "no window", as initially
            m_winHi = 0;
            return;
        }

        // Decode linearly on from the furthest executed instruction (a real
        // boundary) so the user can scroll ahead.
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

    // On-demand analysis: find the call that entered the current frame, lay
    // out every instruction the frame itself executed since (not those of its
    // calls), and define the function. Expensive, so behind a cancellable wait
    // box.
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

        // This thread's instructions from the call to here at depth zero:
        // nested calls count in and returns out, so only the frame's own
        // instructions are laid out.
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
