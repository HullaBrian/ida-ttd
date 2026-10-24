#include "analysis/origin.h"
#include "analysis/query_runner.h"
#include "debugger/trace_manager.h"
#include "ui/names.h"

#include <intel.hpp>

namespace idattd
{
    namespace
    {
        const char *const GP_NAMES[ITTD_REG_GP_COUNT] =
        {
            "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip",
        };

        // How far back a register's last change is sought. The backend's own
        // search replays the thread forward (seconds per few million steps);
        // stepping back one at a time, without one, costs a millisecond or
        // more per step.
        const uint64_t kRegisterLookBack = 4000000;
        const uint64_t kStepLookBack     = 200000;
        // Syscalls checked for having written memory, latest first.
        const size_t   kSyscallsChecked  = 300;

        // IDA's x86 register number to ITTD_REG_* / ITTD_ORIGIN_XMM0 + n;
        // -1 for those not followed (segment, flags, x87, ...).
        int ittd_reg_of(int r)
        {
            if ( r >= R_ax && r <= R_r15 )
                return r - R_ax;
            if ( r >= R_al && r <= R_bl )
                return r - R_al;
            if ( r >= R_ah && r <= R_bh )
                return r - R_ah;
            if ( r >= R_spl && r <= R_dil )
                return ITTD_REG_RSP + (r - R_spl);
            if ( r >= R_xmm0 && r <= R_xmm15 )
                return int(ITTD_ORIGIN_XMM0) + (r - R_xmm0);
            if ( r >= R_ymm0 && r <= R_ymm15 )
                return int(ITTD_ORIGIN_XMM0) + (r - R_ymm0);
            return -1;
        }

        bool same_target(const OriginTarget &a, const OriginTarget &b)
        {
            return a.is_reg == b.is_reg && (a.is_reg ? a.reg == b.reg : a.addr == b.addr && a.size == b.size);
        }

        bytevec_t read_value(ITraceCursor *cur, const OriginTarget &t, uint32_t tid)
        {
            bytevec_t v;
            if ( t.is_reg )
            {
                // Nothing between the general registers and xmm0, or past
                // the last xmm.
                const uint32_t nxmm = (uint32_t)std::extent_v<decltype(ittd_regs::xmm)>;
                if ( t.reg >= ITTD_ORIGIN_XMM0 + nxmm || (t.reg >= ITTD_REG_GP_COUNT && t.reg < ITTD_ORIGIN_XMM0) )
                    return v;
                ittd_regs r{};
                bool ok = cur->thread_id() == tid ? cur->read_registers(&r) : cur->read_thread_registers(tid, &r);
                if ( !ok )
                    return v;
                if ( t.reg >= ITTD_ORIGIN_XMM0 )
                    v.append(r.xmm[t.reg - ITTD_ORIGIN_XMM0], 16);
                else
                    v.append(&r.gp[t.reg], 8);
                return v;
            }
            v.resize(t.size);
            std::vector<uint8_t> known;
            cur->read_memory(t.addr, v.begin(), v.size(), &known);
            return v;
        }

        // What one hop's backend phase found (worker thread, no IDA calls).
        struct Search
        {
            bool        found = false;      // an instruction of the program set it
            Position    pos;
            ea_t        pc = BADADDR;
            uint32_t    tid = 0;
            bool        stepped = false;    // searched by stepping back (no backend search)
            uint64_t    looked = 0;         // how far, when not found
            // The system wrote it after the program last did (memory).
            bool        system = false;
            Position    sys_pos;
            qstring     sys_name;
            std::vector<Access> reads;      // what the setting instruction read
        };

        // The reads the instruction at 'pc' made in the one step at 'pos'.
        void reads_at(ITraceBackend *b, Position pos, ea_t pc, std::vector<Access> *out, ProgressSink *sink)
        {
            // All of user space; the one-step range is what narrows it.
            const ea_t hi = b->info().is64 ? (ea_t)0x800000000000ull : (ea_t)0x100000000ull;
            PositionRange one{ pos, b->position_add(pos, 1) };
            std::vector<Access> v;
            b->query_accesses(0, hi, ACCESS_READ, one, &v, sink);
            for ( const Access &a : v )
                if ( a.pc == pc )
                    out->push_back(a);
        }

        void find_reads(ITraceBackend *b, Search *s, ProgressSink *sink)
        {
            if ( s->found )
                reads_at(b, s->pos, s->pc, &s->reads, sink);
        }

        void search_register(ITraceBackend *b, const OriginTarget &t, Position at, uint32_t tid,
                             Search *s, ProgressSink *sink)
        {
            Position where;
            bool found = false;
            if ( b->query_register_change(at, tid, t.reg, kRegisterLookBack, &where, &found, sink) )
            {
                s->looked = kRegisterLookBack;
                if ( found )
                {
                    CursorPtr cur = b->make_cursor();
                    if ( cur && cur->seek(where) )
                    {
                        s->found = true;
                        s->pos   = where;
                        s->pc    = cur->program_counter();
                        s->tid   = cur->thread_id();
                    }
                }
                return;
            }

            // No search of the backend's own: step back on the thread.
            s->stepped = true;
            CursorPtr cur = b->make_cursor();
            if ( !cur || !cur->seek(at) )
                return;
            std::unique_ptr<INavigator> nav = b->make_navigator(cur.get());
            if ( !nav )
                return;
            const bytevec_t v0 = read_value(cur.get(), t, tid);
            for ( uint64_t i = 0; i < kStepLookBack; i++ )
            {
                if ( (i & 255) == 0 && sink != nullptr )
                {
                    if ( sink->cancelled() )
                        return;
                    sink->report(uint32_t(i * 100 / kStepLookBack));
                }
                if ( nav->step(false) != StopReason::Stepped )
                    break;
                s->looked = i + 1;
                if ( read_value(cur.get(), t, tid) != v0 )
                {
                    s->found = true;
                    s->pos   = cur->position();
                    s->pc    = cur->program_counter();
                    s->tid   = cur->thread_id();
                    return;
                }
            }
        }

        // The syscalls, listed at most once per trace_value_origin: on
        // Microsoft TTD a listing replays the whole recording.
        struct SyscallCache
        {
            bool                      listed = false;
            std::vector<SyscallEvent> calls;
        };

        // Memory is set by the program's last write to it, or by the system
        // afterwards, which may not be reported as a write (Microsoft TTD
        // reports a syscall filling a buffer as other access kinds). So when
        // the value after the program's write differs from the one asked
        // about, or the program never wrote it, the syscalls since are checked,
        // latest first.
        void search_memory(ITraceBackend *b, const OriginTarget &t, Position at, const bytevec_t &value,
                           SyscallCache *sc_cache, Search *s, ProgressSink *sink)
        {
            CursorPtr cur = b->make_cursor();
            if ( !cur || !cur->seek(at) )
                return;
            {
                std::unique_ptr<INavigator> nav = b->make_navigator(cur.get());
                if ( !nav )
                    return;
                Breakpoint bp;
                bp.addr  = t.addr;
                bp.size  = t.size;
                bp.kinds = ACCESS_WRITE;
                nav->set_breakpoints({ bp });
                nav->set_progress(sink);
                StopReason r = nav->run(false);
                nav->set_progress(nullptr);
                if ( r == StopReason::Breakpoint )
                {
                    s->found = true;
                    s->pos   = cur->position();
                    s->pc    = cur->program_counter();
                    s->tid   = cur->thread_id();
                }
            }
            if ( sink != nullptr && sink->cancelled() )
                return;

            // The value just after that write, on its thread.
            if ( s->found )
            {
                CursorPtr c2 = b->make_cursor();
                if ( c2 && c2->seek(s->pos) )
                {
                    std::unique_ptr<INavigator> n2 = b->make_navigator(c2.get());
                    if ( n2 && n2->step(true) == StopReason::Stepped && read_value(c2.get(), t, 0) == value )
                        return;
                }
            }

            if ( !b->capabilities().syscalls )
                return;
            if ( !sc_cache->listed )
            {
                // Start clean: never append to a listing left part-done.
                sc_cache->calls.clear();
                b->query_syscalls(&sc_cache->calls, sink);
                sc_cache->listed = !(sink != nullptr && sink->cancelled());
            }
            const std::vector<SyscallEvent> &calls = sc_cache->calls;
            size_t checked = 0;
            for ( auto it = calls.rbegin(); it != calls.rend() && checked < kSyscallsChecked; ++it )
            {
                if ( !(it->pos < at) )
                    continue;
                if ( s->found && !(s->pos < it->pos) )
                    break;
                if ( sink != nullptr && sink->cancelled() )
                    return;
                checked++;
                CursorPtr c = b->make_cursor();
                if ( !c || !c->seek(it->pos) )
                    continue;
                const bytevec_t before = read_value(c.get(), t, 0);
                const ea_t      sys_pc = c->program_counter();
                std::unique_ptr<INavigator> n = b->make_navigator(c.get());
                if ( !n || n->step(true) != StopReason::Stepped )
                    continue;
                const bytevec_t after = read_value(c.get(), t, 0);
                if ( after == value && before != after )
                {
                    s->system   = true;
                    s->sys_pos  = it->pos;
                    s->sys_name = it->name.empty() ? qstring("a syscall") : it->name;
                    s->found    = true;
                    s->pos      = it->pos;
                    s->pc       = sys_pc;
                    s->tid      = it->tid;
                    return;
                }
            }
        }

        bool is_copy(uint16 itype)
        {
            switch ( itype )
            {
                case NN_mov: case NN_movzx: case NN_movsx: case NN_movsxd:
                case NN_movd: case NN_movq: case NN_movdqa: case NN_movdqu:
                case NN_movups: case NN_movaps: case NN_movupd: case NN_movapd:
                case NN_movss: case NN_movsd: case NN_lddqu:
                case NN_vmovd: case NN_vmovq: case NN_vmovdqa: case NN_vmovdqu:
                case NN_vmovups: case NN_vmovaps: case NN_vmovupd: case NN_vmovapd:
                case NN_vmovdqu8: case NN_vmovdqu16: case NN_vmovdqu32: case NN_vmovdqu64:
                case NN_vmovdqa32: case NN_vmovdqa64:
                    return true;
                default:
                    return false;
            }
        }

        bool is_memory(const op_t &op)
        {
            return op.type == o_mem || op.type == o_displ || op.type == o_phrase;
        }

        // The recorded read of the instruction's memory operand: one of
        // 'want_size' bytes when there is one, else the first.
        const Access *pick_read(const Search &s, size_t want_size)
        {
            const Access *any = nullptr;
            for ( const Access &a : s.reads )
            {
                if ( want_size != 0 && a.size == want_size )
                    return &a;
                if ( any == nullptr )
                    any = &a;
            }
            return any;
        }

        // From the instruction that set the value, what to follow next: for a
        // copy, fills 'next' and returns true; otherwise sets the kind and
        // note and returns false. 'made_here' is set when the instruction
        // computed the value into its destination (not a side-effect
        // register), so its inputs are what the value was made of.
        bool next_source(const OriginHop &hop, const Search &s, OriginHop *out, OriginTarget *next,
                         bool *made_here)
        {
            *made_here = false;
            insn_t ins;
            if ( decode_insn(&ins, s.pc) <= 0 )
            {
                out->kind = OriginKind::Computed;
                out->note = "the instruction could not be decoded here";
                return false;
            }
            if ( ins.itype == NN_syscall || ins.itype == NN_sysenter )
            {
                out->kind = OriginKind::System;
                out->note = hop.what.is_reg ? "the result of a syscall" : "written by the system during a syscall";
                return false;
            }

            // A register a copy changes as a side effect (rsp under push and
            // pop, rsi/rdi/rcx under string moves) was computed, not copied.
            if ( hop.what.is_reg )
            {
                const int want = int(hop.what.reg);
                auto names = [&](const op_t &op) { return op.type == o_reg && ittd_reg_of(op.reg) == want; };
                bool dest = true;
                switch ( ins.itype )
                {
                    case NN_push: case NN_movs: case NN_stos:
                        dest = false;
                        break;
                    case NN_lods:
                        dest = want == ITTD_REG_RAX;
                        break;
                    case NN_xchg:
                        dest = names(ins.ops[0]) || names(ins.ops[1]);
                        break;
                    case NN_pop:
                        dest = names(ins.ops[0]);
                        break;
                    default:
                        if ( is_copy(ins.itype) )
                            dest = names(ins.ops[0]);
                        break;
                }
                if ( !dest )
                {
                    out->kind = OriginKind::Computed;
                    out->note = "changed as a side effect of this instruction";
                    return false;
                }
            }

            const op_t *src = nullptr;
            bool from_read = false;           // the source is what it read
            int  stos_size = 0;
            switch ( ins.itype )
            {
                case NN_push:
                    src = &ins.ops[0];
                    break;
                case NN_pop:
                case NN_movs:
                case NN_lods:
                    from_read = true;
                    break;
                case NN_stos:
                    stos_size = (int)get_dtype_size(ins.ops[0].dtype);
                    break;
                case NN_xchg:
                {
                    // The operand that is not the value's destination.
                    const op_t &a = ins.ops[0], &b = ins.ops[1];
                    bool a_is_dest = hop.what.is_reg
                                   ? a.type == o_reg && ittd_reg_of(a.reg) == int(hop.what.reg)
                                   : is_memory(a);
                    src = a_is_dest ? &b : &a;
                    break;
                }
                default:
                    if ( is_copy(ins.itype) )
                        src = &ins.ops[1];
                    break;
            }

            if ( stos_size != 0 )
            {
                next->is_reg = true;
                next->reg    = ITTD_REG_RAX;
                out->kind = OriginKind::Copied;
                out->note = "stored from rax";
                return true;
            }
            // xor or sub of a register with itself: zero, whatever it held.
            if ( src == nullptr && !from_read
              && ins.ops[0].type == o_reg && ins.ops[1].type == o_reg && ins.ops[0].reg == ins.ops[1].reg )
            {
                switch ( ins.itype )
                {
                    case NN_xor: case NN_sub: case NN_pxor: case NN_xorps: case NN_xorpd:
                        out->kind = OriginKind::Constant;
                        out->note = "zeroed: a register combined with itself";
                        return false;
                    default:
                        break;
                }
            }
            if ( src == nullptr && !from_read )
            {
                out->kind = OriginKind::Computed;
                out->note = "computed by this instruction";
                *made_here = true;
                return false;
            }
            if ( src != nullptr && src->type == o_imm )
            {
                out->kind = OriginKind::Constant;
                out->note.sprnt("the constant 0x%llX in the code", (unsigned long long)src->value);
                return false;
            }
            if ( src != nullptr && src->type == o_reg )
            {
                int r = ittd_reg_of(src->reg);
                if ( r < 0 )
                {
                    out->kind = OriginKind::Computed;
                    out->note = "copied from a register this does not follow";
                    return false;
                }
                next->is_reg = true;
                next->reg    = (uint32_t)r;
                out->kind = OriginKind::Copied;
                out->note.sprnt("copied from %s", origin_target_text(*next).c_str());
                return true;
            }
            // From memory: the recorded read gives the address.
            size_t want = src != nullptr ? get_dtype_size(src->dtype) : 0;
            const Access *rd = pick_read(s, want);
            if ( rd == nullptr )
            {
                out->kind = OriginKind::Computed;
                out->note = "copied from memory, but the recording has no read for it";
                return false;
            }
            next->is_reg = false;
            next->addr   = rd->addr;
            next->size   = rd->size != 0 ? rd->size : 8;
            out->kind = OriginKind::Copied;
            out->note.sprnt("copied from %s", origin_target_text(*next).c_str());
            return true;
        }
    }

    qstring origin_value_text(const bytevec_t &v)
    {
        qstring s;
        if ( v.empty() )
            return "?";
        if ( v.size() <= 8 )
        {
            uint64_t x = 0;
            memcpy(&x, v.begin(), v.size());
            s.sprnt("0x%llX", (unsigned long long)x);
            return s;
        }
        for ( size_t i = 0; i < v.size(); i++ )
            s.cat_sprnt("%02X", v[i]);
        return s;
    }

    qstring origin_target_text(const OriginTarget &t)
    {
        qstring s;
        if ( t.is_reg )
        {
            if ( t.reg >= ITTD_ORIGIN_XMM0 )
                s.sprnt("xmm%u", t.reg - ITTD_ORIGIN_XMM0);
            else if ( t.reg < ITTD_REG_GP_COUNT )
                s = GP_NAMES[t.reg];
            return s;
        }
        s.sprnt("[0x%llX], %u byte%s", (unsigned long long)t.addr, t.size, t.size == 1 ? "" : "s");
        return s;
    }

    bool parse_register(const char *name, uint32_t *reg)
    {
        qstring n(name);
        n.trim2();
        for ( size_t i = 0; i < n.length(); i++ )
            n[i] = qtolower(n[i]);
        for ( uint32_t i = 0; i < ITTD_REG_RIP; i++ )
            if ( n == GP_NAMES[i] )
                return *reg = i, true;
        // 32-, 16- and 8-bit names of the first eight map to the 64-bit one.
        static const char *const NARROW[][4] =
        {
            { "eax", "ax", "al", "ah" }, { "ecx", "cx", "cl", "ch" },
            { "edx", "dx", "dl", "dh" }, { "ebx", "bx", "bl", "bh" },
            { "esp", "sp", "spl", "" }, { "ebp", "bp", "bpl", "" },
            { "esi", "si", "sil", "" }, { "edi", "di", "dil", "" },
        };
        for ( uint32_t i = 0; i < 8; i++ )
            for ( const char *alias : NARROW[i] )
                if ( *alias != '\0' && n == alias )
                    return *reg = i, true;
        // r8d, r8w, r8b and the like map to their 64-bit register.
        if ( n.length() >= 2 && n[0] == 'r' && qisdigit(n[1]) )
        {
            char *end = nullptr;
            unsigned long k = strtoul(n.c_str() + 1, &end, 10);
            if ( end != n.c_str() + 1 && k >= 8 && k <= 15
              && (*end == '\0' || ((*end == 'd' || *end == 'w' || *end == 'b') && end[1] == '\0')) )
                return *reg = (uint32_t)k, true;
        }
        if ( (n.length() == 4 || n.length() == 5) && (n.substr(0, 3) == "xmm" || n.substr(0, 3) == "ymm")
          && qisdigit(n[3]) )
        {
            char *end = nullptr;
            unsigned long k = strtoul(n.c_str() + 3, &end, 10);
            if ( *end == '\0' && k < 16 )
                return *reg = ITTD_ORIGIN_XMM0 + (uint32_t)k, true;
        }
        return false;
    }

    const char *origin_kind_name(OriginKind k)
    {
        switch ( k )
        {
            case OriginKind::Copied:    return "copied";
            case OriginKind::Computed:  return "computed";
            case OriginKind::Constant:  return "constant";
            case OriginKind::System:    return "system";
            case OriginKind::Unchanged: return "unchanged";
            case OriginKind::Cancelled: return "cancelled";
            default:                    return "failed";
        }
    }

    // origin_inputs, also reporting whether the user cancelled the search for
    // the memory read (which leaves 'out' missing that input).
    static bool collect_inputs(TraceManager *mgr, Position at, std::vector<OriginInput> *out,
                               bool *cancelled);

    // How many values (not address registers) the instruction at 'at' read;
    // 'only' gets the first.
    static int value_inputs(TraceManager *mgr, Position at, OriginTarget *only, bool *cancelled)
    {
        std::vector<OriginInput> inputs;
        if ( !collect_inputs(mgr, at, &inputs, cancelled) || *cancelled )
            return 0;
        int n = 0;
        for ( const OriginInput &in : inputs )
            if ( !in.address && n++ == 0 )
                *only = in.what;
        return n;
    }

    // 'syscalls' holds the recording's syscall list once something asked for
    // it; a caller tracing several values passes one cache to all of them, so
    // the list (a full replay) is made at most once.
    static bool trace_from(TraceManager *mgr, const OriginTarget &what, Position start, uint32_t start_tid,
                           size_t max_hops, bool through_computations, std::vector<OriginHop> *out,
                           SyscallCache &syscalls)
    {
        ITraceBackend *b = mgr->backend();
        OriginTarget target = what;
        Position     at     = start;
        uint32_t     tid    = start_tid;
        for ( size_t hop_no = 0; hop_no < max_hops; hop_no++ )
        {
            OriginHop hop;
            hop.what = target;
            hop.at   = at;
            hop.tid  = tid;
            {
                CursorPtr cur = b->make_cursor();
                if ( !cur || !cur->seek(at) )
                    return !out->empty();
                hop.value = read_value(cur.get(), target, tid);
            }

            Search s;
            qstring what_text;
            what_text.sprnt("Finding where %s came from", origin_target_text(target).c_str());
            QueryResult qr = run_query(what_text.c_str(), [&](ProgressSink *sink)
            {
                if ( target.is_reg )
                    search_register(b, target, at, tid, &s, sink);
                else
                    search_memory(b, target, at, hop.value, &syscalls, &s, sink);
                if ( !s.system )
                    find_reads(b, &s, sink);
                QueryResult r;
                r.ran = true;
                r.cancelled = sink != nullptr && sink->cancelled();
                return r;
            });
            if ( qr.cancelled )
            {
                hop.kind = OriginKind::Cancelled;
                out->push_back(hop);
                return true;
            }

            if ( !s.found )
            {
                hop.kind = OriginKind::Unchanged;
                if ( !target.is_reg )
                {
                    qstring mod = mgr->modules().name_at(target.addr);
                    hop.note = mod.empty()
                             ? qstring("nothing in the recording wrote it: it held this value from the start")
                             : qstring("nothing in the recording wrote it: part of ") + mod + "'s image";
                }
                else if ( s.stepped && s.looked >= kStepLookBack )
                    hop.note.sprnt("not changed in the last %llu instructions of this thread",
                                   (unsigned long long)s.looked);
                else if ( !s.stepped && s.looked != 0 )
                    hop.note = "not changed since the thread began, or within the last few million of its instructions";
                else
                    hop.note = "not changed since the thread began";
                out->push_back(hop);
                return true;
            }

            hop.by_pos = s.pos;
            hop.by_pc  = s.pc;
            hop.by_tid = s.tid;
            qstring line;
            if ( generate_disasm_line(&line, s.pc, GENDSM_REMOVE_TAGS | GENDSM_FORCE_CODE) )
            {
                line.trim2();
                hop.insn = line;
            }
            if ( s.system )
            {
                hop.kind = OriginKind::System;
                hop.note.sprnt("written by the system during %s", s.sys_name.c_str());
                out->push_back(hop);
                return true;
            }

            OriginTarget next;
            bool made_here = false;
            bool more = next_source(hop, s, &hop, &next, &made_here);
            // A computation from a single value (lea rax, [rdi+0Dh]; inc rdi;
            // add [mem], 2) is followed through it as if copied. Not through
            // rsp: a stack address's history is just the frames that moved it.
            if ( !more && made_here )
            {
                OriginTarget only;
                bool cancelled = false;
                const int n = through_computations ? value_inputs(mgr, s.pos, &only, &cancelled) : -1;
                if ( cancelled )
                {
                    hop.kind = OriginKind::Cancelled;
                    out->push_back(hop);
                    return true;
                }
                if ( n == 1 && only.is_reg && only.reg == ITTD_REG_RSP )
                {
                    hop.note = "computed from rsp: a stack address";
                }
                else if ( n == 1 )
                {
                    hop.note.sprnt("computed from %s", origin_target_text(only).c_str());
                    next = only;
                    more = true;
                }
                hop.combined = n >= 2 || n < 0;
            }
            out->push_back(hop);
            if ( !more )
                return true;
            // The next hop asks about the source just before the copy ran.
            // Stop rather than follow the same target at the same position.
            if ( same_target(next, target) && s.pos == at )
                return true;
            target = next;
            at     = s.pos;
            tid    = s.tid;
        }
        return true;
    }

    static bool session_ready(TraceManager *mgr)
    {
        return mgr != nullptr && mgr->is_active() && mgr->backend() != nullptr && mgr->cursor() != nullptr;
    }

    bool trace_value_origin(TraceManager *mgr, const OriginTarget &what, size_t max_hops,
                            std::vector<OriginHop> *out, bool through_computations)
    {
        out->clear();
        if ( !session_ready(mgr) )
            return false;
        SyscallCache syscalls;
        return trace_from(mgr, what, mgr->current_position(), mgr->cursor()->thread_id(), max_hops,
                          through_computations, out, syscalls);
    }

    // trace_value_origin at a position, with the caller's syscall cache.
    static bool trace_origin_at(TraceManager *mgr, const OriginTarget &what, Position at, size_t max_hops,
                                std::vector<OriginHop> *out, bool through_computations,
                                SyscallCache &syscalls)
    {
        out->clear();
        if ( !session_ready(mgr) )
            return false;
        CursorPtr cur = mgr->backend()->make_cursor();
        if ( !cur || !cur->seek(at) )
            return false;
        return trace_from(mgr, what, at, cur->thread_id(), max_hops, through_computations, out, syscalls);
    }

    bool trace_value_origin(TraceManager *mgr, const OriginTarget &what, Position at, size_t max_hops,
                            std::vector<OriginHop> *out, bool through_computations)
    {
        SyscallCache syscalls;
        return trace_origin_at(mgr, what, at, max_hops, out, through_computations, syscalls);
    }

    bool build_origin_graph(TraceManager *mgr, const OriginTarget &what, Position at, size_t max_nodes,
                            OriginGraph *out)
    {
        *out = OriginGraph();
        if ( !session_ready(mgr) )
            return false;

        struct Work
        {
            OriginTarget what;
            Position     at;
            int          from = -1;     // the node whose instruction read it
        };
        std::deque<Work> work;
        work.push_back(Work{ what, at, -1 });
        std::map<qstring, int> seen;    // "rax@3A:46", in effect -> node
        auto key = [](const OriginHop &h)
        {
            return origin_target_text(h.what) + qstring().sprnt("@%llX:%llX", h.at.hi, h.at.lo);
        };

        // One syscall list for every value the graph follows.
        SyscallCache syscalls;
        while ( !work.empty() )
        {
            if ( out->nodes.size() >= max_nodes )
            {
                out->truncated = true;
                break;
            }
            Work w = work.front();
            work.pop_front();
            std::vector<OriginHop> hops;
            if ( !trace_origin_at(mgr, w.what, w.at, max_nodes - out->nodes.size(), &hops, true, syscalls)
              || hops.empty() )
                continue;
            int prev = w.from;
            bool input = w.from >= 0;
            for ( OriginHop &h : hops )
            {
                if ( h.kind == OriginKind::Cancelled )
                {
                    out->cancelled = true;
                    return true;
                }
                const int idx = (int)out->nodes.size();
                auto [it, fresh] = seen.emplace(key(h), idx);
                if ( !fresh )
                {
                    if ( prev >= 0 )
                        out->edges.push_back(OriginGraph::Edge{ prev, it->second, input });
                    prev = -1;
                    break;
                }
                if ( prev >= 0 )
                    out->edges.push_back(OriginGraph::Edge{ prev, idx, input });
                out->nodes.push_back(std::move(h));
                prev  = idx;
                input = false;
            }
            if ( prev < 0 )
                continue;
            const OriginHop &end = out->nodes[prev];
            if ( !end.combined || !end.by_pos.is_valid() )
                continue;
            std::vector<OriginInput> inputs;
            bool cancelled = false;
            collect_inputs(mgr, end.by_pos, &inputs, &cancelled);
            if ( cancelled )
            {
                out->cancelled = true;
                return true;
            }
            for ( const OriginInput &in : inputs )
            {
                if ( in.address || (in.what.is_reg && in.what.reg == ITTD_REG_RSP) )
                    continue;
                work.push_back(Work{ in.what, end.by_pos, prev });
            }
        }
        if ( !work.empty() )
            out->truncated = true;
        return true;
    }

    bool origin_inputs(TraceManager *mgr, Position at, std::vector<OriginInput> *out)
    {
        bool cancelled = false;
        return collect_inputs(mgr, at, out, &cancelled);
    }

    static bool collect_inputs(TraceManager *mgr, Position at, std::vector<OriginInput> *out,
                               bool *cancelled)
    {
        out->clear();
        *cancelled = false;
        if ( !session_ready(mgr) )
            return false;
        ITraceBackend *b = mgr->backend();
        CursorPtr cur = b->make_cursor();
        if ( !cur || !cur->seek(at) )
            return true;
        const ea_t     pc  = cur->program_counter();
        const uint32_t tid = cur->thread_id();
        insn_t ins;
        if ( decode_insn(&ins, pc) <= 0 || ins.itype == NN_syscall || ins.itype == NN_sysenter )
            return true;

        // Operands first, then address-only registers: a pointer is rarely the
        // value being chased.
        std::vector<OriginTarget> operands, addresses;
        auto has = [](const std::vector<OriginTarget> &v, const OriginTarget &t)
        {
            for ( const OriginTarget &x : v )
                if ( same_target(x, t) )
                    return true;
            return false;
        };
        auto add_reg = [&](int ida_reg, bool address)
        {
            const int r = ittd_reg_of(ida_reg);
            if ( r < 0 )
                return;
            OriginTarget t;
            t.reg = (uint32_t)r;
            if ( has(operands, t) || has(addresses, t) )
                return;
            (address ? addresses : operands).push_back(t);
        };

        const uint32 feature = ins.get_canon_feature(PH);
        const bool   lea     = ins.itype == NN_lea;
        bool   reads_memory = false;
        size_t memory_size  = 0;
        for ( int n = 0; n < UA_MAXOP && ins.ops[n].type != o_void; n++ )
        {
            const op_t &op = ins.ops[n];
            if ( op.type == o_reg )
            {
                if ( has_cf_use(feature, n) )
                    add_reg(op.reg, false);
                continue;
            }
            if ( !is_memory(op) )
                continue;
            if ( !lea && has_cf_use(feature, n) )
            {
                reads_memory = true;
                memory_size  = get_dtype_size(op.dtype);
            }
            // o_mem has no base: its phrase is not a register.
            if ( op.type != o_mem )
            {
                const int base = x86_base_reg(ins, op);
                if ( base != R_none )
                    add_reg(base, !lea);
            }
            const int index = x86_index_reg(ins, op);
            if ( index != R_none )
                add_reg(index, !lea);
        }
        // Implicit inputs the operands do not show.
        switch ( ins.itype )
        {
            case NN_mul: case NN_div: case NN_idiv:
                add_reg(R_ax, false);
                if ( ins.itype != NN_mul )
                    add_reg(R_dx, false);
                break;
            case NN_imul:
                if ( ins.ops[1].type == o_void )
                    add_reg(R_ax, false);
                break;
            case NN_cbw: case NN_cwde: case NN_cdqe: case NN_cwd: case NN_cdq: case NN_cqo:
                add_reg(R_ax, false);
                break;
            default:
                break;
        }

        // Memory comes from the recorded read; the operand's address is not
        // computed here.
        if ( reads_memory )
        {
            Search s;
            QueryResult qr = run_query("Finding what the instruction read", [&](ProgressSink *sink)
            {
                reads_at(b, at, pc, &s.reads, sink);
                QueryResult r;
                r.ran = true;
                return r;
            });
            *cancelled = qr.cancelled;
            const Access *rd = qr.cancelled ? nullptr : pick_read(s, memory_size);
            if ( rd != nullptr )
            {
                OriginTarget t;
                t.is_reg = false;
                t.addr   = rd->addr;
                t.size   = rd->size != 0 ? rd->size : 8;
                operands.insert(operands.begin(), t);
            }
        }

        for ( int pass = 0; pass < 2; pass++ )
            for ( const OriginTarget &t : pass == 0 ? operands : addresses )
            {
                OriginInput in;
                in.what    = t;
                in.value   = read_value(cur.get(), t, tid);
                in.address = pass == 1;
                out->push_back(in);
            }
        return true;
    }
}
