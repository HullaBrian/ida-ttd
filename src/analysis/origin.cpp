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
        const char *const GP32_NAMES[8] = { "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi" };

        // How far back a register's last change is looked for: the backend's
        // own search is a forward replay of the thread, so millions of steps
        // cost seconds. Stepping back one at a time, where the backend has no
        // search of its own, costs a millisecond or more a step.
        const uint64_t kRegisterLookBack = 4000000;
        const uint64_t kStepLookBack     = 200000;
        // Syscalls checked for having written memory, latest first.
        const size_t   kSyscallsChecked  = 300;

        // IDA's x86 register number to ITTD_REG_* / ITTD_ORIGIN_XMM0 + n;
        // -1 for one this does not follow (segment, flags, x87, ...).
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

        // What the backend phase of one hop found: worker-thread work only,
        // no IDA calls.
        struct Search
        {
            bool        found = false;      // an instruction of the program set it
            Position    pos;
            ea_t        pc = BADADDR;
            uint32_t    tid = 0;
            bool        stepped = false;    // searched by stepping back (no backend search)
            uint64_t    looked = 0;         // how far, when not found
            // The system wrote it after the program last did (memory), or
            // the instruction was a syscall (register).
            bool        system = false;
            Position    sys_pos;
            qstring     sys_name;
            std::vector<Access> reads;      // what the setting instruction read
        };

        void find_reads(ITraceBackend *b, Search *s, ProgressSink *sink)
        {
            if ( !s->found )
                return;
            const ea_t hi = b->info().is64 ? (ea_t)0x800000000000ull : (ea_t)0x100000000ull;
            PositionRange one{ s->pos, s->pos };
            std::vector<Access> v;
            b->query_accesses(0, hi, ACCESS_READ, one, &v, sink);
            for ( const Access &a : v )
                if ( a.pc == s->pc )
                    s->reads.push_back(a);
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

        // Memory is set by the program's last write to it -- or by the system
        // after that, which a recording may not report as a write (Microsoft
        // TTD reports a syscall filling a buffer as other kinds of access).
        // So the value right after the program's write is checked against the
        // value asked about, and when they differ, or nothing of the program
        // wrote it, the syscalls since are checked latest first.
        void search_memory(ITraceBackend *b, const OriginTarget &t, Position at, const bytevec_t &value,
                           Search *s, ProgressSink *sink)
        {
            CursorPtr cur = b->make_cursor();
            if ( !cur || !cur->seek(at) )
                return;
            {
                std::unique_ptr<INavigator> nav = b->make_navigator(cur.get());
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
                    if ( n2->step(true) == StopReason::Stepped && read_value(c2.get(), t, 0) == value )
                        return;
                }
            }

            if ( !b->capabilities().syscalls )
                return;
            std::vector<SyscallEvent> calls;
            b->query_syscalls(&calls, sink);
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
                std::unique_ptr<INavigator> n = b->make_navigator(c.get());
                if ( n->step(true) != StopReason::Stepped )
                    continue;
                const bytevec_t after = read_value(c.get(), t, 0);
                if ( after == value && before != after )
                {
                    s->system   = true;
                    s->sys_pos  = it->pos;
                    s->sys_name = it->name.empty() ? qstring("a syscall") : it->name;
                    s->found    = true;
                    s->pos      = it->pos;
                    s->pc       = c->program_counter();
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

        // The read the instruction made of its memory operand, as the
        // recording has it.
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

        // From the instruction that set the value, the next thing to follow:
        // fills 'next' and returns true for a copy, or sets hop.kind and the
        // note and returns false.
        bool next_source(const OriginHop &hop, const Search &s, OriginHop *out, OriginTarget *next)
        {
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
                    // The operand that is not where the value now is.
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
            if ( src == nullptr && !from_read )
            {
                out->kind = OriginKind::Computed;
                out->note = "computed by this instruction";
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
            // From memory: the address it read, as recorded.
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
        for ( uint32_t i = 0; i < 8; i++ )
            if ( n == GP32_NAMES[i] )
                return *reg = i, true;
        // r8d, r8w, r8b and friends name their 64-bit register.
        if ( n.length() >= 2 && n[0] == 'r' )
        {
            char *end = nullptr;
            unsigned long k = strtoul(n.c_str() + 1, &end, 10);
            if ( end != n.c_str() + 1 && k >= 8 && k <= 15
              && (*end == '\0' || ((*end == 'd' || *end == 'w' || *end == 'b') && end[1] == '\0')) )
                return *reg = (uint32_t)k, true;
        }
        if ( (n.length() == 4 || n.length() == 5) && (n.substr(0, 3) == "xmm" || n.substr(0, 3) == "ymm") )
        {
            unsigned long k = strtoul(n.c_str() + 3, nullptr, 10);
            if ( k < 16 )
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

    bool trace_value_origin(TraceManager *mgr, const OriginTarget &what, size_t max_hops,
                            std::vector<OriginHop> *out)
    {
        out->clear();
        if ( mgr == nullptr || !mgr->is_active() || mgr->backend() == nullptr || mgr->cursor() == nullptr )
            return false;
        ITraceBackend *b = mgr->backend();

        OriginTarget target = what;
        Position     at     = mgr->current_position();
        uint32_t     tid    = mgr->cursor()->thread_id();
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
                    search_memory(b, target, at, hop.value, &s, sink);
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
            if ( generate_disasm_line(&line, s.pc, GENDSM_REMOVE_TAGS) )
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
            const bool more = next_source(hop, s, &hop, &next);
            out->push_back(hop);
            if ( !more )
                return true;
            // The next hop asks about the source as it stood just before the
            // copy ran. Following itself would loop.
            if ( same_target(next, target) && s.pos == at )
                return true;
            target = next;
            at     = s.pos;
            tid    = s.tid;
        }
        return true;
    }
}
