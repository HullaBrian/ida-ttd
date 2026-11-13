#include "analysis/tracer.h"
#include "analysis/batched_memory.h"
#include "debugger/callconv.h"
#include "debugger/apidecode.h"
#include "analysis/query_runner.h"
#include "debugger/trace_manager.h"

namespace idattd
{
    // Untyped functions show this many integer arguments.
    static const size_t kUntypedArgs = 4;

    // Raw integer-register argument when no prototype is available.
    static uint64_t raw_int_arg(const GuestView &view, size_t n, bool is64)
    {
        ittd_regs r{};
        if ( !view.regs || !view.regs(&r) )
            return 0;
        if ( is64 )
        {
            const int regs[4] = { ITTD_REG_RCX, ITTD_REG_RDX, ITTD_REG_R8, ITTD_REG_R8 + 1 };
            return n < 4 ? r.gp[regs[n]] : 0;
        }
        uint32_t v = 0;
        view.read((uint32_t)r.gp[ITTD_REG_RSP] + n * 4, &v, sizeof(v));
        return v;
    }

    TracedProto resolve_traced_proto(ModuleRegistry *mods, ea_t func_ea)
    {
        TracedProto p;
        tinfo_t t;
        bool has_type = get_tinfo(&t, func_ea);
        // A picked import slot (__imp_CreateFileW) holds a pointer to the
        // function: its prototype is the pointed-to type.
        if ( has_type && t.is_funcptr() )
            t = t.get_pointed_object();
        has_type = has_type && t.is_func();
        if ( !(has_type && is_userti(func_ea)) )
            p.sig = api_signature(mods, func_ea);
        if ( p.sig == nullptr )
        {
            if ( has_type )
                p.type = t;
            // A guess with nothing in it (no arguments found) is no better
            // than the untyped default, which at least shows the registers.
            else if ( is_code(get_flags(func_ea)) && guess_tinfo(&t, func_ea) == GUESS_FUNC_OK && t.is_func() )
                p.type = t;
            p.have_type = !p.type.empty() && p.type.get_func_details(&p.fd);
        }

        if ( p.sig != nullptr )
        {
            for ( uint8_t i = 0; i < p.sig->paramCount; i++ )
                p.names.push_back(qstring(p.sig->params[i].name));
        }
        else if ( p.have_type )
        {
            for ( size_t i = 0; i < p.fd.size(); i++ )
            {
                qstring nm = p.fd[i].name;
                if ( nm.empty() )
                    nm.sprnt("arg%d", (int)i);
                p.names.push_back(nm);
            }
        }
        else
        {
            for ( size_t i = 0; i < kUntypedArgs; i++ )
            {
                qstring nm;
                nm.sprnt("arg%d", (int)i);
                p.names.push_back(nm);
            }
        }
        return p;
    }

    // A pointed-to type that is a UTF-16 character: wchar_t itself, or a
    // typedef of it or of a 16-bit integer that Windows uses for one.
    static bool is_wide_char(const tinfo_t &t, const qstring &printed)
    {
        if ( printed == "wchar_t" || printed == "WCHAR" || printed == "OLECHAR"
          || printed == "wchar16_t" || printed == "char16_t" )
            return true;
        return t.get_realtype(true) == (BT_INT16 | BTMT_CHAR);
    }

    static qstring render_pointer(const GuestView &cur, const tinfo_t &ptr_t, uint64_t ptr)
    {
        tinfo_t pointed = ptr_t.get_ptrarr_object();
        qstring pt;
        pointed.print(&pt);
        pt.replace("const ", "");

        qstring value;
        if ( ptr == 0 )
        {
            value = "NULL";
        }
        else if ( pointed.is_char() )
        {
            qstring s = read_string_at(cur, ptr);
            value.sprnt("0x%llX \"%s\"", (uint64_t)ptr, s.c_str());
        }
        else if ( is_wide_char(pointed, pt) )
        {
            qstring s = read_wstring_at(cur, ptr);
            value.sprnt("0x%llX L\"%s\"", (uint64_t)ptr, s.c_str());
        }
        else
        {
            value.sprnt("0x%llX", (uint64_t)ptr);
        }
        return value;
    }

    // The integer an argument or return value of type 't' really holds: a
    // register carries 64 bits, but an int or a BYTE uses only its low bytes,
    // and the rest is whatever the register held before. Truncated to the
    // type's size and sign-extended when the type is signed (an unknown sign,
    // like plain int's, counts as signed unless the type says unsigned).
    static uint64_t fit_to_type(const tinfo_t &t, uint64_t raw)
    {
        size_t sz = t.get_size();
        if ( sz == 0 || sz >= 8 )
            return raw;                     // includes BADSIZE: nothing to cut
        const unsigned bits = (unsigned)sz * 8;
        uint64_t v = raw & ((1ULL << bits) - 1);
        if ( !t.is_unsigned() && !t.is_bool() && (v >> (bits - 1)) != 0 )
            v |= ~0ULL << bits;
        return v;
    }

    // An integer of type 't', already fitted (fit_to_type): hex, as the
    // untyped values and IDA's listings show numbers, except that a negative
    // value of a signed type reads as a signed decimal ("-1", not
    // "0xFFFFFFFFFFFFFFFF"). A bool is 0 or 1.
    static qstring render_int(const tinfo_t &t, uint64_t v)
    {
        qstring out;
        if ( t.is_bool() )
            out.sprnt("%llu", (unsigned long long)v);
        else if ( !t.is_unsigned() && (int64_t)v < 0 )
            out.sprnt("%lld", (long long)v);
        else
            out.sprnt("0x%llX", (unsigned long long)v);
        return out;
    }

    // An enum value by member name: the member equal to it, else for a
    // bitmask enum the members whose bits it has, joined with '|', with any
    // bits left over in hex. Compared at the enum's width: a 4-byte enum's
    // members are matched against the low 32 bits only.
    static qstring render_enum(const tinfo_t &t, uint64_t raw)
    {
        size_t sz = t.get_size();
        uint64_t mask = sz == 0 || sz >= 8 ? ~0ULL : (1ULL << (sz * 8)) - 1;
        uint64_t v = raw & mask;
        qstring value;
        enum_type_data_t ed;
        if ( t.get_enum_details(&ed) )
        {
            for ( size_t k = 0; k < ed.size(); k++ )
                if ( ((uint64_t)ed[k].value & mask) == v )
                    return qstring(ed[k].name);
            if ( t.is_bitmask_enum() && v != 0 )
            {
                uint64_t rest = v;
                for ( size_t k = 0; k < ed.size(); k++ )
                {
                    uint64_t m = (uint64_t)ed[k].value & mask;
                    if ( m != 0 && (rest & m) == m )
                    {
                        if ( !value.empty() )
                            value.append('|');
                        value.append(ed[k].name);
                        rest &= ~m;
                    }
                }
                if ( !value.empty() )
                {
                    if ( rest != 0 )
                        value.cat_sprnt("|0x%llX", (unsigned long long)rest);
                    return value;
                }
            }
        }
        value.sprnt("0x%llX", (unsigned long long)v);
        return value;
    }

    // Render a single argument value (no type prefix) from the integer fetched
    // at the call site.
    static qstring render_value(const GuestView &cur, const tinfo_t &arg, uint64_t raw)
    {
        qstring value;
        if ( arg.is_ptr_or_array() )
        {
            value = render_pointer(cur, arg, raw);
        }
        else if ( arg.is_enum() )
        {
            value = render_enum(arg, raw);
        }
        else if ( arg.is_floating() )
        {
            // 'raw' holds the argument's bits (XMMn on x64, or the stack slot):
            // reinterpret them. Anything but float or double falls back to hex.
            size_t sz = arg.get_size();
            if ( sz == 4 )
            {
                float    fv;
                uint32_t bits = (uint32_t)raw;
                memcpy(&fv, &bits, sizeof(fv));
                value.sprnt("%g", (double)fv);
            }
            else if ( sz == 8 )
            {
                double dv;
                memcpy(&dv, &raw, sizeof(dv));
                value.sprnt("%g", dv);
            }
            else
            {
                value.sprnt("0x%llX", raw);
            }
        }
        else if ( arg.is_int() || arg.is_bool() || arg.is_char() || arg.is_uchar() )
        {
            value = render_int(arg, fit_to_type(arg, raw));
        }
        else
        {
            value.sprnt("0x%llX", raw);
        }
        return value;
    }

    // One value string per argument of the prototype, or four raw
    // register/stack arguments without one. Values only: the chooser's
    // column headers carry the parameter names.
    static void extract_args(const GuestView &cur, const TracedProto &proto, bool is64,
                             std::vector<qstring> &out)
    {
        out.clear();
        if ( !proto.have_type )
        {
            for ( size_t i = 0; i < kUntypedArgs; i++ )
            {
                qstring v;
                v.sprnt("0x%llX", (uint64_t)raw_int_arg(cur, i, is64));
                out.push_back(v);
            }
            return;
        }
        for ( size_t i = 0; i < proto.fd.size(); i++ )
        {
            uint64_t raw = get_int_arg(cur, proto.fd, i, is64);
            out.push_back(render_value(cur, proto.fd[i].type, raw));
        }
    }

    // "(type)value", the type from the prototype ("int" without one).
    static qstring render_return(const GuestView &cur, const TracedProto &proto, bool is64)
    {
        uint64_t rv = get_return_value(cur, is64);

        qstring type_name = "int";
        qstring value;
        if ( proto.have_type )
        {
            const tinfo_t &rt = proto.fd.rettype;
            rt.print(&type_name);
            if ( rt.is_void() )
            {
                value = "void";
            }
            else if ( rt.is_floating() )
            {
                // Returned in XMM0 (x64) or on the x87 stack (x86, which
                // the register snapshot lacks).
                ittd_regs r{};
                if ( is64 && cur.regs && cur.regs(&r) )
                {
                    uint64_t bits = 0;
                    memcpy(&bits, r.xmm[0], sizeof(bits));
                    value = render_value(cur, rt, bits);
                }
                else
                {
                    value = "?";
                }
            }
            else
            {
                value = render_value(cur, rt, rv);
            }
        }
        else
        {
            value.sprnt("0x%llX", rv);
        }

        qstring tmp = value;
        value.sprnt("(%s)%s", type_name.c_str(), tmp.c_str());
        return value;
    }

    void FunctionTracer::reset()
    {
        { std::lock_guard<std::mutex> g(m_traces_mtx); m_traces.clear(); }
        clear_events();
    }

    void FunctionTracer::add_func(ea_t func_ea)
    {
        if ( func_ea == BADADDR )
            return;
        ea_t fstart = get_func_start(func_ea);
        ea_t key = fstart != BADADDR ? fstart : func_ea;
        if ( is_traced(key) )
            return;
        {
            std::lock_guard<std::mutex> g(m_traces_mtx);
            m_traces.push_back(key);
        }
        refresh_chooser("Traced functions");
    }

    void FunctionTracer::remove_trace(size_t n)
    {
        std::lock_guard<std::mutex> g(m_traces_mtx);
        if ( n < m_traces.size() )
            m_traces.erase(m_traces.begin() + n);
    }

    bool FunctionTracer::is_traced(ea_t func_ea)
    {
        std::lock_guard<std::mutex> g(m_traces_mtx);
        for ( ea_t ea : m_traces )
            if ( ea == func_ea )
                return true;
        return false;
    }

    size_t FunctionTracer::count_traced()
    {
        std::lock_guard<std::mutex> g(m_traces_mtx);
        return m_traces.size();
    }

    ea_t FunctionTracer::traced_at(size_t n)
    {
        std::lock_guard<std::mutex> g(m_traces_mtx);
        return n < m_traces.size() ? m_traces[n] : BADADDR;
    }

    size_t FunctionTracer::count_events()
    {
        std::lock_guard<std::mutex> g(m_events_mtx);
        return m_events.size();
    }

    FunctionInvocation FunctionTracer::event_at(size_t n)
    {
        std::lock_guard<std::mutex> g(m_events_mtx);
        return n < m_events.size() ? m_events[n] : FunctionInvocation{};
    }

    void FunctionTracer::remove_event(size_t n)
    {
        std::lock_guard<std::mutex> g(m_events_mtx);
        if ( n < m_events.size() )
            m_events.erase(m_events.begin() + n);
    }

    void FunctionTracer::clear_events()
    {
        std::lock_guard<std::mutex> g(m_events_mtx);
        m_events.clear();
    }

    std::vector<FunctionInvocation> FunctionTracer::snapshot_events()
    {
        std::lock_guard<std::mutex> g(m_events_mtx);
        return m_events;
    }

    // Read the live pointer stored at 'slot' (an IAT/import slot) and add it.
    static void add_live_ptr(ea_t slot, bool is64, std::set<ea_t> &out)
    {
        if ( slot == BADADDR )
            return;
        ea_t v = is64 ? (ea_t)get_qword(slot) : (ea_t)get_dword(slot);
        if ( v != 0 && v != BADADDR )
            out.insert(v);
    }

    // Calls reach an import directly (the real VA) or through a thunk that
    // jumps via the IAT. The function start, the thunk's target and the live
    // IAT pointer are all collected, so the sweep matches either path.
    //
    // The thunk is recognised from its instruction, not from IDA's
    // FUNC_THUNK flag: in a fresh session a system DLL's thunk (kernel32's
    // VirtualProtect, a jmp into kernelbase) is not even a function until a
    // stop lands there, and the trace then missed every call made to the
    // target directly (4 calls instead of 29 in beacon). A slot is read
    // where it holds the bound value: at the playhead, and at the end of
    // the recording for a playhead the loader had not bound it by yet.
    std::vector<ea_t> FunctionTracer::resolve_targets(ea_t func_ea, CursorPtr *at_end) const
    {
        std::set<ea_t> out;
        func_entry_info_t fi;
        bool has_func = get_func_entry_info(&fi, func_ea);
        ea_t start = has_func ? fi.start_ea : func_ea;
        out.insert(start);

        ModuleRegistry *mods = m_mgr != nullptr ? &m_mgr->modules() : nullptr;
        ITraceBackend  *backend = m_mgr != nullptr ? m_mgr->backend() : nullptr;
        const size_t    ptrsz = m_is64 ? 8 : 4;
        // A pointer read from a slot counts only when it is a recorded
        // module's code: anything else is an unbound slot or not a slot.
        auto add_slot = [&](ea_t slot)
        {
            std::set<ea_t> vals;
            add_live_ptr(slot, m_is64, vals);
            if ( !*at_end && backend != nullptr )
            {
                *at_end = backend->make_cursor();
                if ( *at_end && !(*at_end)->seek(backend->info().last) )
                    at_end->reset();
            }
            if ( *at_end )
            {
                uint64_t v = 0;
                std::vector<uint8_t> known;
                if ( (*at_end)->read_memory(slot, &v, ptrsz, &known) == ptrsz )
                    vals.insert((ea_t)v);
            }
            for ( ea_t v : vals )
                if ( mods == nullptr || mods->index_at(v) != (size_t)-1 )
                    out.insert(v);
        };

        // An import thunk (jmp cs:Foo, or a direct jmp): follow it.
        insn_t insn;
        if ( !is_data(get_flags(start))
          && decode_insn(&insn, start) > 0 && (insn.get_canon_feature(PH) & CF_STOP) != 0 )
        {
            const op_t &op = insn.ops[0];
            if ( op.type == o_near || op.type == o_far )
                out.insert(op.addr);
            else if ( op.type == o_mem )
                add_slot(op.addr);
            return std::vector<ea_t>(out.begin(), out.end());
        }

        // The import data slot itself was picked: read the live pointer there.
        // Only for data, so code bytes are never read as a pointer.
        if ( !is_code(get_flags(start)) && !has_func )
            add_slot(start);

        return std::vector<ea_t>(out.begin(), out.end());
    }

    bool FunctionTracer::run_sweep(qstring *error)
    {
        qstring ignored;
        if ( error == nullptr )
            error = &ignored;
        if ( m_mgr == nullptr || !m_mgr->is_active() || m_mgr->backend() == nullptr )
        {
            *error = "Tracing is only available while replaying a trace.";
            return false;
        }

        // Each resolved runtime target to the picked function (for display and
        // types).
        std::map<ea_t, ea_t> tgt2disp;
        {
            std::lock_guard<std::mutex> g(m_traces_mtx);
            CursorPtr at_end;
            for ( ea_t picked : m_traces )
                for ( ea_t t : resolve_targets(picked, &at_end) )
                    tgt2disp.emplace(t, picked);
        }
        if ( tgt2disp.empty() )
        {
            *error = "No functions are being traced. Right-click a function and pick "
                     "'TTD: Find calls to this function'.";
            return false;
        }

        ITraceBackend *backend = m_mgr->backend();

        std::vector<ea_t> targets;
        targets.reserve(tgt2disp.size());
        for ( const auto &kv : tgt2disp )
            targets.push_back(kv.first);

        // Phase 1: the backend finds every call to one of the targets.
        std::vector<CallEvent> calls;
        QueryResult qr = run_query("Tracing function calls across the whole trace",
                                   [&](ProgressSink *p)
        {
            return backend->query_calls(targets, PositionRange{}, &calls, p);
        });
        if ( !qr.ran )
        {
            *error = query_error(m_mgr, backend, qr, "The replay session ended during the call search.",
                                 "This recording's backend could not search for calls.");
            return false;
        }
        if ( qr.truncated )
            msg("[ida-ttd] tracer: hit the backend's call limit; results are "
                "truncated. Narrow the pattern to see the rest.\n");

        // Phase 2 runs on the main thread, with its own progress and Cancel.
        CursorPtr cur = backend->make_cursor();
        std::vector<FunctionInvocation> built;
        built.reserve(calls.size());
        bool cancelled = qr.cancelled;
        const uint64_t ptr = m_is64 ? 8 : 4;
        show_wait_box("Resolving %d call(s)... (Cancel to stop)", (int)calls.size());
        if ( cur )
        {
            // Collect every place to read, then read in position order. A
            // call and its return are far apart, and a backend that rebuilds
            // state from the nearest checkpoint (Sogen) would pay again each
            // time reads alternated between them.
            struct Visit { Position where; size_t call; bool ret; };
            std::vector<Visit> visits;
            std::vector<FunctionInvocation> slot(calls.size());
            // Each function's prototype is resolved once (resolve_traced_proto
            // says which source wins). Those the API metadata describes are
            // decoded from it (flags by name, out parameters re-read at the
            // return); others from IDA's types.
            std::vector<DecodedCall> decoded(calls.size());
            std::map<ea_t, TracedProto> protos;
            auto proto_of = [&](ea_t f) -> const TracedProto &
            {
                auto it = protos.find(f);
                if ( it == protos.end() )
                    it = protos.emplace(f, resolve_traced_proto(&m_mgr->modules(), f)).first;
                return it->second;
            };
            std::vector<bool> keep(calls.size(), false);
            for ( size_t i = 0; i < calls.size(); i++ )
            {
                const CallEvent &c = calls[i];
                auto disp = tgt2disp.find(c.target);
                if ( disp == tgt2disp.end() )
                    continue;
                // Arguments are decoded just before the call. Without a call
                // (the thread began in the callee, or a jump got there) they
                // are read at the entry instead (see below).
                Position where = c.is_call && c.pos.is_valid() ? c.pos : c.entry_pos;
                if ( !where.is_valid() )
                    continue;
                keep[i] = true;
                slot[i].func_ea = disp->second;
                slot[i].tid     = c.tid;
                slot[i].pos     = where;
                visits.push_back(Visit{ where, i, false });
                if ( c.ret_pos.is_valid() )
                    visits.push_back(Visit{ c.ret_pos, i, true });
            }
            std::sort(visits.begin(), visits.end(),
                      [](const Visit &x, const Visit &y) { return x.where < y.where; });

            // A backend that rebuilds registers by replay (Sogen) does each
            // stretch once for a batch, but once per visit through the cursor.
            // With the batch's registers, memory is batched too (below).
            std::vector<ittd_regs> pre;
            bool regs_cancelled = false;
            if ( backend->capabilities().batch_regs && !visits.empty() )
            {
                std::vector<Position> where;
                where.reserve(visits.size());
                for ( const Visit &v : visits )
                    where.push_back(v.where);
                const QueryResult rq = run_query("Reading the registers at the calls", [&](ProgressSink *p)
                {
                    return backend->registers_at(where, &pre, p);
                });
                // Cancelled here: the calls stay listed without values.
                if ( rq.cancelled )
                    cancelled = regs_cancelled = true;
                if ( !rq.ran || pre.size() != visits.size() )
                    pre.clear();
            }
            // Registers at visit k: the batch's when it has every register a
            // calling convention reads, else the cursor's.
            auto view_at = [&](size_t k)
            {
                GuestView gv = guest_view(cur.get());
                const uint32_t need = ITTD_REGS_GP | ITTD_REGS_XMM;
                if ( k < pre.size() && (pre[k].have & need) == need )
                {
                    const ittd_regs *r = &pre[k];
                    gv.regs = [r](ittd_regs *out) { *out = *r; return true; };
                }
                return gv;
            };

            // One visit, read through 'view' (memory and registers there). Run
            // again from scratch when a batched read missed something, so it
            // starts from the call's decode as it was ('at_call').
            std::vector<DecodedCall> at_call;
            auto visit_one = [&](size_t k, GuestView view)
            {
                const Visit &v = visits[k];
                FunctionInvocation &ev = slot[v.call];
                if ( v.ret )
                {
                    ev.end_pos = v.where;
                    ev.has_ret = true;
                    DecodedCall &dc = decoded[v.call];
                    if ( v.call < at_call.size() )
                        dc = at_call[v.call];
                    if ( dc.sig != nullptr )
                    {
                        decode_api_outs(view, &dc);
                        ev.args.clear();
                        for ( const DecodedArg &a : dc.args )
                            ev.args.push_back(a.text);
                        ev.retval = decode_api_return(dc, get_return_value(view, m_is64));
                        return;
                    }
                    ev.retval  = render_return(view, proto_of(ev.func_ea), m_is64);
                    return;
                }
                const CallEvent &c = calls[v.call];
                if ( !(c.is_call && c.pos.is_valid()) )
                {
                    // At the entry the return address is on the stack: skip
                    // it so stack arguments sit where a call site has them.
                    auto regs = view.regs;
                    view.regs = [regs, ptr](ittd_regs *r)
                    {
                        if ( !regs || !regs(r) )
                            return false;
                        r->gp[ITTD_REG_RSP] += ptr;
                        return true;
                    };
                }
                const TracedProto &proto = proto_of(ev.func_ea);
                if ( proto.sig != nullptr )
                {
                    decoded[v.call] = DecodedCall{};
                    decode_api_args(view, *proto.sig, m_is64, &decoded[v.call]);
                    ev.args.clear();
                    for ( const DecodedArg &a : decoded[v.call].args )
                        ev.args.push_back(a.text);
                    return;
                }
                ev.args.clear();
                extract_args(view, proto, m_is64, ev.args);
            };

            // A call both of whose visits have the batch's registers reads its
            // memory in batches (BatchedMemory) instead of seeking the cursor
            // to each visit: about 17 ms a seek on Microsoft TTD, two per call,
            // so a traced API called ten thousand times took minutes. The
            // rest are read through the cursor as before.
            const uint32_t need = ITTD_REGS_GP | ITTD_REGS_XMM;
            std::vector<char> call_batched(calls.size(), 1);
            for ( size_t k = 0; k < visits.size(); k++ )
                if ( !(k < pre.size() && (pre[k].have & need) == need) )
                    call_batched[visits[k].call] = 0;
            std::vector<size_t> batched_calls, batched_rets, seeked;
            for ( size_t k = 0; k < visits.size(); k++ )
            {
                if ( !call_batched[visits[k].call] )
                    seeked.push_back(k);
                else
                    (visits[k].ret ? batched_rets : batched_calls).push_back(k);
            }

            BatchedMemory mem;
            auto batched_view = [&](size_t k)
            {
                GuestView gv;
                gv.read = mem.reader(visits[k].where);
                const ittd_regs *r = &pre[k];
                gv.regs = [r](ittd_regs *out) { *out = *r; return true; };
                return gv;
            };
            // Decode 'todo', fetch what it missed (behind a wait box, through
            // run_query), and decode again those that missed something.
            auto in_rounds = [&](std::vector<size_t> todo) -> bool
            {
                for ( int round = 0; !todo.empty(); round++ )
                {
                    std::vector<size_t> again;
                    for ( size_t k : todo )
                    {
                        const uint64_t before = mem.misses();
                        visit_one(k, batched_view(k));
                        if ( mem.misses() != before )
                            again.push_back(k);
                    }
                    if ( again.empty() || round + 1 == kMaxFetchRounds )
                        break;
                    bool fetched = true;
                    const QueryResult fq = run_query("Reading memory at the calls", [&](ProgressSink *p)
                    {
                        fetched = mem.fetch(backend, p);
                        QueryResult q;
                        q.ran = true;
                        q.cancelled = !fetched;
                        return q;
                    });
                    if ( fq.cancelled || !fetched )
                        return false;
                    todo.swap(again);
                }
                return true;
            };
            if ( !regs_cancelled )
            {
                // Calls before returns: a return's decode starts from its
                // call's.
                if ( !in_rounds(batched_calls) )
                    cancelled = true;
                at_call = decoded;
                if ( !cancelled && !in_rounds(batched_rets) )
                    cancelled = true;
            }

            size_t done = 0;
            for ( size_t idx = 0; idx < seeked.size() && !regs_cancelled && !cancelled; idx++ )
            {
                const size_t k = seeked[idx];
                if ( user_cancelled() )
                {
                    cancelled = true;
                    break;
                }
                if ( (done & 0x3F) == 0 )
                    replace_wait_box("Resolving calls: %d of %d values... (Cancel to stop)",
                                     (int)done + 1, (int)seeked.size());
                done++;
                if ( !cur->seek(visits[k].where) )
                    continue;
                // A seeked return starts from its call's decode as it is now.
                if ( visits[k].ret && visits[k].call < at_call.size() )
                    at_call[visits[k].call] = decoded[visits[k].call];
                visit_one(k, view_at(k));
            }

            // An integer out parameter unchanged at the return may be the
            // kernel's write not yet visible on Microsoft TTD: the backend
            // searches from the return on, where it surfaces. A changed one is
            // kept as read.
            std::vector<OutSlot> oslots;
            std::vector<std::pair<size_t, size_t>> owner;     // (call, parameter)
            for ( size_t i = 0; i < calls.size() && !cancelled; i++ )
            {
                const DecodedCall &d = decoded[i];
                if ( !keep[i] || d.sig == nullptr || !slot[i].has_ret )
                    continue;
                for ( const auto &[p, width] : api_int_outs(d) )
                {
                    const DecodedArg &a = d.args[p];
                    if ( a.pointee_before.has_value() && a.pointee_after.has_value()
                      && *a.pointee_before != *a.pointee_after )
                        continue;
                    OutSlot s;
                    s.call   = slot[i].end_pos;
                    s.addr   = (ea_t)a.raw;
                    s.before = a.pointee_after.value_or(0);
                    s.tid    = slot[i].tid;
                    s.width  = width;
                    oslots.push_back(s);
                    owner.emplace_back(i, p);
                }
            }
            if ( !oslots.empty() )
            {
                std::vector<std::optional<uint64_t>> values;
                bool searched = false;
                const QueryResult oq = run_query("Finding what the calls wrote back", [&](ProgressSink *p)
                {
                    searched = backend->query_out_values(oslots, &values, p);
                    QueryResult r;
                    r.ran = true;
                    return r;
                });
                if ( oq.cancelled )
                    cancelled = true;
                std::set<size_t> touched;
                for ( size_t k = 0; searched && k < oslots.size() && k < values.size(); k++ )
                {
                    if ( !values[k].has_value() )
                        continue;
                    DecodedCall &d = decoded[owner[k].first];
                    d.out_values.resize(d.args.size());
                    d.out_values[owner[k].second] = values[k];
                    touched.insert(owner[k].first);
                }
                for ( size_t i : touched )
                {
                    decode_api_outs(GuestView{}, &decoded[i]);
                    slot[i].args.clear();
                    for ( const DecodedArg &a : decoded[i].args )
                        slot[i].args.push_back(a.text);
                }
            }

            for ( size_t i = 0; i < calls.size(); i++ )
                if ( keep[i] )
                    built.push_back(std::move(slot[i]));
        }

        std::sort(built.begin(), built.end(),
                  [](const FunctionInvocation &a, const FunctionInvocation &b) { return a.pos < b.pos; });

        const size_t nbuilt = built.size();   // read before the move below
        {
            std::lock_guard<std::mutex> g(m_events_mtx);
            m_events = std::move(built);
        }
        hide_wait_box();

        // Open events tabs are not refreshed: each holds a frozen snapshot.
        if ( cancelled )
            msg("[ida-ttd] tracer: cancelled - showing %d of %d recorded call(s).\n",
                (int)nbuilt, (int)calls.size());
        else
            msg("[ida-ttd] tracer: recorded %d call(s).\n", (int)nbuilt);
        return true;
    }
}
