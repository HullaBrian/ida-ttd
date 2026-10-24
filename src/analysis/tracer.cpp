#include "analysis/tracer.h"
#include "debugger/callconv.h"
#include "debugger/apidecode.h"
#include "analysis/query_runner.h"
#include "debugger/trace_manager.h"

namespace idattd
{
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

    static qstring render_pointer(const GuestView &cur, const tinfo_t &ptr_t, uint64_t ptr)
    {
        tinfo_t pointed = ptr_t.get_ptrarr_object();
        qstring pt;
        pointed.print(&pt);
        pt.replace("const ", "");

        qstring value;
        if ( pointed.is_char() )
        {
            qstring s = read_string_at(cur, ptr);
            value.sprnt("0x%llX \"%s\"", (uint64_t)ptr, s.c_str());
        }
        else if ( pt == "wchar_t" )
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

    // An integer of type 't', already fitted (fit_to_type), in decimal.
    static qstring render_int(const tinfo_t &t, uint64_t v)
    {
        qstring out;
        if ( t.is_unsigned() || t.is_bool() )
            out.sprnt("%llu", (unsigned long long)v);
        else
            out.sprnt("%lld", (long long)v);
        return out;
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
            // Compared at the enum's width: a 4-byte enum's members are
            // matched against the low 32 bits only.
            enum_type_data_t ed;
            bool named = false;
            size_t sz = arg.get_size();
            uint64_t mask = sz == 0 || sz >= 8 ? ~0ULL : (1ULL << (sz * 8)) - 1;
            uint64_t v = raw & mask;
            if ( arg.get_enum_details(&ed) )
            {
                for ( size_t k = 0; k < ed.size(); k++ )
                    if ( ((uint64_t)ed[k].value & mask) == v ) { value = ed[k].name; named = true; break; }
            }
            if ( !named )
                value.sprnt("0x%llX", v);
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
        else if ( arg.is_int() || arg.is_bool() )
        {
            value = render_int(arg, fit_to_type(arg, raw));
        }
        else
        {
            value.sprnt("0x%llX", raw);
        }
        return value;
    }

    // One value string per argument of the function's prototype, or four raw
    // register/stack arguments without one.
    static void extract_args(const GuestView &cur, ea_t func_ea, bool is64, std::vector<qstring> &out)
    {
        tinfo_t          tinfo;
        func_type_data_t fd;
        bool have = get_tinfo(&tinfo, func_ea) && tinfo.is_func() && tinfo.get_func_details(&fd);

        // Values only: the chooser's column headers carry the parameter names.
        if ( !have )
        {
            for ( size_t i = 0; i < 4; i++ )
            {
                qstring v;
                v.sprnt("0x%llX", (uint64_t)raw_int_arg(cur, i, is64));
                out.push_back(v);
            }
            return;
        }

        for ( size_t i = 0; i < fd.size(); i++ )
        {
            uint64_t raw = get_int_arg(cur, tinfo, i, is64);
            out.push_back(render_value(cur, fd[i].type, raw));
        }
    }

    static qstring render_return(const GuestView &cur, ea_t func_ea, bool is64)
    {
        uint64_t rv = get_return_value(cur, is64);

        tinfo_t tinfo;
        qstring type_name = "int";
        qstring value;
        if ( get_tinfo(&tinfo, func_ea) && tinfo.is_func() )
        {
            tinfo_t rt = tinfo.get_rettype();
            rt.print(&type_name);
            if ( rt.is_ptr_or_array() )
                value = render_pointer(cur, rt, rv);
            else if ( rt.is_void() )
                value = "void";
            else
                value = render_int(rt, fit_to_type(rt, rv));
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
    std::vector<ea_t> FunctionTracer::resolve_targets(ea_t func_ea) const
    {
        std::set<ea_t> out;
        func_entry_info_t fi;
        bool has_func = get_func_entry_info(&fi, func_ea);
        ea_t start = has_func ? fi.start_ea : func_ea;
        out.insert(start);

        // An import thunk (jmp cs:Foo): follow it and read its live IAT slot.
        if ( has_func && (fi.get_flags() & FUNC_THUNK) != 0 )
        {
            ea_t ptr = BADADDR;
            ea_t tgt = calc_thunk_function_target(&fi, &ptr);
            if ( tgt != BADADDR )
                out.insert(tgt);
            add_live_ptr(ptr, m_is64, out);
        }

        // The import data slot itself was picked: read the live pointer there.
        // Only for data, so code bytes are never read as a pointer.
        if ( !is_code(get_flags(start)) )
            add_live_ptr(start, m_is64, out);

        return std::vector<ea_t>(out.begin(), out.end());
    }

    void FunctionTracer::run_sweep()
    {
        if ( m_mgr == nullptr )
            return;

        // Each resolved runtime target to the picked function (for display and
        // types).
        std::map<ea_t, ea_t> tgt2disp;
        {
            std::lock_guard<std::mutex> g(m_traces_mtx);
            for ( ea_t picked : m_traces )
                for ( ea_t t : resolve_targets(picked) )
                    tgt2disp.emplace(t, picked);
        }
        if ( tgt2disp.empty() )
        {
            info("No functions are being traced. Right-click a function and pick "
                 "'TTD: Find all calls to this function'.");
            return;
        }

        ITraceBackend *backend = m_mgr->backend();
        if ( !m_mgr->is_active() || backend == nullptr )
        {
            warning("Tracing is only available while replaying a trace.");
            return;
        }

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
            warning("This recording's backend could not search for calls.");
            return;
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
            // Functions the API metadata describes are decoded from it (flags
            // by name, out parameters re-read at the return); others from
            // IDA's types.
            std::vector<DecodedCall> decoded(calls.size());
            std::map<ea_t, const win32meta::FuncSig *> sigs;
            auto sig_of = [&](ea_t f) -> const win32meta::FuncSig *
            {
                auto it = sigs.find(f);
                if ( it == sigs.end() )
                    it = sigs.emplace(f, api_signature(&m_mgr->modules(), f)).first;
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
            // Memory is still read through the cursor, which is cheap.
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

            size_t done = 0;
            for ( size_t k = 0; k < visits.size() && !regs_cancelled; k++ )
            {
                const Visit &v = visits[k];
                if ( user_cancelled() )
                {
                    cancelled = true;
                    break;
                }
                if ( (done & 0x3F) == 0 )
                    replace_wait_box("Resolving calls: %d of %d values... (Cancel to stop)",
                                     (int)done + 1, (int)visits.size());
                done++;
                if ( !cur->seek(v.where) )
                    continue;
                FunctionInvocation &ev = slot[v.call];
                if ( v.ret )
                {
                    ev.end_pos = v.where;
                    ev.has_ret = true;
                    DecodedCall &dc = decoded[v.call];
                    if ( dc.sig != nullptr )
                    {
                        GuestView rv = view_at(k);
                        decode_api_outs(rv, &dc);
                        ev.args.clear();
                        for ( const DecodedArg &a : dc.args )
                            ev.args.push_back(a.text);
                        ev.retval = decode_api_return(dc, get_return_value(rv, m_is64));
                        continue;
                    }
                    ev.retval  = render_return(view_at(k), ev.func_ea, m_is64);
                    continue;
                }
                GuestView view = view_at(k);
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
                if ( const win32meta::FuncSig *sig = sig_of(ev.func_ea) )
                {
                    decode_api_args(view, *sig, m_is64, &decoded[v.call]);
                    ev.args.clear();
                    for ( const DecodedArg &a : decoded[v.call].args )
                        ev.args.push_back(a.text);
                    continue;
                }
                extract_args(view, ev.func_ea, m_is64, ev.args);
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
    }
}
