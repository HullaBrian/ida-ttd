#include "analysis/tracer.h"
#include "debugger/callconv.h"
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
            enum_type_data_t ed;
            bool named = false;
            if ( arg.get_enum_details(&ed) )
            {
                for ( size_t k = 0; k < ed.size(); k++ )
                    if ( (uint64_t)ed[k].value == raw ) { value = ed[k].name; named = true; break; }
            }
            if ( !named )
                value.sprnt("0x%llX", raw);
        }
        else if ( arg.is_floating() )
        {
            // 'raw' holds the argument's BITS (XMMn on x64, or the stack slot).
            // Reinterpret them rather than printing them as an integer. Anything
            // that is not a plain float/double (long double, an unknown size)
            // falls back to hex rather than being decoded as one.
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
            value.sprnt("%lld", (long long)raw);
        }
        else
        {
            value.sprnt("0x%llX", raw);
        }
        return value;
    }

    // Produce one "name=value" string per *actual* argument of the function's
    // signature (so the count matches the prototype). Falls back to four raw
    // register/stack args when there is no prototype.
    static void extract_args(const GuestView &cur, ea_t func_ea, bool is64, std::vector<qstring> &out)
    {
        tinfo_t          tinfo;
        func_type_data_t fd;
        bool have = get_tinfo(&tinfo, func_ea) && tinfo.is_func() && tinfo.get_func_details(&fd);

        // Value-only cells: the chooser renders one column per argument with the
        // parameter name as the column header, so the name doesn't belong here.
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
                value.sprnt("%lld", (long long)rv);
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

    // Resolve a picked function address to the real runtime callee address(es).
    // Calls reach an imported function either directly (target == real VA) or
    // through a thunk (target == thunk addr, which jmps via the IAT). We collect
    // all of: the function start, the thunk's resolved target, and the live IAT
    // pointer value, so the call/return sweep matches regardless of the path.
    // Read the live pointer stored at 'slot' (an IAT/import slot) and add it.
    static void add_live_ptr(ea_t slot, bool is64, std::set<ea_t> &out)
    {
        if ( slot == BADADDR )
            return;
        ea_t v = is64 ? (ea_t)get_qword(slot) : (ea_t)get_dword(slot);
        if ( v != 0 && v != BADADDR )
            out.insert(v);
    }

    std::vector<ea_t> FunctionTracer::resolve_targets(ea_t func_ea) const
    {
        std::set<ea_t> out;
        func_entry_info_t fi;
        bool has_func = get_func_entry_info(&fi, func_ea);
        ea_t start = has_func ? fi.start_ea : func_ea;
        out.insert(start);

        // Case 1: an import thunk (jmp cs:Foo) -> follow it and read its live
        // IAT slot to get the real runtime callee VA.
        if ( has_func && (fi.get_flags() & FUNC_THUNK) != 0 )
        {
            ea_t ptr = BADADDR;
            ea_t tgt = calc_thunk_function_target(&fi, &ptr);
            if ( tgt != BADADDR )
                out.insert(tgt);
            add_live_ptr(ptr, m_is64, out);
        }

        // Case 2: the user clicked the import data slot itself (no function, or a
        // data item). Read the live pointer there = runtime callee VA. Only do
        // this for data so we don't misread real code bytes as a pointer.
        if ( !is_code(get_flags(start)) )
            add_live_ptr(start, m_is64, out);

        return std::vector<ea_t>(out.begin(), out.end());
    }

    void FunctionTracer::run_sweep()
    {
        if ( m_mgr == nullptr )
            return;

        // Map every resolved runtime target -> the user-picked function (for
        // display + type info). Built on the main thread; read-only in the
        // replay callback.
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

        // Phase 2 runs on the main thread, so it has real progress and a
        // working Cancel.
        CursorPtr cur = backend->make_cursor();
        std::vector<FunctionInvocation> built;
        built.reserve(calls.size());
        bool cancelled = qr.cancelled;
        const uint64_t ptr = m_is64 ? 8 : 4;
        show_wait_box("Resolving %d call(s)... (Cancel to stop)", (int)calls.size());
        if ( cur )
        {
            // Every place to read, then read them in position order. A call's
            // arguments and its return are far apart, and a backend that
            // rebuilds state from the nearest checkpoint (Sogen) pays for that
            // checkpoint again each time the reads alternate between two --
            // which, call by call, they otherwise always do.
            struct Visit { Position where; size_t call; bool ret; };
            std::vector<Visit> visits;
            std::vector<FunctionInvocation> slot(calls.size());
            std::vector<bool> keep(calls.size(), false);
            for ( size_t i = 0; i < calls.size(); i++ )
            {
                const CallEvent &c = calls[i];
                auto disp = tgt2disp.find(c.target);
                if ( disp == tgt2disp.end() )
                    continue;
                // The arguments are decoded as the caller left them, just
                // before the call. Without a call -- the thread began in the
                // callee, or a jump got there -- they are read at the entry
                // instead (see below).
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

            size_t done = 0;
            for ( const Visit &v : visits )
            {
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
                    ev.retval  = render_return(guest_view(cur.get()), ev.func_ea, m_is64);
                    ev.has_ret = true;
                    continue;
                }
                GuestView view = guest_view(cur.get());
                const CallEvent &c = calls[v.call];
                if ( !(c.is_call && c.pos.is_valid()) )
                {
                    // At the entry the return address is already on the
                    // stack: step the stack pointer back over it so the stack
                    // arguments are where a call site would have them.
                    auto regs = view.regs;
                    view.regs = [regs, ptr](ittd_regs *r)
                    {
                        if ( !regs || !regs(r) )
                            return false;
                        r->gp[ITTD_REG_RSP] += ptr;
                        return true;
                    };
                }
                extract_args(view, ev.func_ea, m_is64, ev.args);
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

        // Open events tabs are not refreshed: each holds a snapshot frozen when it
        // was opened, and a later sweep must not rewrite it.
        if ( cancelled )
            msg("[ida-ttd] tracer: cancelled - showing %d of %d recorded call(s).\n",
                (int)nbuilt, (int)calls.size());
        else
            msg("[ida-ttd] tracer: recorded %d call(s).\n", (int)built.size());
    }
}
