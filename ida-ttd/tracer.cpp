#include "tracer.h"
#include "callconv.h"
#include "trace_manager.h"

using namespace TTD;
using namespace TTD::Replay;

namespace idattd
{
    //-----------------------------------------------------------------------
    // Raw integer-register argument when no prototype is available.
    static uint64_t raw_int_arg(ICursorView *cur, size_t n, bool is64)
    {
        CROSS_PLATFORM_CONTEXT ctx = cur->GetCrossPlatformContext();
        if ( is64 )
        {
            const AMD64_CONTEXT &c = ctx.Amd64Context;
            const uint64_t r[4] = { c.Rcx, c.Rdx, c.R8, c.R9 };
            return n < 4 ? r[n] : 0;
        }
        const X86_NT5_CONTEXT &c = ctx.X86Nt5Context;
        uint32_t v = 0;
        read_guest(cur, (uint64_t)c.Esp + n * 4, &v, sizeof(v));
        return v;
    }

    //-----------------------------------------------------------------------
    static qstring render_pointer(ICursorView *cur, const tinfo_t &ptr_t, uint64_t ptr)
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

    //-----------------------------------------------------------------------
    // Render a single argument value (no type prefix) from the integer fetched
    // at the call site.
    static qstring render_value(ICursorView *cur, const tinfo_t &arg, uint64_t raw)
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

    //-----------------------------------------------------------------------
    // Produce one "name=value" string per *actual* argument of the function's
    // signature (so the count matches the prototype). Falls back to four raw
    // register/stack args when there is no prototype.
    static void extract_args(ICursorView *cur, ea_t func_ea, bool is64, std::vector<qstring> &out)
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

    //-----------------------------------------------------------------------
    static qstring render_return(ICursorView *cur, ea_t func_ea, bool is64)
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

    //=======================================================================
    void FunctionTracer::reset()
    {
        { std::lock_guard<std::mutex> g(m_traces_mtx); m_traces.clear(); }
        clear_events();
    }

    //-----------------------------------------------------------------------
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

    //-----------------------------------------------------------------------
    void FunctionTracer::remove_trace(size_t n)
    {
        std::lock_guard<std::mutex> g(m_traces_mtx);
        if ( n < m_traces.size() )
            m_traces.erase(m_traces.begin() + n);
    }

    //-----------------------------------------------------------------------
    bool FunctionTracer::is_traced(ea_t func_ea)
    {
        std::lock_guard<std::mutex> g(m_traces_mtx);
        for ( ea_t ea : m_traces )
            if ( ea == func_ea )
                return true;
        return false;
    }

    //-----------------------------------------------------------------------
    size_t FunctionTracer::count_traced()
    {
        std::lock_guard<std::mutex> g(m_traces_mtx);
        return m_traces.size();
    }

    //-----------------------------------------------------------------------
    ea_t FunctionTracer::traced_at(size_t n)
    {
        std::lock_guard<std::mutex> g(m_traces_mtx);
        return n < m_traces.size() ? m_traces[n] : BADADDR;
    }

    //-----------------------------------------------------------------------
    size_t FunctionTracer::count_events()
    {
        std::lock_guard<std::mutex> g(m_events_mtx);
        return m_events.size();
    }

    //-----------------------------------------------------------------------
    FunctionInvocation FunctionTracer::event_at(size_t n)
    {
        std::lock_guard<std::mutex> g(m_events_mtx);
        return n < m_events.size() ? m_events[n] : FunctionInvocation{};
    }

    //-----------------------------------------------------------------------
    void FunctionTracer::remove_event(size_t n)
    {
        std::lock_guard<std::mutex> g(m_events_mtx);
        if ( n < m_events.size() )
            m_events.erase(m_events.begin() + n);
    }

    //-----------------------------------------------------------------------
    void FunctionTracer::clear_events()
    {
        std::lock_guard<std::mutex> g(m_events_mtx);
        m_events.clear();
    }

    //-----------------------------------------------------------------------
    std::vector<FunctionInvocation> FunctionTracer::snapshot_events()
    {
        std::lock_guard<std::mutex> g(m_events_mtx);
        return m_events;
    }

    //-----------------------------------------------------------------------
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

    //-----------------------------------------------------------------------
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

        UniqueCursor sweep = m_mgr->make_cursor();
        if ( !sweep )
        {
            warning("Tracing is only available while replaying a trace.");
            return;
        }

        struct Rec
        {
            ea_t     disp;
            uint32_t tid;
            Position callPos;
            uint64_t retAddr;
            Position retPos;
            bool     hasRet;
        };
        std::vector<Rec> recs;
        std::map<uint32_t, std::vector<size_t>> inflight; // per-thread call stack

        auto on_call_ret = [&](GuestAddress instr, GuestAddress fall_through,
                               IThreadView const *t) noexcept
        {
            uint32_t utid = (uint32_t)t->GetThreadInfo().UniqueId;
            if ( (uint64_t)fall_through != 0 )
            {
                // CALL: instr == callee.
                auto it = tgt2disp.find((ea_t)(uint64_t)instr);
                if ( it != tgt2disp.end() )
                {
                    Rec r{};
                    r.disp    = it->second;
                    r.tid     = utid;
                    r.callPos = t->GetPosition();
                    r.retAddr = (uint64_t)fall_through;
                    r.hasRet  = false;
                    inflight[utid].push_back(recs.size());
                    recs.push_back(r);
                }
            }
            else
            {
                // RET: instr == address being returned to. Pair with the most
                // recent in-flight call on this thread whose return address matches.
                auto it = inflight.find(utid);
                if ( it != inflight.end() && !it->second.empty() )
                {
                    size_t idx = it->second.back();
                    if ( (uint64_t)instr == recs[idx].retAddr )
                    {
                        recs[idx].retPos = t->GetPosition();
                        recs[idx].hasRet = true;
                        it->second.pop_back();
                    }
                }
            }
        };

        show_wait_box("HIDECANCEL\nTracing function calls across the whole trace...");
        sweep->SetReplayFlags(ReplayFlags::ReplayAllSegmentsWithoutFiltering
                            | ReplayFlags::ReplaySegmentsSequentially);
        sweep->SetCallReturnCallback(on_call_ret);
        sweep->SetPosition(Position::Min);
        sweep->ReplayForward();
        sweep.reset();

        // Phase 2: resolve arguments / return values at each recorded position.
        replace_wait_box("Resolving %d call(s)...", (int)recs.size());
        UniqueCursor cur = m_mgr->make_cursor();
        std::vector<FunctionInvocation> built;
        built.reserve(recs.size());
        if ( cur )
        {
            for ( const Rec &rec : recs )
            {
                cur->SetPosition(rec.callPos);
                FunctionInvocation ev;
                ev.func_ea = rec.disp;
                ev.pos     = rec.callPos;
                ev.tid     = rec.tid;
                extract_args(cur.get(), rec.disp, m_is64, ev.args);
                if ( rec.hasRet )
                {
                    cur->SetPosition(rec.retPos);
                    ev.end_pos = rec.retPos;
                    ev.retval  = render_return(cur.get(), rec.disp, m_is64);
                    ev.has_ret = true;
                }
                built.push_back(std::move(ev));
            }
        }

        std::sort(built.begin(), built.end(),
                  [](const FunctionInvocation &a, const FunctionInvocation &b) { return a.pos < b.pos; });

        {
            std::lock_guard<std::mutex> g(m_events_mtx);
            m_events = std::move(built);
        }
        hide_wait_box();

        refresh_chooser("Tracing events");
        msg("[ida-ttd] tracer: recorded %d call(s).\n", (int)recs.size());
    }
}
