// Function-call tracing: the traced-function list, the recorded-call listing and
// the actions that drive a sweep.
#include "ui/ui.h"
#include "ui/names.h"

namespace idattd
{
    // IDA's name for a traced function, or the export it is when IDA has no
    // name there yet: a module that is not mapped where the user is has no
    // names in the database, but its exports matched the pattern by name.
    static qstring traced_name(TraceManager *mgr, ea_t ea)
    {
        qstring n = func_display_name(ea);
        if ( n.length() > 2 && n[0] == '0' && n[1] == 'x' && mgr != nullptr )
        {
            qstring e = mgr->modules().export_name_at(ea);
            if ( !e.empty() )
                return e;
        }
        return n;
    }

    //=======================================================================
    // TracedFunctionsChooser
    //=======================================================================
    static const int   g_trc_widths[] = { 18, 48 };
    static const char *g_trc_header[] = { "Offset", "Function name" };

    TracedFunctionsChooser::TracedFunctionsChooser(TraceManager *mgr, FunctionTracer *tracer)
        : chooser_t(CH_CAN_DEL | CH_CAN_INS,
                    qnumber(g_trc_widths), g_trc_widths, g_trc_header, "Traced functions"),
          m_mgr(mgr), m_tracer(tracer)
    {
    }

    size_t idaapi TracedFunctionsChooser::get_count() const
    {
        return m_tracer != nullptr ? m_tracer->count_traced() : 0;
    }

    void idaapi TracedFunctionsChooser::get_row(qstrvec_t *cols, int * /*icon*/,
                                                chooser_item_attrs_t * /*attrs*/, size_t n) const
    {
        if ( m_tracer == nullptr )
            return;
        ea_t ea = m_tracer->traced_at(n);
        cols->at(0).sprnt("0x%llX", (uint64_t)ea);
        cols->at(1) = traced_name(m_mgr, ea);
    }

    ea_t idaapi TracedFunctionsChooser::get_ea(size_t n) const
    {
        return m_tracer != nullptr ? m_tracer->traced_at(n) : BADADDR;
    }

    chooser_t::cbret_t idaapi TracedFunctionsChooser::ins(ssize_t /*n*/)
    {
        ea_t fea = choose_func_ea("Choose a function to trace", get_screen_ea());
        if ( fea == BADADDR || m_tracer == nullptr )
            return cbret_t();
        m_tracer->add_func(fea);
        return ALL_CHANGED;
    }

    chooser_t::cbret_t idaapi TracedFunctionsChooser::del(size_t n)
    {
        if ( m_tracer != nullptr )
            m_tracer->remove_trace(n);
        return ALL_CHANGED;
    }

    //=======================================================================
    // TraceEventsChooser
    //=======================================================================
    // Columns for a function with no prototype: four generic argument slots.
    static const int UNTYPED_ARGC = 4;

    EventColumns::EventColumns(FunctionTracer *tracer)
    {
        // One column per parameter only makes sense when a single function is
        // traced (all rows share its signature). Otherwise fall back to one
        // combined "Arguments" column.
        ea_t single = (tracer != nullptr && tracer->count_traced() == 1)
                    ? tracer->traced_at(0) : BADADDR;

        std::vector<qstring> arg_names;
        if ( single != BADADDR )
        {
            per_arg = true;
            tinfo_t          t;
            func_type_data_t fd;
            if ( get_tinfo(&t, single) && t.is_func() && t.get_func_details(&fd) )
            {
                argc = (int)fd.size();
                for ( size_t i = 0; i < fd.size(); i++ )
                {
                    qstring nm = fd[i].name;
                    if ( nm.empty() )
                        nm.sprnt("arg%d", (int)i);
                    arg_names.push_back(nm);
                }
            }
            else
            {
                argc = UNTYPED_ARGC;
                for ( int i = 0; i < UNTYPED_ARGC; i++ )
                {
                    qstring nm;
                    nm.sprnt("arg%d", i);
                    arg_names.push_back(nm);
                }
            }
        }

        // Fixed leading columns (LEAD == 4): call/return positions, thread, name.
        header_strs.push_back("Start");     widths.push_back(16);
        header_strs.push_back("End");       widths.push_back(16);
        header_strs.push_back("Thread");    widths.push_back(8);
        header_strs.push_back("Function");  widths.push_back(22);
        if ( per_arg )
        {
            for ( const qstring &nm : arg_names )
            {
                header_strs.push_back(nm);
                widths.push_back(24);
            }
        }
        else
        {
            header_strs.push_back("Arguments");
            widths.push_back(72);
        }
        header_strs.push_back("Return");    widths.push_back(26);

        // Build the pointer array only after header_strs is final (so the
        // c_str() pointers stay valid for the chooser's lifetime).
        for ( const qstring &s : header_strs )
            header_ptrs.push_back(s.c_str());

        // A unique, descriptive title so multiple events tabs can coexist (IDA
        // keys widgets by title and would otherwise just re-focus the first).
        static int seq = 0;
        qstring fname = single != BADADDR ? func_display_name(single) : qstring("calls");
        title_str.sprnt("TTD calls: %s [%d]", fname.c_str(), ++seq);
    }

    TraceEventsChooser::TraceEventsChooser(TraceManager *mgr, FunctionTracer *tracer)
        : EventColumns(tracer),
          chooser_t(CH_CAN_DEL,
                    EventColumns::n(), EventColumns::w(), EventColumns::h(), EventColumns::t()),
          m_mgr(mgr),
          m_events(tracer != nullptr ? tracer->snapshot_events() : std::vector<FunctionInvocation>())
    {
    }

    size_t idaapi TraceEventsChooser::get_count() const
    {
        return m_events.size();
    }

    void idaapi TraceEventsChooser::get_row(qstrvec_t *cols, int * /*icon*/,
                                            chooser_item_attrs_t * /*attrs*/, size_t n) const
    {
        if ( n >= m_events.size() )
            return;
        const FunctionInvocation &ev = m_events[n];

        cols->at(0) = format_position(ev.pos);
        // A call with no return in the recording (a thread that exited in it,
        // ExitProcess, an unwind) says so rather than leaving a gap.
        cols->at(1) = ev.has_ret ? format_position(ev.end_pos) : qstring("no return");
        cols->at(2).sprnt("%X", ev.tid);
        cols->at(3) = traced_name(m_mgr, ev.func_ea);

        if ( per_arg )
        {
            for ( int i = 0; i < argc; i++ )
                cols->at(LEAD + i) = i < (int)ev.args.size() ? ev.args[i] : qstring();
            if ( ev.has_ret )
                cols->at(LEAD + argc) = ev.retval;
        }
        else
        {
            // Multiple functions share this column, so label each value with its
            // parameter name (from the row's own signature) when available.
            tinfo_t          t;
            func_type_data_t fd;
            bool named = get_tinfo(&t, ev.func_ea) && t.is_func() && t.get_func_details(&fd);

            qstring joined;
            for ( size_t i = 0; i < ev.args.size(); i++ )
            {
                if ( i != 0 )
                    joined.append(", ");
                if ( named && i < fd.size() && !fd[i].name.empty() )
                {
                    joined.append(fd[i].name);
                    joined.append("=");
                }
                joined.append(ev.args[i]);
            }
            cols->at(LEAD) = joined;
            if ( ev.has_ret )
                cols->at(LEAD + 1) = ev.retval;
        }
    }

    chooser_t::cbret_t idaapi TraceEventsChooser::enter(size_t n)
    {
        if ( m_mgr != nullptr && m_mgr->is_active() && n < m_events.size() )
        {
            m_mgr->set_next_position(m_events[n].pos);
            request_continue_process();
            run_requests();
        }
        return cbret_t(n, NOTHING_CHANGED);
    }

    chooser_t::cbret_t idaapi TraceEventsChooser::del(size_t n)
    {
        if ( n < m_events.size() )
            m_events.erase(m_events.begin() + n);
        return ALL_CHANGED;
    }

    //=======================================================================
    // Tracer actions
    //=======================================================================
    // One click: trace the function under the cursor, sweep the whole trace,
    // and open the results.
    int idaapi TraceFuncHandler::activate(action_activation_ctx_t *ctx)
    {
        if ( tracer() == nullptr )
            return 1;
        if ( mgr() == nullptr || !mgr()->is_active() )
        {
            warning("Tracing is only available while replaying a trace.");
            return 1;
        }
        ea_t ea = ctx != nullptr && ctx->cur_ea != BADADDR ? ctx->cur_ea : get_screen_ea();
        ea_t fstart = get_func_start(ea);
        ea_t target = fstart != BADADDR ? fstart : ea;

        // This is a focused "calls to this function" query: replace any prior
        // traced set so results aren't polluted by earlier picks. (Use the
        // 'Traced functions' chooser + 'Re-run trace' to accumulate several.)
        tracer()->reset();
        tracer()->add_func(target);
        tracer()->run_sweep();

        TraceEventsChooser *ch = new TraceEventsChooser(mgr(), tracer());
        ch->choose();
        return 1;
    }

    action_state_t idaapi TraceFuncHandler::update(action_update_ctx_t *ctx)
    {
        // Meaningful over any address with code (the handler warns if no trace is
        // being replayed when invoked).
        if ( ctx != nullptr && ctx->cur_ea != BADADDR )
            return AST_ENABLE;
        return AST_DISABLE;
    }

    // Prompt for a "module!Glob*" pattern, trace every matching function in one
    // sweep, and open the results. With more than one match the events chooser
    // automatically condenses arguments into a single column.
    int idaapi TracePatternHandler::activate(action_activation_ctx_t *)
    {
        if ( tracer() == nullptr )
            return 1;
        if ( mgr() == nullptr || !mgr()->is_active() )
        {
            warning("Tracing is only available while replaying a trace.");
            return 1;
        }

        qstring pat;
        if ( !ask_str(&pat, 0, "Trace calls to functions matching (wildcards * ?, "
                               "optional module!, e.g. kernel32!Virtual*)")
          || pat.empty() )
            return 1;

        std::vector<ea_t> hits = mgr()->modules().resolve_function_pattern(pat.c_str());
        if ( hits.empty() )
        {
            info("No functions matched '%s'.\n\n"
                 "Patterns match symbol names (exports/PDB). Make sure the module "
                 "is loaded in the trace and try e.g. 'kernel32!Virtual*'.", pat.c_str());
            return 1;
        }

        tracer()->reset();
        for ( ea_t ea : hits )
            tracer()->add_func(ea);
        tracer()->run_sweep();

        TraceEventsChooser *ch = new TraceEventsChooser(mgr(), tracer());
        ch->choose();
        return 1;
    }

    int idaapi OpenTracedHandler::activate(action_activation_ctx_t *)
    {
        TracedFunctionsChooser *ch = new TracedFunctionsChooser(mgr(), tracer());
        ch->choose();
        return 1;
    }

    int idaapi OpenEventsHandler::activate(action_activation_ctx_t *)
    {
        TraceEventsChooser *ch = new TraceEventsChooser(mgr(), tracer());
        ch->choose();
        return 1;
    }

    int idaapi RunTraceHandler::activate(action_activation_ctx_t *)
    {
        if ( mgr() == nullptr || !mgr()->is_active() )
        {
            warning("Tracing is only available while replaying a trace.");
            return 1;
        }
        if ( tracer() != nullptr )
            tracer()->run_sweep();
        return 1;
    }
}
