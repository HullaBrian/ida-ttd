#include "ui.h"

using namespace TTD;

namespace idattd
{
    //=======================================================================
    // Small helper: a function's display name (demangled when possible).
    //=======================================================================
    static qstring func_display_name(ea_t ea)
    {
        qstring name;
        get_func_name(&name, ea);
        qstring dem;
        if ( demangle_name(&dem, name.c_str(), 0) > 0 && !dem.empty() )
            return dem;
        return name;
    }

    //=======================================================================
    // PositionChooser
    //=======================================================================
    static const int   g_pos_widths[] = { 16, 48 };
    static const char *g_pos_header[] = { "Position", "Event" };

    PositionChooser::PositionChooser(TraceManager *mgr)
        : chooser_t(CH_KEEP, qnumber(g_pos_widths), g_pos_widths, g_pos_header, "TTD Timeline"),
          m_mgr(mgr)
    {
        if ( m_mgr != nullptr )
            m_positions = m_mgr->collect_positions();
    }

    size_t idaapi PositionChooser::get_count() const
    {
        return m_positions.size();
    }

    void idaapi PositionChooser::get_row(qstrvec_t *cols, int * /*icon*/,
                                         chooser_item_attrs_t * /*attrs*/, size_t n) const
    {
        if ( n >= m_positions.size() )
            return;
        const TraceManager::NamedPosition &e = m_positions[n];
        cols->at(0).sprnt("%llX:%llX",
                          (uint64_t)e.pos.Sequence, (uint64_t)e.pos.Steps);
        cols->at(1) = e.name.c_str();
    }

    // Double-click / Enter: queue navigation to the selected position. We must
    // NOT resume the debugger synchronously from inside a chooser callback, and
    // we must never do it from get_ea() (IDA calls get_ea while rendering rows,
    // which would resume the debugger once per visible row). Hence: defer with
    // request_continue_process() + run_requests().
    chooser_t::cbret_t idaapi PositionChooser::enter(size_t n)
    {
        if ( m_mgr != nullptr && m_mgr->is_active() && n < m_positions.size() )
        {
            m_mgr->set_next_position(m_positions[n].pos);
            request_continue_process();
            run_requests();
        }
        return cbret_t(n, NOTHING_CHANGED);
    }

    //=======================================================================
    // TracedFunctionsChooser
    //=======================================================================
    static const int   g_trc_widths[] = { 18, 48 };
    static const char *g_trc_header[] = { "Offset", "Function name" };

    TracedFunctionsChooser::TracedFunctionsChooser(TraceManager *mgr, FunctionTracer *tracer)
        : chooser_t(CH_KEEP | CH_CAN_DEL | CH_CAN_INS,
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
        cols->at(1) = func_display_name(ea);
    }

    // Side-effect-free: lets Enter jump the disassembly to the function.
    ea_t idaapi TracedFunctionsChooser::get_ea(size_t n) const
    {
        return m_tracer != nullptr ? m_tracer->traced_at(n) : BADADDR;
    }

    chooser_t::cbret_t idaapi TracedFunctionsChooser::ins(ssize_t /*n*/)
    {
        func_t *f = choose_func("Choose a function to trace", get_screen_ea());
        if ( f == nullptr || m_tracer == nullptr )
            return cbret_t();
        m_tracer->add_func(f->start_ea);
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
            tinfo_t          t;
            func_type_data_t fd;
            if ( get_tinfo(&t, single) && t.is_func() && t.get_func_details(&fd) )
            {
                per_arg = true;
                argc    = (int)fd.size();
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
                // No prototype: four generic register/stack arg columns.
                per_arg = true;
                argc    = 4;
                for ( int i = 0; i < 4; i++ )
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
          chooser_t(CH_KEEP | CH_CAN_DEL,
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

        cols->at(0).sprnt("%llX:%llX", (uint64_t)ev.pos.Sequence, (uint64_t)ev.pos.Steps);
        if ( ev.has_ret )
            cols->at(1).sprnt("%llX:%llX", (uint64_t)ev.end_pos.Sequence, (uint64_t)ev.end_pos.Steps);
        cols->at(2).sprnt("%X", ev.tid);
        cols->at(3) = func_display_name(ev.func_ea);

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

    // Double-click / Enter: time-travel to this call's position. Deferred resume
    // only (never continue_process() directly, never from get_ea()).
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
    // TTD navigation action handlers
    //=======================================================================
    int idaapi RunBackHandler::activate(action_activation_ctx_t *)
    {
        if ( mgr != nullptr )
            mgr->request_run(false);
        return 1;
    }

    int idaapi StepOutBackHandler::activate(action_activation_ctx_t *)
    {
        if ( mgr != nullptr )
            mgr->request_step_out_backward();
        return 1;
    }

    int idaapi OpenTimelineHandler::activate(action_activation_ctx_t *)
    {
        if ( mgr == nullptr || !mgr->is_active() )
        {
            warning("The TTD timeline is only available while replaying a trace.");
            return 1;
        }
        // CH_KEEP: IDA takes ownership and frees the chooser when it closes.
        PositionChooser *ch = new PositionChooser(mgr);
        ch->choose();
        return 1;
    }

    int idaapi GotoPositionHandler::activate(action_activation_ctx_t *)
    {
        if ( mgr != nullptr )
            mgr->goto_position();
        return 1;
    }

    // Copy ASCII text to the Windows clipboard (IDA exposes no clipboard API).
    static void copy_to_clipboard(const char *text)
    {
        if ( text == nullptr || !OpenClipboard(nullptr) )
            return;
        EmptyClipboard();
        size_t  n = qstrlen(text) + 1;
        HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, n);
        if ( h != nullptr )
        {
            void *p = GlobalLock(h);
            if ( p != nullptr )
            {
                memcpy(p, text, n);
                GlobalUnlock(h);
                SetClipboardData(CF_TEXT, h);
            }
            else
            {
                GlobalFree(h);
            }
        }
        CloseClipboard();
    }

    int idaapi PositionCopyHandler::activate(action_activation_ctx_t *)
    {
        if ( mgr == nullptr || !mgr->is_active() )
            return 1;
        TTD::Replay::Position p = mgr->current_position();
        qstring s;
        s.sprnt("%llX:%llX", (uint64_t)p.Sequence, (uint64_t)p.Steps);
        copy_to_clipboard(s.c_str());
        msg("[ida-ttd] copied position %s to clipboard.\n", s.c_str());
        return 1;
    }

    int idaapi AnalyzeFuncHandler::activate(action_activation_ctx_t *)
    {
        if ( mgr == nullptr || !mgr->is_active() )
        {
            warning("Analysis is only available while replaying a trace.");
            return 1;
        }
        mgr->analyze_whole_function();
        return 1;
    }

    //=======================================================================
    // Tracer action handlers
    //=======================================================================
    // One click: trace the function under the cursor, sweep the whole trace,
    // and open the results.
    int idaapi TraceFuncHandler::activate(action_activation_ctx_t *ctx)
    {
        if ( tracer == nullptr )
            return 1;
        if ( mgr == nullptr || !mgr->is_active() )
        {
            warning("Tracing is only available while replaying a trace.");
            return 1;
        }
        ea_t ea = ctx != nullptr && ctx->cur_ea != BADADDR ? ctx->cur_ea : get_screen_ea();
        func_t *f = get_func(ea);
        ea_t target = f != nullptr ? f->start_ea : ea;

        // This is a focused "calls to THIS function" query: replace any prior
        // traced set so results aren't polluted by earlier picks. (Use the
        // 'Traced functions' chooser + 'Re-run trace' to accumulate several.)
        tracer->reset();
        tracer->add_func(target);
        tracer->run_sweep();

        TraceEventsChooser *ch = new TraceEventsChooser(mgr, tracer);
        ch->choose();
        return 1;
    }

    action_state_t idaapi TraceFuncHandler::update(action_update_ctx_t *ctx)
    {
        // Meaningful over a function (or any address with code) while replaying.
        if ( mgr != nullptr && mgr->is_active()
          && ctx != nullptr && ctx->cur_ea != BADADDR )
            return AST_ENABLE;
        return AST_DISABLE;
    }

    // Prompt for a "module!Glob*" pattern, trace every matching function in one
    // sweep, and open the results. With more than one match the events chooser
    // automatically condenses arguments into a single column.
    int idaapi TracePatternHandler::activate(action_activation_ctx_t *)
    {
        if ( tracer == nullptr )
            return 1;
        if ( mgr == nullptr || !mgr->is_active() )
        {
            warning("Tracing is only available while replaying a trace.");
            return 1;
        }

        qstring pat;
        if ( !ask_str(&pat, 0, "Trace calls to functions matching (wildcards * ?, "
                               "optional module!, e.g. kernel32!Virtual*)")
          || pat.empty() )
            return 1;

        std::vector<ea_t> hits = mgr->resolve_function_pattern(pat.c_str());
        if ( hits.empty() )
        {
            info("No functions matched '%s'.\n\n"
                 "Patterns match symbol names (exports/PDB). Make sure the module "
                 "is loaded in the trace and try e.g. 'kernel32!Virtual*'.", pat.c_str());
            return 1;
        }

        tracer->reset();
        for ( ea_t ea : hits )
            tracer->add_func(ea);
        tracer->run_sweep();

        TraceEventsChooser *ch = new TraceEventsChooser(mgr, tracer);
        ch->choose();
        return 1;
    }

    int idaapi OpenTracedHandler::activate(action_activation_ctx_t *)
    {
        TracedFunctionsChooser *ch = new TracedFunctionsChooser(mgr, tracer);
        ch->choose();
        return 1;
    }

    int idaapi OpenEventsHandler::activate(action_activation_ctx_t *)
    {
        TraceEventsChooser *ch = new TraceEventsChooser(mgr, tracer);
        ch->choose();
        return 1;
    }

    int idaapi RunTraceHandler::activate(action_activation_ctx_t *)
    {
        if ( mgr == nullptr || !mgr->is_active() )
        {
            warning("Tracing is only available while replaying a trace.");
            return 1;
        }
        if ( tracer != nullptr )
            tracer->run_sweep();
        return 1;
    }
}
