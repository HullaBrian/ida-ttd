// Function-call tracing: the recorded-call listing and the actions that
// drive a sweep.
#include "ui/ui.h"
#include "ui/names.h"
#include "debugger/apidecode.h"
#include "analysis/tracer.h"

namespace idattd
{
    // IDA's name for a traced function, else its export name: a module not
    // mapped at the current position has no names in the database, though
    // its exports matched the pattern.
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
    // TraceEventsChooser
    //=======================================================================
    EventColumns::EventColumns(FunctionTracer *tracer)
    {
        // One column per parameter only when a single function is traced
        // (all rows share its signature); else one "Arguments" column.
        ea_t single = (tracer != nullptr && tracer->count_traced() == 1)
                    ? tracer->traced_at(0) : BADADDR;

        // The same prototype the sweep decoded with (resolve_traced_proto),
        // so the headers name the values in the rows.
        std::vector<qstring> arg_names;
        if ( single != BADADDR )
        {
            per_arg = true;
            TraceManager *m = tracer->manager();
            arg_names = resolve_traced_proto(m != nullptr ? &m->modules() : nullptr, single).names;
            argc = (int)arg_names.size();
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

        // Only after header_strs is final, so the c_str() pointers stay valid.
        for ( const qstring &s : header_strs )
            header_ptrs.push_back(s.c_str());

        // A unique title so several tabs can coexist (IDA keys widgets by
        // title and would re-focus the first).
        static int seq = 0;
        qstring fname = single != BADADDR ? func_display_name(single) : qstring("calls");
        title_str.sprnt("TTD calls: %s [%d]", fname.c_str(), ++seq);
    }

    TraceEventsChooser::TraceEventsChooser(TraceManager *mgr, FunctionTracer *tracer)
        : EventColumns(tracer),
          ListingChooser(mgr, CH_CAN_DEL,
                         EventColumns::n(), EventColumns::w(), EventColumns::h(), EventColumns::t(),
                         tracer != nullptr ? tracer->snapshot_events() : std::vector<FunctionInvocation>())
    {
        for ( const FunctionInvocation &ev : m_rows )
        {
            auto [it, added] = m_labels.try_emplace(ev.func_ea);
            if ( !added )
                continue;
            FuncLabel &l = it->second;
            l.name = traced_name(m_mgr, ev.func_ea);
            if ( per_arg )
                continue;
            // Functions share the Arguments column, so each value is labeled
            // with its parameter name, from the prototype the sweep used.
            // Untyped functions' values stay unlabeled.
            TracedProto proto = resolve_traced_proto(m_mgr != nullptr ? &m_mgr->modules() : nullptr, ev.func_ea);
            if ( proto.sig != nullptr || proto.have_type )
                l.params = std::move(proto.names);
        }
    }

    void idaapi TraceEventsChooser::get_row(qstrvec_t *cols, int * /*icon*/,
                                            chooser_item_attrs_t * /*attrs*/, size_t n) const
    {
        if ( row(n) == nullptr )
            return;
        const FunctionInvocation &ev = *row(n);

        cols->at(0) = format_position(ev.pos);
        // No return in the recording (thread exit, ExitProcess, an unwind).
        cols->at(1) = ev.has_ret ? format_position(ev.end_pos) : qstring("no return");
        cols->at(2).sprnt("%X", ev.tid);
        auto label = m_labels.find(ev.func_ea);
        if ( label == m_labels.end() )
            return;                     // the constructor labeled every row's function
        cols->at(3) = label->second.name;

        if ( per_arg )
        {
            for ( int i = 0; i < argc; i++ )
                cols->at(LEAD + i) = i < (int)ev.args.size() ? ev.args[i] : qstring();
            if ( ev.has_ret )
                cols->at(LEAD + argc) = ev.retval;
        }
        else
        {
            const std::vector<qstring> &params = label->second.params;
            qstring joined;
            for ( size_t i = 0; i < ev.args.size(); i++ )
            {
                if ( i != 0 )
                    joined.append(", ");
                if ( i < params.size() && !params[i].empty() )
                {
                    joined.append(params[i]);
                    joined.append("=");
                }
                joined.append(ev.args[i]);
            }
            cols->at(LEAD) = joined;
            if ( ev.has_ret )
                cols->at(LEAD + 1) = ev.retval;
        }
    }

    //=======================================================================
    // Tracer actions
    //=======================================================================
    // One click: trace the function under the cursor, sweep the whole trace,
    // and open the results.
    // Open the calls just traced, unless there are none: a sweep that failed
    // or was cancelled has said so already, and one that found nothing has
    // logged "recorded 0 call(s)", so an empty tab would only add clutter.
    static void show_trace_events(TraceManager *mgr, FunctionTracer *tracer)
    {
        TraceEventsChooser *ch = new TraceEventsChooser(mgr, tracer);
        if ( ch->get_count() == 0 )
        {
            delete ch;
            return;
        }
        ch->choose();
    }

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

        // A focused "calls to this function" query: drop earlier picks.
        tracer()->reset();
        tracer()->add_func(target);
        qstring err;
        if ( !tracer()->run_sweep(&err) )
        {
            warning("%s", err.c_str());
            return 1;
        }

        show_trace_events(mgr(), tracer());
        return 1;
    }

    action_state_t idaapi TraceFuncHandler::update(action_update_ctx_t *ctx)
    {
        // Enabled over any address; activate() warns when no trace is
        // replayed.
        if ( ctx != nullptr && ctx->cur_ea != BADADDR )
            return AST_ENABLE;
        return AST_DISABLE;
    }

    // Prompt for a "module!Glob*" pattern, trace every match in one sweep,
    // and open the results (one Arguments column for several matches).
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
        qstring err;
        if ( !tracer()->run_sweep(&err) )
        {
            warning("%s", err.c_str());
            return 1;
        }

        show_trace_events(mgr(), tracer());
        return 1;
    }
}
