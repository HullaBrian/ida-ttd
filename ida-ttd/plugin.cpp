#include "plugin.h"
#include "registers.h"

// Embedded Microsoft codicon debugger glyphs (SVG) for the debug-movement
// actions, including the "continue backwards" action IDA has no native icon for.
#include "icons.hh"

namespace idattd
{
    static const char *TTD_TOOLBAR = "TTDToolBar";

    //-----------------------------------------------------------------------
    // Flag the call stack + stack views for refresh. We build the widget mask by
    // hand instead of via IWID_*/builtin_widget_mask_from_id, whose uint128 <<
    // is defined out-of-line and not present in ida.lib (link error on MSVC).
    static void refresh_call_stack()
    {
        const uint64 m = (uint64(1) << BWN_CALL_STACK) | (uint64(1) << BWN_STKVIEW);
        mark_builtin_widgets(uint128(m, uint64(0)));
    }
    //-----------------------------------------------------------------------
    Plugin::Plugin()
    {
        configure_debugger(m_debugger, inf_is_64bit());
        m_mgr.set_plugin(this);
        m_tracer.set_manager(&m_mgr);
        m_tracer.set_64bit(inf_is_64bit());

        m_dbgEvents.p = this;
        m_uiEvents.p  = this;
        m_idbEvents.p = this;

        register_actions();
        hook_event_listener(HT_IDD, this);
        hook_event_listener(HT_DBG, &m_dbgEvents);
        hook_event_listener(HT_UI,  &m_uiEvents);
        hook_event_listener(HT_IDB, &m_idbEvents);
    }

    //-----------------------------------------------------------------------
    Plugin::~Plugin()
    {
        unhook_event_listener(HT_IDB, &m_idbEvents);
        unhook_event_listener(HT_UI,  &m_uiEvents);
        unhook_event_listener(HT_DBG, &m_dbgEvents);
        unhook_event_listener(HT_IDD, this);
        unregister_actions();
        for ( int ic : { m_icoContinue, m_icoRevContinue, m_icoStepInto,
                         m_icoStepOver, m_icoStepOut, m_icoStepBack,
                         m_icoStepIntoBack, m_icoStepOutBack,
                         m_icoRunToCur, m_icoRunToCurBack,
                         m_icoTimeline, m_icoGoto, m_icoFuncSearch } )
            if ( ic != -1 )
                free_custom_icon(ic);
    }

    //-----------------------------------------------------------------------
    void Plugin::load_icons()
    {
        auto svg = [](const char *s, size_t len) { return load_custom_icon(s, (unsigned)len, "svg"); };
        m_icoContinue    = svg(icon_continue_svg,         sizeof(icon_continue_svg) - 1);
        m_icoRevContinue = svg(icon_reverse_continue_svg, sizeof(icon_reverse_continue_svg) - 1);
        m_icoStepInto    = svg(icon_step_into_svg,        sizeof(icon_step_into_svg) - 1);
        m_icoStepOver    = svg(icon_step_over_svg,        sizeof(icon_step_over_svg) - 1);
        m_icoStepOut     = svg(icon_step_out_svg,         sizeof(icon_step_out_svg) - 1);
        m_icoStepBack    = svg(icon_step_back_svg,        sizeof(icon_step_back_svg) - 1);
        m_icoStepIntoBack = svg(icon_step_into_back_svg,  sizeof(icon_step_into_back_svg) - 1);
        m_icoStepOutBack = svg(icon_step_out_back_svg,    sizeof(icon_step_out_back_svg) - 1);
        m_icoRunToCur    = svg(icon_step_to_cursor_forward_svg,  sizeof(icon_step_to_cursor_forward_svg) - 1);
        m_icoRunToCurBack = svg(icon_step_to_cursor_backward_svg, sizeof(icon_step_to_cursor_backward_svg) - 1);
        m_icoTimeline    = svg(icons_timeline_svg,        sizeof(icons_timeline_svg) - 1);
        m_icoGoto        = svg(icons_goto_time_svg,       sizeof(icons_goto_time_svg) - 1);
        m_icoFuncSearch  = svg(icons_function_search_svg, sizeof(icons_function_search_svg) - 1);
    }

    //-----------------------------------------------------------------------
    bool idaapi Plugin::run(size_t)
    {
        info("ida-ttd: select 'TTD trace replayer' under Debugger > Switch debugger, "
             "then start with a .run trace file as the application.");
        return true;
    }

    //-----------------------------------------------------------------------
    void Plugin::register_actions()
    {
        load_icons();

        // Wire handler back-pointers.
        m_runBack.mgr     = &m_mgr;
        m_stepOutBack.mgr = &m_mgr;
        m_timeline.mgr    = &m_mgr;
        m_posLabel.mgr    = &m_mgr;
        m_goto.mgr        = &m_mgr;
        m_analyzeFunc.mgr = &m_mgr;

        m_traceFunc.mgr  = &m_mgr;  m_traceFunc.tracer  = &m_tracer;
        m_tracePat.mgr   = &m_mgr;  m_tracePat.tracer   = &m_tracer;
        m_openTraced.mgr = &m_mgr;  m_openTraced.tracer = &m_tracer;
        m_openEvents.mgr = &m_mgr;  m_openEvents.tracer = &m_tracer;
        m_runTrace.mgr   = &m_mgr;  m_runTrace.tracer   = &m_tracer;

        register_action(ACTION_DESC_LITERAL_PLUGMOD(
            actions::RUN_BACK, "Continue backwards", &m_runBack, this,
            nullptr, "Continue backwards: run backward to the previous breakpoint or the start of the trace", m_icoRevContinue));
        register_action(ACTION_DESC_LITERAL_PLUGMOD(
            actions::STEP_OUT_BACK, "Step out backwards", &m_stepOutBack, this,
            nullptr, "Step out backwards: run backward out of the current function to the call that entered it", m_icoStepOutBack));
        // Live trace-position readout (text-only toolbar button; click copies).
        register_action(ACTION_DESC_LITERAL_PLUGMOD(
            actions::POS_LABEL, "TTD position", &m_posLabel, this,
            nullptr, "Current TTD position (Sequence:Steps) — click to copy it to the clipboard", -1));
        register_action(ACTION_DESC_LITERAL_PLUGMOD(
            actions::ANALYZE_FUNC, "TTD: Analyze whole function", &m_analyzeFunc, this,
            "Ctrl+Shift+A", "Analyze whole function: walk the trace backward to find the enclosing "
            "function's entry and define it (runs behind a cancellable wait box)", -1));
        register_action(ACTION_DESC_LITERAL_PLUGMOD(
            actions::TRACE_FUNC, "TTD: Find all calls to this function", &m_traceFunc, this,
            "Ctrl+Shift+C", "Find all calls to this function: sweep the whole trace and list every call with its arguments and return value", -1));
        register_action(ACTION_DESC_LITERAL_PLUGMOD(
            actions::TRACE_PAT, "TTD: Find calls by name/pattern...", &m_tracePat, this,
            "Ctrl+Shift+F", "Find calls by name/pattern: trace every function matching a wildcard like 'kernel32!Virtual*' in one sweep", m_icoFuncSearch));
        register_action(ACTION_DESC_LITERAL_PLUGMOD(
            actions::OPEN_EVENTS, "TTD: Trace events...", &m_openEvents, this,
            nullptr, "Trace events: open the recorded calls (arguments and return values)", -1));
        register_action(ACTION_DESC_LITERAL_PLUGMOD(
            actions::OPEN_TRACED, "TTD: Traced functions...", &m_openTraced, this,
            nullptr, "Traced functions: manage the list of functions selected for call tracing", -1));
        register_action(ACTION_DESC_LITERAL_PLUGMOD(
            actions::RUN_TRACE, "TTD: Re-run trace", &m_runTrace, this,
            nullptr, "Re-run trace: re-sweep the trace for all currently traced functions", -1));
        register_action(ACTION_DESC_LITERAL_PLUGMOD(
            actions::TIMELINE, "TTD: Timeline...", &m_timeline, this,
            "Ctrl+Shift+T", "Timeline: open the TTD trace timeline of notable positions", m_icoTimeline));
        register_action(ACTION_DESC_LITERAL_PLUGMOD(
            actions::GOTO_POS, "TTD: Go to position...", &m_goto, this,
            "Ctrl+Shift+G", "Go to position: jump to a Sequence:Steps trace position", m_icoGoto));

        // Top-level TTD menu (extras + a mirror of the movement commands).
        attach_action_to_menu("TTD/Find all calls to function", actions::TRACE_FUNC,  SETMENU_APP);
        attach_action_to_menu("TTD/Find calls by name or pattern", actions::TRACE_PAT, SETMENU_APP);
        attach_action_to_menu("TTD/Analyze whole function",     actions::ANALYZE_FUNC, SETMENU_APP);
        attach_action_to_menu("TTD/Trace events",               actions::OPEN_EVENTS, SETMENU_APP);
        attach_action_to_menu("TTD/Traced functions",           actions::OPEN_TRACED, SETMENU_APP);
        attach_action_to_menu("TTD/Re-run trace",               actions::RUN_TRACE,   SETMENU_APP);
        attach_action_to_menu("TTD/Timeline",                   actions::TIMELINE,    SETMENU_APP);
        attach_action_to_menu("TTD/Go to position",             actions::GOTO_POS,    SETMENU_APP);
        attach_action_to_menu("TTD/Continue backwards",         actions::RUN_BACK,    SETMENU_APP);
        attach_action_to_menu("TTD/Step out backwards",         actions::STEP_OUT_BACK, SETMENU_APP);

        // Build the toolbar immediately so the TTD buttons are always present.
        // (The native debug-movement actions register lazily, so show_actions runs
        // again on session start to pick those up.)
        show_actions();
    }

    //-----------------------------------------------------------------------
    void Plugin::unregister_actions()
    {
        const char *names[] = {
            actions::RUN_BACK, actions::STEP_OUT_BACK, actions::POS_LABEL, actions::TRACE_FUNC,
            actions::TRACE_PAT, actions::ANALYZE_FUNC, actions::OPEN_EVENTS, actions::OPEN_TRACED,
            actions::RUN_TRACE, actions::TIMELINE, actions::GOTO_POS,
        };
        for ( const char *n : names )
            unregister_action(n);
    }

    //-----------------------------------------------------------------------
    // Re-skin the native debug-movement actions with the codicon glyphs. IDA
    // registers some of these actions lazily (e.g. ThreadRunToCursorBackwards may
    // not exist at the first show) and ALSO resets their icons whenever it rebuilds
    // the debugger toolbars (e.g. after a memory-cache invalidation on a TTD jump),
    // so this must be reapplied repeatedly — at session start AND on every stop.
    void Plugin::reskin_actions()
    {
        update_action_icon("ProcessStart",              m_icoContinue);
        update_action_icon("ThreadStepInto",            m_icoStepInto);
        update_action_icon("ThreadStepOver",            m_icoStepOver);
        update_action_icon("ThreadRunUntilReturn",      m_icoStepOut);
        update_action_icon("ThreadStepIntoBackwards",   m_icoStepIntoBack);
        update_action_icon("ThreadStepOverBackwards",   m_icoStepBack);
        update_action_icon("ThreadRunToCursor",         m_icoRunToCur);
        update_action_icon("ThreadRunToCursorBackwards", m_icoRunToCurBack);
    }

    //-----------------------------------------------------------------------
    // (Re)build the TTD toolbar. Always rebuilds from scratch (delete + create) so
    // it survives debugger-desktop resets and never gets stuck hidden. Called at
    // plugin load and again on session start (when the native debug-movement
    // actions exist, so they attach too).
    void Plugin::show_actions()
    {
        delete_toolbar(TTD_TOOLBAR);
        create_toolbar(TTD_TOOLBAR, "TTD");
        // Live position readout, then all forward buttons, then all backward
        // buttons, then the TTD extras.
        attach_action_to_toolbar(TTD_TOOLBAR, actions::POS_LABEL);
        // --- forward ---
        attach_action_to_toolbar(TTD_TOOLBAR, "ProcessStart");           // Continue
        attach_action_to_toolbar(TTD_TOOLBAR, "ThreadStepInto");         // Step into
        attach_action_to_toolbar(TTD_TOOLBAR, "ThreadStepOver");         // Step over
        attach_action_to_toolbar(TTD_TOOLBAR, "ThreadRunUntilReturn");   // Run until return
        attach_action_to_toolbar(TTD_TOOLBAR, "ThreadRunToCursor");      // Run to cursor
        // --- backward ---
        attach_action_to_toolbar(TTD_TOOLBAR, actions::RUN_BACK);        // Continue backwards
        attach_action_to_toolbar(TTD_TOOLBAR, "ThreadStepIntoBackwards");
        attach_action_to_toolbar(TTD_TOOLBAR, "ThreadStepOverBackwards");
        attach_action_to_toolbar(TTD_TOOLBAR, actions::STEP_OUT_BACK);   // Step out backwards
        attach_action_to_toolbar(TTD_TOOLBAR, "ThreadRunToCursorBackwards");
        // --- TTD extras ---
        attach_action_to_toolbar(TTD_TOOLBAR, actions::TIMELINE);
        attach_action_to_toolbar(TTD_TOOLBAR, actions::GOTO_POS);
        attach_action_to_toolbar(TTD_TOOLBAR, actions::TRACE_PAT);
        attach_action_to_toolbar(TTD_TOOLBAR, actions::OPEN_EVENTS);

        reskin_actions();
        update_position_label();
    }

    //-----------------------------------------------------------------------
    // The toolbar is persistent now (always shown), so this is a no-op; kept as a
    // hook the TraceManager calls on session teardown.
    void Plugin::hide_actions()
    {
    }

    //-----------------------------------------------------------------------
    // Refresh the text on the toolbar's position button from the live cursor.
    void Plugin::update_position_label()
    {
        qstring label;
        if ( m_mgr.is_active() )
        {
            TTD::Replay::Position p = m_mgr.current_position();
            label.sprnt("Position %llX:%llX", (uint64_t)p.Sequence, (uint64_t)p.Steps);
        }
        else
        {
            label = "Position: XX:XX";
        }
        update_action_label(actions::POS_LABEL, label.c_str());
    }

    //=======================================================================
    // HT_DBG: resolve export symbols when a module's segment becomes available.
    //=======================================================================
    ssize_t idaapi DbgEventListener::on_event(ssize_t code, va_list va)
    {
        if ( p == nullptr || ::dbg != &p->debugger() )
            return 0;

        switch ( code )
        {
            case dbg_process_start:
            case dbg_library_load:
            {
                const debug_event_t *ev = va_arg(va, const debug_event_t *);
                if ( ev != nullptr )
                {
                    const modinfo_t &mi = ev->modinfo();
                    p->manager().resolve_symbols((ea_t)mi.base, p->manager().is64());
                    p->manager().load_module_pdb((ea_t)mi.base);  // silent PDB symbols
                }
                if ( code == dbg_process_start )
                    p->show_actions();   // (re)build the toolbar inside the now-active debugger desktop
                p->update_position_label();
                break;
            }
            case dbg_suspend_process:
                // Fires after every stop (step/breakpoint/goto), once memory is
                // valid for the new position: name newly-revealed module exports,
                // disassemble around RIP, and refresh the toolbar readout.
                p->manager().on_suspended();
                p->update_position_label();
                // on_suspended() invalidates debugger memory, which makes IDA
                // rebuild the debug toolbars and reset our action icons — reapply.
                p->reskin_actions();
                // Exports were just (re)named; refresh the call stack so frames
                // show names rather than raw VAs.
                refresh_call_stack();
                break;
            default:
                break;
        }
        return 0;
    }

    //=======================================================================
    // HT_UI: add "Trace this function" to the disassembly context menu.
    //=======================================================================
    ssize_t idaapi UiEventListener::on_event(ssize_t code, va_list va)
    {
        if ( p == nullptr )
            return 0;

        // Only augment menus while our debugger backend is the active one.
        if ( code == ui_finish_populating_widget_popup && ::dbg == &p->debugger() )
        {
            TWidget    *widget = va_arg(va, TWidget *);
            TPopupMenu *popup  = va_arg(va, TPopupMenu *);
            // (action_activation_ctx_t* ctx follows; not needed here)
            if ( widget != nullptr && get_widget_type(widget) == BWN_DISASM )
                attach_action_to_popup(widget, popup, actions::TRACE_FUNC, "TTD/");
        }
        return 0;
    }

    //=======================================================================
    // HT_IDB: names changed (e.g. a PDB download finished and IDA applied
    // symbols) — refresh the call stack so frames pick up the new names.
    //=======================================================================
    ssize_t idaapi IdbEventListener::on_event(ssize_t code, va_list)
    {
        if ( p == nullptr || !p->manager().is_active() )
            return 0;
        if ( code == idb_event::renamed )
            refresh_call_stack();   // just flags for refresh; rename storms coalesce
        return 0;
    }

    //-----------------------------------------------------------------------
    // HT_IDD dispatch: translate debugger notifications into TraceManager calls.
    //-----------------------------------------------------------------------
    ssize_t idaapi Plugin::on_event(ssize_t code, va_list va)
    {
        // Only react when our debugger is the active one.
        if ( ::dbg != &m_debugger )
            return 0;

        switch ( code )
        {
            case debugger_t::ev_init_debugger:
            {
                va_arg(va, const char *);   // hostname
                va_arg(va, int);            // port
                va_arg(va, const char *);   // password
                va_arg(va, qstring *);      // errbuf
                return m_mgr.on_init();
            }

            case debugger_t::ev_term_debugger:
                return m_mgr.on_term();

            case debugger_t::ev_get_processes:
            {
                procinfo_vec_t *procs = va_arg(va, procinfo_vec_t *);
                va_arg(va, qstring *);
                return m_mgr.on_get_processes(procs);
            }

            case debugger_t::ev_get_debapp_attrs:
            {
                debapp_attrs_t *attrs = va_arg(va, debapp_attrs_t *);
                return m_mgr.on_get_debapp_attrs(attrs);
            }

            case debugger_t::ev_start_process:
            {
                const char *path = va_arg(va, const char *);
                va_arg(va, const char *);                 // args
                va_arg(va, const char *);                 // startdir
                va_arg(va, uint32);                       // dbg_proc_flags
                const char *input_path = va_arg(va, const char *);
                va_arg(va, uint32);                       // input_file_crc32
                qstring *errbuf = va_arg(va, qstring *);
                return m_mgr.on_start_process(path, input_path, errbuf);
            }

            case debugger_t::ev_rebase_if_required_to:
            {
                ea_t new_base = va_arg(va, ea_t);
                return m_mgr.on_rebase_if_required_to(new_base);
            }

            case debugger_t::ev_exit_process:
            {
                va_arg(va, qstring *);
                return m_mgr.on_exit_process();
            }

            case debugger_t::ev_get_debug_event:
            {
                gdecode_t      *gcode = va_arg(va, gdecode_t *);
                debug_event_t  *event = va_arg(va, debug_event_t *);
                int             tmo   = va_arg(va, int);
                return m_mgr.on_get_debug_event(gcode, event, tmo);
            }

            case debugger_t::ev_resume:
            {
                debug_event_t *event = va_arg(va, debug_event_t *);
                return m_mgr.on_resume(event);
            }

            case debugger_t::ev_set_backwards:
            {
                bool backwards = va_argi(va, bool);
                return m_mgr.on_set_backwards(backwards);
            }

            case debugger_t::ev_set_resume_mode:
            {
                thid_t        tid    = va_argi(va, thid_t);
                resume_mode_t resmod = va_argi(va, resume_mode_t);
                return m_mgr.on_set_resume_mode(tid, resmod);
            }

            case debugger_t::ev_read_registers:
            {
                thid_t    tid     = va_argi(va, thid_t);
                int       clsmask = va_arg(va, int);
                regval_t *values  = va_arg(va, regval_t *);
                va_arg(va, qstring *);
                return m_mgr.on_read_registers(tid, clsmask, values);
            }

            case debugger_t::ev_get_memory_info:
            {
                meminfo_vec_t *ranges = va_arg(va, meminfo_vec_t *);
                va_arg(va, qstring *);
                return m_mgr.on_get_memory_info(ranges);
            }

            case debugger_t::ev_read_memory:
            {
                size_t *nbytes = va_arg(va, size_t *);
                ea_t    ea     = va_arg(va, ea_t);
                void   *buffer = va_arg(va, void *);
                size_t  size   = va_arg(va, size_t);
                va_arg(va, qstring *);
                return m_mgr.on_read_memory(nbytes, ea, buffer, size);
            }

            case debugger_t::ev_update_bpts:
            {
                int               *nbpts = va_arg(va, int *);
                update_bpt_info_t *bpts  = va_arg(va, update_bpt_info_t *);
                int                nadd  = va_arg(va, int);
                int                ndel  = va_arg(va, int);
                va_arg(va, qstring *);
                return m_mgr.on_update_bpts(nbpts, bpts, nadd, ndel);
            }

            default:
                break;
        }
        return 0;
    }
}

//===========================================================================
// Plugin entry point
//===========================================================================
static plugmod_t *idaapi init()
{
    auto *p = new idattd::Plugin();
    dbg = &p->debugger();      // register ourselves as the (a) debugger backend
    return p;
}

plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,
    PLUGIN_DBG | PLUGIN_HIDE | PLUGIN_MULTI,
    init,
    nullptr,
    nullptr,
    "Time Travel Debugger (TTD) trace replayer",
    "Loads Microsoft TTD .run traces and lets you navigate them in IDA.",
    "TTD trace replayer",
    nullptr
};
