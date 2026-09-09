#include "plugin.h"
#include "trace_link.h"
#include "registers.h"

// Embedded Microsoft codicon debugger glyphs (SVG) for the debug-movement
// actions, including the "continue backwards" action IDA has no native icon for.
#include "icons.hh"

namespace idattd
{
    static const char *TTD_TOOLBAR = "TTDToolBar";

    // IDA's native debug-movement actions that we re-skin with codicon glyphs
    // while a trace is loaded. Order must match Plugin::m_nativeSaved and the
    // icon table in reskin_actions().
    static const char *const NATIVE_MOVEMENT_ACTIONS[] =
    {
        "ProcessStart",             // Continue
        "ThreadStepInto",
        "ThreadStepOver",
        "ThreadRunUntilReturn",     // Step out
        "ThreadStepIntoBackwards",
        "ThreadStepOverBackwards",
    };

    // The top-level TTD menu, alongside File / Edit / Jump / ...
    //
    // It has to be CREATED. attach_action_to_menu() resolves its path against
    // menus that already exist and uses it purely to position the new item, so
    // attaching to "TTD/..." without create_menu() first silently did nothing --
    // which is why there was no TTD menu before.
    // Name and label are both "TTD" on purpose: menu paths are resolved by menu
    // NAME, so keeping the two identical means "TTD/" refers to this menu however
    // the path is interpreted. (The toolbar is a separate namespace, "TTDToolBar".)
    static const char *TTD_MENU      = "TTD";
    static const char *TTD_MENU_PATH = "TTD/";      // path items attach under

    // Items in menu order, grouped: navigation, bookmarks, movement, call
    // tracing, coverage. 'sep' starts a new group with a separator above it.
    static const struct { const char *action; bool sep; } TTD_MENU_ITEMS[] =
    {
        { actions::TIMELINE,        false },
        { actions::GOTO_POS,        false },
        { actions::ADD_BOOKMARK,    true  },
        { actions::BOOKMARKS,       false },
        { actions::RUN_BACK,        true  },
        { actions::STEP_OUT_BACK,   false },
        { actions::RUN_TO_CUR_FWD,  false },
        { actions::RUN_TO_CUR_BACK, false },
        { actions::ANALYZE_FUNC,    true  },
        { actions::TRACE_FUNC,      false },
        { actions::TRACE_PAT,       false },
        { actions::OPEN_EVENTS,     false },
        { actions::OPEN_TRACED,     false },
        { actions::RUN_TRACE,       false },
        { actions::COVERAGE,        true  },
        { actions::COVERAGE_CLR,    false },
        { actions::COVERAGE_AUTO,   false },
        { actions::MEM_SEARCH,      true  },
        { actions::MEM_MAP,         false },
        { actions::MEM_MAP_CLR,     false },
        { actions::INDIRECT,        false },
        { actions::INDIRECT_CLR,    false },
    };

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
        m_attachTrace.p = this;

        // Icons are loaded once for the lifetime of the plugin (they are freed in
        // the destructor); the ACTIONS themselves are only registered while a
        // trace is loaded, so the TTD shortcuts and toolbar do not exist until
        // then -- see show_actions()/hide_actions().
        load_icons();
        // Pseudocode coverage highlighting, if this install has a decompiler.
        // Everything about it is optional: without Hex-Rays the plugin behaves
        // exactly as it did before.
        m_haveDecompiler = init_decompiler();
        hook_event_listener(HT_IDD, this);
        hook_event_listener(HT_DBG, &m_dbgEvents);
        hook_event_listener(HT_UI,  &m_uiEvents);
        hook_event_listener(HT_IDB, &m_idbEvents);
    }

    //-----------------------------------------------------------------------
    Plugin::~Plugin()
    {
        if ( m_refocusTimer != nullptr )
        {
            unregister_timer(m_refocusTimer);
            m_refocusTimer = nullptr;
        }
        if ( m_autoCoverTimer != nullptr )
        {
            unregister_timer(m_autoCoverTimer);
            m_autoCoverTimer = nullptr;
        }
        if ( m_attachTimer != nullptr )
        {
            unregister_timer(m_attachTimer);
            m_attachTimer = nullptr;
        }
        term_decompiler();
        unhook_event_listener(HT_IDB, &m_idbEvents);
        unhook_event_listener(HT_UI,  &m_uiEvents);
        unhook_event_listener(HT_DBG, &m_dbgEvents);
        unhook_event_listener(HT_IDD, this);
        // init() pointed IDA's global 'dbg' at m_debugger, which is a member of
        // this object. Leaving it set here would leave the kernel holding a
        // pointer into freed memory (every listener that guarded on it is already
        // unhooked, so nothing else would catch the dereference).
        if ( ::dbg == &m_debugger )
            ::dbg = nullptr;
        hide_actions();     // toolbar + actions, if a session was still open
        if ( m_attachRegistered )
        {
            detach_action_from_menu("Debugger/", actions::ATTACH_TRACE);
            unregister_action(actions::ATTACH_TRACE);
            m_attachRegistered = false;
        }
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
        if ( trace_link_present() && get_process_state() == DSTATE_NOTASK )
        {
            start_trace_session();
            return true;
        }
        info("ida-ttd: open a .run trace directly, or select 'TTD trace replayer' "
             "under Debugger > Switch debugger and start with the trace file as "
             "the application.");
        return true;
    }

    //-----------------------------------------------------------------------
    // Start replaying the recording this database was created from.
    //
    // No prompting here: this is the body of the Debugger menu action, where the
    // user has already said what they want. offer_trace_session() is the one that
    // asks.
    void Plugin::start_trace_session()
    {
        TraceLink link;
        if ( !trace_link_read(&link) )
        {
            warning("This database was not created from a TTD trace, so there is "
                    "nothing to replay.\n\nUse Debugger > Switch debugger to attach "
                    "a trace to it instead.");
            return;
        }
        if ( get_process_state() != DSTATE_NOTASK )
        {
            warning("A debugging session is already running.");
            return;
        }

        // The recording may have moved or been renamed since the database was
        // made. That is a normal thing to happen to a file and not a reason to
        // fail: ask where it went and remember the answer.
        if ( !qfileexist(link.trace_path.c_str()) )
        {
            qstring prompt;
            prompt.sprnt("Locate the TTD trace for this database (was %s)",
                         link.trace_path.c_str());
            const char *chosen = ask_file(false, link.trace_path.c_str(), "%s", prompt.c_str());
            if ( chosen == nullptr )
                return;
            link.trace_path = chosen;
            trace_link_set_path(chosen);
        }

        if ( !select_trace_debugger(link.trace_path.c_str()) )
            return;
        start_process(link.trace_path.c_str(), "", "");
    }

    //-----------------------------------------------------------------------
    bool Plugin::select_trace_debugger(const char *trace_path, bool quiet)
    {
        // Say where the trace is BEFORE trying to switch, and whether or not
        // the switch works. This is what puts the .run into Debugger > Process
        // options, and it is the part that matters most: IDA's Application file
        // browser filters on "*.exe" and no SDK field controls that filter, so a
        // path that is already filled in is the difference between the feature
        // working and the user hunting for their trace behind a wrong filter.
        if ( trace_path != nullptr && trace_path[0] != '\0' )
            set_process_options(trace_path, "", nullptr, "", "", "", -1);

        if ( ::dbg != &m_debugger )
        {
            // What load_debugger() matches on is not documented, and the one
            // example in the SDK is ambiguous: the Windows debugger calls
            // load_debugger("win32_stub") while its debugger_t::name is "win32"
            // and its plugin's wanted_name is "Remote Windows debugger" -- so
            // "win32_stub" is its plugin FILE name. Rather than bet on one
            // reading, try each candidate and say which one worked, because a
            // wrong answer here is a dead end for the user.
            const qstring self = plugin_module_name();
            qstring selfdll = self;
            if ( !selfdll.empty() )
                selfdll.append(".dll");
            const char *candidates[] =
            {
                self.c_str(),                   // plugin file name, e.g. "ida-ttd"
                selfdll.c_str(),                // ...with the extension
                m_debugger.name,                // debugger_t::name, "ttd"
                "TTD trace replayer",           // the plugin's wanted_name
            };
            bool ok = false;
            for ( const char *c : candidates )
            {
                if ( c == nullptr || *c == '\0' )
                    continue;
                if ( load_debugger(c, false) )
                {
                    msg("[ida-ttd] selected the TTD trace replayer (as '%s').\n", c);
                    ok = true;
                    break;
                }
            }
            if ( !ok )
            {
                // Assigning ::dbg by hand is NOT a fallback. init() may do it
                // because IDA is still building its debugger list then; doing it
                // afterwards leaves the kernel's debugger state pointing at a
                // backend it never initialised, and starting a process from
                // there took IDA down. Say what happened and stop.
                if ( !m_switchReported )
                {
                    m_switchReported = true;
                    msg("[ida-ttd] IDA would not switch debuggers for us (tried "
                        "'%s', '%s' and '%s'). Choose 'TTD trace replayer' under "
                        "Debugger > Switch debugger; the trace path is already "
                        "filled in, so starting the process is all that is "
                        "left.\n",
                        self.c_str(),
                        m_debugger.name != nullptr ? m_debugger.name : "",
                        "TTD trace replayer");
                }
                if ( !quiet )
                {
                    warning("Could not select the TTD trace replayer as the "
                            "debugger.\n\n"
                            "Use Debugger > Switch debugger to choose 'TTD trace "
                            "replayer'. The trace path is already filled in, so "
                            "starting the process is all that is left.");
                }
                return false;
            }
        }
        return true;
    }

    //-----------------------------------------------------------------------
    int idaapi Plugin::attach_cb(void *ud)
    {
        Plugin *p = static_cast<Plugin *>(ud);
        // ui_ready_to_run fires while a freshly created database is still being
        // auto-analysed. Starting a debugger session there rebases the program
        // and lays debugger segments over the loader's while the analysis queue
        // is walking them, which crashed IDA outright. Wait it out.
        if ( !auto_is_ok() )
            return 250;
        p->m_attachTimer = nullptr;     // IDA frees the timer on -1
        p->offer_trace_session();
        return -1;
    }

    //-----------------------------------------------------------------------
    void Plugin::schedule_trace_offer()
    {
        if ( m_attachTimer == nullptr )
            m_attachTimer = register_timer(250, attach_cb, this);
    }

    //-----------------------------------------------------------------------
    void Plugin::offer_trace_session()
    {
        if ( !trace_link_present() || get_process_state() != DSTATE_NOTASK )
            return;

        TraceLink link;
        if ( !trace_link_read(&link) )
            return;

        // The action goes on the Debugger menu rather than the TTD menu: the TTD
        // menu only exists while a session is running, and this is the thing that
        // starts one. Registered here rather than in the constructor because it
        // is only meaningful for a database that came from a recording.
        if ( !m_attachRegistered )
        {
            if ( register_action(ACTION_DESC_LITERAL_PLUGMOD(
                     actions::ATTACH_TRACE, "Start the TTD replay for this database",
                     &m_attachTrace, this, nullptr, nullptr, -1)) )
            {
                attach_action_to_menu("Debugger/", actions::ATTACH_TRACE, SETMENU_APP);
                m_attachRegistered = true;
            }
        }

        // Do this before asking, not after: whatever the answer, the database
        // should already be pointed at the right backend with the right trace
        // path, so Debugger > Process options and Start process just work.
        if ( qfileexist(link.trace_path.c_str()) )
            select_trace_debugger(link.trace_path.c_str(), true);

        int pref = trace_link_autostart();
        if ( pref == TL_NO )
            return;                 // asked before, told no; the menu item remains
        if ( pref == TL_ASK )
        {
            int r = ask_yn(ASKBTN_YES,
                           "This database was created from a TTD trace:\n\n  %s\n\n"
                           "Start replaying it now?\n\n"
                           "(You can start it later from Debugger > Start the TTD "
                           "replay for this database.)",
                           link.trace_path.c_str());
            if ( r == ASKBTN_CANCEL )
                return;             // undecided: ask again next time
            trace_link_set_autostart(r == ASKBTN_YES ? TL_YES : TL_NO);
            if ( r != ASKBTN_YES )
                return;
        }
        start_trace_session();
    }

    //-----------------------------------------------------------------------
    // Register every TTD action (and therefore every TTD shortcut). Called from
    // show_actions() when a trace becomes active; the matching unregister happens
    // in hide_actions() when the trace is unloaded.
    void Plugin::register_actions()
    {
        if ( m_actionsRegistered )
            return;

        // Wire handler back-pointers.
        m_runBack.mgr     = &m_mgr;
        m_stepOutBack.mgr = &m_mgr;
        m_runToCurBack.mgr = &m_mgr;
        m_runToCurFwd.mgr = &m_mgr;
        m_timeline.mgr    = &m_mgr;
        m_posLabel.mgr    = &m_mgr;
        m_goto.mgr        = &m_mgr;
        m_analyzeFunc.mgr = &m_mgr;

        m_traceFunc.mgr  = &m_mgr;  m_traceFunc.tracer  = &m_tracer;
        m_tracePat.mgr   = &m_mgr;  m_tracePat.tracer   = &m_tracer;
        m_openTraced.mgr = &m_mgr;  m_openTraced.tracer = &m_tracer;
        m_openEvents.mgr = &m_mgr;  m_openEvents.tracer = &m_tracer;
        m_runTrace.mgr   = &m_mgr;  m_runTrace.tracer   = &m_tracer;

        m_addBookmark.mgr   = &m_mgr;  m_addBookmark.store   = &m_bookmarks;
        m_bookmarksView.mgr = &m_mgr;  m_bookmarksView.store = &m_bookmarks;
        m_coverage.mgr      = &m_mgr;
        m_memSearch.mgr     = &m_mgr;
        m_memMap.mgr        = &m_mgr;
        m_memMapClear.mgr   = &m_mgr;
        m_indirect.mgr      = &m_mgr;

        register_action(ACTION_DESC_LITERAL_PLUGMOD(
            actions::RUN_BACK, "Continue backwards", &m_runBack, this,
            nullptr, "Continue backwards: run backward to the previous breakpoint or the start of the trace", m_icoRevContinue));
        register_action(ACTION_DESC_LITERAL_PLUGMOD(
            actions::STEP_OUT_BACK, "Step out backwards", &m_stepOutBack, this,
            nullptr, "Step out backwards: run backward out of the current function to the call that entered it", m_icoStepOutBack));
        register_action(ACTION_DESC_LITERAL_PLUGMOD(
            actions::RUN_TO_CUR_BACK, "Run to cursor backwards", &m_runToCurBack, this,
            nullptr, "Run to cursor backwards: run backward until execution reaches the cursor address", m_icoRunToCurBack));
        register_action(ACTION_DESC_LITERAL_PLUGMOD(
            actions::RUN_TO_CUR_FWD, "Run to cursor", &m_runToCurFwd, this,
            nullptr, "Run to cursor: run forward until execution reaches the cursor address", m_icoRunToCur));
        // Live trace-position readout (text-only toolbar button; click copies).
        register_action(ACTION_DESC_LITERAL_PLUGMOD(
            actions::POS_LABEL, "TTD position", &m_posLabel, this,
            nullptr, "Current TTD position (Sequence:Steps) -- click to copy it to the clipboard", -1));
        register_action(ACTION_DESC_LITERAL_PLUGMOD(
            actions::ANALYZE_FUNC, "Analyze whole function", &m_analyzeFunc, this,
            "Ctrl+Shift+A", "Analyze whole function: walk the trace backward to find the enclosing "
            "function's entry and define it (runs behind a cancellable wait box)", -1));
        register_action(ACTION_DESC_LITERAL_PLUGMOD(
            actions::TRACE_FUNC, "Find all calls to this function", &m_traceFunc, this,
            "Ctrl+Shift+C", "Find all calls to this function: sweep the whole trace and list every call with its arguments and return value", -1));
        register_action(ACTION_DESC_LITERAL_PLUGMOD(
            actions::TRACE_PAT, "Find calls by name/pattern...", &m_tracePat, this,
            "Ctrl+Shift+F", "Find calls by name/pattern: trace every function matching a wildcard like 'kernel32!Virtual*' in one sweep", m_icoFuncSearch));
        register_action(ACTION_DESC_LITERAL_PLUGMOD(
            actions::OPEN_EVENTS, "Trace events...", &m_openEvents, this,
            nullptr, "Trace events: open the recorded calls (arguments and return values)", -1));
        register_action(ACTION_DESC_LITERAL_PLUGMOD(
            actions::OPEN_TRACED, "Traced functions...", &m_openTraced, this,
            nullptr, "Traced functions: manage the list of functions selected for call tracing", -1));
        register_action(ACTION_DESC_LITERAL_PLUGMOD(
            actions::RUN_TRACE, "Re-run trace", &m_runTrace, this,
            nullptr, "Re-run trace: re-sweep the trace for all currently traced functions", -1));
        register_action(ACTION_DESC_LITERAL_PLUGMOD(
            actions::TIMELINE, "Timeline...", &m_timeline, this,
            "Ctrl+Shift+T", "Timeline: open the TTD trace timeline of notable positions", m_icoTimeline));
        register_action(ACTION_DESC_LITERAL_PLUGMOD(
            actions::GOTO_POS, "Go to position...", &m_goto, this,
            "Ctrl+Shift+G", "Go to position: jump to a Sequence:Steps trace position", m_icoGoto));
        register_action(ACTION_DESC_LITERAL_PLUGMOD(
            actions::ADD_BOOKMARK, "Bookmark this position...", &m_addBookmark, this,
            "Ctrl+Shift+B", "Bookmark this position: save the current trace position, "
            "with a name and a note, in the database", -1));
        register_action(ACTION_DESC_LITERAL_PLUGMOD(
            actions::BOOKMARKS, "Bookmarks...", &m_bookmarksView, this,
            nullptr, "Bookmarks: the saved trace positions for this database", -1));
        register_action(ACTION_DESC_LITERAL_PLUGMOD(
            actions::COVERAGE, "Highlight executed code...", &m_coverage, this,
            nullptr, "Highlight executed code: replay the recording and colour every "
            "instruction in the chosen scope that actually ran", -1));
        register_action(ACTION_DESC_LITERAL_PLUGMOD(
            actions::COVERAGE_CLR, "Clear execution highlight", &m_coverageClear, this,
            nullptr, "Clear execution highlight: remove the coverage colour from the "
            "whole database", -1));
        register_action(ACTION_DESC_LITERAL_PLUGMOD(
            actions::COVERAGE_AUTO, "Highlight functions automatically", &m_coverageAuto, this,
            nullptr, "Highlight functions automatically: measure and colour each "
            "function the first time you stop in it", -1));
        register_action(ACTION_DESC_LITERAL_PLUGMOD(
            actions::MEM_SEARCH, "Find memory accesses...", &m_memSearch, this,
            "Ctrl+Shift+M", "Find memory accesses: every read, write or execute of "
            "an address anywhere in the recording", -1));
        register_action(ACTION_DESC_LITERAL_PLUGMOD(
            actions::MEM_MAP, "Memory map", &m_memMap, this,
            nullptr, "Memory map: every allocation, protection change and free the "
            "recording made, with each live region as a segment", -1));
        register_action(ACTION_DESC_LITERAL_PLUGMOD(
            actions::MEM_MAP_CLR, "Clear memory map", &m_memMapClear, this,
            nullptr, "Clear memory map: forget the reconstructed regions and go "
            "back to one range over user space", -1));
        register_action(ACTION_DESC_LITERAL_PLUGMOD(
            actions::INDIRECT, "Resolve indirect calls...", &m_indirect, this,
            nullptr, "Resolve indirect calls: record where each one actually went, "
            "as a comment and a cross-reference", -1));
        register_action(ACTION_DESC_LITERAL_PLUGMOD(
            actions::INDIRECT_CLR, "Clear resolved indirect calls", &m_indirectClear, this,
            nullptr, "Clear resolved indirect calls: remove the comments and "
            "cross-references a previous run added", -1));
        // Checkable menu entry, ticked from the database's own setting.
        update_action_checkable(actions::COVERAGE_AUTO, true);
        update_action_checked(actions::COVERAGE_AUTO, coverage_auto_enabled());

        // Top-level TTD menu, created before anything is attached to it.
        //
        // The third argument is deliberately absent. create_menu() first tries to
        // resolve it as the NAME of a menu already in the menu bar and, failing
        // that, as a path to a menu ITEM -- so passing "Debugger" did not place
        // TTD next to the Debugger menu, it nested TTD inside it, and "TTD/" then
        // no longer resolved at the top level so every item went nowhere. With no
        // position given, IDA appends the menu to the menu bar, which is where it
        // belongs.
        create_menu(TTD_MENU, "TTD");
        int attached = 0;
        for ( const auto &mi : TTD_MENU_ITEMS )
            if ( attach_action_to_menu(TTD_MENU_PATH, mi.action,
                                       SETMENU_APP | (mi.sep ? SETMENU_ENSURE_SEP : 0)) )
                attached++;
        if ( attached != qnumber(TTD_MENU_ITEMS) )
            msg("[ida-ttd] only %d of %d TTD menu entries could be attached.\n",
                attached, (int)qnumber(TTD_MENU_ITEMS));

        m_actionsRegistered = true;
    }

    //-----------------------------------------------------------------------
    // Drop every TTD action, which also kills their shortcuts and removes them
    // from the menu/toolbars: nothing TTD-specific responds outside a session.
    void Plugin::unregister_actions()
    {
        if ( !m_actionsRegistered )
            return;

        // Drop the whole menu rather than detaching item by item: unregistering
        // the actions alone would leave an empty TTD menu behind in the menu bar.
        delete_menu(TTD_MENU);

        const char *names[] = {
            actions::RUN_BACK, actions::STEP_OUT_BACK, actions::RUN_TO_CUR_BACK, actions::RUN_TO_CUR_FWD, actions::POS_LABEL, actions::TRACE_FUNC,
            actions::TRACE_PAT, actions::ANALYZE_FUNC, actions::OPEN_EVENTS, actions::OPEN_TRACED,
            actions::RUN_TRACE, actions::TIMELINE, actions::GOTO_POS,
            actions::ADD_BOOKMARK, actions::BOOKMARKS,
            actions::COVERAGE, actions::COVERAGE_CLR, actions::COVERAGE_AUTO,
            actions::MEM_SEARCH, actions::MEM_MAP, actions::MEM_MAP_CLR,
            actions::INDIRECT, actions::INDIRECT_CLR,
        };
        for ( const char *n : names )
            unregister_action(n);

        // The next session may be over a different database, so neither the
        // cached bookmark list nor the "user cancelled this sweep" set may
        // carry across.
        m_bookmarks.invalidate();
        m_autoCoverDeclined.clear();
        m_autoCoverFunc = BADADDR;
        m_actionsRegistered = false;
    }

    //-----------------------------------------------------------------------
    // Re-skin the native debug-movement actions with the codicon glyphs. IDA
    // registers some of these actions lazily (e.g. ThreadRunToCursorBackwards may
    // not exist at the first show) and ALSO resets their icons whenever it rebuilds
    // the debugger toolbars (e.g. after a memory-cache invalidation on a TTD jump),
    // so this must be reapplied repeatedly -- at session start AND on every stop.
    // Does nothing without an active trace: the override is global, so IDA's other
    // debuggers must keep their own icons.
    void Plugin::reskin_actions()
    {
        if ( !m_actionsRegistered )
            return;

        const int ours[] = {
            m_icoContinue, m_icoStepInto, m_icoStepOver,
            m_icoStepOut, m_icoStepIntoBack, m_icoStepBack,
        };
        CASSERT(qnumber(ours) == qnumber(NATIVE_MOVEMENT_ACTIONS));

        for ( size_t i = 0; i < qnumber(ours); i++ )
        {
            const char *name = NATIVE_MOVEMENT_ACTIONS[i];
            // Remember IDA's own icon the first time we actually find the action.
            // It cannot be captured in one shot: several of these are registered
            // lazily, and once we have overridden one, querying it again would
            // just return OUR icon.
            if ( !m_nativeSavedOk[i] && get_action_icon(name, &m_nativeSaved[i]) )
                m_nativeSavedOk[i] = true;
            update_action_icon(name, ours[i]);
        }
        // (Run to cursor forward/backward are our own custom actions; their icons
        // are set at registration, so they aren't reskinned here.)
    }

    //-----------------------------------------------------------------------
    // Put IDA's original icons back on the native movement actions.
    void Plugin::restore_native_icons()
    {
        for ( size_t i = 0; i < qnumber(NATIVE_MOVEMENT_ACTIONS); i++ )
        {
            if ( !m_nativeSavedOk[i] )
                continue;
            update_action_icon(NATIVE_MOVEMENT_ACTIONS[i], m_nativeSaved[i]);
            m_nativeSavedOk[i] = false;
            m_nativeSaved[i]   = -1;
        }
    }

    //-----------------------------------------------------------------------
    // Register the TTD actions (if they are not already) and (re)build the TTD
    // toolbar. Always rebuilds the toolbar from scratch (delete + create) so it
    // survives debugger-desktop resets and never gets stuck hidden. Called when a
    // trace is loaded and again on process start (the native debug-movement
    // actions register lazily, so the later call is what attaches them).
    void Plugin::show_actions()
    {
        register_actions();
        try_hook_decompiler();
        suspend_source_debugging();

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
        attach_action_to_toolbar(TTD_TOOLBAR, actions::RUN_TO_CUR_FWD);  // Run to cursor (custom)
        // --- backward ---
        attach_action_to_toolbar(TTD_TOOLBAR, actions::RUN_BACK);        // Continue backwards
        attach_action_to_toolbar(TTD_TOOLBAR, "ThreadStepIntoBackwards");
        attach_action_to_toolbar(TTD_TOOLBAR, "ThreadStepOverBackwards");
        attach_action_to_toolbar(TTD_TOOLBAR, actions::STEP_OUT_BACK);   // Step out backwards
        attach_action_to_toolbar(TTD_TOOLBAR, actions::RUN_TO_CUR_BACK); // Run to cursor backwards (custom)
        // --- TTD extras ---
        attach_action_to_toolbar(TTD_TOOLBAR, actions::TIMELINE);
        attach_action_to_toolbar(TTD_TOOLBAR, actions::GOTO_POS);
        attach_action_to_toolbar(TTD_TOOLBAR, actions::TRACE_PAT);
        attach_action_to_toolbar(TTD_TOOLBAR, actions::OPEN_EVENTS);
        attach_action_to_toolbar(TTD_TOOLBAR, actions::ADD_BOOKMARK);
        attach_action_to_toolbar(TTD_TOOLBAR, actions::BOOKMARKS);

        reskin_actions();
        update_position_label();
    }

    //-----------------------------------------------------------------------
    // The trace is gone: drop the toolbar, hand IDA's movement icons back, and
    // unregister every TTD action so its shortcut stops responding. Safe to call
    // more than once (both the process-exit notification and ev_term_debugger go
    // through here).
    void Plugin::hide_actions()
    {
        // Before anything else: a pseudocode view of code the recording
        // allocated at runtime cannot survive the session, and IDA would
        // save it in the desktop and restore it broken.
        close_volatile_pseudocode_views();
        restore_source_debugging();
        delete_toolbar(TTD_TOOLBAR);
        restore_native_icons();
        unregister_actions();
    }

    //-----------------------------------------------------------------------
    // Refresh the text on the toolbar's position button from the live cursor.
    void Plugin::update_position_label()
    {
        if ( !m_actionsRegistered )
            return;             // no session: the readout action does not exist
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

    //-----------------------------------------------------------------------
    // Remember which code view the user is in. The preference only changes on a
    // genuine user focus change; while m_ignoreWidgetChanges is set (the re-focus
    // window around a debugger stop) the debugger's forced switch to disassembly is
    // recorded but does NOT flip the preference.
    void Plugin::track_widget(TWidget *cur)
    {
        if ( cur == nullptr )
            return;
        int t = get_widget_type(cur);
        if ( t == BWN_PSEUDOCODE )
        {
            m_pseudoWidget = cur;
            if ( !m_ignoreWidgetChanges )
                m_userPrefersDecomp = true;
        }
        else if ( t == BWN_DISASM )
        {
            if ( !m_ignoreWidgetChanges )
                m_userPrefersDecomp = false;
        }
    }

    //-----------------------------------------------------------------------
    void Plugin::widget_closing(TWidget *w)
    {
        if ( w == m_pseudoWidget )
            m_pseudoWidget = nullptr;
    }

    //-----------------------------------------------------------------------
    int idaapi Plugin::refocus_cb(void *ud)
    {
        static_cast<Plugin *>(ud)->do_refocus();
        return -1;  // one-shot: unregister
    }

    void Plugin::do_refocus()
    {
        m_refocusTimer = nullptr;
        if ( m_pseudoWidget != nullptr && m_userPrefersDecomp )
            activate_widget(m_pseudoWidget, true);
        m_ignoreWidgetChanges = false;
    }

    //-----------------------------------------------------------------------
    void Plugin::try_hook_decompiler()
    {
        if ( !m_haveDecompiler )
            m_haveDecompiler = init_decompiler();
    }

    //-----------------------------------------------------------------------
    // Source-info providers are registered by name and there is no API to
    // enumerate them, so the ones that carry line information for native code
    // are named here. A name that is not registered simply yields nullptr.
    static const char *const SRCINFO_PROVIDERS[] = { "PDB", "pdb", "DWARF", "dwarf" };

    void Plugin::suspend_source_debugging()
    {
        for ( const char *n : SRCINFO_PROVIDERS )
        {
            srcinfo_provider_t *sp = get_srcinfo_provider(n);
            // Only ever turn OFF something that is currently on, and remember
            // exactly what we turned off: a provider the user had already
            // disabled must not come back enabled when the session ends.
            if ( sp == nullptr || !sp->is_enabled() )
                continue;
            sp->enable_provider(false);
            m_srcProvidersOff.push_back(n);
            msg("[ida-ttd] source-level debugging via '%s' is off for this session: "
                "it offers to map source paths recorded on the machine that made "
                "the trace. It is restored when the trace closes.\n", n);
        }
    }

    //-----------------------------------------------------------------------
    void Plugin::restore_source_debugging()
    {
        for ( const char *n : m_srcProvidersOff )
        {
            srcinfo_provider_t *sp = get_srcinfo_provider(n);
            if ( sp != nullptr )
                sp->enable_provider(true);
        }
        m_srcProvidersOff.clear();
    }

    //-----------------------------------------------------------------------
    int idaapi Plugin::autocover_cb(void *ud)
    {
        static_cast<Plugin *>(ud)->do_auto_coverage();
        return -1;  // one-shot: unregister
    }

    //-----------------------------------------------------------------------
    // Decide, on a stop, whether the function we are now in should be measured.
    // The work itself is deferred: a sweep pumps the UI behind a wait box, and
    // starting that from inside a debugger notification risks the user driving
    // the debugger again while we are still in it.
    void Plugin::schedule_auto_coverage()
    {
        m_autoCoverFunc = BADADDR;
        if ( !m_actionsRegistered || !m_mgr.is_active() || !coverage_auto_enabled() )
            return;
        ea_t pc = m_mgr.current_pc_ea();
        if ( pc == BADADDR )
            return;
        func_entry_info_t fi;
        if ( !get_func_entry_info(&fi, pc) )
            return;                                  // no function to measure yet
        if ( coverage_function_done(fi.start_ea)
          || m_autoCoverDeclined.find(fi.start_ea) != m_autoCoverDeclined.end() )
            return;                                  // measured, or the user said no
        m_autoCoverFunc = fi.start_ea;
        if ( m_autoCoverTimer == nullptr )
            m_autoCoverTimer = register_timer(10, autocover_cb, this);
    }

    //-----------------------------------------------------------------------
    void Plugin::do_auto_coverage()
    {
        m_autoCoverTimer = nullptr;
        ea_t start = m_autoCoverFunc;
        m_autoCoverFunc = BADADDR;
        if ( start == BADADDR || !m_mgr.is_active() )
            return;
        // Re-read the bounds: the deferred hop gave analysis a chance to change
        // them, and a stale end would measure the wrong span.
        func_entry_info_t fi;
        if ( !get_func_entry_info(&fi, start) || fi.start_ea != start )
            return;
        if ( coverage_function_done(start) )
            return;
        if ( !cover_function(&m_mgr, fi.start_ea, fi.end_ea) )
        {
            // Cancelled, or it could not run. Do not ask again this session --
            // otherwise the next single step inside the same function re-offers
            // the sweep the user just stopped.
            m_autoCoverDeclined.insert(start);
            return;
        }
        refresh_idaview_anyway();
        refresh_pseudocode_views();
    }

    //-----------------------------------------------------------------------
    // Called from the stop handler. If the user was in the decompiler, schedule a
    // deferred re-focus: IDA brings the disassembly to the front as part of its own
    // post-stop handling, so we must re-assert the decompiler AFTER that, from a
    // short timer (the callback runs on the UI thread once IDA has settled).
    void Plugin::keep_decompiler_focused()
    {
        if ( !m_userPrefersDecomp || m_pseudoWidget == nullptr )
            return;
        m_ignoreWidgetChanges = true;          // ignore IDA's forced disasm switch
        if ( m_refocusTimer == nullptr )
            m_refocusTimer = register_timer(10, refocus_cb, this);
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
                // Last chance to pick the decompiler up, for installs where
                // it loads after everything above has already run.
                p->try_hook_decompiler();
                p->update_position_label();
                // Measure the function we landed in, if it has not been measured
                // before and the user has left that switched on. Queued, not run
                // here -- see schedule_auto_coverage().
                p->schedule_auto_coverage();
                // IDA can rebuild the debug toolbars across a stop and reset our
                // action icons -- reapply them (cheap, belt-and-suspenders).
                p->reskin_actions();
                // IDA forces the disassembly view to the front on each stop; if the
                // user was in the decompiler, re-assert it afterward.
                p->keep_decompiler_focused();
                // Exports were just (re)named; refresh the call stack so frames
                // show names rather than raw VAs.
                refresh_call_stack();
                break;
            case dbg_process_exit:
                // The trace session is over (the user terminated it). Drop the
                // toolbar and unregister the TTD actions right away rather than
                // waiting for ev_term_debugger, which only fires when the
                // debugger backend itself is unloaded.
                p->hide_actions();
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

        switch ( code )
        {
            case ui_finish_populating_widget_popup:
            {
                // Only augment menus while our debugger backend is the active one
                // AND a trace is loaded (outside a session the actions do not
                // even exist).
                if ( ::dbg != &p->debugger() || !p->actions_visible() )
                    break;
                TWidget    *widget = va_arg(va, TWidget *);
                TPopupMenu *popup  = va_arg(va, TPopupMenu *);
                // (action_activation_ctx_t* ctx follows; not needed here)
                if ( widget == nullptr )
                    break;
                int wt = get_widget_type(widget);
                if ( wt == BWN_DISASM || wt == BWN_PSEUDOCODE )
                {
                    // Time-travel to the address under the cursor (works in both
                    // the disassembly and the decompiler).
                    attach_action_to_popup(widget, popup, actions::RUN_TO_CUR_FWD, "TTD/");
                    attach_action_to_popup(widget, popup, actions::RUN_TO_CUR_BACK, "TTD/");
                    attach_action_to_popup(widget, popup, actions::ADD_BOOKMARK, "TTD/");
                }
                if ( wt == BWN_DISASM )
                {
                    attach_action_to_popup(widget, popup, actions::TRACE_FUNC, "TTD/");
                    attach_action_to_popup(widget, popup, actions::COVERAGE, "TTD/");
                    attach_action_to_popup(widget, popup, actions::MEM_SEARCH, "TTD/");
                }
                break;
            }
            case ui_ready_to_run:
                // Everything is loaded by now, decompiler included. This is the
                // point the SDK documents for plugins that need the finished UI.
                p->try_hook_decompiler();
                // Starting a debugger session from inside a UI notification is
                // asking for reentrancy, and the prompt is modal. Hand it back to
                // the message loop and do it a turn later.
                if ( trace_link_present() )
                    p->schedule_trace_offer();
                break;
            case ui_current_widget_changed:
            {
                // Track which code view the user is in so we can keep the decompiler
                // focused across debugger stops.
                TWidget *cur = va_arg(va, TWidget *);
                p->track_widget(cur);
                break;
            }
            case ui_widget_invisible:
            {
                TWidget *w = va_arg(va, TWidget *);
                p->widget_closing(w);
                break;
            }
            default:
                break;
        }
        return 0;
    }

    //=======================================================================
    // HT_IDB: names changed (e.g. a PDB download finished and IDA applied
    // symbols) -- refresh the call stack so frames pick up the new names.
    //=======================================================================
    ssize_t idaapi IdbEventListener::on_event(ssize_t code, va_list va)
    {
        if ( p == nullptr || !p->manager().is_active() )
            return 0;
        if ( code == idb_event::renamed )
        {
            ea_t        ea       = va_arg(va, ea_t);
            const char *new_name = va_arg(va, const char *);
            // Debugger views -- the call-stack window in particular -- resolve
            // <name>+offset through the DEBUG-NAME list, NOT plain IDB names. Our
            // exports (set_name) and the PDB plugin's symbols only populate IDB
            // names, so the call stack showed raw addresses. Mirror every applied
            // name into the debug-name list so frames render as <name>+offset.
            if ( new_name != nullptr && new_name[0] != '\0' )
                set_debug_name(ea, new_name);
            // As PDB/export symbols name functions in system modules, mark those
            // functions FUNC_LIB so library code is grouped/de-emphasized (the PDB
            // plugin defines them but does not flag them as library).
            if ( get_func_start(ea) == ea && (get_func_flags(ea) & FUNC_LIB) == 0
              && p->manager().is_library_address(ea) )
            {
                set_func_flag(ea, FUNC_LIB, true);
            }
            refresh_call_stack();   // just flags for refresh; rename storms coalesce
        }
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
                // Re-read the database's bitness here rather than trusting what
                // it was when this object was constructed. The constructor runs
                // at plugin load, and nothing documents whether that is before or
                // after a loader has finished setting up a new database -- but by
                // the time a session is being initialised the answer is settled.
                // Getting it wrong is not cosmetic: it picks the register table.
                configure_debugger(m_debugger, inf_is_64bit());
                m_tracer.set_64bit(inf_is_64bit());
                // The user has just chosen us, possibly by hand because the
                // programmatic switch above did not work. Point the Application
                // field at the recording so they do not have to find it behind
                // IDA's "*.exe" filter.
                {
                    TraceLink link;
                    if ( get_process_state() == DSTATE_NOTASK
                      && trace_link_read(&link)
                      && !link.trace_path.empty() )
                    {
                        set_process_options(link.trace_path.c_str(), "", nullptr,
                                            "", "", "", -1);
                    }
                }
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
