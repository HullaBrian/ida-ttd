// The TTD actions: their icons and table, registration, IDA's re-skinned
// movement actions, the TTD toolbar and its position readout.
#include "plugin/plugin_internal.h"
#include "ui/icons.hh"

namespace idattd
{
    static const char *TTD_TOOLBAR = "TTDToolBar";

    // IDA's movement actions, re-skinned with codicons while a trace is
    // loaded. Order matches Plugin::m_nativeSaved and the first icons.
    static const char *const NATIVE_MOVEMENT_ACTIONS[] =
    {
        "ProcessStart",             // Continue
        "ThreadStepInto",
        "ThreadStepOver",
        "ThreadRunUntilReturn",     // Step out
        "ThreadStepIntoBackwards",
        "ThreadStepOverBackwards",
    };

    // Also how ida_ttd_qt finds the position button.
    static const char POS_LABEL_TOOLTIP[] = "Current trace position; click to copy it";

    void Plugin::load_icons()
    {
        m_icons.fill(-1);
        auto svg = [](const char *s, size_t len) { return load_custom_icon(s, (unsigned)len, "svg"); };
        m_icons[ICO_CONTINUE]        = svg(icon_continue_svg,         sizeof(icon_continue_svg) - 1);
        m_icons[ICO_STEP_INTO]       = svg(icon_step_into_svg,        sizeof(icon_step_into_svg) - 1);
        m_icons[ICO_STEP_OVER]       = svg(icon_step_over_svg,        sizeof(icon_step_over_svg) - 1);
        m_icons[ICO_STEP_OUT]        = svg(icon_step_out_svg,         sizeof(icon_step_out_svg) - 1);
        m_icons[ICO_STEP_INTO_BACK]  = svg(icon_step_into_back_svg,   sizeof(icon_step_into_back_svg) - 1);
        m_icons[ICO_STEP_BACK]       = svg(icon_step_back_svg,        sizeof(icon_step_back_svg) - 1);
        m_icons[ICO_REV_CONTINUE]    = svg(icon_reverse_continue_svg, sizeof(icon_reverse_continue_svg) - 1);
        m_icons[ICO_STEP_OUT_BACK]   = svg(icon_step_out_back_svg,    sizeof(icon_step_out_back_svg) - 1);
        m_icons[ICO_RUN_TO_CUR]      = svg(icon_step_to_cursor_forward_svg,  sizeof(icon_step_to_cursor_forward_svg) - 1);
        m_icons[ICO_RUN_TO_CUR_BACK] = svg(icon_step_to_cursor_backward_svg, sizeof(icon_step_to_cursor_backward_svg) - 1);
        m_icons[ICO_TIMELINE]        = svg(icons_timeline_svg,        sizeof(icons_timeline_svg) - 1);
        m_icons[ICO_GOTO]            = svg(icons_goto_time_svg,       sizeof(icons_goto_time_svg) - 1);
        m_icons[ICO_FUNC_SEARCH]     = svg(icons_function_search_svg, sizeof(icons_function_search_svg) - 1);
        m_icons[ICO_BOOKMARK_ADD]    = svg(icons_bookmark_add_svg,    sizeof(icons_bookmark_add_svg) - 1);
        m_icons[ICO_BOOKMARKS]       = svg(icons_bookmarks_svg,       sizeof(icons_bookmarks_svg) - 1);
        m_icons[ICO_FUNCTION]        = svg(icons_function_svg,        sizeof(icons_function_svg) - 1);
        m_icons[ICO_CALL_TREE]       = svg(icons_call_tree_svg,       sizeof(icons_call_tree_svg) - 1);
        m_icons[ICO_MEMORY]          = svg(icons_memory_svg,          sizeof(icons_memory_svg) - 1);
        m_icons[ICO_SYSCALLS]        = svg(icons_syscalls_svg,        sizeof(icons_syscalls_svg) - 1);
        m_icons[ICO_ORIGIN]          = svg(icons_origin_svg,          sizeof(icons_origin_svg) - 1);
        m_icons[ICO_HANDLES]         = svg(icons_handles_svg,         sizeof(icons_handles_svg) - 1);
    }

    // Every TTD command, in menu order. Adding one takes a handler member, its
    // activate(), and a row here, nothing else.
    void Plugin::build_action_table()
    {
        // Shorthands, so a row stays readable.
        const int  NO_ICON = -1;
        const bool GROUP = true, ITEM = false;
        const bool MENU = true, TOOLBAR_ONLY = false;

        // Tooltips: rows with an icon can sit on the toolbar, where the
        // tooltip is all that names them, so theirs start with the label.
        m_actions = {
            // Getting around.
            { actions::TIMELINE, "Timeline...", &m_timeline, "Ctrl+Shift+T",
              "Timeline: notable positions in the trace",
              m_icons[ICO_TIMELINE], ITEM, MENU },
            { actions::GOTO_POS, "Go to position...", &m_goto, "Ctrl+Shift+G",
              "Go to position: jump to a trace position",
              m_icons[ICO_GOTO], ITEM, MENU },
            { actions::ADD_BOOKMARK, "Bookmark this position...", &m_addBookmark, "Ctrl+Shift+B",
              "Bookmark this position, with a name and a note",
              m_icons[ICO_BOOKMARK_ADD], GROUP, MENU },
            { actions::BOOKMARKS, "Bookmarks...", &m_bookmarksView, nullptr,
              "Bookmarks: the saved positions",
              m_icons[ICO_BOOKMARKS], ITEM, MENU },

            // Forks, right after bookmarks: both are positions to come back to.
            { actions::FORK, "Fork here", &m_fork, nullptr,
              "Make this position a fork: change registers and memory here, then record the fork",
              NO_ICON, ITEM, MENU, SUB_FORKS },
            { actions::FORK_RECORD, "Record fork...", &m_forkRecord, nullptr,
              "Replay to the fork, apply the changes and record from there into a new recording",
              NO_ICON, ITEM, MENU, SUB_FORKS },
            { actions::FORK_DISCARD, "Discard fork", &m_forkDiscard, nullptr,
              "Drop the fork and its changes",
              NO_ICON, ITEM, MENU, SUB_FORKS },
            { actions::FORK_MANAGER, "Fork manager", &m_forkManager, nullptr,
              "This recording and its forks; double-click one to switch to it",
              NO_ICON, GROUP, MENU, SUB_FORKS },
            // On the Fork manager's popup only.
            { actions::FORK_OPEN, "Switch to or open this recording...", &m_forkOpen, nullptr,
              "Switch this IDA to the selected recording, or open it in a new IDA",
              NO_ICON, ITEM, TOOLBAR_ONLY },
            { actions::FORK_FORGET, "Remove fork", &m_forkForget, nullptr,
              "Remove the selected fork from the graph (its file is kept)",
              NO_ICON, ITEM, TOOLBAR_ONLY },

            // Searching the recording.
            { actions::TRACE_FUNC, "Find calls to this function", &m_traceFunc, "Ctrl+Shift+C",
              "Find calls to this function: every call in the trace, with arguments and return value",
              m_icons[ICO_FUNCTION], GROUP, MENU },
            { actions::TRACE_PAT, "Find calls by name/pattern...", &m_tracePat, "Ctrl+Shift+F",
              "Find calls by name/pattern, such as kernel32!Virtual*",
              m_icons[ICO_FUNC_SEARCH], ITEM, MENU },
            { actions::CALL_TREE, "Call tree of this function", &m_callTree, nullptr,
              "Call tree: the calls this function made during this run of it",
              m_icons[ICO_CALL_TREE], ITEM, MENU },
            { actions::MEM_SEARCH, "Find memory accesses...", &m_memSearch, "Ctrl+Shift+M",
              "Find memory accesses: every read, write or execute of an address",
              m_icons[ICO_MEMORY], ITEM, MENU },
            { actions::ORIGIN_GRAPH, "Where did this value come from?...", &m_originGraph, "Ctrl+Shift+W",
              "Where did this value come from: a graph of every chain back to its constants, syscalls and inputs",
              m_icons[ICO_ORIGIN], ITEM, MENU },

            // What the program did, over the whole recording: the system
            // calls and objects at the top, memory and what it wrote below.
            { actions::SYSCALLS, "Syscalls...", &m_syscalls, nullptr,
              "Syscalls: every syscall, with its arguments and result",
              m_icons[ICO_SYSCALLS], GROUP, MENU },
            { actions::HANDLES, "Handles...", &m_handles, nullptr,
              "Handles: every object the program opened, with where it was opened and closed",
              m_icons[ICO_HANDLES], ITEM, MENU },
            { actions::MEM_MAP, "Memory map", &m_memMap, nullptr,
              "Memory map: the regions at this position, with protection and use",
              NO_ICON, ITEM, MENU, SUB_MEMORY },
            { actions::MEM_TIMELINE, "Memory timeline", &m_memTimeline, nullptr,
              "Every allocation, protection change and free, in order",
              NO_ICON, ITEM, MENU, SUB_MEMORY },
            { actions::HEATMAP, "Memory heatmap", &m_heatmap, nullptr,
              "Which pages were read, written and run, and when",
              NO_ICON, ITEM, MENU, SUB_MEMORY },
            { actions::STRINGS, "Recover strings...", &m_recoverStrings, nullptr,
              "Every string the program had in memory, with where it appeared",
              NO_ICON, ITEM, MENU, SUB_WRITTEN },
            { actions::BUFFERS, "Recover buffers...", &m_recoverBuffers, nullptr,
              "Every buffer the program filled, with the code that wrote it",
              NO_ICON, ITEM, MENU, SUB_WRITTEN },
            { actions::SELF_MOD, "Self-modifying code...", &m_selfMod, nullptr,
              "Every instruction the program wrote before running it",
              NO_ICON, ITEM, MENU, SUB_WRITTEN },

            // What the recording can write into the database: the commands
            // that change the listing, then those that undo them.
            { actions::COVERAGE, "Highlight executed code...", &m_coverage, nullptr,
              "Color every instruction in the chosen scope that ran",
              NO_ICON, ITEM, MENU, SUB_ANNOTATE },
            { actions::INDIRECT, "Resolve indirect calls...", &m_indirect, nullptr,
              "Comment each indirect call with where it went, and add the cross-reference",
              NO_ICON, ITEM, MENU, SUB_ANNOTATE },
            { actions::ANALYZE_FUNC, "Analyze whole function", &m_analyzeFunc, "Ctrl+Shift+A",
              "Find the entry of the function around the cursor in the trace and define it",
              NO_ICON, ITEM, MENU, SUB_ANNOTATE },
            { actions::FULL_PDB, "Load full symbols for this module", &m_fullPdb, nullptr,
              "Apply the module's whole PDB, types included, through IDA's PDB plugin "
              "(names load in the background without this). Blocks while it loads",
              NO_ICON, ITEM, MENU, SUB_ANNOTATE },
            // Doing either on every stop is a setting (auto_coverage,
            // auto_callsites), not a menu item.
            { actions::COVERAGE_CLR, "Clear execution highlight", &m_coverageClear, nullptr,
              "Remove the execution color from the whole database",
              NO_ICON, GROUP, MENU, SUB_ANNOTATE },
            { actions::INDIRECT_CLR, "Clear resolved indirect calls", &m_indirectClear, nullptr,
              "Remove the comments and cross-references Resolve indirect calls added",
              NO_ICON, ITEM, MENU, SUB_ANNOTATE },
            // On the disassembly's right-click menu only.
            { actions::REREAD, "Re-read memory from the recording", &m_reread, nullptr,
              "Discard IDA's copy of the selected range, read it again from the recording "
              "and disassemble it",
              NO_ICON, ITEM, TOOLBAR_ONLY },

            // Toolbar only: the backward and run-to-cursor movements sit
            // beside their forward counterparts on the TTD toolbar (four of
            // the ten on the menu read as an arbitrary subset). They stay
            // registered, so shortcuts and buttons work.
            { actions::RUN_BACK, "Continue backwards", &m_runBack, nullptr,
              "Continue backwards to the previous breakpoint or the start of the trace",
              m_icons[ICO_REV_CONTINUE], ITEM, TOOLBAR_ONLY },
            { actions::STEP_OUT_BACK, "Step out backwards", &m_stepOutBack, nullptr,
              "Step out backwards to the call that entered this function",
              m_icons[ICO_STEP_OUT_BACK], ITEM, TOOLBAR_ONLY },
            { actions::RUN_TO_CUR_FWD, "Run to cursor", &m_runToCurFwd, nullptr,
              "Run to cursor",
              m_icons[ICO_RUN_TO_CUR], ITEM, TOOLBAR_ONLY },
            { actions::RUN_TO_CUR_BACK, "Run to cursor backwards", &m_runToCurBack, nullptr,
              "Run to cursor backwards",
              m_icons[ICO_RUN_TO_CUR_BACK], ITEM, TOOLBAR_ONLY },

            // The position readout: a clickable, text-only toolbar button.
            { actions::POS_LABEL, "TTD position", &m_posLabel, nullptr,
              POS_LABEL_TOOLTIP,
              NO_ICON, ITEM, TOOLBAR_ONLY },
        };

        // Every TTD handler reaches the plugin's state through one context.
        for ( const ActionDesc &d : m_actions )
            if ( auto *a = dynamic_cast<TtdAction *>(d.handler) )
                a->ctx = &m_ctx;
    }

    // Register every TTD action (and so every shortcut) and build the menu.
    // From show_actions(); hide_actions() undoes it.
    void Plugin::register_actions()
    {
        if ( m_actionsRegistered )
            return;

        for ( const ActionDesc &d : m_actions )
        {
            if ( !register_action(ACTION_DESC_LITERAL_PLUGMOD(
                     d.id, d.label, d.handler, this, d.shortcut, d.tooltip, d.icon)) )
            {
                msg("[ida-ttd] could not register the '%s' action.\n", d.label);
            }
        }

        m_actionsRegistered = true;
        rebuild_ttd_menu();
    }

    // Drop every TTD action, with its shortcut and menu/toolbar entries:
    // nothing TTD-specific responds outside a session.
    void Plugin::unregister_actions()
    {
        if ( !m_actionsRegistered )
            return;

        for ( const ActionDesc &d : m_actions )
            unregister_action(d.id);

        // The next session may be another database: neither the cached
        // bookmarks nor the cancelled-sweep set carry across.
        m_bookmarks.invalidate();
        m_autoCoverDeclined.clear();
        m_autoCoverFunc = BADADDR;
        m_actionsRegistered = false;
        // The menu stays, with what is there outside a session.
        rebuild_ttd_menu();
    }

    // Re-skin IDA's movement actions with codicons. IDA registers some lazily
    // and resets their icons when it rebuilds the debugger toolbars (e.g.
    // after a memory-cache invalidation on a jump), so this is reapplied at
    // session start and on every stop. Nothing without an active trace: the
    // override is global, and other debuggers keep their icons.
    void Plugin::reskin_actions()
    {
        if ( !m_actionsRegistered )
            return;

        CASSERT(ICO_NATIVE_COUNT == qnumber(NATIVE_MOVEMENT_ACTIONS));

        for ( size_t i = 0; i < ICO_NATIVE_COUNT; i++ )
        {
            const char *name = NATIVE_MOVEMENT_ACTIONS[i];
            // Remember IDA's icon the first time the action is found; not in
            // one shot, since several register lazily, and once overridden a
            // query returns the codicon.
            if ( !m_nativeSavedOk[i] && get_action_icon(name, &m_nativeSaved[i]) )
                m_nativeSavedOk[i] = true;
            update_action_icon(name, m_icons[i]);
        }
    }

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

    // Register the TTD actions (once) and rebuild the TTD toolbar from
    // scratch, so it survives debugger-desktop resets and never sticks hidden.
    // Called when a trace loads and again at process start, when the lazily
    // registered native movement actions exist to attach.
    void Plugin::show_actions()
    {
        m_posPinned.clear();        // a new toolbar button: pin it again
        register_actions();
        try_hook_decompiler();
        suspend_source_debugging();

        delete_toolbar(TTD_TOOLBAR);
        create_toolbar(TTD_TOOLBAR, "TTD");
        // Position readout, forward buttons, backward buttons, TTD extras.
        attach_action_to_toolbar(TTD_TOOLBAR, actions::POS_LABEL);
        // --- bookmarks, next to the position they record ---
        attach_action_to_toolbar(TTD_TOOLBAR, actions::ADD_BOOKMARK);
        attach_action_to_toolbar(TTD_TOOLBAR, actions::BOOKMARKS);
        if ( can_fork_recording() )
            attach_action_to_toolbar(TTD_TOOLBAR, actions::FORK_MANAGER);
        // --- forward ---
        attach_action_to_toolbar(TTD_TOOLBAR, "ProcessStart");           // Continue
        attach_action_to_toolbar(TTD_TOOLBAR, "ThreadStepInto");         // Step into
        attach_action_to_toolbar(TTD_TOOLBAR, "ThreadStepOver");         // Step over
        attach_action_to_toolbar(TTD_TOOLBAR, "ThreadRunUntilReturn");   // Run until return
        attach_action_to_toolbar(TTD_TOOLBAR, actions::RUN_TO_CUR_FWD);  // Run to cursor (custom)
        // --- backward, for a recording that can be stepped backwards ---
        if ( can_reverse() )
        {
            attach_action_to_toolbar(TTD_TOOLBAR, actions::RUN_BACK);        // Continue backwards
            attach_action_to_toolbar(TTD_TOOLBAR, "ThreadStepIntoBackwards");
            attach_action_to_toolbar(TTD_TOOLBAR, "ThreadStepOverBackwards");
            attach_action_to_toolbar(TTD_TOOLBAR, actions::STEP_OUT_BACK);   // Step out backwards
            attach_action_to_toolbar(TTD_TOOLBAR, actions::RUN_TO_CUR_BACK); // Run to cursor backwards (custom)
        }
        // --- TTD extras ---
        attach_action_to_toolbar(TTD_TOOLBAR, actions::TIMELINE);
        attach_action_to_toolbar(TTD_TOOLBAR, actions::GOTO_POS);
        attach_action_to_toolbar(TTD_TOOLBAR, actions::TRACE_PAT);

        reskin_actions();
        update_position_label();
    }

    // The trace is gone: drop the toolbar, restore IDA's movement icons and
    // unregister every TTD action. Safe to repeat (process exit and
    // ev_term_debugger both come here).
    void Plugin::hide_actions()
    {
        m_posPinned.clear();
        // First: a pseudocode view of runtime-allocated code cannot survive
        // the session, and IDA would save it in the desktop and restore it
        // broken.
        close_volatile_pseudocode_views();
        unquiet_ui();
        m_posLabelChars = 0;
        // Nothing of this session's views may reach the next one.
        m_refocusTimer.cancel();
        m_stepView = nullptr;
        m_viewsBefore.clear();
        m_renderBefore.clear();
        restore_source_debugging();
        delete_toolbar(TTD_TOOLBAR);
        restore_native_icons();
        unregister_actions();
    }

    // A fixed width for the position button, so the toolbar does not shift
    // as the position changes.
    static void pin_position_width(const qstring &widest)
    {
        if ( !widest.empty() )
            call_qt("pin_position_width", { POS_LABEL_TOOLTIP, widest.c_str() });
    }

    // Refresh the text on the toolbar's position button from the live cursor.
    void Plugin::update_position_label()
    {
        if ( !m_actionsRegistered )
            return;             // no session: the readout action does not exist
        qstring label;
        qstring pos = m_mgr.is_active() ? format_position(m_mgr.current_position())
                                        : qstring();
        if ( !pos.empty() )
            label.sprnt("Position %s", pos.c_str());
        else
            label = "Position: XX:XX";
        // At a fork being prepared, say so: the views show its changes, not
        // the recording.
        if ( !pos.empty() && m_mgr.at_fork_draft() )
        {
            const auto &d = m_mgr.fork_draft();
            // A register, or a run of consecutive bytes, is one change.
            size_t n = d.regs.size();
            ea_t next = BADADDR;
            for ( const auto &b : d.bytes )
            {
                if ( b.first != next )
                    n++;
                next = b.first + 1;
            }
            if ( n == 0 )
                label.append(" (fork)");
            else
                label.cat_sprnt(" (fork, %u change%s)", (uint)n, n == 1 ? "" : "s");
        }
        // Pad to the widest label of the session with figure spaces (digit
        // wide; ordinary spaces are narrower and the toolbar would shift).
        static const char FIGURE_SPACE[] = "\xE2\x80\x87";
        m_posLabelChars = std::max(m_posLabelChars, label.length());
        for ( size_t n = label.length(); n < m_posLabelChars; n++ )
            label.append(FIGURE_SPACE);
        update_action_label(actions::POS_LABEL, label.c_str());
        // The pin is a Python call, and this runs at every stop, every module
        // load (a hundred at a session's start) and every register write. So
        // it is made only while stopped, when the toolbar's button is
        // certainly there (before the first stop it may not be, and the
        // first stop pins it anyway), and again only for a wider sample. The
        // toolbar is rebuilt at each session's start and end, which resets
        // this (show_actions, hide_actions).
        if ( m_mgr.is_active() && get_process_state() == DSTATE_SUSP )
        {
            const qstring widest = format_position(m_mgr.last_position());
            if ( widest != m_posPinned )
            {
                pin_position_width(widest);
                m_posPinned = widest;
            }
        }
    }
}
