#include "plugin/plugin.h"
#include "analysis/callsites.h"
#include "analysis/fork_registry.h"
#include "common/trace_link.h"
#include "common/symsrv.h"
#include "core/backend_module.h"
#include "core/backend_registry.h"
#include "plugin/script_api.h"
#include "plugin/settings.h"
#include "debugger/registers.h"
#include "core/diag.h"
#include "ui/graph_view.h"
#include <expr.hpp>

// Embedded SVG icons (codicons for the movement actions, including "continue
// backwards", which has no native IDA icon).
#include "ui/icons.hh"

namespace idattd
{
    static const char *TTD_TOOLBAR = "TTDToolBar";

    // "Once IDA has finished what it is doing": the shortest interval that
    // still returns to the message loop first.
    static const int DEFER_MS = 10;
    // How often to re-check whether the initial auto-analysis has drained.
    static const int ATTACH_POLL_MS = 250;

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

    // The top-level TTD menu, beside File / Edit / Jump.
    //
    // Name and label are both "TTD" on purpose: whether a path resolves by
    // name or label, "TTD/" then means this menu. (Toolbars are a separate
    // namespace, "TTDToolBar".)
    static const char *TTD_MENU      = "TTD";
    // Also how ida_ttd_qt finds the position button.
    static const char POS_LABEL_TOOLTIP[] = "Current trace position; click to copy it";
    static const char *TTD_MENU_PATH = "TTD/";      // path items attach under

    // Submenus of the TTD menu, in display order. An ActionDesc names one by
    // 'name'; a submenu's rows are consecutive in the table. Paths resolve by
    // label, so a label holds no '/' or '&'.
    static const char *SUB_FORKS    = "TTDForks";
    static const char *SUB_MEMORY   = "TTDMemory";
    static const char *SUB_WRITTEN  = "TTDWritten";
    static const char *SUB_ANNOTATE = "TTDAnnotate";
    // Not a session submenu: always there, last, built by rebuild_ttd_menu().
    static const char *SUB_BACKENDS       = "TTDBackends";
    static const char *SUB_BACKENDS_LABEL = "Backends";
    struct SubmenuDesc
    {
        const char *name;
        const char *label;
        bool        new_group;      // separator above it in the TTD menu
        const char *icon_svg;       // nullptr: none
    };
    static const SubmenuDesc TTD_SUBMENUS[] =
    {
        // Among the items with icons, so it has one too.
        { SUB_FORKS,    "Forks",             true,  icons_fork_svg },
        // Beside Syscalls and Handles, in their section.
        { SUB_MEMORY,   "Memory",            false, nullptr },
        { SUB_WRITTEN,  "Written data",      false, nullptr },
        // Everything that changes the database, in a section of its own.
        { SUB_ANNOTATE, "Annotate database", true,  nullptr },
    };

    // ida_ttd_qt.<fn>(args...) (scripts/ida_ttd_qt.py), for the Qt changes
    // the SDK has no call for. The arguments go as quoted string literals.
    static bool call_qt(const char *fn, std::initializer_list<const char *> args)
    {
        extlang_object_t py = find_extlang_by_name("Python");
        if ( py == nullptr || py->eval_snippet == nullptr )
            return false;
        qstring code;
        code.sprnt("import ida_ttd_qt\nida_ttd_qt.%s(", fn);
        bool first = true;
        for ( const char *a : args )
        {
            if ( !first )
                code.append(", ");
            first = false;
            json_str(&code, a);
        }
        code.append(")\n");
        qstring err;
        if ( py->eval_snippet(code.c_str(), &err) )
            return true;
        msg("[ida-ttd] ida_ttd_qt.%s failed: %s\n", fn, err.c_str());
        return false;
    }

    // create_menu() takes no icon.
    static void set_submenu_icon(const char *label, const char *svg)
    {
        call_qt("set_submenu_icon", { TTD_MENU, label, svg });
    }

    // A separator goes above a menu item, not a submenu, so the one above a
    // submenu belongs to a hidden action just above it, one per submenu (an
    // action goes on a menu once). It needs a real label: IDA 9.4 refuses to
    // attach an action labelled "-", separator and all.
    static const char SEP_CARRIER_LABEL[] = "separator";
    static const char *const SUBMENU_SEP_ACTIONS[] =
    {
        "idattd:menu_sep_0", "idattd:menu_sep_1", "idattd:menu_sep_2", "idattd:menu_sep_3",
    };
    static const char SUB_BACKENDS_SEP[] = "idattd:menu_sep_backends";
    struct MenuSepHandler : public action_handler_t
    {
        int idaapi activate(action_activation_ctx_t *) override { return 0; }
        action_state_t idaapi update(action_update_ctx_t *) override { return AST_DISABLE_ALWAYS; }
    };
    static MenuSepHandler g_menuSep;

    // TTD > Settings...: the IDA Settings Editor on ida-ttd's settings, or how
    // to change them without it (scripts/ida_ttd_settings.py).
    struct SettingsHandler : public action_handler_t
    {
        int idaapi activate(action_activation_ctx_t *) override
        {
            extlang_object_t py = find_extlang_by_name("Python");
            qstring err;
            if ( py == nullptr || py->eval_snippet == nullptr
              || !py->eval_snippet("import ida_ttd_settings\n"
                                   "ida_ttd_settings.show_editor()\n", &err) )
                warning("ida-ttd's settings are changed with "
                        "\"hcli plugin config ida-ttd set KEY VALUE\"%s%s",
                        err.empty() ? "" : "\n\n", err.c_str());
            return 1;
        }
        action_state_t idaapi update(action_update_ctx_t *) override { return AST_ENABLE_ALWAYS; }
    };
    static SettingsHandler g_settingsHandler;
    static const char SETTINGS_ACTION[] = "idattd:settings";

    // Put ida-ttd-python\ (beside the plugin; scripts/ida_ttd.py and its
    // siblings) on IDAPython's sys.path, so `import ida_ttd` works. Safe to
    // repeat; a no-op without IDAPython or the folder.
    static void register_python_module()
    {
        extlang_object_t py = find_extlang_by_name("Python");
        if ( py == nullptr || py->eval_snippet == nullptr )
            return;
        HMODULE self = nullptr;
        wchar_t buf[MAX_PATH * 2];
        if ( !GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
                               | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                 reinterpret_cast<LPCWSTR>(&register_python_module), &self)
          || GetModuleFileNameW(self, buf, qnumber(buf)) == 0 )
            return;
        qstring dir;
        utf16_utf8(&dir, (const wchar16_t *)buf);
        ssize_t slash = dir.rfind('\\');
        if ( slash < 0 )
            return;
        dir.resize((size_t)slash);
        dir.append("/ida-ttd-python");
        dir.replace("\\", "/");     // a Python string literal without escapes
        if ( !qisdir(dir.c_str()) )
            return;
        // A quote still needs escaping: a user name can hold one (O'Neil).
        dir.replace("'", "\\'");
        qstring code;
        code.sprnt("import sys\n"
                   "if '%s' not in sys.path:\n"
                   "    sys.path.append('%s')\n", dir.c_str(), dir.c_str());
        qstring err;
        if ( !py->eval_snippet(code.c_str(), &err) )
            msg("[ida-ttd] could not put %s on IDAPython's path: %s\n", dir.c_str(), err.c_str());
    }

    // Flag the call stack and stack views for refresh. The mask is built by
    // hand because IWID_*/builtin_widget_mask_from_id use a uint128 << that
    // ida.lib does not export (link error on MSVC).
    static void refresh_call_stack()
    {
        const uint64 m = (uint64(1) << BWN_CALL_STACK) | (uint64(1) << BWN_STKVIEW);
        mark_builtin_widgets(uint128(m, uint64(0)));
    }
    static int idaapi pdb_poll_cb(void *ud);     // below

    // The live plugin. A request queued with execute_ui_requests can outlive
    // the plugin (the database closes), so each checks its pointer against
    // this first.
    static Plugin *g_live_plugin = nullptr;

    Plugin::Plugin()
    {
        g_live_plugin = this;
        // The backend DLLs (load_backend_modules lists where they are found).
        load_backend_modules();
        // Hex-Rays variable and comment edits mark their function for the
        // kept-functions copy, as IDB events do for the rest.
        set_function_edit_hook([](ea_t ea)
        {
            if ( g_live_plugin != nullptr )
                g_live_plugin->manager().kept().note_changed(ea);
        });
        // ttd("...") for scripts (plugin/script_api.h).
        install_script_api(this);
        // An idalib worker gets no ui_ready_to_run; there, IDAPython is
        // already loaded if present at all.
        register_python_module();
        load_settings();

        configure_debugger(m_debugger, inf_is_64bit());
        m_tracer.set_manager(&m_mgr);
        m_tracer.set_64bit(inf_is_64bit());

        // The session's only way back to the plugin, so debugger/ does not
        // depend on plugin/.
        m_mgr.set_session_hooks({
            [this]()
            {
                show_actions();
                // PDB names are applied while a session is paused; the timer
                // runs only then, not in every database for the plugin's life.
                m_pdbTimer.arm(1000, pdb_poll_cb, this);
            },
            [this]()
            {
                hide_actions();
                // The traced functions and recorded calls belong to the closing
                // trace; their positions mean nothing in the next one, and the
                // choosers would travel to them.
                m_tracer.reset();
                coverage_session_ended();
                callsites_session_ended();
                // Their windows travel to positions of this trace too.
                heatmap_session_ended();
                origin_session_ended();
            },
        });

        m_dbgEvents.p = this;
        m_uiEvents.p  = this;
        m_idbEvents.p = this;

        // One context for every TTD handler.
        m_ctx.mgr    = &m_mgr;
        m_ctx.tracer = &m_tracer;
        m_ctx.store  = &m_bookmarks;
        m_ctx.refresh_position = [this]() { update_position_label(); };
        m_ctx.switch_trace     = [this](const qstring &path) { switch_trace(path); };

        // Icons live as long as the plugin; the actions are registered only
        // while a trace is loaded (show_actions/hide_actions).
        load_icons();
        build_action_table();
        // Pseudocode coverage highlighting, optional: without Hex-Rays the
        // rest works unchanged.
        m_haveDecompiler = init_decompiler();
        hook_event_listener(HT_IDD, this);
        hook_event_listener(HT_DBG, &m_dbgEvents);
        hook_event_listener(HT_UI,  &m_uiEvents);
        hook_event_listener(HT_IDB, &m_idbEvents);
    }

    // PDBs are downloaded and read in the background; their names are applied
    // here a few milliseconds at a time while paused, so no step waits on a
    // PDB. Ticks every 100 ms while there is work, else once a second.
    static int idaapi pdb_poll_cb(void *ud)
    {
        Plugin *p = static_cast<Plugin *>(ud);
        if ( !p->manager().is_active() )
            return -1;                  // armed again at the next session's start
        if ( get_process_state() == DSTATE_SUSP
          && p->manager().modules().advance_pdbs(15) != 0 )
            refresh_idaview_anyway();
        return p->manager().modules().pdbs_pending() ? 100 : 1000;
    }

    Plugin::~Plugin()
    {
        g_live_plugin = nullptr;
        // First: no symbol download may outlive the plugin, and no script may
        // reach it while it goes away.
        symsrv_shutdown();
        remove_script_api();
        // The Fork manager holds this plugin's action context.
        close_fork_manager();
        m_refocusTimer.cancel();
        m_autoCoverTimer.cancel();
        m_attachTimer.cancel();
        m_switchTimer.cancel();
        m_pdbTimer.cancel();
        m_keptTimer.cancel();
        set_function_edit_hook(nullptr);
        unhook_event_listener(HT_IDB, &m_idbEvents);
        unhook_event_listener(HT_UI,  &m_uiEvents);
        unhook_event_listener(HT_DBG, &m_dbgEvents);
        unhook_event_listener(HT_IDD, this);
        // init() pointed IDA's global 'dbg' at m_debugger, a member; leaving it
        // would hand the kernel a dangling pointer (the listeners that guarded
        // on it are already unhooked).
        if ( ::dbg == &m_debugger )
            ::dbg = nullptr;
        // The backends stay loaded, this DLL does not: their log callback
        // goes, and a log request still in IDA's queue keeps this DLL mapped.
        backend_log_unloading();
        hide_actions();     // toolbar + actions, if a session was still open
        // After hide_actions(), which closes pseudocode views of runtime code;
        // that needs the Hex-Rays hook.
        term_decompiler();
        // The TTD menu outlives sessions but not the plugin.
        delete_menu(SUB_BACKENDS);
        for ( const SubmenuDesc &s : TTD_SUBMENUS )
            delete_menu(s.name);
        delete_menu(TTD_MENU);
        if ( m_menuActionsRegistered )
        {
            unregister_action(actions::INSTALL_RUNTIME);
            unregister_action(actions::INSTALL_SOGEN);
            unregister_action(actions::RECORD_PROGRAM);
            unregister_action(actions::BACKEND_HDR_MS);
            unregister_action(actions::BACKEND_HDR_SOGEN);
            for ( const char *sep : SUBMENU_SEP_ACTIONS )
                unregister_action(sep);
            unregister_action(SUB_BACKENDS_SEP);
            unregister_action(SETTINGS_ACTION);
            m_menuActionsRegistered = false;
        }
        for ( int ic : m_icons )
            if ( ic != -1 )
                free_custom_icon(ic);
    }

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
        m_icons[ICO_MEMORY_MAP]      = svg(icons_memory_map_svg,      sizeof(icons_memory_map_svg) - 1);
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
            { actions::FORK_FORGET, "Forget this fork", &m_forkForget, nullptr,
              "Remove the selected fork from the graph (its file stays)",
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
              m_icons[ICO_MEMORY_MAP], ITEM, MENU, SUB_MEMORY },
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

    bool idaapi Plugin::run(size_t)
    {
        if ( trace_link_present() && get_process_state() == DSTATE_NOTASK )
        {
            start_trace_session();
            return true;
        }
        info("ida-ttd: open a trace (.run, .sogttd) directly, or select 'TTD trace replayer' "
             "under Debugger > Switch debugger and start with the trace file as "
             "the application.");
        return true;
    }

    // Start replaying the recording this database was created from. No
    // prompting: this is the menu action's body, so the user already asked.
    bool Plugin::start_trace_session(qstring *error)
    {
        TraceLink link;
        if ( !trace_link_read(&link) )
        {
            trace_link_mark_start(false);
            if ( error != nullptr )
                *error = "this database was not created from a TTD trace, so there is nothing to replay";
            else
                warning("This database was not created from a TTD trace, so there is "
                        "nothing to replay.\n\nUse Debugger > Switch debugger to attach "
                        "a trace to it instead.");
            return false;
        }
        if ( get_process_state() != DSTATE_NOTASK )
        {
            trace_link_mark_start(false);
            if ( error != nullptr )
                *error = "a debugging session is already running";
            else
                warning("A debugging session is already running.");
            return false;
        }

        // The recording may have moved since the database was made: ask
        // where it went and remember the answer. A script is told instead.
        if ( !qfileexist(link.trace_path.c_str()) && error != nullptr )
        {
            trace_link_mark_start(false);
            error->sprnt("the recording is not at %s; start it once from the TTD menu to locate it, "
                         "or use 'switch PATH'", link.trace_path.c_str());
            return false;
        }
        if ( !qfileexist(link.trace_path.c_str()) )
        {
            qstring prompt;
            prompt.sprnt("Locate the TTD trace for this database (was %s)",
                         link.trace_path.c_str());
            const char *chosen = ask_file(false, link.trace_path.c_str(), "%s", prompt.c_str());
            if ( chosen == nullptr )
            {
                trace_link_mark_start(false);   // the user declined, nothing broke
                return false;
            }
            link.trace_path = chosen;
            trace_link_set_path(chosen);
        }

        if ( !select_trace_debugger(link.trace_path.c_str(), error != nullptr) )
        {
            trace_link_mark_start(false);       // reported already, nothing broke
            if ( error != nullptr )
                *error = "IDA would not select the TTD trace replayer as the debugger (see the output window)";
            return false;
        }
        if ( start_process(link.trace_path.c_str(), "", "") != 1 )
        {
            if ( error != nullptr )
                *error = "IDA did not start the replay";
            return false;
        }
        return true;
    }

    bool Plugin::select_trace_debugger(const char *trace_path, bool quiet)
    {
        // Set the trace path first, whether or not the switch works: it fills
        // Debugger > Process options. IDA's Application browser filters on
        // "*.exe" (no SDK field changes that), so without it the user hunts
        // for the trace behind the wrong filter.
        if ( trace_path != nullptr && trace_path[0] != '\0' )
            set_process_options(trace_path, "", nullptr, "", "", "", -1);

        if ( ::dbg != &m_debugger )
        {
            // What load_debugger() matches on is undocumented, so try each
            // candidate and report which one worked (see plugin_module_name).
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
                // Assigning ::dbg by hand is no fallback. init() may, while IDA
                // builds its debugger list; afterwards it leaves the kernel on
                // a debugger it never initialised, and starting a process then
                // crashed IDA.
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

    // Runs from IDA's request queue (main thread, when idle). Starting a
    // session rebases the program and replaces the loader's segments, so it
    // must not run inside a timer callback partway through the kernel's work.
    struct start_request_t : public ui_request_t
    {
        Plugin *p;
        explicit start_request_t(Plugin *plugin) : p(plugin) {}
        bool idaapi run() override
        {
            if ( p != g_live_plugin )
                return false;
            p->offer_trace_session();
            return false;               // one-shot; IDA deletes the request
        }
    };

    int idaapi Plugin::attach_cb(void *ud)
    {
        Plugin *p = static_cast<Plugin *>(ud);
        // ui_ready_to_run fires while a new database is still being analysed;
        // starting a session then (rebase, debugger segments over the
        // loader's while analysis walks them) crashed IDA. Wait it out.
        if ( !auto_is_ok() )
            return ATTACH_POLL_MS;      // not yet; ask again
        execute_ui_requests(new start_request_t(p), nullptr);
        return -1;
    }

    // Replay another recording in this database (a fork shares the program
    // and modules).
    //
    // Runs from a timer, outside the caller (the Fork manager's Enter must not
    // see its chooser refreshed under it): end the session, wait until IDA is
    // done with it, start the new one. A switch that cannot happen is
    // dropped, not carried over to a later session's end.
    void Plugin::switch_trace(const qstring &path)
    {
        if ( m_mgr.is_active() && same_trace_path(path, m_mgr.trace_path()) )
            return;
        m_switchTo       = path;
        // Ending the session closes its windows; the Fork manager reopens at
        // the new session's first stop. A pending reopen carries over.
        m_reopenForkManager = m_reopenForkManager || fork_manager_is_open();
        m_switchExitSent = false;
        m_switchTimer.cancel();
        m_switchTimer.arm(10, switch_cb, this);
    }

    // Both halves of a switch run from IDA's request queue, like
    // start_request_t: ending or starting a session inside a timer callback
    // caused internal error 40183.
    struct switch_exit_request_t : public ui_request_t
    {
        Plugin *p;
        explicit switch_exit_request_t(Plugin *plugin) : p(plugin) {}
        bool idaapi run() override
        {
            if ( p != g_live_plugin )
                return false;
            p->switch_exit();
            return false;
        }
    };

    struct switch_start_request_t : public ui_request_t
    {
        Plugin *p;
        qstring path;
        switch_start_request_t(Plugin *plugin, const qstring &to) : p(plugin), path(to) {}
        bool idaapi run() override
        {
            if ( p != g_live_plugin )
                return false;
            if ( get_process_state() != DSTATE_NOTASK )
            {
                msg("[ida-ttd] a session is running again; not switching to %s.\n", path.c_str());
                return false;
            }
            msg("[ida-ttd] switching the replay to %s\n", path.c_str());
            if ( !p->start_trace_at(path.c_str()) )
                warning("Could not start the replay of %s (see the output window).", path.c_str());
            return false;
        }
    };

    void Plugin::switch_exit()
    {
        if ( m_switchTo.empty() )
            return;
        qstring path;
        path.swap(m_switchTo);
        // The session ended between the request being queued and now: there
        // is nothing to exit, so start the switch's replay directly, as
        // switch_cb does without a session. Returning here instead dropped
        // the switch and left the Fork manager to reopen in a later session.
        if ( get_process_state() == DSTATE_NOTASK )
        {
            execute_ui_requests(new switch_start_request_t(this, path), nullptr);
            return;
        }
        // Close the Fork manager while the session is still ordinary rather
        // than let IDA tear it down at session end; it reopens at the new
        // session's first stop.
        close_fork_manager_window();
        // IDA's request queue chains the two, so the start runs once IDA is
        // done with the old session. Starting as soon as the state read "no
        // process" raced IDA's teardown (internal error 40183 at times).
        set_process_options(path.c_str(), "", nullptr, "", "", "", -1);
        msg("[ida-ttd] switching the replay to %s\n", path.c_str());
        request_exit_process();
        request_start_process(path.c_str(), "", "");
        run_requests();
    }

    int idaapi Plugin::switch_cb(void *ud)
    {
        Plugin *p = static_cast<Plugin *>(ud);
        if ( p->m_switchTo.empty() )
            return -1;
        if ( get_process_state() != DSTATE_NOTASK )
        {
            // A session is running: switch_exit ends it and queues the start.
            if ( !p->m_switchExitSent )
            {
                p->m_switchExitSent = true;
                execute_ui_requests(new switch_exit_request_t(p), nullptr);
            }
            return -1;
        }
        qstring path;
        path.swap(p->m_switchTo);
        execute_ui_requests(new switch_start_request_t(p, path), nullptr);
        return -1;
    }

    void Plugin::reopen_fork_manager()
    {
        if ( m_reopenForkManager )
        {
            m_reopenForkManager = false;
            process_ui_action(actions::FORK_MANAGER);
        }
    }

    bool Plugin::start_trace_at(const char *path, bool quiet)
    {
        if ( !select_trace_debugger(path, quiet) )
            return false;
        return start_process(path, "", "") == 1;
    }

    void Plugin::schedule_trace_offer()
    {
        m_attachTimer.arm(ATTACH_POLL_MS, attach_cb, this);
    }

    void Plugin::offer_trace_session()
    {
        if ( !trace_link_present() || get_process_state() != DSTATE_NOTASK )
            return;

        TraceLink link;
        if ( !trace_link_read(&link) )
            return;

        // First, whether or not the replay starts: point the debugger at the
        // trace so Debugger > Start process (F9) replays it. That is also how
        // a replay is started by hand, so the TTD menu has no start item.
        if ( qfileexist(link.trace_path.c_str()) )
            select_trace_debugger(link.trace_path.c_str(), true);

        // Opening a recording is a request to replay it, so nothing is asked.
        // The replay_on_open setting turns this off. (A per-database toggle
        // on the TTD menu used to; its stored answer is ignored now.)
        if ( !settings().replay_on_open )
            return;

        // A leftover mark means the last automatic start never reached a
        // running session (it may have crashed). Clear it and stay put, so the
        // database can open and the automatic start can be switched off.
        if ( trace_link_start_marked() )
        {
            trace_link_mark_start(false);
            msg("[ida-ttd] the last automatic replay start for this database did "
                "not finish, so it was not repeated. Start it with Debugger > "
                "Start process (F9), or turn off \"Replay when a recording's "
                "database opens\" in TTD > Settings.\n");
            return;
        }

        trace_link_mark_start(true);
        start_trace_session();
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

    void Plugin::rebuild_ttd_menu()
    {
        // A headless idalib worker has no menus to build.
        if ( !is_idaq() )
            return;

        // The actions that belong to the menu rather than to a session, once.
        if ( !m_menuActionsRegistered )
        {
            m_menuActionsRegistered = true;
            for ( const char *sep : SUBMENU_SEP_ACTIONS )
                register_action(ACTION_DESC_LITERAL_PLUGMOD(sep, SEP_CARRIER_LABEL, &g_menuSep, this,
                                                            nullptr, nullptr, -1));
            register_action(ACTION_DESC_LITERAL_PLUGMOD(SUB_BACKENDS_SEP, SEP_CARRIER_LABEL, &g_menuSep, this,
                                                        nullptr, nullptr, -1));
            // Section headings: always disabled, so they read as labels.
            register_action(ACTION_DESC_LITERAL_PLUGMOD(
                actions::BACKEND_HDR_MS, "Microsoft TTD", &g_menuSep, this, nullptr, nullptr, -1));
            register_action(ACTION_DESC_LITERAL_PLUGMOD(
                actions::BACKEND_HDR_SOGEN, "Sogen", &g_menuSep, this, nullptr, nullptr, -1));
            register_action(ACTION_DESC_LITERAL_PLUGMOD(
                actions::INSTALL_RUNTIME, "Install the TTD runtime (WinDbg)...",
                &m_installRuntime, this, nullptr,
                "Get Microsoft's TTD replay runtime, which Microsoft TTD recordings "
                "need: copied from an installed WinDbg, or WinDbg downloaded from "
                "Microsoft once you accept its license", -1));
            register_action(ACTION_DESC_LITERAL_PLUGMOD(
                actions::INSTALL_SOGEN, "Install the Sogen backend...",
                &m_installSogen, this, nullptr,
                "The package includes the Sogen backend. This installs another build "
                "of it (ida-ttd-sogen.dll, or a release zip holding it) into "
                "ida-ttd\\backends in your IDA user directory, where it takes the "
                "packaged one's place", -1));
            register_action(ACTION_DESC_LITERAL_PLUGMOD(
                actions::RECORD_PROGRAM, "Record a program with Sogen...",
                &m_recordProgram, this, nullptr,
                "Run a program from its start in Sogen's emulator and record it into a "
                "new Sogen recording (.sogttd), with the Sogen settings: network access, "
                "checkpoint interval, what is recorded", -1));
            register_action(ACTION_DESC_LITERAL_PLUGMOD(
                SETTINGS_ACTION, "Settings...", &g_settingsHandler, this, nullptr,
                "ida-ttd's settings (symbol downloads, automatic coverage and call-site "
                "comments, fork length, Sogen recording, ...), in the IDA Settings Editor. "
                "Changes apply from the next stop of the replay", -1));
        }

        // From scratch, in order. Deleting a menu takes its items with it;
        // the actions stay registered.
        delete_menu(SUB_BACKENDS);
        for ( const SubmenuDesc &s : TTD_SUBMENUS )
            delete_menu(s.name);
        delete_menu(TTD_MENU);

        // create_menu() first: attach_action_to_menu() resolves its path
        // against existing menus, so attaching under "TTD/" before the menu
        // exists silently does nothing.
        //
        // No position argument: create_menu() would read one as an existing
        // menu or item and nest TTD inside it. Without one, IDA appends the
        // menu to the menu bar.
        create_menu(TTD_MENU, "TTD");
        bool above = false;     // anything in the menu yet, to separate from

        if ( m_actionsRegistered )
        {
            attach_session_menu();
            above = true;
        }

        // Backends: one section per backend, separated. The separator above
        // the submenu is carried by a hidden action (see SEP_CARRIER_LABEL).
        if ( above )
        {
            attach_action_to_menu(TTD_MENU_PATH, SUB_BACKENDS_SEP, SETMENU_APP | SETMENU_ENSURE_SEP);
            update_action_visibility(SUB_BACKENDS_SEP, false);
        }
        create_menu(SUB_BACKENDS, SUB_BACKENDS_LABEL, TTD_MENU_PATH);
        qstring bpath;
        bpath.sprnt("%s%s/", TTD_MENU_PATH, SUB_BACKENDS_LABEL);
        attach_action_to_menu(bpath.c_str(), actions::BACKEND_HDR_MS, SETMENU_APP);
        attach_action_to_menu(bpath.c_str(), actions::INSTALL_RUNTIME, SETMENU_APP);
        attach_action_to_menu(bpath.c_str(), actions::BACKEND_HDR_SOGEN, SETMENU_APP | SETMENU_ENSURE_SEP);
        attach_action_to_menu(bpath.c_str(), actions::INSTALL_SOGEN, SETMENU_APP);
        attach_action_to_menu(bpath.c_str(), actions::RECORD_PROGRAM, SETMENU_APP);
        attach_action_to_menu(TTD_MENU_PATH, SETTINGS_ACTION, SETMENU_APP);
    }

    // The session's part of the TTD menu: every menu row of the action
    // table, in its submenu.
    void Plugin::attach_session_menu()
    {
        CASSERT(qnumber(SUBMENU_SEP_ACTIONS) >= qnumber(TTD_SUBMENUS));
        // A recording that cannot be forked (Microsoft's) gets no Forks menu.
        const bool can_fork = can_fork_recording();
        int wanted = 0, attached = 0;
        const char *open_sub = nullptr;     // the submenu the last row went in
        qstring path = TTD_MENU_PATH;
        for ( const ActionDesc &d : m_actions )
        {
            if ( !d.on_menu || (d.submenu == SUB_FORKS && !can_fork) )
                continue;
            if ( d.submenu != open_sub )
            {
                open_sub = d.submenu;
                path = TTD_MENU_PATH;
                for ( size_t i = 0; open_sub != nullptr && i < qnumber(TTD_SUBMENUS); i++ )
                {
                    const SubmenuDesc &s = TTD_SUBMENUS[i];
                    if ( strcmp(s.name, open_sub) != 0 )
                        continue;
                    if ( s.new_group )
                    {
                        attach_action_to_menu(TTD_MENU_PATH, SUBMENU_SEP_ACTIONS[i],
                                              SETMENU_APP | SETMENU_ENSURE_SEP);
                        update_action_visibility(SUBMENU_SEP_ACTIONS[i], false);
                    }
                    create_menu(s.name, s.label, TTD_MENU_PATH);
                    if ( s.icon_svg != nullptr )
                        set_submenu_icon(s.label, s.icon_svg);
                    path.sprnt("%s%s/", TTD_MENU_PATH, s.label);
                }
            }
            wanted++;
            if ( attach_action_to_menu(path.c_str(), d.id,
                                       SETMENU_APP | (d.new_group ? SETMENU_ENSURE_SEP : 0)) )
                attached++;
        }
        if ( attached != wanted )
            msg("[ida-ttd] only %d of %d TTD menu entries could be attached.\n",
                attached, wanted);
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
        // once it has been made while stopped, when the toolbar's button is
        // certainly there, it is made again only for a wider sample. The
        // toolbar is rebuilt at each session's start and end, which resets
        // this (show_actions, hide_actions).
        if ( m_mgr.is_active() )
        {
            const qstring widest = format_position(m_mgr.last_position());
            if ( widest != m_posPinned )
            {
                pin_position_width(widest);
                if ( get_process_state() == DSTATE_SUSP )
                    m_posPinned = widest;
            }
        }
    }

    // Every open disassembly view, by title: the user's (A-Z) and the
    // debugger desktop's, named after the instruction pointer.
    static void list_disasm_views(std::vector<TWidget *> &out)
    {
        out.clear();
        auto add = [&out](const char *title)
        {
            TWidget *w = find_widget(title);
            if ( w != nullptr && get_widget_type(w) == BWN_DISASM )
                out.push_back(w);
        };
        add("IDA View-RIP");
        add("IDA View-EIP");
        for ( char c = 'A'; c <= 'Z'; c++ )
        {
            char title[16];
            qsnprintf(title, sizeof(title), "IDA View-%c", c);
            add(title);
        }
    }

    // The first resume after a settled stop starts a movement, and the widget
    // with focus is where it started (the key or toolbar button does not move
    // focus). Later resumes before the stop settles are the same movement.
    void Plugin::begin_movement()
    {
        if ( m_mgr.resume_serial() != m_settledResume )
            return;
        TWidget *cur = get_current_widget();
        m_stepView = cur != nullptr && get_widget_type(cur) == BWN_PSEUDOCODE ? cur : nullptr;
        list_pseudocode_views(m_viewsBefore);
        std::vector<TWidget *> disasm;
        list_disasm_views(disasm);
        m_renderBefore.clear();
        for ( TWidget *w : disasm )
            m_renderBefore.emplace_back(w, get_view_renderer_type(w));
    }

    // Stepping from pseudocode, IDA decompiles the stop's function, and a stop
    // outside a function (or in one Hex-Rays cannot take) raises a
    // "Decompilation failure" dialog per step. The stop is known once
    // ev_resume has carried the movement out, before IDA acts on it, so the
    // no-function case is caught here; asking Hex-Rays must wait for the stop
    // notification, when memory is readable (check_stop_decompiles()).
    void Plugin::movement_done()
    {
        if ( m_stepView == nullptr || !m_mgr.is_active() )
            return;
        ea_t pc = m_mgr.current_pc_ea();
        func_entry_info_t fi;
        if ( pc != BADADDR && !get_func_entry_info(&fi, pc) )
            quiet_ui();
    }

    void Plugin::check_stop_decompiles()
    {
        if ( m_stepView == nullptr || m_quiet || !m_mgr.is_active() )
            return;
        ea_t pc = m_mgr.current_pc_ea();
        func_entry_info_t fi;
        if ( pc != BADADDR && get_func_entry_info(&fi, pc) && !can_decompile(fi.start_ea) )
            quiet_ui();
    }

    void Plugin::quiet_ui()
    {
        if ( m_quiet )
            return;
        // Only what this turns on is turned off again. Saving 'batch' and
        // restoring it later put back a stale value: on when something else
        // (a script run in batch mode, an MCP call, the PDB plugin's guard)
        // had it on for a moment as the stop arrived, and so left IDA in
        // batch mode for good, with every dialog suppressed (Go to
        // position... did nothing).
        m_quietOwned = !batch;
        batch        = true;
        m_quiet      = true;
    }

    void Plugin::unquiet_ui()
    {
        if ( !m_quiet )
            return;
        if ( m_quietOwned )
            batch = false;
        m_quietOwned = false;
        m_quiet      = false;
    }

    void Plugin::restore_renderers()
    {
        std::vector<TWidget *> now;
        list_disasm_views(now);
        for ( const auto &[w, before] : m_renderBefore )
        {
            // Only text that became graph. The other way round is IDA
            // falling back to text where a graph cannot be drawn.
            if ( before != TCCRT_FLAT
              || std::find(now.begin(), now.end(), w) == now.end()
              || get_view_renderer_type(w) != TCCRT_GRAPH )
                continue;
            set_view_renderer_type(w, TCCRT_FLAT);
        }
        m_renderBefore.clear();
    }

    void Plugin::widget_closing(TWidget *w)
    {
        if ( w == m_stepView )
            m_stepView = nullptr;
    }

    void Plugin::settle_stop()
    {
        m_settledResume = m_mgr.resume_serial();
    }

    int idaapi Plugin::refocus_cb(void *ud)
    {
        static_cast<Plugin *>(ud)->do_after_stop();
        return -1;  // one-shot
    }

    // Leave exactly one pseudocode view on the stop, in front.
    //
    // Stepping from pseudocode into another function, IDA opens that function
    // in a new view, so each call stepped into left a window behind. IDA then
    // reuses that view while the steps stay in the function, so its view is
    // kept and the one the step started from is closed. When IDA opened
    // nothing, the starting view is moved to the function instead.
    void Plugin::do_after_stop()
    {
        // Warnings stay in the output window until all of this is done: the
        // view work below makes Hex-Rays decompile, and a function it cannot
        // take would raise a "Decompilation failure" dialog per step.
        struct Unquiet
        {
            Plugin *p;
            ~Unquiet() { p->unquiet_ui(); }
        } unquiet{ this };
        restore_renderers();
        settle_stop();
        // Before anything below reads a setting.
        reload_settings_if_changed();
        // These write to the database or open windows, so they run here
        // rather than inside IDA's stop notification.
        if ( m_mgr.is_active() )
            coverage_settle_recording_change();
        // The stop may have shown a function painted since its pseudocode
        // was last printed. After a layout change, decompiled afresh.
        if ( m_layoutChanged )
            redecompile_pseudocode_views();
        else
            refresh_pseudocode_views();
        m_layoutChanged = false;
        reopen_fork_manager();
        // The replayed recording may have changed: redraw here, never at
        // session start or end (see switch_exit).
        refresh_fork_manager();
        // The memory map follows the playhead.
        if ( m_mgr.is_active() )
            MemoryMapChooser::refresh_open();
        // A list asked to show memory in the hex view once the travel landed.
        show_pending_bytes();
        TWidget *from = m_stepView;
        if ( from == nullptr )
        {
            m_viewsBefore.clear();
            return;
        }

        std::vector<TWidget *> now;
        list_pseudocode_views(now);
        std::vector<TWidget *> opened;
        for ( TWidget *w : now )
            if ( w != from && std::find(m_viewsBefore.begin(), m_viewsBefore.end(), w)
                              == m_viewsBefore.end() )
                opened.push_back(w);

        ea_t pc = m_mgr.current_pc_ea();
        TWidget *keep = from;
        if ( !opened.empty() )
        {
            keep = opened.back();
            for ( TWidget *w : opened )
                if ( w != keep )
                    close_widget(w, 0);
            close_widget(from, 0);      // reaches widget_closing()
        }
        // Also within one function: IDA puts the caret on an argument's own
        // line when the stop is in code setting it up.
        if ( pc != BADADDR )
            show_in_pseudocode(keep, pc);
        diag("refocus: from %p, %d opened, kept %p showing %llX, pc %llX",
             from, (int)opened.size(), keep,
             (unsigned long long)pseudocode_function(keep), (unsigned long long)pc);
        activate_widget(keep, true);
        // Only a stop after a movement from begin_movement() may close a
        // view; the next starts from scratch.
        m_stepView = nullptr;
        m_viewsBefore.clear();
    }

    void Plugin::try_hook_decompiler()
    {
        if ( !m_haveDecompiler )
            m_haveDecompiler = init_decompiler();
    }

    // Source-info providers cannot be enumerated, so the ones with line
    // information for native code are named here; an unregistered name yields
    // nullptr.
    static const char *const SRCINFO_PROVIDERS[] = { "PDB", "pdb", "DWARF", "dwarf" };

    void Plugin::suspend_source_debugging()
    {
        for ( const char *n : SRCINFO_PROVIDERS )
        {
            srcinfo_provider_t *sp = get_srcinfo_provider(n);
            // Turn off only what is on, and remember it, so a provider the
            // user had disabled is not re-enabled at session end.
            if ( sp == nullptr || !sp->is_enabled() )
                continue;
            sp->enable_provider(false);
            m_srcProvidersOff.push_back(n);
            msg("[ida-ttd] source-level debugging via '%s' is off for this session: "
                "it offers to map source paths recorded on the machine that made "
                "the trace. It is restored when the trace closes.\n", n);
        }
    }

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

    int idaapi Plugin::kept_cb(void *ud)
    {
        Plugin *p = static_cast<Plugin *>(ud);
        if ( !p->m_mgr.is_active() )
            return -1;
        // Only while stopped, as every database change from the recording.
        if ( get_process_state() != DSTATE_SUSP || p->m_mgr.is_navigating() )
            return 200;
        if ( p->m_mgr.restore_kept() )
        {
            refresh_idaview_anyway();
            redecompile_pseudocode_views();
        }
        return -1;
    }

    void Plugin::schedule_kept_restore()
    {
        m_keptTimer.arm(DEFER_MS, kept_cb, this);
    }

    int idaapi Plugin::autocover_cb(void *ud)
    {
        static_cast<Plugin *>(ud)->do_auto_coverage();
        return -1;  // one-shot: unregister
    }

    // On a stop, decide whether to measure the function stopped in. The work
    // is deferred: a sweep pumps the UI behind a wait box, and inside a
    // debugger notification the user could drive the debugger again.
    void Plugin::schedule_auto_coverage()
    {
        m_autoCoverFunc = BADADDR;
        if ( !m_actionsRegistered || !m_mgr.is_active() )
            return;
        if ( !coverage_auto_enabled() && !callsites_auto_enabled() )
            return;
        ea_t pc = m_mgr.current_pc_ea();
        if ( pc == BADADDR )
            return;
        func_entry_info_t fi;
        if ( !get_func_entry_info(&fi, pc) )
            return;                                  // no function to measure yet
        if ( m_autoCoverDeclined.find(fi.start_ea) != m_autoCoverDeclined.end() )
            return;                                  // the user said no
        if ( !auto_coverage_wanted(fi.start_ea) && !auto_indirect_wanted(fi.start_ea) )
            return;                                  // nothing left to do there
        m_autoCoverFunc = fi.start_ea;
        m_autoCoverTimer.arm(DEFER_MS, autocover_cb, this);
    }

    bool Plugin::auto_coverage_wanted(ea_t start) const
    {
        return coverage_auto_enabled() && !coverage_function_done(start);
    }

    bool Plugin::auto_indirect_wanted(ea_t start) const
    {
        return callsites_auto_enabled() && !callsites_function_done(start);
    }

    void Plugin::do_auto_coverage()
    {
        unquiet_ui();       // its wait box must show, whatever ran first
        ea_t start = m_autoCoverFunc;
        m_autoCoverFunc = BADADDR;
        if ( start == BADADDR || !m_mgr.is_active() )
            return;
        // Re-read the bounds: analysis may have changed them since the stop.
        func_entry_info_t fi;
        if ( !get_func_entry_info(&fi, start) || fi.start_ea != start )
            return;
        bool changed = false, retyped = false;
        if ( auto_coverage_wanted(start) )
        {
            if ( !cover_function(&m_mgr, fi.start_ea, fi.end_ea) )
            {
                // Cancelled or failed: not again this session, or the next
                // step in the function would re-offer it.
                m_autoCoverDeclined.insert(start);
                return;
            }
            changed = true;
        }
        if ( auto_indirect_wanted(start) )
        {
            if ( !auto_annotate_function(&m_mgr, fi.start_ea, fi.end_ea) )
            {
                m_autoCoverDeclined.insert(start);
                return;
            }
            changed = retyped = true;
        }
        if ( changed )
        {
            refresh_idaview_anyway();
            // New call types change what the decompiler writes, not just
            // how it is painted.
            if ( retyped )
                redecompile_pseudocode_views();
            else
                refresh_pseudocode_views();
        }
    }

    // From the stop handler. IDA's own post-stop handling raises the
    // disassembly, switches its mode and opens pseudocode, so corrections wait
    // for it: a short timer, then the next turn of the UI loop.
    void Plugin::schedule_after_stop()
    {
        m_refocusTimer.arm(DEFER_MS, refocus_cb, this);
    }

    //=======================================================================
    // HT_DBG: module symbols, and the per-stop and session-end work.
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
                    p->manager().modules().resolve_symbols((ea_t)mi.base);
                    p->manager().modules().load_pdb((ea_t)mi.base);  // silent PDB symbols
                }
                if ( code == dbg_process_start )
                {
                    trace_link_mark_start(false);   // the start survived
                    p->reset_step_state();
                    p->show_actions();   // rebuild the toolbar in the debugger desktop
                }
                p->update_position_label();
                break;
            }
            case dbg_suspend_process:
                // After every stop, once memory is valid for the new position.
                p->manager().on_suspended();
                // Before anything else can make IDA decompile the stop.
                p->check_stop_decompiles();
                // For installs where the decompiler loads late.
                p->try_hook_decompiler();
                p->update_position_label();
                // Queued before the coverage sweep so that it runs first: the
                // sweep's wait box must not be shown in batch mode.
                p->schedule_after_stop();
                p->schedule_auto_coverage();
                // IDA can rebuild the debug toolbars across a stop and reset
                // the icons; reapplying is cheap.
                p->reskin_actions();
                // Exports were just named; frames should show them.
                refresh_call_stack();
                // A travel from a list is done once all of the above is.
                p->manager().end_travel_wait();
                break;
            case dbg_process_exit:
                // The session is over. Drop the toolbar and actions now:
                // ev_term_debugger fires only when the debugger is unloaded.
                p->hide_actions();
                p->manager().end_travel_wait();
                break;
            default:
                break;
        }
        return 0;
    }

    //=======================================================================
    // HT_UI: context-menu items, UI ready, widgets closing.
    //=======================================================================
    ssize_t idaapi UiEventListener::on_event(ssize_t code, va_list va)
    {
        if ( p == nullptr )
            return 0;

        switch ( code )
        {
            case ui_finish_populating_widget_popup:
            {
                // Only while this debugger is active and a trace is loaded
                // (outside a session the actions do not exist).
                if ( ::dbg != &p->debugger() || !p->actions_visible() )
                    break;
                TWidget    *widget = va_arg(va, TWidget *);
                TPopupMenu *popup  = va_arg(va, TPopupMenu *);
                // (action_activation_ctx_t* ctx follows; not needed here)
                if ( widget == nullptr )
                    break;
                if ( fork_manager_widget(widget) )
                {
                    attach_action_to_popup(widget, popup, actions::FORK_OPEN);
                    attach_action_to_popup(widget, popup, actions::FORK_FORGET);
                    break;
                }
                int wt = get_widget_type(widget);
                if ( wt == BWN_DISASM || wt == BWN_PSEUDOCODE )
                {
                    // Travel to the address under the cursor.
                    attach_action_to_popup(widget, popup, actions::RUN_TO_CUR_FWD, "TTD/");
                    attach_action_to_popup(widget, popup, actions::RUN_TO_CUR_BACK, "TTD/");
                    attach_action_to_popup(widget, popup, actions::ADD_BOOKMARK, "TTD/");
                }
                // Forking, wherever program state is changed (code, memory,
                // registers), for forkable recordings; Record and Discard only
                // with a fork begun.
                if ( (wt == BWN_DISASM || wt == BWN_PSEUDOCODE || wt == BWN_HEXVIEW || wt == BWN_CPUREGS)
                  && p->manager().backend() != nullptr && p->manager().backend()->capabilities().fork )
                {
                    attach_action_to_popup(widget, popup, actions::FORK, "TTD/");
                    if ( p->manager().fork_draft().active )
                    {
                        attach_action_to_popup(widget, popup, actions::FORK_RECORD, "TTD/");
                        attach_action_to_popup(widget, popup, actions::FORK_DISCARD, "TTD/");
                    }
                }
                if ( wt == BWN_DISASM )
                {
                    attach_action_to_popup(widget, popup, actions::TRACE_FUNC, "TTD/");
                    attach_action_to_popup(widget, popup, actions::COVERAGE, "TTD/");
                    attach_action_to_popup(widget, popup, actions::MEM_SEARCH, "TTD/");
                    attach_action_to_popup(widget, popup, actions::REREAD, "TTD/");
                }
                // Highlight bytes, then find what read, wrote or ran them.
                if ( wt == BWN_HEXVIEW )
                    attach_action_to_popup(widget, popup, actions::MEM_SEARCH, "TTD/");
                // Where a register's or memory's value came from.
                if ( wt == BWN_CPUREGS || wt == BWN_HEXVIEW || wt == BWN_DISASM )
                {
                    attach_action_to_popup(widget, popup, actions::ORIGIN_GRAPH, "TTD/");
                }
                break;
            }
            case ui_ready_to_run:
                // Everything is loaded by now, decompiler and IDAPython
                // included (the SDK's point for plugins needing the full UI).
                p->try_hook_decompiler();
                register_python_module();
                load_settings();
                // The TTD menu, with Backends, in every database: the TTD
                // runtime is needed before a Microsoft recording can open.
                p->rebuild_ttd_menu();
                // Starting a session inside a UI notification invites
                // reentrancy; do it from the message loop later.
                if ( trace_link_present() )
                    p->schedule_trace_offer();
                break;
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

    // HT_IDB: names changed (e.g. IDA applied a downloaded PDB); refresh the
    // call stack so frames pick them up.
    ssize_t idaapi IdbEventListener::on_event(ssize_t code, va_list va)
    {
        if ( p == nullptr || !p->manager().is_active() )
            return 0;
        KeptFunctions &kept = p->manager().kept();
        switch ( code )
        {
            // A function outside the modules may have been worked on before:
            // its work comes back once the notification is over.
            case idb_event::function_added:
                if ( kept.note_added(va_arg(va, ea_t)) )
                    p->schedule_kept_restore();
                return 0;
            // What the user can set on one, copied before the next movement.
            case idb_event::ti_changed:
            case idb_event::cmt_changed:
            case idb_event::function_updated:
                kept.note_changed(va_arg(va, ea_t));
                return 0;
            case idb_event::range_cmt_changed:
            {
                range_kind_t   kind = (range_kind_t)va_arg(va, int);
                const range_t *r    = va_arg(va, const range_t *);
                if ( kind == RANGE_KIND_FUNC && r != nullptr )
                    kept.note_changed(r->start_ea);
                return 0;
            }
            // A saved database must hold the work done so far.
            case idb_event::savebase:
                kept.capture_all();
                return 0;
            default:
                break;
        }
        if ( code == idb_event::renamed )
        {
            ea_t        ea       = va_arg(va, ea_t);
            const char *new_name = va_arg(va, const char *);
            kept.note_changed(ea);
            // Debugger views (the call stack in particular) resolve
            // <name>+offset through the debug-name list, but exports and PDB
            // symbols only set IDB names, so frames showed raw addresses.
            // Mirror each name into the debug-name list, deletions too, or a
            // deleted name would live on in those views.
            if ( new_name != nullptr && new_name[0] != '\0' )
                set_debug_name(ea, new_name);
            else
                del_debug_names(ea, ea + 1);
            // Functions named in system modules get FUNC_LIB, so library
            // code is de-emphasised (the PDB plugin does not flag them).
            if ( get_func_start(ea) == ea && (get_func_flags(ea) & FUNC_LIB) == 0
              && p->manager().modules().is_library_address(ea) )
            {
                set_func_flag(ea, FUNC_LIB, true);
            }
            refresh_call_stack();   // just flags for refresh; rename storms coalesce
        }
        return 0;
    }

    // HT_IDD dispatch: translate debugger notifications into TraceManager calls.
    ssize_t idaapi Plugin::on_event(ssize_t code, va_list va)
    {
        // Only react when this debugger is the active one.
        if ( ::dbg != &m_debugger )
            return 0;

        // Log IDA's debugger requests for diagnostics, minus the frequent
        // polls and reads.
        if ( code != debugger_t::ev_get_debug_event && code != debugger_t::ev_read_memory
          && code != debugger_t::ev_read_registers && code != debugger_t::ev_get_memory_info )
            diag("idd: %d (process state %d)", (int)code, get_process_state());

        switch ( code )
        {
            case debugger_t::ev_init_debugger:
            {
                va_arg(va, const char *);   // hostname
                va_arg(va, int);            // port
                va_arg(va, const char *);   // password
                va_arg(va, qstring *);      // errbuf
                // Re-read the bitness: the constructor may run before a loader
                // has set up a new database, but by now it is settled. It picks
                // the register table.
                configure_debugger(m_debugger, inf_is_64bit());
                m_tracer.set_64bit(inf_is_64bit());
                // The debugger may have been chosen by hand. Point the
                // Application field at the recording, unless it already names
                // an existing recording: a session on a fork (the Fork
                // manager's switch) must not be turned back to the original.
                {
                    TraceLink link;
                    qstring app;
                    get_process_options(&app, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
                    load_backend_modules();
                    bool chosen = !app.empty() && qfileexist(app.c_str())
                               && BackendRegistry::instance().for_file(app.c_str()) != nullptr;
                    if ( !chosen
                      && get_process_state() == DSTATE_NOTASK
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
                begin_movement();
                ssize_t rc = m_mgr.on_resume(event);
                movement_done();
                return rc;
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
                const uint32_t before = m_mgr.layout().changes();
                ssize_t rc = m_mgr.on_get_memory_info(ranges);
                // A new layout makes IDA rebuild its debugger segments and
                // re-decompile open pseudocode from stale ranges ("bad input
                // ranges" dialogs). Quiet until the after-stop work has
                // decompiled them afresh.
                if ( m_mgr.layout().changes() != before )
                {
                    quiet_ui();
                    m_layoutChanged = true;
                    schedule_after_stop();
                }
                return rc;
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

            // Accepted only at a fork's position (TTD > Fork here); they
            // become the fork's changes.
            case debugger_t::ev_write_register:
            {
                thid_t          tid    = va_argi(va, thid_t);
                int             regidx = va_arg(va, int);
                const regval_t *value  = va_arg(va, const regval_t *);
                qstring        *errbuf = va_arg(va, qstring *);
                ssize_t rc = m_mgr.on_write_register(tid, regidx, value, errbuf);
                if ( rc == DRC_OK )
                    update_position_label();
                return rc;
            }

            case debugger_t::ev_write_memory:
            {
                size_t     *nbytes = va_arg(va, size_t *);
                ea_t        ea     = va_arg(va, ea_t);
                const void *buffer = va_arg(va, const void *);
                size_t      size   = va_arg(va, size_t);
                qstring    *errbuf = va_arg(va, qstring *);
                ssize_t rc = m_mgr.on_write_memory(nbytes, ea, buffer, size, errbuf);
                if ( rc == DRC_OK )
                    update_position_label();
                return rc;
            }

            case debugger_t::ev_check_bpt:
            {
                // Every kind (execute, read, write, read/write) at any address
                // and size; ev_update_bpts says per breakpoint whether the
                // engine can arm it.
                int *bptvc = va_arg(va, int *);
                if ( bptvc != nullptr )
                    *bptvc = BPT_OK;
                return DRC_OK;
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
    dbg = &p->debugger();      // make this plugin's debugger the active one
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
    "Loads time travel recordings (Microsoft TTD, Sogen) and lets you navigate them in IDA.",
    "TTD trace replayer",
    nullptr
};
