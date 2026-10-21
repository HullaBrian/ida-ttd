#include "plugin/plugin.h"
#include "analysis/callsites.h"
#include "analysis/fork_registry.h"
#include "common/trace_link.h"
#include "common/symsrv.h"
#include "core/backend_module.h"
#include "core/backend_registry.h"
#include "plugin/script_api.h"
#include "debugger/registers.h"
#include "core/diag.h"
#include <expr.hpp>

// Embedded Microsoft codicon debugger glyphs (SVG) for the debug-movement
// actions, including the "continue backwards" action IDA has no native icon for.
#include "ui/icons.hh"

namespace idattd
{
    static const char *TTD_TOOLBAR = "TTDToolBar";

    // "Do this once IDA has finished what it is doing": the shortest interval
    // that still hands control back to the message loop first.
    static const int DEFER_MS = 10;
    // How often to re-check whether the initial auto-analysis has drained.
    static const int ATTACH_POLL_MS = 250;

    // IDA's native debug-movement actions re-skinned with codicon glyphs
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
    // create_menu() must run first: attach_action_to_menu() resolves its path
    // against menus that already exist and uses it only to position the item, so
    // attaching to "TTD/..." before the menu exists silently does nothing.
    // Name and label are both "TTD" on purpose: menu paths are resolved by menu
    // NAME, so keeping the two identical means "TTD/" refers to this menu however
    // the path is interpreted. (The toolbar is a separate namespace, "TTDToolBar".)
    static const char *TTD_MENU      = "TTD";
    static const char *TTD_MENU_PATH = "TTD/";      // path items attach under

    // Submenus of the TTD menu, in the order they appear. An ActionDesc names
    // one of them by 'name'; the rows of one submenu are consecutive in the
    // table. Paths resolve by label, so a label holds no '/' or '&'.
    static const char *SUB_CODE     = "TTDCode";
    static const char *SUB_ANALYSIS = "TTDAnalysis";
    static const char *SUB_FORKS    = "TTDForks";
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
        { SUB_FORKS,    "Forks",    true,  icons_fork_svg },
        { SUB_CODE,     "Code",     true,  nullptr },
        { SUB_ANALYSIS, "Analysis", false, nullptr },
    };

    // create_menu() takes no icon, so it is set on the submenu's Qt action,
    // through IDAPython's PySide (IDA's Qt renders SVG, as load_custom_icon
    // relies on). Without IDAPython or Qt (an idalib worker) the submenu
    // simply has none.
    static void set_submenu_icon(const char *label, const char *svg)
    {
        extlang_object_t py = find_extlang_by_name("Python");
        if ( py == nullptr || py->eval_snippet == nullptr )
            return;
        // The label and the SVG hold no quote or backslash, so they go into
        // Python string literals as they are.
        qstring code;
        code.sprnt("def _idattd_submenu_icon():\n"
                   "    try:\n"
                   "        from PySide6 import QtGui, QtWidgets\n"
                   "        import shiboken6\n"
                   "    except ImportError:\n"
                   "        return\n"
                   "    app = QtWidgets.QApplication.instance()\n"
                   "    if app is None:\n"
                   "        return\n"
                   "    pix = QtGui.QPixmap()\n"
                   "    pix.loadFromData(b'%s', 'SVG')\n"
                   "    for m in app.allWidgets():\n"
                   "        if not isinstance(m, QtWidgets.QMenu) or not shiboken6.isValid(m) \\\n"
                   "                or m.title().replace('&', '') != '%s':\n"
                   "            continue\n"
                   "        for a in m.actions():\n"
                   "            sub = a.menu()\n"
                   "            if sub is not None and shiboken6.isValid(sub) and a.text().replace('&', '') == '%s':\n"
                   "                a.setIcon(QtGui.QIcon(pix))\n"
                   "_idattd_submenu_icon()\n"
                   "del _idattd_submenu_icon\n",
                   svg, TTD_MENU, label);
        qstring err;
        if ( !py->eval_snippet(code.c_str(), &err) )
            msg("[ida-ttd] could not give the %s submenu its icon: %s\n", label, err.c_str());
    }

    // A separator goes above a menu item, not above a submenu. The one above
    // a submenu belongs to a hidden action that sits just above it, one per
    // submenu (an action goes on a menu once). It needs a real label: IDA 9.4
    // refuses to attach an action labelled "-", and with it the separator.
    static const char SEP_CARRIER_LABEL[] = "separator";
    static const char *const SUBMENU_SEP_ACTIONS[] =
    {
        "idattd:menu_sep_0", "idattd:menu_sep_1", "idattd:menu_sep_2",
    };
    static const char SUB_BACKENDS_SEP[] = "idattd:menu_sep_backends";
    struct MenuSepHandler : public action_handler_t
    {
        int idaapi activate(action_activation_ctx_t *) override { return 0; }
        action_state_t idaapi update(action_update_ctx_t *) override { return AST_DISABLE_ALWAYS; }
    };
    static MenuSepHandler g_menuSep;

    // `import ida_ttd` in IDAPython: the module (scripts/ida_ttd.py) is
    // installed in ida-ttd-python\ beside the plugin, and that folder goes on
    // IDAPython's sys.path. Safe to call more than once, and a no-op without
    // IDAPython or without the folder.
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
        // ...except a quote, which a user name can hold (C:/Users/O'Neil).
        dir.replace("'", "\\'");
        qstring code;
        code.sprnt("import sys\n"
                   "if '%s' not in sys.path:\n"
                   "    sys.path.append('%s')\n", dir.c_str(), dir.c_str());
        qstring err;
        if ( !py->eval_snippet(code.c_str(), &err) )
            msg("[ida-ttd] could not put %s on IDAPython's path: %s\n", dir.c_str(), err.c_str());
    }

    // A Microsoft TTD recording starts with "TTDLog", as the MS backend's
    // can_open checks; the plugin only needs to know which menu to offer.
    static bool is_ms_recording(const char *path)
    {
        FILE *f = qfopen(path, "rb");
        if ( f == nullptr )
            return false;
        char magic[6] = { 0 };
        bool ms = qfread(f, magic, sizeof(magic)) == sizeof(magic)
               && memcmp(magic, "TTDLog", sizeof(magic)) == 0;
        qfclose(f);
        return ms;
    }

    // Flag the call stack + stack views for refresh. The widget mask is built
    // by hand instead of via IWID_*/builtin_widget_mask_from_id, whose uint128
    // << is defined out-of-line and not present in ida.lib (link error on MSVC).
    static void refresh_call_stack()
    {
        const uint64 m = (uint64(1) << BWN_CALL_STACK) | (uint64(1) << BWN_STKVIEW);
        mark_builtin_widgets(uint128(m, uint64(0)));
    }
    static int idaapi pdb_poll_cb(void *ud);     // below

    // The plugin while it exists. A request queued with execute_ui_requests
    // can still be waiting when IDA unloads the plugin (the database closes),
    // so each one checks its Plugin pointer against this before using it.
    static Plugin *g_live_plugin = nullptr;

    Plugin::Plugin()
    {
        g_live_plugin = this;
        // Backends for kinds of recording other than Microsoft's, installed as
        // DLLs in $IDAUSR\ida-ttd\backends. Nothing is there unless the user
        // put it there, in which case each one is named in the output window.
        load_backend_modules();
        m_pdbTimer.arm(1000, pdb_poll_cb, this);
        // ttd("...") for scripts: how the plugin is driven and tested without
        // a person at the UI (plugin/script_api.h).
        install_script_api(this);
        // In an idalib worker no ui_ready_to_run follows; IDAPython is
        // loaded already when it is there at all.
        register_python_module();

        configure_debugger(m_debugger, inf_is_64bit());
        m_tracer.set_manager(&m_mgr);
        m_tracer.set_64bit(inf_is_64bit());

        // The backend's only way back out to the plugin, so debugger/ does not
        // depend on plugin/.
        m_mgr.set_session_hooks({
            [this]() { show_actions(); },
            [this]()
            {
                hide_actions();
                // The traced-function list and the recorded calls belong to the
                // trace that is closing: their addresses and positions mean
                // nothing in the next one, and the choosers would happily
                // time-travel to them.
                m_tracer.reset();
                coverage_session_ended();
                callsites_session_ended();
            },
        });

        m_dbgEvents.p = this;
        m_uiEvents.p  = this;
        m_idbEvents.p = this;
        m_attachTrace.start_session = [this]() { start_trace_session(); };

        // One context for every TTD handler, rather than a back-pointer
        // assignment per handler.
        m_ctx.mgr    = &m_mgr;
        m_ctx.tracer = &m_tracer;
        m_ctx.store  = &m_bookmarks;
        m_ctx.refresh_position = [this]() { update_position_label(); };
        m_ctx.switch_trace     = [this](const qstring &path) { switch_trace(path); };

        // Icons are loaded once for the lifetime of the plugin (they are freed in
        // the destructor); the actions themselves are only registered while a
        // trace is loaded, so the TTD shortcuts and toolbar do not exist until
        // then -- see show_actions()/hide_actions().
        load_icons();
        build_action_table();
        // Pseudocode coverage highlighting, if this install has a decompiler.
        // Everything about it is optional: without Hex-Rays the plugin behaves
        // exactly as it did before.
        m_haveDecompiler = init_decompiler();
        hook_event_listener(HT_IDD, this);
        hook_event_listener(HT_DBG, &m_dbgEvents);
        hook_event_listener(HT_UI,  &m_uiEvents);
        hook_event_listener(HT_IDB, &m_idbEvents);
    }

    // PDBs are downloaded and read in the background; the names they give are
    // set here, a few milliseconds at a time while the replay is paused, so a
    // module's names fill in on their own and no step ever waits on a PDB.
    // Ticks quickly while there is work, and once a second otherwise.
    static int idaapi pdb_poll_cb(void *ud)
    {
        Plugin *p = static_cast<Plugin *>(ud);
        if ( !p->manager().is_active() )
            return 1000;
        if ( get_process_state() == DSTATE_SUSP
          && p->manager().modules().advance_pdbs(15) != 0 )
            refresh_idaview_anyway();
        return p->manager().modules().pdbs_pending() ? 100 : 1000;
    }

    Plugin::~Plugin()
    {
        g_live_plugin = nullptr;
        // Before anything else: a symbol download must not outlive the plugin
        // whose session asked for it, and a script must not reach a plugin
        // that is going away.
        symsrv_shutdown();
        remove_script_api();
        // The Fork manager holds this plugin's action context.
        close_fork_manager();
        m_refocusTimer.cancel();
        m_autoCoverTimer.cancel();
        m_attachTimer.cancel();
        m_switchTimer.cancel();
        m_pdbTimer.cancel();
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
        // After hide_actions(): it closes pseudocode views of runtime-allocated
        // code, and that check is a no-op once the Hex-Rays hook is gone.
        term_decompiler();
        // The TTD menu outlives sessions but not the plugin.
        delete_menu(SUB_BACKENDS);
        for ( const SubmenuDesc &s : TTD_SUBMENUS )
            delete_menu(s.name);
        delete_menu(TTD_MENU);
        if ( m_attachRegistered )
        {
            unregister_action(actions::ATTACH_TRACE);
            unregister_action(actions::AUTO_START);
            m_attachRegistered = false;
        }
        if ( m_menuActionsRegistered )
        {
            unregister_action(actions::INSTALL_RUNTIME);
            unregister_action(actions::INSTALL_SOGEN);
            unregister_action(actions::BACKEND_HDR_MS);
            unregister_action(actions::BACKEND_HDR_SOGEN);
            for ( const char *sep : SUBMENU_SEP_ACTIONS )
                unregister_action(sep);
            unregister_action(SUB_BACKENDS_SEP);
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

    // Every TTD command, in the order it appears on the TTD menu. Adding one
    // means a handler member, its activate(), and a row here -- nothing else.
    void Plugin::build_action_table()
    {
        // Shorthands, so a row stays readable.
        const int  NO_ICON = -1;
        const bool GROUP = true, ITEM = false;
        const bool MENU = true, TOOLBAR_ONLY = false;

        m_actions = {
            // Getting around.
            { actions::TIMELINE, "Timeline...", &m_timeline, "Ctrl+Shift+T",
              "Timeline: open the TTD trace timeline of notable positions",
              m_icons[ICO_TIMELINE], ITEM, MENU },
            { actions::GOTO_POS, "Go to position...", &m_goto, "Ctrl+Shift+G",
              "Go to position: jump to a Sequence:Steps trace position",
              m_icons[ICO_GOTO], ITEM, MENU },
            { actions::ADD_BOOKMARK, "Bookmark this position...", &m_addBookmark, "Ctrl+Shift+B",
              "Bookmark this position: save the current trace position, with a name "
              "and a note, in the database",
              m_icons[ICO_BOOKMARK_ADD], GROUP, MENU },
            { actions::BOOKMARKS, "Bookmarks...", &m_bookmarksView, nullptr,
              "Bookmarks: the saved trace positions for this database",
              m_icons[ICO_BOOKMARKS], ITEM, MENU },

            // Forks, right after the bookmarks: both are about positions you
            // come back to.
            { actions::FORK, "Fork here", &m_fork, nullptr,
              "Fork here: make this position a fork. Change registers and memory in "
              "IDA as on a live target, then Record fork (Sogen recordings)",
              NO_ICON, ITEM, MENU, SUB_FORKS },
            { actions::FORK_RECORD, "Record fork...", &m_forkRecord, nullptr,
              "Record fork: replay the program to the fork, apply the changes, and let "
              "it run on into a new recording",
              NO_ICON, ITEM, MENU, SUB_FORKS },
            { actions::FORK_DISCARD, "Discard fork", &m_forkDiscard, nullptr,
              "Discard fork: drop the fork and its changes",
              NO_ICON, ITEM, MENU, SUB_FORKS },
            { actions::FORK_MANAGER, "Fork manager", &m_forkManager, nullptr,
              "Fork manager: this recording and the forks recorded from it, as a graph; "
              "double-click one to switch to it",
              NO_ICON, GROUP, MENU, SUB_FORKS },
            // On the Fork manager's popup only.
            { actions::FORK_OPEN, "Switch to or open this recording...", &m_forkOpen, nullptr,
              "Switch this IDA to the selected recording, or open it in a new IDA",
              NO_ICON, ITEM, TOOLBAR_ONLY },
            { actions::FORK_FORGET, "Forget this fork", &m_forkForget, nullptr,
              "Take the selected fork out of the graph (its file stays)",
              NO_ICON, ITEM, TOOLBAR_ONLY },

            // Searching the recording.
            { actions::TRACE_FUNC, "Find all calls to this function", &m_traceFunc, "Ctrl+Shift+C",
              "Find all calls to this function: sweep the whole trace and list every "
              "call with its arguments and return value",
              m_icons[ICO_FUNCTION], GROUP, MENU },
            { actions::TRACE_PAT, "Find calls by name/pattern...", &m_tracePat, "Ctrl+Shift+F",
              "Find calls by name/pattern: trace every function matching a wildcard "
              "like 'kernel32!Virtual*' in one sweep",
              m_icons[ICO_FUNC_SEARCH], ITEM, MENU },
            { actions::CALL_TREE, "Call tree of this function", &m_callTree, nullptr,
              "Call tree: every call the function at the cursor made during this run "
              "of it, nested, from its entry to its return",
              m_icons[ICO_CALL_TREE], ITEM, MENU },
            { actions::MEM_SEARCH, "Find memory accesses...", &m_memSearch, "Ctrl+Shift+M",
              "Find memory accesses: every read, write or execute of an address "
              "anywhere in the recording",
              m_icons[ICO_MEMORY], ITEM, MENU },
            { actions::VALUE_ORIGIN, "Where did this value come from?...", &m_valueOrigin, "Ctrl+Shift+W",
              "Where did this value come from: follow a register or memory back through "
              "the instructions that copied it, to where it was made",
              m_icons[ICO_ORIGIN], ITEM, MENU },
            { actions::ORIGIN_GRAPH, "Graph where this value came from...", &m_originGraph,
              "Ctrl+Shift+Alt+W",
              "Graph where this value came from: every chain at once, following each value an "
              "instruction combined, to the constants, syscalls and inputs it was made of",
              m_icons[ICO_ORIGIN], ITEM, MENU },

            // What the program asked of the system, over the whole recording.
            { actions::SYSCALLS, "Syscalls...", &m_syscalls, nullptr,
              "Syscalls: every syscall the program made, with its result and "
              "arguments",
              m_icons[ICO_SYSCALLS], GROUP, MENU },
            { actions::MEM_MAP, "Memory map", &m_memMap, nullptr,
              "Memory map: every region of memory at this position, with its "
              "protection, its type and what it is used for",
              m_icons[ICO_MEMORY_MAP], ITEM, MENU },
            { actions::HANDLES, "Handles...", &m_handles, nullptr,
              "Handles: every file, key, socket, pipe, process and other object the program "
              "opened, with its name, where it was opened and where it was closed",
              m_icons[ICO_HANDLES], ITEM, MENU },

            // Code: what the recording says about the code in front of you,
            // written into the database.
            { actions::ANALYZE_FUNC, "Analyze whole function", &m_analyzeFunc, "Ctrl+Shift+A",
              "Analyze whole function: walk the trace backward to find the enclosing "
              "function's entry and define it (runs behind a cancellable wait box)",
              NO_ICON, ITEM, MENU, SUB_CODE },
            { actions::FULL_PDB, "Load full symbols for this module", &m_fullPdb, nullptr,
              "Load full symbols: apply the whole PDB of the module under the cursor "
              "(types and prototypes too) through IDA's PDB plugin. Function names "
              "are applied in the background without this; it blocks while it loads",
              NO_ICON, ITEM, MENU, SUB_CODE },
            { actions::COVERAGE, "Highlight executed code...", &m_coverage, nullptr,
              "Highlight executed code: replay the recording and color every "
              "instruction in the chosen scope that actually ran",
              NO_ICON, ITEM, MENU, SUB_CODE },
            { actions::INDIRECT, "Resolve indirect calls...", &m_indirect, nullptr,
              "Resolve indirect calls: record where each one actually went, as a "
              "comment and a cross-reference",
              NO_ICON, ITEM, MENU, SUB_CODE },
            // The automatic behaviors.
            { actions::COVERAGE_AUTO, "Highlight functions automatically", &m_coverageAuto, nullptr,
              "Highlight functions automatically: measure and color each function "
              "the first time you stop in it",
              NO_ICON, GROUP, MENU, SUB_CODE },
            { actions::INDIRECT_AUTO, "Resolve indirect calls automatically", &m_indirectAuto, nullptr,
              "Resolve indirect calls automatically: annotate the indirect calls of "
              "each function the first time you stop in it (one replay per module)",
              NO_ICON, ITEM, MENU, SUB_CODE },
            // Undoing the above, in a section of their own.
            { actions::COVERAGE_CLR, "Clear execution highlight", &m_coverageClear, nullptr,
              "Clear execution highlight: remove the coverage color from the whole "
              "database",
              NO_ICON, GROUP, MENU, SUB_CODE },
            { actions::INDIRECT_CLR, "Clear resolved indirect calls", &m_indirectClear, nullptr,
              "Clear resolved indirect calls: remove the comments and cross-references "
              "a previous run added",
              NO_ICON, ITEM, MENU, SUB_CODE },

            // Analysis: what the program did, recovered by replaying the
            // whole recording.
            { actions::SELF_MOD, "Self-modifying code...", &m_selfMod, nullptr,
              "Self-modifying code: every instruction the program wrote before "
              "running it, with the write",
              NO_ICON, ITEM, MENU, SUB_ANALYSIS },
            { actions::STRINGS, "Recover strings...", &m_recoverStrings, nullptr,
              "Recover strings: replay the recording and list every string the "
              "program had in memory, with where it appeared",
              NO_ICON, ITEM, MENU, SUB_ANALYSIS },
            { actions::BUFFERS, "Recover buffers...", &m_recoverBuffers, nullptr,
              "Recover buffers: replay the recording and list every buffer the "
              "program filled, with the code that wrote it",
              NO_ICON, ITEM, MENU, SUB_ANALYSIS },
            { actions::HEATMAP, "Memory heatmap", &m_heatmap, nullptr,
              "Memory heatmap: which pages the program read, wrote and ran from, and when, "
              "drawn as a grid of address against time",
              NO_ICON, GROUP, MENU, SUB_ANALYSIS },
            { actions::MEM_TIMELINE, "Memory timeline", &m_memTimeline, nullptr,
              "Memory timeline: every allocation, protection change and free the "
              "recording made, in order, with each live region as a segment",
              NO_ICON, GROUP, MENU, SUB_ANALYSIS },
            // On the disassembly's right-click menu only.
            { actions::REREAD, "Re-read memory from the recording", &m_reread, nullptr,
              "Re-read memory: discard what IDA cached for the selected range, rebuild "
              "it from the recording and disassemble it again",
              NO_ICON, ITEM, TOOLBAR_ONLY },

            // Toolbar only. The backward movement and run-to-cursor actions sit
            // on the TTD toolbar beside their forward counterparts, which is
            // where a debugger's movement controls belong; four of the ten on
            // the menu read as an arbitrary subset. They stay registered, so
            // their shortcuts and buttons work as before.
            { actions::RUN_BACK, "Continue backwards", &m_runBack, nullptr,
              "Continue backwards: run backward to the previous breakpoint or the "
              "start of the trace",
              m_icons[ICO_REV_CONTINUE], ITEM, TOOLBAR_ONLY },
            { actions::STEP_OUT_BACK, "Step out backwards", &m_stepOutBack, nullptr,
              "Step out backwards: run backward out of the current function to the "
              "call that entered it",
              m_icons[ICO_STEP_OUT_BACK], ITEM, TOOLBAR_ONLY },
            { actions::RUN_TO_CUR_FWD, "Run to cursor", &m_runToCurFwd, nullptr,
              "Run to cursor: run forward until execution reaches the cursor address",
              m_icons[ICO_RUN_TO_CUR], ITEM, TOOLBAR_ONLY },
            { actions::RUN_TO_CUR_BACK, "Run to cursor backwards", &m_runToCurBack, nullptr,
              "Run to cursor backwards: run backward until execution reaches the "
              "cursor address",
              m_icons[ICO_RUN_TO_CUR_BACK], ITEM, TOOLBAR_ONLY },

            // The live position readout: a text-only toolbar button, not a menu
            // entry -- it is a display that happens to be clickable.
            { actions::POS_LABEL, "TTD position", &m_posLabel, nullptr,
              "Current TTD position (Sequence:Steps) -- click to copy it to the clipboard",
              NO_ICON, ITEM, TOOLBAR_ONLY },
        };

        // Every TTD handler reaches the plugin's state through one context.
        // AttachTrace is not in the table and carries its own callback.
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

    // Start replaying the recording this database was created from.
    //
    // No prompting here: this is the body of the TTD menu action, where the
    // user has already said what they want. offer_trace_session() is the one that
    // asks.
    void Plugin::start_trace_session()
    {
        TraceLink link;
        if ( !trace_link_read(&link) )
        {
            trace_link_mark_start(false);
            warning("This database was not created from a TTD trace, so there is "
                    "nothing to replay.\n\nUse Debugger > Switch debugger to attach "
                    "a trace to it instead.");
            return;
        }
        if ( get_process_state() != DSTATE_NOTASK )
        {
            trace_link_mark_start(false);
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
            {
                trace_link_mark_start(false);   // the user declined, nothing broke
                return;
            }
            link.trace_path = chosen;
            trace_link_set_path(chosen);
        }

        if ( !select_trace_debugger(link.trace_path.c_str()) )
        {
            trace_link_mark_start(false);       // reported already, nothing broke
            return;
        }
        start_process(link.trace_path.c_str(), "", "");
    }

    bool Plugin::select_trace_debugger(const char *trace_path, bool quiet)
    {
        // Say where the trace is before trying to switch, and whether or not
        // the switch works. This is what puts the .run into Debugger > Process
        // options, and it is the part that matters most: IDA's Application file
        // browser filters on "*.exe" and no SDK field controls that filter, so a
        // path that is already filled in is the difference between the feature
        // working and the user hunting for their trace behind a wrong filter.
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
                // Assigning ::dbg by hand is not a fallback. init() may do it
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

    // Runs from IDA's request queue, which is dispatched on the main thread when
    // IDA is idle. Starting a debugger session rebases the program and replaces
    // the loader's segments, so it must not happen from inside a timer callback
    // partway through the kernel's own work.
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
        // ui_ready_to_run fires while a freshly created database is still being
        // auto-analysed. Starting a debugger session there rebases the program
        // and lays debugger segments over the loader's while the analysis queue
        // is walking them, which crashed IDA outright. Wait it out.
        if ( !auto_is_ok() )
            return ATTACH_POLL_MS;      // not yet; ask again
        execute_ui_requests(new start_request_t(p), nullptr);
        return -1;
    }

    // Replay another recording in this database: a fork shares the
    // recording's program and modules, so the same database serves it.
    //
    // All of it runs from a timer, outside whatever asked (the Fork
    // manager's Enter, which must not see its chooser refreshed under it):
    // end the session, wait until IDA is done with it, start the new one.
    // The request lives only while that runs, so a switch that cannot
    // happen is dropped, not carried over to some later session's end.
    void Plugin::switch_trace(const qstring &path)
    {
        if ( m_mgr.is_active() && same_trace_path(path, m_mgr.trace_path()) )
            return;
        m_switchTo       = path;
        // Ending the session closes the debugging session's windows; the
        // Fork manager is opened again at the new session's first stop.
        // A reopen still pending from the last switch carries over.
        m_reopenForkManager = m_reopenForkManager || fork_manager_is_open();
        m_switchExitSent = false;
        m_switchTimer.cancel();
        m_switchTimer.arm(10, switch_cb, this);
    }

    // Both halves of a switch run from IDA's request queue, like the
    // automatic start (start_request_t): ending a session and starting one
    // from inside a timer callback is what made IDA stop with internal
    // error 40183.
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
                warning("Could not start the replay of %s: the TTD debugger could not be selected.", path.c_str());
            return false;
        }
    };

    void Plugin::switch_exit()
    {
        if ( m_switchTo.empty() || get_process_state() == DSTATE_NOTASK )
            return;
        qstring path;
        path.swap(m_switchTo);
        // Close the Fork manager now, while the session is still an ordinary
        // one, rather than leave it to IDA to tear down as the session ends.
        // It is opened again at the new session's first stop.
        close_fork_manager_window();
        // IDA's own request queue chains the two: the start runs only once
        // IDA is done with the old session. Starting it ourselves as soon as
        // the process state read "no process" raced IDA's end-of-session work
        // and now and then stopped it with internal error 40183.
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
            // A session is running: end it and start the new one through
            // IDA's request queue (switch_exit).
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

    bool Plugin::start_trace_at(const char *path)
    {
        if ( !select_trace_debugger(path) )
            return false;
        start_process(path, "", "");
        return true;
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

        // Both actions go in the part of the TTD menu that is there outside a
        // session: these are what start one. Registered here rather than in
        // the constructor because they are only meaningful for a database
        // that came from a recording.
        if ( !m_attachRegistered )
        {
            m_attachRegistered = true;      // one attempt, whatever it yields
            register_action(ACTION_DESC_LITERAL_PLUGMOD(
                actions::ATTACH_TRACE, "Start the TTD replay for this database",
                &m_attachTrace, this, nullptr, nullptr, -1));
            if ( register_action(ACTION_DESC_LITERAL_PLUGMOD(
                     actions::AUTO_START, "Replay the TTD trace when this database opens",
                     &m_autoStart, this, nullptr, nullptr, -1)) )
            {
                update_action_checkable(actions::AUTO_START, true);
                update_action_checked(actions::AUTO_START,
                                      trace_link_autostart() != TL_NO);
            }
            rebuild_ttd_menu();
        }

        // Do this first: whether or not the replay starts, the database should be
        // pointed at the right backend with the right trace path, so Debugger >
        // Process options and Start process just work.
        if ( qfileexist(link.trace_path.c_str()) )
            select_trace_debugger(link.trace_path.c_str(), true);

        // Opening a recording is a request to replay it, so nothing is asked
        // here. The TTD menu carries a toggle for anyone who wants to open
        // the database without starting a session.
        if ( trace_link_autostart() == TL_NO )
            return;

        // A mark left over from last time means the previous automatic start did
        // not get as far as a running session. Clear it and stay put, so this
        // database can at least be opened and the automatic start switched off.
        if ( trace_link_start_marked() )
        {
            trace_link_mark_start(false);
            msg("[ida-ttd] the last automatic replay start for this database did "
                "not finish, so it was not repeated. Start it by hand from "
                "TTD > Start the TTD replay for this database, or leave it "
                "off with the toggle beside it.\n");
            return;
        }

        trace_link_mark_start(true);
        start_trace_session();
    }

    // Register every TTD action (and therefore every TTD shortcut) and build the
    // TTD menu. Called from show_actions() when a trace becomes active; the
    // matching unregister happens in hide_actions() when the trace is unloaded.
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

        // Checkable menu entry, ticked from the database's own setting.
        update_action_checkable(actions::COVERAGE_AUTO, true);
        update_action_checked(actions::COVERAGE_AUTO, coverage_auto_enabled());
        update_action_checkable(actions::INDIRECT_AUTO, true);
        update_action_checked(actions::INDIRECT_AUTO, callsites_auto_enabled());

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
                "Install the backend that opens Sogen recordings (.sogttd) and records "
                "forks: ida-ttd-sogen.dll, or a release zip holding it, copied into "
                "ida-ttd\\backends in your IDA user directory", -1));
        }

        // From scratch, in order. Deleting a menu takes its items with it;
        // the actions stay registered.
        delete_menu(SUB_BACKENDS);
        for ( const SubmenuDesc &s : TTD_SUBMENUS )
            delete_menu(s.name);
        delete_menu(TTD_MENU);

        // create_menu() must run first: attach_action_to_menu() resolves its path
        // against menus that already exist and uses it only to position the item,
        // so attaching to "TTD/..." before the menu exists silently does nothing.
        //
        // No position argument: create_menu() would read one as the name of an
        // existing menu, or a path to a menu item, and nest TTD inside it. With
        // none given, IDA appends the menu to the menu bar.
        create_menu(TTD_MENU, "TTD");
        bool above = false;     // anything in the menu yet, to separate from

        if ( m_actionsRegistered )
        {
            attach_session_menu();
            above = true;
        }

        if ( m_attachRegistered )
        {
            attach_action_to_menu(TTD_MENU_PATH, actions::ATTACH_TRACE,
                                  SETMENU_APP | (above ? SETMENU_ENSURE_SEP : 0));
            attach_action_to_menu(TTD_MENU_PATH, actions::AUTO_START, SETMENU_APP);
            above = true;
        }

        // Backends, one section per backend with a separator between them.
        // A separator goes above a menu item, not above a submenu: the one
        // above Backends is a hidden action just above it.
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
    }

    // The session's part of the TTD menu: every row of the action table that
    // goes on the menu, in their submenus.
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

    // Drop every TTD action, which also kills their shortcuts and removes them
    // from the menu/toolbars: nothing TTD-specific responds outside a session.
    void Plugin::unregister_actions()
    {
        if ( !m_actionsRegistered )
            return;

        for ( const ActionDesc &d : m_actions )
            unregister_action(d.id);

        // The next session may be over a different database, so neither the
        // cached bookmark list nor the "user cancelled this sweep" set may
        // carry across.
        m_bookmarks.invalidate();
        m_autoCoverDeclined.clear();
        m_autoCoverFunc = BADADDR;
        m_actionsRegistered = false;
        // The menu stays, with what is there outside a session.
        rebuild_ttd_menu();
    }

    // Re-skin the native debug-movement actions with the codicon glyphs. IDA
    // registers some of these actions lazily (e.g. ThreadRunToCursorBackwards may
    // not exist at the first show) and also resets their icons whenever it rebuilds
    // the debugger toolbars (e.g. after a memory-cache invalidation on a TTD jump),
    // so this must be reapplied repeatedly -- at session start and on every stop.
    // Does nothing without an active trace: the override is global, so IDA's other
    // debuggers must keep their own icons.
    void Plugin::reskin_actions()
    {
        if ( !m_actionsRegistered )
            return;

        CASSERT(ICO_NATIVE_COUNT == qnumber(NATIVE_MOVEMENT_ACTIONS));

        for ( size_t i = 0; i < ICO_NATIVE_COUNT; i++ )
        {
            const char *name = NATIVE_MOVEMENT_ACTIONS[i];
            // Remember IDA's own icon the first time the action is found. It
            // cannot be captured in one shot: several of these are registered
            // lazily, and once one is overridden, querying it again would just
            // return the codicon.
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
        // Where a fork is being prepared, say so: what is shown there is the
        // fork's changes, not the recording.
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
        // Pad to the widest label shown this session with figure spaces,
        // which are as wide as a digit; ordinary spaces are narrower, so the
        // toolbar would still shift.
        static const char FIGURE_SPACE[] = "\xE2\x80\x87";
        m_posLabelChars = std::max(m_posLabelChars, label.length());
        for ( size_t n = label.length(); n < m_posLabelChars; n++ )
            label.append(FIGURE_SPACE);
        update_action_label(actions::POS_LABEL, label.c_str());
    }

    // Every open disassembly view, by title: the ones the user opened and the
    // one the debugger desktop names after the instruction pointer.
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

    // The first resume after a stop has settled is the user starting a
    // movement, and the widget with focus is the one they started it from:
    // the key or toolbar button that asked for it does not move the focus.
    // Later resumes before the stop settles belong to the same movement.
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

    // Stepping from pseudocode, IDA opens the function the stop is in with
    // Hex-Rays, and a stop in code that is not a function (or that Hex-Rays
    // cannot take) raises a "Decompilation failure" dialog -- one per step
    // through such code. The stop is known once ev_resume has carried the
    // movement out, before IDA does anything with it, so the case without a
    // function is caught here. Asking Hex-Rays itself has to wait for the stop
    // notification, where memory can be read (check_stop_decompiles()).
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
        m_quietSaved = batch;
        batch        = true;
        m_quiet      = true;
    }

    void Plugin::unquiet_ui()
    {
        if ( !m_quiet )
            return;
        batch   = m_quietSaved;
        m_quiet = false;
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

    // Leave exactly one pseudocode view on the stop, and bring it to the front.
    //
    // Stepping from pseudocode into another function, IDA's source-level
    // debugging opens that function in a view of its own, so every call stepped
    // into left one more window behind. IDA then reuses that view while the
    // steps stay in the function, and would only open another if it were
    // closed -- so its view is the one kept, and the one the step started from
    // is closed. When IDA opened nothing, the view the step started from is
    // moved to the function instead.
    void Plugin::do_after_stop()
    {
        // Warnings stay in the output window until all of this is done, not
        // just until it starts: activating, refreshing and moving pseudocode
        // views below makes Hex-Rays decompile, and a function it cannot take
        // would otherwise raise a "Decompilation failure" dialog per step.
        struct Unquiet
        {
            Plugin *p;
            ~Unquiet() { p->unquiet_ui(); }
        } unquiet{ this };
        restore_renderers();
        settle_stop();
        // Both write to the database or open windows, so they wait for here
        // rather than running inside IDA's stop notification.
        if ( m_mgr.is_active() )
            coverage_settle_recording_change();
        // The stop may have shown a function painted since its pseudocode
        // was last printed.
        refresh_pseudocode_views();
        reopen_fork_manager();
        // Which recording is being replayed may have changed: redraw it here,
        // never at the session's start or end (see switch_exit).
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
        else if ( pc != BADADDR )
        {
            func_entry_info_t fi;
            if ( get_func_entry_info(&fi, pc) && pseudocode_function(from) != fi.start_ea )
                show_in_pseudocode(from, pc);
        }
        diag("refocus: from %p, %d opened, kept %p showing %llX, pc %llX",
             from, (int)opened.size(), keep,
             (unsigned long long)pseudocode_function(keep), (unsigned long long)pc);
        activate_widget(keep, true);
        // Only a stop that follows a movement begun by begin_movement() may
        // close a view; the next one starts from scratch.
        m_stepView = nullptr;
        m_viewsBefore.clear();
    }

    void Plugin::try_hook_decompiler()
    {
        if ( !m_haveDecompiler )
            m_haveDecompiler = init_decompiler();
    }

    // Source-info providers are registered by name and there is no API to
    // enumerate them, so the ones that carry line information for native code
    // are named here. A name that is not registered simply yields nullptr.
    static const char *const SRCINFO_PROVIDERS[] = { "PDB", "pdb", "DWARF", "dwarf" };

    void Plugin::suspend_source_debugging()
    {
        for ( const char *n : SRCINFO_PROVIDERS )
        {
            srcinfo_provider_t *sp = get_srcinfo_provider(n);
            // Only ever turn off something that is currently on, and remember
            // exactly what was turned off: a provider the user had already
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

    int idaapi Plugin::autocover_cb(void *ud)
    {
        static_cast<Plugin *>(ud)->do_auto_coverage();
        return -1;  // one-shot: unregister
    }

    // Decide, on a stop, whether the function stopped in should be measured.
    // The work itself is deferred: a sweep pumps the UI behind a wait box, and
    // starting that from inside a debugger notification risks the user driving
    // the debugger again while the notification is still running.
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
        // Re-read the bounds: the deferred hop gave analysis a chance to change
        // them, and a stale end would measure the wrong span.
        func_entry_info_t fi;
        if ( !get_func_entry_info(&fi, start) || fi.start_ea != start )
            return;
        bool changed = false, retyped = false;
        if ( auto_coverage_wanted(start) )
        {
            if ( !cover_function(&m_mgr, fi.start_ea, fi.end_ea) )
            {
                // Cancelled, or it could not run. Do not ask again this session --
                // otherwise the next single step inside the same function re-offers
                // the sweep the user just stopped.
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

    // Called from the stop handler. IDA brings the disassembly to the front,
    // switches its view mode and opens pseudocode as part of its own post-stop
    // handling, so whatever is put right afterwards has to wait until it is
    // done: a short timer, then the next turn of the UI loop.
    void Plugin::schedule_after_stop()
    {
        m_refocusTimer.arm(DEFER_MS, refocus_cb, this);
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
                    p->manager().modules().resolve_symbols((ea_t)mi.base);
                    p->manager().modules().load_pdb((ea_t)mi.base);  // silent PDB symbols
                }
                if ( code == dbg_process_start )
                {
                    trace_link_mark_start(false);   // the start survived
                    p->reset_step_state();
                    p->show_actions();   // (re)build the toolbar inside the now-active debugger desktop
                }
                p->update_position_label();
                break;
            }
            case dbg_suspend_process:
                // Fires after every stop (step/breakpoint/goto), once memory is
                // valid for the new position: name newly-revealed module exports,
                // disassemble around RIP, and refresh the toolbar readout.
                p->manager().on_suspended();
                // Before anything else can make IDA decompile the stop.
                p->check_stop_decompiles();
                // Last chance to pick the decompiler up, for installs where
                // it loads after everything above has already run.
                p->try_hook_decompiler();
                p->update_position_label();
                // Queued before the coverage sweep so that it runs first: the
                // sweep's wait box must not be shown in batch mode.
                p->schedule_after_stop();
                // Measure the function stopped in, if it has not been measured
                // before and the user has left that switched on. Queued, not run
                // here -- see schedule_auto_coverage().
                p->schedule_auto_coverage();
                // IDA can rebuild the debug toolbars across a stop and reset the plugin's
                // action icons -- reapply them (cheap, belt-and-suspenders).
                p->reskin_actions();
                // Exports were just (re)named; refresh the call stack so frames
                // show names rather than raw VAs.
                refresh_call_stack();
                // A travel from a list is done once all of the above is.
                p->manager().end_travel_wait();
                break;
            case dbg_process_exit:
                // The trace session is over (the user terminated it). Drop the
                // toolbar and unregister the TTD actions right away rather than
                // waiting for ev_term_debugger, which only fires when the
                // debugger backend itself is unloaded.
                p->hide_actions();
                p->manager().end_travel_wait();
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
                // Only augment menus while this debugger backend is the active one
                // and a trace is loaded (outside a session the actions do not
                // even exist).
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
                    // Time-travel to the address under the cursor (works in both
                    // the disassembly and the decompiler).
                    attach_action_to_popup(widget, popup, actions::RUN_TO_CUR_FWD, "TTD/");
                    attach_action_to_popup(widget, popup, actions::RUN_TO_CUR_BACK, "TTD/");
                    attach_action_to_popup(widget, popup, actions::ADD_BOOKMARK, "TTD/");
                }
                // Forking, wherever the user would change the program's
                // state: code, memory, registers. Only for a recording that
                // can be forked, and Record / Discard only with a fork begun.
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
                    attach_action_to_popup(widget, popup, actions::VALUE_ORIGIN, "TTD/");
                    attach_action_to_popup(widget, popup, actions::ORIGIN_GRAPH, "TTD/");
                }
                if ( is_value_origin_listing(widget) )
                    attach_action_to_popup(widget, popup, actions::ORIGIN_GRAPH);
                break;
            }
            case ui_ready_to_run:
                // Everything is loaded by now, decompiler included. This is the
                // point the SDK documents for plugins that need the finished UI.
                p->try_hook_decompiler();
                // IDAPython is surely loaded by now.
                register_python_module();
                // The TTD menu, with Backends, in every database: the TTD
                // runtime is needed before a Microsoft recording can open.
                p->rebuild_ttd_menu();
                // Starting a debugger session from inside a UI notification is
                // asking for reentrancy, and the prompt is modal. Hand it back to
                // the message loop and do it a turn later.
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

    // HT_IDB: names changed (e.g. a PDB download finished and IDA applied
    // symbols) -- refresh the call stack so frames pick up the new names.
    ssize_t idaapi IdbEventListener::on_event(ssize_t code, va_list va)
    {
        if ( p == nullptr || !p->manager().is_active() )
            return 0;
        if ( code == idb_event::renamed )
        {
            ea_t        ea       = va_arg(va, ea_t);
            const char *new_name = va_arg(va, const char *);
            // Debugger views -- the call-stack window in particular -- resolve
            // <name>+offset through the DEBUG-name list, not plain IDB names. The
            // exports (set_name) and the PDB plugin's symbols only populate IDB
            // names, so the call stack showed raw addresses. Mirror every applied
            // name into the debug-name list so frames render as <name>+offset.
            if ( new_name != nullptr && new_name[0] != '\0' )
                set_debug_name(ea, new_name);
            // As PDB/export symbols name functions in system modules, mark those
            // functions FUNC_LIB so library code is grouped/de-emphasized (the PDB
            // plugin defines them but does not flag them as library).
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

        // What IDA asks of the debugger, around a session's start and end,
        // for the diagnostics log. The frequent polls and reads are left out.
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
                // Re-read the database's bitness here rather than trusting what
                // it was when this object was constructed. The constructor runs
                // at plugin load, and nothing documents whether that is before or
                // after a loader has finished setting up a new database -- but by
                // the time a session is being initialised the answer is settled.
                // Getting it wrong is not cosmetic: it picks the register table.
                configure_debugger(m_debugger, inf_is_64bit());
                m_tracer.set_64bit(inf_is_64bit());
                // The user has just chosen this debugger, possibly by hand because the
                // programmatic switch above did not work. Point the Application
                // field at the recording so they do not have to find it behind
                // IDA's "*.exe" filter -- unless it already names a recording
                // that exists. This runs for every session, and a session
                // started on a fork of the recording (the Fork manager's
                // switch) must not be turned back to the recording itself.
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
                // Every kind IDA has -- execute, read, write, read/write --
                // at any address and size; whether the engine can arm it is
                // answered by ev_update_bpts, per breakpoint.
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
    "Loads time travel recordings (Microsoft TTD, Sogen) and lets you navigate them in IDA.",
    "TTD trace replayer",
    nullptr
};
