// The plugin's lifetime: the constructor, the destructor, run() and the
// entry point. The rest of Plugin is in the plugin_*.cpp files
// (plugin_internal.h says which holds what).
#include "plugin/plugin_internal.h"
#include "analysis/callsites.h"
#include "common/trace_link.h"
#include "common/symsrv.h"
#include "common/python_eval.h"
#include "core/backend_module.h"
#include "plugin/script_api.h"
#include "plugin/settings.h"
#include "debugger/registers.h"

namespace idattd
{
    // Put ida-ttd-python\ (beside the plugin; scripts/ida_ttd.py and its
    // siblings) on IDAPython's sys.path, so `import ida_ttd` works. Safe to
    // repeat; a no-op without IDAPython or the folder. True when IDAPython is
    // loaded (so the settings could be read through it).
    static bool register_python_module()
    {
        if ( !python_available() )
            return false;
        HMODULE self = nullptr;
        wchar_t buf[MAX_PATH * 2];
        if ( !GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
                               | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                 reinterpret_cast<LPCWSTR>(&register_python_module), &self)
          || GetModuleFileNameW(self, buf, qnumber(buf)) == 0 )
            return true;
        qstring dir;
        utf16_utf8(&dir, (const wchar16_t *)buf);
        ssize_t slash = dir.rfind('\\');
        if ( slash < 0 )
            return true;
        dir.resize((size_t)slash);
        dir.append("/ida-ttd-python");
        dir.replace("\\", "/");     // a Python string literal without escapes
        if ( !qisdir(dir.c_str()) )
            return true;
        // A quote still needs escaping: a user name can hold one (O'Neil).
        dir.replace("'", "\\'");
        qstring code;
        code.sprnt("import sys\n"
                   "if '%s' not in sys.path:\n"
                   "    sys.path.append('%s')\n", dir.c_str(), dir.c_str());
        qstring err;
        if ( !eval_py(code.c_str(), &err) )
            msg("[ida-ttd] could not put %s on IDAPython's path: %s\n", dir.c_str(), err.c_str());
        return true;
    }

    static int idaapi pdb_poll_cb(void *ud);     // below

    // The live plugin. A request queued with execute_ui_requests can outlive
    // the plugin (the database closes), so each checks its pointer against
    // this first.
    Plugin *g_live_plugin = nullptr;

    Plugin::Plugin()
    {
        g_live_plugin = this;
        // The backend DLLs are not loaded here: the plugin loads in every
        // database, and the Sogen backend links its whole emulator. Every
        // path that needs one (opening a recording, the debugger's init,
        // drv.open, backends, forks) calls load_backend_modules first.
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
        m_pythonSeen = register_python_module();
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
        m_recordProgram.ctx    = &m_ctx;

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
        // hide_actions() below rebuilds the TTD menu (with Python calls for
        // its icons) when it unregisters the session's actions; the menu is
        // deleted a few lines later, so that work would be thrown away.
        m_tearingDown = true;
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

    // At ui_ready_to_run: IDAPython is loaded by now. The settings are read
    // again only if it was not when the plugin was (they then came from the
    // defaults), so a GUI start reads them once, not twice.
    void Plugin::settings_after_python()
    {
        if ( !m_pythonSeen && register_python_module() )
        {
            m_pythonSeen = true;
            load_settings();
        }
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
