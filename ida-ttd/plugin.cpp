#include "plugin.h"
#include "registers.h"

namespace idattd
{
    //-----------------------------------------------------------------------
    Plugin::Plugin()
    {
        configure_debugger(m_debugger, inf_is_64bit());
        m_mgr.set_plugin(this);

        register_actions();
        hook_event_listener(HT_IDD, this);
    }

    //-----------------------------------------------------------------------
    Plugin::~Plugin()
    {
        unhook_event_listener(HT_IDD, this);
        hide_actions();
        unregister_actions();
    }

    //-----------------------------------------------------------------------
    bool idaapi Plugin::run(size_t)
    {
        // The plugin is a debugger backend; there is no standalone action.
        info("ida-ttd: select 'TTD trace replayer' under Debugger > Switch debugger, "
             "then start with a .run trace file as the application.");
        return true;
    }

    //-----------------------------------------------------------------------
    void Plugin::register_actions()
    {
        m_stepBack.mgr = &m_mgr;
        m_timeline.mgr = &m_mgr;
        m_goto.mgr     = &m_mgr;

        register_action(ACTION_DESC_LITERAL_PLUGMOD(
            actions::STEP_BACK, "Step backwards", &m_stepBack, this,
            "Ctrl+Shift+F7", "Time travel one instruction backwards", -1));
        register_action(ACTION_DESC_LITERAL_PLUGMOD(
            actions::TIMELINE, "TTD timeline", &m_timeline, this,
            "Ctrl+Shift+T", "Open the TTD trace timeline", -1));
        register_action(ACTION_DESC_LITERAL_PLUGMOD(
            actions::GOTO_POS, "Go to position", &m_goto, this,
            "Ctrl+Shift+G", "Jump to a Sequence:Steps trace position", -1));
    }

    //-----------------------------------------------------------------------
    void Plugin::unregister_actions()
    {
        unregister_action(actions::STEP_BACK);
        unregister_action(actions::TIMELINE);
        unregister_action(actions::GOTO_POS);
    }

    //-----------------------------------------------------------------------
    void Plugin::show_actions()
    {
        attach_action_to_toolbar("DebugToolBar", actions::STEP_BACK);
        attach_action_to_toolbar("DebugToolBar", actions::TIMELINE);
        attach_action_to_toolbar("DebugToolBar", actions::GOTO_POS);
    }

    //-----------------------------------------------------------------------
    void Plugin::hide_actions()
    {
        detach_action_from_toolbar("DebugToolBar", actions::STEP_BACK);
        detach_action_from_toolbar("DebugToolBar", actions::TIMELINE);
        detach_action_from_toolbar("DebugToolBar", actions::GOTO_POS);
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
