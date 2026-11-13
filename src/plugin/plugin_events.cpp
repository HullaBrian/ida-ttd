// IDA's notifications: the HT_DBG, HT_UI and HT_IDB listeners, and the
// HT_IDD switch that hands the debugger's requests to TraceManager.
#include "plugin/plugin_internal.h"
#include "common/trace_link.h"
#include "core/backend_module.h"
#include "core/backend_registry.h"
#include "core/diag.h"
#include "debugger/registers.h"

namespace idattd
{
    // Flag the call stack and stack views for refresh. The mask is built by
    // hand because IWID_*/builtin_widget_mask_from_id use a uint128 << that
    // ida.lib does not export (link error on MSVC).
    static void refresh_call_stack()
    {
        const uint64 m = (uint64(1) << BWN_CALL_STACK) | (uint64(1) << BWN_STKVIEW);
        mark_builtin_widgets(uint128(m, uint64(0)));
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
                    // Forking at the playhead, as in TTD > Forks.
                    if ( p->can_fork_recording() )
                    {
                        attach_action_to_popup(widget, popup, nullptr);
                        attach_action_to_popup(widget, popup, actions::FORK);
                        attach_action_to_popup(widget, popup, actions::FORK_RECORD);
                        attach_action_to_popup(widget, popup, actions::FORK_DISCARD);
                    }
                    break;
                }
                int wt = get_widget_type(widget);
                if ( wt == BWN_DISASM || wt == BWN_PSEUDOCODE )
                {
                    // Travel to the address under the cursor.
                    attach_action_to_popup(widget, popup, actions::RUN_TO_CUR_FWD, "TTD/");
                    if ( p->can_reverse() )
                        attach_action_to_popup(widget, popup, actions::RUN_TO_CUR_BACK, "TTD/");
                    attach_action_to_popup(widget, popup, actions::ADD_BOOKMARK, "TTD/");
                }
                // Forking, wherever program state is changed (code, memory,
                // registers), for forkable recordings; Record and Discard only
                // with a fork begun.
                if ( (wt == BWN_DISASM || wt == BWN_PSEUDOCODE || wt == BWN_HEXVIEW || wt == BWN_CPUREGS)
                  && p->can_fork_recording() )
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
                p->settings_after_python();
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
