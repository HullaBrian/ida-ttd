// The work around a stop: noting where a movement started, keeping the
// pseudocode and disassembly views as the user had them, keeping dialogs
// out of the way, automatic coverage and restoring kept functions.
#include "plugin/plugin_internal.h"
#include "analysis/callsites.h"
#include "plugin/settings.h"
#include "core/diag.h"

namespace idattd
{
    // "Once IDA has finished what it is doing": the shortest interval that
    // still returns to the message loop first.
    static const int DEFER_MS = 10;

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
}
