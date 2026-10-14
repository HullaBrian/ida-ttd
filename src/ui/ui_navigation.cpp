// Moving through the recording: the timeline listing, the movement actions IDA
// has no native equivalent for, and the toolbar position readout.
#include "ui/ui.h"
#include "ui/clipboard.h"
#include "common/trace_link.h"

namespace idattd
{
    //=======================================================================
    // PositionChooser
    //=======================================================================
    static const int   g_pos_widths[] = { 16, 48 };
    static const char *g_pos_header[] = { "Position", "Event" };

    PositionChooser::PositionChooser(TraceManager *mgr)
        : chooser_t(0, qnumber(g_pos_widths), g_pos_widths, g_pos_header, "TTD Timeline"),
          m_mgr(mgr)
    {
        if ( m_mgr != nullptr )
            m_positions = m_mgr->collect_positions();
    }

    size_t idaapi PositionChooser::get_count() const
    {
        return m_positions.size();
    }

    void idaapi PositionChooser::get_row(qstrvec_t *cols, int * /*icon*/,
                                         chooser_item_attrs_t * /*attrs*/, size_t n) const
    {
        if ( n >= m_positions.size() )
            return;
        const TraceManager::NamedPosition &e = m_positions[n];
        cols->at(0) = format_position(e.pos);
        cols->at(1) = e.name.c_str();
    }

    chooser_t::cbret_t idaapi PositionChooser::enter(size_t n)
    {
        if ( m_mgr != nullptr && m_mgr->is_active() && n < m_positions.size() )
        {
            m_mgr->set_next_position(m_positions[n].pos);
            request_continue_process();
            run_requests();
        }
        return cbret_t(n, NOTHING_CHANGED);
    }

    //=======================================================================
    // Movement actions
    //=======================================================================
    int idaapi RunBackHandler::activate(action_activation_ctx_t *)
    {
        if ( mgr() != nullptr )
            mgr()->request_run(false);
        return 1;
    }

    int idaapi StepOutBackHandler::activate(action_activation_ctx_t *)
    {
        if ( mgr() != nullptr )
            mgr()->request_step_out_backward();
        return 1;
    }

    // The address under the cursor, which works from the disassembly and the
    // decompiler alike; the screen ea when the context did not carry one.
    static ea_t context_ea(const action_activation_ctx_t *ctx)
    {
        return ctx != nullptr && ctx->cur_ea != BADADDR ? ctx->cur_ea : get_screen_ea();
    }

    int idaapi RunToCursorBackHandler::activate(action_activation_ctx_t *ctx)
    {
        if ( mgr() != nullptr )
            mgr()->request_run_to_cursor_backward(context_ea(ctx));
        return 1;
    }

    int idaapi RunToCursorFwdHandler::activate(action_activation_ctx_t *ctx)
    {
        if ( mgr() != nullptr )
            mgr()->request_run_to_cursor_forward(context_ea(ctx));
        return 1;
    }

    int idaapi OpenTimelineHandler::activate(action_activation_ctx_t *)
    {
        if ( mgr() == nullptr || !mgr()->is_active() )
        {
            warning("The TTD timeline is only available while replaying a trace.");
            return 1;
        }
        PositionChooser *ch = new PositionChooser(mgr());
        ch->choose();
        return 1;
    }

    int idaapi GotoPositionHandler::activate(action_activation_ctx_t *)
    {
        if ( mgr() != nullptr )
            mgr()->goto_position();
        return 1;
    }

    int idaapi PositionCopyHandler::activate(action_activation_ctx_t *)
    {
        if ( mgr() == nullptr || !mgr()->is_active() )
            return 1;
        qstring s = format_position(mgr()->current_position());
        if ( s.empty() )
            return 1;
        copy_to_clipboard(s.c_str());
        msg("[ida-ttd] copied position %s to clipboard.\n", s.c_str());
        return 1;
    }

    int idaapi AnalyzeFuncHandler::activate(action_activation_ctx_t *)
    {
        if ( mgr() == nullptr || !mgr()->is_active() )
        {
            warning("Analysis is only available while replaying a trace.");
            return 1;
        }
        mgr()->analyze_whole_function();
        return 1;
    }

    //=======================================================================
    // Starting the replay for a database that came from a .run
    //=======================================================================
    int idaapi AttachTraceHandler::activate(action_activation_ctx_t *)
    {
        if ( start_session )
            start_session();
        return 1;
    }

    action_state_t idaapi AttachTraceHandler::update(action_update_ctx_t *)
    {
        // Only offer it when there is a recording to attach to and nothing is
        // running yet -- otherwise it would restart a live session.
        if ( !trace_link_present() || get_process_state() != DSTATE_NOTASK )
            return AST_DISABLE;
        return AST_ENABLE_ALWAYS;
    }

    int idaapi AutoStartHandler::activate(action_activation_ctx_t *)
    {
        bool on = trace_link_autostart() != TL_NO;
        trace_link_set_autostart(on ? TL_NO : TL_YES);
        update_action_checked(actions::AUTO_START, !on);
        return 1;
    }

    action_state_t idaapi AutoStartHandler::update(action_update_ctx_t *)
    {
        if ( !trace_link_present() )
            return AST_DISABLE;
        return AST_ENABLE_ALWAYS;
    }

    //=======================================================================
    // Travel, then show memory in the hex view
    //=======================================================================
    // IDA moves its views to the instruction pointer when the debugger stops,
    // and a synchronized hex view goes with them, so the jump waits for the
    // stop: show_pending_bytes() runs after IDA's own post-stop handling.
    static ea_t g_pendingBytes = BADADDR;

    static TWidget *open_hex_view()
    {
        for ( int i = 1; i <= 9; i++ )
        {
            qstring title;
            title.sprnt("Hex View-%d", i);
            TWidget *w = find_widget(title.c_str());
            if ( w != nullptr && get_widget_type(w) == BWN_HEXVIEW )
                return w;
        }
        return nullptr;
    }

    static void show_bytes(TWidget *hex, ea_t ea)
    {
        activate_widget(hex, true);
        ea_viewer_history_push_and_jump(hex, ea, 0, 0, 0);
    }

    bool travel_and_show_bytes(TraceManager *mgr, Position p, ea_t ea)
    {
        g_pendingBytes = BADADDR;
        if ( mgr == nullptr || !mgr->is_active() )
            return false;
        TWidget *hex = ea != BADADDR ? open_hex_view() : nullptr;
        if ( !p.is_valid() || p == mgr->current_position() )
        {
            if ( hex != nullptr )
                show_bytes(hex, ea);
            return hex != nullptr;
        }
        if ( hex != nullptr )
            g_pendingBytes = ea;
        mgr->set_next_position(p);
        request_continue_process();
        run_requests();
        return hex != nullptr;
    }

    void show_pending_bytes()
    {
        ea_t ea = g_pendingBytes;
        g_pendingBytes = BADADDR;
        if ( ea == BADADDR )
            return;
        TWidget *hex = open_hex_view();
        if ( hex != nullptr )
            show_bytes(hex, ea);
    }
}
