// Moving through the recording: the timeline listing, the movement actions IDA
// has no native equivalent for, and the toolbar position readout.
#include "ui/ui.h"
#include "ui/clipboard.h"
#include "common/trace_link.h"
#include <expr.hpp>

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
        if ( n < m_positions.size() )
            travel_to(m_mgr, m_positions[n].pos);
        return cbret_t(n, NOTHING_CHANGED);
    }

    void travel_to(TraceManager *mgr, Position p)
    {
        if ( mgr == nullptr || !mgr->is_active() || !p.is_valid() )
            return;
        mgr->set_next_position(p);
        request_continue_process();
        run_requests();
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

    // The address under the cursor (disassembly or decompiler), else the
    // screen ea.
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

    int idaapi FullPdbHandler::activate(action_activation_ctx_t *)
    {
        if ( mgr() == nullptr || !mgr()->is_active() )
        {
            warning("Symbols can only be loaded while replaying a trace.");
            return 1;
        }
        if ( mgr()->modules().load_full_pdb(get_screen_ea()) )
            refresh_idaview_anyway();
        return 1;
    }

    int idaapi InstallRuntimeHandler::activate(action_activation_ctx_t *)
    {
        // Done in Python (HTTP, zip, a license dialog); the module is in
        // ida-ttd-python\, put on sys.path at plugin load.
        extlang_object_t py = find_extlang_by_name("Python");
        if ( py == nullptr || py->eval_snippet == nullptr )
        {
            warning("Installing the TTD runtime needs IDAPython, which is not available.\n\n"
                    "Install WinDbg (aka.ms/windbg/download) and copy its amd64\\ttd folder "
                    "to ida-ttd\\windbg\\amd64\\ttd in your IDA user directory "
                    "(%%APPDATA%%\\Hex-Rays\\IDA Pro) instead.");
            return 1;
        }
        qstring err;
        if ( !py->eval_snippet("import ida_ttd_runtime\n"
                               "ida_ttd_runtime.install_runtime()\n", &err) )
            warning("Installing the TTD runtime failed: %s", err.c_str());
        return 1;
    }

    int idaapi InstallSogenHandler::activate(action_activation_ctx_t *)
    {
        extlang_object_t py = find_extlang_by_name("Python");
        if ( py == nullptr || py->eval_snippet == nullptr )
        {
            warning("Installing the Sogen backend needs IDAPython, which is not available.\n\n"
                    "Copy ida-ttd-sogen.dll to ida-ttd\\backends\\ in your IDA user "
                    "directory (%%APPDATA%%\\Hex-Rays\\IDA Pro) instead, and restart IDA.");
            return 1;
        }
        qstring err;
        if ( !py->eval_snippet("import ida_ttd_runtime\n"
                               "ida_ttd_runtime.install_sogen()\n", &err) )
            warning("Installing the Sogen backend failed: %s", err.c_str());
        return 1;
    }

    //=======================================================================
    // Travel, then show memory in the hex view
    //=======================================================================
    // IDA moves its views (a synchronized hex view too) to the instruction
    // pointer on a stop, so the jump waits: show_pending_bytes() runs after
    // IDA's own post-stop handling.
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
        travel_to(mgr, p);
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
