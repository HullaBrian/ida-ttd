#include "ui.h"

using namespace TTD;

namespace idattd
{
    //=======================================================================
    // PositionChooser
    //=======================================================================
    static const int   g_widths[] = { 16, 48 };
    static const char *g_header[] = { "Position", "Event" };

    PositionChooser::PositionChooser(TraceManager *mgr)
        : chooser_t(CH_KEEP, qnumber(g_widths), g_widths, g_header, "TTD Timeline"),
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
        cols->at(0).sprnt("%llX:%llX",
                          (uint64_t)e.pos.Sequence, (uint64_t)e.pos.Steps);
        cols->at(1) = e.name.c_str();
    }

    // Double-click / Enter: queue navigation to the selected position. We must
    // NOT resume the debugger synchronously from inside a chooser callback, and
    // we must never do it from get_ea() (IDA calls get_ea while rendering rows,
    // which would resume the debugger once per visible row). Hence: defer with
    // request_continue_process() + run_requests().
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
    // Action handlers
    //=======================================================================
    int idaapi StepBackHandler::activate(action_activation_ctx_t *)
    {
        if ( mgr != nullptr )
            mgr->request_backward_step();
        return 1;
    }

    int idaapi OpenTimelineHandler::activate(action_activation_ctx_t *)
    {
        if ( mgr == nullptr || !mgr->is_active() )
        {
            warning("The TTD timeline is only available while replaying a trace.");
            return 1;
        }
        // CH_KEEP: IDA takes ownership and frees the chooser when it closes.
        PositionChooser *ch = new PositionChooser(mgr);
        ch->choose();
        return 1;
    }

    int idaapi GotoPositionHandler::activate(action_activation_ctx_t *)
    {
        if ( mgr != nullptr )
            mgr->goto_position();
        return 1;
    }
}
