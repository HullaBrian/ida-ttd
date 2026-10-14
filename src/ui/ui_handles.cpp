// The handles the program opened and closed: the listing and its action.
#include "ui/ui.h"
#include "ui/names.h"

namespace idattd
{
    static const int   g_hd_widths[] = { 10, 14, 60, 14, 22, 14, 8 };
    static const char *g_hd_header[] = { "Handle", "Type", "Name", "Opened", "By", "Closed", "Thread" };

    HandlesChooser::HandlesChooser(TraceManager *mgr, std::vector<HandleRecord> &&rows)
        : chooser_t(CH_CAN_EDIT | CH_CAN_REFRESH, qnumber(g_hd_widths), g_hd_widths, g_hd_header, nullptr),
          m_mgr(mgr), m_rows(std::move(rows))
    {
        set_title();
        popup_names[POPUP_EDIT]    = "Travel to where it was closed";
        popup_names[POPUP_REFRESH] = "Rebuild from the recording";
    }

    void HandlesChooser::set_title()
    {
        size_t open = 0;
        for ( const HandleRecord &h : m_rows )
            open += h.opened.is_valid() && !h.closed.is_valid();
        m_title.sprnt("TTD handles [%d, %d open at the end]", (int)m_rows.size(), (int)open);
        title = m_title.c_str();
    }

    chooser_t::cbret_t idaapi HandlesChooser::refresh(ssize_t n)
    {
        std::vector<HandleRecord> rows;
        bool cancelled = false;
        if ( m_mgr != nullptr && m_mgr->is_active() && list_handles(m_mgr, &rows, &cancelled) && !cancelled )
            m_rows = std::move(rows);
        set_title();
        return cbret_t(n, ALL_CHANGED);
    }

    size_t idaapi HandlesChooser::get_count() const
    {
        return m_rows.size();
    }

    void idaapi HandlesChooser::get_row(qstrvec_t *cols, int * /*icon*/,
                                        chooser_item_attrs_t *attrs, size_t n) const
    {
        if ( n >= m_rows.size() )
            return;
        const HandleRecord &h = m_rows[n];
        cols->at(0).sprnt("0x%llX", (unsigned long long)h.handle);
        cols->at(1) = h.type;
        cols->at(2) = h.name;
        cols->at(3) = h.opened.is_valid() ? format_position(h.opened) : qstring("before");
        cols->at(4) = h.opened_by;
        cols->at(5) = h.closed.is_valid() ? format_position(h.closed) : qstring("open");
        if ( h.tid != 0 )
            cols->at(6).sprnt("%X", h.tid);
        // Still open when the recording ended: what the program held on to.
        if ( attrs != nullptr && h.opened.is_valid() && !h.closed.is_valid() )
            attrs->flags |= CHITEM_BOLD;
    }

    static void travel_to(TraceManager *mgr, Position p)
    {
        if ( mgr == nullptr || !mgr->is_active() || !p.is_valid() )
            return;
        mgr->set_next_position(p);
        request_continue_process();
        run_requests();
    }

    chooser_t::cbret_t idaapi HandlesChooser::enter(size_t n)
    {
        if ( n < m_rows.size() )
            travel_to(m_mgr, m_rows[n].opened.is_valid() ? m_rows[n].opened : m_rows[n].closed);
        return cbret_t(n, NOTHING_CHANGED);
    }

    chooser_t::cbret_t idaapi HandlesChooser::edit(size_t n)
    {
        if ( n < m_rows.size() )
        {
            if ( m_rows[n].closed.is_valid() )
                travel_to(m_mgr, m_rows[n].closed);
            else
                info("This handle was still open when the recording ended.");
        }
        return cbret_t(n, NOTHING_CHANGED);
    }

    int idaapi HandlesHandler::activate(action_activation_ctx_t *)
    {
        if ( mgr() == nullptr || !mgr()->is_active() || mgr()->backend() == nullptr
          || !mgr()->backend()->capabilities().syscalls )
        {
            warning("The handle list needs a recording whose syscalls can be listed.");
            return 1;
        }
        // The list saved the last time, else built now (and saved).
        std::vector<HandleRecord> rows;
        bool cancelled = false;
        if ( load_handles(&rows) )
            msg("[ida-ttd] handles: the list saved in the database; Refresh (Ctrl+U) in it rebuilds it.\n");
        else if ( !list_handles(mgr(), &rows, &cancelled) )
            return 1;
        msg("[ida-ttd] %d handle(s)%s.\n", (int)rows.size(), cancelled ? " (cancelled)" : "");
        if ( rows.empty() )
        {
            if ( !cancelled )
                info("The recording opened no handles that could be followed.");
            return 1;
        }
        HandlesChooser *ch = new HandlesChooser(mgr(), std::move(rows));
        ch->choose();
        return 1;
    }

    action_state_t idaapi HandlesHandler::update(action_update_ctx_t *)
    {
        return mgr() != nullptr && mgr()->is_active() && mgr()->backend() != nullptr
            && mgr()->backend()->capabilities().syscalls ? AST_ENABLE : AST_DISABLE;
    }
}
