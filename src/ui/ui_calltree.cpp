// The call tree of the function at the cursor: the listing and its action.
#include "ui/ui.h"
#include "ui/names.h"

namespace idattd
{
    static const int   g_ct_widths[] = { 16, 60, 30, 16 };
    static const char *g_ct_header[] = { "Position", "Call", "From", "Returns at" };

    // "name+0x12" when IDA knows a function there, else the address.
    static qstring code_name(ea_t ea)
    {
        qstring s;
        ea_t fs = get_func_start(ea);
        if ( fs == BADADDR )
        {
            if ( get_name(&s, ea) <= 0 || s.empty() )
                s.sprnt("0x%llX", (uint64_t)ea);
        }
        else if ( fs == ea )
        {
            s = func_display_name(fs);
        }
        else
        {
            s.sprnt("%s+0x%llX", func_display_name(fs).c_str(), (uint64_t)(ea - fs));
        }
        return s;
    }

    CallTreeChooser::CallTreeChooser(TraceManager *mgr, CallTree &&tree)
        : chooser_t(0, qnumber(g_ct_widths), g_ct_widths, g_ct_header, nullptr),
          m_mgr(mgr), m_tree(std::move(tree))
    {
        m_title.sprnt("TTD call tree: %s [%d]",
                      m_tree.root != BADADDR ? code_name(m_tree.root).c_str() : "here",
                      (int)m_tree.rows.size());
        title = m_title.c_str();
    }

    size_t idaapi CallTreeChooser::get_count() const
    {
        return m_tree.rows.size();
    }

    void idaapi CallTreeChooser::get_row(qstrvec_t *cols, int *, chooser_item_attrs_t *attrs, size_t n) const
    {
        if ( n >= m_tree.rows.size() )
            return;
        const CallTreeRow &r = m_tree.rows[n];
        cols->at(0) = format_position(r.pos);
        qstring call;
        for ( int d = 0; d < r.depth && d < 64; d++ )
            call.append("|  ");
        call.append(code_name(r.target));
        if ( !r.is_call )
            call.append("  (jump)");
        cols->at(1) = call;
        cols->at(2) = code_name(r.site);
        if ( r.ret_pos.is_valid() )
            cols->at(3) = format_position(r.ret_pos);
        else
            cols->at(3) = r.is_call ? "never" : "";
        // The function's own calls stand out from what they called in turn.
        if ( r.depth == 0 && attrs != nullptr )
            attrs->flags |= CHITEM_BOLD;
    }

    ea_t idaapi CallTreeChooser::get_ea(size_t n) const
    {
        return n < m_tree.rows.size() ? m_tree.rows[n].site : BADADDR;
    }

    chooser_t::cbret_t idaapi CallTreeChooser::enter(size_t n)
    {
        if ( m_mgr != nullptr && m_mgr->is_active() && n < m_tree.rows.size() )
        {
            m_mgr->set_next_position(m_tree.rows[n].pos);
            request_continue_process();
            run_requests();
        }
        return cbret_t(n, NOTHING_CHANGED);
    }

    int idaapi CallTreeHandler::activate(action_activation_ctx_t *)
    {
        if ( mgr() == nullptr || !mgr()->is_active() )
        {
            warning("The call tree is only available while replaying a trace.");
            return 1;
        }
        CallTree tree;
        qstring err;
        if ( !build_call_tree(mgr(), &tree, &err) )
        {
            if ( !tree.cancelled )
                warning("Could not build the call tree: %s", err.c_str());
            return 1;
        }
        msg("[ida-ttd] call tree: %d call(s) from %s to %s%s%s%s.\n", (int)tree.rows.size(),
            format_position(tree.from).c_str(), format_position(tree.to).c_str(),
            tree.from_cursor ? " (the function's entry was not found; from the cursor)" : "",
            tree.truncated ? " (cut short)" : "",
            tree.cancelled ? " (stopped early)" : "");
        if ( tree.rows.empty() )
        {
            info("The function made no calls during this run.");
            return 1;
        }
        CallTreeChooser *ch = new CallTreeChooser(mgr(), std::move(tree));
        ch->choose();
        return 1;
    }
}
