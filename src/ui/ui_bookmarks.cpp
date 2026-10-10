// Saved trace positions: the listing, the name/comment form and the two actions.
#include "ui/ui.h"
#include "ui/names.h"

using namespace TTD;

namespace idattd
{
    static const int   g_bm_widths[] = { 16, 18, 8, 28, 40 };
    static const char *g_bm_header[] = { "Position", "Address", "Thread", "Name", "Comment" };

    // Prompt for a bookmark's name and note. 'b' carries the defaults in and the
    // answers out; false means the user cancelled.
    static bool ask_bookmark_details(Bookmark &b, bool is_new)
    {
        // The form text is a format string to IDA as well, so only the hex
        // position is interpolated into it -- never a symbol name, which could
        // contain characters the form parser treats as syntax.
        qstring fmt;
        fmt.sprnt("%s TTD bookmark\n"
                  "\n"
                  "\n"
                  "Position %s\n"
                  "\n"
                  "<~N~ame:q:256:60::>\n"
                  "<~C~omment:t::60:::>\n"
                  "\n",
                  is_new ? "New" : "Edit",
                  format_position(b.pos).c_str());

        qstring         name = b.name;
        textctrl_info_t ti;
        ti.cb   = sizeof(textctrl_info_t);
        ti.text = b.comment;
        if ( ask_form(fmt.c_str(), &name, &ti) <= 0 )
            return false;
        b.name    = name;
        b.comment = ti.text;
        return true;
    }

    // Build a bookmark for wherever the cursor is standing right now.
    static bool bookmark_here(TraceManager *mgr, Bookmark &b)
    {
        if ( mgr == nullptr || !mgr->is_active() )
        {
            warning("Bookmarks are only available while replaying a trace.");
            return false;
        }
        b.pos = mgr->current_position();
        b.ea  = mgr->current_pc_ea();
        b.tid = (uint32_t)get_current_thread();
        // A default label so a bookmark dropped without typing anything still
        // says something useful in the list.
        if ( b.ea != BADADDR )
            b.name = func_display_name(b.ea);
        return true;
    }

    BookmarkChooser::BookmarkChooser(TraceManager *mgr, BookmarkStore *store)
        : chooser_t(CH_CAN_INS | CH_CAN_DEL | CH_CAN_EDIT,
                    qnumber(g_bm_widths), g_bm_widths, g_bm_header, "TTD Bookmarks"),
          m_mgr(mgr), m_store(store)
    {
    }

    size_t idaapi BookmarkChooser::get_count() const
    {
        return m_store != nullptr ? m_store->size() : 0;
    }

    void idaapi BookmarkChooser::get_row(qstrvec_t *cols, int * /*icon*/,
                                         chooser_item_attrs_t * /*attrs*/, size_t n) const
    {
        const Bookmark *b = m_store != nullptr ? m_store->at(n) : nullptr;
        if ( b == nullptr )
            return;
        cols->at(0) = format_position(b->pos);
        if ( b->ea != BADADDR )
            cols->at(1).sprnt("0x%llX", (uint64_t)b->ea);
        cols->at(2).sprnt("0x%X", b->tid);
        cols->at(3) = b->name;
        cols->at(4) = b->comment;
        // A note spanning several lines would break the row; show the first only.
        size_t nl = cols->at(4).find('\n');
        if ( nl != qstring::npos )
        {
            cols->at(4).resize(nl);
            cols->at(4).append(" ...");
        }
    }

    ea_t idaapi BookmarkChooser::get_ea(size_t n) const
    {
        const Bookmark *b = m_store != nullptr ? m_store->at(n) : nullptr;
        return b != nullptr ? b->ea : BADADDR;
    }

    chooser_t::cbret_t idaapi BookmarkChooser::enter(size_t n)
    {
        const Bookmark *b = m_store != nullptr ? m_store->at(n) : nullptr;
        if ( b != nullptr && m_mgr != nullptr && m_mgr->is_active() )
        {
            m_mgr->set_next_position(b->pos);
            request_continue_process();
            run_requests();
        }
        return cbret_t(n, NOTHING_CHANGED);
    }

    chooser_t::cbret_t idaapi BookmarkChooser::ins(ssize_t /*n*/)
    {
        Bookmark b;
        if ( m_store == nullptr || !bookmark_here(m_mgr, b) || !ask_bookmark_details(b, true) )
            return cbret_t();
        return cbret_t((ssize_t)m_store->add(b), ALL_CHANGED);
    }

    chooser_t::cbret_t idaapi BookmarkChooser::del(size_t n)
    {
        if ( m_store != nullptr )
            m_store->remove(n);
        return ALL_CHANGED;
    }

    chooser_t::cbret_t idaapi BookmarkChooser::edit(size_t n)
    {
        const Bookmark *cur = m_store != nullptr ? m_store->at(n) : nullptr;
        if ( cur == nullptr )
            return cbret_t();
        Bookmark b = *cur;              // copy: at() points into the store
        if ( !ask_bookmark_details(b, false) )
            return cbret_t();
        m_store->update(n, b);
        return cbret_t((ssize_t)n, ALL_CHANGED);
    }

    //=======================================================================
    // Bookmark actions
    //=======================================================================
    int idaapi AddBookmarkHandler::activate(action_activation_ctx_t *)
    {
        Bookmark b;
        if ( store() == nullptr || !bookmark_here(mgr(), b) || !ask_bookmark_details(b, true) )
            return 1;
        store()->add(b);
        msg("[ida-ttd] bookmarked %s (%s).\n",
            format_position(b.pos).c_str(), b.name.c_str());
        // Any open bookmark window reads the same store, so tell it to re-read
        // rather than leaving the new entry invisible until it is reopened.
        refresh_chooser("TTD Bookmarks");
        return 1;
    }

    int idaapi OpenBookmarksHandler::activate(action_activation_ctx_t *)
    {
        BookmarkChooser *ch = new BookmarkChooser(mgr(), store());
        ch->choose();
        return 1;
    }
}
