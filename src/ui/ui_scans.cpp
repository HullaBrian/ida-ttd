// Strings and buffers recovered from the recording's writes: the listings and
// the actions that open them.
#include "ui/ui.h"
#include "ui/names.h"

namespace idattd
{
    static bool backend_scans(TraceManager *mgr)
    {
        return mgr != nullptr && mgr->is_active() && mgr->backend() != nullptr
            && mgr->backend()->capabilities().replay_scans;
    }

    //=======================================================================
    // StringsChooser
    //=======================================================================
    static const int   g_rs_widths[] = { 16, 18, 4, 80 };
    static const char *g_rs_header[] = { "Appeared at", "Address", "Enc", "Text" };

    StringsChooser::StringsChooser(TraceManager *mgr, std::vector<StringHit> &&hits)
        : chooser_t(0, qnumber(g_rs_widths), g_rs_widths, g_rs_header, nullptr),
          m_mgr(mgr), m_hits(std::move(hits))
    {
        m_title.sprnt("TTD recovered strings [%d]", (int)m_hits.size());
        make_title_unique(&m_title);
        title = m_title.c_str();
    }

    size_t idaapi StringsChooser::get_count() const
    {
        return m_hits.size();
    }

    void idaapi StringsChooser::get_row(qstrvec_t *cols, int *, chooser_item_attrs_t *, size_t n) const
    {
        if ( n >= m_hits.size() )
            return;
        const StringHit &h = m_hits[n];
        cols->at(0) = format_position(h.pos);
        cols->at(1).sprnt("0x%llX", (uint64_t)h.address);
        cols->at(2) = h.wide ? "W" : "A";
        // A recovered string may hold line breaks; a row is one line.
        qstring t = h.text;
        for ( size_t i = 0; i < t.length(); i++ )
            if ( t[i] == '\n' || t[i] == '\r' || t[i] == '\t' )
                t[i] = ' ';
        cols->at(3) = t;
    }

    ea_t idaapi StringsChooser::get_ea(size_t n) const
    {
        return n < m_hits.size() ? m_hits[n].address : BADADDR;
    }

    // To where it appeared, showing it in the hex view when one is open.
    chooser_t::cbret_t idaapi StringsChooser::enter(size_t n)
    {
        if ( n < m_hits.size() )
            if ( listing_is_current(m_made) )
                travel_and_show_bytes(m_mgr, m_hits[n].pos, m_hits[n].address);
        return cbret_t(n, NOTHING_CHANGED);
    }

    //=======================================================================
    // BuffersChooser
    //=======================================================================
    static const int   g_rb_widths[] = { 18, 8, 16, 16, 16, 28, 8, 50 };
    static const char *g_rb_header[] = { "Address", "Size", "Kind", "First write", "Last write",
                                         "Written by", "Writes", "Preview" };

    BuffersChooser::BuffersChooser(TraceManager *mgr, std::vector<BufferHit> &&hits)
        : chooser_t(0, qnumber(g_rb_widths), g_rb_widths, g_rb_header, nullptr),
          m_mgr(mgr), m_hits(std::move(hits))
    {
        m_title.sprnt("TTD recovered buffers [%d]", (int)m_hits.size());
        make_title_unique(&m_title);
        title = m_title.c_str();
    }

    size_t idaapi BuffersChooser::get_count() const
    {
        return m_hits.size();
    }

    void idaapi BuffersChooser::get_row(qstrvec_t *cols, int *, chooser_item_attrs_t *, size_t n) const
    {
        if ( n >= m_hits.size() )
            return;
        const BufferHit &h = m_hits[n];
        cols->at(0).sprnt("0x%llX", (uint64_t)h.address);
        cols->at(1).sprnt("0x%llX", (uint64_t)h.size);
        cols->at(2) = h.kind;
        cols->at(3) = format_position(h.first_pos);
        cols->at(4) = format_position(h.last_pos);
        cols->at(5) = func_offset_name(h.writer_ip);
        cols->at(6).sprnt("%llu", (unsigned long long)h.writes);
        cols->at(7) = h.preview;
    }

    ea_t idaapi BuffersChooser::get_ea(size_t n) const
    {
        return n < m_hits.size() ? m_hits[n].address : BADADDR;
    }

    // To the last write, where the buffer is complete, showing it in the hex
    // view when one is open.
    chooser_t::cbret_t idaapi BuffersChooser::enter(size_t n)
    {
        if ( n < m_hits.size() )
            if ( listing_is_current(m_made) )
                travel_and_show_bytes(m_mgr, m_hits[n].last_pos, m_hits[n].address);
        return cbret_t(n, NOTHING_CHANGED);
    }

    //=======================================================================
    // Actions
    //=======================================================================
    // Run a replay scan, asking for what it needs (host consent, the hives)
    // when it is refused for want of it. False, reported, when it did not run.
    static bool run_scan(TraceManager *mgr, const char *what, bool *cancelled,
                         const std::function<bool(const ReplaySettings &, qstring *)> &scan)
    {
        ReplaySettings rs = initial_replay_settings(mgr);
        qstring err;
        for ( ;; )
        {
            err.clear();
            if ( scan(rs, &err) )
            {
                // A replay that could not follow the whole recording still
                // returns what it found; say what it missed. The dialog shows
                // once per scan, recording and note, since the backend keeps
                // its answer and a repeat scan gives the same note.
                static std::set<std::string> told;
                qstring note = mgr->backend()->scan_notice();
                if ( !note.empty() )
                {
                    msg("[ida-ttd] %s: %s\n", what, note.c_str());
                    std::string key = std::string(what) + "|" + mgr->trace_path().c_str() + "|" + note.c_str();
                    if ( told.insert(key).second )
                        info("The results are incomplete: %s", note.c_str());
                }
                return true;
            }
            if ( *cancelled || !ask_replay_needs(mgr, &rs) )
                break;
        }
        if ( *cancelled )
            msg("[ida-ttd] %s cancelled.\n", what);
        else if ( mgr->backend() != nullptr && mgr->backend()->last_replay_block() != ReplayBlock::None )
            msg("[ida-ttd] %s not run: %s.\n", what, err.c_str());
        else
            warning("The replay failed: %s", err.empty() ? "no reason given" : err.c_str());
        return false;
    }

    int idaapi RecoverStringsHandler::activate(action_activation_ctx_t *)
    {
        if ( !backend_scans(mgr()) )
        {
            warning("This recording's backend cannot recover strings.");
            return 1;
        }
        static const char form[] =
            "Recover strings\n"
            "\n"
            "\n"
            "Every ASCII and UTF-16 string the program had in memory, and where it appeared.\n"
            "This reads the whole recording, seconds for a small one, minutes for a large one.\n"
            "\n"
            "<~M~inimum length:D::8::>\n"
            "\n";
        static sval_t min_len = 6;
        if ( ask_form(form, &min_len) <= 0 )
            return 1;

        std::vector<StringHit> hits;
        bool cancelled = false;
        if ( !run_scan(mgr(), "string recovery", &cancelled, [&](const ReplaySettings &rs, qstring *err)
            {
                return recover_strings(mgr(), rs, (uint32_t)std::max<sval_t>(min_len, 2), &hits, &cancelled, err);
            }) )
            return 1;
        msg("[ida-ttd] %d string(s) recovered%s.\n", (int)hits.size(), cancelled ? " (cancelled)" : "");
        if ( hits.empty() )
        {
            if ( !cancelled )
                info("No strings of that length were found.");
            return 1;
        }
        StringsChooser *ch = new StringsChooser(mgr(), std::move(hits));
        ch->choose();
        return 1;
    }

    action_state_t idaapi RecoverStringsHandler::update(action_update_ctx_t *)
    {
        return backend_scans(mgr()) ? AST_ENABLE : AST_DISABLE;
    }

    int idaapi RecoverBuffersHandler::activate(action_activation_ctx_t *)
    {
        if ( !backend_scans(mgr()) )
        {
            warning("This recording's backend cannot recover buffers.");
            return 1;
        }
        // No questions up front: every buffer, from a replay of the whole
        // recording behind a cancellable wait box.
        std::vector<BufferHit> hits;
        bool cancelled = false;
        if ( !run_scan(mgr(), "buffer recovery", &cancelled, [&](const ReplaySettings &rs, qstring *err)
            {
                return recover_buffers(mgr(), rs, &hits, &cancelled, err);
            }) )
            return 1;
        msg("[ida-ttd] %d buffer(s) recovered%s.\n", (int)hits.size(), cancelled ? " (cancelled)" : "");
        if ( hits.empty() )
        {
            if ( !cancelled )
                info("No buffers were found.");
            return 1;
        }
        BuffersChooser *ch = new BuffersChooser(mgr(), std::move(hits));
        ch->choose();
        return 1;
    }

    action_state_t idaapi RecoverBuffersHandler::update(action_update_ctx_t *)
    {
        return backend_scans(mgr()) ? AST_ENABLE : AST_DISABLE;
    }
}
