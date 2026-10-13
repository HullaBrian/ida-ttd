// Strings and buffers recovered by replaying the recording: the listings and
// the actions that open them.
#include "ui/ui.h"
#include "ui/names.h"

namespace idattd
{
    static void travel(TraceManager *mgr, Position p)
    {
        if ( mgr == nullptr || !mgr->is_active() || !p.is_valid() )
            return;
        mgr->set_next_position(p);
        request_continue_process();
        run_requests();
    }

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
        // A recovered string can hold anything, new lines included, and a row
        // is one line.
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

    chooser_t::cbret_t idaapi StringsChooser::enter(size_t n)
    {
        if ( n < m_hits.size() )
            travel(m_mgr, m_hits[n].pos);
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
        ea_t fs = get_func_start(h.writer_ip);
        if ( fs != BADADDR && fs != h.writer_ip )
            cols->at(5).sprnt("%s+0x%llX", func_display_name(fs).c_str(), (uint64_t)(h.writer_ip - fs));
        else if ( fs != BADADDR )
            cols->at(5) = func_display_name(fs);
        else
            cols->at(5).sprnt("0x%llX", (uint64_t)h.writer_ip);
        cols->at(6).sprnt("%llu", (unsigned long long)h.writes);
        cols->at(7) = h.preview;
    }

    ea_t idaapi BuffersChooser::get_ea(size_t n) const
    {
        return n < m_hits.size() ? m_hits[n].address : BADADDR;
    }

    // To the last write: the buffer is complete there.
    chooser_t::cbret_t idaapi BuffersChooser::enter(size_t n)
    {
        if ( n < m_hits.size() )
            travel(m_mgr, m_hits[n].last_pos);
        return cbret_t(n, NOTHING_CHANGED);
    }

    //=======================================================================
    // Actions
    //=======================================================================
    static const char SCAN_NOTE[] =
        "This replays the whole recording in Sogen's emulator -- seconds for a small\n"
        "one, minutes for a large one -- with the registry hives it ran against.\n"
        "The result is kept until the recording is closed.\n"
        "\n"
        "A recording made against the host (no emulation root) runs its program's\n"
        "file and network operations on this machine again -- only allow that for\n"
        "programs you trust.\n";

    int idaapi RecoverStringsHandler::activate(action_activation_ctx_t *)
    {
        if ( !backend_scans(mgr()) )
        {
            warning("Strings can only be recovered from a recording that can be replayed "
                    "(Sogen recordings).");
            return 1;
        }
        static const char form[] =
            "Recover strings\n"
            "\n"
            "\n"
            "Every ASCII and UTF-16 string the program had in memory, and where it appeared.\n"
            "%A\n"
            "<~M~inimum length:D::8::>\n"
            "<Registry ~h~ives folder (empty: next to the Sogen backend):F::64::>\n"
            "<##Replay##~A~llow a recording made against the host to touch this machine:C>>\n"
            "\n";
        static sval_t min_len = 6;
        char registry[QMAXPATH];
        qstrncpy(registry, saved_registry_dir().c_str(), sizeof(registry));
        ushort allow = 0;
        if ( ask_form(form, SCAN_NOTE, &min_len, registry, &allow) <= 0 )
            return 1;
        save_registry_dir(registry);

        ReplaySettings rs;
        rs.registry_dir = registry;
        rs.allow_host   = allow != 0;
        std::vector<StringHit> hits;
        bool cancelled = false;
        qstring err;
        if ( !recover_strings(mgr(), rs, (uint32_t)std::max<sval_t>(min_len, 2), &hits, &cancelled, &err) )
        {
            if ( cancelled )
                msg("[ida-ttd] string recovery cancelled.\n");
            else
                warning("The replay failed: %s", err.empty() ? "no reason given" : err.c_str());
            return 1;
        }
        msg("[ida-ttd] %d string(s) recovered.\n", (int)hits.size());
        if ( hits.empty() )
        {
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
            warning("Buffers can only be recovered from a recording that can be replayed "
                    "(Sogen recordings).");
            return 1;
        }
        static const char form[] =
            "Recover buffers\n"
            "\n"
            "\n"
            "Every buffer the program filled -- decoded data, built strings, unpacked\n"
            "images -- with the code that wrote it and when.\n"
            "%A\n"
            "<Registry ~h~ives folder (empty: next to the Sogen backend):F::64::>\n"
            "<##Replay##~A~llow a recording made against the host to touch this machine:C>>\n"
            "\n";
        char registry[QMAXPATH];
        qstrncpy(registry, saved_registry_dir().c_str(), sizeof(registry));
        ushort allow = 0;
        if ( ask_form(form, SCAN_NOTE, registry, &allow) <= 0 )
            return 1;
        save_registry_dir(registry);

        ReplaySettings rs;
        rs.registry_dir = registry;
        rs.allow_host   = allow != 0;
        std::vector<BufferHit> hits;
        bool cancelled = false;
        qstring err;
        if ( !recover_buffers(mgr(), rs, &hits, &cancelled, &err) )
        {
            if ( cancelled )
                msg("[ida-ttd] buffer recovery cancelled.\n");
            else
                warning("The replay failed: %s", err.empty() ? "no reason given" : err.c_str());
            return 1;
        }
        msg("[ida-ttd] %d buffer(s) recovered.\n", (int)hits.size());
        if ( hits.empty() )
        {
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
