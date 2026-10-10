// Memory access search: the address/length/kind prompt and the hit listing.
#include "ui/ui.h"
#include "ui/names.h"

using namespace TTD;

namespace idattd
{
    //=======================================================================
    // MemAccessChooser
    //=======================================================================
    static const int   g_ma_widths[] = { 16, 8, 8, 18, 6, 28 };
    static const char *g_ma_header[] = { "Position", "Thread", "Access",
                                         "Address", "Size", "Instruction" };

    MemAccessChooser::MemAccessChooser(TraceManager *mgr, ea_t lo, ea_t hi,
                                       std::vector<MemAccess> &&hits)
        : chooser_t(CH_CAN_DEL, qnumber(g_ma_widths), g_ma_widths, g_ma_header, nullptr),
          m_mgr(mgr), m_hits(std::move(hits))
    {
        // A unique title per search, so two searches open as two tabs instead of
        // one replacing the other. The string is a member because chooser_base_t
        // keeps the pointer it is given rather than copying it.
        if ( hi - lo <= 1 )
            m_title.sprnt("TTD accesses: 0x%llX [%d]", (uint64_t)lo, (int)m_hits.size());
        else
            m_title.sprnt("TTD accesses: 0x%llX..0x%llX [%d]",
                          (uint64_t)lo, (uint64_t)hi, (int)m_hits.size());
        title = m_title.c_str();
    }

    size_t idaapi MemAccessChooser::get_count() const
    {
        return m_hits.size();
    }

    void idaapi MemAccessChooser::get_row(qstrvec_t *cols, int * /*icon*/,
                                          chooser_item_attrs_t * /*attrs*/, size_t n) const
    {
        if ( n >= m_hits.size() )
            return;
        const MemAccess &a = m_hits[n];
        cols->at(0) = format_position(a.pos);
        cols->at(1).sprnt("0x%X", a.tid);
        cols->at(2) = access_name(a.kind);
        cols->at(3).sprnt("0x%llX", (uint64_t)a.addr);
        cols->at(4).sprnt("%u", a.size);
        // Where the access came from, as a name plus offset when there is one --
        // the raw address alone rarely says anything.
        qstring where;
        ea_t fs = get_func_start(a.pc);
        if ( fs != BADADDR )
        {
            qstring fn = func_display_name(fs);
            if ( a.pc == fs )
                where = fn;
            else
                where.sprnt("%s+0x%llX", fn.c_str(), (uint64_t)(a.pc - fs));
        }
        else
        {
            where.sprnt("0x%llX", (uint64_t)a.pc);
        }
        cols->at(5) = where;
    }

    ea_t idaapi MemAccessChooser::get_ea(size_t n) const
    {
        return n < m_hits.size() ? m_hits[n].pc : BADADDR;
    }

    chooser_t::cbret_t idaapi MemAccessChooser::enter(size_t n)
    {
        if ( m_mgr != nullptr && m_mgr->is_active() && n < m_hits.size() )
        {
            m_mgr->set_next_position(m_hits[n].pos);
            request_continue_process();
            run_requests();
        }
        return cbret_t(n, NOTHING_CHANGED);
    }

    chooser_t::cbret_t idaapi MemAccessChooser::del(size_t n)
    {
        if ( n < m_hits.size() )
            m_hits.erase(m_hits.begin() + n);
        return ALL_CHANGED;
    }

    //=======================================================================
    // Memory access search action
    //=======================================================================
    int idaapi MemSearchHandler::activate(action_activation_ctx_t *ctx)
    {
        if ( mgr() == nullptr || !mgr()->is_active() )
        {
            warning("Memory searching is only available while replaying a trace.");
            return 1;
        }

        static const char form[] =
            "TTD memory access search\n"
            "\n"
            "\n"
            "Find every time the recording touched this memory.\n"
            "\n"
            "<~A~ddress:$::18::>\n"
            "<~L~ength in bytes:D::18::>\n"
            "<##Access##~R~ead:C>\n"
            "<~W~rite:C>\n"
            "<E~x~ecute:C>>\n"
            "\n";

        // Seed from wherever the user is, which is usually what they mean.
        static sval_t  len  = 1;
        static ushort  bits = ACC_READ | ACC_WRITE;
        ea_t addr = ctx != nullptr && ctx->cur_ea != BADADDR ? ctx->cur_ea : get_screen_ea();
        if ( ask_form(form, &addr, &len, &bits) <= 0 )
            return 1;
        if ( len <= 0 )
            len = 1;

        std::vector<MemAccess> hits;
        bool truncated = false, cancelled = false;
        if ( !search_memory(mgr(), addr, addr + (ea_t)len, (uint8_t)bits,
                            &hits, &truncated, &cancelled) )
            return 1;

        msg("[ida-ttd] memory search: %d access(es) to 0x%llX..0x%llX%s%s.\n",
            (int)hits.size(), (uint64_t)addr, (uint64_t)(addr + (ea_t)len),
            truncated ? " (record limit reached, results are partial)" : "",
            cancelled ? " (stopped early)" : "");
        if ( hits.empty() )
        {
            info("Nothing in the recording read, wrote or executed that memory.");
            return 1;
        }

        MemAccessChooser *ch = new MemAccessChooser(mgr(), addr, addr + (ea_t)len,
                                                    std::move(hits));
        ch->choose();
        return 1;
    }
}
