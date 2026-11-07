// Code the program wrote and then ran: the listing and the action that opens it.
#include "ui/ui.h"
#include "ui/names.h"

namespace idattd
{
    //=======================================================================
    // SelfModChooser
    //=======================================================================
    static const int   g_sm_widths[] = { 18, 5, 16, 30, 16, 8 };
    static const char *g_sm_header[] = { "Address", "Size", "Written at", "Written by",
                                         "First run at", "Runs" };

    SelfModChooser::SelfModChooser(TraceManager *mgr, std::vector<SelfModHit> &&hits)
        : chooser_t(0, qnumber(g_sm_widths), g_sm_widths, g_sm_header, nullptr),
          m_mgr(mgr), m_hits(std::move(hits))
    {
        m_title.sprnt("TTD self-modifying code [%d]", (int)m_hits.size());
        make_title_unique(&m_title);
        title = m_title.c_str();
    }

    size_t idaapi SelfModChooser::get_count() const
    {
        return m_hits.size();
    }

    void idaapi SelfModChooser::get_row(qstrvec_t *cols, int * /*icon*/,
                                        chooser_item_attrs_t * /*attrs*/, size_t n) const
    {
        if ( n >= m_hits.size() )
            return;
        const SelfModHit &h = m_hits[n];
        cols->at(0).sprnt("0x%llX", (uint64_t)h.address);
        cols->at(1).sprnt("%llu", (unsigned long long)h.size);
        cols->at(2) = format_position(h.write_pos);
        cols->at(3) = func_offset_name(h.write_ip);
        cols->at(4) = format_position(h.execute_pos);
        cols->at(5).sprnt("%llu", (unsigned long long)h.executions);
    }

    // Selecting a row shows the written code; travelling goes to the write,
    // in the stub that unpacked it.
    ea_t idaapi SelfModChooser::get_ea(size_t n) const
    {
        return n < m_hits.size() ? m_hits[n].address : BADADDR;
    }

    chooser_t::cbret_t idaapi SelfModChooser::enter(size_t n)
    {
        if ( n < m_hits.size() )
            travel_to(m_mgr, m_hits[n].write_pos, m_made);
        return cbret_t(n, NOTHING_CHANGED);
    }

    //=======================================================================
    // Self-modifying code action
    //=======================================================================
    static bool backend_finds_selfmod(TraceManager *mgr)
    {
        return mgr != nullptr && mgr->is_active() && mgr->backend() != nullptr
            && mgr->backend()->capabilities().self_modifying;
    }

    int idaapi SelfModHandler::activate(action_activation_ctx_t *)
    {
        if ( !backend_finds_selfmod(mgr()) )
        {
            warning("This recording's backend cannot look for self-modifying code.");
            return 1;
        }
        std::vector<SelfModHit> hits;
        bool cancelled = false;
        if ( !find_self_modifying(mgr(), &hits, &cancelled) )
        {
            warning("The recording's backend could not look for self-modifying code.");
            return 1;
        }
        msg("[ida-ttd] %d instruction(s) the program wrote and then ran%s.\n", (int)hits.size(),
            cancelled ? " (stopped early)" : "");
        if ( hits.empty() )
        {
            info("The program ran no code it had written itself%s.",
                 cancelled ? " (as far as the search got)" : "");
            return 1;
        }
        SelfModChooser *ch = new SelfModChooser(mgr(), std::move(hits));
        ch->choose();
        return 1;
    }

    action_state_t idaapi SelfModHandler::update(action_update_ctx_t *)
    {
        return backend_finds_selfmod(mgr()) ? AST_ENABLE : AST_DISABLE;
    }
}
