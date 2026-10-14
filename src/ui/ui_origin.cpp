// Where a value came from: the listing of the chain, and the action that asks.
#include "ui/ui.h"
#include "ui/names.h"

namespace idattd
{
    //=======================================================================
    // ValueOriginChooser
    //=======================================================================
    static const int   g_vo_widths[] = { 3, 20, 22, 14, 14, 40, 44 };
    static const char *g_vo_header[] = { "#", "Value", "In", "As of", "Set at", "By", "How" };

    ValueOriginChooser::ValueOriginChooser(TraceManager *mgr, std::vector<OriginHop> &&hops)
        : chooser_t(0, qnumber(g_vo_widths), g_vo_widths, g_vo_header, nullptr),
          m_mgr(mgr), m_hops(std::move(hops))
    {
        static int seq = 0;
        m_title.sprnt("TTD value origin: %s [%d]",
                      m_hops.empty() ? "?" : origin_target_text(m_hops[0].what).c_str(), ++seq);
        title = m_title.c_str();
    }

    size_t idaapi ValueOriginChooser::get_count() const
    {
        return m_hops.size();
    }

    void idaapi ValueOriginChooser::get_row(qstrvec_t *cols, int * /*icon*/,
                                            chooser_item_attrs_t *attrs, size_t n) const
    {
        if ( n >= m_hops.size() )
            return;
        const OriginHop &h = m_hops[n];
        cols->at(0).sprnt("%d", (int)n + 1);
        cols->at(1) = origin_value_text(h.value);
        cols->at(2) = origin_target_text(h.what);
        cols->at(3) = format_position(h.at);
        if ( h.by_pc != BADADDR )
        {
            cols->at(4) = format_position(h.by_pos);
            qstring where = describe_address(m_mgr, h.by_pc);
            cols->at(5) = h.insn.empty() ? where : where + ": " + h.insn;
        }
        cols->at(6) = h.note.empty() ? qstring(origin_kind_name(h.kind)) : h.note;
        // The row the chain ends on is the answer.
        if ( attrs != nullptr && n + 1 == m_hops.size() && h.kind != OriginKind::Copied )
            attrs->flags |= CHITEM_BOLD;
    }

    ea_t idaapi ValueOriginChooser::get_ea(size_t n) const
    {
        return n < m_hops.size() ? m_hops[n].by_pc : BADADDR;
    }

    chooser_t::cbret_t idaapi ValueOriginChooser::enter(size_t n)
    {
        if ( n < m_hops.size() && m_mgr != nullptr && m_mgr->is_active() )
        {
            const OriginHop &h = m_hops[n];
            Position p = h.by_pos.is_valid() ? h.by_pos : h.at;
            if ( p.is_valid() )
            {
                m_mgr->set_next_position(p);
                request_continue_process();
                run_requests();
            }
        }
        return cbret_t(n, NOTHING_CHANGED);
    }

    //=======================================================================
    // The action
    //=======================================================================
    // "rax", "xmm2", "0x1234" or "0x1234 8" (an address and a size).
    static bool parse_target(const char *text, OriginTarget *t)
    {
        uint32_t reg = 0;
        if ( parse_register(text, &reg) )
        {
            t->is_reg = true;
            t->reg    = reg;
            return true;
        }
        qstring s(text);
        s.trim2();
        if ( !s.empty() && s[0] == '[' )
            s.remove(0, 1);
        char *end = nullptr;
        uint64_t a = strtoull(s.c_str(), &end, 16);
        if ( end == s.c_str() )
            return false;
        while ( *end == ' ' || *end == ']' || *end == ',' )
            end++;
        uint64_t size = *end != '\0' ? strtoull(end, nullptr, 0) : 8;
        t->is_reg = false;
        t->addr   = (ea_t)a;
        t->size   = (uint32_t)std::min<uint64_t>(std::max<uint64_t>(size, 1), 64);
        return true;
    }

    // What the context names: a register in the registers window or under the
    // cursor, bytes selected in the hex view, data under the cursor.
    static bool target_from_context(action_activation_ctx_t *ctx, OriginTarget *t)
    {
        if ( ctx == nullptr || ctx->widget == nullptr )
            return false;
        const int wt = ctx->widget_type;
        uint32_t reg = 0;
        if ( wt == BWN_CPUREGS && ctx->regname != nullptr && parse_register(ctx->regname, &reg) )
        {
            t->is_reg = true;
            t->reg    = reg;
            return true;
        }
        if ( wt == BWN_HEXVIEW || wt == BWN_DISASM )
        {
            ea_t lo = BADADDR, hi = BADADDR;
            if ( ctx->has_flag(ACF_HAS_SELECTION) && read_range_selection(ctx->widget, &lo, &hi) && lo < hi )
            {
                t->is_reg = false;
                t->addr   = lo;
                t->size   = (uint32_t)std::min<ea_t>(hi - lo, 64);
                return true;
            }
        }
        if ( wt == BWN_DISASM )
        {
            qstring word;
            uint32 flags = 0;
            if ( get_highlight(&word, ctx->widget, &flags) && parse_register(word.c_str(), &reg) )
            {
                t->is_reg = true;
                t->reg    = reg;
                return true;
            }
            const ea_t ea = ctx->cur_ea;
            if ( ea != BADADDR && !is_code(get_flags(ea)) )
            {
                asize_t sz = get_item_size(ea);
                t->is_reg = false;
                t->addr   = get_item_head(ea);
                t->size   = (uint32_t)std::min<asize_t>(std::max<asize_t>(sz, 1), 16);
                return true;
            }
        }
        if ( wt == BWN_HEXVIEW && ctx->cur_ea != BADADDR )
        {
            t->is_reg = false;
            t->addr   = ctx->cur_ea;
            t->size   = 8;
            return true;
        }
        return false;
    }

    int idaapi ValueOriginHandler::activate(action_activation_ctx_t *ctx)
    {
        if ( mgr() == nullptr || !mgr()->is_active() )
        {
            warning("Finding where a value came from is only possible while replaying a trace.");
            return 1;
        }
        OriginTarget t;
        if ( !target_from_context(ctx, &t) )
        {
            static qstring last = "rax";
            qstring text = last;
            if ( !ask_str(&text, HIST_IDENT,
                          "Where did this value come from? A register (rax, ecx, xmm0, ...), "
                          "or memory as an address and a size (0x1234 8)") )
                return 1;
            if ( !parse_target(text.c_str(), &t) )
            {
                warning("'%s' is neither a register nor an address.", text.c_str());
                return 1;
            }
            last = text;
        }

        std::vector<OriginHop> hops;
        if ( !trace_value_origin(mgr(), t, 24, &hops) || hops.empty() )
            return 1;
        const OriginHop &end = hops.back();
        msg("[ida-ttd] %s = %s: %d hop%s, ending %s%s%s.\n",
            origin_target_text(t).c_str(), origin_value_text(hops[0].value).c_str(),
            (int)hops.size(), hops.size() == 1 ? "" : "s", origin_kind_name(end.kind),
            end.note.empty() ? "" : ": ", end.note.c_str());
        ValueOriginChooser *ch = new ValueOriginChooser(mgr(), std::move(hops));
        ch->choose();
        return 1;
    }
}
