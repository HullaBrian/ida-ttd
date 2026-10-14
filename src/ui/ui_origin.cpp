// Where a value came from: the listing of the chain, and the action that asks.
#include "ui/ui.h"
#include "ui/names.h"

namespace idattd
{
    //=======================================================================
    // ValueOriginChooser
    //=======================================================================
    // "Seen at": where the row looks at the value (where it was asked about,
    // or where the previous row's instruction read it). "Written at": the
    // last instruction before that which wrote it.
    static const int   g_vo_widths[] = { 3, 20, 26, 14, 14, 40, 44 };
    static const char *g_vo_header[] = { "#", "Value", "In", "Seen at", "Written at", "By", "How" };

    ValueOriginChooser::ValueOriginChooser(TraceManager *mgr, std::vector<OriginHop> &&hops)
        : chooser_t(CH_CAN_EDIT, qnumber(g_vo_widths), g_vo_widths, g_vo_header, nullptr),
          m_mgr(mgr), m_hops(std::move(hops)), m_input_of(m_hops.size(), -1)
    {
        popup_names[POPUP_EDIT] = "Follow an input of this instruction";
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
        if ( n < m_input_of.size() && m_input_of[n] >= 0 )
            cols->at(2).cat_sprnt(", read by #%d", (int)m_input_of[n] + 1);
        cols->at(3) = format_position(h.at);
        if ( h.by_pc != BADADDR )
        {
            cols->at(4) = format_position(h.by_pos);
            qstring where = describe_address(m_mgr, h.by_pc);
            cols->at(5) = h.insn.empty() ? where : where + ": " + h.insn;
        }
        cols->at(6) = h.note.empty() ? qstring(origin_kind_name(h.kind)) : h.note;
        // The rows a chain ends on are the answers.
        const bool chain_ends = n + 1 == m_hops.size() || (n + 1 < m_input_of.size() && m_input_of[n + 1] >= 0);
        if ( chain_ends && h.kind == OriginKind::Computed )
            cols->at(6).append(" (Ctrl+E follows what it read)");
        if ( attrs != nullptr && chain_ends && h.kind != OriginKind::Copied )
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

    // The inputs of one instruction, to pick from.
    class OriginInputChooser : public chooser_t
    {
    public:
        OriginInputChooser(const std::vector<OriginInput> &inputs, const qstring &title)
            : chooser_t(CH_MODAL | CH_KEEP, qnumber(widths), widths, header, nullptr),
              m_inputs(inputs), m_title(title)
        {
            this->title = m_title.c_str();
        }
        size_t idaapi get_count() const override { return m_inputs.size(); }
        void idaapi get_row(qstrvec_t *cols, int *, chooser_item_attrs_t *, size_t n) const override
        {
            const OriginInput &in = m_inputs[n];
            cols->at(0) = origin_target_text(in.what);
            cols->at(1) = origin_value_text(in.value);
            cols->at(2) = in.address ? "formed the address" : "operand";
        }

    private:
        static constexpr int   widths[] = { 26, 20, 20 };
        static constexpr const char *header[] = { "Input", "Value", "As" };
        const std::vector<OriginInput> &m_inputs;
        qstring m_title;
    };

    chooser_t::cbret_t idaapi ValueOriginChooser::edit(size_t n)
    {
        if ( n >= m_hops.size() || m_mgr == nullptr || !m_mgr->is_active() )
            return cbret_t(n, NOTHING_CHANGED);
        const OriginHop &h = m_hops[n];
        if ( !h.by_pos.is_valid() || h.by_pc == BADADDR )
        {
            info("Nothing in the recording wrote %s here, so there is no instruction to follow.",
                 origin_target_text(h.what).c_str());
            return cbret_t(n, NOTHING_CHANGED);
        }
        std::vector<OriginInput> inputs;
        origin_inputs(m_mgr, h.by_pos, &inputs);
        if ( inputs.empty() )
        {
            info("%s reads nothing this can follow%s.", h.insn.empty() ? "The instruction" : h.insn.c_str(),
                 h.kind == OriginKind::System ? ": it is a syscall" : "");
            return cbret_t(n, NOTHING_CHANGED);
        }
        size_t pick = 0;
        if ( inputs.size() > 1 )
        {
            qstring title;
            title.sprnt("Follow which input of %s?", h.insn.empty() ? "the instruction" : h.insn.c_str());
            OriginInputChooser ch(inputs, title);
            ssize_t r = ch.choose();
            if ( r < 0 || (size_t)r >= inputs.size() )
                return cbret_t(n, NOTHING_CHANGED);
            pick = (size_t)r;
        }

        // From just before the instruction ran: by_pos is where it is about
        // to, on its thread.
        std::vector<OriginHop> more;
        if ( !trace_value_origin(m_mgr, inputs[pick].what, h.by_pos, 24, &more) || more.empty() )
            return cbret_t(n, NOTHING_CHANGED);
        const size_t first = m_hops.size();
        m_input_of.push_back((ssize_t)n);
        m_input_of.resize(first + more.size(), -1);
        for ( OriginHop &x : more )
            m_hops.push_back(std::move(x));
        return cbret_t(first, ALL_CHANGED);
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
