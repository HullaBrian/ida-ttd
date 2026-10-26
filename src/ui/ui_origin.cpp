// Where a value came from: the listing of the chain, the graph of every
// chain at once, and the actions that ask.
#include "ui/ui.h"
#include "ui/names.h"
#include "ui/clipboard.h"
#include "ui/graph_view.h"

namespace idattd
{
    //=======================================================================
    // ValueOriginChooser
    //=======================================================================
    // Limits on a chain's length and a graph's size: each hop is a search of
    // the recording.
    static const size_t kOriginHops = 40;
    static const size_t kGraphNodes = 60;

    // Each listing's starting value, by title, for the graph action on its
    // context menu.
    struct OriginRoot
    {
        OriginTarget what;
        Position     at;
    };
    static std::map<qstring, OriginRoot> g_origin_roots;

    // "Seen at": where the row looks at the value (where it was asked about,
    // or where the previous row's instruction read it). "Written at": the
    // last write before that.
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
        if ( !m_hops.empty() )
            g_origin_roots[m_title] = OriginRoot{ m_hops[0].what, m_hops[0].at };
    }

    // The listing's window closed: nothing can ask for its root any more.
    ValueOriginChooser::~ValueOriginChooser()
    {
        g_origin_roots.erase(m_title);
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
        if ( chain_ends && h.combined )
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
        if ( n < m_hops.size() )
            travel_to(m_mgr, m_hops[n].by_pos.is_valid() ? m_hops[n].by_pos : m_hops[n].at);
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

        // From just before the instruction ran (by_pos, on its thread).
        std::vector<OriginHop> more;
        if ( !trace_value_origin(m_mgr, inputs[pick].what, h.by_pos, kOriginHops, &more) || more.empty() )
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

    // What to follow: from the context, else asked for. False when the user
    // cancelled or gave an unparsable answer (after a warning).
    static bool pick_target(action_activation_ctx_t *ctx, OriginTarget *out)
    {
        OriginTarget &t = *out;
        if ( !target_from_context(ctx, &t) )
        {
            static qstring last = "rax";
            qstring text = last;
            // Not HIST_IDENT: IDA refuses a register name as an identifier.
            if ( !ask_str(&text, HIST_SRCH,
                          "Where did this value come from? A register (rax, ecx, xmm0, ...), "
                          "or memory as an address and a size (0x1234 8)") )
                return false;
            if ( !parse_target(text.c_str(), &t) )
            {
                warning("'%s' is neither a register nor an address.", text.c_str());
                return false;
            }
            last = text;
        }
        return true;
    }

    int idaapi ValueOriginHandler::activate(action_activation_ctx_t *ctx)
    {
        if ( mgr() == nullptr || !mgr()->is_active() )
        {
            warning("Finding where a value came from is only possible while replaying a trace.");
            return 1;
        }
        OriginTarget t;
        if ( !pick_target(ctx, &t) )
            return 1;

        std::vector<OriginHop> hops;
        if ( !trace_value_origin(mgr(), t, kOriginHops, &hops) || hops.empty() )
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

    //=======================================================================
    // The graph
    //=======================================================================
    static const char OG_KIND[]  = "origin";
    static const char OG_TITLE[] = "TTD value origin graph";

    namespace
    {
        TraceManager *g_og_mgr = nullptr;
        OriginGraph   g_og;
    }

    static void og_action(int node, const qstring &action)
    {
        if ( node < 0 || node >= (int)g_og.nodes.size() )
            return;
        const OriginHop &h = g_og.nodes[node];
        if ( action == "written" )
        {
            travel_to(g_og_mgr, h.by_pos);
        }
        else if ( action == "seen" )
        {
            travel_to(g_og_mgr, h.at);
        }
        else if ( action == "show" )
        {
            if ( h.by_pc != BADADDR )
                jumpto(h.by_pc);
        }
        else if ( action == "copy" )
        {
            copy_to_clipboard(origin_value_text(h.value).c_str());
        }
        else if ( action == "list" )
        {
            if ( g_og_mgr == nullptr || !g_og_mgr->is_active() )
                return;
            std::vector<OriginHop> hops;
            if ( trace_value_origin(g_og_mgr, h.what, h.at, kOriginHops, &hops) && !hops.empty() )
                (new ValueOriginChooser(g_og_mgr, std::move(hops)))->choose();
        }
    }

    static GraphNode og_node(TraceManager *mgr, const OriginHop &h, bool root)
    {
        GraphNode g;
        g.title.sprnt("%s = %s", origin_target_text(h.what).c_str(), origin_value_text(h.value).c_str());
        const bool written = h.by_pos.is_valid() && h.by_pc != BADADDR;
        if ( written )
        {
            g.code = h.insn;
            // A copy gets one line: chains of them (spills and reloads) are
            // long, and only where they lead matters.
            if ( h.kind == OriginKind::Copied )
            {
                g.lines.push_back(qstring().sprnt("%s, written at %s", describe_address(mgr, h.by_pc).c_str(),
                                                  format_position(h.by_pos).c_str()));
            }
            else
            {
                g.lines.push_back(describe_address(mgr, h.by_pc));
                g.lines.push_back(qstring().sprnt("written at %s, seen at %s",
                                                  format_position(h.by_pos).c_str(), format_position(h.at).c_str()));
            }
        }
        else
        {
            g.lines.push_back(qstring().sprnt("seen at %s", format_position(h.at).c_str()));
        }
        if ( !h.note.empty() && h.kind != OriginKind::Copied )
            g.lines.push_back(h.note);

        switch ( h.kind )
        {
            case OriginKind::Copied:    g.badge = "copy";      break;
            case OriginKind::Constant:  g.badge = "constant";  break;
            case OriginKind::System:    g.badge = "system";    break;
            case OriginKind::Unchanged: g.badge = "unchanged"; g.dashed = true; break;
            case OriginKind::Computed:  g.badge = h.combined ? "combined" : "computed"; break;
            default:                    g.badge = origin_kind_name(h.kind); break;
        }
        g.emphasis = root;
        g.tooltip  = h.note;
        if ( written )
        {
            g.menu.emplace_back("Go to where it was written", "written");
            g.menu.emplace_back("Go to where it was seen", "seen");
            g.menu.emplace_back("Show the instruction", "show");
        }
        else
        {
            g.menu.emplace_back("Go to where it was seen", "seen");
        }
        g.menu.emplace_back("", "");
        g.menu.emplace_back("Copy the value", "copy");
        g.menu.emplace_back("Where did this come from? (list)", "list");
        return g;
    }

    // Build the graph of 'what' as of 'at' and show it.
    void show_origin_graph(TraceManager *mgr, const OriginTarget &what, Position at)
    {
        if ( !graph_window_available() )
        {
            warning("The value origin graph needs IDAPython; the listing (Ctrl+Shift+W) works without it.");
            return;
        }
        OriginGraph g;
        if ( !build_origin_graph(mgr, what, at, kGraphNodes, &g) || g.nodes.empty() )
            return;
        g_og_mgr = mgr;
        g_og     = std::move(g);

        GraphModel m;
        m.title     = OG_TITLE;
        m.arrows_up = true;
        int combined = 0;
        for ( size_t i = 0; i < g_og.nodes.size(); i++ )
        {
            combined += g_og.nodes[i].combined ? 1 : 0;
            m.nodes.push_back(og_node(mgr, g_og.nodes[i], i == 0));
        }
        for ( const OriginGraph::Edge &e : g_og.edges )
        {
            GraphEdge x;
            x.src    = e.from;
            x.dst    = e.to;
            x.dashed = false;
            m.edges.push_back(x);
        }
        m.status.sprnt("Where %s at %s came from: %d value%s; every input of the %d instruction%s that "
                       "combined several was followed (registers that only formed an address, and rsp, "
                       "were not).%s%s Double-click a value to go to where it was written.",
                       origin_target_text(what).c_str(), format_position(at).c_str(),
                       (int)g_og.nodes.size(), g_og.nodes.size() == 1 ? "" : "s",
                       combined, combined == 1 ? "" : "s",
                       g_og.truncated ? " Cut short at the size limit." : "",
                       g_og.cancelled ? " Stopped before the end." : "");
        m.act = og_action;
        show_graph(OG_KIND, std::move(m));
    }

    void origin_session_ended()
    {
        forget_graph(OG_KIND);
        g_og     = OriginGraph();
        g_og_mgr = nullptr;
    }

    int idaapi OriginGraphHandler::activate(action_activation_ctx_t *ctx)
    {
        if ( mgr() == nullptr || !mgr()->is_active() )
        {
            warning("Finding where a value came from is only possible while replaying a trace.");
            return 1;
        }
        // From a listing: the value it started from.
        if ( ctx != nullptr && ctx->widget != nullptr && ctx->widget_type == BWN_CHOOSER )
        {
            qstring title;
            get_widget_title(&title, ctx->widget);
            auto it = g_origin_roots.find(title);
            if ( it != g_origin_roots.end() )
            {
                show_origin_graph(mgr(), it->second.what, it->second.at);
                return 1;
            }
        }
        OriginTarget t;
        if ( !pick_target(ctx, &t) )
            return 1;
        show_origin_graph(mgr(), t, mgr()->current_position());
        return 1;
    }

    bool is_value_origin_listing(TWidget *w)
    {
        if ( w == nullptr || get_widget_type(w) != BWN_CHOOSER )
            return false;
        qstring title;
        get_widget_title(&title, w);
        return g_origin_roots.find(title) != g_origin_roots.end();
    }
}
