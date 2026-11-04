// Where a value came from: the graph of every chain back to its sources,
// and the action that asks.
#include "ui/ui.h"
#include "ui/names.h"
#include "ui/clipboard.h"
#include "ui/graph_view.h"

namespace idattd
{
    // A graph's size limit: each value in it is a search of the recording.
    static const size_t kGraphNodes = 60;

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
        return g;
    }

    // Build the graph of 'what' as of 'at' and show it.
    void show_origin_graph(TraceManager *mgr, const OriginTarget &what, Position at)
    {
        if ( !graph_window_available() )
        {
            warning("The value origin graph needs IDAPython.");
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
        OriginTarget t;
        if ( !pick_target(ctx, &t) )
            return 1;
        show_origin_graph(mgr(), t, mgr()->current_position());
        return 1;
    }
}
