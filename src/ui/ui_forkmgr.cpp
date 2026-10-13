// The Fork manager: the recording this database came from and every fork
// recorded from it (and from its forks), drawn as a graph. A node is a
// recording; double-clicking one switches this IDA to it or opens it in
// another.
//
// The graph viewer is created inside a widget of our own (create_graph_viewer's
// 'parent'), not as a window by itself. IDA 9.4 refreshes the current
// instruction in every top-level graph window after a step or a register
// change, treating each as a disassembly graph; with the Fork manager a
// window of that kind, that took IDA down.
#include "ui/ui.h"
#include "analysis/fork.h"
#include "analysis/fork_registry.h"
#include "common/trace_link.h"

#include <graph.hpp>

namespace idattd
{
    static const char FM_TITLE[] = "TTD forks";
    static const char FM_GRAPH[] = "TTD fork graph";
    static const char FM_NODE[]  = "$ ida-ttd fork graph";

    namespace
    {
        struct Node
        {
            qstring path;
            qstring text;
            qstring hint;
            int     record  = -1;       // index into records; -1 for a recording not forked here
            bool    current = false;    // the one being replayed
            bool    missing = false;    // its file is gone
        };

        struct ForkGraph
        {
            const ActionContext     *ctx  = nullptr;
            TWidget                 *host = nullptr;
            graph_viewer_t          *gv   = nullptr;
            std::vector<ForkRecord>  records;
            std::vector<Node>        nodes;
            std::vector<std::pair<int, int>> edges;

            int find(const qstring &path) const
            {
                for ( size_t i = 0; i < nodes.size(); i++ )
                    if ( same_trace_path(nodes[i].path, path) )
                        return (int)i;
                return -1;
            }

            int add(const qstring &path)
            {
                int n = find(path);
                if ( n >= 0 )
                    return n;
                Node node;
                node.path = path;
                nodes.push_back(node);
                return (int)nodes.size() - 1;
            }

            void rebuild();
        };

        ForkGraph g_fm;
    }

    void ForkGraph::rebuild()
    {
        records = load_fork_records(nullptr);
        nodes.clear();
        edges.clear();

        // The database's own recording first, so it is the root even when
        // nothing has been forked from it yet.
        TraceLink link;
        if ( trace_link_read(&link) && !link.trace_path.empty() )
            add(link.trace_path);
        TraceManager *mgr = ctx != nullptr ? ctx->mgr : nullptr;
        if ( mgr != nullptr && !mgr->trace_path().empty() )
            add(mgr->trace_path());
        for ( size_t i = 0; i < records.size(); i++ )
        {
            int parent = add(records[i].parent);
            int child  = add(records[i].path);
            if ( parent == child )
                continue;
            nodes[child].record = (int)i;
            edges.emplace_back(parent, child);
        }

        for ( Node &n : nodes )
        {
            n.current = mgr != nullptr && mgr->is_active() && same_trace_path(n.path, mgr->trace_path());
            n.missing = !qfileexist(n.path.c_str());
            n.text = qbasename(n.path.c_str());
            n.hint = n.path;
            if ( n.record >= 0 )
            {
                const ForkRecord &r = records[n.record];
                n.text.cat_sprnt("\nforked at %s\n%s\n%llu instructions", r.at.c_str(), r.changes.c_str(),
                                 (unsigned long long)r.instructions);
                char when[64] = {};
                qstrftime64(when, sizeof(when), "%Y-%m-%d %H:%M", (qtime64_t)r.time);
                n.hint.cat_sprnt("\nforked at %s, %s\nchanges: %s", r.at.c_str(), when, r.changes.c_str());
            }
            else
            {
                n.text.append("\nrecording");
            }
            if ( n.current )
                n.text.append("\n(replaying now)");
            if ( n.missing )
                n.text.append("\n(file not found)");
        }
    }

    static void act_on(int node)
    {
        if ( node < 0 || node >= (int)g_fm.nodes.size() )
            return;
        const Node &n = g_fm.nodes[node];
        if ( n.current )
        {
            info("%s is the recording being replayed.", n.path.c_str());
            return;
        }
        if ( n.missing )
        {
            warning("%s is not there any more.", n.path.c_str());
            return;
        }
        qstring path = n.path;
        int answer = ask_buttons("~S~witch here", "Open in a ~n~ew IDA", "Cancel", ASKBTN_YES,
                                 "HIDECANCEL\n%s\n\n"
                                 "Switch this IDA to that recording? The replay stops here and starts\n"
                                 "again on it, in this database. Or open it in a new IDA instead.",
                                 path.c_str());
        if ( answer == ASKBTN_YES )
        {
            if ( g_fm.ctx != nullptr && g_fm.ctx->switch_trace )
                g_fm.ctx->switch_trace(path);
        }
        else if ( answer == ASKBTN_NO )
        {
            if ( !open_in_new_ida(path.c_str()) )
                warning("Could not start another IDA. Open %s from IDA's File menu.", path.c_str());
        }
    }

    static ssize_t idaapi fm_callback(void *, int code, va_list va)
    {
        switch ( code )
        {
            case grcode_user_refresh:
            {
                interactive_graph_t *g = va_arg(va, interactive_graph_t *);
                g_fm.rebuild();
                g->clear();
                g->resize((int)g_fm.nodes.size());
                for ( const auto &[src, dst] : g_fm.edges )
                    g->add_edge(src, dst, nullptr);
                return 1;
            }

            case grcode_user_text:
            {
                va_arg(va, interactive_graph_t *);
                int          node    = va_arg(va, int);
                const char **text    = va_arg(va, const char **);
                bgcolor_t   *bgcolor = va_arg(va, bgcolor_t *);
                if ( node < 0 || node >= (int)g_fm.nodes.size() )
                    return 0;
                const Node &n = g_fm.nodes[node];
                *text = n.text.c_str();
                if ( bgcolor != nullptr )
                    *bgcolor = n.current ? 0xC0F0C0 : n.missing ? 0xC0C0C0 : DEFCOLOR;
                return 1;
            }

            case grcode_user_hint:
            {
                va_arg(va, interactive_graph_t *);
                int    node = va_arg(va, int);
                va_arg(va, int);
                va_arg(va, int);
                char **hint = va_arg(va, char **);
                if ( node < 0 || node >= (int)g_fm.nodes.size() )
                    return 0;
                *hint = qstrdup(g_fm.nodes[node].hint.c_str());
                return 1;
            }

            case grcode_dblclicked:
            {
                va_arg(va, graph_viewer_t *);
                selection_item_t *s = va_arg(va, selection_item_t *);
                if ( s != nullptr && s->is_node )
                    act_on(s->node);
                return 1;
            }

            default:
                break;
        }
        return 0;
    }

    // Still open? IDA deletes both widgets when the user closes the window.
    static bool fm_open()
    {
        if ( g_fm.host != nullptr && find_widget(FM_TITLE) == g_fm.host )
            return true;
        g_fm.host = nullptr;
        g_fm.gv   = nullptr;
        return false;
    }

    // The fork under the graph's selection, for the popup actions.
    static int selected_node(action_ctx_base_t *ctx)
    {
        if ( ctx == nullptr || !fork_manager_widget(ctx->widget) || ctx->graph_selection == nullptr )
            return -1;
        for ( size_t i = 0; i < ctx->graph_selection->size(); i++ )
            if ( ctx->graph_selection->at(i).is_node )
                return ctx->graph_selection->at(i).node;
        return -1;
    }

    int idaapi ForkOpenHandler::activate(action_activation_ctx_t *ctx)
    {
        act_on(selected_node(ctx));
        return 1;
    }

    action_state_t idaapi ForkOpenHandler::update(action_update_ctx_t *ctx)
    {
        if ( !fork_manager_widget(ctx->widget) )
            return AST_DISABLE_FOR_WIDGET;
        return selected_node(ctx) >= 0 ? AST_ENABLE : AST_DISABLE;
    }

    int idaapi ForkForgetHandler::activate(action_activation_ctx_t *ctx)
    {
        int node = selected_node(ctx);
        if ( node < 0 || g_fm.nodes[node].record < 0 )
            return 1;
        const qstring path = g_fm.nodes[node].path;
        if ( ask_yn(ASKBTN_NO, "HIDECANCEL\nTake %s out of the fork graph?\n\n"
                               "Its file stays where it is, and so do forks made from it.",
                    path.c_str()) != ASKBTN_YES )
            return 1;
        remove_fork_record(path.c_str());
        refresh_fork_manager();
        return 1;
    }

    action_state_t idaapi ForkForgetHandler::update(action_update_ctx_t *ctx)
    {
        if ( !fork_manager_widget(ctx->widget) )
            return AST_DISABLE_FOR_WIDGET;
        int node = selected_node(ctx);
        return node >= 0 && g_fm.nodes[node].record >= 0 ? AST_ENABLE : AST_DISABLE;
    }

    void refresh_fork_manager()
    {
        if ( fm_open() && g_fm.gv != nullptr )
            refresh_viewer(g_fm.gv);
    }

    bool fork_manager_widget(TWidget *w)
    {
        return w != nullptr && fm_open() && (w == g_fm.host || w == (TWidget *)g_fm.gv);
    }

    void close_fork_manager()
    {
        if ( fm_open() )
            close_widget(g_fm.host, 0);
        g_fm = ForkGraph();
    }

    int idaapi ForkManagerHandler::activate(action_activation_ctx_t *)
    {
        g_fm.ctx = ctx;
        if ( fm_open() )
        {
            refresh_fork_manager();
            activate_widget(g_fm.host, true);
            return 1;
        }
        g_fm.host = create_empty_widget(FM_TITLE);
        if ( g_fm.host == nullptr )
        {
            warning("Could not open the fork graph.");
            return 1;
        }
        netnode id;
        id.create(FM_NODE);
        g_fm.gv = create_graph_viewer(FM_GRAPH, id, fm_callback, nullptr, 0, g_fm.host);
        if ( g_fm.gv == nullptr )
        {
            close_widget(g_fm.host, 0);
            g_fm.host = nullptr;
            warning("Could not open the fork graph.");
            return 1;
        }
        display_widget(g_fm.host, WOPN_DP_TAB | WOPN_RESTORE);
        viewer_fit_window(g_fm.gv);
        return 1;
    }
}
