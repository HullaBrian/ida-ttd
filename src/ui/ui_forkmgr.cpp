// The Fork manager: the database's recording and every fork recorded from it
// (and from its forks), as a graph. A node is a recording; double-clicking one
// switches this IDA to it or opens it in another.
//
// Drawn by the plugin's graph window (graph_view.h) where IDAPython is
// available, else by IDA's graph viewer, which most of this file handles.
//
// IDA 9.4 bug, worked around in guard_graph(): after a step or register
// change, IDA updates the current instruction in every graph view as if it
// were a disassembly graph, calling virtual slots 35 and 39 ("node at this
// address", "line in it"). A plugin graph (IDA's user_graph_t, the SDK's
// interactive_graph_t) has 33 slots, so the calls ran into another class's
// table and crashed IDA.
#include "ui/ui.h"
#include "analysis/fork.h"
#include "analysis/fork_registry.h"
#include "common/trace_link.h"
#include "ui/clipboard.h"
#include "ui/graph_view.h"

#include <graph.hpp>

namespace idattd
{
    static const char FM_TITLE[] = "TTD forks";
    static const char FM_KIND[]  = "forks";
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

        // The database's own recording first, so it is the root even with
        // no forks yet.
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

    //-----------------------------------------------------------------------
    // The graph's extra virtual table
    //-----------------------------------------------------------------------
    // Give the plugin's graph object a copy of its class's virtual table,
    // extended past the class's own slots with harmless functions: "no node"
    // (-1) for slot 39 of IDA's current-instruction update, zero for the
    // rest. Only code that wrongly treats the graph as a disassembly graph
    // calls past the real slots. The copy keeps the RTTI entry in front.
    namespace
    {
        constexpr size_t EXTRA_SLOTS = 64;      // beyond the class's own
        constexpr size_t NODE_AT_LINE_SLOT = 39;  // "-1": no node, skip it

        uint64_t idaapi slot_nothing() { return 0; }
        int64_t  idaapi slot_no_node() { return -1; }

        struct GuardedTable
        {
            void *const      *original = nullptr;
            std::vector<void *> slots;           // [0] = the type information, then the table
        };
        std::vector<GuardedTable *> g_tables;    // never freed: IDA may keep a graph past the plugin

        bool executable(const void *p)
        {
            MEMORY_BASIC_INFORMATION mbi;
            if ( p == nullptr || VirtualQuery(p, &mbi, sizeof(mbi)) == 0 || mbi.State != MEM_COMMIT )
                return false;
            const DWORD x = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
            return (mbi.Protect & x) != 0;
        }

        bool readable(const void *p, size_t n)
        {
            MEMORY_BASIC_INFORMATION mbi;
            if ( p == nullptr || VirtualQuery(p, &mbi, sizeof(mbi)) == 0 || mbi.State != MEM_COMMIT
              || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0 )
                return false;
            return (const char *)p + n <= (const char *)mbi.BaseAddress + mbi.RegionSize;
        }

        // The class name the compiler recorded for the object's table.
        qstring class_of(void *const *vtbl)
        {
            struct Col { uint32_t sig, off, cdoff, td, cd, self; };
            if ( !readable(vtbl - 1, sizeof(void *)) )
                return qstring();
            const Col *col = (const Col *)vtbl[-1];
            if ( !readable(col, sizeof(Col)) || col->sig != 1 )
                return qstring();
            const char *base = (const char *)col - col->self;
            const char *name = base + col->td + 16;
            if ( !readable(name, 64) )
                return qstring();
            return qstring(name, strnlen(name, 64));
        }
    }

    static void guard_graph(interactive_graph_t *g)
    {
        if ( g == nullptr )
            return;
        void *const **vptr = (void *const **)g;
        void *const *vtbl = *vptr;
        for ( const GuardedTable *t : g_tables )
            if ( vtbl == t->slots.data() + 1 )
                return;                             // already guarded
        // Only IDA's own graph class, whose layout this is about.
        if ( class_of(vtbl) != ".?AVuser_graph_t@@" )
        {
            msg("[ida-ttd] the fork graph is not the kind expected (%s); stepping with it open may crash IDA.\n",
                class_of(vtbl).c_str());
            return;
        }
        GuardedTable *t = nullptr;
        for ( GuardedTable *x : g_tables )
            if ( x->original == vtbl )
                t = x;
        if ( t == nullptr )
        {
            size_t own = 0;
            while ( own < 256 && readable(vtbl + own, sizeof(void *)) && executable(vtbl[own]) )
                own++;
            // 33 in IDA 9.4; the lookups IDA makes are slots 35 and 39.
            if ( own < 30 || own >= 35 )
            {
                msg("[ida-ttd] the fork graph's class has %d functions, not the 33 expected; "
                    "stepping with it open may crash IDA.\n", (int)own);
                return;
            }
            t = new GuardedTable;
            t->original = vtbl;
            t->slots.push_back(vtbl[-1]);
            for ( size_t i = 0; i < own; i++ )
                t->slots.push_back(vtbl[i]);
            for ( size_t i = own; i < own + EXTRA_SLOTS; i++ )
                t->slots.push_back(i == NODE_AT_LINE_SLOT ? (void *)&slot_no_node : (void *)&slot_nothing);
            g_tables.push_back(t);
            msg("[ida-ttd] fork graph: guarded IDA's current-instruction update (%d functions).\n", (int)own);
        }
        *(void *const **)vptr = t->slots.data() + 1;
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

    static void forget(int node)
    {
        if ( node < 0 || node >= (int)g_fm.nodes.size() || g_fm.nodes[node].record < 0 )
            return;
        const qstring path = g_fm.nodes[node].path;
        if ( ask_yn(ASKBTN_NO, "HIDECANCEL\nRemove the fork %s?\n\nIts file is kept.",
                    qbasename(path.c_str())) != ASKBTN_YES )
            return;
        remove_fork_record(path.c_str());
        refresh_fork_manager();
    }

    //-----------------------------------------------------------------------
    // The graph window's model
    //-----------------------------------------------------------------------
    // An action run once the graph window's menu handler has returned:
    // Record fork runs a recording for minutes, with its own window, which
    // is better not nested inside the Python call that reported the click.
    static void run_action_later(const char *name)
    {
        struct Later : public exec_request_t
        {
            const char *name;
            explicit Later(const char *n) : name(n) {}
            ssize_t idaapi execute() override
            {
                process_ui_action(name);
                return 0;
            }
        };
        // With MFF_NOWAIT, IDA deletes the request after running it.
        execute_sync(*new Later(name), MFF_WRITE | MFF_NOWAIT);
    }

    static void graph_action(int node, const qstring &action)
    {
        if ( node < 0 || node >= (int)g_fm.nodes.size() )
            return;
        const qstring path = g_fm.nodes[node].path;
        if ( action == "open" )
        {
            act_on(node);
        }
        else if ( action == "switch" )
        {
            if ( g_fm.ctx != nullptr && g_fm.ctx->switch_trace )
                g_fm.ctx->switch_trace(path);
        }
        else if ( action == "newida" )
        {
            if ( !open_in_new_ida(path.c_str()) )
                warning("Could not start another IDA. Open %s from IDA's File menu.", path.c_str());
        }
        else if ( action == "copypath" )
        {
            copy_to_clipboard(path.c_str());
        }
        else if ( action == "forget" )
        {
            forget(node);
        }
        // Forking, on the recording being replayed: the same commands as
        // TTD > Forks, at the playhead.
        else if ( action == "fork" )
        {
            run_action_later(actions::FORK);
        }
        else if ( action == "forkrecord" )
        {
            run_action_later(actions::FORK_RECORD);
        }
        else if ( action == "forkdiscard" )
        {
            run_action_later(actions::FORK_DISCARD);
        }
    }

    // Forks can be made from the recording being replayed now.
    static bool can_fork_now()
    {
        TraceManager *mgr = g_fm.ctx != nullptr ? g_fm.ctx->mgr : nullptr;
        return mgr != nullptr && mgr->is_active() && mgr->backend() != nullptr
            && mgr->backend()->capabilities().fork;
    }

    static GraphModel fork_model()
    {
        GraphModel m;
        m.title = FM_TITLE;
        int forks = 0;
        for ( const Node &n : g_fm.nodes )
        {
            GraphNode g;
            g.title   = qbasename(n.path.c_str());
            g.tooltip = n.hint;
            if ( n.record >= 0 )
            {
                const ForkRecord &r = g_fm.records[n.record];
                forks++;
                g.code = r.changes;
                g.lines.push_back(qstring().sprnt("%llu instructions", (unsigned long long)r.instructions));
                char when[64] = {};
                qstrftime64(when, sizeof(when), "%Y-%m-%d %H:%M", (qtime64_t)r.time);
                g.lines.push_back(qstring("recorded ") + when);
                g.badge = "fork";
            }
            else
            {
                g.lines.push_back("the recording this database was made from");
                g.badge = "recording";
            }
            if ( n.current )
            {
                g.badge    = "replaying";
                g.emphasis = true;
                if ( can_fork_now() )
                {
                    const TraceManager::ForkDraft &d = g_fm.ctx->mgr->fork_draft();
                    if ( d.active )
                        g.lines.push_back(qstring("a fork is being made at ") + format_position(d.at));
                    g.menu.emplace_back("Fork at the current position", "fork");
                    if ( d.active )
                    {
                        g.menu.emplace_back("Record fork...", "forkrecord");
                        g.menu.emplace_back("Discard fork", "forkdiscard");
                    }
                    g.menu.emplace_back("", "");
                }
            }
            if ( n.missing )
            {
                g.badge  = "missing";
                g.dashed = true;
                g.lines.push_back("the file is not there any more");
            }
            if ( !n.current && !n.missing )
            {
                g.menu.emplace_back("Open...", "open");
                g.menu.emplace_back("Switch this IDA to it", "switch");
                g.menu.emplace_back("Open it in a new IDA", "newida");
                g.menu.emplace_back("", "");
            }
            g.menu.emplace_back("Copy the path", "copypath");
            if ( n.record >= 0 )
                g.menu.emplace_back("Remove fork", "forget");
            m.nodes.push_back(std::move(g));
        }
        for ( const auto &[src, dst] : g_fm.edges )
        {
            GraphEdge e;
            e.src = src;
            e.dst = dst;
            const int rec = g_fm.nodes[dst].record;
            if ( rec >= 0 )
                e.label.sprnt("forked at %s", g_fm.records[rec].at.c_str());
            m.edges.push_back(std::move(e));
        }
        if ( forks == 0 )
            m.status = "No forks yet: right-click the recording being replayed, or use Fork here "
                       "(TTD menu, or right-click in the disassembly), on a Sogen recording.";
        else
            m.status.sprnt("%d fork%s. Double-click a recording to switch to it or open it in a new IDA; "
                           "right-click for more. Ctrl+wheel zooms, F fits.", forks, forks == 1 ? "" : "s");
        m.act = graph_action;
        return m;
    }

    static ssize_t idaapi fm_callback(void *, int code, va_list va)
    {
        switch ( code )
        {
            case grcode_user_refresh:
            {
                interactive_graph_t *g = va_arg(va, interactive_graph_t *);
                guard_graph(g);
                g_fm.rebuild();
                g->clear();
                g->resize((int)g_fm.nodes.size());
                for ( const auto &[src, dst] : g_fm.edges )
                    g->add_edge(src, dst, nullptr);
                return 1;
            }

            // A new graph object (grouping makes one): guard it too.
            case grcode_changed_graph:
                guard_graph(va_arg(va, interactive_graph_t *));
                return 0;

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

    // Still open? IDA deletes the widget when the user closes it.
    static bool fm_open()
    {
        if ( g_fm.gv != nullptr && find_widget(FM_TITLE) == (TWidget *)g_fm.gv )
            return true;
        g_fm.gv = nullptr;
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
        forget(selected_node(ctx));
        return 1;
    }

    action_state_t idaapi ForkForgetHandler::update(action_update_ctx_t *ctx)
    {
        if ( !fork_manager_widget(ctx->widget) )
            return AST_DISABLE_FOR_WIDGET;
        // The selection is the graph's, which can lag a rebuild of the nodes.
        int node = selected_node(ctx);
        return node >= 0 && node < (int)g_fm.nodes.size() && g_fm.nodes[node].record >= 0
             ? AST_ENABLE : AST_DISABLE;
    }

    // Redrawn from a timer: callers include IDA's process start and exit
    // notifications, and refreshing a graph viewer inside the exit one
    // stopped IDA with internal error 40183.
    static qtimer_t g_refreshTimer = nullptr;

    static int idaapi refresh_cb(void *)
    {
        g_refreshTimer = nullptr;
        if ( fm_open() )
            refresh_viewer(g_fm.gv);
        if ( graph_is_open(FM_KIND) )
        {
            g_fm.rebuild();
            refresh_graph(FM_KIND, fork_model());
        }
        return -1;                      // once
    }

    void refresh_fork_manager()
    {
        if ( g_refreshTimer == nullptr && (fm_open() || graph_is_open(FM_KIND)) )
            g_refreshTimer = register_timer(50, refresh_cb, nullptr);
    }

    bool fork_manager_widget(TWidget *w)
    {
        return w != nullptr && fm_open() && w == (TWidget *)g_fm.gv;
    }

    bool fork_manager_is_open()
    {
        return fm_open() || graph_is_open(FM_KIND);
    }

    void close_fork_manager_window()
    {
        if ( g_refreshTimer != nullptr )
        {
            unregister_timer(g_refreshTimer);
            g_refreshTimer = nullptr;
        }
        if ( fm_open() )
            close_widget(g_fm.gv, 0);
        g_fm.gv = nullptr;
        close_graph(FM_KIND);
    }

    void close_fork_manager()
    {
        close_fork_manager_window();
        g_fm = ForkGraph();
    }

    int idaapi ForkManagerHandler::activate(action_activation_ctx_t *)
    {
        g_fm.ctx = ctx;
        if ( graph_window_available() && !fm_open() )
        {
            g_fm.rebuild();
            if ( show_graph(FM_KIND, fork_model()) )
                return 1;
        }
        if ( fm_open() )
        {
            refresh_fork_manager();
            activate_widget(g_fm.gv, true);
            return 1;
        }
        netnode id;
        id.create(FM_NODE);
        g_fm.gv = create_graph_viewer(FM_TITLE, id, fm_callback, nullptr, 0);
        if ( g_fm.gv == nullptr )
        {
            warning("Could not open the fork graph.");
            return 1;
        }
        guard_graph(get_viewer_graph(g_fm.gv));
        display_widget(g_fm.gv, WOPN_DP_TAB | WOPN_RESTORE);
        viewer_fit_window(g_fm.gv);
        return 1;
    }
}
