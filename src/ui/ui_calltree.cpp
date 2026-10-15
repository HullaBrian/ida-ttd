// The call tree of the function at the cursor: a folding text view, one line
// per call, each opened and closed from the arrow in the gutter (or Left /
// Right), the way IDA's own trees are.
#include "ui/ui.h"
#include "ui/names.h"
#include "ui/graph_view.h"
#include "ui/calltree_py.hh"
#include <expr.hpp>

namespace idattd
{
    // Trees up to this many calls open fully; a bigger one opens one level
    // deep, so the first thing shown is what the function itself called.
    static const size_t kOpenAllRows = 300;

    // "name+0x12" when IDA knows a function there; outside one, the name IDA
    // has for the address (an export it has not made a function of), else
    // the address.
    static qstring code_name(ea_t ea)
    {
        qstring s;
        if ( get_func_start(ea) == BADADDR && get_name(&s, ea) > 0 && !s.empty() )
            return s;
        return func_offset_name(ea);
    }

    static void colored(qstring *out, const qstring &text, color_t tag)
    {
        out->append(COLOR_ON);
        out->append(char(tag));
        out->append(text);
        out->append(COLOR_OFF);
        out->append(char(tag));
    }

    // One open call tree window. Lives until its window closes.
    //
    // Node 0 is the function itself; node i+1 is row i of the tree. A node's
    // children are the rows after it that are deeper than it, up to the next
    // one that is not.
    class CallTreeView
    {
    public:
        CallTreeView(TraceManager *mgr, CallTree &&tree)
            : m_mgr(mgr), m_tree(std::move(tree))
        {
            const size_t n = m_tree.rows.size();
            m_subtree.assign(n + 1, 0);
            for ( size_t i = n; i-- > 0; )
            {
                size_t end = i + 1;
                while ( end < n && m_tree.rows[end].depth > m_tree.rows[i].depth )
                    end += 1 + m_subtree[end + 1];
                m_subtree[i + 1] = end - (i + 1);
            }
            m_subtree[0] = n;
            m_closed.assign(n + 1, false);
            if ( n > kOpenAllRows )
                for ( size_t i = 0; i < n; i++ )
                    m_closed[i + 1] = m_subtree[i + 1] != 0;
            m_title.sprnt("TTD call tree: %s",
                          m_tree.root != BADADDR ? code_name(m_tree.root).c_str() : "here");
        }

        bool open()
        {
            TWidget *old = find_widget(m_title.c_str());
            if ( old != nullptr )
                close_widget(old, 0);
            rebuild();
            simpleline_place_t first(0), last(int(m_lines.size() - 1));
            static const custom_viewer_handlers_t handlers(
                    on_key,         // keyboard
                    nullptr,        // popup
                    nullptr,        // mouse moved
                    nullptr,        // click
                    on_dblclick,    // dblclick
                    nullptr,        // curpos
                    on_close,       // close
                    nullptr,        // help
                    nullptr,        // adjust_place
                    nullptr,        // get_place_xcoord
                    nullptr,        // location_changed
                    nullptr,        // can_navigate
                    fold_state,
                    fold_toggle);
            m_view = create_custom_viewer(m_title.c_str(), &first, &last, &first, nullptr,
                                          &m_lines, &handlers, this);
            if ( m_view == nullptr )
                return false;
            display_widget(m_view, WOPN_DP_TAB | WOPN_RESTORE);
            return true;
        }

    private:
        TraceManager           *m_mgr;
        CallTree                m_tree;
        qstring                 m_title;
        TWidget                *m_view = nullptr;
        std::vector<size_t>     m_subtree;  // per node: how many nodes below it
        std::vector<bool>       m_closed;   // per node: folded
        strvec_t                m_lines;
        std::vector<size_t>     m_lineNode; // per line: its node

        bool has_children(size_t node) const { return m_subtree[node] != 0; }

        qstring node_text(size_t node) const
        {
            qstring s;
            if ( node == 0 )
            {
                colored(&s, m_tree.root != BADADDR ? code_name(m_tree.root) : qstring("(this function)"),
                        COLOR_CNAME);
                qstring where;
                where.sprnt("   %s .. %s, thread %u, %u call(s)%s%s",
                            format_position(m_tree.from).c_str(), format_position(m_tree.to).c_str(),
                            m_tree.tid, (unsigned)m_tree.rows.size(),
                            m_tree.from_cursor ? ", from the cursor (its entry was not found)" : "",
                            m_tree.truncated ? ", cut short" : "");
                colored(&s, where, COLOR_AUTOCMT);
                return s;
            }
            const CallTreeRow &r = m_tree.rows[node - 1];
            for ( int d = 0; d <= r.depth && d < 64; d++ )
                s.append("    ");
            colored(&s, code_name(r.target), COLOR_CNAME);
            if ( !r.is_call )
                colored(&s, qstring("  (jump)"), COLOR_KEYWORD);
            qstring where;
            where.sprnt("   at %s from %s", format_position(r.pos).c_str(), code_name(r.site).c_str());
            if ( r.ret_pos.is_valid() )
                where.cat_sprnt(", returns at %s", format_position(r.ret_pos).c_str());
            else if ( r.is_call )
                where.append(", never returns");
            if ( m_closed[node] && has_children(node) )
                where.cat_sprnt("   [+%u]", (unsigned)m_subtree[node]);
            colored(&s, where, COLOR_AUTOCMT);
            return s;
        }

        void rebuild()
        {
            m_lines.clear();
            m_lineNode.clear();
            const size_t n = m_tree.rows.size() + 1;
            for ( size_t node = 0; node < n; )
            {
                m_lines.push_back(simpleline_t(node_text(node)));
                m_lineNode.push_back(node);
                node += m_closed[node] ? 1 + m_subtree[node] : 1;
            }
        }

        // Fold or unfold one node and redraw, keeping the cursor on it.
        void set_closed(size_t node, bool closed)
        {
            if ( !has_children(node) || m_closed[node] == closed )
                return;
            m_closed[node] = closed;
            rebuild();
            simpleline_place_t first(0), last(int(m_lines.size() - 1));
            set_custom_viewer_range(m_view, &first, &last);
            size_t line = std::find(m_lineNode.begin(), m_lineNode.end(), node) - m_lineNode.begin();
            simpleline_place_t here((int)line);
            jumpto(m_view, &here, 0, -1);
            refresh_custom_viewer(m_view);
        }

        size_t node_at(const place_t *p) const
        {
            if ( p == nullptr )
                return size_t(-1);
            uint32 line = static_cast<const simpleline_place_t *>(p)->n;
            return line < m_lineNode.size() ? m_lineNode[line] : size_t(-1);
        }

        size_t current_node() const
        {
            int x, y;
            return node_at(get_custom_viewer_place(m_view, false, &x, &y));
        }

        void travel(size_t node)
        {
            if ( node != size_t(-1) )
                travel_to(m_mgr, node == 0 ? m_tree.from : m_tree.rows[node - 1].pos);
        }

        static CallTreeView *self(void *ud) { return static_cast<CallTreeView *>(ud); }

        static place_collapsible_state_t idaapi fold_state(TWidget *, const place_t *p, void *ud)
        {
            CallTreeView *v = self(ud);
            size_t node = v->node_at(p);
            if ( node == size_t(-1) || !v->has_children(node) )
                return pcs_none;
            return v->m_closed[node] ? pcs_collapsed : pcs_expanded;
        }

        static bool idaapi fold_toggle(TWidget *, const place_t *p, void *ud)
        {
            CallTreeView *v = self(ud);
            size_t node = v->node_at(p);
            if ( node == size_t(-1) || !v->has_children(node) )
                return false;
            v->set_closed(node, !v->m_closed[node]);
            return true;
        }

        static bool idaapi on_key(TWidget *, int key, int shift, void *ud)
        {
            CallTreeView *v = self(ud);
            if ( shift != 0 )
                return false;
            size_t node = v->current_node();
            if ( node == size_t(-1) )
                return false;
            switch ( key )
            {
                case IK_RETURN:
                    v->travel(node);
                    return true;
                case IK_RIGHT:
                case IK_ADD:
                    v->set_closed(node, false);
                    return true;
                case IK_LEFT:
                case IK_SUBTRACT:
                    v->set_closed(node, true);
                    return true;
            }
            return false;
        }

        static bool idaapi on_dblclick(TWidget *, int, void *ud)
        {
            CallTreeView *v = self(ud);
            v->travel(v->current_node());
            return true;
        }

        static void idaapi on_close(TWidget *, void *ud)
        {
            delete self(ud);
        }
    };

    // The last call tree built, as the window script asks for it
    // (ttd("ui.calltree")).
    static qstring g_callTreeJson;

    const qstring &call_tree_json()
    {
        return g_callTreeJson;
    }

    static qstring tree_json(const CallTree &t)
    {
        qstring j;
        j.append("{\"name\":");
        json_str(&j, t.root != BADADDR ? code_name(t.root).c_str() : "(this function)");
        // "" for no root, which the window takes as nothing to show.
        if ( t.root != BADADDR )
            j.cat_sprnt(",\"root\":\"0x%llX\",\"from\":", (uint64_t)t.root);
        else
            j.append(",\"root\":\"\",\"from\":");
        json_str(&j, format_position(t.from).c_str());
        j.append(",\"to\":");
        json_str(&j, format_position(t.to).c_str());
        j.cat_sprnt(",\"tid\":\"0x%X\",\"from_cursor\":%s,\"truncated\":%s,\"rows\":[",
                    t.tid, t.from_cursor ? "true" : "false", t.truncated ? "true" : "false");
        for ( size_t i = 0; i < t.rows.size(); i++ )
        {
            const CallTreeRow &r = t.rows[i];
            if ( i != 0 )
                j.append(',');
            j.cat_sprnt("{\"depth\":%d,\"jump\":%s,\"site\":\"0x%llX\",\"target\":\"0x%llX\",\"name\":",
                        r.depth, r.is_call ? "false" : "true", (uint64_t)r.site, (uint64_t)r.target);
            json_str(&j, code_name(r.target).c_str());
            j.append(",\"from\":");
            json_str(&j, code_name(r.site).c_str());
            j.append(",\"pos\":");
            json_str(&j, format_position(r.pos).c_str());
            j.append(",\"ret\":");
            json_str(&j, r.ret_pos.is_valid() ? format_position(r.ret_pos).c_str()
                                              : r.is_call ? "never" : "");
            j.append('}');
        }
        j.append("]}");
        return j;
    }

    // Open the tree control (calltree_py.hh). False when IDAPython is not
    // there or the script failed, which the output window is told.
    static bool open_call_tree_window()
    {
        extlang_object_t py = find_extlang_by_name("Python");
        if ( py == nullptr || py->eval_snippet == nullptr )
            return false;
        qstring err;
        if ( py->eval_snippet(CALL_TREE_PY, &err) )
            return true;
        msg("[ida-ttd] the call tree window could not be opened (%s); showing it as text.\n",
            err.c_str());
        return false;
    }

    int idaapi CallTreeHandler::activate(action_activation_ctx_t *)
    {
        if ( mgr() == nullptr || !mgr()->is_active() )
        {
            warning("The call tree is only available while replaying a trace.");
            return 1;
        }
        CallTree tree;
        qstring err;
        if ( !build_call_tree(mgr(), &tree, &err) )
        {
            if ( !tree.cancelled )
                warning("Could not build the call tree: %s", err.c_str());
            return 1;
        }
        msg("[ida-ttd] call tree: %d call(s) from %s to %s%s%s%s.\n", (int)tree.rows.size(),
            format_position(tree.from).c_str(), format_position(tree.to).c_str(),
            tree.from_cursor ? " (the function's entry was not found; from the cursor)" : "",
            tree.truncated ? " (cut short)" : "",
            tree.cancelled ? " (stopped early)" : "");
        if ( tree.rows.empty() )
        {
            info("The function made no calls during this run.");
            return 1;
        }
        // The tree control, through IDAPython; the text view without it.
        g_callTreeJson = tree_json(tree);
        if ( open_call_tree_window() )
            return 1;
        CallTreeView *v = new CallTreeView(mgr(), std::move(tree));
        if ( !v->open() )
        {
            delete v;
            warning("Could not open the call tree window.");
        }
        return 1;
    }
}
