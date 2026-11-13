// The plugin's graph window: the models it draws, handed to IDAPython as
// JSON, and the actions it sends back.
#include "ui/graph_view.h"

#include <expr.hpp>

namespace idattd
{
    namespace
    {
        std::map<qstring, GraphModel> g_models;

        void json_field(qstring *out, const char *name, const qstring &value)
        {
            out->cat_sprnt("\"%s\":", name);
            json_str(out, value.c_str());
        }

        // Kinds are plugin-chosen words; this keeps anything else out of the
        // Python snippet.
        bool plain(const char *kind)
        {
            if ( kind == nullptr || *kind == '\0' )
                return false;
            for ( const char *p = kind; *p != '\0'; p++ )
                if ( !qisalnum((uchar)*p) && *p != '_' )
                    return false;
            return true;
        }

        // The window's code is scripts/ida_ttd_graph.py.
        bool run_python(const char *call)
        {
            qstring err;
            if ( run_python_window("ida_ttd_graph", call, &err) )
                return true;
            msg("[ida-ttd] the graph window failed: %s\n", err.c_str());
            return false;
        }
    }

    bool run_python_window(const char *module, const char *call, qstring *err)
    {
        extlang_object_t py = find_extlang_by_name("Python");
        if ( py == nullptr || py->eval_snippet == nullptr )
        {
            *err = "no IDAPython";
            return false;
        }
        // fresh_module reloads the module when its file changed, so a
        // reinstall's version takes over, as when this code was a string run
        // on every call, without compiling it again on every show.
        qstring code;
        code.sprnt("import ida_ttd_qt\nida_ttd_qt.fresh_module('%s').%s\n", module, call);
        return py->eval_snippet(code.c_str(), err);
    }

    void json_str(qstring *out, const char *s)
    {
        out->append('"');
        for ( ; *s != '\0'; s++ )
        {
            unsigned char c = (unsigned char)*s;
            if ( c == '"' || c == '\\' )
            {
                out->append('\\');
                out->append((char)c);
            }
            else if ( c < 0x20 )
            {
                out->cat_sprnt("\\u%04x", c);
            }
            else
            {
                out->append((char)c);
            }
        }
        out->append('"');
    }

    bool graph_window_available()
    {
        extlang_object_t py = find_extlang_by_name("Python");
        return py != nullptr && py->eval_snippet != nullptr;
    }

    TWidget *graph_widget(const char *kind)
    {
        auto it = g_models.find(kind);
        return it != g_models.end() ? find_widget(it->second.title.c_str()) : nullptr;
    }

    bool graph_is_open(const char *kind)
    {
        return graph_widget(kind) != nullptr;
    }

    bool show_graph(const char *kind, GraphModel &&model)
    {
        if ( !plain(kind) )
            return false;
        const bool open = graph_is_open(kind);
        g_models[kind] = std::move(model);
        qstring call;
        call.sprnt("show('%s', %s)", kind, open ? "False" : "True");
        return run_python(call.c_str());
    }

    void refresh_graph(const char *kind, GraphModel &&model)
    {
        if ( !plain(kind) || !graph_is_open(kind) )
            return;
        // Redrawn only when what the window shows changed. The Fork manager
        // is refreshed at every stop, and a redraw re-runs the window's
        // script, lays the graph out again and drops the selection; with
        // the same model the node ids also stay what a pending click names.
        qstring before;
        const bool had = graph_json(kind, &before);
        g_models[kind] = std::move(model);
        qstring after;
        if ( had && graph_json(kind, &after) && after == before )
            return;
        qstring call;
        call.sprnt("show('%s', False)", kind);
        run_python(call.c_str());
    }

    void close_graph(const char *kind)
    {
        TWidget *w = graph_widget(kind);
        if ( w != nullptr )
            close_widget(w, 0);
    }

    void forget_graph(const char *kind)
    {
        close_graph(kind);
        g_models.erase(kind);
    }

    bool graph_json(const char *kind, qstring *out)
    {
        auto it = g_models.find(kind);
        if ( it == g_models.end() )
            return false;
        const GraphModel &m = it->second;
        qstring &j = *out;
        j = "{";
        json_field(&j, "title", m.title);
        j.append(',');
        json_field(&j, "status", m.status);
        j.cat_sprnt(",\"arrows_up\":%s,\"nodes\":[", m.arrows_up ? "true" : "false");
        for ( size_t i = 0; i < m.nodes.size(); i++ )
        {
            const GraphNode &n = m.nodes[i];
            if ( i != 0 )
                j.append(',');
            j.cat_sprnt("{\"id\":%d,", (int)i);
            json_field(&j, "title", n.title);
            j.append(',');
            json_field(&j, "code", n.code);
            j.append(',');
            json_field(&j, "badge", n.badge);
            j.append(',');
            json_field(&j, "tooltip", n.tooltip);
            j.cat_sprnt(",\"dashed\":%s,\"emphasis\":%s,\"lines\":[",
                        n.dashed ? "true" : "false", n.emphasis ? "true" : "false");
            for ( size_t k = 0; k < n.lines.size(); k++ )
            {
                if ( k != 0 )
                    j.append(',');
                json_str(&j, n.lines[k].c_str());
            }
            j.append("],\"menu\":[");
            for ( size_t k = 0; k < n.menu.size(); k++ )
            {
                if ( k != 0 )
                    j.append(',');
                j.append('[');
                json_str(&j, n.menu[k].first.c_str());
                j.append(',');
                json_str(&j, n.menu[k].second.c_str());
                j.append(']');
            }
            j.append("]}");
        }
        j.append("],\"edges\":[");
        for ( size_t i = 0; i < m.edges.size(); i++ )
        {
            const GraphEdge &e = m.edges[i];
            if ( i != 0 )
                j.append(',');
            j.cat_sprnt("{\"src\":%d,\"dst\":%d,\"dashed\":%s,", e.src, e.dst, e.dashed ? "true" : "false");
            json_field(&j, "label", e.label);
            j.append('}');
        }
        j.append("]}");
        return true;
    }

    bool graph_act(const char *kind, int node, const qstring &action)
    {
        auto it = g_models.find(kind);
        if ( it == g_models.end() || node < 0 || node >= (int)it->second.nodes.size() || !it->second.act )
            return false;
        // A copy: the action may replace the model (a fork switch redraws).
        auto act = it->second.act;
        act(node, action);
        return true;
    }
}
