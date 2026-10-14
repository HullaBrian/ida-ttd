// The plugin's graph window: the models it draws, handed to IDAPython as
// JSON, and the actions it sends back.
#include "ui/graph_view.h"
#include "ui/graph_py.hh"

#include <expr.hpp>

namespace idattd
{
    namespace
    {
        std::map<qstring, GraphModel> g_models;

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

        void json_field(qstring *out, const char *name, const qstring &value)
        {
            out->cat_sprnt("\"%s\":", name);
            json_str(out, value.c_str());
        }

        // Kinds are plugin-chosen words; nothing else reaches the snippet.
        bool plain(const char *kind)
        {
            if ( kind == nullptr || *kind == '\0' )
                return false;
            for ( const char *p = kind; *p != '\0'; p++ )
                if ( !qisalnum((uchar)*p) && *p != '_' )
                    return false;
            return true;
        }

        // Run Python: the window's code (defined again each time, so a
        // reinstalled plugin's takes over), then 'call'.
        bool run_python(const char *call)
        {
            extlang_object_t py = find_extlang_by_name("Python");
            if ( py == nullptr || py->eval_snippet == nullptr )
                return false;
            qstring code(GRAPH_PY);
            code.append(call);
            code.append('\n');
            qstring err;
            if ( py->eval_snippet(code.c_str(), &err) )
                return true;
            msg("[ida-ttd] the graph window failed: %s\n", err.c_str());
            return false;
        }
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
        call.sprnt("_ida_ttd_graph_show('%s', %s)", kind, open ? "False" : "True");
        return run_python(call.c_str());
    }

    void refresh_graph(const char *kind, GraphModel &&model)
    {
        if ( !plain(kind) || !graph_is_open(kind) )
            return;
        g_models[kind] = std::move(model);
        qstring call;
        call.sprnt("_ida_ttd_graph_show('%s', False)", kind);
        run_python(call.c_str());
    }

    void close_graph(const char *kind)
    {
        TWidget *w = graph_widget(kind);
        if ( w != nullptr )
            close_widget(w, 0);
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
            json_field(&j, "tone", n.tone);
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
