#pragma once

#include "common/pch.h"

namespace idattd
{
    // A graph drawn by the plugin's own graph window
    // (scripts/ida_ttd_graph.py), styled and panned and zoomed like IDA's
    // graphs. The plugin builds the model; IDAPython fetches it with
    // ttd("ui.graph KIND") and sends node actions back with
    // ttd("ui.graphact KIND NODE ACTION"). One window per kind ("forks",
    // "origin").
    //
    // Not IDA's graph viewer: there a plugin node gets only a background
    // colour and one block of text, and custom drawing means building against
    // IDA's exact Qt.

    struct GraphNode
    {
        qstring title;                  // first line
        qstring code;                   // an instruction, coloured as IDA colours one
        qvector<qstring> lines;         // comment lines
        qstring badge;                  // the node's kind, a comment after the title
        bool    dashed = false;         // a dashed frame: something missing
        bool    emphasis = false;       // IDA's highlight colour: where the graph starts
        qstring tooltip;
        // Context menu: (label, action) pairs; an empty pair is a separator.
        // The first is what a double-click does.
        std::vector<std::pair<qstring, qstring>> menu;
    };

    struct GraphEdge
    {
        int     src = -1;
        int     dst = -1;
        qstring label;
        bool    dashed = false;
    };

    struct GraphModel
    {
        qstring title;                  // the window's
        qstring status;                 // the line under the graph
        // Arrowheads at each edge's top end: flow goes up (a value's sources
        // below it) rather than down (a recording's forks).
        bool    arrows_up = false;
        std::vector<GraphNode> nodes;
        std::vector<GraphEdge> edges;
        // A node's action from its menu or a double-click. Runs on the main
        // thread, from the window's event handler.
        std::function<void(int node, const qstring &action)> act;
    };

    // Whether IDAPython (and so the graph window) is there.
    bool graph_window_available();
    // Keep 'model' as the graph of 'kind' and show its window, or bring it
    // up to date if it is open. False when the window could not be opened.
    bool show_graph(const char *kind, GraphModel &&model);
    // Only when its window is open: the model replaced and the window redrawn.
    void refresh_graph(const char *kind, GraphModel &&model);
    bool graph_is_open(const char *kind);
    void close_graph(const char *kind);
    // Close the window and drop the model, so the window's commands find no
    // graph (one whose positions belong to a recording no longer open).
    void forget_graph(const char *kind);
    // TWidget of the window, or nullptr.
    TWidget *graph_widget(const char *kind);

    // For the script commands the window uses.
    bool graph_json(const char *kind, qstring *out);
    bool graph_act(const char *kind, int node, const qstring &action);

    // Run 'call' (say "show()") on the PySide window module 'module'
    // (scripts/<module>.py, in ida-ttd-python/ beside the plugin), reloaded
    // first if its file changed. False, with IDAPython's error in 'err',
    // when IDAPython is absent or the call raised.
    bool run_python_window(const char *module, const char *call, qstring *err);

    // Append UTF-8 's' as a quoted JSON string, which is also a Python
    // string literal: the one escaper for every model an IDAPython window
    // asks for (graphs, the call tree, the heatmap) and every string the
    // plugin passes to Python code it runs. Plain ASCII apart from
    // characters outside the BMP (as UTF-8); bytes that are not UTF-8 come
    // out as U+FFFD.
    void json_str(qstring *out, const char *s);
}
