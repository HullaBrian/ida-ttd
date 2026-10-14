#pragma once

#include "common/pch.h"

namespace idattd
{
    // A graph drawn by the plugin's own graph window (graph_py.hh): rounded
    // cards joined by curved edges, in IDA's theme colours, panned and zoomed
    // like IDA's graphs. The plugin builds the model; IDAPython draws it,
    // asking for it with ttd("ui.graph KIND") and sending a node's actions
    // back with ttd("ui.graphact KIND NODE ACTION"). Each kind ("forks",
    // "origin") has one window.
    //
    // Not IDA's own graph viewer: a plugin can give its nodes only a
    // background colour and one block of text there, and drawing them itself
    // means building against IDA's exact Qt.

    struct GraphNode
    {
        qstring title;                  // bold, first line
        qstring code;                   // monospaced: an instruction
        qvector<qstring> lines;         // smaller, dimmer
        qstring badge;                  // a short word in the top corner
        // The colour of the badge and the card's edge: "accent", "good",
        // "warn", "bad", "muted", or "" for none.
        qstring tone;
        bool    dashed = false;         // the card's edge: something missing
        bool    emphasis = false;       // a heavier edge: where the graph starts
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
        // Arrowheads at the top end of each edge: the flow goes up the graph
        // (a value's sources below it), not down (a recording's forks).
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
    // TWidget of the window, or nullptr.
    TWidget *graph_widget(const char *kind);

    // For the script commands the window uses.
    bool graph_json(const char *kind, qstring *out);
    bool graph_act(const char *kind, int node, const qstring &action);
}
