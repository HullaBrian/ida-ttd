// The ui.* script commands: what the plugin's windows ask for (their
// models, a node's action), and the travels they make.
#include "plugin/script_internal.h"
#include "analysis/calltree.h"
#include "analysis/origin.h"
#include "ui/graph_view.h"

namespace idattd
{
    // For the call tree window (scripts/ida_ttd_calltree.py): the tree the
    // TTD menu command last built.
    static void cmd_ui_calltree(const Args &, JObj &out)
    {
        const qstring &j = call_tree_json();
        if ( j.empty() )
            fail("no call tree has been built");
        out.raw("tree", j);
    }

    // The heatmap's counts, for its window.
    static void cmd_ui_heat(const Args &, JObj &out)
    {
        const qstring &j = heatmap_json();
        if ( j.empty() )
            fail("no heatmap has been built");
        out.raw("heat", j);
    }

    // The heatmap slice the cursor is in, for the window's marker. Polled,
    // so cheap; "busy" while the replay is moving.
    static void cmd_ui_heatnow(const Args &, JObj &out)
    {
        if ( get_process_state() != DSTATE_SUSP )
        {
            out.boolean("busy", true);
            return;
        }
        out.num("slice", heatmap_current_slice(&mgr()));
    }

    // Count the heatmap again over a span (FROM TO), or over the whole
    // recording (no arguments), and hand the window the new counts.
    static void cmd_ui_heatzoom(const Args &a, JObj &out)
    {
        need_session();
        PositionRange when;
        if ( a.count() >= 2 )
        {
            when.first = position_arg(a.at(0));
            when.last  = position_arg(a.at(1));
        }
        qstring err;
        if ( !build_heatmap(&mgr(), &err, when) )
            fail("%s", err.c_str());
        out.raw("heat", heatmap_json());
    }

    // Travel, then show EA in the hex view, as a double-click in the heatmap does.
    static void cmd_ui_showbytes(const Args &a, JObj &out)
    {
        need_session();
        bool hex = travel_and_show_bytes(&mgr(), position_arg(a.at(0)), (ea_t)a.u64(1));
        out.boolean("hex_view", hex);
    }

    // Travel the way a double-click in a list does: returns at once.
    static void cmd_ui_travel(const Args &a, JObj &out)
    {
        need_session();
        // ui.travel POS [RECORDING]: with the fingerprint of the recording
        // the position came from (a window's data), refused on another one.
        if ( a.count() > 1 && !a.at(1).empty() )
        {
            RecordingStamp made;
            made.fingerprint = a.u64(1);
            if ( !made.current() )
                fail("the position is from another recording than the one being replayed");
            travel_to(&mgr(), position_arg(a.at(0)), made);
        }
        else
        {
            travel_to(&mgr(), position_arg(a.at(0)));
        }
        out.str("queued", a.at(0));
    }

    // The value origin graph, shown as the TTD menu shows it.
    static void cmd_ui_origingraph(const Args &args, JObj &out)
    {
        need_session();
        Args a = args;
        Position from = mgr().current_position();
        from_arg(&a, &from);
        const OriginTarget t = origin_target_arg(a, "ui.origingraph");
        show_origin_graph(&mgr(), t, from);
        out.boolean("shown", graph_is_open("origin"));
    }

    // The graph window's model, and a node's action.
    static void cmd_ui_graph(const Args &a, JObj &out)
    {
        qstring j;
        if ( !graph_json(a.at(0).c_str(), &j) )
            fail("there is no '%s' graph", a.at(0).c_str());
        out.raw("graph", j);
    }

    static void cmd_ui_graphact(const Args &a, JObj &)
    {
        if ( !graph_act(a.at(0).c_str(), (int)a.u64(1), a.count() > 2 ? a.at(2) : qstring()) )
            fail("no such node");
    }

    // ------------------------------------------------------------------ commands

    static const Command UI_COMMANDS[] = {
        { "ui.origingraph", cmd_ui_origingraph, "REG | mem ADDR [SIZE] [from=POS] show the value origin graph" },
        { "ui.graph",       cmd_ui_graph,       "KIND the model of a graph window (forks, origin)" },
        { "ui.graphact",    cmd_ui_graphact,    "KIND NODE ACTION run a graph node's action (NODE in hex, as every number)" },
        { "ui.calltree",    cmd_ui_calltree,    "the call tree last built by the TTD menu (for its window)" },
        { "ui.heat",        cmd_ui_heat,        "the memory heatmap's counts (for its window)" },
        { "ui.heatnow",     cmd_ui_heatnow,     "the heatmap slice the current position is in (-1: outside the span)" },
        { "ui.heatzoom",    cmd_ui_heatzoom,    "[FROM TO] count the heatmap over a span (none: the whole recording)" },
        { "ui.showbytes",   cmd_ui_showbytes,   "POS EA travel there and show EA in the hex view" },
        { "ui.travel",      cmd_ui_travel,      "POS travel there, returning at once (as a double-click does)" },
    };

    std::span<const Command> ui_commands() { return UI_COMMANDS; }
}
