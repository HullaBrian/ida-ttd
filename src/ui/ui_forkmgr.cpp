// The Fork manager: the recording this database came from and every fork
// recorded from it (and from its forks), as an indented tree. A row is a
// recording; Enter switches this IDA to it or opens it in another, Delete
// takes a fork out of the tree.
//
// Not a graph view, though a graph is the natural picture: IDA 9.4 crashes
// when a plugin's graph viewer (create_graph_viewer) is open during a debugging
// session and the instruction pointer is refreshed -- after a step, or a
// register change. Its routine that highlights the current instruction in
// every graph view assumes each one is a disassembly graph, calls the
// renderer's address lookup, and on a plugin graph's renderer that slot is
// another function, which takes the address for a type name and reads it.
#include "ui/ui.h"
#include "analysis/fork.h"
#include "analysis/fork_registry.h"
#include "common/trace_link.h"

namespace idattd
{
    static const char FM_TITLE[] = "TTD forks";

    namespace
    {
        struct Row
        {
            qstring path;
            int     depth   = 0;
            int     record  = -1;       // index into records; -1 for a recording not forked here
            bool    current = false;    // the one being replayed
            bool    missing = false;    // its file is gone
        };

        struct ForkTree
        {
            const ActionContext     *ctx = nullptr;
            std::vector<ForkRecord>  records;
            std::vector<Row>         rows;

            void rebuild();
        };

        ForkTree g_ft;
    }

    void ForkTree::rebuild()
    {
        records = load_fork_records(nullptr);
        rows.clear();
        TraceManager *mgr = ctx != nullptr ? ctx->mgr : nullptr;

        // Every recording that is not itself a recorded fork is a root: the
        // database's own recording first, so it heads the list even when
        // nothing has been forked from it yet.
        std::vector<qstring> roots;
        auto add_root = [&](const qstring &p)
        {
            if ( p.empty() )
                return;
            for ( const ForkRecord &r : records )
                if ( same_trace_path(r.path, p) )
                    return;
            for ( const qstring &q : roots )
                if ( same_trace_path(q, p) )
                    return;
            roots.push_back(p);
        };
        TraceLink link;
        if ( trace_link_read(&link) )
            add_root(link.trace_path);
        if ( mgr != nullptr )
            add_root(mgr->trace_path());
        for ( const ForkRecord &r : records )
            add_root(r.parent);

        // Depth first, children in the order they were recorded. 'seen'
        // guards against a cycle in a hand-edited or confused record.
        std::vector<bool> seen(records.size(), false);
        std::function<void(const qstring &, int, int)> walk = [&](const qstring &path, int record, int depth)
        {
            Row row;
            row.path   = path;
            row.depth  = depth;
            row.record = record;
            rows.push_back(row);
            for ( size_t i = 0; i < records.size(); i++ )
                if ( !seen[i] && same_trace_path(records[i].parent, path) )
                {
                    seen[i] = true;
                    walk(records[i].path, (int)i, depth + 1);
                }
        };
        for ( const qstring &r : roots )
            walk(r, -1, 0);

        for ( Row &r : rows )
        {
            r.current = mgr != nullptr && mgr->is_active() && same_trace_path(r.path, mgr->trace_path());
            r.missing = !qfileexist(r.path.c_str());
        }
    }

    static void act_on(size_t n)
    {
        if ( n >= g_ft.rows.size() )
            return;
        const Row &r = g_ft.rows[n];
        if ( r.current )
        {
            info("%s is the recording being replayed.", r.path.c_str());
            return;
        }
        if ( r.missing )
        {
            warning("%s is not there any more.", r.path.c_str());
            return;
        }
        qstring path = r.path;
        int answer = ask_buttons("~S~witch here", "Open in a ~n~ew IDA", "Cancel", ASKBTN_YES,
                                 "HIDECANCEL\n%s\n\n"
                                 "Switch this IDA to that recording? The replay stops here and starts\n"
                                 "again on it, in this database. Or open it in a new IDA instead.",
                                 path.c_str());
        if ( answer == ASKBTN_YES )
        {
            if ( g_ft.ctx != nullptr && g_ft.ctx->switch_trace )
                g_ft.ctx->switch_trace(path);
        }
        else if ( answer == ASKBTN_NO )
        {
            if ( !open_in_new_ida(path.c_str()) )
                warning("Could not start another IDA. Open %s from IDA's File menu.", path.c_str());
        }
    }

    namespace
    {
        const int   g_fm_widths[] = { 40, 14, 40, 12, 16 };
        const char *g_fm_header[] = { "Recording", "Forked at", "Changes", "Instructions", "Recorded" };

        struct ForkChooser : public chooser_t
        {
            ForkChooser()
                : chooser_t(CH_CAN_DEL | CH_CAN_REFRESH,
                            qnumber(g_fm_widths), g_fm_widths, g_fm_header, FM_TITLE)
            {
                g_ft.rebuild();
            }

            size_t idaapi get_count() const override { return g_ft.rows.size(); }

            void idaapi get_row(qstrvec_t *cols, int *, chooser_item_attrs_t *attrs, size_t n) const override
            {
                if ( n >= g_ft.rows.size() )
                    return;
                const Row &r = g_ft.rows[n];
                qstring name;
                for ( int i = 0; i < r.depth; i++ )
                    name.append(i + 1 == r.depth ? "  \xE2\x94\x94\xE2\x94\x80 " : "     ");  // "  |- " in box-drawing characters
                name.append(qbasename(r.path.c_str()));
                if ( r.current )
                    name.append("   (replaying now)");
                if ( r.missing )
                    name.append("   (file not found)");
                cols->at(0) = name;
                if ( r.record >= 0 )
                {
                    const ForkRecord &f = g_ft.records[r.record];
                    cols->at(1) = f.at;
                    cols->at(2) = f.changes;
                    cols->at(3).sprnt("%llu", (unsigned long long)f.instructions);
                    char when[64] = {};
                    qstrftime64(when, sizeof(when), "%Y-%m-%d %H:%M", (qtime64_t)f.time);
                    cols->at(4) = when;
                }
                else
                {
                    cols->at(2) = "the recording";
                }
                if ( attrs != nullptr )
                {
                    if ( r.current )
                        attrs->color = 0xC0F0C0;
                    else if ( r.missing )
                        attrs->flags |= CHITEM_GRAY;
                }
            }

            cbret_t idaapi enter(size_t n) override
            {
                act_on(n);
                return cbret_t(n, NOTHING_CHANGED);
            }

            cbret_t idaapi del(size_t n) override
            {
                if ( n >= g_ft.rows.size() || g_ft.rows[n].record < 0 )
                {
                    warning("Only forks can be taken out of the list, not the recording they came from.");
                    return cbret_t(n, NOTHING_CHANGED);
                }
                const qstring path = g_ft.rows[n].path;
                if ( ask_yn(ASKBTN_NO, "HIDECANCEL\nTake %s out of the fork list?\n\n"
                                       "Its file stays where it is, and so do forks made from it.",
                            path.c_str()) != ASKBTN_YES )
                    return cbret_t(n, NOTHING_CHANGED);
                remove_fork_record(path.c_str());
                g_ft.rebuild();
                return cbret_t(n == 0 ? 0 : n - 1, ALL_CHANGED);
            }

            cbret_t idaapi refresh(ssize_t n) override
            {
                g_ft.rebuild();
                return cbret_t(n, ALL_CHANGED);
            }
        };
    }

    void refresh_fork_manager()
    {
        if ( find_widget(FM_TITLE) != nullptr )
        {
            g_ft.rebuild();
            refresh_chooser(FM_TITLE);
        }
    }

    void close_fork_manager()
    {
        if ( TWidget *w = find_widget(FM_TITLE) )
            close_widget(w, 0);
        g_ft.ctx = nullptr;
        g_ft.rows.clear();
        g_ft.records.clear();
    }

    int idaapi ForkManagerHandler::activate(action_activation_ctx_t *)
    {
        g_ft.ctx = ctx;
        if ( TWidget *w = find_widget(FM_TITLE) )
        {
            refresh_fork_manager();
            activate_widget(w, true);
            return 1;
        }
        // IDA deletes a non-modal chooser when its widget closes.
        ForkChooser *ch = new ForkChooser();
        ch->choose();
        return 1;
    }
}
