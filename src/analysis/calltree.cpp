#include "analysis/calltree.h"
#include "analysis/query_runner.h"
#include "debugger/trace_manager.h"

namespace idattd
{
    // Row cap: a bigger tree is not read row by row and is slow to build.
    static const size_t kMaxRows = 100000;

    // How far back to look for the call that entered the frame; a function
    // running longer is shown from the cursor.
    static const uint64_t kMaxBack = 50000000;

    void nest_calls(const std::vector<CallEvent> &calls, std::vector<CallTreeRow> *rows, size_t max_rows,
                    bool *truncated)
    {
        rows->clear();
        std::vector<const CallEvent *> order;
        order.reserve(calls.size());
        for ( const CallEvent &c : calls )
            if ( c.pos.is_valid() )
                order.push_back(&c);
        std::stable_sort(order.begin(), order.end(),
                         [](const CallEvent *a, const CallEvent *b) { return a->pos < b->pos; });

        // Return positions of the calls still running, innermost last. A call
        // that never returned stays open to the end.
        std::vector<Position> open;
        for ( const CallEvent *c : order )
        {
            // The outermost call that has returned by now closes itself and
            // everything opened inside it, including calls with no recorded
            // return (left by an exception or longjmp): stopping at the first
            // of those would keep the returned callers beneath it open and
            // nest every later call too deep.
            for ( size_t k = 0; k < open.size(); k++ )
            {
                if ( open[k].is_valid() && open[k] <= c->pos )
                {
                    open.resize(k);
                    break;
                }
            }
            if ( rows->size() >= max_rows )
            {
                if ( truncated != nullptr )
                    *truncated = true;
                break;
            }
            CallTreeRow r;
            r.pos     = c->pos;
            r.ret_pos = c->ret_pos;
            r.site    = c->site;
            r.target  = c->target;
            r.is_call = c->is_call;
            r.depth   = (int)open.size();
            rows->push_back(r);
            // A jump has no return of its own: its target returns for the
            // call already open.
            if ( c->is_call )
                open.push_back(c->ret_pos);
        }
    }

    bool build_call_tree(TraceManager *mgr, CallTree *out, qstring *err)
    {
        *out = CallTree{};
        if ( mgr == nullptr || !mgr->is_active() || mgr->backend() == nullptr )
        {
            *err = "no recording is being replayed";
            return false;
        }
        ITraceBackend *backend = mgr->backend();
        if ( !backend->capabilities().call_queries )
        {
            *err = "this recording's backend cannot list calls";
            return false;
        }
        const Position here = mgr->current_position();
        out->tid = mgr->cursor() != nullptr ? mgr->cursor()->thread_id() : 0;

        // Where this run of the function began, and where it ends.
        Position call_pos = Position::none();
        ea_t entry = BADADDR;
        bool found = false;
        // Cancellable where the backend's search takes a sink
        // (query_frame_entry_progress); elsewhere Cancel waits for the
        // search, which is then bounded (Microsoft TTD looks back 65,536
        // steps at most).
        QueryResult qr = run_query("Finding where this function was entered", [&](ProgressSink *p)
        {
            found = backend->query_frame_entry(here, out->tid, kMaxBack, &call_pos, &entry, p);
            QueryResult q;
            q.ran = true;
            q.cancelled = p != nullptr && p->cancelled();
            return q;
        });
        if ( qr.cancelled )
        {
            out->cancelled = true;
            *err = "cancelled";
            return false;
        }
        out->from = here;
        out->to   = backend->info().last;
        if ( found && call_pos.is_valid() )
        {
            out->root = entry;
            out->from = call_pos;
            // A replay on Microsoft TTD: behind a wait box, off the UI thread.
            std::vector<CallEvent> self;
            const QueryResult rq = run_query("Finding where this function returned", [&](ProgressSink *p)
            {
                return backend->query_calls({ entry }, PositionRange{ call_pos, call_pos }, &self, p);
            });
            if ( rq.cancelled )
            {
                out->cancelled = true;
                *err = "cancelled";
                return false;
            }
            for ( const CallEvent &c : self )
                if ( c.pos == call_pos && c.ret_pos.is_valid() )
                    out->to = c.ret_pos;
        }
        else
        {
            out->from_cursor = true;
            func_entry_info_t fi;
            if ( get_func_entry_info(&fi, mgr->current_pc_ea()) )
                out->root = fi.start_ea;
        }

        // Every call in the window, then this thread's, nested; the entering
        // call is the root, not a row. The window ends one past the return,
        // since a ret is recognised where it lands.
        std::vector<CallEvent> all;
        PositionRange when{ out->from, backend->position_add(out->to, 1) };
        qr = run_query("Listing the calls this function made", [&](ProgressSink *p)
        {
            return backend->query_calls({}, when, &all, p);
        });
        if ( !qr.ran )
        {
            *err = query_error(mgr, backend, "the replay session ended during the call listing",
                               "the call listing did not run");
            return false;
        }
        out->cancelled = qr.cancelled;
        out->truncated = qr.truncated;
        std::vector<CallEvent> mine;
        mine.reserve(all.size());
        for ( const CallEvent &c : all )
            if ( c.tid == out->tid && !(found && c.pos == call_pos) )
                mine.push_back(c);
        nest_calls(mine, &out->rows, kMaxRows, &out->truncated);
        return true;
    }
}
