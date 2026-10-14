#pragma once

#include "common/pch.h"
#include "core/position.h"

namespace idattd
{
    class TraceManager;

    // One recorded call to a traced function, with its arguments and (when the
    // matching return was seen) its return value.
    struct FunctionInvocation
    {
        ea_t     func_ea = BADADDR;  // the user-picked function (for display/types)
        Position pos;                // position of the call site (start time)
        Position end_pos;            // position of the matching return (end time)
        uint32_t              tid = 0;            // thread the call ran on
        std::vector<qstring>  args;
        qstring               retval;
        bool                  has_ret = false;
    };

    // Records every call to a user-selected set of functions over the entire
    // execution. A single sweep (run_sweep) replays the whole trace once with a
    // call/return callback, then resolves arguments/return values in a second
    // pass. Robust to import thunks: the picked address is resolved to the real
    // runtime callee address(es) before matching.
    class FunctionTracer
    {
    public:
        void set_manager(TraceManager *mgr) { m_mgr = mgr; }
        TraceManager *manager() const       { return m_mgr; }
        void set_64bit(bool is64)           { m_is64 = is64; }
        void reset();   // forget all traced functions and events (trace closed)

        // ---- traced function list -----------------------------------------
        void   add_func(ea_t func_ea);
        void   remove_trace(size_t n);
        bool   is_traced(ea_t func_ea);
        size_t count_traced();
        ea_t   traced_at(size_t n);

        // ---- recorded events ----------------------------------------------
        size_t             count_events();
        FunctionInvocation event_at(size_t n);
        void               remove_event(size_t n);
        void               clear_events();
        // A stable copy of all recorded events (for an independent chooser tab
        // whose contents won't change when a later sweep replaces the live set).
        std::vector<FunctionInvocation> snapshot_events();

        // Replay the whole trace and (re)build the event list for the currently
        // traced functions. Shows a wait box; safe to call from a UI action.
        void run_sweep();

    private:
        // Resolve a picked address to the set of real runtime callee addresses
        // (follows import thunks and reads the live IAT pointer).
        std::vector<ea_t> resolve_targets(ea_t func_ea) const;

        TraceManager      *m_mgr  = nullptr;
        bool               m_is64 = false;

        std::mutex                      m_traces_mtx;
        std::vector<ea_t>               m_traces;

        std::mutex                      m_events_mtx;
        std::vector<FunctionInvocation> m_events;
    };
}
