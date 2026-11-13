#pragma once

#include "common/pch.h"
#include "core/position.h"
#include "core/backend.h"

namespace idattd
{
    class TraceManager;
    class ModuleRegistry;
    namespace win32meta { struct FuncSig; }

    // How a traced function's calls are decoded, decided once per function:
    //   1. a prototype the user set in IDA (Y on the function) wins;
    //   2. else the API metadata, when it knows the name: it describes the
    //      same API as a type library's prototype, plus flag names, buffer
    //      lengths and which parameters the callee fills in;
    //   3. else IDA's prototype (a PDB's, a type library's, the decompiler's
    //      saved one), else the one IDA guesses from the code;
    //   4. else four untyped integer arguments.
    struct TracedProto
    {
        const win32meta::FuncSig *sig = nullptr;    // 2
        bool                 have_type = false;     // 1 or 3: 'type' and 'fd' hold it
        tinfo_t              type;
        func_type_data_t     fd;
        std::vector<qstring> names;                 // a header per argument ("arg0" when unnamed)
    };
    TracedProto resolve_traced_proto(ModuleRegistry *mods, ea_t func_ea);

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

    // Records every call to a user-selected set of functions over the whole
    // recording. run_sweep finds the calls in one backend query, then reads
    // arguments and return values in a second pass. Picked addresses are
    // resolved through import thunks to the real runtime callees first.
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
        // A copy of all events, for a chooser tab that a later sweep must not
        // change.
        std::vector<FunctionInvocation> snapshot_events();

        // Rebuild the event list for the traced functions from the whole
        // recording. Shows a wait box; safe from a UI action. False, with the
        // reason in 'error' and no dialog (a script would hang on one), when
        // it could not run.
        bool run_sweep(qstring *error);

    private:
        // The runtime callee addresses for a picked address (through import
        // thunks and the live IAT pointer). 'at_end' is a cursor at the end of
        // the recording, made on first use and shared by every call: one seek
        // for the whole pattern, not one per import slot (~17 ms each on
        // Microsoft TTD).
        std::vector<ea_t> resolve_targets(ea_t func_ea, CursorPtr *at_end) const;

        TraceManager      *m_mgr  = nullptr;
        bool               m_is64 = false;

        std::mutex                      m_traces_mtx;
        std::vector<ea_t>               m_traces;

        std::mutex                      m_events_mtx;
        std::vector<FunctionInvocation> m_events;
    };
}
