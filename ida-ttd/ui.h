#pragma once

#include "pch.h"
#include "trace_manager.h"
#include "tracer.h"

namespace idattd
{
    // A non-modal "Timeline" chooser listing notable trace positions
    // (thread create/exit, module load/unload, exceptions). Double-clicking a
    // row moves the cursor to that position.
    class PositionChooser : public chooser_t
    {
    public:
        explicit PositionChooser(TraceManager *mgr);

        size_t  idaapi get_count() const override;
        void    idaapi get_row(qstrvec_t *cols, int *icon, chooser_item_attrs_t *attrs, size_t n) const override;
        cbret_t idaapi enter(size_t n) override;

    private:
        TraceManager                            *m_mgr;
        std::vector<TraceManager::NamedPosition> m_positions;
    };

    // List of functions selected for call tracing. Insert opens choose_func;
    // delete removes a trace.
    class TracedFunctionsChooser : public chooser_t
    {
    public:
        TracedFunctionsChooser(TraceManager *mgr, FunctionTracer *tracer);

        size_t  idaapi get_count() const override;
        void    idaapi get_row(qstrvec_t *cols, int *icon, chooser_item_attrs_t *attrs, size_t n) const override;
        ea_t    idaapi get_ea(size_t n) const override;   // pure navigation, no side effects
        cbret_t idaapi ins(ssize_t n) override;
        cbret_t idaapi del(size_t n) override;

    private:
        TraceManager   *m_mgr;
        FunctionTracer *m_tracer;
    };

    // Builds the trace-events column layout from the traced function's
    // signature. Fixed leading columns Start/End/Thread/Function, then one
    // column per parameter (named after it) when a single function is traced,
    // otherwise a single "Arguments" column, then Return. Also owns the
    // (unique) chooser title. Must be a base of TraceEventsChooser and listed
    // BEFORE chooser_t, so its arrays/title stay alive for the chooser's
    // lifetime (chooser_base_t keeps the pointers, it does not copy them).
    struct EventColumns
    {
        explicit EventColumns(FunctionTracer *tracer);

        const int         *w() const { return widths.data(); }
        const char *const *h() const { return header_ptrs.data(); }
        int                n() const { return (int)widths.size(); }
        const char        *t() const { return title_str.c_str(); }

        std::vector<int>          widths;
        std::vector<qstring>      header_strs;
        std::vector<const char *> header_ptrs;
        qstring                   title_str;
        bool                      per_arg = false;  // true: one column per arg
        int                       argc = 0;
        static const int          LEAD = 4;         // Start, End, Thread, Function
    };

    // Results of the call-trace sweep: one row per recorded call. Holds its own
    // snapshot of the events so several "Tracing events" tabs can coexist, each
    // frozen at the moment it was opened. Double-clicking a row time-travels the
    // debugger to that call's position.
    class TraceEventsChooser : public EventColumns, public chooser_t
    {
    public:
        TraceEventsChooser(TraceManager *mgr, FunctionTracer *tracer);

        size_t  idaapi get_count() const override;
        void    idaapi get_row(qstrvec_t *cols, int *icon, chooser_item_attrs_t *attrs, size_t n) const override;
        cbret_t idaapi enter(size_t n) override;
        cbret_t idaapi del(size_t n) override;

    private:
        TraceManager                    *m_mgr;
        std::vector<FunctionInvocation>  m_events;  // frozen snapshot
    };

    // ---- TTD-specific action handlers --------------------------------------
    // Most stepping is provided by IDA's native debugger actions (attached to
    // our toolbar). IDA has no native "continue backwards", so we add one.
    // All TTD actions are only meaningful while a trace is being replayed, so
    // they enable/disable (and thus grey out on the toolbar/menu) with the
    // session. is_active() is true exactly when a cursor over a trace exists.
    struct RunBackHandler : public action_handler_t
    {
        TraceManager *mgr = nullptr;
        int           idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override
        { return mgr != nullptr && mgr->is_active() ? AST_ENABLE : AST_DISABLE; }
    };

    struct OpenTimelineHandler : public action_handler_t
    {
        TraceManager *mgr = nullptr;
        int           idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override
        { return mgr != nullptr && mgr->is_active() ? AST_ENABLE : AST_DISABLE; }
    };

    struct GotoPositionHandler : public action_handler_t
    {
        TraceManager *mgr = nullptr;
        int           idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override
        { return mgr != nullptr && mgr->is_active() ? AST_ENABLE : AST_DISABLE; }
    };

    // Click handler for the toolbar position readout: copies the current
    // Sequence:Steps position to the clipboard.
    struct PositionCopyHandler : public action_handler_t
    {
        TraceManager *mgr = nullptr;
        int           idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override
        { return mgr != nullptr && mgr->is_active() ? AST_ENABLE : AST_DISABLE; }
    };

    // Deep, on-demand "define the whole enclosing function" (expensive backward
    // trace walk behind a wait box). The cheap per-stop analysis never does this.
    struct AnalyzeFuncHandler : public action_handler_t
    {
        TraceManager *mgr = nullptr;
        int           idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override
        { return mgr != nullptr && mgr->is_active() ? AST_ENABLE : AST_DISABLE; }
    };

    // One-click: trace the function under the cursor, sweep, and show results.
    struct TraceFuncHandler : public action_handler_t
    {
        TraceManager   *mgr    = nullptr;
        FunctionTracer *tracer = nullptr;
        int           idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override;
    };

    // Prompt for a name pattern ("module!Glob*"), trace every matching function,
    // sweep, and show results (one combined Arguments column when >1 match).
    struct TracePatternHandler : public action_handler_t
    {
        TraceManager   *mgr    = nullptr;
        FunctionTracer *tracer = nullptr;
        int           idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override
        { return mgr != nullptr && mgr->is_active() ? AST_ENABLE : AST_DISABLE; }
    };

    struct OpenTracedHandler : public action_handler_t
    {
        TraceManager   *mgr    = nullptr;
        FunctionTracer *tracer = nullptr;
        int           idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override
        { return mgr != nullptr && mgr->is_active() ? AST_ENABLE : AST_DISABLE; }
    };

    struct OpenEventsHandler : public action_handler_t
    {
        TraceManager   *mgr    = nullptr;
        FunctionTracer *tracer = nullptr;
        int           idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override
        { return mgr != nullptr && mgr->is_active() ? AST_ENABLE : AST_DISABLE; }
    };

    struct RunTraceHandler : public action_handler_t
    {
        TraceManager   *mgr    = nullptr;
        FunctionTracer *tracer = nullptr;
        int           idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override
        { return mgr != nullptr && mgr->is_active() ? AST_ENABLE : AST_DISABLE; }
    };

    // Action identifiers (used for registration + menu/popup attach).
    namespace actions
    {
        constexpr const char *RUN_BACK     = "idattd:run_back";
        constexpr const char *POS_LABEL    = "idattd:pos_label";
        constexpr const char *TIMELINE     = "idattd:timeline";
        constexpr const char *GOTO_POS     = "idattd:goto_position";
        constexpr const char *TRACE_FUNC   = "idattd:trace_func";
        constexpr const char *TRACE_PAT    = "idattd:trace_pattern";
        constexpr const char *ANALYZE_FUNC = "idattd:analyze_func";
        constexpr const char *OPEN_TRACED  = "idattd:open_traced";
        constexpr const char *OPEN_EVENTS  = "idattd:open_events";
        constexpr const char *RUN_TRACE    = "idattd:run_trace";
    }
}
