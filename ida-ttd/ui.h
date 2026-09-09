#pragma once

#include "pch.h"
#include "trace_manager.h"
#include "tracer.h"
#include "bookmarks.h"
#include "memsearch.h"
#include "memmap.h"

namespace idattd
{
    // Two rules hold for every chooser below.
    //
    // None sets CH_KEEP. They are heap-allocated and handed to choose(), and
    // CH_KEEP means the instance is not tied to its widget, so IDA would never
    // delete it. It is for static or stack-allocated choosers.
    //
    // enter() queues navigation with request_continue_process() rather than
    // resuming the debugger directly, and get_ea() never navigates at all: IDA
    // calls get_ea while rendering rows, which would resume once per visible row.

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

    // List of functions selected for call tracing. Insert opens choose_func_ea;
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
    // before chooser_t, so its arrays/title stay alive for the chooser's
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

    // Saved trace positions, kept in the IDB. Enter time-travels to the row,
    // Ins bookmarks the current position, Del removes, and the edit key reopens
    // the name/comment form. The store is the single copy: this chooser holds a
    // pointer to it rather than a snapshot, so several open windows agree.
    class BookmarkChooser : public chooser_t
    {
    public:
        BookmarkChooser(TraceManager *mgr, BookmarkStore *store);

        size_t  idaapi get_count() const override;
        void    idaapi get_row(qstrvec_t *cols, int *icon, chooser_item_attrs_t *attrs, size_t n) const override;
        ea_t    idaapi get_ea(size_t n) const override;   // pure navigation, no side effects
        cbret_t idaapi enter(size_t n) override;
        cbret_t idaapi ins(ssize_t n) override;
        cbret_t idaapi del(size_t n) override;
        cbret_t idaapi edit(size_t n) override;

    private:
        TraceManager  *m_mgr;
        BookmarkStore *m_store;
    };

    // Results of a memory access search: one row per recorded touch of the
    // watched range. Holds its own snapshot so several searches can sit open
    // side by side, each frozen as it was run. Enter time-travels to the
    // access; the address column follows the instruction that made it.
    class MemAccessChooser : public chooser_t
    {
    public:
        MemAccessChooser(TraceManager *mgr, ea_t lo, ea_t hi,
                         std::vector<MemAccess> &&hits);

        size_t  idaapi get_count() const override;
        void    idaapi get_row(qstrvec_t *cols, int *icon, chooser_item_attrs_t *attrs, size_t n) const override;
        ea_t    idaapi get_ea(size_t n) const override;
        cbret_t idaapi enter(size_t n) override;
        cbret_t idaapi del(size_t n) override;

    private:
        TraceManager           *m_mgr;
        std::vector<MemAccess>  m_hits;   // frozen snapshot
        qstring                 m_title;  // owned: chooser_base_t keeps the pointer
    };

    // The reconstructed memory map, as a timeline. One row per allocation,
    // protection change or free the recording made, in the order they happened.
    // Enter time-travels to the call that made the change.
    class MemoryMapChooser : public chooser_t
    {
    public:
        MemoryMapChooser(TraceManager *mgr, std::vector<RegionChange> &&rows);

        size_t  idaapi get_count() const override;
        void    idaapi get_row(qstrvec_t *cols, int *icon, chooser_item_attrs_t *attrs, size_t n) const override;
        ea_t    idaapi get_ea(size_t n) const override;
        cbret_t idaapi enter(size_t n) override;

    private:
        TraceManager             *m_mgr;
        std::vector<RegionChange> m_rows;   // frozen snapshot
        qstring                   m_title;  // owned: chooser_base_t keeps the pointer
    };

    // ---- TTD-specific action handlers --------------------------------------
    // Most stepping is provided by IDA's native debugger actions (attached to
    // our toolbar). IDA has no native "continue backwards", so we add one.
    // All TTD actions are only meaningful while a trace is being replayed, so the
    // plugin registers them when a trace is loaded and unregisters them when it is
    // unloaded (Plugin::show_actions/hide_actions) -- outside a session neither the
    // shortcuts nor the toolbar buttons exist at all. While they do exist a trace
    // is by definition active, hence AST_ENABLE_ALWAYS; the handlers still check
    // is_active() (true exactly when a cursor over a trace exists) before acting.
    struct RunBackHandler : public action_handler_t
    {
        TraceManager *mgr = nullptr;
        int           idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override
        { return AST_ENABLE_ALWAYS; }
    };

    struct OpenTimelineHandler : public action_handler_t
    {
        TraceManager *mgr = nullptr;
        int           idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override
        { return AST_ENABLE_ALWAYS; }
    };

    // IDA has no native "step out backwards", so we add one (run backward out of
    // the current function to its call site).
    struct StepOutBackHandler : public action_handler_t
    {
        TraceManager *mgr = nullptr;
        int           idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override
        { return AST_ENABLE_ALWAYS; }
    };

    // IDA greys out its native ThreadRunToCursorBackwards for this backend, so we
    // provide our own: run backward until execution reaches the cursor address.
    struct RunToCursorBackHandler : public action_handler_t
    {
        TraceManager *mgr = nullptr;
        int           idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override
        { return AST_ENABLE_ALWAYS; }
    };

    // IDA's native ThreadRunToCursor intermittently fails on this read-only
    // backend (it tries to plant a real/source breakpoint), so we provide our
    // own forward run-to-cursor that drives the cursor with a temp watchpoint.
    struct RunToCursorFwdHandler : public action_handler_t
    {
        TraceManager *mgr = nullptr;
        int           idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override
        { return AST_ENABLE_ALWAYS; }
    };

    struct GotoPositionHandler : public action_handler_t
    {
        TraceManager *mgr = nullptr;
        int           idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override
        { return AST_ENABLE_ALWAYS; }
    };

    // Click handler for the toolbar position readout: copies the current
    // Sequence:Steps position to the clipboard.
    struct PositionCopyHandler : public action_handler_t
    {
        TraceManager *mgr = nullptr;
        int           idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override
        { return AST_ENABLE_ALWAYS; }
    };

    // Deep, on-demand "define the whole enclosing function" (expensive backward
    // trace walk behind a wait box). The cheap per-stop analysis never does this.
    struct AnalyzeFuncHandler : public action_handler_t
    {
        TraceManager *mgr = nullptr;
        int           idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override
        { return AST_ENABLE_ALWAYS; }
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
        { return AST_ENABLE_ALWAYS; }
    };

    struct OpenTracedHandler : public action_handler_t
    {
        TraceManager   *mgr    = nullptr;
        FunctionTracer *tracer = nullptr;
        int           idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override
        { return AST_ENABLE_ALWAYS; }
    };

    struct OpenEventsHandler : public action_handler_t
    {
        TraceManager   *mgr    = nullptr;
        FunctionTracer *tracer = nullptr;
        int           idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override
        { return AST_ENABLE_ALWAYS; }
    };

    struct RunTraceHandler : public action_handler_t
    {
        TraceManager   *mgr    = nullptr;
        FunctionTracer *tracer = nullptr;
        int           idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override
        { return AST_ENABLE_ALWAYS; }
    };

    // Bookmark the current trace position (prompts for a name and a comment).
    struct AddBookmarkHandler : public action_handler_t
    {
        TraceManager  *mgr   = nullptr;
        BookmarkStore *store = nullptr;
        int           idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override
        { return AST_ENABLE_ALWAYS; }
    };

    struct OpenBookmarksHandler : public action_handler_t
    {
        TraceManager  *mgr   = nullptr;
        BookmarkStore *store = nullptr;
        int           idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override
        { return AST_ENABLE_ALWAYS; }
    };

    // Sweep the recording and colour the instructions that actually executed.
    struct CoverageHandler : public action_handler_t
    {
        TraceManager *mgr = nullptr;
        int           idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override
        { return AST_ENABLE_ALWAYS; }
    };

    struct ClearCoverageHandler : public action_handler_t
    {
        int           idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override
        { return AST_ENABLE_ALWAYS; }
    };

    // Checkable: highlight each function as you stop in it, without asking.
    struct AutoCoverageHandler : public action_handler_t
    {
        int           idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override;
    };

    // Build the memory-region timeline and open it as a listing.
    struct MemoryMapHandler : public action_handler_t
    {
        TraceManager *mgr = nullptr;
        int           idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override
        { return AST_ENABLE_ALWAYS; }
    };

    struct ClearMemoryMapHandler : public action_handler_t
    {
        TraceManager *mgr = nullptr;
        int           idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override
        { return AST_ENABLE_ALWAYS; }
    };

    // Find every read, write or execute of an address over the whole trace.
    struct MemSearchHandler : public action_handler_t
    {
        TraceManager *mgr = nullptr;
        int           idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override
        { return AST_ENABLE_ALWAYS; }
    };

    // Record where every indirect call actually went, as comments and xrefs.
    struct IndirectCallsHandler : public action_handler_t
    {
        TraceManager *mgr = nullptr;
        int           idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override
        { return AST_ENABLE_ALWAYS; }
    };

    struct ClearIndirectCallsHandler : public action_handler_t
    {
        int           idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override
        { return AST_ENABLE_ALWAYS; }
    };

    // Start the replay for a database that was created from a .run file. This
    // is the one TTD action that exists while no trace is loaded, so it lives on
    // the Debugger menu rather than the TTD menu (which the plugin only builds
    // once a session is running).
    struct AttachTraceHandler : public action_handler_t
    {
        Plugin *p = nullptr;
        int  idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override;
    };

    // Action identifiers, used for registration and for menu and popup attach.
    namespace actions
    {
        constexpr const char *ADD_BOOKMARK  = "idattd:add_bookmark";
        constexpr const char *BOOKMARKS     = "idattd:bookmarks";
        constexpr const char *COVERAGE      = "idattd:coverage";
        constexpr const char *COVERAGE_CLR  = "idattd:coverage_clear";
        constexpr const char *COVERAGE_AUTO = "idattd:coverage_auto";
        constexpr const char *MEM_SEARCH    = "idattd:mem_search";
        constexpr const char *MEM_MAP       = "idattd:memory_map";
        constexpr const char *MEM_MAP_CLR   = "idattd:memory_map_clear";
        constexpr const char *INDIRECT      = "idattd:indirect_calls";
        constexpr const char *INDIRECT_CLR  = "idattd:indirect_calls_clear";
        constexpr const char *RUN_BACK     = "idattd:run_back";
        constexpr const char *STEP_OUT_BACK = "idattd:step_out_back";
        constexpr const char *RUN_TO_CUR_BACK = "idattd:run_to_cursor_back";
        constexpr const char *RUN_TO_CUR_FWD = "idattd:run_to_cursor_fwd";
        constexpr const char *POS_LABEL    = "idattd:pos_label";
        constexpr const char *TIMELINE     = "idattd:timeline";
        constexpr const char *GOTO_POS     = "idattd:goto_position";
        constexpr const char *TRACE_FUNC   = "idattd:trace_func";
        constexpr const char *TRACE_PAT    = "idattd:trace_pattern";
        constexpr const char *ANALYZE_FUNC = "idattd:analyze_func";
        constexpr const char *OPEN_TRACED  = "idattd:open_traced";
        constexpr const char *OPEN_EVENTS  = "idattd:open_events";
        constexpr const char *RUN_TRACE    = "idattd:run_trace";
        constexpr const char *ATTACH_TRACE = "idattd:attach_trace";
    }
}
