#pragma once

#include "common/pch.h"
#include "debugger/trace_manager.h"
#include "analysis/tracer.h"
#include "analysis/bookmarks.h"
#include "analysis/memsearch.h"
#include "analysis/memmap.h"

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
    // snapshot of the calls so several "TTD calls" tabs can coexist, each
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
    //
    // Most stepping is provided by IDA's native debugger actions, attached to
    // the TTD toolbar. The handlers here are the TTD-only commands plus the few
    // movements IDA has no working native action for.
    //
    // A TTD action is only registered while a trace is being replayed
    // (Plugin::show_actions / hide_actions), so outside a session neither its
    // shortcut nor its toolbar button exists at all. While one does exist a
    // trace is by definition active, which is why the shared update() below
    // answers AST_ENABLE_ALWAYS; handlers still check is_active() (true exactly
    // when a cursor over a trace exists) before acting.

    // The handles nearly every handler needs. Bound once by the plugin, so
    // adding a command does not add a line to a back-pointer block.
    struct ActionContext
    {
        TraceManager   *mgr    = nullptr;
        FunctionTracer *tracer = nullptr;
        BookmarkStore  *store  = nullptr;
    };

    // Base for the TTD handlers: the shared context, and the enabled-always
    // update() explained above. A handler that genuinely has something to say
    // about its own state overrides update(), which makes those three visible.
    struct TtdAction : public action_handler_t
    {
        const ActionContext *ctx = nullptr;

        TraceManager   *mgr()    const { return ctx != nullptr ? ctx->mgr    : nullptr; }
        FunctionTracer *tracer() const { return ctx != nullptr ? ctx->tracer : nullptr; }
        BookmarkStore  *store()  const { return ctx != nullptr ? ctx->store  : nullptr; }

        action_state_t idaapi update(action_update_ctx_t *) override
        { return AST_ENABLE_ALWAYS; }
    };

    // IDA has no native "continue backwards".
    struct RunBackHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };

    struct OpenTimelineHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };

    // IDA has no native "step out backwards" either (run backward out of the
    // current function to its call site).
    struct StepOutBackHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };

    // IDA greys out its native ThreadRunToCursorBackwards for this backend, so
    // this runs backward until execution reaches the cursor address.
    struct RunToCursorBackHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };

    // IDA's native ThreadRunToCursor intermittently fails on this read-only
    // backend (it tries to plant a real/source breakpoint), so this drives the
    // cursor forward with a temporary watchpoint instead.
    struct RunToCursorFwdHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };

    struct GotoPositionHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };

    // Click handler for the toolbar position readout: copies the current
    // Sequence:Steps position to the clipboard.
    struct PositionCopyHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };

    // Deep, on-demand "define the whole enclosing function" (an expensive
    // backward trace walk behind a wait box). The per-stop analysis never does
    // this.
    struct AnalyzeFuncHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };

    // One click: trace the function under the cursor, sweep, and show results.
    struct TraceFuncHandler : public TtdAction
    {
        int idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override;
    };

    // Prompt for a name pattern ("module!Glob*"), trace every matching function,
    // sweep, and show results (one combined Arguments column when >1 match).
    struct TracePatternHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };

    struct OpenTracedHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };

    struct OpenEventsHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };

    struct RunTraceHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };

    // Bookmark the current trace position (prompts for a name and a comment).
    struct AddBookmarkHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };

    struct OpenBookmarksHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };

    // Sweep the recording and colour the instructions that actually executed.
    struct CoverageHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };

    struct ClearCoverageHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };

    // Checkable: highlight each function as you stop in it, without asking.
    struct AutoCoverageHandler : public TtdAction
    {
        int idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override;
    };

    // Build the memory-region timeline and open it as a listing.
    struct MemoryMapHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };

    struct ClearMemoryMapHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };

    // Find every read, write or execute of an address over the whole trace.
    struct MemSearchHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };

    // Re-read a range of memory from the recording and disassemble it again.
    // Uses the current selection when there is one, otherwise asks for a range.
    struct RereadHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };

    // Record where every indirect call actually went, as comments and xrefs.
    struct IndirectCallsHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };

    struct ClearIndirectCallsHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };

    // Start the replay for a database that was created from a .run file. This is
    // the one TTD action that exists while no trace is loaded, so it lives on
    // the Debugger menu rather than the TTD menu (which the plugin only builds
    // once a session is running) and is not part of the TTD action table.
    struct AttachTraceHandler : public action_handler_t
    {
        // A callback rather than a Plugin*, so nothing under ui/ has to know
        // what a Plugin is. The plugin binds Plugin::start_trace_session.
        std::function<void()> start_session;
        int  idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override;
    };

    // Turn the automatic replay start for this database on or off. A database
    // made from a .run starts replaying as soon as it is opened, which is what
    // opening a recording is for; this is how that is switched off. Lives on
    // the Debugger menu beside AttachTraceHandler, for the same reason.
    struct AutoStartHandler : public action_handler_t
    {
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
        constexpr const char *REREAD        = "idattd:reread_memory";
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
        constexpr const char *AUTO_START   = "idattd:auto_start";
    }
}
