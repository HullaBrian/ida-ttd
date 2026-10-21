#pragma once

#include "common/pch.h"
#include "debugger/trace_manager.h"
#include "analysis/tracer.h"
#include "analysis/bookmarks.h"
#include "analysis/memsearch.h"
#include "analysis/memmap.h"
#include "analysis/address_space.h"
#include "analysis/origin.h"
#include "analysis/handles.h"
#include "analysis/syscalls.h"
#include "analysis/replay_scans.h"
#include "analysis/calltree.h"

#include <map>

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

    // Queue a travel to 'p' and return at once, as a double-click in a listing
    // does. Nothing happens when no trace is being replayed or 'p' is not a
    // position.
    void travel_to(TraceManager *mgr, Position p);

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
        // What a row says about its function, worked out once per function
        // rather than on every repaint: the signature lookups behind it read
        // type information.
        struct FuncLabel
        {
            qstring              name;
            // For the combined Arguments column: each argument's name, or
            // empty to show the value alone.
            std::vector<qstring> params;
        };

        TraceManager                    *m_mgr;
        std::vector<FunctionInvocation>  m_events;  // frozen snapshot
        std::map<ea_t, FuncLabel>        m_labels;  // by FunctionInvocation::func_ea
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

    // The syscalls the recording made, with their result and arguments.
    // Enter time-travels to the call.
    class SyscallChooser : public chooser_t
    {
    public:
        // 'decoded' lines up with 'calls': each call's arguments by name, or
        // empty where the metadata has no signature (or decoding stopped).
        SyscallChooser(TraceManager *mgr, std::vector<SyscallEvent> &&calls,
                       std::vector<qstring> &&decoded);

        size_t  idaapi get_count() const override;
        void    idaapi get_row(qstrvec_t *cols, int *icon, chooser_item_attrs_t *attrs, size_t n) const override;
        cbret_t idaapi enter(size_t n) override;
        // Ctrl+E: decode one call that was not (the decoding was stopped).
        cbret_t idaapi edit(size_t n) override;
        // Refresh (Ctrl+U): list and decode them again from the recording.
        cbret_t idaapi refresh(ssize_t n) override;

    private:
        const std::optional<SyscallArgs> &args_of(size_t n) const;
        void reset_rows();

        TraceManager              *m_mgr;
        std::vector<SyscallEvent>  m_calls;
        std::vector<qstring>       m_decoded;
        // Read a chunk at a time as rows are drawn; see ARG_CHUNK.
        mutable std::vector<std::optional<SyscallArgs>> m_args;
        mutable std::vector<bool>                       m_argsRead;
        qstring                    m_title;  // owned: chooser_base_t keeps the pointer
    };

    // Code the program wrote and then ran, one row per executed address.
    // Selecting a row shows the code; Enter time-travels to the write.
    class SelfModChooser : public chooser_t
    {
    public:
        SelfModChooser(TraceManager *mgr, std::vector<SelfModHit> &&hits);

        size_t  idaapi get_count() const override;
        void    idaapi get_row(qstrvec_t *cols, int *icon, chooser_item_attrs_t *attrs, size_t n) const override;
        ea_t    idaapi get_ea(size_t n) const override;
        cbret_t idaapi enter(size_t n) override;

    private:
        TraceManager             *m_mgr;
        std::vector<SelfModHit>   m_hits;
        qstring                   m_title;  // owned: chooser_base_t keeps the pointer
    };

    // Strings recovered by replaying the recording. Selecting a row shows the
    // address; Enter time-travels to where the string appeared.
    class StringsChooser : public chooser_t
    {
    public:
        StringsChooser(TraceManager *mgr, std::vector<StringHit> &&hits);

        size_t  idaapi get_count() const override;
        void    idaapi get_row(qstrvec_t *cols, int *icon, chooser_item_attrs_t *attrs, size_t n) const override;
        ea_t    idaapi get_ea(size_t n) const override;
        cbret_t idaapi enter(size_t n) override;

    private:
        TraceManager            *m_mgr;
        std::vector<StringHit>   m_hits;
        qstring                  m_title;  // owned: chooser_base_t keeps the pointer
    };

    // Buffers recovered by replaying the recording. Enter time-travels to the
    // last write, where the buffer is complete.
    class BuffersChooser : public chooser_t
    {
    public:
        BuffersChooser(TraceManager *mgr, std::vector<BufferHit> &&hits);

        size_t  idaapi get_count() const override;
        void    idaapi get_row(qstrvec_t *cols, int *icon, chooser_item_attrs_t *attrs, size_t n) const override;
        ea_t    idaapi get_ea(size_t n) const override;
        cbret_t idaapi enter(size_t n) override;

    private:
        TraceManager            *m_mgr;
        std::vector<BufferHit>   m_hits;
        qstring                  m_title;  // owned: chooser_base_t keeps the pointer
    };

    // The reconstructed memory map, as a timeline. One row per allocation,
    // protection change or free the recording made, in the order they happened.
    // Enter time-travels to the call that made the change.
    class MemoryTimelineChooser : public chooser_t
    {
    public:
        MemoryTimelineChooser(TraceManager *mgr, std::vector<RegionChange> &&rows);

        size_t  idaapi get_count() const override;
        void    idaapi get_row(qstrvec_t *cols, int *icon, chooser_item_attrs_t *attrs, size_t n) const override;
        ea_t    idaapi get_ea(size_t n) const override;
        cbret_t idaapi enter(size_t n) override;

    private:
        TraceManager             *m_mgr;
        std::vector<RegionChange> m_rows;   // frozen snapshot
        qstring                   m_title;  // owned: chooser_base_t keeps the pointer
    };

    // Where a value came from: one row per hop, from the value asked about
    // back to where it was made. Enter travels to the instruction that set
    // the row's value, before it ran.
    class ValueOriginChooser : public chooser_t
    {
    public:
        ValueOriginChooser(TraceManager *mgr, std::vector<OriginHop> &&hops);
        ~ValueOriginChooser() override;

        size_t  idaapi get_count() const override;
        void    idaapi get_row(qstrvec_t *cols, int *icon, chooser_item_attrs_t *attrs, size_t n) const override;
        ea_t    idaapi get_ea(size_t n) const override;
        cbret_t idaapi enter(size_t n) override;
        // Edit (Ctrl+E): follow a value the row's instruction read, as a new
        // chain appended to the list.
        cbret_t idaapi edit(size_t n) override;

    private:
        TraceManager          *m_mgr;
        std::vector<OriginHop> m_hops;
        // For the first row of a chain added by edit(): the row whose
        // instruction read it. -1 for every other row.
        std::vector<ssize_t>   m_input_of;
        qstring                m_title;  // owned: chooser_base_t keeps the pointer
    };

    // The handles the program opened and closed. Enter travels to where one
    // was opened; Edit (Ctrl+E) to where it was closed.
    class HandlesChooser : public chooser_t
    {
    public:
        HandlesChooser(TraceManager *mgr, std::vector<HandleRecord> &&rows);

        size_t  idaapi get_count() const override;
        void    idaapi get_row(qstrvec_t *cols, int *icon, chooser_item_attrs_t *attrs, size_t n) const override;
        cbret_t idaapi enter(size_t n) override;
        cbret_t idaapi edit(size_t n) override;
        // Refresh (Ctrl+U): rebuild the list from the recording.
        cbret_t idaapi refresh(ssize_t n) override;

    private:
        void set_title();

        TraceManager             *m_mgr;
        std::vector<HandleRecord> m_rows;
        qstring                   m_title;  // owned: chooser_base_t keeps the pointer
    };

    // The memory map at the playhead: every region with its protection, kind
    // and use (see address_space_at). Follows the playhead: each stop
    // refreshes it. Enter jumps to the region; travelling to where it was
    // made is on the context menu.
    class MemoryMapChooser : public chooser_t
    {
    public:
        static const char *const TITLE;
        explicit MemoryMapChooser(TraceManager *mgr);

        size_t  idaapi get_count() const override;
        void    idaapi get_row(qstrvec_t *cols, int *icon, chooser_item_attrs_t *attrs, size_t n) const override;
        ea_t    idaapi get_ea(size_t n) const override;
        cbret_t idaapi enter(size_t n) override;
        cbret_t idaapi edit(size_t n) override;
        cbret_t idaapi refresh(ssize_t n) override;

        // Refresh the open listing, if there is one, for a new position.
        static void refresh_open();

    private:
        void rebuild() const;

        TraceManager *m_mgr;
        mutable std::vector<AddressRegion> m_rows;
        // What m_rows was built from: the playhead and the size of the change
        // timeline, which grows when the map is built with the listing open.
        mutable Position                   m_at = Position::none();
        mutable size_t                     m_mapSize = 0;
    };

    // Travel to 'p' and, once there, show 'ea' in the hex view if one is
    // open (the listing rows that name memory: buffers, strings). False when
    // no hex view is open; the travel happens either way.
    bool travel_and_show_bytes(TraceManager *mgr, Position p, ea_t ea);
    // After each stop: the hex view jump a travel above left for it.
    void show_pending_bytes();

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
        // Redraw the toolbar's position readout (a fork begun or ended).
        std::function<void()> refresh_position;
        // Stop the replay and start it again on another recording (a fork)
        // in this database.
        std::function<void(const qstring &)> switch_trace;
    };

    // Base for the TTD handlers: the shared context, and the enabled-always
    // update() explained above. A handler that genuinely has something to say
    // about its own state (a checkbox, a backend capability, a selection)
    // declares its own update(), so those stand out below.
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

    // The whole PDB (types too) of the module under the cursor, through IDA's
    // PDB plugin. Names are applied in the background on their own; this is
    // the blocking load, only ever done on request.
    struct FullPdbHandler : public TtdAction
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
    struct MemoryTimelineHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };

    // The memory map at the playhead.
    struct MemoryMapHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };

    // The memory heatmap: count every access by page and slice of time, and
    // open the window that draws it (IDAPython with PySide6).
    struct HeatmapHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };
    // The counts the window draws, as ttd("ui.heat") hands them over; empty
    // until build_heatmap() ran.
    const qstring &heatmap_json();
    // Count over 'when' (the whole recording by default; part of it when the
    // window zooms in, which only some backends can).
    bool build_heatmap(TraceManager *mgr, qstring *err, PositionRange when = PositionRange{});
    // The slice of the counted span the cursor's position falls in, -1 when
    // it is outside the span (or nothing is counted).
    int heatmap_current_slice(TraceManager *mgr);

    // The handles the program opened and closed.
    struct HandlesHandler : public TtdAction
    {
        int idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override;
    };

    // Where did this value come from? A register (the registers window, or
    // one under the cursor) or memory (the hex view's selection, or data
    // under the cursor), else asked for.
    struct ValueOriginHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };
    // The same as a graph: every chain at once, each input of an instruction
    // that combined several values followed. From a value-origin listing's
    // context menu, of the value it started from.
    struct OriginGraphHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };
    bool is_value_origin_listing(TWidget *w);
    // Build the graph of 'what' as of 'at' and show it (the action, without
    // asking: ttd("ui.origingraph")).
    void show_origin_graph(TraceManager *mgr, const OriginTarget &what, Position at);

    // Find every read, write or execute of an address over the whole trace.
    struct MemSearchHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };

    // The self-modifying code listing. Enabled only for a backend that can
    // look for it.
    struct SelfModHandler : public TtdAction
    {
        int idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override;
    };

    // The call tree of the function at the cursor.
    struct CallTreeHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };
    // The last call tree built, as JSON, for the window script (calltree_py.hh).
    const qstring &call_tree_json();

    // The replay scans. Enabled only for a backend that can replay.
    struct RecoverStringsHandler : public TtdAction
    {
        int idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override;
    };
    struct RecoverBuffersHandler : public TtdAction
    {
        int idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override;
    };

    // Forking: "Fork here" makes the current position a fork, whose
    // registers and memory are then changed in IDA as on a live target;
    // "Record fork" runs it on into a new trace; "Discard fork" drops it.
    // Enabled only for a backend that can fork (and the last two only with a
    // fork begun).
    struct ForkHandler : public TtdAction
    {
        int idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override;
    };
    struct ForkRecordHandler : public TtdAction
    {
        int idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override;
    };
    struct ForkDiscardHandler : public TtdAction
    {
        int idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override;
    };

    // The Fork manager: a graph of this database's recording and the forks
    // recorded from it. Open / Forget act on the node selected in it.
    struct ForkManagerHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };
    struct ForkOpenHandler : public TtdAction
    {
        int idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override;
    };
    struct ForkForgetHandler : public TtdAction
    {
        int idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override;
    };
    // Redraw the Fork manager, if it is open (a fork recorded, a switch).
    void refresh_fork_manager();
    // The widget is the Fork manager's graph.
    bool fork_manager_widget(TWidget *w);
    // The Fork manager is open.
    bool fork_manager_is_open();
    // Close its window (the plugin stays). For a switch, before the session ends.
    void close_fork_manager_window();
    // Close it and drop its hold on the plugin (the plugin is going away).
    void close_fork_manager();
    // The views showed a fork's changes, and the fork is gone or begun:
    // have IDA read registers and memory again, and redraw the position.
    void fork_draft_changed(const ActionContext *ctx, bool views_showed_changes);

    // Replays (forks, recovered strings and buffers) start with the saved
    // hives folder and without consent to replay a recording made against
    // the host. When one is refused for want of either, this asks the user
    // for it and updates 'rs'; true to try again.
    ReplaySettings initial_replay_settings(TraceManager *mgr);
    bool ask_replay_needs(TraceManager *mgr, ReplaySettings *rs);

    // The syscall listing. Enabled only for a recording that has one.
    struct SyscallsHandler : public TtdAction
    {
        int idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override;
    };

    // Re-read a range of memory from the recording and disassemble it again.
    // Uses the current selection when there is one, otherwise asks for a range.
    struct RereadHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };

    // Record where every indirect call actually went, as comments and xrefs.
    struct IndirectCallsHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };

    struct ClearIndirectCallsHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };

    // Toggle: resolve the indirect calls of each function you stop in.
    struct AutoIndirectCallsHandler : public TtdAction
    {
        int idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override;
    };

    // Start the replay for a database that was created from a .run file. It
    // exists while no trace is loaded, so it is not part of the session's
    // action table: it sits in the part of the TTD menu that is always there
    // (Plugin::rebuild_ttd_menu).
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
    // opening a recording is for; this is how that is switched off. Lives in
    // the part of the TTD menu that is there outside a session, beside
    // AttachTraceHandler, for the same reason.
    struct AutoStartHandler : public action_handler_t
    {
        int  idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override;
    };

    // Get Microsoft's TTD replay runtime, which ida-ttd may not ship: copy it
    // from an installed WinDbg, or download WinDbg after the user accepts its
    // license (scripts/ida_ttd_runtime.py, through IDAPython). Under TTD >
    // Backends, which is there in every database: it is needed exactly when
    // no session can start.
    struct InstallRuntimeHandler : public action_handler_t
    {
        int  idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override
        { return AST_ENABLE_ALWAYS; }
    };

    // Install the Sogen backend (GPL-2.0, so not in the Apache-2.0 package)
    // into $IDAUSR\plugins\ida-ttd-backends\, from a file the user picks: the
    // DLL, or a release zip that holds it (ida_ttd_runtime.install_sogen()).
    struct InstallSogenHandler : public action_handler_t
    {
        int  idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override
        { return AST_ENABLE_ALWAYS; }
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
        constexpr const char *SYSCALLS      = "idattd:syscalls";
        constexpr const char *SELF_MOD      = "idattd:self_modifying";
        constexpr const char *FORK          = "idattd:fork";
        constexpr const char *FORK_RECORD   = "idattd:fork_record";
        constexpr const char *FORK_DISCARD  = "idattd:fork_discard";
        constexpr const char *FORK_MANAGER  = "idattd:fork_manager";
        constexpr const char *FORK_OPEN     = "idattd:fork_open";
        constexpr const char *FORK_FORGET   = "idattd:fork_forget";
        constexpr const char *STRINGS       = "idattd:recover_strings";
        constexpr const char *CALL_TREE     = "idattd:call_tree";
        constexpr const char *BUFFERS       = "idattd:recover_buffers";
        constexpr const char *MEM_MAP       = "idattd:memory_map";
        constexpr const char *MEM_TIMELINE  = "idattd:memory_timeline";
        constexpr const char *VALUE_ORIGIN  = "idattd:value_origin";
        constexpr const char *ORIGIN_GRAPH  = "idattd:origin_graph";
        constexpr const char *HANDLES       = "idattd:handles";
        constexpr const char *HEATMAP       = "idattd:heatmap";
        constexpr const char *REREAD        = "idattd:reread_memory";
        constexpr const char *INDIRECT      = "idattd:indirect_calls";
        constexpr const char *INDIRECT_CLR  = "idattd:indirect_calls_clear";
        constexpr const char *INDIRECT_AUTO = "idattd:indirect_calls_auto";
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
        constexpr const char *FULL_PDB     = "idattd:full_pdb";
        constexpr const char *ATTACH_TRACE = "idattd:attach_trace";
        constexpr const char *AUTO_START   = "idattd:auto_start";
        constexpr const char *INSTALL_RUNTIME = "idattd:install_runtime";
        constexpr const char *INSTALL_SOGEN   = "idattd:install_sogen";
        // Greyed section headings in TTD > Backends, one per backend.
        constexpr const char *BACKEND_HDR_MS    = "idattd:backend_hdr_msttd";
        constexpr const char *BACKEND_HDR_SOGEN = "idattd:backend_hdr_sogen";
    }
}
