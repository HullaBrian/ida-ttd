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
#include "analysis/trace_store.h"

#include <map>

namespace idattd
{
    // Two rules for every chooser below:
    //
    // - None sets CH_KEEP. They are heap-allocated and handed to choose();
    //   with CH_KEEP IDA would never delete them (it is for static or stack
    //   choosers).
    // - enter() queues navigation (travel_to) rather than resuming the
    //   debugger directly, and get_ea() never navigates: IDA calls it while
    //   rendering, once per visible row.

    // Queue a travel to 'p' and return at once, as a double-click in a listing
    // does. No-op when no trace is replayed or 'p' is not a position.
    void travel_to(TraceManager *mgr, Position p);

    // The recording a listing was made from, taken when the listing is
    // built. A listing stays open after its session ends, and the Fork
    // manager can switch this database to a fork, whose positions mean other
    // things: a listing's positions must only be used on its own recording.
    struct RecordingStamp
    {
        uint64_t fingerprint = current_trace();
        // The session replays the recording this was taken from.
        bool current() const { return fingerprint == 0 || fingerprint == current_trace(); }
    };

    // travel_to, refused with a message when the listing ('made') is from
    // another recording than the one being replayed.
    void travel_to(TraceManager *mgr, Position p, const RecordingStamp &made);
    // False, with that message, when 'made' is not the replayed recording:
    // for a listing about to read the recording at one of its positions.
    bool listing_is_current(const RecordingStamp &made);

    // Suffix ' (2)', ' (3)', ... while a widget already has 'title'. IDA keys
    // widgets by title and focuses the open one instead of showing a second:
    // two searches of one address with as many hits each, or a list made
    // again after a fork switch, would never show.
    void make_title_unique(qstring *title);

    // The base of the listings made from the recording: a snapshot of rows,
    // the manager, the recording they came from (RecordingStamp), and the
    // title, owned here since chooser_base_t keeps the pointer, not a copy.
    // get_count() is the rows'; enter() travels to the row's position_of(),
    // refused for a listing of another recording. A listing that lists
    // again (Refresh) hands the new rows to restamp(), which also stamps
    // them with the recording replayed now.
    template <class Row>
    class ListingChooser : public chooser_t
    {
    public:
        size_t  idaapi get_count() const override { return m_rows.size(); }
        cbret_t idaapi enter(size_t n) override
        {
            if ( n < m_rows.size() )
                travel_to(m_mgr, position_of(m_rows[n]), m_made);
            return cbret_t(n, NOTHING_CHANGED);
        }

    protected:
        // 'fixed_title' for a listing with one window (it is then not made
        // unique); else nullptr and set_unique_title() in the constructor.
        ListingChooser(TraceManager *mgr, uint32 flags, int columns, const int *widths,
                       const char *const *header, const char *fixed_title,
                       std::vector<Row> &&rows = {})
            : chooser_t(flags, columns, widths, header, fixed_title),
              m_mgr(mgr), m_rows(std::move(rows))
        {
        }

        // Where enter() travels for a row. A listing whose double-click does
        // something else overrides enter() instead.
        virtual Position position_of(const Row &) const { return Position::none(); }

        // Row n, or nullptr past the end (IDA can ask for a row a refresh
        // just removed).
        const Row *row(size_t n) const { return n < m_rows.size() ? &m_rows[n] : nullptr; }

        // 'text', suffixed while another window has it (make_title_unique).
        // Once, from the constructor: on a refresh it would find this
        // listing's own window and add ' (2)'.
        void set_unique_title(const qstring &text)
        {
            m_title = text;
            make_title_unique(&m_title);
            title = m_title.c_str();
        }

        // New rows, listed again from the recording replayed now.
        void restamp(std::vector<Row> &&rows)
        {
            m_rows = std::move(rows);
            m_made = RecordingStamp{};
        }

        // del() for a listing whose rows can be dropped from view.
        cbret_t erase_row(size_t n)
        {
            if ( n < m_rows.size() )
                m_rows.erase(m_rows.begin() + n);
            // A bare ALL_CHANGED would convert to cbret_t(1, ...) and select row 1.
            return cbret_t(adjust_last_item(n), ALL_CHANGED);
        }

        TraceManager     *m_mgr;
        RecordingStamp    m_made;       // the recording the rows come from
        std::vector<Row>  m_rows;       // frozen snapshot
        qstring           m_title;      // set_unique_title's
    };

    // A non-modal "Timeline" chooser listing notable trace positions
    // (thread create/exit, module load/unload, exceptions). Double-clicking a
    // row moves the cursor to that position.
    class PositionChooser : public ListingChooser<TraceManager::NamedPosition>
    {
    public:
        explicit PositionChooser(TraceManager *mgr);

        void    idaapi get_row(qstrvec_t *cols, int *icon, chooser_item_attrs_t *attrs, size_t n) const override;

    private:
        Position position_of(const TraceManager::NamedPosition &r) const override { return r.pos; }
    };

    // The trace-events column layout: Start/End/Thread/Function, then one
    // column per parameter when a single function is traced (else one
    // "Arguments" column), then Return. Also owns the unique title. A base of
    // TraceEventsChooser listed before chooser_t, so its arrays and title
    // outlive the chooser (chooser_base_t keeps the pointers, not copies).
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
    // snapshot so several "TTD calls" tabs can coexist. Double-click travels
    // to the call.
    class TraceEventsChooser : public EventColumns, public ListingChooser<FunctionInvocation>
    {
    public:
        TraceEventsChooser(TraceManager *mgr, FunctionTracer *tracer);

        void    idaapi get_row(qstrvec_t *cols, int *icon, chooser_item_attrs_t *attrs, size_t n) const override;
        cbret_t idaapi del(size_t n) override { return erase_row(n); }

    private:
        Position position_of(const FunctionInvocation &r) const override { return r.pos; }

        // A row's function label, computed once per function rather than per
        // repaint (the signature lookups read type information).
        struct FuncLabel
        {
            qstring              name;
            // For the combined Arguments column: each argument's name, or
            // empty to show the value alone.
            std::vector<qstring> params;
        };

        std::map<ea_t, FuncLabel>        m_labels;  // by FunctionInvocation::func_ea
    };

    // Saved trace positions, kept in the IDB. Enter travels, Ins bookmarks the
    // current position, Del removes, Edit reopens the name/comment form. Reads
    // the store directly (no snapshot), so several open windows agree.
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

    // Results of a memory access search: one row per access to the range.
    // Holds its own snapshot so several searches can be open at once. Enter
    // travels to the access; get_ea() is the instruction that made it.
    class MemAccessChooser : public ListingChooser<MemAccess>
    {
    public:
        MemAccessChooser(TraceManager *mgr, ea_t lo, ea_t hi,
                         std::vector<MemAccess> &&hits);

        void    idaapi get_row(qstrvec_t *cols, int *icon, chooser_item_attrs_t *attrs, size_t n) const override;
        ea_t    idaapi get_ea(size_t n) const override;
        cbret_t idaapi del(size_t n) override { return erase_row(n); }

    private:
        Position position_of(const MemAccess &r) const override { return r.pos; }
    };

    // The syscalls the recording made, with their result and arguments.
    // Enter time-travels to the call.
    class SyscallChooser : public ListingChooser<SyscallEvent>
    {
    public:
        // 'decoded' lines up with 'calls': each call's arguments by name, or
        // empty where the metadata has no signature (or decoding stopped).
        SyscallChooser(TraceManager *mgr, std::vector<SyscallEvent> &&calls,
                       std::vector<qstring> &&decoded);

        void    idaapi get_row(qstrvec_t *cols, int *icon, chooser_item_attrs_t *attrs, size_t n) const override;
        // Ctrl+E: decode one call that was not (the decoding was stopped).
        cbret_t idaapi edit(size_t n) override;
        // Refresh (Ctrl+U): list and decode them again from the recording.
        cbret_t idaapi refresh(ssize_t n) override;

    private:
        Position position_of(const SyscallEvent &r) const override { return r.pos; }
        void reset_rows();

        // Both line up with the rows.
        std::vector<qstring>       m_decoded;
        // The registers of each undecoded call (reset_rows).
        std::vector<std::optional<SyscallArgs>> m_args;
    };

    // Code the program wrote and then ran, one row per executed address.
    // Selecting a row shows the code; Enter time-travels to the write.
    class SelfModChooser : public ListingChooser<SelfModHit>
    {
    public:
        SelfModChooser(TraceManager *mgr, std::vector<SelfModHit> &&hits);

        void    idaapi get_row(qstrvec_t *cols, int *icon, chooser_item_attrs_t *attrs, size_t n) const override;
        ea_t    idaapi get_ea(size_t n) const override;

    private:
        // The write, in the stub that unpacked the code.
        Position position_of(const SelfModHit &r) const override { return r.write_pos; }
    };

    // Strings recovered by replaying the recording. Selecting a row shows the
    // address; Enter time-travels to where the string appeared.
    class StringsChooser : public ListingChooser<StringHit>
    {
    public:
        StringsChooser(TraceManager *mgr, std::vector<StringHit> &&hits);

        void    idaapi get_row(qstrvec_t *cols, int *icon, chooser_item_attrs_t *attrs, size_t n) const override;
        ea_t    idaapi get_ea(size_t n) const override;
        cbret_t idaapi enter(size_t n) override;
    };

    // Buffers recovered by replaying the recording. Enter time-travels to the
    // last write, where the buffer is complete.
    class BuffersChooser : public ListingChooser<BufferHit>
    {
    public:
        BuffersChooser(TraceManager *mgr, std::vector<BufferHit> &&hits);

        void    idaapi get_row(qstrvec_t *cols, int *icon, chooser_item_attrs_t *attrs, size_t n) const override;
        ea_t    idaapi get_ea(size_t n) const override;
        cbret_t idaapi enter(size_t n) override;
    };

    // The reconstructed memory map, as a timeline. One row per allocation,
    // protection change or free the recording made, in the order they happened.
    // Enter time-travels to the call that made the change.
    class MemoryTimelineChooser : public ListingChooser<RegionChange>
    {
    public:
        MemoryTimelineChooser(TraceManager *mgr, std::vector<RegionChange> &&rows);

        void    idaapi get_row(qstrvec_t *cols, int *icon, chooser_item_attrs_t *attrs, size_t n) const override;
        ea_t    idaapi get_ea(size_t n) const override;

    private:
        // The call, not the return: the return is inside the syscall stub,
        // not the function the row names.
        Position position_of(const RegionChange &r) const override
        { return r.call_pos.is_valid() ? r.call_pos : r.pos; }
        // describe_address per address: IDA asks for every row when the
        // list is filtered or sorted, and each description is a name lookup,
        // a function-table search and a walk of the names. Dropped when the
        // database's name count changes (a PDB applied meanwhile).
        const qstring &described(ea_t ea) const;
        mutable std::map<ea_t, qstring> m_described;
        mutable size_t                  m_namesSeen = 0;
    };

    // The handles the program opened and closed. Enter travels to where one
    // was opened; Edit (Ctrl+E) to where it was closed.
    class HandlesChooser : public ListingChooser<HandleRecord>
    {
    public:
        HandlesChooser(TraceManager *mgr, std::vector<HandleRecord> &&rows);

        void    idaapi get_row(qstrvec_t *cols, int *icon, chooser_item_attrs_t *attrs, size_t n) const override;
        cbret_t idaapi edit(size_t n) override;
        // Refresh (Ctrl+U): rebuild the list from the recording.
        cbret_t idaapi refresh(ssize_t n) override;

    private:
        // Where it was opened; one open before the recording, where it closed.
        Position position_of(const HandleRecord &r) const override
        { return r.opened.is_valid() ? r.opened : r.closed; }
    };

    // The memory map at the playhead (address_space_at), refreshed at each
    // stop. Enter jumps to the region; Edit travels to where it was made.
    class MemoryMapChooser : public ListingChooser<AddressRegion>
    {
    public:
        static const char *const TITLE;
        explicit MemoryMapChooser(TraceManager *mgr);

        // The rows' count, after rebuilding them if the playhead moved.
        size_t  idaapi get_count() const override;
        void    idaapi get_row(qstrvec_t *cols, int *icon, chooser_item_attrs_t *attrs, size_t n) const override;
        ea_t    idaapi get_ea(size_t n) const override;
        cbret_t idaapi enter(size_t n) override;
        cbret_t idaapi edit(size_t n) override;
        cbret_t idaapi refresh(ssize_t n) override;

        // Refresh the open listing, if there is one, for a new position.
        static void refresh_open();

    private:
        void rebuild();

        // What m_rows was built from: the playhead and the change timeline's
        // size (it grows if the map is built with the listing open).
        Position                   m_at = Position::none();
        size_t                     m_mapSize = 0;
    };

    // Travel to 'p' and, once there, show 'ea' in the hex view if one is open
    // (for rows naming memory: buffers, strings). False when no hex view is
    // open; the travel happens either way.
    bool travel_and_show_bytes(TraceManager *mgr, Position p, ea_t ea);
    // After each stop: the hex view jump a travel above left for it.
    void show_pending_bytes();

    // ---- TTD-specific action handlers --------------------------------------
    //
    // Most stepping is IDA's native debugger actions on the TTD toolbar. These
    // are the TTD-only commands plus the few movements IDA has no working
    // native action for.
    //
    // A TTD action is registered only while a trace is replayed
    // (Plugin::show_actions / hide_actions), so the shared update() below
    // answers AST_ENABLE_ALWAYS; handlers still check is_active() before
    // acting.

    // What nearly every handler needs, bound once by the plugin.
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

    // Base for the TTD handlers: the shared context and the enabled-always
    // update(). A handler whose state depends on something (a checkbox, a
    // backend capability, a selection) declares its own update().
    struct TtdAction : public action_handler_t
    {
        const ActionContext *ctx = nullptr;

        TraceManager   *mgr()    const { return ctx != nullptr ? ctx->mgr    : nullptr; }
        FunctionTracer *tracer() const { return ctx != nullptr ? ctx->tracer : nullptr; }
        BookmarkStore  *store()  const { return ctx != nullptr ? ctx->store  : nullptr; }

        action_state_t idaapi update(action_update_ctx_t *) override
        { return AST_ENABLE_ALWAYS; }

        // Enabled while the replayed recording can list memory accesses
        // (ITTD_CAP_ACCESS_QUERIES), for the actions built on them.
        action_state_t access_queries_state() const
        {
            TraceManager *m = mgr();
            return m != nullptr && m->backend() != nullptr && m->backend()->capabilities().access_queries
                 ? AST_ENABLE : AST_DISABLE;
        }
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

    // IDA grays out its native ThreadRunToCursorBackwards for this backend, so
    // this runs backward until execution reaches the cursor address.
    struct RunToCursorBackHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };

    // IDA's native ThreadRunToCursor intermittently fails on this read-only
    // backend (it plants a real/source breakpoint), so this runs forward to a
    // temporary watchpoint instead.
    struct RunToCursorFwdHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };

    struct GotoPositionHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };

    // Click handler for the toolbar position readout: copies the current
    // Sequence:Steps position to the clipboard.
    struct PositionCopyHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };

    // On demand, define the whole enclosing function (an expensive backward
    // trace walk behind a wait box); the per-stop analysis never does this.
    struct AnalyzeFuncHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };

    // The whole PDB (types too) of the module under the cursor, through IDA's
    // PDB plugin. Names are applied in the background anyway; this blocking
    // load runs only on request.
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

    // Sweep the recording and color the instructions that actually executed.
    struct CoverageHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };

    struct ClearCoverageHandler : public TtdAction
    { int idaapi activate(action_activation_ctx_t *) override; };

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
    // The session ended: drop the counts and close the window, whose slices
    // are positions of the recording that just closed.
    void heatmap_session_ended();

    // The handles the program opened and closed.
    struct HandlesHandler : public TtdAction
    {
        int idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override;
    };

    // Where did this value come from? A register (the registers window, or
    // one under the cursor) or memory (the hex view's selection, or data
    // under the cursor), else asked for, graphed: every chain at once,
    // following each input of an instruction that combined several values.
    struct OriginGraphHandler : public TtdAction
    {
        int idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override { return access_queries_state(); }
    };
    // Build the graph of 'what' as of 'at' and show it (the action, without
    // asking: ttd("ui.origingraph")).
    void show_origin_graph(TraceManager *mgr, const OriginTarget &what, Position at);
    // The session ended: drop the graph and close its window, whose nodes
    // travel to positions of the recording that just closed.
    void origin_session_ended();

    // Find every read, write or execute of an address over the whole trace.
    struct MemSearchHandler : public TtdAction
    {
        int idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override { return access_queries_state(); }
    };

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
    // The last call tree built, as JSON, for the window script (scripts/ida_ttd_calltree.py).
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

    // Forking: "Fork here" makes the current position a fork, whose registers
    // and memory are then edited in IDA as on a live target; "Record fork"
    // runs it on into a new trace; "Discard fork" drops it. Enabled only for a
    // backend that can fork (the last two only with a fork begun).
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
    // A fork was begun or dropped: redraw the position and, when the views
    // showed the fork's changes, have IDA reread registers and memory.
    void fork_draft_changed(const ActionContext *ctx, bool views_showed_changes);

    // Replays (forks, recovered strings and buffers) start with the saved
    // hives folder and without consent to replay a host-mode recording. When
    // one is refused for want of either, ask_replay_needs() asks the user,
    // updates 'rs', and returns true to try again.
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

    // Get Microsoft's TTD replay runtime, which ida-ttd may not ship: copy it
    // from an installed WinDbg, or download WinDbg after the user accepts its
    // license (scripts/ida_ttd_runtime.py, through IDAPython). Under TTD >
    // Backends, present in every database, since it is needed exactly when no
    // session can start.
    struct InstallRuntimeHandler : public action_handler_t
    {
        int  idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override
        { return AST_ENABLE_ALWAYS; }
    };

    // Install another build of the Sogen backend (the package has one)
    // into $IDAUSR\ida-ttd\backends\, from a file the user picks: the
    // DLL, or a release zip that holds it (ida_ttd_runtime.install_sogen()).
    struct InstallSogenHandler : public action_handler_t
    {
        int  idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override
        { return AST_ENABLE_ALWAYS; }
    };

    // Run a program in Sogen's emulator from its start and record it into a
    // new .sogttd (ITraceBackend::record_program), with the Sogen settings
    // (recording_options). In every database, like the install actions; it
    // starts from the database's input file. A TtdAction for the context's
    // switch_trace (opening the new recording in this window); it is not in
    // the session's action table, so the plugin sets its context itself.
    struct RecordProgramHandler : public TtdAction
    {
        int  idaapi activate(action_activation_ctx_t *) override;
    };

    // Action identifiers, used for registration and for menu and popup attach.
    namespace actions
    {
        constexpr const char *ADD_BOOKMARK  = "idattd:add_bookmark";
        constexpr const char *BOOKMARKS     = "idattd:bookmarks";
        constexpr const char *COVERAGE      = "idattd:coverage";
        constexpr const char *COVERAGE_CLR  = "idattd:coverage_clear";
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
        constexpr const char *ORIGIN_GRAPH  = "idattd:origin_graph";
        constexpr const char *HANDLES       = "idattd:handles";
        constexpr const char *HEATMAP       = "idattd:heatmap";
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
        constexpr const char *FULL_PDB     = "idattd:full_pdb";
        constexpr const char *INSTALL_RUNTIME = "idattd:install_runtime";
        constexpr const char *INSTALL_SOGEN   = "idattd:install_sogen";
        constexpr const char *RECORD_PROGRAM  = "idattd:record_program";
        // Grayed section headings in TTD > Backends, one per backend.
        constexpr const char *BACKEND_HDR_MS    = "idattd:backend_hdr_msttd";
        constexpr const char *BACKEND_HDR_SOGEN = "idattd:backend_hdr_sogen";
    }
}
