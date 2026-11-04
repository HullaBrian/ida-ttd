#pragma once

#include "common/pch.h"
#include "debugger/trace_manager.h"
#include "analysis/tracer.h"
#include "ui/ui.h"
#include "plugin/one_shot_timer.h"
#include "analysis/coverage.h"
#include "ui/decompiler.h"

// Base name of this DLL without its extension, from dllmain.cpp.
qstring plugin_module_name();

namespace idattd
{
    class Plugin;

    // HT_DBG notifications. Resolves export symbols once IDA has created a
    // module's segment.
    struct DbgEventListener : public event_listener_t
    {
        Plugin *p = nullptr;
        ssize_t idaapi on_event(ssize_t code, va_list va) override;
    };

    // HT_UI notifications: the TTD context-menu items, plus UI-ready and
    // widget-closing handling.
    struct UiEventListener : public event_listener_t
    {
        Plugin *p = nullptr;
        ssize_t idaapi on_event(ssize_t code, va_list va) override;
    };

    // HT_IDB notifications: when names change (e.g. IDA applies a downloaded
    // PDB), refresh the call stack so frames show names instead of raw VAs.
    struct IdbEventListener : public event_listener_t
    {
        Plugin *p = nullptr;
        ssize_t idaapi on_event(ssize_t code, va_list va) override;
    };

    // The plugmod_t returned from init(), and the HT_IDD listener for every
    // debugger (ev_*) notification of the plugin's debugger_t.
    class Plugin : public plugmod_t, public event_listener_t
    {
    public:
        Plugin();
        virtual ~Plugin();

        bool    idaapi run(size_t arg) override;
        ssize_t idaapi on_event(ssize_t code, va_list va) override;

        debugger_t     &debugger() { return m_debugger; }
        TraceManager   &manager()  { return m_mgr; }
        const ActionContext *action_context() const { return &m_ctx; }
        FunctionTracer &tracer()   { return m_tracer; }

        // The TTD commands exist only while a trace is loaded, so no TTD
        // shortcut or button is live without one.
        void show_actions();    // register actions, build the TTD toolbar (session start)
        void hide_actions();    // remove the toolbar, unregister actions (session end)
        void reskin_actions();  // (re)apply the codicon icons to the movement actions
        bool actions_visible() const { return m_actionsRegistered; }
        void update_position_label();   // refresh the toolbar's position readout

        // --- keep the decompiler focused across stops --------------------------
        // IDA brings the disassembly to the front on every stop; if the user
        // stepped from the decompiler, it is brought back afterwards.
        void begin_movement();                // ev_resume: note where the user stepped from
        void movement_done();                 // ev_resume carried it out; the stop is known
        void check_stop_decompiles();         // dbg_suspend_process, stepping in pseudocode
        void widget_closing(TWidget *w);      // drop a closed widget pointer
        void reset_step_state()               // a new session: no movement is under way
        { m_stepView = nullptr; m_viewsBefore.clear(); m_renderBefore.clear(); }
        void schedule_after_stop();           // queue the re-focus and view restores

        // Queue a coverage sweep of the function just stopped in, if enabled
        // and not measured before. Deferred to a timer: a sweep pumps the UI
        // behind a wait box, which invites reentrancy inside a debugger
        // notification.
        void schedule_auto_coverage();

        // Restore kept work on functions just defined outside the modules
        // (KeptFunctions), from a timer: the definition is reported inside
        // IDA's notification, where changing the function again is unsafe.
        void schedule_kept_restore();

        // Install the decompiler hook if not installed yet. Cheap, idempotent,
        // and called from several places because Hex-Rays may load after this
        // plugin.
        void try_hook_decompiler();

        // A database created by the loader records its recording. If present,
        // start (or offer) the replay and put a TTD menu action for it, so a
        // declined start is never a dead end. Called once the UI is up.
        void offer_trace_session();
        // Rebuild the whole TTD menu: session items (during a session), then
        // the replay-start items (database made from a recording), then
        // Backends (always). IDA appends to menus and has no reliable
        // "insert before", so every change rebuilds it in order.
        void rebuild_ttd_menu();
        // Wait for the initial analysis to finish, then offer. Starting a
        // session rebases the program and adds segments, which is unsafe while
        // the analysis queue is draining.
        void schedule_trace_offer();
        void switch_trace(const qstring &path);
        // A switch's first half, from the request queue: end the session.
        void switch_exit();
        // At the new session's first stop after a switch: reopen the Fork
        // manager if it was open before.
        void reopen_fork_manager();
        // Start replaying 'path' (a fork of this database's recording). False
        // when the debugger could not be selected.
        bool start_trace_at(const char *path);
        void start_trace_session();     // the action body; no prompting
        // Point IDA's debugger at this plugin and the trace, so Debugger >
        // Process options and Start process are correct whether or not the
        // replay starts now. False when the debugger could not be selected.
        // 'quiet' suppresses the popup, for the silent call on database open.
        bool select_trace_debugger(const char *trace_path, bool quiet = false);

        // IDA offers to map a source file whenever it finds line information
        // at the stop; for someone else's build that source is not here and
        // the dialog is noise. The line-info providers are switched off for
        // the session and back on when it ends.
        void suspend_source_debugging();
        void restore_source_debugging();

    private:
        void register_actions();
        bool can_fork_recording() const
        {
            return m_mgr.backend() != nullptr && m_mgr.backend()->capabilities().fork;
        }
        void unregister_actions();
        void attach_session_menu();
        void restore_native_icons();          // give IDA's movement actions their own icons back
        void load_icons();
        void build_action_table();            // fill m_actions (after load_icons)
        void do_after_stop();                 // timer body: post-stop view work
        static int idaapi refocus_cb(void *ud);
        void do_auto_coverage();              // timer body: sweep the current function
        bool auto_coverage_wanted(ea_t start) const;
        bool auto_indirect_wanted(ea_t start) const;
        static int idaapi autocover_cb(void *ud);
        static int idaapi kept_cb(void *ud);
        static int idaapi attach_cb(void *ud);  // timer body: wait for analysis, then offer

        // One TTD command, as registration, the menu and unregistration need
        // it. m_actions is the only list, so a command cannot be added to one
        // of the three and forgotten in the others.
        struct ActionDesc
        {
            const char       *id       = nullptr;
            const char       *label    = nullptr;
            action_handler_t *handler  = nullptr;
            const char       *shortcut = nullptr;   // nullptr for none
            const char       *tooltip  = nullptr;
            int               icon     = -1;        // -1 for none
            bool              new_group = false;    // separator above this item, in its menu
            bool              on_menu   = true;     // false: toolbar only
            const char       *submenu  = nullptr;   // a TTD_SUBMENUS name, nullptr for the TTD menu
        };

        debugger_t     m_debugger = {};
        TraceManager   m_mgr;
        FunctionTracer m_tracer;
        // Bookmarks belong to the database, so this outlives a session; it is
        // invalidated at session end since the next may be another database.
        BookmarkStore  m_bookmarks;

        DbgEventListener m_dbgEvents;
        UiEventListener  m_uiEvents;
        IdbEventListener m_idbEvents;

        // What every TTD handler reaches the plugin's state through, bound once.
        ActionContext m_ctx;

        // TTD-specific navigation (most stepping is IDA's native actions).
        RunBackHandler         m_runBack;
        StepOutBackHandler     m_stepOutBack;
        RunToCursorBackHandler m_runToCurBack;
        RunToCursorFwdHandler  m_runToCurFwd;
        OpenTimelineHandler    m_timeline;
        PositionCopyHandler    m_posLabel;   // toolbar readout; click copies position
        GotoPositionHandler    m_goto;
        AnalyzeFuncHandler     m_analyzeFunc;
        FullPdbHandler         m_fullPdb;
        // Function-call tracer
        TraceFuncHandler    m_traceFunc;
        TracePatternHandler m_tracePat;
        InstallRuntimeHandler m_installRuntime;
        InstallSogenHandler   m_installSogen;
        // Bookmarks + execution coverage
        AddBookmarkHandler   m_addBookmark;
        OpenBookmarksHandler m_bookmarksView;
        CoverageHandler      m_coverage;
        ClearCoverageHandler m_coverageClear;
        // Memory access search + indirect call annotation
        MemSearchHandler          m_memSearch;
        SyscallsHandler           m_syscalls;
        SelfModHandler            m_selfMod;
        ForkHandler               m_fork;
        ForkRecordHandler         m_forkRecord;
        ForkDiscardHandler        m_forkDiscard;
        ForkManagerHandler        m_forkManager;
        ForkOpenHandler           m_forkOpen;
        ForkForgetHandler         m_forkForget;
        RecoverStringsHandler     m_recoverStrings;
        RecoverBuffersHandler     m_recoverBuffers;
        CallTreeHandler           m_callTree;
        RereadHandler             m_reread;
        MemoryMapHandler          m_memMap;
        MemoryTimelineHandler     m_memTimeline;
        OriginGraphHandler        m_originGraph;
        HandlesHandler            m_handles;
        HeatmapHandler            m_heatmap;
        IndirectCallsHandler      m_indirect;
        ClearIndirectCallsHandler m_indirectClear;

        // Every TTD command, in menu order. Built once in the constructor.
        std::vector<ActionDesc> m_actions;

        // SVG icons, loaded once for the plugin's lifetime. The first six go
        // on IDA's own movement actions, in NATIVE_MOVEMENT_ACTIONS order; the
        // rest belong to TTD actions and are set at registration.
        enum Icon
        {
            ICO_CONTINUE = 0,
            ICO_STEP_INTO,
            ICO_STEP_OVER,
            ICO_STEP_OUT,
            ICO_STEP_INTO_BACK,
            ICO_STEP_BACK,          // circle-arrow glyph; used for step-over-back
            ICO_NATIVE_COUNT,       // the six above re-skin native actions

            ICO_REV_CONTINUE = ICO_NATIVE_COUNT,
            ICO_STEP_OUT_BACK,
            ICO_RUN_TO_CUR,
            ICO_RUN_TO_CUR_BACK,
            ICO_TIMELINE,
            ICO_GOTO,
            ICO_FUNC_SEARCH,
            ICO_BOOKMARK_ADD,
            ICO_BOOKMARKS,
            ICO_FUNCTION,
            ICO_CALL_TREE,
            ICO_MEMORY,
            ICO_SYSCALLS,
            ICO_MEMORY_MAP,
            ICO_ORIGIN,
            ICO_HANDLES,
            ICO_COUNT
        };
        // One array, so the destructor frees them all without a second list
        // to keep in step. -1 means "not loaded".
        std::array<int, ICO_COUNT> m_icons{};

        // True while the actions are registered (a trace is loaded), so
        // registration is never doubled.
        bool m_actionsRegistered = false;

        // IDA's own icons for the re-skinned movement actions, captured the
        // first time each action is seen (they register lazily) and restored
        // when the trace unloads: the override is global and would otherwise
        // re-skin the toolbar for every other debugger. Parallel to
        // NATIVE_MOVEMENT_ACTIONS in plugin.cpp.
        int  m_nativeSaved[ICO_NATIVE_COUNT]   = { -1, -1, -1, -1, -1, -1 };
        bool m_nativeSavedOk[ICO_NATIVE_COUNT] = { false, false, false, false, false, false };

        // Decompiler-focus tracking, decided when a movement starts: the view
        // with focus then is where the user stepped from. Watching focus
        // changes cannot work, because IDA's own switches look like the user's.
        TWidget *m_stepView = nullptr;        // pseudocode view the movement started in
        std::vector<TWidget *> m_viewsBefore; // pseudocode views open when it started
        uint64   m_settledResume = 0;         // resume_serial() when the last stop settled
        OneShotTimer m_refocusTimer;          // deferred re-focus
        void settle_stop();                   // the stop is done: the next resume is a new movement
        // Disassembly views and their text/graph mode when the movement
        // started: IDA flips a text view to graph by itself when a stop lands
        // in a function, and that is undone.
        std::vector<std::pair<TWidget *, tcc_renderer_type_t>> m_renderBefore;
        void restore_renderers();
        // IDA's 'batch' flag, set across a stop Hex-Rays cannot decompile so
        // its "Decompilation failure" goes to the output window instead of a
        // dialog per step.
        bool m_quiet      = false;
        bool m_quietOwned = false;      // batch was off, and quiet_ui() turned it on
        bool m_layoutChanged = false;   // since the last after-stop work
        void quiet_ui();
        void unquiet_ui();
        // The position readout only grows within a session, so the toolbar
        // does not shift each time the position gains a digit.
        size_t m_posLabelChars = 0;

        // Automatic per-function coverage. Functions whose sweep the user
        // cancelled are remembered for the session only, so the next step
        // does not re-offer it; reopening the trace retries.
        OneShotTimer    m_autoCoverTimer;
        OneShotTimer    m_attachTimer;
        // Switching the replay to another recording: stop, then start it once
        // IDA has finished with the old session.
        qstring         m_switchTo;
        bool            m_switchExitSent = false;
        bool            m_reopenForkManager = false;   // it was open when a switch began
        OneShotTimer    m_switchTimer;
        static int idaapi switch_cb(void *ud);
        OneShotTimer    m_pdbTimer;          // applies downloaded PDBs while paused
        OneShotTimer    m_keptTimer;         // restores kept work (schedule_kept_restore)
        ea_t            m_autoCoverFunc  = BADADDR;   // function the timer will sweep
        std::set<ea_t>  m_autoCoverDeclined;
        bool            m_haveDecompiler = false;
        // Source-info providers turned off here; only these are turned back
        // on, so one the user had disabled stays disabled. The entries are
        // string literals, so storing the pointers is safe.
        std::vector<const char *> m_srcProvidersOff;
        // The Backends actions and menu separators: registered with the
        // plugin, not a session.
        bool m_menuActionsRegistered = false;
        // A failed debugger switch is worth saying once, not on every try.
        bool m_switchReported   = false;
    };
}
