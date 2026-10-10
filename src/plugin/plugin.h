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

    // Listener for HT_UI notifications -- adds the "Trace this function" item to
    // the disassembly context menu.
    struct UiEventListener : public event_listener_t
    {
        Plugin *p = nullptr;
        ssize_t idaapi on_event(ssize_t code, va_list va) override;
    };

    // Listener for HT_IDB notifications -- when names change (e.g. a PDB finishes
    // downloading and IDA applies symbols), refresh the call stack so frames show
    // names instead of raw VAs.
    struct IdbEventListener : public event_listener_t
    {
        Plugin *p = nullptr;
        ssize_t idaapi on_event(ssize_t code, va_list va) override;
    };

    // The plugin object. It is both the plugmod_t returned from init() and the
    // HT_IDD event listener that receives all debugger (ev_*) notifications for
    // our debugger_t.
    class Plugin : public plugmod_t, public event_listener_t
    {
    public:
        Plugin();
        virtual ~Plugin();

        bool    idaapi run(size_t arg) override;
        ssize_t idaapi on_event(ssize_t code, va_list va) override;

        debugger_t     &debugger() { return m_debugger; }
        TraceManager   &manager()  { return m_mgr; }
        FunctionTracer &tracer()   { return m_tracer; }

        // The TTD commands only exist while a trace is loaded: show_actions()
        // registers them (shortcuts included) and builds the toolbar,
        // hide_actions() tears the toolbar down and unregisters them again, so
        // no TTD shortcut or button is live without an active trace.
        void show_actions();    // register actions + build the TTD toolbar (session start)
        void hide_actions();    // tear the TTD toolbar down + unregister actions (session end)
        void reskin_actions();  // (re)apply the codicon icons to the movement actions
        bool actions_visible() const { return m_actionsRegistered; }
        void update_position_label();   // refresh the live "Seq:Steps" toolbar readout

        // --- keep the decompiler focused across stops (HT_UI driven) ----------
        // IDA forces the disassembly view to the front on every debugger stop. If
        // the user was viewing the decompiler, we re-assert it after the stop.
        void track_widget(TWidget *cur);      // remember the user's active code view
        void widget_closing(TWidget *w);      // drop a closed widget pointer
        void keep_decompiler_focused();       // schedule a re-focus after a stop (if wanted)

        // Queue a coverage sweep of the function we just stopped in, if that is
        // switched on and the function has not been measured before. Deferred to
        // a timer rather than run here: a sweep pumps the UI behind a wait box,
        // and doing that from inside a debugger notification invites reentrancy.
        void schedule_auto_coverage();

        // Install the decompiler hook if it is not installed yet. Cheap and
        // idempotent, and called from several points because Hex-Rays is a
        // plugin too and may not have loaded when we first ask for it.
        void try_hook_decompiler();

        // Databases created by the .run loader carry a record naming the
        // recording they came from. When one is present, offer to start
        // replaying it, and put an action on the Debugger menu so a declined
        // offer is never a dead end. Called once the UI is up.
        void offer_trace_session();
        // Wait for the database's initial analysis to finish, then offer.
        // Starting a session rebases the program and adds segments, neither of
        // which is safe while the analysis queue is still draining.
        void schedule_trace_offer();
        void start_trace_session();     // the action body; no prompting
        // Make IDA's debugger machinery point at us and know where the trace is,
        // so Debugger > Process options and Start process are already correct
        // whether or not the replay is started right now. Returns false when the
        // backend could not be selected at all.
        // 'quiet' suppresses the popup when another debugger is already
        // active, for the call made silently on database open.
        bool select_trace_debugger(const char *trace_path, bool quiet = false);

        // Source-path prompts. IDA offers to map a source file whenever it
        // finds line information for the address we stopped at; replaying
        // someone else's build, that source is not on this machine and the
        // dialog is pure noise. The provider supplying the line info is
        // switched off for the session and switched back on when it ends.
        void suspend_source_debugging();
        void restore_source_debugging();

    private:
        void register_actions();
        void unregister_actions();
        void restore_native_icons();          // give IDA's movement actions their own icons back
        void load_icons();
        void build_action_table();            // fill m_actions (after load_icons)
        void do_refocus();                    // timer body: re-activate the decompiler
        static int idaapi refocus_cb(void *ud);
        void do_auto_coverage();              // timer body: sweep the current function
        static int idaapi autocover_cb(void *ud);
        static int idaapi attach_cb(void *ud);  // timer body: wait for analysis, then offer

        // One TTD command, as registration, the TTD menu and unregistration all
        // need it. m_actions is the only list of them, so a command cannot be
        // added to one of the three and forgotten in the others.
        struct ActionDesc
        {
            const char       *id       = nullptr;
            const char       *label    = nullptr;
            action_handler_t *handler  = nullptr;
            const char       *shortcut = nullptr;   // nullptr for none
            const char       *tooltip  = nullptr;
            int               icon     = -1;        // -1 for none
            bool              new_group = false;    // separator above this item
            bool              on_menu   = true;     // false: toolbar only
        };

        debugger_t     m_debugger = {};
        TraceManager   m_mgr;
        FunctionTracer m_tracer;
        // Bookmarks belong to the database, not the trace, so this outlives any
        // one session; it is invalidated at session end because the next one may
        // be a different database.
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
        // Function-call tracer
        TraceFuncHandler    m_traceFunc;
        TracePatternHandler m_tracePat;
        OpenTracedHandler   m_openTraced;
        OpenEventsHandler   m_openEvents;
        RunTraceHandler     m_runTrace;
        AttachTraceHandler  m_attachTrace;
        // Bookmarks + execution coverage
        AddBookmarkHandler   m_addBookmark;
        OpenBookmarksHandler m_bookmarksView;
        CoverageHandler      m_coverage;
        ClearCoverageHandler m_coverageClear;
        AutoCoverageHandler  m_coverageAuto;
        // Memory access search + indirect call annotation
        MemSearchHandler          m_memSearch;
        MemoryMapHandler          m_memMap;
        ClearMemoryMapHandler     m_memMapClear;
        IndirectCallsHandler      m_indirect;
        ClearIndirectCallsHandler m_indirectClear;

        // Every TTD command, in menu order. Built once in the constructor.
        std::vector<ActionDesc> m_actions;

        // Custom codicon icons (SVG), loaded once for the plugin's lifetime.
        // The first six are the glyphs put on IDA's own movement actions, in the
        // order NATIVE_MOVEMENT_ACTIONS expects; the rest belong to TTD actions
        // and are set at registration time.
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
            ICO_COUNT
        };
        // One array rather than 13 handles, so the destructor frees them all
        // without a second list to keep in step. -1 means "not loaded".
        std::array<int, ICO_COUNT> m_icons{};

        // True while our actions are registered (i.e. a trace is loaded). Guards
        // show_actions()/hide_actions() so registration is never doubled up.
        bool m_actionsRegistered = false;

        // IDA's own icons for the native movement actions we re-skin, captured
        // the first time each action is seen (they register lazily) and restored
        // when the trace is unloaded -- the override is global, so leaving it in
        // place would re-skin IDA's toolbar for every other debugger too.
        // Parallel to NATIVE_MOVEMENT_ACTIONS in plugin.cpp.
        int  m_nativeSaved[ICO_NATIVE_COUNT]   = { -1, -1, -1, -1, -1, -1 };
        bool m_nativeSavedOk[ICO_NATIVE_COUNT] = { false, false, false, false, false, false };

        // Decompiler-focus tracking. m_userPrefersDecomp is sticky: it only flips on
        // a user focus change (not the debugger's forced disasm switch, which we
        // ignore while m_ignoreWidgetChanges is set during the re-focus window).
        TWidget *m_pseudoWidget   = nullptr;  // last-seen Pseudocode widget
        bool     m_userPrefersDecomp = false; // user was last in the decompiler
        bool     m_ignoreWidgetChanges = false; // freeze preference during a stop
        OneShotTimer m_refocusTimer;          // deferred re-focus

        // Automatic per-function coverage. Functions the user cancelled out of
        // are remembered for the session only, so a sweep they stopped is not
        // offered again on the very next step -- but reopening the trace retries.
        OneShotTimer    m_autoCoverTimer;
        OneShotTimer    m_attachTimer;
        ea_t            m_autoCoverFunc  = BADADDR;   // function the timer will sweep
        std::set<ea_t>  m_autoCoverDeclined;
        bool            m_haveDecompiler = false;
        // Source-info providers we turned off, so only those are turned back
        // on: one the user had already disabled must stay that way. The
        // entries are string literals, so storing the pointers is safe.
        std::vector<const char *> m_srcProvidersOff;
        // The "start the replay for this database" action, registered only when
        // the database actually came from a .run. Unlike every other TTD action
        // it lives OUTSIDE a session -- it is the thing that starts one.
        bool m_attachRegistered = false;
        // A failed debugger switch is worth saying once, not on every try.
        bool m_switchReported   = false;
    };
}
