#pragma once

#include "pch.h"
#include "trace_manager.h"
#include "tracer.h"
#include "ui.h"

namespace idattd
{
    class Plugin;

    // Listener for HT_DBG notifications (module load/process start) — used to
    // resolve export symbols once IDA has created the module's segment.
    struct DbgEventListener : public event_listener_t
    {
        Plugin *p = nullptr;
        ssize_t idaapi on_event(ssize_t code, va_list va) override;
    };

    // Listener for HT_UI notifications — adds the "Trace this function" item to
    // the disassembly context menu.
    struct UiEventListener : public event_listener_t
    {
        Plugin *p = nullptr;
        ssize_t idaapi on_event(ssize_t code, va_list va) override;
    };

    // Listener for HT_IDB notifications — when names change (e.g. a PDB finishes
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

        void show_actions();    // build the TTD toolbar + override icons (session start)
        void hide_actions();    // tear the TTD toolbar down (session end)
        void reskin_actions();  // (re)apply the codicon icons to the movement actions
        void update_position_label();   // refresh the live "Seq:Steps" toolbar readout

        // --- keep the decompiler focused across stops (HT_UI driven) ----------
        // IDA forces the disassembly view to the front on every debugger stop. If
        // the user was viewing the decompiler, we re-assert it after the stop.
        void track_widget(TWidget *cur);      // remember the user's active code view
        void widget_closing(TWidget *w);      // drop a closed widget pointer
        void keep_decompiler_focused();       // schedule a re-focus after a stop (if wanted)

    private:
        void register_actions();
        void unregister_actions();
        void load_icons();
        void do_refocus();                    // timer body: re-activate the decompiler
        static int idaapi refocus_cb(void *ud);

        debugger_t     m_debugger = {};
        TraceManager   m_mgr;
        FunctionTracer m_tracer;

        DbgEventListener m_dbgEvents;
        UiEventListener  m_uiEvents;
        IdbEventListener m_idbEvents;

        // TTD-specific navigation (most stepping is IDA's native actions).
        RunBackHandler      m_runBack;   // IDA has no native "continue backwards"
        StepOutBackHandler  m_stepOutBack; // ...nor "step out backwards"
        RunToCursorBackHandler m_runToCurBack; // ...and its native run-to-cursor-back greys out
        RunToCursorFwdHandler m_runToCurFwd; // ...and its native run-to-cursor fails intermittently
        OpenTimelineHandler m_timeline;
        PositionCopyHandler m_posLabel;  // toolbar timestamp; click copies position
        GotoPositionHandler m_goto;
        AnalyzeFuncHandler  m_analyzeFunc;
        // Function-call tracer
        TraceFuncHandler    m_traceFunc;
        TracePatternHandler m_tracePat;
        OpenTracedHandler   m_openTraced;
        OpenEventsHandler   m_openEvents;
        RunTraceHandler     m_runTrace;

        // Custom codicon debug-movement icons (SVG). Forward/back continue plus
        // the native step actions whose icons we override.
        int  m_icoContinue    = -1;
        int  m_icoRevContinue = -1;   // also the icon for our RUN_BACK action
        int  m_icoStepInto    = -1;
        int  m_icoStepOver    = -1;
        int  m_icoStepOut     = -1;
        int  m_icoStepBack    = -1;      // circle-arrow glyph; used for step-over-back
        int  m_icoStepIntoBack = -1;     // mirrored step-into (blue)
        int  m_icoStepOutBack = -1;      // step-out (blue)
        int  m_icoRunToCur    = -1;
        int  m_icoRunToCurBack = -1;
        // TTD action icons (custom actions, set at registration time).
        int  m_icoTimeline    = -1;
        int  m_icoGoto        = -1;
        int  m_icoFuncSearch  = -1;

        // Decompiler-focus tracking. m_userPrefersDecomp is sticky: it only flips on
        // a USER focus change (not the debugger's forced disasm switch, which we
        // ignore while m_ignoreWidgetChanges is set during the re-focus window).
        TWidget *m_pseudoWidget   = nullptr;  // last-seen Pseudocode widget
        bool     m_userPrefersDecomp = false; // user was last in the decompiler
        bool     m_ignoreWidgetChanges = false; // freeze preference during a stop
        qtimer_t m_refocusTimer   = nullptr;  // one-shot deferred re-focus
    };
}
