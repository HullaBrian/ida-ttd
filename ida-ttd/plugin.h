#pragma once

#include "pch.h"
#include "trace_manager.h"
#include "ui.h"

namespace idattd
{
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

        debugger_t   &debugger() { return m_debugger; }
        TraceManager &manager()  { return m_mgr; }

        void show_actions();
        void hide_actions();

    private:
        void register_actions();
        void unregister_actions();

        debugger_t   m_debugger = {};
        TraceManager m_mgr;

        StepBackHandler     m_stepBack;
        OpenTimelineHandler m_timeline;
        GotoPositionHandler m_goto;
    };
}
