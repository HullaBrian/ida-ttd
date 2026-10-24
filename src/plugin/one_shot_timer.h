#pragma once

#include "common/pch.h"

namespace idattd
{
    // A deferred call onto IDA's UI thread, for work that must not run inside
    // the notification that decided on it.
    //
    // The callback does NOT run from IDA's timer. IDA locks its timer list
    // while a timer callback runs; if the callback pumps the event loop (any
    // wait box or dialog does) and another one-shot timer fires, that timer
    // waits on the same lock to unregister itself, and the main thread
    // deadlocks. This froze IDA when the auto-coverage sweep ran behind a wait
    // box from its timer and the decompiler re-focus timer fired inside it.
    // So the timer only queues an execute_sync(MFF_NOWAIT) request, which IDA
    // runs on a later turn of the UI loop, outside any timer.
    //
    // The callback returns a positive interval to be called again, anything
    // else to stop.
    class OneShotTimer
    {
    public:
        using callback_t = int (idaapi *)(void *ud);

        OneShotTimer() = default;
        ~OneShotTimer() { cancel(); }
        OneShotTimer(const OneShotTimer &) = delete;
        OneShotTimer &operator=(const OneShotTimer &) = delete;

        // Arm, unless already armed or queued: a second request before the
        // first has run is the same request.
        void arm(int interval_ms, callback_t callback, void *ud)
        {
            if ( m_timer != nullptr || m_req != nullptr )
                return;
            m_cb = callback;
            m_ud = ud;
            m_timer = register_timer(interval_ms, on_timer, this);
        }

        void cancel()
        {
            if ( m_timer != nullptr )
            {
                unregister_timer(m_timer);
                m_timer = nullptr;
            }
            if ( m_req != nullptr )
            {
                // Still queued, so still alive: m_req is cleared before the
                // request runs. Disowned first in case it runs regardless.
                m_req->owner = nullptr;
                cancel_exec_request(m_reqId);
                m_req = nullptr;
            }
        }

    private:
        // With MFF_NOWAIT, IDA owns the request and deletes it after running it.
        struct Request : public exec_request_t
        {
            OneShotTimer *owner = nullptr;
            ssize_t idaapi execute() override
            {
                if ( owner != nullptr )
                    owner->run();
                return 0;
            }
        };

        static int idaapi on_timer(void *ud)
        {
            OneShotTimer *t = static_cast<OneShotTimer *>(ud);
            t->m_timer = nullptr;               // IDA frees it once this returns -1
            Request *r = new Request;
            r->owner = t;
            t->m_req = r;
            t->m_reqId = (int)execute_sync(*r, MFF_WRITE | MFF_NOWAIT);
            if ( t->m_reqId < 0 )
            {
                // Not queued, so IDA will neither run nor delete it; left
                // in m_req it would also block every later arm().
                t->m_req   = nullptr;
                t->m_reqId = 0;
                delete r;
            }
            return -1;
        }

        void run()
        {
            m_req = nullptr;
            int again = m_cb(m_ud);
            if ( again > 0 )
                arm(again, m_cb, m_ud);
        }

        qtimer_t   m_timer = nullptr;
        Request   *m_req   = nullptr;
        int        m_reqId = -1;
        callback_t m_cb    = nullptr;
        void      *m_ud    = nullptr;
    };
}
