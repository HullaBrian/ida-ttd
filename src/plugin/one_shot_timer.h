#pragma once

#include "common/pch.h"

namespace idattd
{
    // A deferred call onto IDA's UI thread, used wherever work must not run
    // inside the notification that decided to do it.
    //
    // IDA frees the timer object itself once the callback returns -1, so the
    // handle has to be dropped by the callback (fired()) and not by whoever
    // armed it: unregistering an already-fired timer would be a double free.
    // A callback that returns a positive value is asking to be called again,
    // and must not call fired() until it finally returns -1.
    class OneShotTimer
    {
    public:
        OneShotTimer() = default;
        ~OneShotTimer() { cancel(); }
        OneShotTimer(const OneShotTimer &) = delete;
        OneShotTimer &operator=(const OneShotTimer &) = delete;

        // Arm, unless it is already armed -- a second request before the first
        // has fired is the same request.
        void arm(int interval_ms, int (idaapi *callback)(void *ud), void *ud)
        {
            if ( m_timer == nullptr )
                m_timer = register_timer(interval_ms, callback, ud);
        }

        // Called from the callback that is about to return -1.
        void fired() { m_timer = nullptr; }

        void cancel()
        {
            if ( m_timer != nullptr )
            {
                unregister_timer(m_timer);
                m_timer = nullptr;
            }
        }

    private:
        qtimer_t m_timer = nullptr;
    };
}
