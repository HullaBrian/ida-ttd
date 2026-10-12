#pragma once

#include "common/pch.h"

namespace idattd
{
    // A timing log for what takes long, in %TEMP%\ida-ttd-diag.log.
    //
    // A frozen IDA cannot be asked what it is doing, but a file it wrote can
    // be read afterwards, from another process. Each line has a timestamp and
    // the thread; slow backend calls and the session's phases are logged.
    // Cheap: nothing is written for a call that finishes quickly.
    void diag(const char *fmt, ...);

    // Start a fresh log, keeping the last one as ida-ttd-diag.prev.log.
    void diag_rotate();

    // Logs '<what> <detail>: <n> ms' on destruction when the scope took at
    // least 'threshold_ms'. 0 logs always.
    class DiagTimer
    {
    public:
        DiagTimer(const char *what, uint32_t threshold_ms = 200);
        DiagTimer(const char *what, const qstring &detail, uint32_t threshold_ms = 200);
        ~DiagTimer();

    private:
        const char *m_what;
        qstring     m_detail;
        uint32_t    m_threshold;
        uint64_t    m_t0;
    };
}
