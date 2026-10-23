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

    // Off: nothing more is written (the diagnostics_log setting).
    void diag_set_enabled(bool on);

    // Logs '<what> <detail>: <n> ms' on destruction when the scope took at
    // least 'threshold_ms'. 0 logs always.
    class DiagTimer
    {
    public:
        DiagTimer(const char *what, uint32_t threshold_ms = 200);
        DiagTimer(const char *what, const qstring &detail, uint32_t threshold_ms = 200);
        // '<what> <ea>+<size>', the detail formatted only if the line is
        // written: for timers on every memory read, where building a string
        // each time would cost more than most reads.
        DiagTimer(const char *what, uint64_t ea, uint64_t size, uint32_t threshold_ms = 200);
        ~DiagTimer();

    private:
        const char *m_what;
        qstring     m_detail;
        uint32_t    m_threshold;
        uint64_t    m_t0;
        bool        m_range = false;   // log m_ea+m_size rather than m_detail
        uint64_t    m_ea = 0;
        uint64_t    m_size = 0;
    };
}
