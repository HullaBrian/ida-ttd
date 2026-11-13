#pragma once

#include "common/pch.h"

namespace idattd
{
    class TraceManager;

    // Default background for executed instructions: #584848, a muted
    // red-brown that suits IDA's default dark theme (bgcolor_t is 0xBBGGRR).
    // Configurable per database because IDA cannot report whether the theme
    // is light or dark.
    static const bgcolor_t COVERAGE_DEFAULT_COLOR = 0x484858;

    // The colour this database was last painted with (the default if never).
    bgcolor_t coverage_color();

    // Every colour this database has been painted with, so callers recognise
    // their own paint (clearing the disassembly, repainting pseudocode).
    std::set<bgcolor_t> coverage_colors();
    // The colour marks another recording's coverage (painted before the replay
    // switched to this one), in the complement of its original shade.
    bool coverage_is_previous(bgcolor_t c);
    // After the replay changed recording, repaint the other recording's
    // coverage in the complementary shade. Only from a safe place (a timer
    // after the stop, or a command): it writes every painted instruction.
    void coverage_settle_recording_change();

    // Automatic highlighting of the function stopped in: the auto_coverage
    // setting (TTD > Settings...).
    bool coverage_auto_enabled();

    // Has the function starting at 'start' been swept against this recording?
    // Recorded so a function is measured once, not on every stop.
    bool coverage_function_done(ea_t start);
    // The session ended: what it painted in debugger segments went with them.
    void coverage_session_ended();

    // Sweep and colour one function in the current colour, then mark it done.
    // False when it did not complete (no trace, or cancelled); the caller
    // should not keep retrying.
    bool cover_function(TraceManager *mgr, ea_t start, ea_t end);

    struct CoverageResult
    {
        uint64_t executed  = 0;   // distinct addresses the recording executed
        uint64_t colored   = 0;   // ...of those, ones IDA has an instruction at
        uint64_t undefined = 0;   // ...and ones it does not (nothing to colour)
        bool     cancelled = false;
        qstring  error;           // why run_coverage returned false, for the caller to show
    };

    // Replay the recording and colour every instruction in 'ranges' that ran.
    // Ranges are [lo, hi), any order; they become Execute watchpoints, so a
    // narrow scope lets the engine skip stretches of the trace.
    //
    // Runs behind a cancellable wait box. False, with 'error' set and no
    // dialog shown, when there is no trace, the scope is unusable, or the
    // backend could not run it; a cancelled sweep
    // returns true with 'cancelled' set and paints nothing.
    bool run_coverage(TraceManager *mgr,
                      const std::vector<std::pair<ea_t, ea_t>> &ranges,
                      bgcolor_t color,
                      CoverageResult *out);

    // Remove every coverage colour from the database; returns the number of
    // instructions cleared.
    size_t clear_coverage();
}
