#pragma once

#include "common/pch.h"

namespace idattd
{
    class TraceManager;

    // Default background colour for executed instructions: #584848, a muted
    // red-brown that reads well on IDA's default dark theme without drowning
    // the listing's syntax colours. bgcolor_t is 0xBBGGRR. The shade is
    // configurable per database because IDA exposes no way to ask whether the
    // current theme is light or dark.
    static const bgcolor_t COVERAGE_DEFAULT_COLOR = 0x484858;

    // The colour this database was last painted with (the default if never).
    bgcolor_t coverage_color();

    // Every colour this database has been painted with. Callers use it to
    // recognise their own work: the disassembly when clearing, the decompiler
    // when repainting pseudocode lines.
    std::set<bgcolor_t> coverage_colors();
    // The colour shows another recording's coverage: painted before the
    // replay switched to this one (a fork, or the recording it came from),
    // in the complement of the shade it had.
    bool coverage_is_previous(bgcolor_t c);
    // After the replay changed recording, repaint the other recording's
    // coverage in the complementary shade. Only from a safe place (a timer
    // after the stop, or a command): it writes to every painted instruction.
    void coverage_settle_recording_change();

    // Automatic highlighting of the function you stop in. On by default,
    // remembered per database.
    bool coverage_auto_enabled();
    void set_coverage_auto_enabled(bool on);

    // Has the function starting at 'start' already been swept in this database?
    // Sweeps are recorded so a function is measured once, ever, not once a stop.
    bool coverage_function_done(ea_t start);
    // The session ended: what it painted in debugger segments went with them.
    void coverage_session_ended();

    // Sweep and colour one function with the database's current colour, then
    // record it as done. False means it did not complete (no trace, or the user
    // cancelled), and the caller should not keep retrying it.
    bool cover_function(TraceManager *mgr, ea_t start, ea_t end);

    struct CoverageResult
    {
        uint64_t executed  = 0;   // distinct addresses the recording executed
        uint64_t colored   = 0;   // ...of those, ones IDA has an instruction at
        uint64_t undefined = 0;   // ...and ones it does not (nothing to colour)
        bool     cancelled = false;
    };

    // Replay the whole recording and colour every instruction inside 'ranges'
    // that actually ran. Ranges are [lo, hi) and need not be sorted; they become
    // Execute watchpoints, so a narrow scope lets the engine skip whole segments
    // of the trace rather than replaying all of it.
    //
    // Runs behind a cancellable wait box. Returns false when there is no trace,
    // the scope is unusable, or the sweep was abandoned.
    bool run_coverage(TraceManager *mgr,
                      const std::vector<std::pair<ea_t, ea_t>> &ranges,
                      bgcolor_t color,
                      CoverageResult *out);

    // Remove every colour this database has been painted with. Returns the
    // number of instructions cleared.
    size_t clear_coverage();
}
