// Execution coverage: the scope/color prompt and the two coverage actions.
#include "ui/ui.h"
#include "ui/decompiler.h"
#include "ui/scope.h"
#include "analysis/coverage.h"

namespace idattd
{
    // Which addresses the sweep watches. The watchpoints let the engine skip
    // parts of the recording, so a narrow scope means seconds, not minutes.
    //
    // The color is asked for too: IDA cannot say whether the theme is dark,
    // and a shade that reads on a light theme is nearly invisible on a dark
    // one, so the default is the last one this database used.
    static bool ask_coverage_options(TraceManager *mgr, ea_t ea,
                                     int &scope, bgcolor_t &color)
    {
        static const char form[] =
            "TTD execution coverage\n"
            "\n"
            "\n"
            "Color every instruction the recording actually executed.\n"
            "A narrower scope replays much less of the trace.\n"
            "\n"
            "<~S~cope:b:0:40::>\n"
            "<~C~olour:K::6::>\n"
            "\n";
        qstrvec_t items;
        scope_items(mgr, ea, &items);
        static int sel = SCOPE_FUNCTION;   // the last choice within this session
        color = coverage_color();
        if ( ask_form(form, &items, &sel, &color) <= 0 )
            return false;
        scope = sel;
        return true;
    }

    int idaapi CoverageHandler::activate(action_activation_ctx_t *ctx)
    {
        if ( mgr() == nullptr || !mgr()->is_active() )
        {
            warning("Execution coverage is only available while replaying a trace.");
            return 1;
        }

        ea_t      ea    = scope_anchor(mgr(), ctx);
        int       scope = SCOPE_FUNCTION;
        bgcolor_t color = COVERAGE_DEFAULT_COLOR;
        if ( !ask_coverage_options(mgr(), ea, scope, color) )
            return 1;

        std::vector<std::pair<ea_t, ea_t>> ranges;
        if ( !scope_ranges(mgr(), ea, scope, "measure", ranges) )
            return 1;

        CoverageResult r;
        if ( !run_coverage(mgr(), ranges, color, &r) )
        {
            warning("%s", r.error.c_str());
            return 1;
        }

        msg("[ida-ttd] coverage%s: %llu addresses executed, %llu instructions "
            "colored, %llu with no code defined.\n",
            r.cancelled ? " (stopped early, results are partial)" : "",
            r.executed, r.colored, r.undefined);
        if ( r.cancelled )
            info("The sweep was stopped early, so the highlight shows only the "
                 "part of the recording that had been replayed.");
        else if ( r.executed == 0 )
            info("Nothing in that range executed anywhere in the recording.");
        refresh_idaview_anyway();
        // Pseudocode paints the coverage too (decompiler.cpp).
        refresh_pseudocode_views();
        return 1;
    }

    int idaapi ClearCoverageHandler::activate(action_activation_ctx_t *)
    {
        size_t n = clear_coverage();
        msg("[ida-ttd] cleared the execution highlight from %d instructions.\n", (int)n);
        refresh_idaview_anyway();
        refresh_pseudocode_views();
        return 1;
    }

}
