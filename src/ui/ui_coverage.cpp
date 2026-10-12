// Execution coverage: the scope/colour prompt and the three coverage actions.
#include "ui/ui.h"
#include "ui/decompiler.h"
#include "ui/scope.h"
#include "analysis/coverage.h"

using namespace TTD;

namespace idattd
{
    // Which addresses should the sweep watch? A narrower answer is not just
    // tidier: the watchpoints are what let the engine skip parts of the
    // recording, so the scope is the difference between seconds and minutes.
    //
    // The colour has to be asked for too. IDA has no API for "is the theme
    // dark", and a shade that reads on a light theme is nearly invisible on a
    // dark one, so the only honest default is the last one this database used.
    static bool ask_coverage_options(TraceManager *mgr, ea_t ea,
                                     int &scope, bgcolor_t &color)
    {
        static const char form[] =
            "TTD execution coverage\n"
            "\n"
            "\n"
            "Colour every instruction the recording actually executed.\n"
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
            return 1;

        msg("[ida-ttd] coverage%s: %llu addresses executed, %llu instructions "
            "coloured, %llu with no code defined.\n",
            r.cancelled ? " (stopped early, results are partial)" : "",
            r.executed, r.colored, r.undefined);
        if ( r.cancelled )
            info("The sweep was stopped early, so the highlight shows only the "
                 "part of the recording that had been replayed.");
        else if ( r.executed == 0 )
            info("Nothing in that range executed anywhere in the recording.");
        refresh_idaview_anyway();
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

    int idaapi AutoCoverageHandler::activate(action_activation_ctx_t *)
    {
        bool on = !coverage_auto_enabled();
        set_coverage_auto_enabled(on);
        update_action_checked(actions::COVERAGE_AUTO, on);
        msg("[ida-ttd] automatic coverage of the function you stop in is now %s.\n",
            on ? "on" : "off");
        return 1;
    }

    action_state_t idaapi AutoCoverageHandler::update(action_update_ctx_t *)
    {
        // The tick has to be re-asserted here: IDA asks for the state when it
        // draws the menu, and the answer lives in the database, not in this
        // object, so it can change under us when a different IDB is opened.
        update_action_checked(actions::COVERAGE_AUTO, coverage_auto_enabled());
        return AST_ENABLE_ALWAYS;
    }
}
