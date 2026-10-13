// Indirect-call annotation: the scope prompt and the two actions.
#include "ui/ui.h"
#include "ui/decompiler.h"
#include "ui/scope.h"
#include "analysis/callsites.h"

namespace idattd
{
    int idaapi IndirectCallsHandler::activate(action_activation_ctx_t *ctx)
    {
        if ( mgr() == nullptr || !mgr()->is_active() )
        {
            warning("This is only available while replaying a trace.");
            return 1;
        }

        static const char form[] =
            "TTD indirect calls\n"
            "\n"
            "\n"
            "Watch where every indirect call actually goes, and write that\n"
            "back as a comment and a real cross-reference.\n"
            "\n"
            "The whole recording is replayed whichever scope you pick: a call\n"
            "is not something the engine can skip ahead to. The scope decides\n"
            "which call sites get annotated.\n"
            "\n"
            "<~S~cope:b:0:40::>\n"
            "\n";
        ea_t ea = scope_anchor(mgr(), ctx);
        qstrvec_t items;
        scope_items(mgr(), ea, &items);
        static int sel = SCOPE_FUNCTION;   // the function the cursor is stopped in
        if ( ask_form(form, &items, &sel) <= 0 )
            return 1;

        std::vector<std::pair<ea_t, ea_t>> ranges;
        if ( !scope_ranges(mgr(), ea, sel, "annotate", ranges) )
            return 1;

        CallSiteResult r;
        if ( !annotate_indirect_calls(mgr(), ranges, &r) )
            return 1;

        msg("[ida-ttd] indirect calls: %d site(s) annotated, %d distinct target(s), "
            "%d site(s) reached more than one, %d given their callee's prototype%s%s.\n",
            (int)r.sites, (int)r.targets, (int)r.polymorphic, (int)r.typed,
            r.truncated ? " (site limit reached)" : "",
            r.cancelled ? " (stopped early)" : "");
        if ( r.undefined != 0 )
            msg("[ida-ttd] %d call site(s) were skipped: IDA has no instruction "
                "defined there, so a cross-reference cannot be attached.\n",
                (int)r.undefined);
        if ( r.sites == 0 )
            info("No indirect call in that scope was executed by the recording.");
        refresh_idaview_anyway();
        if ( r.typed != 0 )
            redecompile_pseudocode_views();
        else
            refresh_pseudocode_views();
        return 1;
    }

    int idaapi ClearIndirectCallsHandler::activate(action_activation_ctx_t *)
    {
        size_t n = clear_indirect_call_annotations();
        msg("[ida-ttd] removed the indirect-call annotation from %d site(s).\n", (int)n);
        refresh_idaview_anyway();
        redecompile_pseudocode_views();
        return 1;
    }
}
