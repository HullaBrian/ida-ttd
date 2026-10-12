#pragma once

#include "common/pch.h"

namespace idattd
{
    class TraceManager;

    // How much of the database a whole-trace pass should look at. The values are
    // the indices of the radio items scope_items() builds, so they are what an
    // ask_form() "<~S~cope:b:0:40::>" field yields.
    enum Scope
    {
        SCOPE_FUNCTION = 0,     // the function under the cursor
        SCOPE_MODULE,           // the module under the cursor
        SCOPE_ALL_MODULES,
    };

    // Where a "current function" or "current module" scope is measured from.
    //
    // The view wins when it points at a function, because right-clicking one is
    // how you scope to a function you navigated to deliberately. Otherwise the
    // replay position does: IDA's view does not always follow a time-travel
    // jump, and scoping to a stale address fails with "no function there" when
    // the command would have worked at the position the cursor is stopped at.
    ea_t scope_anchor(TraceManager *mgr, action_activation_ctx_t *ctx);

    // The radio items for a scope field around 'ea', in Scope order. They name
    // the function and module, so whichever address scope_anchor() picked is
    // visible before anything runs.
    void scope_items(TraceManager *mgr, ea_t ea, qstrvec_t *out);

    // Turn a scope choice around 'ea' into the [lo, hi) ranges it means.
    //
    // Returns false, having explained why in a warning, when there is nothing of
    // that kind at 'ea': no defined function, or an address in no module (which
    // is what dynamically allocated code looks like). 'what' names the pass in
    // the warning, e.g. "measure".
    bool scope_ranges(TraceManager *mgr, ea_t ea, int scope, const char *what,
                      std::vector<std::pair<ea_t, ea_t>> &out);
}
