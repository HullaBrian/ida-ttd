#pragma once

#include "common/pch.h"

namespace idattd
{
    class TraceManager;

    // How much of the database a whole-trace pass looks at. The values are the
    // indices of scope_items()' radio items, as an ask_form()
    // "<~S~cope:b:0:40::>" field yields them.
    enum Scope
    {
        SCOPE_FUNCTION = 0,     // the function under the cursor
        SCOPE_MODULE,           // the module under the cursor
        SCOPE_ALL_MODULES,
    };

    // Where a "current function" or "current module" scope is measured from.
    // The view wins when it points at a function (a deliberate right-click);
    // otherwise the replay position does, since IDA's view does not always
    // follow a travel and a stale address would fail with "no function there".
    ea_t scope_anchor(TraceManager *mgr, action_activation_ctx_t *ctx);

    // The radio items for a scope field around 'ea', in Scope order. They name
    // the function and module, showing which address scope_anchor() picked.
    void scope_items(TraceManager *mgr, ea_t ea, qstrvec_t *out);

    // Turn a scope choice around 'ea' into the [lo, hi) ranges it means.
    // False, after a warning, when 'ea' has no defined function or is in no
    // module (dynamically allocated code). 'what' names the pass in the
    // warning, e.g. "measure".
    bool scope_ranges(TraceManager *mgr, ea_t ea, int scope, const char *what,
                      std::vector<std::pair<ea_t, ea_t>> &out);
}
