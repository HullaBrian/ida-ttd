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

    // The radio items for a scope field, in Scope order.
    void scope_items(qstrvec_t *out);

    // Turn a scope choice around 'ea' into the [lo, hi) ranges it means.
    //
    // Returns false, having explained why in a warning, when there is nothing of
    // that kind at 'ea': no defined function, or an address in no module (which
    // is what dynamically allocated code looks like). 'what' names the pass in
    // the warning, e.g. "measure".
    bool scope_ranges(TraceManager *mgr, ea_t ea, int scope, const char *what,
                      std::vector<std::pair<ea_t, ea_t>> &out);
}
