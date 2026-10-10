#include "ui/scope.h"
#include "debugger/trace_manager.h"

namespace idattd
{
    void scope_items(qstrvec_t *out)
    {
        if ( out == nullptr )
            return;
        out->clear();
        out->push_back("Function under the cursor");
        out->push_back("Module under the cursor");
        out->push_back("All loaded modules");
    }

    bool scope_ranges(TraceManager *mgr, ea_t ea, int scope, const char *what,
                      std::vector<std::pair<ea_t, ea_t>> &out)
    {
        out.clear();
        if ( mgr == nullptr )
            return false;

        switch ( scope )
        {
            case SCOPE_FUNCTION:
            {
                func_entry_info_t fi;
                if ( !get_func_entry_info(&fi, ea) )
                {
                    warning("There is no defined function at 0x%llX.\n\n"
                            "Define one first, or %s the whole module instead.",
                            (uint64_t)ea, what);
                    return false;
                }
                out.push_back({ fi.start_ea, fi.end_ea });
                return true;
            }

            case SCOPE_MODULE:
            {
                ea_t lo = 0, hi = 0;
                if ( !mgr->module_range_at(ea, lo, hi) )
                {
                    warning("0x%llX is not inside a module loaded by the trace.\n\n"
                            "Dynamically allocated code has no module to %s; use "
                            "the function scope there.", (uint64_t)ea, what);
                    return false;
                }
                out.push_back({ lo, hi });
                return true;
            }

            default:
                out = mgr->module_ranges();
                return true;
        }
    }
}
