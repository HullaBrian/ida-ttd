#include "ui/scope.h"
#include "debugger/trace_manager.h"

namespace idattd
{
    ea_t scope_anchor(TraceManager *mgr, action_activation_ctx_t *ctx)
    {
        ea_t view = ctx != nullptr && ctx->cur_ea != BADADDR ? ctx->cur_ea
                                                            : get_screen_ea();
        func_entry_info_t fi;
        if ( view != BADADDR && get_func_entry_info(&fi, view) )
            return view;

        if ( mgr != nullptr && mgr->is_active() )
        {
            ea_t pc = mgr->current_pc_ea();
            if ( pc != BADADDR )
                return pc;
        }
        return view;
    }

    void scope_items(TraceManager *mgr, ea_t ea, qstrvec_t *out)
    {
        if ( out == nullptr )
            return;
        out->clear();

        qstring where;
        func_entry_info_t fi;
        if ( get_func_entry_info(&fi, ea) )
        {
            qstring fn;
            if ( get_func_name(&fn, fi.start_ea) > 0 && !fn.empty() )
                where.sprnt("Function %s", fn.c_str());
        }
        if ( where.empty() )
            where.sprnt("Function containing 0x%llX", (uint64_t)ea);

        qstring mod = mgr != nullptr ? mgr->modules().name_at(ea) : qstring();
        qstring modline;
        if ( !mod.empty() )
            modline.sprnt("Module %s", mod.c_str());
        else
            modline.sprnt("Module containing 0x%llX", (uint64_t)ea);

        out->push_back(where);
        out->push_back(modline);
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
                if ( !mgr->modules().range_at(ea, lo, hi) )
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
                out = mgr->modules().ranges();
                return true;
        }
    }
}
