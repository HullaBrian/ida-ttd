#include "trace_link.h"

namespace idattd
{
    // Same naming convention as the other per-database records the plugin keeps
    // (bookmarks, coverage, callsites): a '$' name is reserved for a netnode, so
    // it can never collide with a program byte name.
    static const char  TL_NODE[] = "$ ida-ttd trace";
    static const uchar TL_STR    = 'S';   // supstr slots
    static const uchar TL_NUM    = 'N';   // altval slots

    // Slot numbers. Adding a field means a new slot and a version bump; changing
    // the meaning of an existing one means the version check below must reject
    // the old layout rather than misread it.
    enum
    {
        S_TRACE_PATH  = 0,
        S_MODULE_PATH = 1,
        S_MODULE_NAME = 2,
    };
    enum
    {
        N_VERSION     = 0,
        N_MODULE_BASE = 1,
        N_MODULE_SIZE = 2,
        // Biased so that "never written" (altval returns 0 for a missing slot)
        // is distinguishable from a real answer: 1 = 32-bit, 2 = 64-bit.
        N_BITNESS     = 3,
        N_AUTOSTART   = 4,
    };

    static const nodeidx_t TL_VERSION = 1;

    //-----------------------------------------------------------------------
    bool trace_link_present()
    {
        netnode nn(TL_NODE);
        if ( nn == BADNODE )
            return false;
        return nn.altval(N_VERSION, TL_NUM) == TL_VERSION;
    }

    //-----------------------------------------------------------------------
    bool trace_link_read(TraceLink *out)
    {
        if ( out == nullptr )
            return false;
        netnode nn(TL_NODE);
        if ( nn == BADNODE )
            return false;
        // A record from a schema this build does not know is not readable field
        // by field: refuse it rather than hand back half of it.
        if ( nn.altval(N_VERSION, TL_NUM) != TL_VERSION )
            return false;

        *out = TraceLink();
        nn.supstr(&out->trace_path,  S_TRACE_PATH,  TL_STR);
        nn.supstr(&out->module_path, S_MODULE_PATH, TL_STR);
        nn.supstr(&out->module_name, S_MODULE_NAME, TL_STR);
        out->module_base = (ea_t)nn.altval(N_MODULE_BASE, TL_NUM);
        out->module_size = (uint64_t)nn.altval(N_MODULE_SIZE, TL_NUM);

        nodeidx_t b = nn.altval(N_BITNESS, TL_NUM);
        out->bitness = b == 1 ? 32 : b == 2 ? 64 : 0;

        return !out->trace_path.empty();
    }

    //-----------------------------------------------------------------------
    void trace_link_write(const TraceLink &link)
    {
        netnode nn(TL_NODE, 0, true);   // create on first write
        nn.altset(N_VERSION, TL_VERSION, TL_NUM);
        nn.supset(S_TRACE_PATH,  link.trace_path.c_str(),  link.trace_path.length() + 1,  TL_STR);
        nn.supset(S_MODULE_PATH, link.module_path.c_str(), link.module_path.length() + 1, TL_STR);
        nn.supset(S_MODULE_NAME, link.module_name.c_str(), link.module_name.length() + 1, TL_STR);
        nn.altset(N_MODULE_BASE, (nodeidx_t)link.module_base, TL_NUM);
        nn.altset(N_MODULE_SIZE, (nodeidx_t)link.module_size, TL_NUM);
        nn.altset(N_BITNESS, link.bitness == 32 ? 1 : link.bitness == 64 ? 2 : 0, TL_NUM);
    }

    //-----------------------------------------------------------------------
    void trace_link_set_path(const char *path)
    {
        if ( path == nullptr )
            return;
        netnode nn(TL_NODE, 0, true);
        nn.supset(S_TRACE_PATH, path, qstrlen(path) + 1, TL_STR);
    }

    //-----------------------------------------------------------------------
    int trace_link_autostart()
    {
        netnode nn(TL_NODE);
        if ( nn == BADNODE )
            return TL_ASK;
        return (int)nn.altval(N_AUTOSTART, TL_NUM);
    }

    //-----------------------------------------------------------------------
    void trace_link_set_autostart(int v)
    {
        netnode nn(TL_NODE, 0, true);
        nn.altset(N_AUTOSTART, (nodeidx_t)v, TL_NUM);
    }
}
