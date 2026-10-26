#include "common/trace_link.h"

namespace idattd
{
    // A "$ " name, like the plugin's other netnodes, cannot collide with a
    // program byte name.
    static const char  TL_NODE[] = "$ ida-ttd trace";
    static const uchar TL_STR    = 'S';   // supstr slots
    static const uchar TL_NUM    = 'N';   // altval slots

    // Slot numbers. A new field takes a new slot and a version bump; changing
    // a slot's meaning requires the version check to reject the old layout.
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
        // 1 = 32-bit, 2 = 64-bit, so 0 (altval's missing slot) means unknown.
        N_BITNESS     = 3,
        // 4 held the per-database automatic start answer; the
        // replay_on_open setting replaced it. Not to be reused: old
        // databases still have it.
    };

    static const nodeidx_t TL_VERSION = 1;

    bool trace_link_present()
    {
        netnode nn(TL_NODE);
        if ( nn == BADNODE )
            return false;
        return nn.altval(N_VERSION, TL_NUM) == TL_VERSION;
    }

    bool trace_link_read(TraceLink *out)
    {
        if ( out == nullptr )
            return false;
        netnode nn(TL_NODE);
        if ( nn == BADNODE )
            return false;
        // Refuse an unknown schema rather than return half of it.
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

    void trace_link_set_path(const char *path)
    {
        if ( path == nullptr )
            return;
        netnode nn(TL_NODE, 0, true);
        nn.supset(S_TRACE_PATH, path, qstrlen(path) + 1, TL_STR);
    }

    // Settings subkey for the start mark. One value per database, so one that
    // fails does not block the others.
    static const char TL_REGKEY[] = "ida-ttd";

    static qstring start_mark_name()
    {
        const char *path = get_path(PATH_TYPE_IDB);
        if ( path == nullptr || path[0] == 0 )
            path = get_path(PATH_TYPE_CMD);
        if ( path == nullptr || path[0] == 0 )
            return qstring();
        qstring name = "starting:";
        name.append(path);
        return name;
    }

    bool trace_link_start_marked()
    {
        qstring name = start_mark_name();
        return !name.empty() && reg_read_int(name.c_str(), 0, TL_REGKEY) != 0;
    }

    void trace_link_mark_start(bool pending)
    {
        qstring name = start_mark_name();
        if ( name.empty() )
            return;
        if ( pending )
            reg_write_int(name.c_str(), 1, TL_REGKEY);
        else
            reg_delete(name.c_str(), TL_REGKEY);
    }
}
