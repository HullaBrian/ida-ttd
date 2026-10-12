#include "backend-msttd/msttd_host.h"

#include <cstdio>

namespace idattd
{
    static MsttdLogFn g_log    = nullptr;
    static void      *g_log_ud = nullptr;

    void msttd_set_log(MsttdLogFn fn, void *ud)
    {
        g_log    = fn;
        g_log_ud = ud;
    }

    void msttd_vlog(const char *fmt, va_list va)
    {
        char buf[2048];
        vsnprintf(buf, sizeof(buf), fmt, va);
        if ( g_log != nullptr )
            g_log(g_log_ud, buf);
        else
            OutputDebugStringA(buf);
    }

    void msttd_log(const char *fmt, ...)
    {
        va_list va;
        va_start(va, fmt);
        msttd_vlog(fmt, va);
        va_end(va);
    }
}
