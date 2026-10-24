#pragma once

#include "common/pch.h"

namespace idattd
{
    // Where the Microsoft backend's diagnostics go. A DLL behind the C ABI
    // cannot call msg(), so the host hands it a callback
    // (ittd_backend_api::set_log); without one, lines go to the debugger
    // output, which is all a probe needs.
    using MsttdLogFn = void (*)(void *ud, const char *line);
    void msttd_set_log(MsttdLogFn fn, void *ud);

    // printf-style, one line, the newline included by the caller.
    void msttd_log(const char *fmt, ...);
    void msttd_vlog(const char *fmt, va_list va);
}
