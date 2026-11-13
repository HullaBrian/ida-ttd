#pragma once

#include "common/pch.h"
#include "core/backend.h"

namespace idattd
{
    // The C ABI for a backend written against ITraceBackend: the inverse of
    // BackendModule. A backend DLL built from C++ exports
    //
    //   extern "C" __declspec(dllexport)
    //   const ittd_backend_api *ida_ttd_backend(uint32_t abi_version)
    //   {
    //       // Any core since the last layout change (ida_ttd_backend.h).
    //       return abi_version >= ITTD_ABI_LAYOUT
    //            ? export_backend(make_my_backend, my_set_log) : nullptr;
    //   }
    //
    // and the core sees it through BackendModule like any other. Each
    // ittd_backend handle is a fresh backend from 'factory', opened on one
    // recording; identity questions go to one kept unopened.
    //
    // Count queries are asked twice (count, then fill), and a replay engine
    // answers each by replaying the recording, so the answer is kept between
    // the two calls.
    using BackendFactory = BackendPtr (*)();
    using LogCallback    = void (*)(void *ud, const char *line);
    using LogSetter      = void (*)(LogCallback log, void *ud);

    // The table, built on the first call; later calls return the same one.
    const ittd_backend_api *export_backend(BackendFactory factory, LogSetter set_log);
}
