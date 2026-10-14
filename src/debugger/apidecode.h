#pragma once

#include "common/pch.h"
#include "core/guest_view.h"
#include "common/apimeta/win32meta.hpp"

namespace idattd
{
    class ModuleRegistry;

    // API calls decoded from metadata rather than from IDA's types: Microsoft's
    // Win32 metadata (win32json) and the native API headers of phnt, as the
    // indexes ttd-capa builds from them (common/apimeta, the two files in
    // plugins\ida-ttd-data). They know what IDA's type libraries do not:
    // flag and enum values by name, which parameters the callee fills in (so
    // they are read again at the return), and how long each buffer is.

    // The signature for a function, by its export or IDA name, or nullptr.
    // The indexes are loaded on first use; when they are missing everything
    // here answers nullptr and callers fall back to IDA's types.
    const win32meta::FuncSig *api_signature(ModuleRegistry *mods, ea_t func_ea);
    const win32meta::FuncSig *api_signature(const char *name);
    // Why the indexes are not loaded, or empty when they are.
    const qstring &api_metadata_error();

    struct DecodedArg
    {
        qstring  name;
        qstring  text;                  // as shown
        uint64_t raw = 0;               // the argument's own value
        bool     out = false;           // read again at the return
        // An out parameter pointing at an integer: the integer at the call,
        // and as read at the return. Equal values may be Microsoft TTD not
        // having the kernel's write yet (ITraceBackend::query_out_values).
        std::optional<uint64_t> pointee_before, pointee_after;
    };

    struct DecodedCall
    {
        const win32meta::FuncSig *sig = nullptr;
        bool                      is64 = true;
        std::vector<DecodedArg>   args;
        // Values found for out parameters that point at an integer or a
        // handle, by parameter (ITraceBackend::query_out_values): used in
        // place of reading memory at the return, where Microsoft TTD does not
        // have the kernel's writes.
        std::vector<std::optional<uint64_t>> out_values;
    };

    // The out parameters of a decoded call that point at an integer or a
    // handle: parameter index and the integer's width.
    std::vector<std::pair<size_t, uint32_t>> api_int_outs(const DecodedCall &call);
    // "name=value, ..." of a decoded call.
    qstring api_args_text(const DecodedCall &call);

    // At the call site, before the call: every parameter of 'sig'. 'is64' is
    // the calling convention (x64, or x86 stdcall/cdecl).
    void decode_api_args(const GuestView &v, const win32meta::FuncSig &sig, bool is64, DecodedCall *out);
    // At the return: what the callee wrote through its out parameters.
    void decode_api_outs(const GuestView &v, DecodedCall *call);
    // The return value: an NTSTATUS by name for a native API, else hex.
    qstring decode_api_return(const DecodedCall &call, uint64_t rv);
}
