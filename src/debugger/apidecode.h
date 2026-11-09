#pragma once

#include "common/pch.h"
#include "core/guest_view.h"
#include "common/apimeta/win32meta.hpp"

namespace idattd
{
    class ModuleRegistry;

    // API calls decoded from metadata rather than IDA's types: Microsoft's
    // Win32 metadata (win32json) and phnt's native API headers, as indexed by
    // ttd-capa (common/apimeta; the two files in ida-ttd-data). They know what
    // IDA's type libraries do not: flag and enum names, which parameters the
    // callee fills in (read again at the return), and each buffer's length.

    // The signature for a function, by its export or IDA name, or nullptr.
    // The indexes load on first use; without them everything here answers
    // nullptr and callers fall back to IDA's types.
    const win32meta::FuncSig *api_signature(ModuleRegistry *mods, ea_t func_ea);
    const win32meta::FuncSig *api_signature(const char *name);
    // Why the indexes are not loaded, or empty when they are.
    const qstring &api_metadata_error();

    // An IDA prototype built from a signature, for a function the database's
    // type libraries do not know (phnt's ntdll Rtl names, which mssdk lacks).
    // Each parameter keeps its name and gets its metadata type when the
    // database's types know that name (ULONG, HANDLE, UNICODE_STRING *),
    // else a generic integer or pointer of the right size. The metadata has
    // no return types: Nt and Zw calls return NTSTATUS, others a
    // pointer-sized integer. __fastcall on x64, __stdcall on x86 (__cdecl
    // for the C runtime). False for a signature that returns an aggregate
    // through a hidden pointer, whose parameter list would be misleading.
    bool api_prototype(const win32meta::FuncSig &sig, bool is64, tinfo_t *out);

    struct DecodedArg
    {
        qstring  name;
        qstring  text;                  // as shown
        uint64_t raw = 0;               // the argument's own value
        bool     out = false;           // read again at the return
        // An out parameter pointing at an integer: the integer at the call
        // and at the return. Equal values may mean Microsoft TTD lacks the
        // kernel's write (ITraceBackend::query_out_values).
        std::optional<uint64_t> pointee_before, pointee_after;
    };

    struct DecodedCall
    {
        const win32meta::FuncSig *sig = nullptr;
        bool                      is64 = true;
        std::vector<DecodedArg>   args;
        // Values found for integer and handle out parameters, by parameter
        // (ITraceBackend::query_out_values), used instead of reading memory at
        // the return, where Microsoft TTD lacks the kernel's writes.
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
    // Whether decode_api_args would mark any of sig's arguments 'out' (so
    // decode_api_outs may read memory after the call), from the signature
    // alone.
    bool api_has_out_params(const win32meta::FuncSig &sig);
    // At the return: what the callee wrote through its out parameters.
    void decode_api_outs(const GuestView &v, DecodedCall *call);
    // The return value: an NTSTATUS by name for a native API, else hex.
    qstring decode_api_return(const DecodedCall &call, uint64_t rv);
}
