// ida-ttd-msttd.dll: Microsoft TTD recordings (.run) behind the backend ABI.
//
// The backend is written against ITraceBackend; core/abi_export turns that
// into the C table the core loads, the same way it loads Sogen's.

#include "backend-msttd/msttd_backend.h"
#include "backend-msttd/msttd_host.h"
#include "core/abi_export.h"

using namespace idattd;

static BackendPtr make_msttd()
{
    return std::make_unique<MsTtdBackend>();
}

extern "C" __declspec(dllexport) const ittd_backend_api *ida_ttd_backend(uint32_t abi_version)
{
    // Any core from the last layout change on: a newer one reads this table
    // only up to its 'size', and passes structs that carry their own.
    if ( abi_version < ITTD_ABI_LAYOUT )
        return nullptr;
    return export_backend(make_msttd, msttd_set_log);
}
