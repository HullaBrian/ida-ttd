#pragma once

#include "common/pch.h"
#include "core/position.h"

namespace idattd
{
    class TraceManager;

    // The address space at the playhead, as a debugger's !address lists it:
    // each region with its protection, memory type and use.
    //
    // The recording keeps no region list, so this is assembled from:
    //
    //   - the regions allocated or mapped, folded from the memory map's
    //     timeline up to the playhead;
    //   - the loaded modules, per section, with the header's protection and
    //     any later protection change inside (Sogen reports its own image
    //     regions, which are used instead);
    //   - each live thread's stack and TEB, the PEB and the shared user data
    //     page, read from the TEB and PEB (the kernel creates these, so no
    //     recorded call locates them).
    //
    // PEB pointers (heaps, process parameters, API set map, code page tables)
    // label the regions holding them.
    struct AddressRegion
    {
        ea_t     base = 0;
        uint64_t size = 0;
        uint32_t protect = 0;         // PAGE_*; 0 when unknown
        bool     reserved = false;    // reserved but not committed
        uint32_t type = 0;            // ITTD_REGION_*
        qstring  use;                 // "ntdll .text", "Stack (thread 0x1A2C)", ...
        bool     in_module = false;   // overlaps a module loaded at the playhead
        // Position of the call that made the region, when known.
        Position since = Position::none();
        ea_t end() const { return (ea_t)(base + size); }
    };

    // The regions at the playhead, sorted by address. Free memory is left out.
    void address_space_at(TraceManager *mgr, std::vector<AddressRegion> *out);

    // Executable memory outside every loaded module (unpacked, injected, JIT).
    bool is_code_outside_modules(const AddressRegion &r);

    // "Image", "Private", "Mapped", ... for an ITTD_REGION_* value; empty when
    // unknown.
    const char *region_type_name(uint32_t type);
}
