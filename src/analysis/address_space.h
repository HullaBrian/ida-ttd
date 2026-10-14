#pragma once

#include "common/pch.h"
#include "core/position.h"

namespace idattd
{
    class TraceManager;

    // The address space as it stands at the playhead, the way a debugger's
    // !address lists it: every region with its protection, what kind of
    // memory it is, and what it is used for.
    //
    // Assembled from what the plugin knows rather than asked of the recording,
    // which keeps no region list:
    //
    //   - the regions the recording allocated or mapped, folded from the
    //     memory map's change timeline up to the playhead;
    //   - the modules loaded there, section by section, with the protection
    //     each section's header asks for and any protection change the
    //     recording made inside it since (a Sogen recording reports its own
    //     image regions and is believed instead);
    //   - each live thread's stack and TEB, the PEB and the shared user data
    //     page, read from the TEB and PEB themselves -- the kernel creates
    //     these, so no recorded call says where they are.
    //
    // The PEB also names the heaps, the process parameters, the API set map
    // and the code page tables, which label the regions holding them.
    struct AddressRegion
    {
        ea_t     base = 0;
        uint64_t size = 0;
        uint32_t protect = 0;         // PAGE_*; 0 when unknown
        bool     reserved = false;    // reserved but not committed
        uint32_t type = 0;            // ITTD_REGION_*
        qstring  use;                 // "ntdll .text", "Stack (thread 0x1A2C)", ...
        // Where the call that made the region was made, when one did.
        Position since = Position::none();
        ea_t end() const { return (ea_t)(base + size); }
    };

    // The regions at the playhead, sorted by address. Free memory is left out.
    void address_space_at(TraceManager *mgr, std::vector<AddressRegion> *out);

    // "Image", "Private", "Mapped", ... for an ITTD_REGION_* value; empty when
    // unknown.
    const char *region_type_name(uint32_t type);
}
