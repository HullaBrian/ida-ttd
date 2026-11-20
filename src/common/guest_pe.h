#pragma once

#include "common/pch.h"
#include "core/guest_view.h"

namespace idattd
{
    // PE parsing from guest memory, for both the backends and the core. Nothing
    // here touches the IDA database; common/symbols applies the results.

    // Read exactly 'size' bytes of guest memory; false on a short read.
    bool pe_read(const GuestRead &c, uint64_t addr, void *buf, size_t size);
    template <typename T>
    bool pe_read_val(const GuestRead &c, uint64_t addr, T *out)
    {
        return pe_read(c, addr, out, sizeof(T));
    }
    // A NUL-terminated string of at most 'maxlen' bytes; empty when unreadable.
    std::string pe_read_cstr(const GuestRead &c, uint64_t addr, size_t maxlen = 512);

    // Every named, non-forwarded export of the module at 'base', as (address,
    // name). The cursor must be where the module is mapped. Returns the count.
    size_t read_guest_exports(const GuestRead &cursor, ea_t base, bool is64,
                              std::vector<std::pair<ea_t, std::string>> *out);

    // ---- reading a module's PE headers straight out of the recording -------
    //
    // The loader and the memory-map sweep need a module's bitness, entry point
    // and section layout. The engine's Module record has only name, base, size,
    // checksum and timestamp, so these come from the image itself, read at a
    // position where the module is mapped.

    struct GuestPeSection
    {
        char     name[9] = { 0 };   // NUL-terminated copy of the 8-byte PE name
        uint32_t va = 0;            // RVA of the section
        uint32_t vsize = 0;         // virtual size (0 means "use rawsize")
        uint32_t rawsize = 0;       // size of the initialized data on disk
        uint32_t characteristics = 0;
    };

    struct GuestPeInfo
    {
        bool     is64 = false;      // from the optional header magic, not the host
        uint32_t entry_rva = 0;
        uint32_t size_of_image = 0;
        uint32_t size_of_headers = 0;
        uint64_t preferred_base = 0;
        uint32_t timestamp = 0;     // FileHeader.TimeDateStamp
        uint32_t checksum = 0;      // OptionalHeader.CheckSum
        std::vector<GuestPeSection> sections;
    };

    // Parse the PE headers of the module at 'base'. The cursor must be where
    // the module is loaded (its ModuleLoadedEvent position is reliable).
    //
    // Bitness comes from the optional header magic, not the engine's
    // SystemInfo, which describes the recording machine: a 32-bit program
    // recorded on x64 reports AMD64 there.
    bool read_guest_pe_info(const GuestRead &cursor, ea_t base, GuestPeInfo *out);

    // Which PDB a module was built with, from the CodeView record in its debug
    // directory. The only authoritative answer when the local DLL is a
    // different build: its PDB would describe code the recording never ran.
    struct GuestPdbInfo
    {
        std::string name;           // e.g. "ntdll.pdb", as the linker wrote it
        std::string signature;      // GUID + age, the symbol server's directory
    };

    // Read the above for the module at 'base'; the cursor must be where it is
    // loaded. False when it is unreadable there or has no CodeView record.
    bool read_guest_pdb_info(const GuestRead &cursor, ea_t base,
                             GuestPdbInfo *out);
}
