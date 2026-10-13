#pragma once

#include "common/pch.h"
#include "core/guest_view.h"

namespace idattd
{
    // Parsing a PE image out of guest memory: what the backends and the core
    // both need, with nothing of IDA's database in it. common/symbols applies
    // what this reads to the database.

    // Read exactly 'size' bytes of guest memory; false on a short read.
    bool pe_read(const GuestRead &c, uint64_t addr, void *buf, size_t size);
    template <typename T>
    bool pe_read_val(const GuestRead &c, uint64_t addr, T *out)
    {
        return pe_read(c, addr, out, sizeof(T));
    }
    // A NUL-terminated string of at most 'maxlen' bytes; empty when unreadable.
    std::string pe_read_cstr(const GuestRead &c, uint64_t addr, size_t maxlen = 512);

    // Every named export of the module mapped at 'base', as (address, name),
    // forwarders left out. Reads the export directory from guest memory, so
    // the cursor must be where the module is mapped. Returns how many.
    size_t read_guest_exports(const GuestRead &cursor, ea_t base, bool is64,
                              std::vector<std::pair<ea_t, std::string>> *out);

    // ---- reading a module's PE headers straight out of the recording -------
    //
    // The loader and the memory-map sweep both need to know things about a module
    // that the TTD engine does not report: whether it is 32- or 64-bit, where its
    // entry point is, and how its sections are laid out. The engine's Module
    // record carries only a name, a base, a size, a checksum and a timestamp, so
    // the answer has to come from the image itself, read at a position where the
    // module is mapped.

    struct GuestPeSection
    {
        char     name[9] = { 0 };   // NUL-terminated copy of the 8-byte PE name
        uint32_t va = 0;            // RVA of the section
        uint32_t vsize = 0;         // virtual size (0 means "use rawsize")
        uint32_t rawsize = 0;       // size of the initialised data on disk
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

    // Parse the PE headers of the module mapped at 'base' out of guest memory.
    // The cursor must be positioned where the module is loaded (its
    // ModuleLoadedEvent position is the reliable choice).
    //
    // Bitness comes from the optional header magic. It deliberately does not come
    // from the engine's SystemInfo: that reports the recording machine, so a
    // 32-bit program recorded on an x64 box calls itself AMD64 there.
    bool read_guest_pe_info(const GuestRead &cursor, ea_t base, GuestPeInfo *out);

    // Runtime address of one export of the module at 'base', read from the
    // module's own export directory in guest memory. BADADDR when the module is
    // unreadable at this position, the name is not exported, or the export is a
    // forwarder (whose real target lives in another module).
    //
    // This is the address-returning sibling of apply_module_exports, which walks
    // the same table but applies IDA names instead.
    ea_t resolve_export_va(const GuestRead &cursor, ea_t base, bool is64,
                           const char *name);

    // Which PDB a module was built with, taken from the CodeView record in its
    // debug directory. This is the only authoritative answer when the copy of
    // the DLL on this machine is a different build from the recorded one: the
    // local file names a different PDB, and symbols fetched for it describe
    // code the recording never ran.
    struct GuestPdbInfo
    {
        std::string name;           // e.g. "ntdll.pdb", as the linker wrote it
        std::string signature;      // GUID + age, the symbol server's directory
    };

    // Read the above out of guest memory for the module mapped at 'base'. The
    // cursor must be positioned where the module is loaded. False when the module
    // is unreadable there, has no debug directory, or carries no CodeView record.
    bool read_guest_pdb_info(const GuestRead &cursor, ea_t base,
                             GuestPdbInfo *out);
}
