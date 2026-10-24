#pragma once

#include "common/pch.h"
#include "core/guest_view.h"
#include "common/guest_pe.h"

namespace idattd
{
    // Name every export of the module at 'base' from its export table in guest
    // memory. 'cursor' must be positioned where the module is loaded. Returns
    // the number of names applied.
    //
    // The offline symbol path: needs no symbol server. PDB names, when
    // available, are applied on top and add non-exported functions.
    size_t apply_module_exports(const GuestRead &cursor, ea_t base, bool is64);

    // Name one exported address by the rule every name source follows: a real
    // name already there wins, except that a Zw syscall stub gives way to the
    // Nt spelling of the same stub. True when the name was applied.
    bool apply_export_name(ea_t va, const char *name);

    // The [start, end) range of every function of the module at 'base', from
    // its x64 exception directory (.pdata) in guest memory, sorted by start.
    // This recovers function bounds of stripped system DLLs without symbols,
    // as WinDbg does. Returns the count; 0 for x86, which has no such table.
    size_t parse_pdata_functions(const GuestRead &cursor, ea_t base, bool is64,
                                 std::vector<std::pair<ea_t, ea_t>> &out);

    // Same, from the module's on-disk PE file at 'path'. The more complete
    // source: TTD records only accessed memory, and .pdata is often never
    // touched. A non-zero 'want_timestamp' / 'want_checksum' (from the trace's
    // Module record) must match the file's NT headers, else the file is a
    // different build and its bounds would be wrong. Pass 0 for both to skip.
    size_t parse_pdata_functions_from_file(const char *path, ea_t base, bool is64,
                                           uint32_t want_timestamp, uint32_t want_checksum,
                                           std::vector<std::pair<ea_t, ea_t>> &out);

    // A module's on-disk PE image, cached to serve bytes the recording never
    // saw (code never executed or read). WinDbg fills those gaps from the file
    // too. Recorded memory always wins (it reflects self-modification); the
    // image only fills holes.
    struct ModuleImage
    {
        struct Section { uint32_t va, vsize, raw, rawsize; };
        std::vector<uint8_t> file;        // whole file contents
        std::vector<Section> sections;
        uint32_t             sizeOfHeaders = 0;
        // Identity of the file opened, from its NT headers. The trace records
        // the same values, so the caller can refuse a different build: the
        // path is the recording machine's and may name another file here.
        uint32_t             timestamp = 0;   // FileHeader.TimeDateStamp
        uint32_t             checksum  = 0;   // OptionalHeader.CheckSum
        uint32_t             sizeOfImage = 0; // OptionalHeader.SizeOfImage
        bool                 ok = false;  // false once tried and failed
    };

    // Read the module file at 'path' into 'out' and parse its section map.
    // Returns out.ok; false (not a crash) for a missing or non-PE file.
    bool load_module_image(const char *path, ModuleImage &out);

    // Copy up to 'size' image bytes starting at 'rva' into 'buf'. Returns the
    // length of one contiguous run (bounded by the containing section's raw
    // data, or the headers), or 0 when 'rva' has no file bytes (a zero-fill
    // tail), which the caller leaves zero as the loader would.
    size_t read_module_image_rva(const ModuleImage &img, uint32_t rva, void *buf, size_t size);
}
