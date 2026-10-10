#pragma once

#include "common/pch.h"

namespace idattd
{
    // Parse the PE export table of the module mapped at 'base' out of the trace's
    // guest memory (read through 'cursor', which the caller must already have
    // positioned at a point in time where the module is loaded -- see
    // TraceManager::resolve_symbols), and apply IDA names to each exported
    // function address. Returns the number of names applied.
    //
    // This is the offline-first symbol path: it works with no symbol server and
    // names every export. IDA's own PDB symbols (when available) apply on top and
    // add internal/non-exported names.
    size_t apply_module_exports(TTD::Replay::ICursorView *cursor, ea_t base, bool is64);

    // Parse the x64 PE exception directory (.pdata / RUNTIME_FUNCTION table) of
    // the module at 'base' out of guest memory, returning the [start, end) address
    // range of every function in the module (sorted by start). This is how the
    // function boundaries of stripped system DLLs are recovered without symbols
    // (x64 unwinding requires this table) -- the same source WinDbg uses. Returns
    // the number of ranges; 'out' is sorted ascending. x64 only (returns 0 for x86).
    size_t parse_pdata_functions(TTD::Replay::ICursorView *cursor, ea_t base, bool is64,
                                 std::vector<std::pair<ea_t, ea_t>> &out);

    // Same as parse_pdata_functions but reads the .pdata from the module's on-disk
    // PE file at 'path' (the RUNTIME_FUNCTION RVAs are base-relative, so they map to
    // runtime addresses for the module loaded at 'base'). This is the reliable
    // source: TTD only records memory that was accessed at runtime, and a module's
    // .pdata is often never touched, so reading it from the trace can come up empty.
    // 'want_timestamp' / 'want_checksum' come from the trace's Module record: when
    // either is non-zero the file's own NT headers must match it, otherwise the
    // file is a different build of the module and its function bounds would be
    // wrong. Pass 0 for both to skip the check.
    size_t parse_pdata_functions_from_file(const char *path, ea_t base, bool is64,
                                           uint32_t want_timestamp, uint32_t want_checksum,
                                           std::vector<std::pair<ea_t, ea_t>> &out);

    // A module's on-disk PE image, cached for serving never-recorded bytes. TTD
    // only records memory that was accessed at runtime; for image-backed pages the
    // never-executed code (the other side of a branch, a cold epilogue) is in the
    // trace at no position. WinDbg fills those gaps from the module file, and so do
    // we. Recorded memory always takes precedence (it reflects self-modification);
    // the image only fills holes.
    struct ModuleImage
    {
        struct Section { uint32_t va, vsize, raw, rawsize; };
        std::vector<uint8_t> file;        // whole file contents
        std::vector<Section> sections;
        uint32_t             sizeOfHeaders = 0;
        // Identity of the file we actually opened, from its NT headers. The trace
        // records the same two values for each module, so the caller can refuse a
        // file that is a different build of the same DLL -- the path came off the
        // recording machine and may resolve to something else entirely here.
        uint32_t             timestamp = 0;   // FileHeader.TimeDateStamp
        uint32_t             checksum  = 0;   // OptionalHeader.CheckSum
        uint32_t             sizeOfImage = 0; // OptionalHeader.SizeOfImage
        bool                 ok = false;  // false once we've tried and failed
    };

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
        std::vector<GuestPeSection> sections;
    };

    // Parse the PE headers of the module mapped at 'base' out of guest memory.
    // The cursor must be positioned where the module is loaded (its
    // ModuleLoadedEvent position is the reliable choice).
    //
    // Bitness comes from the optional header magic. It deliberately does not come
    // from the engine's SystemInfo: that reports the recording machine, so a
    // 32-bit program recorded on an x64 box calls itself AMD64 there.
    bool read_guest_pe_info(TTD::Replay::ICursorView *cursor, ea_t base, GuestPeInfo *out);

    // Runtime address of one export of the module at 'base', read from the
    // module's own export directory in guest memory. BADADDR when the module is
    // unreadable at this position, the name is not exported, or the export is a
    // forwarder (whose real target lives in another module).
    //
    // This is the address-returning sibling of apply_module_exports, which walks
    // the same table but applies IDA names instead.
    ea_t resolve_export_va(TTD::Replay::ICursorView *cursor, ea_t base, bool is64,
                           const char *name);

    // Read the module file at 'path' into 'out' and parse its section map. Returns
    // out.ok. Safe to call on a non-PE / missing file (returns false, out.ok=false).
    bool load_module_image(const char *path, ModuleImage &out);

    // Copy up to 'size' bytes that the image has for run starting at relative
    // virtual address 'rva' into 'buf'. Returns the count copied, which is a single
    // contiguous run (bounded by the containing section's raw data, or the headers).
    // Returns 0 when 'rva' isn't backed by file bytes (e.g. a .bss/zero-fill tail),
    // so the caller can leave those bytes zero -- matching the image.
    size_t read_module_image_rva(const ModuleImage &img, uint32_t rva, void *buf, size_t size);
}
