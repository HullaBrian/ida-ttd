#pragma once

#include "pch.h"

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
    // (x64 unwinding requires this table) — the same source WinDbg uses. Returns
    // the number of ranges; 'out' is sorted ascending. x64 only (returns 0 for x86).
    size_t parse_pdata_functions(TTD::Replay::ICursorView *cursor, ea_t base, bool is64,
                                 std::vector<std::pair<ea_t, ea_t>> &out);

    // Same as parse_pdata_functions but reads the .pdata from the module's on-disk
    // PE file at 'path' (the RUNTIME_FUNCTION RVAs are base-relative, so they map to
    // runtime addresses for the module loaded at 'base'). This is the reliable
    // source: TTD only records memory that was accessed at runtime, and a module's
    // .pdata is often never touched, so reading it from the trace can come up empty.
    size_t parse_pdata_functions_from_file(const char *path, ea_t base, bool is64,
                                           std::vector<std::pair<ea_t, ea_t>> &out);
}
