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
}
