#pragma once

#include "common/pch.h"

namespace idattd
{
    class TraceManager;

    // A function's display name, demangled when possible. Falls back to any
    // plain name at the address (an export or a PDB symbol for a function IDA
    // has not defined), then to the bare address, so a column is never blank.
    qstring func_display_name(ea_t ea);

    // "name+0x12" from the function IDA has defined around an address, the
    // name alone at its entry, else the address in hex.
    qstring func_offset_name(ea_t ea);

    // "module!symbol+offset" for an address, as honestly as the database allows.
    //
    // The naive answer -- ask IDA for the nearest name -- is actively misleading
    // in a system DLL. Only exports are named there unless a PDB was loaded, and
    // the code that allocates memory is almost always an internal helper, so the
    // nearest name below it can be an unrelated function tens of kilobytes away.
    //
    // So the enclosing function is established first -- from IDA when it has
    // defined one, otherwise from the module's exception table, which knows where
    // every x64 function starts whether or not anything named it. A name is only
    // used when it lies inside that function. Failing all of that the address is
    // given relative to the module, which says less but is never wrong.
    qstring describe_address(TraceManager *mgr, ea_t ea);
}
