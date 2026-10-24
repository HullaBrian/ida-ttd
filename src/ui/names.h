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
    // The nearest name is misleading in a system DLL: without a PDB only
    // exports are named, and allocating code is usually an internal helper,
    // so the nearest name can be an unrelated function tens of KB away.
    //
    // So the enclosing function comes first (IDA's, else the module's
    // exception table, which knows every x64 function start), and a name is
    // used only inside it. Failing that, the address is given relative to the
    // module: less informative, never wrong.
    qstring describe_address(TraceManager *mgr, ea_t ea);
}
