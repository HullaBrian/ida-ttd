#pragma once

// Reading a PDB's public symbols without IDA, on any thread.
//
// IDA's PDB plugin is the only way to apply a PDB in full (types, prototypes,
// names), and it runs on the main thread for as long as the PDB takes --
// seconds for ntdll, more for the bigger system DLLs. Run at a stop, that is
// a step that hangs. But what an analyst moving through a recording needs from
// a system DLL's PDB is the names of its functions, and the PDBs Microsoft's
// symbol server hands out are stripped to their public symbols anyway. Those
// sit in one stream of the file and take milliseconds to read, so they are
// read here, off the main thread, and only the naming is left to IDA.
//
// Standard library only: no IDA type crosses this boundary, so a worker
// thread can call it while the main thread owns the database.

#include <cstdint>
#include <string>
#include <vector>

namespace idattd
{
    struct PdbPublic
    {
        uint32_t    rva = 0;        // relative to the module's image base
        bool        code = false;   // a function (cvpsfCode / cvpsfFunction)
        std::string name;           // as recorded: possibly decorated
    };

    // Every public symbol of the PDB at 'path' (wide: the symbol store sits
    // under the user's profile, which need not be ASCII), with section:offset already
    // turned into an RVA through the PDB's own section headers. False, with a
    // reason in 'error', when the file is not an MSF 7 PDB, is damaged, or
    // describes an image rearranged after linking (OMAP), whose public
    // offsets name addresses that no longer exist; such a PDB has to go
    // through IDA's PDB plugin.
    bool read_pdb_publics(const wchar_t *path, std::vector<PdbPublic> &out, std::string *error);
}
