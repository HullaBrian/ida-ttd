#pragma once

// Reading a PDB's public symbols without IDA, on any thread.
//
// IDA's PDB plugin applies a PDB in full (types, prototypes, names) but runs
// on the main thread for seconds per system DLL, which makes a step hang.
// What a system DLL needs is its function names, and Microsoft's public PDBs
// are stripped to public symbols anyway. Those sit in one stream and take
// milliseconds to read, so they are read here off the main thread and only
// the naming is left to IDA.
//
// Standard library only, so a worker thread can call it while the main thread
// owns the database.

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

    // Every public symbol of the PDB at 'path' (wide, since the store is under
    // the user's profile), with section:offset turned into an RVA through the
    // PDB's own section headers. False, with a reason in 'error', when the file
    // is not an MSF 7 PDB, is damaged, or describes an image rearranged after
    // linking (OMAP); such a PDB has to go through IDA's PDB plugin.
    bool read_pdb_publics(const wchar_t *path, std::vector<PdbPublic> &out, std::string *error);
}
