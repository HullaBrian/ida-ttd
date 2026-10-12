#pragma once

#include "common/pch.h"
#include "common/symbols.h"
#include "core/backend.h"

namespace idattd
{
    // Everything the plugin knows about the modules a recording loaded: where
    // they sit, what they are called, where their functions start, which of
    // their addresses have names, and their on-disk images.
    //
    // One sorted table answers every lookup by binary search, built once when
    // the session binds -- a recording's module list does not change. The
    // table carries each module's display name and segment identifier,
    // computed once rather than per query from a path recorded on another
    // machine.
    //
    // Backend-neutral: the modules come from ITraceBackend::modules(), names
    // from the backend's recorded exports when it has them and from the
    // image's export directory read through a scratch cursor otherwise, and
    // function bounds from the backend, the file on disk, or the recorded
    // .pdata, in that order.
    class ModuleRegistry
    {
    public:
        // One module as the table holds it.
        struct Span
        {
            ea_t    base = 0;
            ea_t    end  = 0;
            // "kernel32.dll": the file name as recorded, without its directory.
            qstring file;
            // "kernel32": the same without the extension, the way a debugger
            // writes a qualified symbol.
            qstring name;
            // "kernel32_dll": the file name with its extension, rewritten so it
            // is a legal IDA name, for the segment a region maps to.
            qstring ident;
            bool operator<(const Span &o) const { return base < o.base; }
        };

        // One load of one module: where it went, how big it was, its base name,
        // and the position at which the trace saw it mapped -- the position at
        // which its own headers and export table can be read.
        struct Load
        {
            ea_t     base = BADADDR;
            uint64_t size = 0;
            qstring  name;        // base name, as recorded
            Position pos;         // where it was loaded
        };

        // ---- session lifetime ----------------------------------------------
        //
        // 'target_name' is the file name of the analysed binary, which is how
        // the PDB path refuses to fetch symbols for the file IDA already owns.
        void bind(ITraceBackend *backend, bool is64, const char *target_name);
        void reset();

        // ---- lookups -------------------------------------------------------
        const std::vector<Span> &spans() const { return m_spans; }
        // Index into spans() of the module containing 'ea', or SIZE_MAX.
        size_t  index_at(ea_t ea) const;
        // Loaded module containing 'ea', as [lo, hi). False when 'ea' belongs
        // to no module (dynamically allocated code).
        bool    range_at(ea_t ea, ea_t &lo, ea_t &hi) const;
        qstring name_at(ea_t ea) const;
        qstring ident_at(ea_t ea) const;
        // Every loaded module as [lo, hi), sorted by base.
        std::vector<std::pair<ea_t, ea_t>> ranges() const;
        // Every module load in the trace, in load order. A module loaded twice
        // at the same address appears twice, which is deliberate: each load
        // needs its own read position.
        std::vector<Load> loads() const;
        // The modules mapped at 'pos', as their records.
        std::vector<const ModuleInfo *> loaded_at(Position pos) const;
        // The record for the module based at 'base' (its first load), or null.
        const ModuleInfo *record_at(ea_t base) const;
        // The analysed binary's record, or null.
        const ModuleInfo *main_module() const;

        // True if 'ea' is inside a loaded module other than the analysed
        // binary -- that is, library or system code.
        bool is_library_address(ea_t ea) const;

        // [start, end) of the function containing 'pc', from the exception
        // table of its module. False for a module whose table has not been
        // read and for addresses outside any recorded function. Populated as a
        // side effect of resolve_symbols().
        bool function_range_at(ea_t pc, ea_t &start, ea_t &end) const;

        // Resolve a name pattern to the set of matching function addresses.
        // Shell-style wildcards (* and ?), case-insensitive, with an optional
        // "module!" qualifier, e.g. "kernel32!Virtual*" or "*Alloc".
        std::vector<ea_t> resolve_function_pattern(const char *pattern) const;

        // ---- naming --------------------------------------------------------
        //
        // Apply export names for the module loaded at 'base' and record its
        // function bounds. Deduplicated: a base is only attempted once per
        // trace.
        void resolve_symbols(ea_t base);
        // The same for every module mapped at 'pos'.
        void resolve_loaded(Position pos);
        // Load symbols for the module at 'base' without blocking: the PDB the
        // recorded image names is fetched into a local store on a worker
        // thread (common/symsrv.h), and IDA's PDB plugin is only driven, with
        // no "load symbols?" prompt, once the file is on disk. Deduplicated per
        // module.
        void load_pdb(ea_t base);
        // Hand every PDB that finished downloading since the last call to IDA.
        // Main thread only; called once per stop.
        void apply_finished_pdbs();

        // ---- on-disk images ------------------------------------------------
        //
        // Find the image of the module containing 'ea', loading and caching it
        // on first use. Null when 'ea' is in no module, the file is
        // unavailable, or the file is a different build of the module than the
        // recording saw. On success 'base_out' is the module's runtime base, so
        // the caller can form rva = ea - base. Used to serve bytes the
        // recording never captured.
        const ModuleImage *image_for(ea_t ea, ea_t &base_out);

    private:
        // Guest memory of the module at 'base', where it is known to be mapped.
        GuestRead read_at_load(ea_t base);
        bool pdb_identity(ea_t base, GuestPdbInfo *out);
        void apply_pdb(ea_t base, const std::string &path, const GuestPdbInfo &pdb);
        void keep_names_only(ea_t base);
        void report_missing_pdb(const std::string &path, const GuestPdbInfo &pdb);

        ITraceBackend *m_backend = nullptr;
        bool           m_is64 = false;
        qstring        m_targetName;

        std::vector<ModuleInfo> m_modules;   // per load, as the backend gives them
        std::vector<Span>       m_spans;     // unique by base, sorted
        ea_t                    m_mainBase = BADADDR;

        std::set<ea_t> m_resolvedBases;   // modules whose exports we have named
        std::set<ea_t> m_pdbBases;        // modules whose PDB we have requested

        // Per-module function bounds, keyed by module base; each vector is
        // sorted by start address.
        std::map<ea_t, std::vector<std::pair<ea_t, ea_t>>> m_funcRanges;

        // Per-module on-disk image cache, keyed by module base. An entry with
        // ok == false means the file was already tried and rejected.
        std::map<ea_t, ModuleImage> m_moduleImages;

        // Scratch cursor for reading a module's headers at its load position.
        CursorPtr m_symCursor;
    };
}
