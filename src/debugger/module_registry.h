#pragma once

#include "common/pch.h"
#include "common/symbols.h"
#include "core/position.h"

namespace idattd
{
    // Everything the plugin knows about the modules a recording loaded: where
    // they sit, what they are called, where their functions start, which of
    // their addresses have names, and their on-disk images.
    //
    // One sorted table answers every lookup by binary search, and it is rebuilt
    // only when the engine's module list changes. The shape this replaced asked
    // the engine's unsorted list a fresh linear question each time -- including
    // from the "a name was applied" handler, which runs about 14,000 times when
    // a PDB loads.
    //
    // The table carries each module's display name and segment identifier,
    // computed once when it is built. Both are derived from a path recorded on
    // another machine, so deriving them per query meant a UTF-8 conversion and
    // a string rewrite on paths that never change.
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
        // and the position at which the trace saw it mapped. That last field is
        // what makes reading a module's own headers or export table possible --
        // they can only be read at a position where the module exists.
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
        void bind(TTD::Replay::IReplayEngine *engine, bool is64, const char *target_name);
        void reset();

        // ---- lookups -------------------------------------------------------
        const std::vector<Span> &spans() const;
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

        // True if 'ea' is inside a loaded module other than the analysed binary
        // (module 0) -- that is, library or system code.
        bool is_library_address(ea_t ea) const;

        // [start, end) of the function containing 'pc', from the exception
        // table of its module. This is the authority on where a function in a
        // system DLL begins, with or without symbols -- x64 unwinding requires
        // the table, so every module carries one. False for x86 modules, for a
        // module whose table has not been read, and for addresses outside any
        // recorded function. Populated as a side effect of resolve_symbols().
        bool function_range_at(ea_t pc, ea_t &start, ea_t &end) const;

        // Resolve a name pattern to the set of matching function addresses.
        // Shell-style wildcards (* and ?), case-insensitive, with an optional
        // "module!" qualifier, e.g. "kernel32!Virtual*" or "*Alloc".
        std::vector<ea_t> resolve_function_pattern(const char *pattern) const;

        // ---- naming --------------------------------------------------------
        //
        // Apply offline export-symbol names for the module loaded at 'base',
        // reading its PE at the module's recorded load position, and record its
        // function bounds. Deduplicated: a base is only attempted once per
        // trace.
        void resolve_symbols(ea_t base);
        // The same for every module loaded at 'cursor''s position.
        void resolve_loaded(TTD::Replay::ICursorView *cursor);
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

        // The engine's own record for the module based at 'base', or null.
        const TTD::Replay::Module *record_at(ea_t base) const;

    private:
        // Which PDB the module at 'base' was built with, read from the
        // recording rather than from whatever file sits at that path here.
        bool pdb_identity(ea_t base, GuestPdbInfo *out);
        // Hand one already-downloaded PDB to IDA, and say so when it fails.
        void apply_pdb(ea_t base, const std::string &path, const GuestPdbInfo &pdb);
        void report_missing_pdb(const std::string &path, const GuestPdbInfo &pdb);

        TTD::Replay::IReplayEngine *m_engine = nullptr;
        bool                        m_is64 = false;
        qstring                     m_targetName;

        // Cache backing spans(); mutable so the const lookups can refresh it
        // lazily. m_spanCount is the module count it was built from, and
        // m_spanEngine the engine it was built from -- two traces can have the
        // same module count, so the count alone cannot detect a stale cache
        // even though bind() also clears it.
        mutable std::vector<Span> m_spans;
        mutable size_t            m_spanCount  = (size_t)-1;
        mutable const void       *m_spanEngine = nullptr;

        std::set<ea_t> m_resolvedBases;   // modules whose exports we have named
        std::set<ea_t> m_pdbBases;        // modules whose PDB we have requested

        // Per-module function bounds from the PE exception table (.pdata),
        // keyed by module base; each vector is sorted by start address.
        std::map<ea_t, std::vector<std::pair<ea_t, ea_t>>> m_funcRanges;

        // Per-module on-disk image cache, keyed by module base. An entry with
        // ok == false means the file was already tried and rejected.
        std::map<ea_t, ModuleImage> m_moduleImages;

        // Scratch cursor for symbol reads, parked at a module's load position.
        TTD::Replay::UniqueCursor m_symCursor;
    };
}
