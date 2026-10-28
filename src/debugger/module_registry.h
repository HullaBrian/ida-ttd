#pragma once

#include "common/pch.h"
#include "common/symbols.h"
#include "common/pdb_publics.h"
#include "core/backend.h"

#include <future>

namespace idattd
{
    // Everything the plugin knows about the modules a recording loaded: where
    // they sit, what they are called, where their functions start, which of
    // their addresses have names, and their on-disk images.
    //
    // One sorted table, built once at bind (a recording's module list does
    // not change), answers every lookup by binary search. It carries each
    // module's display name and segment identifier, computed once rather than
    // per query.
    //
    // Backend-neutral: modules come from ITraceBackend::modules(); names from
    // the backend's recorded exports, else the image's export directory read
    // through a scratch cursor; function bounds from the backend, the file on
    // disk, or the recorded .pdata, in that order.
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
            // "kernel32_dll": the file name made a legal IDA name, for the
            // module's segment.
            qstring ident;
            bool operator<(const Span &o) const { return base < o.base; }
        };

        // One load of one module: base, size, base name, and the position at
        // which it was mapped, where its headers and exports can be read.
        struct Load
        {
            ea_t     base = BADADDR;
            uint64_t size = 0;
            qstring  name;        // base name, as recorded
            Position pos;         // where it was loaded
        };

        // ---- session lifetime ----------------------------------------------
        //
        // 'target_name' is the analysed binary's file name; no PDB is fetched
        // for it, since IDA already owns that file.
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
        // at one address appears twice on purpose: each load has its own read
        // position.
        std::vector<Load> loads() const;
        // The modules mapped at 'pos', as their records.
        std::vector<const ModuleInfo *> loaded_at(Position pos) const;
        // The record for the module based at 'base' (its first load), or null.
        const ModuleInfo *record_at(ea_t base) const;
        // The analysed binary's record, or null.
        const ModuleInfo *main_module() const;

        // True if 'ea' is in a module other than the analysed binary (library
        // or system code).
        bool is_library_address(ea_t ea) const;

        // [start, end) of the function containing 'pc', from its module's
        // exception table, worked out on first use. False outside any
        // recorded function.
        bool function_range_at(ea_t pc, ea_t &start, ea_t &end) const;
        // True if 'ea' is in a module whose exception table was read (from
        // the file or recorded memory). Code there outside every range is a
        // leaf function, which x64 gives no entry, not unpacked code.
        bool has_function_table(ea_t ea) const;
        // When no range covers 'pc' and its module's table was read from
        // recorded memory, read the table again as it stands at 'now': a
        // packer writes the real one when it unpacks, after the module
        // loaded. True when the ranges changed.
        bool refresh_function_ranges(ea_t pc, ITraceCursor *now);
        // "kernel32!SleepStub" for an export at 'ea', or empty: a name for a
        // listing when IDA has none yet (the module is not mapped where the
        // user is).
        qstring export_name_at(ea_t ea);

        // Resolve a name pattern to the set of matching function addresses.
        // Shell-style wildcards (* and ?), case-insensitive, with an optional
        // "module!" qualifier, e.g. "kernel32!Virtual*" or "*Alloc".
        std::vector<ea_t> resolve_function_pattern(const char *pattern) const;

        // ---- naming --------------------------------------------------------
        //
        // Apply export names for the module at 'base' and record its function
        // bounds. Done once per base, and only once the module has a segment.
        void resolve_symbols(ea_t base);
        // The same for every module mapped at 'pos'.
        void resolve_loaded(Position pos);
        // Name the functions of the module at 'base' from its PDB without
        // blocking: the PDB the recorded image names is downloaded on a worker
        // (common/symsrv.h), its publics read on another
        // (common/pdb_publics.h), and the names set a slice at a time by
        // advance_pdbs(). Once per module. 'stopped_here': the user is stopped
        // in this module, so it gets its PDB even without cheap reads.
        void load_pdb(ea_t base, bool stopped_here = false);
        // Start reading finished downloads and set names from read PDBs, for
        // at most 'budget_ms'. Returns how many names were set. Main thread
        // only, while the replay is paused.
        size_t advance_pdbs(int budget_ms);
        // Downloads, reads or names still to set: advance_pdbs() has work.
        bool pdbs_pending() const;
        // The whole PDB (types and prototypes as well as names) of the module
        // containing 'ea', through IDA's PDB plugin. Blocks behind a wait box
        // for as long as the plugin takes, so only on the user's request.
        // False, with the reason in the output window, when it cannot be done
        // (yet).
        bool load_full_pdb(ea_t ea);

        // ---- on-disk images ------------------------------------------------
        //
        // The image of the module mapped at 'ea' at position 'pos', loaded and
        // cached on first use, to serve bytes the recording never captured.
        // Null when no module is mapped there at 'pos' (before its load,
        // after its unload), the file is unavailable, or it is a different
        // build than the recording's. Each load is judged on its own, so a
        // DLL that later takes the same base gets its own file. On success
        // 'base_out' is the module's runtime base (rva = ea - base).
        const ModuleImage *image_for(ea_t ea, Position pos, ea_t &base_out);

    private:
        // Guest memory of the module at 'base', where it is known to be mapped.
        GuestRead read_at_load(ea_t base);
        // The same for one particular load, at its own load position.
        GuestRead read_at_record(const ModuleInfo *m);
        bool pdb_identity(ea_t base, GuestPdbInfo *out);
        void apply_pdb(ea_t base, const std::string &path, const GuestPdbInfo &pdb);
        void keep_names_only(ea_t base);
        size_t function_ranges(ea_t base);
        // The named exports of the module at 'base', read once.
        const std::vector<std::pair<ea_t, std::string>> &exports_of(ea_t base);
        void report_missing_pdb(const std::string &path, const GuestPdbInfo &pdb);
        void start_publics(ea_t base, const std::string &pdb_path);
        bool apply_publics_slice(DWORD deadline, size_t &named);

        ITraceBackend *m_backend = nullptr;
        bool           m_is64 = false;
        qstring        m_targetName;

        std::vector<ModuleInfo> m_modules;   // per load, as the backend gives them
        std::vector<Span>       m_spans;     // unique by base, sorted
        ea_t                    m_mainBase = BADADDR;

        std::set<ea_t> m_resolvedBases;   // modules whose exports have been named
        std::set<ea_t> m_pdbBases;        // modules whose PDB has been requested
        std::set<ea_t> m_pdbRetried;      // ... and asked for again after a failed download

        // Per-module function bounds, keyed by module base; each vector is
        // sorted by start address.
        std::map<ea_t, std::vector<std::pair<ea_t, ea_t>>> m_funcRanges;
        std::set<ea_t> m_funcTried;     // function_ranges() ran for these
        std::set<ea_t> m_funcFromMemory;  // ... and read the table from recorded memory
        // Per-module named exports, keyed by module base; each vector is
        // sorted by address (stable, so aliases keep their recorded order).
        std::map<ea_t, std::vector<std::pair<ea_t, std::string>>> m_exports;

        // On-disk image cache, keyed by the load's identity (path, base,
        // size, timestamp, checksum), so two loads of one file share it and
        // another file at the same base does not. ok == false: the file was
        // tried and rejected. std::map: entries never move, so the per-load
        // pointers below stay valid.
        std::map<qstring, ModuleImage> m_moduleImages;
        // Per entry of m_modules: its image once looked up (null when none
        // or not looked up yet; m_loadImageTried says which).
        std::vector<const ModuleImage *> m_loadImage;
        std::vector<uint8_t>             m_loadImageTried;
        // The m_modules entry image_for matched last: consecutive reads are
        // nearly always in the same module at the same position.
        size_t                           m_lastImageLoad = (size_t)-1;

        // Scratch cursor for reading a module's headers at its load position.
        CursorPtr m_symCursor;

        // A PDB whose publics are being read, or set as names a slice at a
        // time.
        struct PublicsJob
        {
            ea_t                    base = BADADDR;
            std::string             pdb_name;
            std::future<bool>       reading;    // valid while the worker runs
            std::vector<PdbPublic>  pubs;       // written by the worker only
            std::string             error;      // likewise
            size_t                  next  = 0;  // first public not yet named
            size_t                  named = 0;
        };
        // unique_ptr: the worker writes into the job, so it must not move.
        std::vector<std::unique_ptr<PublicsJob>> m_publics;
    };
}
