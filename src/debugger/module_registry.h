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
    // The unit is one load: an entry of the backend's module list, which
    // holds a module once per time it was mapped. A recording can unload a
    // DLL and map another at the same base, so "the module at this address"
    // depends on the position, and every lookup that names a module answers
    // for a load: the one mapped at the address at a given position, or, for
    // the lookups that take none, at the playhead's (set_now), else the first
    // load whose span holds the address. What is read out of an image
    // (exports, function bounds, the file on disk) is kept per image, keyed
    // by its identity (path, size, timestamp and checksum) and held as RVAs,
    // so two loads of one file share it at whatever bases they had, and two
    // files that took turns at one base do not.
    //
    // The spans, one per base over every load there, are what does not vary
    // with the position: the segment layout and "is this address in any
    // module" use them, since IDA rebuilds its debugger segments whenever
    // their layout changes.
    //
    // Backend-neutral: modules come from ITraceBackend::modules(); names from
    // the backend's recorded exports, else the image's export directory read
    // through a scratch cursor; function bounds from the backend, the file on
    // disk, or the recorded .pdata, in that order.
    class ModuleRegistry
    {
    public:
        // Every load at one base, as one range.
        struct Span
        {
            ea_t    base = 0;
            ea_t    end  = 0;         // the furthest any load there reaches
            // "kernel32.dll": the first load's file name as recorded, without
            // its directory.
            qstring file;
            // "kernel32": the same without the extension, the way a debugger
            // writes a qualified symbol.
            qstring name;
            // "kernel32_dll": the file name made a legal IDA name, for the
            // module's segment.
            qstring ident;
            // The loads at this base, as indices into the module list, in
            // the backend's order.
            std::vector<size_t> loads;
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

        static const size_t NONE = (size_t)-1;

        // ---- session lifetime ----------------------------------------------
        //
        // 'target_name' is the analysed binary's file name; no PDB is fetched
        // for it, since IDA already owns that file.
        void bind(ITraceBackend *backend, bool is64, const char *target_name);
        void reset();
        // The position the lookups without one answer for: the playhead's,
        // which TraceManager sets once each movement has ended (never during
        // one, so a lookup from a message pump sees what IDA shows).
        void set_now(Position p) { m_now = p; }

        // ---- the spans (position-independent) -----------------------------
        const std::vector<Span> &spans() const { return m_spans; }
        // Index into spans() of the innermost span containing 'ea' (the one
        // with the greatest base: a span can lie inside an earlier, larger
        // one), or NONE.
        size_t  index_at(ea_t ea) const;
        // The span containing 'ea', as [lo, hi). False when 'ea' belongs to
        // no module at any position (dynamically allocated code).
        bool    range_at(ea_t ea, ea_t &lo, ea_t &hi) const;
        qstring ident_at(ea_t ea) const;
        // Every span as [lo, hi), sorted by base.
        std::vector<std::pair<ea_t, ea_t>> ranges() const;

        // ---- loads ---------------------------------------------------------
        //
        // Every module load in the trace, in load order. A module loaded twice
        // at one address appears twice on purpose: each load has its own read
        // position.
        std::vector<Load> loads() const;
        // The load mapped at 'ea' at 'pos' (the innermost, if loads nest), as
        // an index into the module list, or NONE.
        size_t  load_index_at(ea_t ea, Position pos) const;
        const ModuleInfo *load_at(ea_t ea, Position pos) const;
        // The modules mapped at 'pos', as their records.
        std::vector<const ModuleInfo *> loaded_at(Position pos) const;
        // The load based at 'base' mapped at the playhead, else the first load
        // there, or null.
        const ModuleInfo *record_at(ea_t base) const;
        // The analysed binary's record, or null.
        const ModuleInfo *main_module() const;

        // The display name ("kernel32") of the module at 'ea'.
        qstring name_at(ea_t ea) const { return name_at(ea, m_now); }
        qstring name_at(ea_t ea, Position pos) const;

        // True if 'ea' is in a module other than the analysed binary (library
        // or system code).
        bool is_library_address(ea_t ea) const;

        // [start, end) of the function containing 'pc', from its module's
        // exception table, worked out on first use. False outside any
        // recorded function.
        bool function_range_at(ea_t pc, ea_t &start, ea_t &end) const
        { return function_range_at(pc, m_now, start, end); }
        bool function_range_at(ea_t pc, Position pos, ea_t &start, ea_t &end) const;
        // True if 'ea' is in a module whose exception table was read (from
        // the file or recorded memory). Code there outside every range is a
        // leaf function, which x64 gives no entry, not unpacked code.
        bool has_function_table(ea_t ea) const;
        // When no range covers 'pc' and its module's table was read from
        // recorded memory, read the table again as it stands at 'now': a
        // packer writes the real one when it unpacks, after the module
        // loaded. True when the ranges changed. A system module is never
        // packed, and a table whose bytes have not changed since the last
        // read is not parsed again, so a leaf function costs a few small
        // reads, not the whole table, per stop.
        bool refresh_function_ranges(ea_t pc, ITraceCursor *now);
        // "kernel32!SleepStub" for an export at 'ea', or empty: a name for a
        // listing when IDA has none yet (the module is not mapped where the
        // user is).
        qstring export_name_at(ea_t ea) { return export_name_at(ea, m_now); }
        qstring export_name_at(ea_t ea, Position pos);

        // Resolve a name pattern to the set of matching function addresses.
        // Shell-style wildcards (* and ?), case-insensitive, with an optional
        // "module!" qualifier, e.g. "kernel32!Virtual*" or "*Alloc".
        std::vector<ea_t> resolve_function_pattern(const char *pattern) const;

        // ---- naming --------------------------------------------------------
        //
        // Apply export names for the module at 'base' (the load there at the
        // playhead) and record its function bounds. Done once per base, and
        // only once the module has a segment; again when a different image
        // has taken the base since, after the old one's names are removed.
        void resolve_symbols(ea_t base);
        // The same for every module mapped at 'pos'.
        void resolve_loaded(Position pos);
        // Name the functions of the module at 'base' from its PDB without
        // blocking: the PDB the recorded image names is downloaded on a worker
        // (common/symsrv.h), its publics read on another
        // (common/pdb_publics.h), and the names set a slice at a time by
        // advance_pdbs(). Once per base (and again when another image takes
        // it). 'stopped_here': the user is stopped in this module, so it gets
        // its PDB even without cheap reads.
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
        // build than the recording's. Each load is judged by its own image,
        // so a DLL that later takes the same base gets its own file. On
        // success 'base_out' is the module's runtime base (rva = ea - base).
        const ModuleImage *image_for(ea_t ea, Position pos, ea_t &base_out);

    private:
        // What is read out of one image, shared by every load of it. Offsets
        // are from the load's base (RVAs), so a lookup adds the base of the
        // load it answers for.
        struct Image
        {
            // Its named exports, sorted by RVA (stable, so aliases keep their
            // recorded order).
            bool exports_read = false;
            std::vector<std::pair<ea_t, std::string>> exports;
            // Function bounds, sorted by start.
            bool funcs_tried = false;
            bool funcs_from_memory = false;   // ... read from recorded memory
            std::vector<std::pair<ea_t, ea_t>> funcs;
            // A fingerprint of the in-memory table as last parsed, so a miss
            // re-reads it only once its bytes change.
            uint64_t table_stamp = 0;
            // Under the Windows directory: never packed, so its table is
            // never re-read.
            bool system = false;
            // The file on disk: loaded once, ok == false when it was
            // unavailable or a different build.
            bool        file_tried = false;
            ModuleImage file;
        };
        // Per entry of m_modules.
        struct LoadNames
        {
            qstring file, name;          // as Span::file and Span::name
            Image  *image = nullptr;     // once identified (image_of)
            uint32_t timestamp = 0, checksum = 0;   // as identified
        };

        size_t  load_for(ea_t ea, Position pos) const;
        bool    live(size_t li, ea_t ea, Position pos) const;
        bool    is_main_load(size_t li) const;
        size_t  record_index(ea_t base) const;
        // The image load 'li' is of, worked out (and its exports and bounds
        // looked up) on first use.
        Image  &image_of(size_t li);
        const std::vector<std::pair<ea_t, std::string>> &exports_of(size_t li);
        void    function_ranges(size_t li);
        void    resolve_load(size_t li);
        void    unname_exports(ea_t base, const Image &img);
        // Guest memory of one load, at its own load position.
        GuestRead read_at_record(size_t li);
        GuestRead read_at_load(ea_t base) { return read_at_record(record_index(base)); }
        bool pdb_identity(ea_t base, GuestPdbInfo *out);
        void apply_pdb(ea_t base, const std::string &path, const GuestPdbInfo &pdb);
        void keep_names_only(ea_t base);
        void report_missing_pdb(const std::string &path, const GuestPdbInfo &pdb);
        void start_publics(ea_t base, const std::string &pdb_path);
        bool apply_publics_slice(DWORD deadline, size_t &named);

        ITraceBackend *m_backend = nullptr;
        bool           m_is64 = false;
        qstring        m_targetName;
        Position       m_now = Position::none();

        std::vector<ModuleInfo> m_modules;   // per load, as the backend gives them
        std::vector<LoadNames>  m_names;     // per load
        std::vector<Span>       m_spans;     // unique by base, sorted
        // m_spanReach[i]: the furthest end of spans[0..i], so a lookup can
        // tell when no earlier span reaches an address.
        std::vector<ea_t>       m_spanReach;
        size_t                  m_mainLoad = NONE;

        // By image identity. std::map: entries never move, so the per-load
        // pointers into it stay valid.
        mutable std::map<qstring, Image> m_images;

        // Which image named each base (resolve_symbols), so another image
        // taking the base is named again.
        std::map<ea_t, const Image *> m_namedBy;
        std::set<ea_t> m_pdbBases;        // modules whose PDB has been requested
        std::set<ea_t> m_pdbRetried;      // ... and asked for again after a failed download

        // The load image_for matched last: consecutive reads are nearly
        // always in the same module at the same position.
        size_t    m_lastImageLoad = NONE;

        // Scratch cursor for reading a module's headers at its load position,
        // and where it stands.
        CursorPtr m_symCursor;
        Position  m_symAt = Position::none();

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
