#pragma once

#include "common/pch.h"
#include "core/backend.h"

namespace idattd
{
    class ModuleRegistry;
    class MemoryReader;

    // The user's work on functions in memory no module covers (allocations,
    // mapped views, code the recording wrote and ran), kept across sessions.
    //
    // That memory is all debugger segments, which IDA deletes when a session
    // ends (and rebuilds mid-session when a travel changes the memory map),
    // taking every function, name, prototype and comment in them along. So
    // what the user set on such a function is copied into the database: its
    // bounds, name, prototype, comments and labels, and Hex-Rays' variable
    // names, types and comments and its pseudocode comments. When a function
    // starts there again, by the user (P) or the per-stop analysis, it all
    // comes back.
    //
    // Each copy carries a hash of the function's bytes, and comes back only
    // where the bytes match: an address can hold different code at different
    // positions (a region freed and reused, an unpacker's later stage), and
    // each version keeps its own work.
    class KeptFunctions
    {
    public:
        void bind(ModuleRegistry *modules, MemoryReader *memory);
        void reset();

        // Memory this keeps work for: a debugger segment outside every module.
        bool covers(ea_t ea) const;

        // Something the user can set changed at 'ea' (a name, a type, a
        // comment, a variable): its function is copied by capture_dirty().
        void note_changed(ea_t ea);
        // Copy the functions noted since the last call. Run before anything
        // can move the playhead: a movement can land where the bytes differ,
        // and the analysis then deletes the function with its work.
        void capture_dirty();
        // Copy every function in the memory covers() accepts. Run before IDA
        // deletes those segments: a layout change, the session's end, a save.
        void capture_all();

        // A function now starts at 'start'. What was kept for it is applied
        // by restore_pending(), outside the notification that said so. False
        // when 'start' is not in memory this keeps work for.
        bool note_added(ea_t start);
        bool has_pending() const { return !m_pending.empty(); }
        // Apply the kept work to the functions noted since the last call.
        // 'playhead' rebuilds never-executed bytes from recorded writes when
        // the bytes do not match at first. Returns the functions restored.
        size_t restore_pending(ITraceCursor *playhead);

        // No function covers 'pc': define the kept one that did, with its
        // bounds, if its bytes match here. Its start, or BADADDR.
        ea_t define_at(ITraceCursor *playhead, ea_t pc);

    private:
        // Copy the function starting at 'start'. One with nothing user-set
        // leaves an earlier copy alone: a half-deleted function seen during a
        // teardown must not erase a good copy.
        void capture(ea_t start);

        ModuleRegistry *m_modules = nullptr;
        MemoryReader   *m_memory  = nullptr;
        std::set<ea_t>  m_pending;
        std::set<ea_t>  m_dirty;
        // Versions whose bytes still differed after a rebuild, start ->
        // hashes, so a stop does not replay the rebuild again. For the session.
        std::map<ea_t, std::set<uint64_t>> m_rebuilt;
    };
}
