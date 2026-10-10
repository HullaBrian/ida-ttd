#pragma once

#include "common/pch.h"
#include "core/position.h"
#include "abi/ida_ttd_backend.h"

// What the core plugin needs from a recording, and nothing about how any one
// kind of recording provides it. See docs/modular-backends.md.
//
// Why the whole-trace work is expressed as queries rather than as "install a
// watchpoint and replay": Microsoft TTD answers "every access to this range"
// by replaying the recording with a watchpoint armed, and Sogen answers it by
// reading a page index. An interface written in terms of watchpoints and
// replays would make Sogen pretend to replay; one written in terms of
// questions lets each backend answer the way it can.
//
// ---------------------------------------------------------------------------
// This is the CORE-SIDE view, in C++ and free to use IDA types. It is not the
// boundary a backend module sees.
//
// A backend is a separate DLL, so the actual boundary is the flat C ABI in
// abi/ida_ttd_backend.h: no C++ types, no IDA types, caller-provided buffers.
// BackendModule adapts a loaded module to the interface below, and a backend
// compiled into the core (if any ever is) implements the interface directly.
//
// The two are kept deliberately close in shape, so the adapter stays a
// translation and never grows logic of its own. Where this file uses an ABI
// type outright -- ittd_regs below -- that is on purpose: a third
// representation of the same registers would only be translated twice.
// ---------------------------------------------------------------------------

namespace idattd
{
    // ---------------------------------------------------------------- queries
    //
    // What a backend can be asked. The core checks these before offering a
    // command, so a backend is never asked a question it cannot answer and
    // the user is never shown an action that would only apologise.
    //
    // The same set as the ITTD_CAP_* bits, as named booleans: core code reads
    // these far more often than the adapter translates them.
    struct Capabilities
    {
        // Accesses to an address range can be listed (memory search, coverage).
        bool access_queries   = false;
        // Calls and returns can be listed (the call tracer, indirect calls).
        bool call_queries     = false;
        // The recording says where memory was mapped and unmapped, so the
        // memory map does not have to be reconstructed from syscalls.
        bool mapping_changes  = false;
        // Dispatched syscalls are recorded with their arguments and results.
        bool syscalls         = false;
        // Module export tables come out of the recording, so the core does not
        // need to parse them out of guest memory.
        bool recorded_exports = false;
        // Seeking is cheap enough to do on every row of a listing. False means
        // the core should keep offering positions rather than values, and
        // should run prepare() if the backend offers one.
        bool cheap_seek       = false;
        // The recording can be stepped backwards instruction by instruction.
        // (Both backends can; a future one reading an ETW-style trace could
        // not, and the backward movement actions would then not be registered.)
        bool reverse_step     = true;
    };

    // ------------------------------------------------------------- the trace
    struct TraceInfo
    {
        bool     is64 = false;
        // Identity of this recording, so results cached in the database against
        // one are not shown against another. Stable across opens of the same
        // file; different for a re-recording of the same program.
        uint64_t fingerprint = 0;
        Position first, last;
        // Base name of the program that was recorded ("sample.exe").
        qstring  main_module;
        // What to call this backend in the UI ("Microsoft TTD", "Sogen").
        qstring  backend_name;
    };

    struct ModuleInfo
    {
        ea_t     base = BADADDR;
        uint64_t size = 0;
        qstring  name;            // base name, as recorded
        qstring  path;            // full path on the recording machine
        // Where the recording saw it mapped. For Microsoft TTD this is also the
        // only position at which the module's own headers can be read.
        Position loaded;
        Position unloaded;        // none() while still mapped at the end
    };

    struct ThreadInfo
    {
        uint32_t tid = 0;
        Position created, exited;
        qstring  name;            // empty when the recording does not say
    };

    // One thing worth putting on the timeline: a thread starting or exiting, a
    // module loading or unloading, an exception.
    struct TraceEvent
    {
        Position pos;
        qstring  what;
    };

    enum AccessKind : uint8_t
    {
        ACCESS_READ  = 1,
        ACCESS_WRITE = 2,
        ACCESS_EXEC  = 4,
    };

    struct Access
    {
        Position pos;
        uint32_t tid  = 0;
        ea_t     pc   = BADADDR;    // the instruction that did it
        ea_t     addr = BADADDR;    // the address it touched
        uint32_t size = 0;
        uint8_t  kind = 0;          // one ACCESS_* value
    };

    struct CallEvent
    {
        Position pos;               // the call
        Position ret_pos;           // the matching return; none() if unseen
        uint32_t tid    = 0;
        ea_t     site   = BADADDR;  // the call instruction
        ea_t     target = BADADDR;  // where it actually went
    };

    // Reported by a query that could not return everything it found.
    struct QueryResult
    {
        bool ran       = false;   // the query was attempted at all
        bool cancelled = false;   // the user stopped it part-way
        bool truncated = false;   // a record cap was hit; results are a prefix
    };

    // How a long query reports in and asks whether to stop. The core implements
    // this with a wait box; a backend only calls it, and must assume it may be
    // called from a worker thread -- so an implementation touches no IDA API
    // beyond what is thread-safe.
    //
    // A backend that answers from an index and never takes long simply ignores
    // the sink it is handed.
    class ProgressSink
    {
    public:
        virtual ~ProgressSink() = default;
        virtual void report(uint32_t percent) = 0;
        virtual bool cancelled() = 0;
    };

    // ------------------------------------------------------------- the cursor
    //
    // A movable viewpoint onto a recording. The core creates one for the
    // debugger's playhead and one per concurrent query, because a query must
    // not move the position the user is looking at.
    class ITraceCursor
    {
    public:
        virtual ~ITraceCursor() = default;

        virtual Position position() const = 0;
        // Move to 'p', resolving the begin()/end() sentinels. False when 'p' is
        // not a position this recording has.
        virtual bool     seek(Position p) = 0;

        virtual uint32_t thread_id() const = 0;
        virtual ea_t     program_counter() const = 0;
        virtual uint64_t stack_pointer() const = 0;
        // The canonical register set (abi/ida_ttd_backend.h). The core maps it
        // onto IDA's register array for the table configure_debugger()
        // installed.
        //
        // An earlier draft had the backend fill regval_t directly, which is
        // simpler but only works in-process: a backend DLL must not see IDA
        // types at all. Both engines have something close to ittd_regs already
        // -- Microsoft's CROSS_PLATFORM_CONTEXT, Sogen's save_registers blob --
        // so neither pays much to produce it.
        virtual bool     read_registers(ittd_regs *out) const = 0;

        // Bytes as the recording has them at this position.
        //
        // 'known' is resized to 'size' and marks the bytes the recording can
        // actually account for. The rest are left as the caller found them: the
        // core fills those from the module's on-disk image where there is one,
        // which is backend-independent and therefore not a backend's job.
        //
        // Returns the number of bytes marked known.
        virtual size_t   read_memory(ea_t ea, void *buf, size_t size,
                                     std::vector<uint8_t> *known) = 0;

        // The threads alive at this position.
        virtual std::vector<ThreadInfo> live_threads() const = 0;
    };

    using CursorPtr = std::unique_ptr<ITraceCursor>;

    // ---------------------------------------------------------- the navigator
    //
    // Stepping is a strategy, not a primitive. "Step over backwards" means
    // something quite different to a replay engine (rewind, then detect that we
    // landed in a callee that had just returned, then rewind out) than to an
    // indexed trace (read the previous execute event at this frame's depth).
    // Each backend implements the whole family, because each has a cheap route
    // the other does not.
    //
    // Every call moves the cursor the backend was created with, honours the
    // breakpoints set through set_breakpoints(), and says why it stopped.
    enum class StopReason
    {
        Stepped,        // the movement completed
        Breakpoint,     // a user breakpoint was hit on the way
        TraceBoundary,  // the start or end of the recording was reached
        Failed,
    };

    class INavigator
    {
    public:
        virtual ~INavigator() = default;

        virtual StopReason step(bool forward) = 0;
        virtual StopReason step_over(bool forward) = 0;
        virtual StopReason step_out(bool forward) = 0;
        virtual StopReason run(bool forward) = 0;
        virtual StopReason run_to(ea_t addr, bool forward) = 0;
        virtual StopReason seek_to(Position p) = 0;

        // Execute breakpoints, as the whole set rather than one at a time: both
        // backends key them by address and replacing the set is cheaper and
        // harder to get wrong than reconciling adds and deletes.
        virtual void set_breakpoints(const std::vector<ea_t> &addrs) = 0;
    };

    // ------------------------------------------------------------ the backend
    class ITraceBackend
    {
    public:
        virtual ~ITraceBackend() = default;

        // ---- identity, before anything is open -----------------------------
        //
        // Short id used in the database and when naming a module ("msttd",
        // "sogen"). It is written into the trace-link record, so changing one
        // orphans existing databases.
        virtual const char *id() const = 0;
        virtual const char *display_name() const = 0;
        // Does this backend handle the file at 'path'? Asked of every registered
        // backend, in registration order, by the loader and by the debugger when
        // a session starts. Must be cheap and must not open the recording: a
        // signature read is the most it should do.
        virtual bool can_open(const char *path) const = 0;
        // The File > Open filter fragment this backend contributes, e.g.
        // "Microsoft TTD trace (*.run)".
        virtual const char *file_filter() const = 0;

        // ---- the session ---------------------------------------------------
        virtual bool open(const char *path, qstring *errbuf) = 0;
        virtual void close() = 0;
        virtual bool is_open() const = 0;
        virtual const TraceInfo     &info() const = 0;
        virtual const Capabilities  &capabilities() const = 0;

        // Work the backend would like done once per recording before its seeks
        // become fast, with a progress bar -- building Microsoft's memory index,
        // filling Sogen's keyframes. Nothing to do returns true immediately. The
        // core offers it when a session starts, and does not insist.
        virtual bool prepare(ProgressSink *progress) { qnotused(progress); return true; }

        // ---- positions -----------------------------------------------------
        virtual qstring format_position(Position p) const = 0;
        virtual bool    parse_position(const char *text, Position *out) const = 0;
        // What to put next to the input box, e.g. "Sequence:Steps in hex".
        virtual const char *position_syntax() const = 0;

        // ---- reading -------------------------------------------------------
        virtual CursorPtr make_cursor() = 0;
        // A navigator over 'cursor', which it does not own and which must
        // outlive it.
        virtual std::unique_ptr<INavigator> make_navigator(ITraceCursor *cursor) = 0;

        // ---- enumeration ---------------------------------------------------
        virtual std::vector<ModuleInfo> modules() const = 0;
        virtual std::vector<ThreadInfo> threads() const = 0;
        virtual std::vector<TraceEvent> timeline() const = 0;

        // ---- whole-trace queries -------------------------------------------
        //
        // Each may take minutes on one backend and microseconds on another.
        // They report through 'progress' (which may be null) and stop when it
        // says to.

        // Every access to [lo, hi) within 'when' matching 'kinds'. Appends to
        // 'out'. Requires capabilities().access_queries.
        virtual QueryResult query_accesses(ea_t lo, ea_t hi, uint8_t kinds,
                                           PositionRange when,
                                           std::vector<Access> *out,
                                           ProgressSink *progress) = 0;

        // The distinct addresses inside 'ranges' that the recording executed.
        // A separate entry point from query_accesses because coverage wants a
        // set of addresses, not millions of individual events, and both
        // backends have a much cheaper way to produce one.
        virtual QueryResult query_executed(const std::vector<std::pair<ea_t, ea_t>> &ranges,
                                           std::set<ea_t> *out,
                                           ProgressSink *progress) = 0;

        // Every call, within 'when', whose target is one of 'targets' (empty
        // means every call). Requires capabilities().call_queries.
        virtual QueryResult query_calls(const std::vector<ea_t> &targets,
                                        PositionRange when,
                                        std::vector<CallEvent> *out,
                                        ProgressSink *progress) = 0;

        // Every indirect call made from inside 'ranges', with where it went.
        // Separate from query_calls because the question is about call *sites*
        // and the answer is grouped by site, not by invocation.
        virtual QueryResult query_indirect_targets(
                const std::vector<std::pair<ea_t, ea_t>> &ranges,
                std::map<ea_t, std::set<ea_t>> *out,
                ProgressSink *progress) = 0;

        // ---- symbols -------------------------------------------------------
        //
        // Named addresses the recording itself knows about. Microsoft TTD has
        // none and parses the export table out of guest memory to produce them;
        // Sogen records every module's export directory. Either way the core
        // gets a list and applies IDA names, so only one of the two has to deal
        // with PE parsing.
        struct Symbol { ea_t ea = BADADDR; qstring name; bool is_export = true; };
        virtual std::vector<Symbol> module_symbols(ea_t base) = 0;
        // [start, end) of every function in the module at 'base', from whatever
        // the backend has that knows: the PE exception table, or the recording's
        // own notion of a function. Empty when it has nothing.
        virtual std::vector<std::pair<ea_t, ea_t>> module_functions(ea_t base) = 0;
    };

    using BackendPtr = std::unique_ptr<ITraceBackend>;
}
