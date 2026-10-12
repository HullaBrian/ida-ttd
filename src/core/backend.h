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
        // The recording says where memory was mapped, unmapped and
        // reprotected, with the protection, so the memory map does not have to
        // be reconstructed from syscalls. Knowing only *that* a range changed
        // (which is what Sogen records today) does not qualify.
        bool mapping_changes  = false;
        // Dispatched syscalls are recorded: which, where, and what they
        // returned. (Not necessarily their arguments -- Sogen records the
        // result and the host writes, not the registers going in.)
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
        // Exceptions the system dispatched can be listed (query_exceptions).
        bool exceptions       = false;
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
        // IMAGE_FILE_MACHINE_*: 0x8664, or 0x14c for 32-bit code in a WoW64
        // process. 0 when the recording does not say; read the PE header.
        uint16_t machine = 0;
        // The image's TimeDateStamp and CheckSum as the recording saw them,
        // which is how a file on this machine is told apart from a different
        // build of the same DLL. 0 when the backend does not say; the core
        // then reads them from the recorded headers.
        uint32_t timestamp = 0;
        uint32_t checksum  = 0;
    };

    struct ThreadInfo
    {
        uint32_t tid = 0;
        Position created, exited;
        qstring  name;            // empty when the recording does not say
        // 0 when the recording does not say. Bounds at creation; a fiber
        // switch rewrites them in the TEB. See ittd_thread.
        ea_t     teb = 0, teb32 = 0;
        ea_t     stack_base = 0, stack_limit = 0;
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

    // One entry into a function. See ittd_call for why there are three
    // positions: who called, the arguments, and the return value are each read
    // at a different one.
    struct CallEvent
    {
        Position pos;               // at the call; none() if the thread began in the callee
        Position entry_pos;         // at the callee's first instruction
        Position ret_pos;           // just after the return; none() if unseen
        uint32_t tid    = 0;
        ea_t     site   = BADADDR;  // the call instruction
        ea_t     target = BADADDR;  // where it actually went
        bool     is_call = true;    // false: reached by a jump, so no return of its own
    };

    // One target an indirect branch reached.
    struct IndirectTarget
    {
        ea_t     target = BADADDR;
        uint64_t hits   = 0;
        Position first;             // the first time; none() if the backend does not know
        bool     is_call = true;    // false for an indirect jump
    };

    // An exception the system dispatched. See ittd_exception for which ones
    // that leaves out.
    struct ExceptionEvent
    {
        Position pos;               // the dispatch
        Position raise_pos;         // the instruction that raised it; none() if unknown
        uint32_t tid     = 0;
        uint32_t code    = 0;
        uint32_t flags   = 0;
        ea_t     address = BADADDR;
        uint64_t information[2] = {};
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

        // The registers of another thread at this position, for IDA's thread
        // list. False when the backend can only show the current thread's.
        virtual bool     read_thread_registers(uint32_t tid, ittd_regs *out) const
        {
            qnotused(tid); qnotused(out);
            return false;
        }

        // Bytes as the recording has them at this position.
        //
        // 'known' is resized to 'size' and marks each byte ITTD_KNOWN_*: the
        // recording's value, a placeholder zero (mapped, value unknown), or
        // nothing. Unknown bytes are left as the caller found them: the core
        // fills those -- and placeholders -- from the module's on-disk image
        // where there is one, which is backend-independent and therefore not a
        // backend's job.
        //
        // Returns the number of bytes marked known or placeholder.
        virtual size_t   read_memory(ea_t ea, void *buf, size_t size,
                                     std::vector<uint8_t> *known) = 0;

        // The threads alive at this position.
        virtual std::vector<ThreadInfo> live_threads() const = 0;

        // Rebuild [lo, hi) as of this position from the recording's own
        // writes, for memory the position query cannot answer (an unpacker's
        // output before it runs), and serve it from then on. With 'replace',
        // anything rebuilt for the range before is thrown away first (a
        // re-read); without, a range already rebuilt is reused (the per-stop
        // path). Returns the bytes recovered in the range. A backend whose
        // reads are already complete has nothing to do: 0.
        virtual size_t   rebuild_range(ea_t lo, ea_t hi, bool replace)
        {
            qnotused(lo); qnotused(hi); qnotused(replace);
            return 0;
        }
    };

    // One breakpoint: an execution of 'addr', or an access of the kinds in
    // 'kinds' (AccessKind) to any byte of [addr, addr + size).
    struct Breakpoint
    {
        ea_t     addr  = BADADDR;
        uint64_t size  = 1;
        uint8_t  kinds = ACCESS_EXEC;
        bool operator==(const Breakpoint &o) const
        { return addr == o.addr && size == o.size && kinds == o.kinds; }
        bool operator<(const Breakpoint &o) const
        {
            if ( addr != o.addr ) return addr < o.addr;
            if ( size != o.size ) return size < o.size;
            return kinds < o.kinds;
        }
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

        // Breakpoints, as the whole set rather than one at a time: both
        // backends key them by address and replacing the set is cheaper and
        // harder to get wrong than reconciling adds and deletes. A data
        // breakpoint stops at the instruction that made the access.
        //
        // 'accepted', when given, gets one entry per breakpoint: false for one
        // the engine refused, so IDA can show it as bad instead of as a
        // breakpoint that silently never fires.
        virtual bool set_breakpoints(const std::vector<Breakpoint> &bpts,
                                     std::vector<bool> *accepted = nullptr) = 0;

        // Something the last movement wants the user told once the stop is
        // shown ("this frame does not return anywhere"), or empty. Taking it
        // clears it.
        virtual qstring take_notice() { return qstring(); }

        // Where a long movement reports and asks whether to stop: the core
        // sets one around every movement and clears it after. Movements run
        // on the main thread, so a sink's cancelled() may pump IDA's message
        // loop. Null means no one is asking.
        virtual void set_progress(ProgressSink *progress) { qnotused(progress); }
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
        // become fast or its reads complete -- building Microsoft's memory
        // index, filling Sogen's keyframes. Nothing to do returns true
        // immediately. Called on the main thread after open(): the debugger
        // runs it when a session starts, the loader asks the user first.
        //
        // 'progress' may be null; a backend whose preparation cannot be
        // interrupted may show IDA's wait box itself.
        virtual bool prepare(ProgressSink *progress) { qnotused(progress); return true; }
        // Whether prepare() has nothing left to do for the open recording.
        virtual bool prepared() const { return true; }

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
        // Appends to 'out' in ascending order, each address once: a vector
        // rather than a set, because a module's worth is millions of entries.
        virtual QueryResult query_executed(const std::vector<std::pair<ea_t, ea_t>> &ranges,
                                           std::vector<ea_t> *out,
                                           ProgressSink *progress) = 0;

        // Every call, within 'when', whose target is one of 'targets' (empty
        // means every call). Requires capabilities().call_queries.
        virtual QueryResult query_calls(const std::vector<ea_t> &targets,
                                        PositionRange when,
                                        std::vector<CallEvent> *out,
                                        ProgressSink *progress) = 0;

        // Every indirect call made from inside 'ranges', with where it went,
        // and every indirect jump too when 'jumps' is set. Separate from
        // query_calls because the question is about call *sites* and the
        // answer is grouped by site, not by invocation.
        virtual QueryResult query_indirect_targets(
                const std::vector<std::pair<ea_t, ea_t>> &ranges,
                bool jumps,
                std::map<ea_t, std::vector<IndirectTarget>> *out,
                ProgressSink *progress) = 0;

        // Every exception the system dispatched, in order. Requires
        // capabilities().exceptions.
        virtual QueryResult query_exceptions(std::vector<ExceptionEvent> *out,
                                             ProgressSink *progress) = 0;

        // Every mapping change the recording holds, as the ABI's own structs
        // (ittd_mapping_change carries Windows' MEM_* and PAGE_* values, which
        // the memory map wants as they are), and the mapped-file names their
        // 'file' fields index, one-based. Requires capabilities().
        // mapping_changes; a backend without it answers not-ran.
        virtual QueryResult query_mapping_changes(std::vector<ittd_mapping_change> *out,
                                                  std::vector<qstring> *files,
                                                  ProgressSink *progress)
        {
            qnotused(out); qnotused(files); qnotused(progress);
            return QueryResult{};
        }

        // The instructions executed within 'when', in order, on thread 'tid'
        // (0: every thread): at most 'max' of them, as ACCESS_EXEC accesses
        // whose pc is the instruction. 'truncated' says the range held more.
        // What lays out runtime-only code and finds where a function began, so
        // callers keep 'when' short.
        virtual QueryResult query_instructions(PositionRange when, uint32_t tid, size_t max,
                                               std::vector<Access> *out, ProgressSink *progress)
        {
            qnotused(when); qnotused(tid); qnotused(max); qnotused(out); qnotused(progress);
            return QueryResult{};
        }

        // A position about 'delta' instructions from 'p', without seeking;
        // see ittd_backend_api::position_add. The default does not move.
        virtual Position position_add(Position p, int64_t delta) const
        {
            qnotused(delta);
            return p;
        }

        // The call that entered thread 'tid''s frame at 'at', searching back at
        // most about 'max_back' instructions: its position and the function
        // entry it went to. False when not found within the bound.
        virtual bool query_frame_entry(Position at, uint32_t tid, uint64_t max_back,
                                       Position *call_pos, ea_t *entry)
        {
            qnotused(at); qnotused(tid); qnotused(max_back); qnotused(call_pos); qnotused(entry);
            return false;
        }

        // The registers at each of 'positions', in the same order; an entry
        // whose 'have' is 0 could not be reconstructed. A batch because
        // neighbouring positions share work -- see ittd_backend_api::regs_at.
        // The default seeks a scratch cursor per position, which is what a
        // backend without a cheaper route would do anyway.
        virtual QueryResult registers_at(const std::vector<Position> &positions,
                                         std::vector<ittd_regs> *out,
                                         ProgressSink *progress)
        {
            QueryResult r;
            r.ran = true;
            out->assign(positions.size(), ittd_regs{});
            CursorPtr cursor = make_cursor();
            if ( cursor == nullptr )
                return r;
            for ( size_t i = 0; i < positions.size(); ++i )
            {
                if ( progress != nullptr )
                {
                    if ( progress->cancelled() )
                    {
                        r.cancelled = true;
                        break;
                    }
                    progress->report(uint32_t(i * 100 / positions.size()));
                }
                if ( cursor->seek(positions[i]) && !cursor->read_registers(&(*out)[i]) )
                    (*out)[i].have = 0;
            }
            return r;
        }

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
