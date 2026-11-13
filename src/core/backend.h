#pragma once

#include "common/pch.h"
#include "core/position.h"
#include "abi/ida_ttd_backend.h"
#include <filesystem>

// What the core plugin needs from a recording, independent of how any one kind
// of recording provides it. See docs/modular-backends.md.
//
// Whole-trace work is expressed as queries rather than "install a watchpoint
// and replay": Microsoft TTD answers "every access to this range" by replaying
// with a watchpoint armed, Sogen by reading a page index. Questions let each
// backend answer the way it can.
//
// ---------------------------------------------------------------------------
// This is the CORE-SIDE view, in C++ and free to use IDA types. A backend DLL
// sees the flat C ABI in abi/ida_ttd_backend.h instead; BackendModule adapts a
// loaded module to this interface.
//
// The two are kept close in shape so the adapter stays a pure translation.
// Where this file uses an ABI type outright (ittd_regs), that is deliberate: a
// third representation of the registers would only be translated twice.
// ---------------------------------------------------------------------------

namespace idattd
{
    // ---------------------------------------------------------------- queries
    //
    // What a backend can be asked. The core checks these before offering a
    // command, so a backend is never asked a question it cannot answer.
    //
    // The ITTD_CAP_* bits as named booleans, which core code reads far more
    // often than the adapter translates them.
    struct Capabilities
    {
        // Accesses to an address range can be listed (memory search, coverage).
        bool access_queries   = false;
        // Calls and returns can be listed (the call tracer, indirect calls).
        bool call_queries     = false;
        // The recording says where memory was mapped, unmapped and
        // reprotected, with the protection, so the memory map need not be
        // reconstructed from syscalls. Knowing only *that* a range changed
        // (all a Sogen recording older than its memory-region section says)
        // does not qualify.
        bool mapping_changes  = false;
        // Dispatched syscalls are recorded: which, where, and what they
        // returned. Not necessarily their arguments: Sogen records the result
        // and the host writes, not the registers going in.
        bool syscalls         = false;
        // Module export tables come out of the recording, so the core does not
        // need to parse them out of guest memory.
        bool recorded_exports = false;
        // Seeking is cheap enough to do on every row of a listing. False: the
        // core offers positions rather than values, and runs prepare() if the
        // backend has one.
        bool cheap_seek       = false;
        // registers_at over many positions costs much less than a seek and a
        // register read at each (ITTD_CAP_BATCH_REGS), so a listing that
        // needs registers at thousands of positions asks for them up front.
        bool batch_regs       = false;
        // The recording can be stepped backwards instruction by instruction.
        // Both backends can; without it the backward actions are not
        // registered.
        bool reverse_step     = true;
        // Exceptions the system dispatched can be listed (query_exceptions).
        bool exceptions       = false;
        // Reading a page costs about a copy (ITTD_CAP_CHEAP_READS): IDA may
        // analyse whole library modules, reading all of their code.
        bool cheap_reads      = false;
        // Code the program wrote and then ran can be listed
        // (query_self_modifying).
        bool self_modifying   = false;
        // The recording can be forked into a new one (record_fork).
        bool fork             = false;
        // Strings and buffers can be recovered by replaying the recording
        // (query_strings, query_buffers).
        bool replay_scans     = false;
    };

    // ------------------------------------------------------------- the trace
    struct TraceInfo
    {
        bool     is64 = false;
        // Identity of this recording, so results cached in the database for
        // one are not shown for another. Stable across opens of the same file;
        // different for a re-recording of the same program.
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
        // Where the recording saw it mapped. For Microsoft TTD, also the only
        // position at which the module's headers can be read.
        Position loaded;
        Position unloaded;        // none() while still mapped at the end
        // IMAGE_FILE_MACHINE_*: 0x8664, or 0x14c for 32-bit code in a WoW64
        // process. 0 when the recording does not say; read the PE header.
        uint16_t machine = 0;
        // The image's TimeDateStamp and CheckSum as recorded, which tell a
        // file on this machine apart from another build of the same DLL. 0
        // when the backend does not say; the core then reads the headers.
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

    // A syscall the program made (ittd_syscall). Its arguments are the
    // registers at 'pos'.
    struct SyscallEvent
    {
        Position pos;               // at the syscall instruction
        uint64_t result = 0;        // rax after it
        uint32_t number = 0;
        uint32_t tid    = 0;        // 0 when unknown
        qstring  name;              // empty when unknown
    };

    // A syscall's out parameter (ittd_out_slot).
    struct OutSlot
    {
        Position call;
        ea_t     addr = 0;
        uint64_t before = 0;
        uint32_t tid = 0;
        uint32_t width = 8;
    };

    // One read of read_memory_at (ittd_mem_read).
    struct MemAt
    {
        Position pos;
        ea_t     addr = 0;
        size_t   offset = 0;        // into the caller's buffers
        size_t   size = 0;
    };

    // The accesses to one page in one slice of time (ittd_heat_cell).
    struct HeatCell
    {
        uint64_t page = 0;
        uint32_t slice = 0;
        uint32_t reads = 0, writes = 0, executes = 0;
    };

    // An instruction the program wrote before running it (ittd_selfmod).
    struct SelfModHit
    {
        ea_t     address     = BADADDR;
        uint64_t size        = 0;
        Position write_pos;         // at the writing instruction
        ea_t     write_ip    = BADADDR;
        Position execute_pos;       // its first execution
        uint64_t executions  = 0;
    };

    // How a recording is made (a fork's, or a new one), and what its program
    // may reach: ittd_fork_settings' ABI 3 fields.
    struct RecordOptions
    {
        // The real network (ITTD_NET_LIVE): past a fork's position, or from
        // a new recording's start. Otherwise a loopback-only one.
        bool     network = false;
        uint32_t access_mask = 0;           // ITTD_ACCESS_* kept; 0: all
        uint64_t checkpoint_interval = 0;   // 0: the backend's default
        bool     elevated = false;          // an administrator's token (new recordings)
        bool     log = false;               // the emulator's log to the output window
        // The emulator's last lines kept for a recording's wait box
        // (emulator_log_tail), with or without 'log'.
        bool     log_tail = false;
    };

    // What replaying the recording needs beyond the recording itself.
    struct ReplaySettings
    {
        qstring registry_dir;               // empty: the backend's default; host recordings only
        qstring emulation_root;             // empty: the recording's own
        bool    strict = false;
        // Replay a recording made against the host, whose program then touches
        // this machine's files again (ITTD_FORK_ALLOW_HOST).
        bool    allow_host = false;
        // Replay with hives that are not the recording's (ITTD_FORK_ANY_REGISTRY).
        bool    any_registry = false;
        // Only 'log' matters to a replay of the recording itself (the scans).
        RecordOptions rec;
    };

    // What replaying the recording needs, as far as it says (ittd_replay_env).
    struct ReplayEnv
    {
        bool    host = false;               // made against the host, not an emulation root
        bool    registry_known = false;     // names its hives, so they can be checked
        bool    registry_carried = false;   // carries what it read of them: no hive files needed
        uint32_t system_dlls = ITTD_DLLS_UNKNOWN;   // this machine's against the recording's (ITTD_DLLS_*)
        qstring registry_hint;              // the emulation root's registry folder; empty for the host
        qstring emulation_root;             // empty for the host
        qstring windows_version;            // "10.0.26100.1"; empty when not recorded
    };

    // Whether a folder holds the hives the recording was made with
    // (check_registry).
    enum class HiveCheck
    {
        Match,          // the recording's own hives
        Unverified,     // hives, and the recording does not say which
        Missing,        // no hives there
        Mismatch,       // other hives than the recording's
    };

    // A string the program had in memory (ittd_string_hit).
    struct StringHit
    {
        ea_t     address = BADADDR;
        Position pos;                       // the write that completed it
        bool     wide    = false;           // UTF-16LE in memory
        uint32_t length  = 0;               // characters
        qstring  text;                      // UTF-8
    };

    // A buffer the program filled (ittd_buffer_hit).
    struct BufferHit
    {
        ea_t     address   = BADADDR;
        uint64_t size      = 0;
        Position first_pos;
        Position last_pos;
        ea_t     writer_ip = BADADDR;
        uint64_t writes    = 0;
        qstring  kind;
        qstring  preview;
    };

    // Why a replay was refused before it ran, when the user can fix it.
    enum class ReplayBlock
    {
        None,
        HostConsent,    // made against the host: needs ReplaySettings::allow_host
        Registry,       // no registry hives where the replay looked
        RegistryMismatch, // hives that are not the recording's (ReplaySettings::any_registry)
    };

    // A fork: replay to 'at', change registers and memory there, and run on,
    // recording into a new trace at 'path' (ITTD_CAP_FORK).
    struct ForkRequest
    {
        Position at;
        qstring  path;
        uint64_t max_instructions = 0;      // 0: until the program exits
        qstring  registry_dir;              // empty: the backend's default
        qstring  emulation_root;            // empty: the recording's own
        bool     strict = false;
        bool     allow_host = false;        // see ReplaySettings::allow_host
        bool     any_registry = false;      // see ReplaySettings::any_registry
        std::vector<std::pair<int, uint64_t>>   regs;     // ITTD_REG_* index (or FORK_REG_RFLAGS), value
        std::vector<std::pair<ea_t, bytevec_t>> memory;   // address, bytes
        qstring  note;                      // goes into the new trace's manifest
        RecordOptions rec;                  // 'elevated' does not apply: the fork's token is the recording's
    };
    constexpr int FORK_REG_RFLAGS = 100;

    struct ForkResult
    {
        bool     ok = false;
        bool     cancelled = false;
        uint64_t instructions = 0;          // how many the fork ran
        qstring  error;
        // Why it was refused before anything ran, when the user can fix it.
        ReplayBlock block = ReplayBlock::None;
    };

    // A program to record from its start (ITraceBackend::record_program).
    struct RecordRequest
    {
        qstring  application;               // the executable
        qstring  arguments;                 // the command line after its name, as typed
        qstring  working_dir;               // empty: the executable's folder
        qstring  path;                      // the new recording
        uint64_t max_instructions = 0;      // 0: until the program exits
        qstring  registry_dir;              // the hives it runs against (no emulation root)
        qstring  emulation_root;            // empty: against this machine's files
        bool     allow_host = false;        // consent to run against this machine's files
        int64_t  start_time = 0;            // seconds since 1970 UTC the program starts at; 0: 1970
        RecordOptions rec;
    };

    // Reported by a query that could not return everything it found.
    struct QueryResult
    {
        bool ran       = false;   // it ran to the end or was cancelled; false when
                                  // the backend cannot answer it or it failed
        bool cancelled = false;   // the user stopped it part-way
        bool truncated = false;   // a record cap was hit; results are a prefix
    };

    // How a long query reports progress and asks whether to stop. The core
    // implements it with a wait box. It may be called from a worker thread, so
    // an implementation uses only thread-safe IDA APIs. A fast backend may
    // ignore it.
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
    // debugger's playhead and one per concurrent query, so a query never moves
    // what the user is looking at.
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
        // The canonical register set (abi/ida_ttd_backend.h), which the core
        // maps onto the register table configure_debugger() installed. Not
        // regval_t: a backend DLL must not see IDA types.
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
        // nothing. Unknown bytes are left as the caller found them; the core
        // fills those and placeholders from the module's on-disk image, which
        // is the same job for every backend.
        //
        // Returns the number of bytes marked known or placeholder.
        virtual size_t   read_memory(ea_t ea, void *buf, size_t size,
                                     std::vector<uint8_t> *known) = 0;

        // The threads alive at this position.
        virtual std::vector<ThreadInfo> live_threads() const = 0;

        // Rebuild [lo, hi) as of this position from the recording's own
        // writes, for memory a position read cannot answer (an unpacker's
        // output before it runs), and serve it from then on. 'replace'
        // discards an earlier rebuild of the range (a re-read); without it a
        // rebuilt range is reused (the per-stop path). Returns the bytes
        // recovered; 0 for a backend whose reads are complete.
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
    // Stepping is a strategy, not a primitive: see the navigation section of
    // abi/ida_ttd_backend.h. Each backend implements the whole family.
    //
    // Every call moves the cursor the navigator was made for, honours the
    // set_breakpoints() set, and says why it stopped.
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

        // Breakpoints as the whole set (see ittd_backend_api::nav_breakpoints).
        // A data breakpoint stops at the instruction that made the access.
        //
        // 'accepted', when given, gets one entry per breakpoint: false for one
        // the engine refused, so IDA shows it as bad rather than as one that
        // silently never fires.
        virtual bool set_breakpoints(const std::vector<Breakpoint> &bpts,
                                     std::vector<bool> *accepted = nullptr) = 0;

        // A message for the user about the last movement, shown after the
        // stop ("this frame does not return anywhere"), or empty. Taking it
        // clears it.
        virtual qstring take_notice() { return qstring(); }

        // Where a long movement reports and asks whether to stop; the core
        // sets one around every movement and clears it after. Movements run
        // on the main thread, so a sink's cancelled() may pump IDA's message
        // loop. Null clears it.
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
        // "sogen"). Stored in the trace-link record, so changing it orphans
        // existing databases.
        virtual const char *id() const = 0;
        virtual const char *display_name() const = 0;
        // Whether this backend handles the file at 'path'. Asked of every
        // registered backend in order, by the loader and when a session
        // starts, so it must be cheap: a signature read at most, never an
        // open.
        virtual bool can_open(const char *path) const = 0;
        // The File > Open filter fragment this backend contributes, e.g.
        // "Microsoft TTD trace (*.run)".
        virtual const char *file_filter() const = 0;
        // Another instance of this backend, not open, for a second recording
        // alongside the one this instance has open (a script's, beside the
        // debugger session's). nullptr when the backend cannot make one.
        virtual std::unique_ptr<ITraceBackend> new_instance() const { return nullptr; }

        // ---- the session ---------------------------------------------------
        virtual bool open(const char *path, qstring *errbuf) = 0;
        virtual void close() = 0;
        virtual bool is_open() const = 0;
        virtual const TraceInfo     &info() const = 0;
        virtual const Capabilities  &capabilities() const = 0;

        // One-off work per recording that makes seeks fast or reads complete:
        // building Microsoft's memory index, filling Sogen's keyframes.
        // Returns true at once when there is nothing to do. Called on the main
        // thread after open(): the debugger runs it when a session starts, the
        // loader asks the user first.
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
        // They report through 'progress' (may be null) and stop when it says
        // so.

        // Every access to [lo, hi) within 'when' matching 'kinds'. Appends to
        // 'out'. Requires capabilities().access_queries.
        virtual QueryResult query_accesses(ea_t lo, ea_t hi, uint8_t kinds,
                                           PositionRange when,
                                           std::vector<Access> *out,
                                           ProgressSink *progress) = 0;

        // The distinct addresses inside 'ranges' that the recording executed
        // (see ittd_backend_api::query_executed). Appends to 'out' in
        // ascending order, each address once: a vector rather than a set,
        // because a module's worth is millions of entries.
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
        // and every indirect jump too when 'jumps' is set. Grouped by site,
        // not by invocation.
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
        // (Windows' MEM_* and PAGE_* values, which the memory map wants as
        // they are), and the mapped-file names their one-based 'file' fields
        // index. A backend without it answers not-ran.
        virtual QueryResult query_mapping_changes(std::vector<ittd_mapping_change> *out,
                                                  std::vector<qstring> *files,
                                                  ProgressSink *progress)
        {
            qnotused(out); qnotused(files); qnotused(progress);
            return QueryResult{};
        }

        // Every instruction the program wrote before running it. Requires
        // capabilities().self_modifying; a backend without it answers not-ran.
        virtual QueryResult query_self_modifying(std::vector<SelfModHit> *out,
                                                 ProgressSink *progress)
        {
            qnotused(out); qnotused(progress);
            return QueryResult{};
        }

        // Every string the program had in memory, of at least 'min_length'
        // characters, by replaying the whole recording. Requires
        // capabilities().replay_scans.
        virtual QueryResult query_strings(const ReplaySettings &settings, uint32_t min_length,
                                          std::vector<StringHit> *out, ProgressSink *progress)
        {
            qnotused(settings); qnotused(min_length); qnotused(out); qnotused(progress);
            return QueryResult{};
        }

        // Every buffer the program filled, by replaying the whole recording.
        // Requires capabilities().replay_scans.
        virtual QueryResult query_buffers(const ReplaySettings &settings,
                                          std::vector<BufferHit> *out, ProgressSink *progress)
        {
            qnotused(settings); qnotused(out); qnotused(progress);
            return QueryResult{};
        }

        // Why the last call failed, when the backend says; empty otherwise.
        virtual qstring last_error() const { return qstring(); }
        // Forget the calling thread's last error, before a call whose own
        // reason last_error() should then give (abi_export does this), so an
        // earlier failure's text never answers for a later one.
        virtual void clear_error() {}

        // Why the last replay (record_fork, query_strings, query_buffers) was
        // refused, when the user can fix it: consent to replay a recording made
        // against the host, or the registry hives.
        virtual ReplayBlock last_replay_block() const { return ReplayBlock::None; }

        // What a replay of the open recording needs. False when the backend
        // does not say.
        virtual bool replay_env(ReplayEnv * /*out*/) { return false; }
        // Whether 'dir' holds the recording's own hives; 'why' says why not.
        // A backend that cannot tell answers Unverified for any folder with
        // a SYSTEM hive in it. Reads every hive, so it takes a moment.
        virtual HiveCheck check_registry(const char *dir, qstring *why)
        {
            // std::filesystem, not qfileexist: the Microsoft backend builds
            // this header without ida.lib.
            std::error_code ec;
            if ( dir != nullptr && *dir != '\0'
              && std::filesystem::is_regular_file(
                     std::filesystem::path(std::u8string(reinterpret_cast<const char8_t *>(dir))) / "SYSTEM", ec) )
                return HiveCheck::Unverified;
            if ( why != nullptr )
                why->sprnt("no registry hives (SYSTEM, SOFTWARE, ...) in %s", dir != nullptr ? dir : "");
            return HiveCheck::Missing;
        }

        // What the last query_strings or query_buffers skipped, in words: the
        // stretches its replay could not follow on this machine. Empty when
        // it covered everything.
        virtual qstring scan_notice() const { return qstring(); }

        // Fork the recording (see ForkRequest). Requires capabilities().fork.
        // Long: a replay to the position, then the recording.
        virtual ForkResult record_fork(const ForkRequest &req, ProgressSink *progress)
        {
            qnotused(req); qnotused(progress);
            ForkResult r;
            r.error = "this recording's backend cannot fork it";
            return r;
        }

        // Whether record_program works: the backend can run a program in its
        // emulator and record it, with nothing open.
        virtual bool can_record() const { return false; }
        // Record a program from its start (see RecordRequest). Long: the
        // whole run. A refusal the user can fix sets ForkResult::block.
        virtual ForkResult record_program(const RecordRequest &req, ProgressSink *progress)
        {
            qnotused(req); qnotused(progress);
            ForkResult r;
            r.error = "this backend cannot record programs";
            return r;
        }

        // Every syscall the program made, in order. Requires
        // capabilities().syscalls; a backend without it answers not-ran.
        virtual QueryResult query_syscalls(std::vector<SyscallEvent> *out,
                                           ProgressSink *progress)
        {
            qnotused(out); qnotused(progress);
            return QueryResult{};
        }

        // The instructions executed within 'when', in order, on thread 'tid'
        // (0: every thread): at most 'max' of them, as ACCESS_EXEC accesses
        // whose pc is the instruction. 'truncated' says the range held more.
        // Callers keep 'when' short.
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
        // entry it went to. False when not found within the bound, or when
        // 'progress' (optional) asked to stop.
        virtual bool query_frame_entry(Position at, uint32_t tid, uint64_t max_back,
                                       Position *call_pos, ea_t *entry, ProgressSink *progress = nullptr)
        {
            qnotused(at); qnotused(tid); qnotused(max_back); qnotused(call_pos); qnotused(entry);
            qnotused(progress);
            return false;
        }

        // Every access counted by page (1 << page_shift bytes) and by slice of
        // the recording's time; empty cells left out. ran == false when the
        // backend cannot.
        virtual QueryResult query_access_heat(uint32_t page_shift, uint32_t slices,
                                              std::vector<HeatCell> *out, ProgressSink *progress)
        {
            qnotused(page_shift); qnotused(slices); qnotused(out); qnotused(progress);
            return QueryResult{};
        }
        // The same over the stretch 'when' only, cut into equal slices (the
        // heatmap zoomed in). A whole-trace range is the query above; ran ==
        // false when the backend cannot count part of the recording.
        virtual QueryResult query_access_heat_window(uint32_t page_shift, uint32_t slices,
                                                     PositionRange when, std::vector<HeatCell> *out,
                                                     ProgressSink *progress)
        {
            if ( when.whole_trace() )
                return query_access_heat(page_shift, slices, out, progress);
            qnotused(out); qnotused(progress);
            return QueryResult{};
        }
        // Can query_access_heat_window count part of the recording?
        virtual bool can_window_heat() const { return false; }
        // What each syscall wrote through an out parameter, nullopt where it
        // could not be found. False when the backend has no way of its own:
        // the caller reads each slot one position after the call.
        virtual bool query_out_values(const std::vector<OutSlot> &slots,
                                      std::vector<std::optional<uint64_t>> *out, ProgressSink *progress)
        {
            qnotused(slots); qnotused(out); qnotused(progress);
            return false;
        }

        // Where slice 'slice' of 'slices' begins; none() when unknown.
        virtual Position heat_slice_position(uint32_t slices, uint32_t slice)
        {
            qnotused(slices); qnotused(slice);
            return Position::none();
        }
        // The same for a slice of the stretch 'when'.
        virtual Position heat_window_slice_position(uint32_t slices, uint32_t slice, PositionRange when)
        {
            if ( when.whole_trace() )
                return heat_slice_position(slices, slice);
            return Position::none();
        }

        // The last instruction of thread 'tid' before 'at' that changed
        // register 'reg' (ITTD_REG_*, or ITTD_ORIGIN_XMM0 + n), searching back
        // about 'max_back' of its steps: *found, and *where (before it ran).
        // False when the backend has no fast way; the caller steps back itself.
        virtual bool query_register_change(Position at, uint32_t tid, uint32_t reg, uint64_t max_back,
                                           Position *where, bool *found, ProgressSink *progress)
        {
            qnotused(at); qnotused(tid); qnotused(reg); qnotused(max_back);
            qnotused(where); qnotused(found); qnotused(progress);
            return false;
        }

        // The registers at each of 'positions', in the same order; an entry
        // whose 'have' is 0 could not be reconstructed. A batch because
        // neighbouring positions share work (ittd_backend_api::regs_at). The
        // default seeks a scratch cursor per position.
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

        // ittd_backend_api::visit_positions: fn(i, 0, read) with memory
        // readable at at[i], then fn(i, 1, read) at (*after)[i] when 'after'
        // is given and that is a position. Calls come in no particular order
        // and may come from several threads at once; 'read' is valid only
        // during the call (returns the leading bytes known, as guest_read).
        // ran false: the backend has no such visit, use read_memory_at.
        using VisitRead = std::function<size_t(uint64_t addr, void *buf, size_t size)>;
        using VisitFn   = std::function<void(size_t index, int phase, const VisitRead &read)>;
        virtual QueryResult visit_positions(const std::vector<Position> &at, const std::vector<Position> *after,
                                            const VisitFn &fn, ProgressSink *progress)
        {
            qnotused(at); qnotused(after); qnotused(fn); qnotused(progress);
            return QueryResult{};
        }

        // Each of 'reads' as a cursor at its position would read it: the
        // bytes into (*data)[offset, offset + size) and an ITTD_KNOWN_* a byte
        // into (*known), both sized here to the furthest read. A batch for a
        // backend whose seeks are dear (Microsoft TTD: about 15 ms each),
        // which can spread the positions over several cursors at once. The
        // default seeks a scratch cursor once per distinct position.
        virtual QueryResult read_memory_at(const std::vector<MemAt> &reads, std::vector<uint8_t> *data,
                                           std::vector<uint8_t> *known, ProgressSink *progress)
        {
            QueryResult r;
            size_t total = 0;
            for ( const MemAt &m : reads )
                total = std::max(total, m.offset + m.size);
            data->assign(total, 0);
            known->assign(total, ITTD_KNOWN_NO);
            CursorPtr cursor = make_cursor();
            if ( cursor == nullptr )
                return r;
            r.ran = true;
            std::vector<size_t> order(reads.size());
            for ( size_t i = 0; i < order.size(); i++ )
                order[i] = i;
            std::stable_sort(order.begin(), order.end(),
                             [&](size_t a, size_t b) { return reads[a].pos < reads[b].pos; });
            std::vector<uint8_t> k;
            bool started = false, at = false;
            Position here = Position::none();
            for ( size_t i = 0; i < order.size(); i++ )
            {
                const MemAt &m = reads[order[i]];
                if ( !started || m.pos != here )
                {
                    started = true;
                    if ( progress != nullptr )
                    {
                        if ( progress->cancelled() )
                        {
                            r.cancelled = true;
                            break;
                        }
                        progress->report(uint32_t(i * 100 / order.size()));
                    }
                    here = m.pos;
                    at   = cursor->seek(m.pos);
                }
                if ( !at || m.size == 0 )
                    continue;
                cursor->read_memory(m.addr, data->data() + m.offset, m.size, &k);
                for ( size_t j = 0; j < m.size && j < k.size(); j++ )
                    (*known)[m.offset + j] = k[j];
            }
            return r;
        }

        // ---- symbols -------------------------------------------------------
        //
        // Named addresses the recording knows about. Microsoft TTD records
        // none, so its backend parses the export table out of guest memory;
        // Sogen records every module's export directory. Either way the core
        // gets a list and applies IDA names.
        struct Symbol { ea_t ea = BADADDR; qstring name; bool is_export = true; };
        virtual std::vector<Symbol> module_symbols(ea_t base) = 0;
        // [start, end) of every function in the module at 'base', from whatever
        // the backend has that knows: the PE exception table, or the recording's
        // own notion of a function. Empty when it has nothing.
        virtual std::vector<std::pair<ea_t, ea_t>> module_functions(ea_t base) = 0;
    };

    using BackendPtr = std::unique_ptr<ITraceBackend>;
}
