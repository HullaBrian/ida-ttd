#pragma once

#include "backend-msttd/msttd_pch.h"
#include "backend-msttd/msttd_trace_open.h"
#include "core/backend.h"
#include "backend-msttd/msttd_position.h"

#include <thread>
#include <unordered_map>

namespace idattd
{
    struct SyscallCensus;

    // Microsoft TTD (.run recordings) behind ITraceBackend, exported as the
    // C ABI by msttd_entry.cpp; nothing outside src/backend-msttd/ sees these
    // types. Whole-trace questions are replays with a watchpoint armed;
    // moving the playhead is cheap.
    class MsTtdBackend : public ITraceBackend
    {
    public:
        MsTtdBackend();
        ~MsTtdBackend() override;

        const char *id() const override           { return "msttd"; }
        const char *display_name() const override { return "Microsoft TTD"; }
        bool        can_open(const char *path) const override;
        const char *file_filter() const override  { return "Microsoft TTD trace (*.run)"; }

        bool open(const char *path, qstring *errbuf) override;
        void close() override;
        bool is_open() const override { return (bool)m_engine; }
        // The memory index: without it, memory reads are severely limited.
        // Built behind IDA's wait box; the engine cannot be interrupted.
        bool prepare(ProgressSink *progress) override;
        bool prepared() const override;
        const TraceInfo    &info() const override         { return m_info; }
        const Capabilities &capabilities() const override { return m_caps; }

        qstring     format_position(Position p) const override;
        bool        parse_position(const char *text, Position *out) const override;
        const char *position_syntax() const override;

        CursorPtr make_cursor() override;
        std::unique_ptr<INavigator> make_navigator(ITraceCursor *cursor) override;

        std::vector<ModuleInfo> modules() const override;
        std::vector<ThreadInfo> threads() const override;
        std::vector<TraceEvent> timeline() const override;

        // Each a replay with a watchpoint or the call/return callback armed
        // (msttd_queries.cpp); progress and Cancel through 'progress'.
        QueryResult query_accesses(ea_t lo, ea_t hi, uint8_t kinds, PositionRange when,
                                   std::vector<Access> *out, ProgressSink *progress) override;
        QueryResult query_executed(const std::vector<std::pair<ea_t, ea_t>> &ranges,
                                   std::vector<ea_t> *out, ProgressSink *progress) override;
        QueryResult query_calls(const std::vector<ea_t> &targets, PositionRange when,
                                std::vector<CallEvent> *out, ProgressSink *progress) override;
        QueryResult query_indirect_targets(const std::vector<std::pair<ea_t, ea_t>> &ranges, bool jumps,
                                           std::map<ea_t, std::vector<IndirectTarget>> *out,
                                           ProgressSink *progress) override;
        // Reconstructed from the five memory syscalls (msttd_memmap.cpp).
        QueryResult query_mapping_changes(std::vector<ittd_mapping_change> *out,
                                          std::vector<qstring> *files,
                                          ProgressSink *progress) override;
        QueryResult query_exceptions(std::vector<ExceptionEvent> *out, ProgressSink *progress) override;
        // Every transition into the kernel (msttd_syscalls.cpp).
        QueryResult query_syscalls(std::vector<SyscallEvent> *out, ProgressSink *progress) override;
        // Two replays watching every write, kept (msttd_scans.cpp).
        QueryResult query_self_modifying(std::vector<SelfModHit> *out, ProgressSink *progress) override;
        QueryResult query_strings(const ReplaySettings &settings, uint32_t min_length,
                                  std::vector<StringHit> *out, ProgressSink *progress) override;
        QueryResult query_buffers(const ReplaySettings &settings, std::vector<BufferHit> *out,
                                  ProgressSink *progress) override;
        // From the syscall census where it has them, else by seeking.
        QueryResult registers_at(const std::vector<Position> &positions, std::vector<ittd_regs> *out,
                                 ProgressSink *progress) override;
        // One cursor carried forward from position to position, rather than
        // a seek to each.
        QueryResult visit_positions(const std::vector<Position> &at, const std::vector<Position> *after,
                                    const VisitFn &fn, ProgressSink *progress) override;
        QueryResult read_memory_at(const std::vector<MemAt> &reads, std::vector<uint8_t> *data,
                                   std::vector<uint8_t> *known, ProgressSink *progress) override;
        QueryResult query_instructions(PositionRange when, uint32_t tid, size_t max,
                                       std::vector<Access> *out, ProgressSink *progress) override;
        Position position_add(Position p, int64_t delta) const override;
        QueryResult query_access_heat(uint32_t page_shift, uint32_t slices,
                                      std::vector<HeatCell> *out, ProgressSink *progress) override;
        Position heat_slice_position(uint32_t slices, uint32_t slice) override;
        QueryResult query_access_heat_window(uint32_t page_shift, uint32_t slices, PositionRange when,
                                             std::vector<HeatCell> *out, ProgressSink *progress) override;
        Position heat_window_slice_position(uint32_t slices, uint32_t slice, PositionRange when) override;
        bool can_window_heat() const override { return true; }
        bool query_out_values(const std::vector<OutSlot> &slots,
                              std::vector<std::optional<uint64_t>> *out, ProgressSink *progress) override;
        bool query_register_change(Position at, uint32_t tid, uint32_t reg, uint64_t max_back,
                                   Position *where, bool *found, ProgressSink *progress) override;
        bool query_frame_entry(Position at, uint32_t tid, uint64_t max_back,
                               Position *call_pos, ea_t *entry, ProgressSink *progress = nullptr) override;

        // The engine records neither, and the core parses exports and .pdata
        // out of guest memory or the file itself.
        std::vector<Symbol> module_symbols(ea_t) override { return {}; }
        std::vector<std::pair<ea_t, ea_t>> module_functions(ea_t) override { return {}; }

        // Why the last call failed. Queries run on worker threads while the
        // main thread asks this, so the text is mutex-guarded and copied out.
        qstring last_error() const override;
        void    clear_error() override;

        // ---- Microsoft-only, for the rest of this backend ----
        // Set the text last_error() gives. Const: a failure found in a const
        // call (making a cursor) is still worth saying.
        void set_error(const char *fmt, ...) const;
        TTD::Replay::IReplayEngine *engine() const { return m_engine.get(); }
        TTD::Replay::UniqueCursor   new_engine_cursor() const;
        bool                        is64() const { return m_info.is64; }
        // The UniqueId of the thread with OS id 'tid' alive at 'at': an OS id
        // can be reused within a recording. Failing that, the last thread
        // that had the id; 0 when none did.
        uint32_t                    unique_thread_id(uint32_t tid, Position at) const;

        // The CALL that entered a thread's frame, for query_frame_entry and
        // the navigator's step-out (forward and backward) and backward
        // step-over: one search with each caller's own look-back schedule.
        struct FrameEntry
        {
            TTD::Replay::Position pos{};          // the call instruction
            ea_t                  entry    = 0;   // its target
            uint64_t              ret_addr = 0;   // where it returns to
        };
        enum class FrameWindowKind
        {
            InSequence,     // 'back' steps, clipped at the start of the sequence
            ThreadSteps,    // 'back' of the thread's steps, across sequences
            Sequences,      // from the start of the sequence 'back' sequences earlier
        };
        struct FrameWindow
        {
            FrameWindowKind kind;
            uint64_t        back;
        };
        enum class FrameSearch { Found, NotFound, Cancelled };
        // Replays each window up to 'here' on 'scratch' (sequential and
        // unfiltered, owned by the caller and used by one thread at a time)
        // with the call/return callback, keeping thread 'utid''s open calls,
        // until a window holds the entering call: the innermost open call
        // made at or above 'here_sp' (0 accepts the innermost). 'progress'
        // may be null; 'log_miss' logs why a search found nothing.
        FrameSearch find_frame_entry(TTD::Replay::ICursorView *scratch, TTD::Replay::Position here,
                                     uint32_t utid, uint64_t here_sp,
                                     const FrameWindow *windows, size_t nwindows,
                                     ProgressSink *progress, bool log_miss, FrameEntry *out) const;

    private:
        // The end of user-mode address space, for watchpoints over all of it.
        uint64_t user_space_end() const { return m_info.is64 ? 0x800000000000ull : 0x100000000ull; }

        TTD::Replay::UniqueReplayEngine m_engine;
        MsttdErrorReporting             m_err;
        mutable std::mutex              m_errorMtx;
        // last_error(), per thread: a query on a worker and a cursor call on
        // the main thread fail independently, and each caller (abi_export)
        // reads its own right after its own call.
        mutable std::unordered_map<std::thread::id, std::string> m_error;
        // Sequential, unfiltered: query_frame_entry's call/return callback
        // mutates an unsynchronized map, and the engine's default parallel
        // replay would dispatch it from several threads at once.
        // Each scratch object has its own mutex: the core may ask one query
        // on a worker while the main thread asks another on every stop. Each
        // is held only for that query's bounded work and never with another,
        // so none can deadlock. The write scans (m_scans) run for minutes and
        // are not locked: a main thread blocked behind them would hang IDA.
        TTD::Replay::UniqueCursor       m_frameScratch;
        TTD::Replay::UniqueCursor       m_insnScratch;     // query_instructions, likewise
        TTD::Replay::UniqueCursor       m_regsScratch;     // registers_at
        std::mutex                      m_frameMtx;        // m_frameScratch
        std::mutex                      m_insnMtx;         // m_insnScratch
        std::mutex                      m_regsMtx;         // m_regsScratch, m_syscallRegs
        struct SyscallRegs
        {
            uint64_t gp[ITTD_REG_GP_COUNT];
            uint64_t rflags;
        };
        std::map<std::pair<uint64_t, uint64_t>, SyscallRegs> m_syscallRegs;  // by (sequence, steps)
        // The syscall census (msttd_syscalls.cpp), shared by query_syscalls
        // and query_mapping_changes. Only a census that ran to the end is
        // cached. m_censusMtx guards the pointer only, never a replay: two
        // queries that both miss each run their own, and the last one kept
        // is as good as the first.
        std::mutex                      m_censusMtx;
        std::shared_ptr<const SyscallCensus> m_census;
        std::shared_ptr<const SyscallCensus> cached_census();
        // The cached census, else one replay for it. 'need_memmap': when the
        // recording names no memory syscall, return a census with no
        // 'memmap' and no calls, without replaying. Null when no replay
        // could be made. A cancelled census is returned but not cached.
        std::shared_ptr<const SyscallCensus> syscall_census(bool need_memmap, ProgressSink *progress,
                                                            QueryResult *qr);
        // What the write scans found (msttd_scans.cpp), once they have run.
        struct ScanResultsPtr
        {
            struct MsTtdScanResults *p = nullptr;
            ScanResultsPtr() = default;
            ScanResultsPtr(const ScanResultsPtr &) = delete;
            ScanResultsPtr &operator=(const ScanResultsPtr &) = delete;
            ~ScanResultsPtr();
            void reset();
        };
        ScanResultsPtr                  m_scans;
        // Guards only reading and publishing m_scans.p, never the scan: two
        // scans that finish together keep the first's results, and the
        // second's are dropped instead of leaked.
        std::mutex                      m_scansMtx;
        bool run_scans(ProgressSink *progress, QueryResult *qr);
        TraceInfo                       m_info;
        Capabilities                    m_caps;
        bool                            m_indexed = false;   // prepare() ran this session
    };

    // A position in a Microsoft recording, with the playhead's thread and
    // registers. Memory reads use a second cursor that is only positioned,
    // never executed: a cursor left "in execution" answers every memory query
    // thread-locally whatever the policy, so unexecuted bytes read as zeros.
    class MsTtdCursor : public ITraceCursor
    {
    public:
        MsTtdCursor(MsTtdBackend *owner, TTD::Replay::UniqueCursor exec, TTD::Replay::UniqueCursor read);

        Position position() const override;
        bool     seek(Position p) override;
        uint32_t thread_id() const override;
        ea_t     program_counter() const override;
        uint64_t stack_pointer() const override;
        bool     read_registers(ittd_regs *out) const override;
        bool     read_thread_registers(uint32_t tid, ittd_regs *out) const override;
        size_t   read_memory(ea_t ea, void *buf, size_t size, std::vector<uint8_t> *known) override;
        std::vector<ThreadInfo> live_threads() const override;
        size_t   rebuild_range(ea_t lo, ea_t hi, bool replace) override;

        // Keep the playhead on a recorded position: the engine's Min/Max are
        // sentinels, and stepping from one does not move by one instruction.
        void clamp_to_trace();

        TTD::Replay::ICursorView *exec() const { return m_exec.get(); }
        MsTtdBackend             *owner() const { return m_owner; }

    private:
        bool rebuild(ea_t lo, ea_t hi);

        MsTtdBackend             *m_owner;
        TTD::Replay::UniqueCursor m_exec;     // the playhead
        TTD::Replay::UniqueCursor m_read;     // parked at the playhead for reads
        TTD::Replay::Position     m_readPos{};
        bool                      m_readPosValid = false;

        // Scratch, reused across reads so the hot path does not allocate.
        std::vector<uint8_t> m_probe;

        // Bytes rebuilt from recorded writes (rebuild_range); they win over
        // the position query, which only zero-fills that memory. Each holds
        // the memory as of one position and is served only there: elsewhere
        // later writes, or earlier absence, make it wrong. The few most recent
        // are kept, so travelling back and forth does not replay again.
        struct Rebuilt
        {
            ea_t                  lo = 0, hi = 0;
            TTD::Replay::Position pos{};
            std::vector<uint8_t>  data;
            std::vector<bool>     known;
        };
        std::vector<Rebuilt> m_rebuilt;     // oldest first
    };
}
