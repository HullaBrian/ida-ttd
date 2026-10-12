#pragma once

#include "common/pch.h"
#include "common/trace_open.h"
#include "core/backend.h"
#include "debugger/msttd_position.h"

namespace idattd
{
    // Microsoft TTD (.run recordings) behind ITraceBackend.
    //
    // Compiled into the plugin for now; phase 4 of docs/modular-backends.md
    // moves it into its own DLL behind the C ABI, which is why nothing outside
    // src/backend-msttd/ is meant to know its types. During the move, the
    // analyses that still drive the engine directly reach it through
    // engine() -- each of those is converted to a query in turn.
    //
    // The engine is a replay engine: a question about the whole trace is
    // answered by replaying with a watchpoint armed, and moving the playhead is
    // cheap. Its cursor and navigator below are what TraceManager's navigate_*
    // family and MemoryReader's engine half became.
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

        // The whole-trace sweeps move here in step 5; until then these say
        // they did not run and the analyses keep driving the engine.
        QueryResult query_accesses(ea_t, ea_t, uint8_t, PositionRange, std::vector<Access> *,
                                   ProgressSink *) override { return QueryResult{}; }
        QueryResult query_executed(const std::vector<std::pair<ea_t, ea_t>> &, std::set<ea_t> *,
                                   ProgressSink *) override { return QueryResult{}; }
        QueryResult query_calls(const std::vector<ea_t> &, PositionRange, std::vector<CallEvent> *,
                                ProgressSink *) override { return QueryResult{}; }
        QueryResult query_indirect_targets(const std::vector<std::pair<ea_t, ea_t>> &, bool,
                                           std::map<ea_t, std::vector<IndirectTarget>> *,
                                           ProgressSink *) override { return QueryResult{}; }
        QueryResult query_exceptions(std::vector<ExceptionEvent> *out, ProgressSink *progress) override;
        QueryResult query_instructions(PositionRange when, uint32_t tid, size_t max,
                                       std::vector<Access> *out, ProgressSink *progress) override;
        Position position_add(Position p, int64_t delta) const override;
        bool query_frame_entry(Position at, uint32_t tid, uint64_t max_back,
                               Position *call_pos, ea_t *entry) override;

        // The engine records neither, and the core parses exports and .pdata
        // out of guest memory or the file itself.
        std::vector<Symbol> module_symbols(ea_t) override { return {}; }
        std::vector<std::pair<ea_t, ea_t>> module_functions(ea_t) override { return {}; }

        // ---- Microsoft-only, for code not yet moved behind the interface ----
        TTD::Replay::IReplayEngine *engine() const { return m_engine.get(); }
        TTD::Replay::UniqueCursor   new_engine_cursor() const;
        bool                        is64() const { return m_info.is64; }

    private:
        TTD::Replay::UniqueReplayEngine m_engine;
        IdaErrorReporting               m_err;
        // Sequential, unfiltered: query_frame_entry's call/return callback
        // mutates an unsynchronized map, and the engine's default parallel
        // replay would dispatch it from several threads at once.
        TTD::Replay::UniqueCursor       m_frameScratch;
        TTD::Replay::UniqueCursor       m_insnScratch;     // query_instructions, likewise
        TraceInfo                       m_info;
        Capabilities                    m_caps;
    };

    // A position in a Microsoft recording, with the playhead's thread and
    // registers. Reads come from a second engine cursor that is only ever
    // positioned, never executed: a cursor left "in execution" answers every
    // memory query thread-locally whatever policy is asked for, which is what
    // made non-executed bytes read back as zeros.
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
        // the position query, which only zero-fills that memory.
        struct Rebuilt
        {
            ea_t                 lo = 0, hi = 0;
            std::vector<uint8_t> data;
            std::vector<bool>    known;
        };
        std::vector<Rebuilt> m_rebuilt;
    };
}
