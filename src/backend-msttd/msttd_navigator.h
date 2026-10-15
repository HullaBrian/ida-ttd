#pragma once

#include "backend-msttd/msttd_backend.h"
#include "backend-msttd/msttd_x86.h"

namespace idattd
{
    // Movement through a Microsoft recording. Stepping is a strategy here, not
    // a primitive -- "step over backwards" is rewind, notice the step landed
    // in a callee that had just returned, rewind out of it -- and each
    // strategy is the engine's cheapest route: one replay with a watchpoint
    // armed rather than a step loop.
    //
    // It moves the cursor it was made over and honours the breakpoints set on
    // it, which it keeps as engine watchpoints on that cursor.
    class MsTtdNavigator : public INavigator
    {
    public:
        MsTtdNavigator(MsTtdBackend *backend, MsTtdCursor *cursor);
        ~MsTtdNavigator() override;

        StopReason step(bool forward) override;
        StopReason step_over(bool forward) override;
        StopReason step_out(bool forward) override;
        StopReason run(bool forward) override;
        StopReason run_to(ea_t addr, bool forward) override;
        StopReason seek_to(Position p) override;

        bool set_breakpoints(const std::vector<Breakpoint> &bpts,
                             std::vector<bool> *accepted) override;
        qstring take_notice() override;
        void set_progress(ProgressSink *progress) override { m_progress = progress; }

    private:
        using EventType = TTD::Replay::EventType;

        enum class RunStop
        {
            Reached,        // execution came back to the address asked for
            Breakpoint,     // a user breakpoint stopped it first
            TraceBoundary,  // the recording ended first
        };

        TTD::Replay::ICursorView *cur() const { return m_cursor->exec(); }

        EventType navigate_steps(bool forward, TTD::Replay::StepCount steps);
        EventType navigate_over(bool step_out);
        EventType navigate_over_backward();
        EventType navigate_out_backward();
        EventType navigate_backward_to(ea_t addr);
        EventType navigate_forward_to(ea_t addr);
        EventType rewind_to(const TTD::Replay::Position &p);
        bool      find_frame_entry_position(TTD::Replay::Position &out, bool &cancelled);
        TTD::Replay::ICursorView *frame_cursor();
        RunStop   run_to_addr_guarded(ea_t addr, uint64_t min_sp, uint32_t utid);
        // The call or return at the playhead, decoded from recorded memory.
        X86Branch branch_here();
        bool      cancelled() const { return m_progress != nullptr && m_progress->cancelled(); }
        bool      add_temp_exec_watchpoint(ea_t addr, TTD::Replay::MemoryWatchpointData &wp);
        void      drop_temp_exec_watchpoint(const TTD::Replay::MemoryWatchpointData &wp, bool owned);
        void      restore_event_mask();

        // The movement's engine result as a stop reason, after clamping onto a
        // real position: a run that reached either end leaves the cursor on
        // the limit sentinel, and everything after it works from there.
        StopReason settle(EventType sr, bool forward, ea_t target = BADADDR);

        // Data breakpoints. The engine reports a data watchpoint just after
        // the instruction that made the access, in either direction, and a
        // backward run never reports the instruction right before where it
        // started; the ABI's stop is at that instruction.
        bool data_breakpoints_armed() const;
        bool data_hit_just_before();
        // A movement does not stop on an access made by the instruction it
        // starts on -- that is where the last stop left it, and stopping
        // there again would never move. Executes that one instruction when it
        // makes such an access; true when it did.
        bool step_past_own_access();
        // Records, for every watchpoint that stops a replay, whether it was a
        // data access: the program counter alone cannot say, since an execute
        // breakpoint on any byte of an instruction stops on its first.
        void record_hits();

        MsTtdBackend *m_backend;
        MsTtdCursor  *m_cursor;
        TTD::Replay::UniqueCursor m_frameCursor;   // see frame_cursor()
        std::set<TTD::Replay::MemoryWatchpointData> m_userWatchpoints;
        qstring m_notice;
        ProgressSink *m_progress = nullptr;
        bool          m_lastHitData = false;   // see record_hits()
    };
}
