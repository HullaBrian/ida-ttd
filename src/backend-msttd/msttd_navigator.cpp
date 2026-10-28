#include "backend-msttd/msttd_navigator.h"
#include "backend-msttd/msttd_host.h"

using namespace TTD;
using namespace TTD::Replay;

namespace idattd
{
    static DataAccessMask access_mask_of(uint8_t kinds)
    {
        DataAccessMask m = DataAccessMask::None;
        if ( kinds & ACCESS_READ )  m = m | DataAccessMask::Read;
        if ( kinds & ACCESS_WRITE ) m = m | DataAccessMask::Write;
        if ( kinds & ACCESS_EXEC )  m = m | DataAccessMask::Execute;
        return m == DataAccessMask::None ? DataAccessMask::Execute : m;
    }

    MsTtdNavigator::MsTtdNavigator(MsTtdBackend *backend, MsTtdCursor *cursor)
        : m_backend(backend), m_cursor(cursor)
    {
        record_hits();
    }

    MsTtdNavigator::~MsTtdNavigator()
    {
        // The watchpoints live on the cursor, which outlives this navigator.
        for ( const MemoryWatchpointData &wp : m_userWatchpoints )
            cur()->RemoveMemoryWatchpoint(wp);
        cur()->SetMemoryWatchpointCallback(nullptr, 0);
        cur()->SetEventMask(EventMask::None);
    }

    void MsTtdNavigator::restore_event_mask()
    {
        cur()->SetEventMask(m_userWatchpoints.empty() ? EventMask::None : EventMask::MemoryWatchpoint);
    }

    bool MsTtdNavigator::set_breakpoints(const std::vector<Breakpoint> &bpts, std::vector<bool> *accepted)
    {
        for ( const MemoryWatchpointData &wp : m_userWatchpoints )
            cur()->RemoveMemoryWatchpoint(wp);
        m_userWatchpoints.clear();
        if ( accepted != nullptr )
            accepted->assign(bpts.size(), false);

        bool all = true;
        for ( size_t i = 0; i < bpts.size(); i++ )
        {
            DataAccessMask mask = access_mask_of(bpts[i].kinds);
            MemoryWatchpointData wp{};
            wp.Address    = GuestAddress{ (uint64_t)bpts[i].addr };
            wp.Size       = mask == DataAccessMask::Execute ? 1 : (bpts[i].size > 0 ? bpts[i].size : 1);
            wp.AccessMask = mask;
            // Report the truth: a watchpoint the engine refuses never fires,
            // and claiming it was set would leave IDA showing an active
            // breakpoint that silently does nothing.
            if ( cur()->AddMemoryWatchpoint(wp) )
            {
                m_userWatchpoints.insert(wp);
                if ( accepted != nullptr )
                    (*accepted)[i] = true;
            }
            else
            {
                all = false;
                msttd_log("[ida-ttd] could not set a TTD watchpoint for the breakpoint at 0x%llX.\n",
                    (uint64_t)bpts[i].addr);
            }
        }
        restore_event_mask();
        return all;
    }

    qstring MsTtdNavigator::take_notice()
    {
        qstring n;
        n.swap(m_notice);
        return n;
    }

    bool MsTtdNavigator::data_breakpoints_armed() const
    {
        for ( const MemoryWatchpointData &wp : m_userWatchpoints )
            if ( wp.AccessMask != DataAccessMask::Execute )
                return true;
        return false;
    }

    static bool is_data_access(DataAccessType t)
    {
        return t == DataAccessType::Read || t == DataAccessType::Write || t == DataAccessType::Overwrite;
    }

    // The context is the navigator's m_lastHitData. A plain function, because
    // the SDK keeps a pointer to the callable it is given, not a copy.
    static bool __fastcall record_hit(uintptr_t context, ICursorView::MemoryWatchpointResult const &w,
                                      IThreadView const *)
    {
        *reinterpret_cast<bool *>(context) = is_data_access(w.AccessType);
        return true;
    }

    void MsTtdNavigator::record_hits()
    {
        cur()->SetMemoryWatchpointCallback(&record_hit, reinterpret_cast<uintptr_t>(&m_lastHitData));
    }

    // Did the instruction just before the playhead make a watched data access?
    // A backward run cannot say (the engine would report it at the playhead
    // itself, which it skips), so replay that one instruction forward and
    // see. When it did, stop on it.
    bool MsTtdNavigator::data_hit_just_before()
    {
        if ( !data_breakpoints_armed() )
            return false;
        const TtdPosition here = cur()->GetPosition();
        cur()->ReplayBackward(TtdPosition::Min, StepCount{ 1 });
        const TtdPosition before = cur()->GetPosition();
        if ( !(before < here) )
        {
            cur()->SetPosition(here);
            return false;
        }
        m_lastHitData = false;
        ICursorView::ReplayResult r = cur()->ReplayForward(TtdPosition::Max, StepCount{ 1 });
        bool hit = r.StopReason == EventType::MemoryWatchpoint && m_lastHitData;
        cur()->SetPosition(hit ? before : here);
        return hit;
    }

    bool MsTtdNavigator::step_past_own_access()
    {
        if ( !data_breakpoints_armed() )
            return false;
        const TtdPosition here = cur()->GetPosition();
        m_lastHitData = false;
        ICursorView::ReplayResult r = cur()->ReplayForward(TtdPosition::Max, StepCount{ 1 });
        if ( r.StopReason == EventType::MemoryWatchpoint && m_lastHitData )
        {
            m_lastHitData = false;
            return true;
        }
        cur()->SetPosition(here);
        m_lastHitData = false;
        return false;
    }

    StopReason MsTtdNavigator::settle(EventType sr, bool forward, ea_t target)
    {
        // First and unconditionally: a run that reached either end leaves the
        // cursor on the limit sentinel, not a recorded position.
        m_cursor->clamp_to_trace();

        // A breakpoint stop is not a trace edge.
        if ( sr == EventType::MemoryWatchpoint )
        {
            // An execute breakpoint or the movement's own target stops on the
            // instruction. A data breakpoint stops just after the access, so
            // step back onto the instruction that made it.
            ea_t pc = (ea_t)(uint64_t)cur()->GetProgramCounter();
            if ( pc != target && m_lastHitData )
                cur()->ReplayBackward(TtdPosition::Min, StepCount{ 1 });
            m_lastHitData = false;
            return StopReason::Breakpoint;
        }
        IReplayEngine *e = m_backend->engine();
        TtdPosition p = cur()->GetPosition();
        if ( forward && !(p < e->GetLastPosition()) )
            return StopReason::TraceBoundary;
        if ( !forward && !(e->GetFirstPosition() < p) )
            return StopReason::TraceBoundary;
        return StopReason::Stepped;
    }

    StopReason MsTtdNavigator::step(bool forward)
    {
        EventType sr = navigate_steps(forward, StepCount{ 1 });
        // The access is the stepped instruction's own: the step completed.
        if ( sr == EventType::MemoryWatchpoint && m_lastHitData )
        {
            m_lastHitData = false;
            sr = EventType::Position;
        }
        return settle(sr, forward);
    }

    StopReason MsTtdNavigator::run(bool forward)
    {
        if ( !forward && data_hit_just_before() )
            return StopReason::Breakpoint;
        if ( forward )
            step_past_own_access();
        return settle(navigate_steps(forward, StepCount::Max), forward);
    }

    StopReason MsTtdNavigator::step_over(bool forward)
    {
        // IDA has no RESMOD_BACKOVER: "step over backwards" arrives as
        // ev_set_backwards plus RESMOD_OVER, and is a real backward step-over.
        EventType sr = forward ? navigate_over(false) : navigate_over_backward();
        return settle(sr, forward);
    }

    StopReason MsTtdNavigator::step_out(bool forward)
    {
        // Likewise: backward step-out is the frame walk, not one step.
        EventType sr = forward ? navigate_over(true) : navigate_out_backward();
        return settle(sr, forward);
    }

    StopReason MsTtdNavigator::run_to(ea_t addr, bool forward)
    {
        if ( !forward && data_hit_just_before() )
            return StopReason::Breakpoint;
        if ( forward && step_past_own_access()
          && (ea_t)(uint64_t)cur()->GetProgramCounter() == addr )
            return StopReason::Stepped;
        EventType sr = forward ? navigate_forward_to(addr) : navigate_backward_to(addr);
        StopReason r = settle(sr, forward, addr);
        // The target is a temporary watchpoint, so reaching it reads as a
        // watchpoint stop; it is the movement completing, unless a user
        // breakpoint somewhere else stopped it first.
        if ( r == StopReason::Breakpoint && (ea_t)(uint64_t)cur()->GetProgramCounter() == addr )
            return StopReason::Stepped;
        return r;
    }

    StopReason MsTtdNavigator::seek_to(Position p)
    {
        return m_cursor->seek(p) ? StopReason::Stepped : StopReason::Failed;
    }

    //=======================================================================
    // The strategies
    //=======================================================================
    EventType MsTtdNavigator::navigate_steps(bool forward, StepCount steps)
    {
        // A bounded step must start from a recorded position: one step
        // backward from the end-of-trace sentinel runs to the start instead.
        if ( steps != StepCount::Max )
            m_cursor->clamp_to_trace();
        const TtdPosition before = cur()->GetPosition();

        ICursorView::ReplayResult r = forward
            ? cur()->ReplayForward(TtdPosition::Max, steps)
            : cur()->ReplayBackward(TtdPosition::Min, steps);

        // An execute breakpoint on the instruction the replay starts from
        // fires before it runs, so the movement stopped where it was. A step
        // or a run from there must still execute it, as in a debugger that
        // steps over the breakpoint it is stopped on. IDA sets one there
        // itself when stepping from pseudocode, and the step then reported a
        // breakpoint without moving, which IDA's statement stepping could
        // answer by running on to the end of the recording.
        if ( r.StopReason == EventType::MemoryWatchpoint && !m_lastHitData
          && cur()->GetPosition() == before )
        {
            r = forward
              ? cur()->ReplayForward(TtdPosition::Max, steps)
              : cur()->ReplayBackward(TtdPosition::Min, steps);
        }

        // A bounded backward step that lands on the first position jumped to
        // the start instead of stepping; say so.
        if ( !forward && steps != StepCount::Max )
        {
            const TtdPosition after = cur()->GetPosition();
            const TtdPosition first = m_backend->engine()->GetFirstPosition();
            if ( first.IsValid() && after <= first && before.Sequence != first.Sequence )
            {
                msttd_log("[ida-ttd] backward step from %llX:%llX landed at the start of "
                    "the trace (%llX:%llX) instead of stepping.\n",
                    (uint64_t)before.Sequence, (uint64_t)before.Steps,
                    (uint64_t)after.Sequence, (uint64_t)after.Steps);
            }
        }
        return r.StopReason;
    }

    bool MsTtdNavigator::add_temp_exec_watchpoint(ea_t addr, MemoryWatchpointData &wp)
    {
        wp = MemoryWatchpointData{};
        wp.Address    = GuestAddress{ (uint64_t)addr };
        wp.Size       = 1;
        wp.AccessMask = DataAccessMask::Execute;
        // An identical user breakpoint is the same watchpoint to the engine;
        // removing "ours" afterwards would delete the user's.
        if ( m_userWatchpoints.find(wp) != m_userWatchpoints.end() )
            return false;
        return cur()->AddMemoryWatchpoint(wp);
    }

    void MsTtdNavigator::drop_temp_exec_watchpoint(const MemoryWatchpointData &wp, bool owned)
    {
        if ( owned )
            cur()->RemoveMemoryWatchpoint(wp);
    }

    // Run forward to 'addr' on a specific thread and frame, honouring breakpoints.
    MsTtdNavigator::RunStop MsTtdNavigator::run_to_addr_guarded(ea_t addr, uint64_t min_sp, uint32_t utid)
    {
        MemoryWatchpointData wp{};
        bool owned = add_temp_exec_watchpoint(addr, wp);

        // The callback is shared by all watchpoints on the cursor: accept the
        // step target only on the right thread and frame, but always stop on
        // any other (user) breakpoint.
        auto stop_cb = [this, addr, min_sp, utid](ICursorView::MemoryWatchpointResult const &w,
                                                  IThreadView const *t) noexcept -> bool
        {
            if ( (uint64_t)w.Address == (uint64_t)addr && w.AccessType != DataAccessType::Read
              && w.AccessType != DataAccessType::Write && w.AccessType != DataAccessType::Overwrite )
            {
                m_lastHitData = false;
                return (uint32_t)t->GetThreadInfo().UniqueId == utid
                    && (uint64_t)t->GetStackPointer() >= min_sp;
            }
            m_lastHitData = is_data_access(w.AccessType);
            return true; // user breakpoint
        };
        cur()->SetMemoryWatchpointCallback(stop_cb);
        cur()->SetEventMask(EventMask::MemoryWatchpoint);

        ICursorView::ReplayResult r = cur()->ReplayForward();

        drop_temp_exec_watchpoint(wp, owned);
        record_hits();
        restore_event_mask();

        if ( r.StopReason != EventType::MemoryWatchpoint )
            return RunStop::TraceBoundary;
        return (ea_t)(uint64_t)cur()->GetProgramCounter() == addr ? RunStop::Reached : RunStop::Breakpoint;
    }

    // Run backward to 'addr': a temporary Execute watchpoint and one backward
    // replay, which the engine answers by seeking straight to the previous
    // execution (no backward single-step loop).
    EventType MsTtdNavigator::navigate_backward_to(ea_t addr)
    {
        MemoryWatchpointData wp{};
        bool owned = add_temp_exec_watchpoint(addr, wp);
        cur()->SetEventMask(EventMask::MemoryWatchpoint);
        ICursorView::ReplayResult r = cur()->ReplayBackward();
        drop_temp_exec_watchpoint(wp, owned);
        restore_event_mask();
        return r.StopReason;
    }

    // Run forward to 'addr' the same way. If the cursor is already on 'addr',
    // step once first, so the run reaches the next occurrence.
    EventType MsTtdNavigator::navigate_forward_to(ea_t addr)
    {
        if ( (ea_t)(uint64_t)cur()->GetProgramCounter() == addr )
            cur()->ReplayForward(TtdPosition::Max, StepCount{ 1 });
        MemoryWatchpointData wp{};
        bool owned = add_temp_exec_watchpoint(addr, wp);
        cur()->SetEventMask(EventMask::MemoryWatchpoint);
        ICursorView::ReplayResult r = cur()->ReplayForward();
        drop_temp_exec_watchpoint(wp, owned);
        restore_event_mask();
        return r.StopReason;
    }

    // Forward step-out without stepping: find the call that entered the frame
    // and run to its return address, accepting the hit only on this thread
    // with the stack back where it was at the call (a recursive call's return
    // to the same address happens deeper). One frame search and one replay,
    // where the step loop can take a hundred thousand single steps. 'origin'
    // is where the movement began, to go back to when the frame never
    // returns. Called part-way through a step-out, never on its first
    // instruction, so any data access from here on is a stop.
    bool MsTtdNavigator::step_out_by_entry(EventType *result, const TtdPosition &origin)
    {
        const uint64_t    start_sp  = (uint64_t)cur()->GetStackPointer();
        const uint32_t    utid      = (uint32_t)cur()->GetThreadInfo().UniqueId;

        MsTtdBackend::FrameEntry fe;
        bool cancelled = false;
        if ( !find_frame_entry_position(fe, cancelled) )
        {
            if ( !cancelled )
                return false;
            *result = EventType::Position;          // stay where it started
            return true;
        }

        // The stack pointer at the call itself, before its push: the callback
        // that found the call may report it either side of the push. Inside
        // the callee the stack is lower, or the call found is not this
        // frame's, and the step loop decides instead.
        ICursorView *fc = frame_cursor();
        if ( fc == nullptr || fe.ret_addr == 0 )
            return false;
        fc->SetPosition(fe.pos);
        if ( (uint32_t)fc->GetThreadInfo().UniqueId != utid )
            return false;
        const uint64_t call_sp = (uint64_t)fc->GetStackPointer();
        if ( call_sp <= start_sp )
            return false;
        const ea_t ret = (ea_t)fe.ret_addr;

        switch ( run_to_addr_guarded(ret, call_sp, utid) )
        {
            case RunStop::Reached:
                *result = EventType::Position;
                break;
            case RunStop::Breakpoint:
                *result = EventType::MemoryWatchpoint;
                break;
            case RunStop::TraceBoundary:
                // The recording ended before the frame unwound, which is no
                // answer to "step out": stay where it started.
                cur()->SetPosition(origin);
                m_notice = "This frame does not return anywhere in the "
                           "recording, so there is nothing to step out to.\n\n"
                           "The position has been left where it was.";
                *result = EventType::Position;
                break;
        }
        return true;
    }

    // Forward step-over and step-out on the playhead: step over a call by
    // running to the return site; step out by repeating until the frame is
    // unwound. Single instructions are stepped directly.
    //
    // A step-out first single-steps a short budget: most frames end within
    // it, sooner than the frame search and seek of step_out_by_entry (tens
    // to hundreds of milliseconds) would. A frame still running after it is
    // left by the entering call's return, and the loop goes on only when that
    // call cannot be found.
    EventType MsTtdNavigator::navigate_over(bool step_out)
    {
        TtdPosition start_pos = cur()->GetPosition();
        uint64_t    start_sp  = (uint64_t)cur()->GetStackPointer();
        uint32_t    utid      = (uint32_t)cur()->GetThreadInfo().UniqueId;
        bool hit_bpt  = false;
        bool boundary = false;      // ran out of recording rather than unwinding

        // Both can run long: stepping over a call that never returns replays
        // to the end of the trace, and step-out repeats until the frame
        // unwinds. The core's progress sink keeps Cancel working between
        // iterations.
        const int CAP = 100000;                 // backstop against a pathological frame
        const int kQuickSteps = 64;             // step-out's budget before the frame search
        int iters = 0;
        for ( ;; )
        {
            if ( cancelled() )
                break;
            if ( ++iters > CAP )
            {
                msttd_log("[ida-ttd] step out: giving up after %d iterations without unwinding the frame.\n", CAP);
                break;
            }

            ea_t      pc = (ea_t)(uint64_t)cur()->GetProgramCounter();
            X86Branch br = branch_here();
            int  len     = br.len;
            bool is_call = br.is_call;
            bool is_ret  = br.is_ret;

            if ( is_call )
            {
                // Guard on this call's stack pointer, not the frame's: at a
                // nested call the stack is below start_sp, so guarding on it
                // would reject the very return being waited for.
                uint64_t call_sp = (uint64_t)cur()->GetStackPointer();
                // The call's own push is not a stop (step_past_own_access).
                if ( iters == 1 )
                    step_past_own_access();
                RunStop oc = run_to_addr_guarded((ea_t)((uint64_t)pc + len), call_sp, utid);
                if ( oc == RunStop::Breakpoint ) { hit_bpt = true; break; }
                if ( oc == RunStop::TraceBoundary ) { boundary = true; break; }
            }
            else
            {
                ICursorView::ReplayResult r = cur()->ReplayForward(TtdPosition::Max, StepCount{ 1 });
                // On the first instruction an access is its own, not a stop;
                // later in a step-out it is one.
                bool own = iters == 1 && m_lastHitData;
                if ( r.StopReason == EventType::MemoryWatchpoint && !own ) { hit_bpt = true; break; }
                m_lastHitData = false;
                if ( r.StopReason == EventType::Position
                  || r.StopReason == EventType::Process
                  || r.StopReason == EventType::Error )
                {
                    boundary = true;
                    break;
                }
            }

            if ( !step_out )
                break;                                  // step-over: a single iteration
            // Step-out: done once a RET takes the stack above where it
            // started. The rise alone is not enough; an epilogue's 'add rsp'
            // does that a few instructions before the RET.
            if ( is_ret && (uint64_t)cur()->GetStackPointer() > start_sp )
                break;
            if ( iters == kQuickSteps )
            {
                EventType ev;
                if ( step_out_by_entry(&ev, start_pos) )
                    return ev;
            }
        }

        // The recording ended before the frame unwound, which is no answer to
        // "step out": stay where it started.
        if ( step_out && boundary && (uint64_t)cur()->GetStackPointer() <= start_sp )
        {
            cur()->SetPosition(start_pos);
            m_notice = "This frame does not return anywhere in the "
                       "recording, so there is nothing to step out to.\n\n"
                       "The position has been left where it was.";
        }
        return hit_bpt ? EventType::MemoryWatchpoint : EventType::Position;
    }

    ICursorView *MsTtdNavigator::frame_cursor()
    {
        if ( !m_frameCursor )
        {
            m_frameCursor = m_backend->new_engine_cursor();
            if ( m_frameCursor )
                m_frameCursor->SetReplayFlags(ReplayFlags::ReplayAllSegmentsWithoutFiltering
                                            | ReplayFlags::ReplaySegmentsSequentially);
        }
        return m_frameCursor.get();
    }

    // Find the CALL that entered the playhead's frame, so the caller can seek
    // straight to it or run to its return (MsTtdBackend::find_frame_entry).
    bool MsTtdNavigator::find_frame_entry_position(MsTtdBackend::FrameEntry &out, bool &cancelled)
    {
        cancelled = false;
        out       = MsTtdBackend::FrameEntry{};
        if ( frame_cursor() == nullptr )
            return false;

        // Look-back schedule: a slice of the current sequence, then all of
        // it, then ever more whole sequences. Capped, or a frame entered near
        // the start of a long recording would mean replaying all of it.
        // Sequence ids advance unevenly, hence widening well past 64.
        using Kind = MsTtdBackend::FrameWindowKind;
        static const MsTtdBackend::FrameWindow kWindows[] = {
            { Kind::InSequence, 4096  }, { Kind::InSequence, 65536 },
            { Kind::Sequences,  1     }, { Kind::Sequences,  4     }, { Kind::Sequences, 16    },
            { Kind::Sequences,  64    }, { Kind::Sequences,  256   }, { Kind::Sequences, 1024  },
            { Kind::Sequences,  4096  }, { Kind::Sequences,  16384 },
        };
        MsTtdBackend::FrameSearch fs = m_backend->find_frame_entry(
            m_frameCursor.get(), cur()->GetPosition(), (uint32_t)cur()->GetThreadInfo().UniqueId,
            (uint64_t)cur()->GetStackPointer(), kWindows, qnumber(kWindows), m_progress, true, &out);
        cancelled = fs == MsTtdBackend::FrameSearch::Cancelled;
        return fs == MsTtdBackend::FrameSearch::Found;
    }

    X86Branch MsTtdNavigator::branch_here()
    {
        uint8_t b[16] = { 0 };
        ea_t pc = (ea_t)(uint64_t)cur()->GetProgramCounter();
        MemoryBuffer mb = cur()->QueryMemoryBuffer(GuestAddress{ (uint64_t)pc }, BufferView{ b, sizeof(b) },
                                                   QueryMemoryPolicy::GloballyAggressive);
        // A 32-bit thread of a 64-bit process (WoW64) runs with CS 0x23.
        bool is64 = m_backend->is64();
        if ( is64 )
        {
            CROSS_PLATFORM_CONTEXT ctx = cur()->GetCrossPlatformContext();
            if ( ctx.Amd64Context.SegCs == 0x23 )
                is64 = false;
        }
        return x86_branch(b, (size_t)mb.Memory.Size, is64);
    }

    EventType MsTtdNavigator::rewind_to(const TtdPosition &p)
    {
        // One engine call, not a step loop. User breakpoints stay armed, so a
        // hit between here and 'p' stops the run there.
        ICursorView::ReplayResult r = cur()->ReplayBackward(p);
        return r.StopReason == EventType::MemoryWatchpoint ? EventType::MemoryWatchpoint
                                                            : EventType::Position;
    }

    EventType MsTtdNavigator::navigate_out_backward()
    {
        MsTtdBackend::FrameEntry entry;
        bool cancelled = false;
        if ( !find_frame_entry_position(entry, cancelled) )
        {
            if ( !cancelled )
                m_notice = "Could not find the call that entered this frame.\n\n"
                           "It happened further back than the search window "
                           "reaches, or this thread is in its outermost frame.";
            return EventType::Position;     // leave the cursor where it is
        }
        return rewind_to(entry.pos);
    }

    // Backward step-over: one backward step; if that landed on the tail of a
    // callee that had just returned (same thread, deeper frame), rewind on out
    // of it to the CALL that entered it.
    EventType MsTtdNavigator::navigate_over_backward()
    {
        const uint64_t start_sp = (uint64_t)cur()->GetStackPointer();
        const uint32_t utid     = (uint32_t)cur()->GetThreadInfo().UniqueId;

        ICursorView::ReplayResult r = cur()->ReplayBackward(TtdPosition::Min, StepCount{ 1 });
        const bool hit_bpt = r.StopReason == EventType::MemoryWatchpoint;

        // A lower stack pointer alone is not enough (stepping back over a
        // 'pop' does that too): a returning callee is identified by landing on
        // its RET with the stack lower, on the same thread.
        bool deeper = false;
        if ( !hit_bpt
          && (uint32_t)cur()->GetThreadInfo().UniqueId == utid
          && (uint64_t)cur()->GetStackPointer() < start_sp )
        {
            deeper = branch_here().is_ret;
        }

        if ( deeper )
        {
            // If the entering call cannot be found, stay on the RET: the step
            // already moved, and a popup would be noise for "step back one".
            MsTtdBackend::FrameEntry entry;
            bool cancelled = false;
            if ( find_frame_entry_position(entry, cancelled) )
                return rewind_to(entry.pos);
        }
        return hit_bpt ? EventType::MemoryWatchpoint : EventType::Position;
    }
}
