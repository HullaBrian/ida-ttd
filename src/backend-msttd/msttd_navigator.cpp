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
    }

    MsTtdNavigator::~MsTtdNavigator()
    {
        // The watchpoints live on the cursor, which outlives this navigator.
        for ( const MemoryWatchpointData &wp : m_userWatchpoints )
            cur()->RemoveMemoryWatchpoint(wp);
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

    StopReason MsTtdNavigator::settle(EventType sr, bool forward)
    {
        // Do this FIRST and unconditionally: a run that reached either end of
        // the trace leaves the cursor on the limit sentinel, not on a real
        // recorded position.
        m_cursor->clamp_to_trace();

        // A breakpoint stop is not a trace edge.
        if ( sr == EventType::MemoryWatchpoint )
            return StopReason::Breakpoint;
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
        return settle(navigate_steps(forward, StepCount{ 1 }), forward);
    }

    StopReason MsTtdNavigator::run(bool forward)
    {
        return settle(navigate_steps(forward, StepCount::Max), forward);
    }

    StopReason MsTtdNavigator::step_over(bool forward)
    {
        // IDA has no RESMOD_BACKOVER: "step over backwards" arrives as
        // ev_set_backwards plus the ordinary RESMOD_OVER, and is a real
        // backward step-over, not a plain backward step.
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
        EventType sr = forward ? navigate_forward_to(addr) : navigate_backward_to(addr);
        StopReason r = settle(sr, forward);
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
        // A bounded step must start from a position that exists in the
        // recording. Replaying backward "one step" from the end-of-trace
        // sentinel does not move one instruction -- it runs to the start.
        if ( steps != StepCount::Max )
            m_cursor->clamp_to_trace();
        const TtdPosition before = cur()->GetPosition();

        ICursorView::ReplayResult r = forward
            ? cur()->ReplayForward(TtdPosition::Max, steps)
            : cur()->ReplayBackward(TtdPosition::Min, steps);

        // A bounded backward step that lands on the trace's first position
        // moved to the start instead of stepping. Say so rather than silently
        // teleporting the user.
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
        // An identical user breakpoint is this watchpoint as far as the engine
        // is concerned. Leave it alone: removing "ours" afterwards would
        // silently delete the user's breakpoint.
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
        auto stop_cb = [addr, min_sp, utid](ICursorView::MemoryWatchpointResult const &w,
                                            IThreadView const *t) noexcept -> bool
        {
            if ( (uint64_t)w.Address == (uint64_t)addr )
                return (uint32_t)t->GetThreadInfo().UniqueId == utid
                    && (uint64_t)t->GetStackPointer() >= min_sp;
            return true; // user breakpoint
        };
        cur()->SetMemoryWatchpointCallback(stop_cb);
        cur()->SetEventMask(EventMask::MemoryWatchpoint);

        ICursorView::ReplayResult r = cur()->ReplayForward();

        drop_temp_exec_watchpoint(wp, owned);
        cur()->SetMemoryWatchpointCallback(nullptr, 0);
        restore_event_mask();

        if ( r.StopReason != EventType::MemoryWatchpoint )
            return RunStop::TraceBoundary;
        return (ea_t)(uint64_t)cur()->GetProgramCounter() == addr ? RunStop::Reached : RunStop::Breakpoint;
    }

    // Run backward to 'addr': a temporary Execute watchpoint and one backward
    // replay, which the engine answers by seeking straight to the previous
    // execution of 'addr' -- not a backward single-step loop.
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
    // step once first so we advance to the next occurrence.
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

    // Forward step-over and step-out on the playhead: step over a call by
    // running to the return site; step out by repeating until the frame is
    // unwound. Single instructions are stepped directly.
    EventType MsTtdNavigator::navigate_over(bool step_out)
    {
        TtdPosition start_pos = cur()->GetPosition();
        uint64_t    start_sp  = (uint64_t)cur()->GetStackPointer();
        uint32_t    utid      = (uint32_t)cur()->GetThreadInfo().UniqueId;
        bool hit_bpt  = false;
        bool boundary = false;      // ran out of recording rather than unwinding

        // Both can run for a long time: stepping over a call that never
        // returns replays to the END of the trace, and step-out repeats that
        // until the frame unwinds. The core's progress sink is what keeps
        // Cancel working between iterations.
        const int CAP = 100000;                 // backstop against a pathological frame
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
                // The guard belongs to THIS call, not to the frame being
                // stepped out of: by a nested call the stack has grown past
                // the frame's entry level, so guarding on start_sp would
                // reject the very return being waited for.
                uint64_t call_sp = (uint64_t)cur()->GetStackPointer();
                RunStop oc = run_to_addr_guarded((ea_t)((uint64_t)pc + len), call_sp, utid);
                if ( oc == RunStop::Breakpoint ) { hit_bpt = true; break; }
                if ( oc == RunStop::TraceBoundary ) { boundary = true; break; }
            }
            else
            {
                ICursorView::ReplayResult r = cur()->ReplayForward(TtdPosition::Max, StepCount{ 1 });
                if ( r.StopReason == EventType::MemoryWatchpoint ) { hit_bpt = true; break; }
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
            // Step-out: the frame has returned once a RET took the stack above
            // where it started. The rise alone is not the test -- an epilogue's
            // 'add rsp' does that a few instructions before the RET.
            if ( is_ret && (uint64_t)cur()->GetStackPointer() > start_sp )
                break;
        }

        // The recording ran out before the frame unwound: the end of the
        // recording is not an answer to "step out", so stay where we were.
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

    // Find the CALL instruction that entered the frame the playhead stands in,
    // so the caller can seek straight to it in one engine hop.
    //
    // Never by single-stepping backward -- that re-seeks a keyframe per step
    // and takes minutes. Instead: seek to a position before the playhead and
    // replay forward to it, tracking a per-thread stack of open calls; the top
    // of our thread's stack at the playhead is the call we want. The window
    // widens until it captures that call.
    bool MsTtdNavigator::find_frame_entry_position(TtdPosition &out, bool &cancelled)
    {
        cancelled = false;
        out       = TtdPosition::Invalid;
        if ( frame_cursor() == nullptr )
            return false;

        IReplayEngine *engine = m_backend->engine();
        const TTD::Replay::ThreadInfo &ti = cur()->GetThreadInfo();
        const uint32_t    tid  = (uint32_t)ti.UniqueId;
        const TtdPosition last = engine->GetLastPosition();

        // Floor for the search: nothing this thread did lies before its
        // ActiveTime, so a window reaching it without an open call means the
        // thread really is in its outermost frame.
        TtdPosition first = engine->GetFirstPosition();
        if ( ti.ActiveTime.Min.IsValid() && first < ti.ActiveTime.Min )
            first = ti.ActiveTime.Min;

        // Work from a position that exists, and that this thread reached: the
        // end of the recording can belong to another thread, and a window
        // ending there holds none of this one's instructions.
        TtdPosition here = cur()->GetPosition();
        if ( last.IsValid() && here > last )
            here = last;
        if ( ti.ActiveTime.Max.IsValid() && here > ti.ActiveTime.Max )
            here = ti.ActiveTime.Max;
        if ( first.IsValid() && here < first )
            here = first;

        // A CALL pushes, a RET pops. A RET with nothing on the stack is a frame
        // already open when the window began; ignoring it is what makes a
        // partial window still give the right answer.
        struct Open { TtdPosition pos; uint64_t sp; };
        std::map<uint32_t, std::vector<Open>> stacks;
        uint64_t seen_all  = 0;
        uint64_t seen_mine = 0;
        auto on_call_ret = [&](GuestAddress, GuestAddress fall_through, IThreadView const *t) noexcept
        {
            // Engine callbacks are noexcept: cap the depth rather than let an
            // allocation throw in here.
            static const size_t kMaxDepth = 8192;
            uint32_t utid = (uint32_t)t->GetThreadInfo().UniqueId;
            seen_all++;
            if ( utid == tid )
                seen_mine++;
            try
            {
                if ( (uint64_t)fall_through != 0 )
                {
                    std::vector<Open> &st = stacks[utid];
                    if ( st.size() < kMaxDepth )
                        st.push_back(Open{ t->GetPosition(), (uint64_t)t->GetStackPointer() });
                }
                else
                {
                    auto it = stacks.find(utid);
                    if ( it != stacks.end() && !it->second.empty() )
                        it->second.pop_back();
                }
            }
            catch ( ... )
            {
            }
        };

        // Look-back schedule: a slice of the current sequence, then the whole
        // of it, then progressively more whole sequences. Capped: a frame
        // entered near the start of a long recording would otherwise mean
        // replaying all of it. Sequence ids do not advance at a uniform rate,
        // which is why the schedule keeps widening well past 64.
        struct Attempt { bool by_steps; uint64_t back; };
        static const Attempt kAttempts[] = {
            { true,  4096  }, { true,  65536 },
            { false, 1     }, { false, 4     }, { false, 16    },
            { false, 64    }, { false, 256   }, { false, 1024  },
            { false, 4096  }, { false, 16384 },
        };

        // Not every call is matched by a RET: one that leaves by a syscall, a
        // context switch or an exception stays open on the stack forever. The
        // call that entered this frame is the innermost open one made from a
        // shallower frame -- at or above the stack pointer here (at the
        // callee's first instruction the two can be equal, depending on whether
        // the engine reports the stack before or after the call's push).
        // Anything below it is one of those deeper calls that never came back.
        const uint64_t here_sp = (uint64_t)cur()->GetStackPointer();

        bool        found     = false;
        TtdPosition lastStart = TtdPosition::Invalid;
        TtdPosition winStart  = TtdPosition::Invalid;
        uint64_t    winInsns  = 0;
        for ( size_t i = 0; i < qnumber(kAttempts) && !found; i++ )
        {
            if ( this->cancelled() )
            {
                cancelled = true;
                break;
            }
            if ( m_progress != nullptr )
                m_progress->report((uint32_t)(i * 100 / qnumber(kAttempts)));

            TtdPosition s = here;
            if ( kAttempts[i].by_steps )
            {
                uint64_t st = (uint64_t)here.Steps;
                s.Steps = (StepCount)(st > kAttempts[i].back ? st - kAttempts[i].back : 0);
            }
            else
            {
                uint64_t sq = (uint64_t)here.Sequence;
                uint64_t bk = kAttempts[i].back;
                s.Sequence = (SequenceId)(sq > bk ? sq - bk : 0);
                s.Steps    = StepCount::Min;
            }
            if ( s < first )
                s = first;
            if ( s == lastStart )
                continue;           // the step-based windows collapse near a sequence start
            lastStart = s;

            stacks.clear();
            seen_all  = 0;
            seen_mine = 0;
            m_frameCursor->SetPosition(s);
            m_frameCursor->SetCallReturnCallback(on_call_ret);
            ICursorView::ReplayResult rr = m_frameCursor->ReplayForward(here);
            m_frameCursor->SetCallReturnCallback(nullptr, 0);
            winStart = s;
            winInsns = (uint64_t)rr.InstructionsExecuted;

            auto it = stacks.find(tid);
            if ( it != stacks.end() )
            {
                for ( auto o = it->second.rbegin(); o != it->second.rend(); ++o )
                    if ( o->sp >= here_sp )
                    {
                        out   = o->pos;
                        found = true;
                        break;
                    }
                if ( found )
                    break;
            }
            if ( !(first < s) )
                break;      // the window already reached the start of the trace
        }
        if ( !found && !cancelled )
        {
            // A thread really in its outermost frame and a window that replayed
            // nothing look the same in the popup; say which.
            msttd_log("[ida-ttd] no entering call for thread %X searching back from "
                "%llX:%llX. Last window %llX:%llX replayed %llu instructions, "
                "%llu call/ret events, %llu of them on this thread.\n",
                tid, (uint64_t)here.Sequence, (uint64_t)here.Steps,
                (uint64_t)winStart.Sequence, (uint64_t)winStart.Steps,
                winInsns, seen_all, seen_mine);
        }
        return found;
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
        // One engine call rather than a step loop. User breakpoints stay
        // armed, so anything hit between here and 'p' stops us there instead.
        ICursorView::ReplayResult r = cur()->ReplayBackward(p);
        return r.StopReason == EventType::MemoryWatchpoint ? EventType::MemoryWatchpoint
                                                            : EventType::Position;
    }

    EventType MsTtdNavigator::navigate_out_backward()
    {
        TtdPosition entry;
        bool        cancelled = false;
        if ( !find_frame_entry_position(entry, cancelled) )
        {
            if ( !cancelled )
                m_notice = "Could not find the call that entered this frame.\n\n"
                           "It happened further back than the search window "
                           "reaches, or this thread is in its outermost frame.";
            return EventType::Position;     // leave the cursor where it is
        }
        return rewind_to(entry);
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

        // A lower stack pointer alone is not the test -- stepping back over a
        // 'pop' does that too. What identifies a returning callee is landing
        // on its RET with the return address still stacked: both, on the same
        // thread.
        bool deeper = false;
        if ( !hit_bpt
          && (uint32_t)cur()->GetThreadInfo().UniqueId == utid
          && (uint64_t)cur()->GetStackPointer() < start_sp )
        {
            deeper = branch_here().is_ret;
        }

        if ( deeper )
        {
            // If the entering call cannot be found we stay on the RET: the step
            // already moved, and a popup would be noise for "step back one".
            TtdPosition entry;
            bool        cancelled = false;
            if ( find_frame_entry_position(entry, cancelled) )
                return rewind_to(entry);
        }
        return hit_bpt ? EventType::MemoryWatchpoint : EventType::Position;
    }
}
