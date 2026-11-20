// SPDX-License-Identifier: GPL-2.0-only
//
// ida-ttd's Sogen backend: stepping and running a cursor, and finding the
// call that entered a frame.
// See sogen_state.h.

#include "backend-sogen/sogen_state.h"
#include "backend-sogen/sogen_insn.h"

namespace idattd::sogen
{
    // ------------------------------------------------------------ navigation

    // A single step moves one position, on whichever thread runs next: that
    // is what a Sogen position is, and it matches "step into" on a recording.
    int nav_step(ittd_cursor *hc, int forward, int *out_stop)
    {
        cursor_t *c = C(hc);
        if ( c == nullptr )
            return ITTD_E_BAD_ARG;
        const ttd::trace &t = *c->trace;
        int stop = ITTD_STOP_STEPPED;
        if ( forward )
        {
            if ( c->position >= last_position(t) )
                stop = ITTD_STOP_BOUNDARY;
            else
                move(c, c->position + 1);
        }
        else
        {
            if ( c->position <= first_position(t) )
                stop = ITTD_STOP_BOUNDARY;
            else
                move(c, c->position - 1);
        }
        if ( out_stop != nullptr )
            *out_stop = stop;
        return ITTD_OK;
    }

    // The next (or previous) execution of an instruction covering 'a', by step.
    //
    // Covering, not starting at: that is what an execute breakpoint means to
    // Microsoft's engine, and IDA relies on it. Its backward step-over puts
    // the temporary breakpoint on the return address minus one (the call's
    // last byte) and runs backward to it.
    //
    // next_access(s) answers steps above s, previous_access(s) steps below s.
    // At cursor position p the instruction about to run is step p + 1, so a
    // forward run looks at steps after it and a backward run at steps up to
    // p, the last one that already ran.
    std::optional<uint64_t> execution_of(ttd::trace &t, uint64_t a, uint64_t position, bool forward)
    {
        const uint64_t X = (uint64_t)ttd::access_kind::execute;
        std::optional<ttd::access_event> ev = forward ? t.next_access(a, 1, position + 1, X)
                                                      : t.previous_access(a, 1, position + 1, X);
        if ( !ev )
            return std::nullopt;
        return ev->step;
    }

    // The next (or previous) read or write of any byte of [a, a + size), by
    // step, with the same convention as execution_of. A host write (a syscall
    // writing guest memory) counts as a write.
    std::optional<uint64_t> access_of(ttd::trace &t, const ittd_breakpoint &b, uint64_t position,
                                      bool forward)
    {
        const uint64_t mask = sogen_mask(b.kinds & (ITTD_ACCESS_READ | ITTD_ACCESS_WRITE));
        if ( mask == 0 )
            return std::nullopt;
        uint64_t size = b.size == 0 ? 1 : b.size;
        std::optional<ttd::access_event> ev = forward ? t.next_access(b.addr, size, position + 1, mask)
                                                      : t.previous_access(b.addr, size, position + 1, mask);
        if ( !ev )
            return std::nullopt;
        return ev->step;
    }

    // The nearest hit of any of 'bpts' after (or before) the cursor, as the
    // position just before the instruction that hit it, and which breakpoint
    // it was. Each breakpoint is a page-index lookup; nothing is replayed.
    bool nearest_hit(cursor_t *c, const std::vector<ittd_breakpoint> &bpts, bool forward,
                     uint64_t *out_pos, size_t *out_index)
    {
        bool found = false;
        uint64_t best = 0;
        for ( size_t i = 0; i < bpts.size(); i++ )
        {
            const ittd_breakpoint &b = bpts[i];
            std::optional<uint64_t> steps[2];
            if ( b.kinds & ITTD_ACCESS_EXEC )
                steps[0] = execution_of(*c->trace, b.addr, c->position, forward);
            steps[1] = access_of(*c->trace, b, c->position, forward);
            for ( const std::optional<uint64_t> &step : steps )
            {
                if ( !step )
                    continue;
                if ( !found || (forward ? *step < best : *step > best) )
                {
                    best       = *step;
                    *out_index = i;
                    found      = true;
                }
            }
        }
        if ( found )
            *out_pos = best - 1;
        return found;
    }

    ittd_breakpoint exec_bp(uint64_t addr)
    {
        ittd_breakpoint b{};
        b.addr  = addr;
        b.size  = 1;
        b.kinds = ITTD_ACCESS_EXEC;
        return b;
    }

    // The stack pointer of the thread about to run after 'position', or
    // nothing when the state there cannot be rebuilt.
    std::optional<uint64_t> sp_at(ttd::trace &t, uint64_t position)
    {
        try
        {
            ttd::cpu_view view(t, position);
            return view.read_register(x86_register::rsp);
        }
        catch ( const ttd::divergence_error & )
        {
            return std::nullopt;
        }
    }

    // The call that entered the frame thread 'tid' is in at cursor position
    // 'pos'. Walks the thread's instructions backward from the one about to
    // run, counting returns in and calls out: the first call met at depth
    // zero entered this frame. Each step is a lookup in the thread's runs, so
    // a short walk is cheap enough for every stop.
    //
    // Not every call is matched by a ret: one whose callee left by a syscall,
    // a context switch or an exception looks, walking back, just like the
    // entering call. The stack tells them apart: the entering call was made
    // from a shallower frame, with a stack pointer above the one here, and
    // the others below it. So a call at depth zero is accepted only if its
    // stack pointer (read just before it, where the running thread is
    // certainly this one) was higher. That costs a cpu_view per candidate,
    // and there is rarely more than one.
    //
    // 'check_sp' false skips the check, for callers walking many frames that
    // cannot afford a cpu_view per candidate and accept the small risk.
    //
    // 'progress', when given, can cancel the walk (operation_cancelled), which
    // over kNavFrameWalk instructions takes long enough to want a Cancel.
    std::optional<ttd::access_event> entering_call(ttd::trace &t, uint64_t pos, uint32_t tid,
                                                   uint64_t max_back, bool check_sp,
                                                   const ittd_progress *progress)
    {
        const ttd::operation_control ctl = control(progress);
        std::optional<uint64_t> here_sp = check_sp && thread_after(t, pos) == tid ? sp_at(t, pos)
                                                                                  : std::nullopt;
        uint64_t s = pos + 1;               // the instruction about to run
        int64_t depth = 0;
        for ( uint64_t n = 0; n < max_back; n++ )
        {
            if ( (n & 0x3FFF) == 0x3FFF )
                ctl.check();
            std::optional<ttd::access_event> ev = t.previous_instruction(s, tid);
            if ( !ev )
                break;
            s = ev->step;
            if ( is_ret_insn(*ev) )
            {
                depth++;
            }
            else if ( is_call_insn(*ev) )
            {
                if ( depth == 0 )
                {
                    std::optional<uint64_t> call_sp = here_sp ? sp_at(t, ev->step - 1) : std::nullopt;
                    if ( !here_sp || !call_sp || *call_sp > *here_sp )
                        return ev;
                    continue;               // a deeper call that never returned
                }
                depth--;
            }
        }
        return std::nullopt;
    }

    int query_frame_entry(ittd_backend *hb, ittd_position where, uint32_t tid, uint64_t max_back,
                          ittd_position *out_call, uint64_t *out_entry)
    {
        return query_frame_entry_progress(hb, where, tid, max_back, out_call, out_entry, nullptr);
    }

    // The walk back checks 'progress' every 16,384 instructions
    // (entering_call), so a call tree's search of tens of millions can stop.
    //
    // A search with progress is the call tree's, on the core's worker, and
    // may walk for seconds: it runs on query_reader, as the other long
    // queries do, so the module and thread lists asked for at a stop never
    // wait behind it on 'mtx'. One without is the short, bounded search the
    // main thread makes at every stop, which must not wait behind a long
    // query on the query reader; it keeps the shared reader.
    int query_frame_entry_progress(ittd_backend *hb, ittd_position where, uint32_t tid, uint64_t max_back,
                                   ittd_position *out_call, uint64_t *out_entry, const ittd_progress *progress)
    {
        backend_t *b = B(hb);
        if ( b == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            std::optional<query_reader> reader;
            std::unique_lock<std::mutex> lock;
            if ( progress != nullptr )
                reader.emplace(b);
            else
                lock = std::unique_lock<std::mutex>(b->mtx);
            ttd::trace &t = reader.has_value() ? reader->trace() : *b->trace;
            uint64_t pos = 0;
            if ( !resolve(t, where, &pos) )
                return ITTD_E_NO_POSITION;
            std::optional<ttd::access_event> call = entering_call(t, pos, tid, max_back, true, progress);
            if ( !call )
            {
                b->error.set("no entering call within the search bound");
                return ITTD_E_FAILED;
            }
            std::optional<ttd::access_event> entry = t.next_instruction(call->step, tid);
            if ( out_call != nullptr )
                *out_call = before_step(call->step);
            if ( out_entry != nullptr )
                *out_entry = entry ? entry->ip : 0;
            return ITTD_OK;
        });
    }

    // How far back the navigator looks for the call that entered a frame.
    // Stepping out of a frame that has run longer than this (main, say)
    // reports that no entering call was found instead of walking forever.
    static const uint64_t kNavFrameWalk = 1ull << 22;

    // The step of the ret that returned from the call at 'call_step' on 'tid'.
    // From calls_to, which pairs a call with its ret through the stack slot
    // of the return address, so it is exact under recursion.
    std::optional<uint64_t> return_of(ttd::trace &t, uint64_t call_step, uint32_t tid)
    {
        std::optional<ttd::access_event> entry = t.next_instruction(call_step, tid);
        if ( !entry )
            return std::nullopt;
        for ( const ttd::call_event &e : t.calls_to(entry->ip, entry->step, entry->step) )
            if ( e.step == call_step && e.return_step != UINT64_MAX )
                return e.return_step;
        return std::nullopt;
    }

    // Move to 'dest', unless a breakpoint lies strictly between the cursor and
    // it: then stop on the breakpoint, as a live process would.
    void move_guarded(cursor_t *c, uint64_t dest, bool forward, int *stop)
    {
        uint64_t bp = 0;
        size_t hit = 0;
        if ( !c->breakpoints.empty() && nearest_hit(c, c->breakpoints, forward, &bp, &hit)
          && (forward ? bp > c->position && bp < dest : bp < c->position && bp > dest) )
        {
            dest  = bp;
            *stop = ITTD_STOP_BREAKPOINT;
        }
        move(c, dest);
    }

    // Forward step over: run the instruction about to execute on this thread,
    // and if it is a call, the whole call. The return comes from return_of,
    // which is exact under recursion, unlike "the next time this thread
    // reaches the return address".
    //
    // Backward: step back one instruction on this thread, and if that was a
    // ret, on back to just before the call it returned from.
    int nav_step_over(ittd_cursor *hc, int forward, int *out_stop)
    {
        cursor_t *c = C(hc);
        if ( c == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(c->owner->error, [&]()
        {
            ttd::trace &t = *c->trace;
            uint32_t tid = thread_after(t, c->position);
            int stop = ITTD_STOP_BOUNDARY;
            uint64_t dest = forward ? last_position(t) : first_position(t);
            if ( forward )
            {
                std::optional<ttd::access_event> cur = t.next_instruction(c->position, tid);
                std::optional<ttd::access_event> after = cur ? t.next_instruction(cur->step, tid) : std::nullopt;
                if ( cur && after )
                {
                    if ( is_call_insn(*cur) )
                    {
                        if ( std::optional<uint64_t> ret = return_of(t, cur->step, tid) )
                        {
                            dest = *ret;            // just after the ret
                            stop = ITTD_STOP_STEPPED;
                        }
                    }
                    else
                    {
                        dest = after->step - 1;
                        stop = ITTD_STOP_STEPPED;
                    }
                }
            }
            else if ( std::optional<ttd::access_event> prev = t.previous_instruction(c->position + 1, tid) )
            {
                // 'prev' is the last instruction this thread ran.
                dest = prev->step - 1;
                stop = ITTD_STOP_STEPPED;
                if ( is_ret_insn(*prev) )
                {
                    // Standing just before the ret is standing in the callee.
                    std::optional<ttd::access_event> call =
                        entering_call(t, prev->step - 1, tid, kNavFrameWalk, true, c->progress);
                    if ( call )
                        dest = call->step - 1;
                }
            }
            // A breakpoint inside the call stops the step there, as it would
            // on a live process.
            move_guarded(c, dest, forward != 0, &stop);
            if ( out_stop != nullptr )
                *out_stop = stop;
            return ITTD_OK;
        });
    }

    // The step of the ret that leaves the frame running at 'pos' on 'tid',
    // found walking forward, for when the call that entered the frame is not
    // in the recording: a fork's file starts at its fork position, so a frame
    // entered before that has its call in the parent's file. Calls and rets
    // are paired by depth. A deeper call that never returns by a ret (its
    // callee left by an exception, or by unwinding) would put the frame's
    // own ret at depth one and hide it, as it does walking back in
    // entering_call; so a ret at depth zero is accepted only if its stack
    // pointer is at or above the one here, which every deeper frame's is
    // below, and the stack checked once per candidate.
    static std::optional<uint64_t> frame_return_forward(ttd::trace &t, uint64_t pos, uint32_t tid,
                                                        uint64_t max_forward, const ittd_progress *progress)
    {
        const ttd::operation_control ctl = control(progress);
        std::optional<uint64_t> here_sp = thread_after(t, pos) == tid ? sp_at(t, pos) : std::nullopt;
        uint64_t s = pos;
        int64_t depth = 0;
        for ( uint64_t n = 0; n < max_forward; n++ )
        {
            if ( (n & 0x3FFF) == 0x3FFF )
                ctl.check();
            std::optional<ttd::access_event> ev = t.next_instruction(s, tid);
            if ( !ev )
                break;
            s = ev->step;
            if ( is_call_insn(*ev) )
            {
                depth++;
            }
            else if ( is_ret_insn(*ev) )
            {
                if ( depth == 0 )
                {
                    std::optional<uint64_t> ret_sp = here_sp ? sp_at(t, ev->step - 1) : std::nullopt;
                    if ( !here_sp || !ret_sp || *ret_sp >= *here_sp )
                        return ev->step;    // just after the ret
                    continue;               // a deeper frame's, under a call that never returned
                }
                depth--;
            }
        }
        return std::nullopt;
    }

    // Step out: find the call that entered this frame; backward, stop just
    // before it, forward, just after its ret. Forward with no entering call
    // in the recording (a fork's frame entered before its fork position),
    // the frame's ret is found walking forward instead. With neither in
    // reach (a thread's outermost frame, or one older than the walk), or a
    // call that never returns, the cursor stays put and the error says why.
    int nav_step_out(ittd_cursor *hc, int forward, int *out_stop)
    {
        cursor_t *c = C(hc);
        if ( c == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(c->owner->error, [&]()
        {
            ttd::trace &t = *c->trace;
            uint32_t tid = thread_after(t, c->position);
            std::optional<ttd::access_event> call = entering_call(t, c->position, tid, kNavFrameWalk, true, c->progress);
            uint64_t dest = 0;
            if ( !call && forward )
            {
                std::optional<uint64_t> ret = frame_return_forward(t, c->position, tid, kNavFrameWalk, c->progress);
                if ( !ret )
                {
                    c->owner->error.set("no call entering this frame was found, nor a return from it");
                    return ITTD_E_FAILED;
                }
                dest = *ret;
            }
            else if ( !call )
            {
                c->owner->error.set("no call entering this frame was found");
                return ITTD_E_FAILED;
            }
            else if ( forward )
            {
                std::optional<uint64_t> ret = return_of(t, call->step, tid);
                if ( !ret )
                {
                    c->owner->error.set("this frame does not return within the recording");
                    return ITTD_E_FAILED;
                }
                dest = *ret;                // just after the ret
            }
            else
            {
                dest = call->step - 1;      // just before the call
            }
            int stop = ITTD_STOP_STEPPED;
            move_guarded(c, dest, forward != 0, &stop);
            if ( out_stop != nullptr )
                *out_stop = stop;
            return ITTD_OK;
        });
    }

    int nav_run_to(ittd_cursor *hc, uint64_t addr, int forward, int *out_stop)
    {
        cursor_t *c = C(hc);
        if ( c == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(c->owner->error, [&]()
        {
            std::vector<ittd_breakpoint> targets = c->breakpoints;
            targets.push_back(exec_bp(addr));
            uint64_t p = 0;
            size_t hit = 0;
            int stop = ITTD_STOP_BOUNDARY;
            if ( nearest_hit(c, targets, forward != 0, &p, &hit) )
            {
                move(c, p);
                stop = hit == targets.size() - 1 ? ITTD_STOP_STEPPED : ITTD_STOP_BREAKPOINT;
            }
            else
            {
                move(c, forward ? last_position(*c->trace) : first_position(*c->trace));
            }
            if ( out_stop != nullptr )
                *out_stop = stop;
            return ITTD_OK;
        });
    }

    int nav_run(ittd_cursor *hc, int forward, int *out_stop)
    {
        cursor_t *c = C(hc);
        if ( c == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(c->owner->error, [&]()
        {
            uint64_t p = 0;
            size_t hit = 0;
            int stop = ITTD_STOP_BOUNDARY;
            if ( nearest_hit(c, c->breakpoints, forward != 0, &p, &hit) )
            {
                move(c, p);
                stop = ITTD_STOP_BREAKPOINT;
            }
            else
            {
                move(c, forward ? last_position(*c->trace) : first_position(*c->trace));
            }
            if ( out_stop != nullptr )
                *out_stop = stop;
            return ITTD_OK;
        });
    }

    int nav_set_progress(ittd_cursor *hc, const ittd_progress *progress)
    {
        cursor_t *c = C(hc);
        if ( c == nullptr )
            return ITTD_E_BAD_ARG;
        c->progress = progress;
        return ITTD_OK;
    }

    int nav_breakpoints(ittd_cursor *hc, const ittd_breakpoint *bpts, size_t count)
    {
        cursor_t *c = C(hc);
        if ( c == nullptr || (bpts == nullptr && count != 0) )
            return ITTD_E_BAD_ARG;
        return guarded(c->owner->error, [&]()
        {
            c->breakpoints.assign(bpts, bpts + count);
            return ITTD_OK;
        });
    }
}
