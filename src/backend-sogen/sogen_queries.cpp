// SPDX-License-Identifier: GPL-2.0-only
//
// ida-ttd's Sogen backend: the whole-recording queries, read from the
// recording's events without a replay.
// See sogen_state.h.

#include "backend-sogen/sogen_state.h"
#include "backend-sogen/sogen_insn.h"

#include <set>

namespace idattd::sogen
{
    // ------------------------------------------------------------ queries
    //
    // Each runs the Sogen query, holds the whole answer and copies out what
    // fits. Those that compute their answer from scratch keep it from the
    // count call to the fill (kept_fill); the others are cheap to ask again.
    // The long ones run on query_reader, not under 'mtx'.

    // A kept answer's key: the bytes of the arguments that decide it.
    struct query_key
    {
        std::string s;

        template <typename T>
        query_key &add(const T &v)
        {
            s.append(reinterpret_cast<const char *>(&v), sizeof(T));
            return *this;
        }

        query_key &add_bytes(const void *p, size_t n)
        {
            if ( n != 0 )
                s.append(static_cast<const char *>(p), n);
            return *this;
        }
    };

    // Answer one call of a count-then-fill pair from 'slot', running 'run'
    // (which returns the whole answer as a std::vector<T>, or throws) only
    // when the slot does not hold the answer to 'key'. The slot's lock is not
    // held while 'run' works: the reader it takes serializes the work, and a
    // call on another slot never waits for it.
    template <typename T, typename Run>
    int kept_fill(kept_answer<T> &slot, const std::string &key, T *buf, size_t cap,
                  size_t *out_count, int *out_truncated, Run &&run)
    {
        std::shared_ptr<const std::vector<T>> data;
        {
            std::lock_guard<std::mutex> lock(slot.mtx);
            if ( slot.data != nullptr && slot.key == key )
                data = slot.data;
        }
        if ( data == nullptr )
        {
            data = std::make_shared<const std::vector<T>>(run());
            std::lock_guard<std::mutex> lock(slot.mtx);
            slot.key    = key;
            slot.data   = data;
            slot.served = 0;
        }
        const std::vector<T> &v = *data;
        set_truncated(out_truncated, v.size(), cap, buf != nullptr);
        fill(v, buf, cap, out_count, [](const T &x) { return x; });
        // Answered after a fill (or two counts without one, as abi_export
        // allows), and at once when empty: the core does not fill an empty
        // answer, and a kept one would answer the next identical question
        // without running it.
        std::lock_guard<std::mutex> lock(slot.mtx);
        if ( slot.data == data && (++slot.served >= 2 || buf != nullptr || v.empty()) )
        {
            slot.data.reset();
            slot.key.clear();
        }
        return ITTD_OK;
    }

    int query_accesses(ittd_backend *hb, uint64_t lo, uint64_t hi, uint32_t kinds,
                       ittd_position_range when, ittd_access *buf, size_t cap,
                       size_t *out_count, int *out_truncated, const ittd_progress *progress)
    {
        backend_t *b = B(hb);
        if ( b == nullptr || hi <= lo )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            query_key key;
            key.add(lo).add(hi).add(kinds).add(when);
            return kept_fill(b->accesses_answer, key.s, buf, cap, out_count, out_truncated, [&]()
            {
                query_reader reader(b);
                ttd::trace &t = reader.trace();
                uint64_t s0 = 0, s1 = 0;
                step_range(t, when, &s0, &s1);
                std::vector<ttd::access_event> ev =
                    t.accesses(lo, hi - lo, s0, s1, sogen_mask(kinds), control(progress));
                std::vector<ittd_access> v;
                v.reserve(ev.size());
                for ( const ttd::access_event &e : ev )
                {
                    ittd_access a{};
                    a.pos  = before_step(e.step);
                    a.pc   = e.ip;
                    a.addr = e.address;
                    a.size = (uint32_t)e.size;
                    a.kind = access_kind_of(e.kind);
                    a.tid  = t.thread_at(e.step).value_or(0);
                    v.push_back(a);
                }
                return v;
            });
        });
    }

    int query_executed(ittd_backend *hb, const ittd_range *ranges, size_t nranges,
                       uint64_t *buf, size_t cap, size_t *out_count,
                       int *out_truncated, const ittd_progress *progress)
    {
        backend_t *b = B(hb);
        if ( b == nullptr || (ranges == nullptr && nranges != 0) )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            query_reader reader(b);
            ttd::trace &t = reader.trace();
            std::vector<std::pair<uint64_t, uint64_t>> want;
            for ( size_t i = 0; i < nranges; i++ )
                if ( ranges[i].end > ranges[i].start )
                    want.emplace_back(ranges[i].start, ranges[i].end);
            // The fill call of a count query asks the same as the count call
            // did: answer it from the set the first one built. The cache is
            // guarded by query_mtx, which 'reader' holds.
            if ( !b->executed_valid || b->executed_ranges != want )
            {
                b->executed_valid = false;
                b->executed.clear();
                std::set<uint64_t> seen;
                const ttd::operation_control ctl = control(progress);
                // Only cancellation reaches each accesses() call; progress is
                // reported here, over the whole request (report also checks
                // for cancellation).
                ttd::operation_control inner;
                inner.interrupted = ctl.interrupted;
                // The events are fetched a stretch of steps at a time, so a
                // hot range never holds every execution of the recording at
                // once, only those of one stretch. Each call decodes only the
                // chunks of its own stretch, so the stretches add little.
                constexpr uint64_t kSlice = 1ull << 21;
                const uint64_t last = last_position(t);
                const uint64_t slices = last / kSlice + 1;
                const uint64_t X = (uint64_t)ttd::access_kind::execute;
                for ( size_t i = 0; i < want.size(); i++ )
                {
                    const uint64_t lo = want[i].first, hi = want[i].second;
                    for ( uint64_t k = 0; k < slices; k++ )
                    {
                        ctl.report(i * slices + k, want.size() * slices);
                        const uint64_t s0 = k * kSlice;
                        const uint64_t s1 = k + 1 == slices ? UINT64_MAX : s0 + kSlice - 1;
                        for ( const ttd::access_event &e : t.accesses(lo, hi - lo, s0, s1, X, inner) )
                            if ( e.ip >= lo && e.ip < hi )
                                seen.insert(e.ip);
                    }
                }
                b->executed.assign(seen.begin(), seen.end());
                b->executed_ranges = std::move(want);
                b->executed_valid  = true;
            }
            const std::vector<uint64_t> &v = b->executed;
            set_truncated(out_truncated, v.size(), cap, buf != nullptr);
            return fill(v, buf, cap, out_count, [](uint64_t a) { return a; });
        });
    }

    // The return of a function entered by a jump (a tail call, an import
    // thunk, the CFG dispatcher's 'jmp rax'), which calls_to cannot pair
    // because there is no call of its own. Walking back finds the call that
    // led to the jump; its return address is that call's address plus its
    // length, and the function returned at the ret just before the next
    // execution of that address on this thread. Index lookups only: rebuilding
    // CPU state from a checkpoint would cost tens of milliseconds an entry.
    // UINT64_MAX when there is no such return (the thread ended in it, or
    // unwound past it).
    uint64_t return_of_jump_entry(ttd::trace &t, uint64_t entry_step, uint32_t tid)
    {
        if ( entry_step == 0 || entry_step == UINT64_MAX )
            return UINT64_MAX;
        std::optional<ttd::access_event> call = entering_call(t, entry_step - 1, tid, 1ull << 16, false);
        if ( !call )
            return UINT64_MAX;
        const uint64_t ra = call->ip + call->size;
        const uint64_t X  = (uint64_t)ttd::access_kind::execute;
        uint64_t s = entry_step;
        for ( int k = 0; k < 64; k++ )
        {
            std::optional<ttd::access_event> ev = t.next_access(ra, 1, s, X);
            if ( !ev )
                return UINT64_MAX;
            s = ev->step;
            if ( ev->ip != ra || t.thread_at(ev->step).value_or(0) != tid )
                continue;
            std::optional<ttd::access_event> prev = t.previous_instruction(ev->step, tid);
            if ( prev && is_ret_insn(*prev) )
                return prev->step;
        }
        return UINT64_MAX;
    }

    // Every call made in steps [s0, s1]. The reader lists calls by target
    // only, so this walks the execute events: a call is recognized by its
    // bytes, its callee is the thread's next instruction, and its return is
    // the first ret on the thread that lands on its return address (calls
    // opened after it then left without returning: an exception, a longjmp).
    // A call that has not returned by s1 has no return.
    std::vector<ttd::call_event> every_call(ttd::trace &t, uint64_t s0, uint64_t s1, bool is64,
                                            const ttd::operation_control &ctl)
    {
        struct open_call { size_t index; uint64_t return_address; };
        struct thread_state
        {
            std::vector<open_call> open;
            std::optional<size_t>   call_pending;   // its callee is the next instruction
            std::optional<uint64_t> ret_pending;    // the step of a ret, until where it went is known
        };
        std::vector<ttd::call_event> out;
        if ( s0 > s1 )
            return out;
        std::unordered_map<uint32_t, thread_state> threads;
        const uint64_t X = (uint64_t)ttd::access_kind::execute;
        ttd::event_reader reader(t, t.first_event_after(s0 - 1));
        for ( uint64_t seen = 0;; seen++ )
        {
            std::optional<ttd::access_event> ev = reader.next(X);
            if ( !ev || ev->step > s1 )
                break;
            if ( (seen & 0xFFFF) == 0 )
            {
                ctl.check();
                if ( ctl.progress && s1 > s0 )
                    ctl.progress(ev->step - s0, s1 - s0);
            }
            uint32_t tid = t.thread_at(ev->step).value_or(0);
            thread_state &ts = threads[tid];
            if ( ts.call_pending )
            {
                out[*ts.call_pending].entry_step = ev->step;
                out[*ts.call_pending].target     = ev->ip;
                ts.call_pending.reset();
            }
            if ( ts.ret_pending )
            {
                for ( size_t k = ts.open.size(); k-- > 0; )
                    if ( ts.open[k].return_address == ev->ip )
                    {
                        out[ts.open[k].index].return_step = *ts.ret_pending;
                        ts.open.resize(k);
                        break;
                    }
                ts.ret_pending.reset();
            }
            uint8_t op = 0, modrm = 0;
            if ( !opcode_of(*ev, is64, &op, &modrm) )
                continue;
            if ( is_call_op(op, modrm, is64) )
            {
                ttd::call_event c;
                c.step      = ev->step;
                c.site      = ev->ip;
                c.thread_id = tid;
                c.is_call   = true;
                out.push_back(c);
                ts.call_pending = out.size() - 1;
                ts.open.push_back({ out.size() - 1, ev->ip + ev->size });
            }
            else if ( is_ret_op(op) )
            {
                ts.ret_pending = ev->step;
            }
        }
        // A ret on the last steps lands after s1: see where it went.
        for ( auto &[tid, ts] : threads )
        {
            if ( !ts.ret_pending )
                continue;
            std::optional<ttd::access_event> next = t.next_instruction(*ts.ret_pending, tid);
            if ( !next )
                continue;
            for ( size_t k = ts.open.size(); k-- > 0; )
                if ( ts.open[k].return_address == next->ip )
                {
                    out[ts.open[k].index].return_step = *ts.ret_pending;
                    break;
                }
        }
        // A call made on the last step has no callee in range.
        out.erase(std::remove_if(out.begin(), out.end(),
                                 [](const ttd::call_event &c) { return c.entry_step == 0; }),
                  out.end());
        return out;
    }

    // query_calls' answer, computed: the calls to 'targets', or every call
    // when there are none, in [when].
    std::vector<ittd_call> find_calls(backend_t *b, const uint64_t *targets, size_t ntargets,
                                      ittd_position_range when, const ittd_progress *progress)
    {
        query_reader reader(b);
        ttd::trace &t = reader.trace();
        uint64_t s0 = 0, s1 = 0;
        step_range(t, when, &s0, &s1);
        std::vector<ttd::call_event> all;
        // No targets: every call in the range. Meant for a short range,
        // such as the run of one function a call tree shows.
        if ( ntargets == 0 )
            all = every_call(t, s0, s1, is64(t), control(progress));
        for ( size_t i = 0; i < ntargets; i++ )
        {
            // Each target reports its share of the whole: a pattern can
            // name thousands, and per-target progress ran the bar from 0
            // to 100% over and over.
            ttd::operation_control ctl = control(progress);
            if ( ctl.progress )
            {
                auto whole = ctl.progress;
                ctl.progress = [whole, i, ntargets](uint64_t done, uint64_t total)
                {
                    uint64_t part = total == 0 ? 0 : std::min<uint64_t>(1000, done * 1000 / total);
                    whole((uint64_t)i * 1000 + part, (uint64_t)ntargets * 1000);
                };
            }
            std::vector<ttd::call_event> v = t.calls_to(targets[i], s0, s1, ctl);
            all.insert(all.end(), v.begin(), v.end());
        }
        std::sort(all.begin(), all.end(), [](const ttd::call_event &a, const ttd::call_event &b)
                  { return a.entry_step < b.entry_step; });
        // In entry order: neighbouring entries walk the same stretch of
        // the event stream, whose decoded chunks the reader keeps.
        for ( ttd::call_event &e : all )
            if ( !e.is_call && e.return_step == UINT64_MAX )
                e.return_step = return_of_jump_entry(t, e.entry_step, e.thread_id);
        std::vector<ittd_call> v;
        v.reserve(all.size());
        for ( const ttd::call_event &e : all )
        {
            ittd_call c{};
            c.pos       = before_step(e.step);
            c.entry_pos = before_step(e.entry_step);
            // Position = the ret's step is the state after it: back at the
            // return address with the result in RAX.
            c.ret_pos   = e.return_step == UINT64_MAX ? NONE : at(e.return_step);
            c.site      = e.step == UINT64_MAX ? ITTD_BADADDR : e.site;
            c.target    = e.target;
            c.tid       = e.thread_id;
            c.flags     = e.is_call ? 0 : ITTD_CALL_F_NOT_CALL;
            v.push_back(c);
        }
        return v;
    }

    int query_calls(ittd_backend *hb, const uint64_t *targets, size_t ntargets,
                    ittd_position_range when, ittd_call *buf, size_t cap,
                    size_t *out_count, int *out_truncated, const ittd_progress *progress)
    {
        backend_t *b = B(hb);
        if ( b == nullptr || (targets == nullptr && ntargets != 0) )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            query_key key;
            key.add(ntargets).add_bytes(targets, ntargets * sizeof(uint64_t)).add(when);
            return kept_fill(b->calls_answer, key.s, buf, cap, out_count, out_truncated,
                             [&]() { return find_calls(b, targets, ntargets, when, progress); });
        });
    }

    int query_indirect(ittd_backend *hb, const ittd_range *ranges, size_t nranges, uint32_t flags,
                       ittd_call_target *buf, size_t cap, size_t *out_count,
                       int *out_truncated, const ittd_progress *progress)
    {
        backend_t *b = B(hb);
        if ( b == nullptr || (ranges == nullptr && nranges != 0) )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            std::vector<std::pair<uint64_t, uint64_t>> r;
            for ( size_t i = 0; i < nranges; i++ )
                if ( ranges[i].end > ranges[i].start )
                    r.emplace_back(ranges[i].start, ranges[i].end - ranges[i].start);
            const bool jumps = (flags & ITTD_INDIRECT_JUMPS) != 0;
            query_key key;
            key.add(jumps).add(r.size()).add_bytes(r.data(), r.size() * sizeof(r[0]));
            return kept_fill(b->indirect_answer, key.s, buf, cap, out_count, out_truncated, [&]()
            {
                query_reader reader(b);
                std::vector<ttd::indirect_branch> found =
                    reader.trace().indirect_branches(r, jumps, control(progress));
                std::vector<ittd_call_target> v;
                v.reserve(found.size());
                for ( const ttd::indirect_branch &e : found )
                {
                    ittd_call_target t{};
                    t.site      = e.site;
                    t.target    = e.target;
                    t.hits      = e.hits;
                    t.first_pos = before_step(e.first_step);
                    t.flags     = e.is_call ? 0 : ITTD_CALL_F_NOT_CALL;
                    v.push_back(t);
                }
                return v;
            });
        });
    }

    int query_exceptions(ittd_backend *hb, ittd_exception *buf, size_t cap, size_t *out_count,
                         int *out_truncated, const ittd_progress *progress)
    {
        backend_t *b = B(hb);
        if ( b == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            return kept_fill(b->exceptions_answer, std::string(), buf, cap, out_count, out_truncated, [&]()
            {
                query_reader reader(b);
                std::vector<ttd::exception_event> found = reader.trace().exceptions(control(progress));
                std::vector<ittd_exception> v;
                v.reserve(found.size());
                for ( const ttd::exception_event &e : found )
                {
                    ittd_exception x{};
                    x.pos            = before_step(e.step);
                    x.raise_pos      = before_step(e.raise_step);
                    x.address        = e.address;
                    x.information[0] = e.information[0];
                    x.information[1] = e.information[1];
                    x.code           = e.code;
                    x.flags          = e.flags;
                    x.tid            = e.thread_id;
                    v.push_back(x);
                }
                return v;
            });
        });
    }

    // The syscall table is decoded when the trace opens, so this is a copy.
    // The thread comes from the switch table; the arguments, which the table
    // lacks, are left to regs_at. On query_reader: the fill builds a cpu_view
    // for every syscall that can block, which on a large recording is
    // seconds that the module and thread lists must not wait on 'mtx' for.
    int query_syscalls(ittd_backend *hb, ittd_syscall *buf, size_t cap, size_t *out_count,
                       int *out_truncated, const ittd_progress *)
    {
        backend_t *b = B(hb);
        if ( b == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            query_reader reader(b);
            ttd::trace &t = reader.trace();
            std::span<const ttd::syscall_entry> v = t.syscalls();
            set_truncated(out_truncated, v.size(), cap, buf != nullptr);
            return fill(v, buf, cap, out_count, [&](const ttd::syscall_entry &e)
            {
                ittd_syscall x{};
                x.pos    = before_step(e.step);
                x.result = e.result;
                x.number = e.id;
                x.tid    = t.thread_at(e.step).value_or(0);
                // A syscall that can block (a wait, a delay, a completion
                // port) is recorded with the status its handler gave at once,
                // STATUS_SUCCESS, though the thread resumes with the real one
                // (STATUS_TIMEOUT for an expired wait) in rax: so for those
                // the result is rax where the thread resumes. cpu_view at a
                // position shows the thread that runs the next instruction.
                // Only for those, as a view costs about a millisecond.
                const std::optional<std::string_view> name = t.syscall_name(e.id);
                const bool may_block = name.has_value()
                    && (name->find("Wait") != std::string_view::npos || name->find("Delay") != std::string_view::npos
                     || name->find("RemoveIoCompletion") != std::string_view::npos);
                if ( buf != nullptr && x.tid != 0 && may_block )
                {
                    if ( std::optional<ttd::access_event> resume = t.next_instruction(e.step, x.tid) )
                    {
                        if ( resume->step > 0 )
                        {
                            ttd::cpu_view view(t, resume->step - 1);
                            ittd_regs r{};
                            read_regs(view, &r);
                            if ( (r.have & ITTD_REGS_GP) != 0 )
                                x.result = r.gp[ITTD_REG_RAX];
                        }
                    }
                }
                if ( name.has_value() )
                {
                    size_t len = std::min(name->size(), sizeof(x.name) - 1);
                    memcpy(x.name, name->data(), len);
                }
                return x;
            });
        });
    }

    // One pass over every write and execute event, in the reader: seconds on
    // a large trace. Progress counts events.
    int query_self_modifying(ittd_backend *hb, ittd_selfmod *buf, size_t cap, size_t *out_count,
                             int *out_truncated, const ittd_progress *progress)
    {
        backend_t *b = B(hb);
        if ( b == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            return kept_fill(b->selfmod_answer, std::string(), buf, cap, out_count, out_truncated, [&]()
            {
                // A reader of its own under scans.mtx, so seconds of scanning
                // hold neither 'mtx' nor the query reader.
                std::lock_guard<std::mutex> lock(b->scans.mtx);
                std::unique_ptr<ttd::trace> own = open_forward_trace(b->path);
                ttd::trace &t = *own;
                const uint64_t need = (uint64_t)ttd::access_kind::write | (uint64_t)ttd::access_kind::execute;
                if ( (t.access_mask() & need) != need )
                    throw coded_error(ITTD_E_FAILED, "this recording was made without write or execute events, "
                                                     "which finding self-modifying code needs");
                std::vector<ttd::self_modifying_hit> found = t.self_modifying_code(control(progress));
                std::vector<ittd_selfmod> v;
                v.reserve(found.size());
                for ( const ttd::self_modifying_hit &h : found )
                {
                    ittd_selfmod x{};
                    x.address     = h.address;
                    x.size        = h.size;
                    x.write_pos   = before_step(h.write_step);
                    x.write_ip    = h.write_ip;
                    x.execute_pos = before_step(h.execute_step);
                    x.executions  = h.executions;
                    v.push_back(x);
                }
                return v;
            });
        });
    }

    // ------------------------------------------------------------ the memory heatmap
    //
    // Every recorded access, counted by page and by slice of the recording's
    // steps, in one pass over the event stream. A window (the heatmap zoomed
    // in) reads only its own stretch of events.
    bool whole_trace(ittd_position_range when)
    {
        return same(when.first, BEGIN) && same(when.last, END);
    }

    // Where the slices of 'when' count from, and how many steps they share.
    // The whole recording counts from start_position, as it always has.
    void heat_span(const ttd::trace &t, ittd_position_range when, uint64_t *start, uint64_t *span)
    {
        if ( whole_trace(when) )
        {
            *start = t.start_position();
            *span  = std::max<uint64_t>(last_position(t) - std::min(last_position(t), *start), 1);
            return;
        }
        // step_range gives the steps of the events inside the window: after
        // its first position, up to and including its last. The slices count
        // from that first position, so slice 0 begins exactly where asked.
        uint64_t lo = 0, hi = 0;
        step_range(t, when, &lo, &hi);
        *start = lo - 1;
        *span  = std::max<uint64_t>(hi >= *start ? hi - *start : 1, 1);
    }

    int query_access_heat_window(ittd_backend *hb, uint32_t page_shift, uint32_t slices,
                                 ittd_position_range when,
                                 ittd_heat_cell *buf, size_t cap, size_t *out_count,
                                 int *out_truncated, const ittd_progress *progress)
    {
        backend_t *b = B(hb);
        if ( b == nullptr || slices == 0 || slices > 4096 || page_shift < 8 || page_shift > 30 )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            std::lock_guard<std::mutex> lock(b->scans.mtx);
            const bool whole = whole_trace(when);
            std::string key = std::to_string(page_shift) + "|" + std::to_string(slices);
            if ( !whole )
                key += "|" + std::to_string(when.first.hi) + ":" + std::to_string(when.first.lo)
                     + "|" + std::to_string(when.last.hi) + ":" + std::to_string(when.last.lo);
            auto found = b->scans.heat.find(key);
            if ( found == b->scans.heat.end() )
            {
                // Zooming in and out asks for the same few windows. Past 16
                // entries every cached window is dropped, so the cache cannot
                // grow without bound. The whole-recording answers each cost a
                // pass over every event and are asked for again whenever the
                // heatmap opens, so they are kept longer: past 4 page sizes
                // and slice counts, those go too.
                auto is_window = [](const std::string &k) { return std::count(k.begin(), k.end(), '|') > 1; };
                size_t windows = 0;
                for ( const auto &[k, v] : b->scans.heat )
                    windows += is_window(k) ? 1 : 0;
                const size_t wholes = b->scans.heat.size() - windows;
                if ( (!whole && b->scans.heat.size() > 16) || (whole && wholes >= 4) )
                    for ( auto it = b->scans.heat.begin(); it != b->scans.heat.end(); )
                        it = is_window(it->first) == !whole ? b->scans.heat.erase(it) : std::next(it);
                std::unique_ptr<ttd::trace> own = open_forward_trace(b->path);
                ttd::trace &t = *own;
                uint64_t start = 0, span = 1;
                heat_span(t, when, &start, &span);
                uint64_t lo = 0, hi = UINT64_MAX;
                if ( !whole )
                    step_range(t, when, &lo, &hi);
                const uint64_t total = std::max<uint64_t>(t.metadata().event_count, 1);
                // Keyed by page and slice, not packed into one integer: a page
                // number at the smallest shift takes 56 bits, the slice 12.
                struct cell_key
                {
                    uint64_t page;
                    uint64_t slice;
                    bool operator==(const cell_key &o) const { return page == o.page && slice == o.slice; }
                };
                struct cell_hash
                {
                    size_t operator()(const cell_key &k) const
                    {
                        return std::hash<uint64_t>()(k.page * 0x9E3779B97F4A7C15ull ^ k.slice);
                    }
                };
                std::unordered_map<cell_key, ittd_heat_cell, cell_hash> cells;
                const ttd::operation_control ctl = control(progress);
                ttd::event_reader reader(t, whole ? 0 : t.first_event_after(lo - 1));
                uint64_t seen = 0;
                while ( std::optional<ttd::access_event> ev = reader.next() )
                {
                    if ( (++seen & 0xFFFF) == 0 )
                        ctl.report(reader.last_number(), total);
                    if ( ev->step > hi )
                        break;              // past the window: events are in step order
                    if ( ev->step < lo )
                        continue;
                    uint64_t slice = (ev->step - std::min(ev->step, start)) * slices / span;
                    if ( slice >= slices )
                        slice = slices - 1;
                    const uint64_t page = ev->address >> page_shift;
                    ittd_heat_cell &c = cells[cell_key{ page, slice }];
                    c.page  = page;
                    c.slice = (uint32_t)slice;
                    switch ( ev->kind )
                    {
                        case ttd::access_kind::read:    c.reads++;    break;
                        case ttd::access_kind::execute: c.executes++; break;
                        default:                        c.writes++;   break;
                    }
                }
                std::vector<ittd_heat_cell> v;
                v.reserve(cells.size());
                for ( const auto &[k, c] : cells )
                    v.push_back(c);
                std::sort(v.begin(), v.end(), [](const ittd_heat_cell &a, const ittd_heat_cell &c)
                {
                    return a.page != c.page ? a.page < c.page : a.slice < c.slice;
                });
                found = b->scans.heat.emplace(key, std::move(v)).first;
            }
            set_truncated(out_truncated, found->second.size(), cap, buf != nullptr);
            return fill(found->second, buf, cap, out_count, [](const ittd_heat_cell &c) { return c; });
        });
    }

    int query_access_heat(ittd_backend *hb, uint32_t page_shift, uint32_t slices,
                          ittd_heat_cell *buf, size_t cap, size_t *out_count,
                          int *out_truncated, const ittd_progress *progress)
    {
        return query_access_heat_window(hb, page_shift, slices, ittd_position_range{ BEGIN, END },
                                        buf, cap, out_count, out_truncated, progress);
    }

    int heat_window_slice_position(ittd_backend *hb, uint32_t slices, uint32_t slice,
                                   ittd_position_range when, ittd_position *out)
    {
        backend_t *b = B(hb);
        if ( b == nullptr || out == nullptr || slices == 0 )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            std::lock_guard<std::mutex> lock(b->mtx);
            const ttd::trace &t = *b->trace;
            uint64_t start = 0, span = 1;
            heat_span(t, when, &start, &span);
            *out = at(start + std::min<uint64_t>(slice, slices) * span / slices);
            return ITTD_OK;
        });
    }

    int heat_slice_position(ittd_backend *hb, uint32_t slices, uint32_t slice, ittd_position *out)
    {
        return heat_window_slice_position(hb, slices, slice, ittd_position_range{ BEGIN, END }, out);
    }

    // The instruction stream of one thread (or all) over a range of positions,
    // straight from the execute events: no replay, so a window costs only the
    // events it reads. Stops after 'cap'.
    int query_instructions(ittd_backend *hb, ittd_position_range when, uint32_t tid,
                           ittd_access *buf, size_t cap, size_t *out_count,
                           int *out_truncated, const ittd_progress *progress)
    {
        backend_t *b = B(hb);
        if ( b == nullptr || (buf == nullptr && cap != 0) )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            query_reader reader(b);
            ttd::trace &t = reader.trace();
            ttd::operation_control ctl = control(progress);
            uint64_t s0 = 0, s1 = 0;
            step_range(t, when, &s0, &s1);
            size_t n = 0;
            bool more = false;
            if ( s0 <= s1 )
            {
                const uint64_t X = (uint64_t)ttd::access_kind::execute;
                ttd::event_reader reader(t, t.first_event_after(s0 - 1));
                for ( uint64_t seen = 0;; seen++ )
                {
                    std::optional<ttd::access_event> ev = reader.next(X);
                    if ( !ev || ev->step > s1 )
                        break;
                    if ( (seen & 0xFFFF) == 0 )
                        ctl.check();
                    uint32_t et = t.thread_at(ev->step).value_or(0);
                    if ( tid != 0 && et != tid )
                        continue;
                    if ( n == cap )
                    {
                        more = true;
                        break;
                    }
                    ittd_access &a = buf[n++];
                    a = ittd_access{};
                    a.pos  = before_step(ev->step);
                    a.pc   = ev->ip;
                    a.addr = ev->ip;
                    a.size = (uint32_t)ev->size;
                    a.kind = ITTD_ACCESS_EXEC;
                    a.tid  = et;
                }
            }
            if ( out_count != nullptr )
                *out_count = n;
            if ( out_truncated != nullptr )
                *out_truncated = more ? 1 : 0;
            return ITTD_OK;
        });
    }

    // Sogen's finer region kind, as the ABI's region_type.
    uint32_t region_type_of(uint32_t kind)
    {
        switch ( kind )
        {
            case 1: return ITTD_REGION_PRIVATE;
            case 2: return ITTD_REGION_MAPPED;
            case 3: return ITTD_REGION_SECTION;
            case 4: return ITTD_REGION_IMAGE;
            case 5: return ITTD_REGION_MMIO;
            case 6: return ITTD_REGION_HOST;
            default: return ITTD_REGION_UNKNOWN;
        }
    }

    // Who asked for a recorded map change: the routine whose syscall made it
    // (the target of the call into the syscall stub, such as ntdll's
    // NtAllocateVirtualMemory) and the call sites that led there, innermost
    // first and one per library module crossed, but every frame in the
    // program's own module ('main_base') and outside every module, as the
    // Microsoft backend reports from the calls it watches: the program's
    // innermost frame is often a helper every allocation goes through. Sogen
    // records the outcome, not the call, so the chain is walked back from the
    // syscall instruction.
    void syscall_chain(ttd::trace &t, uint64_t sys_step, uint32_t tid,
                       const std::vector<std::pair<uint64_t, uint64_t>> &mods, uint64_t main_base,
                       ittd_mapping_change *m)
    {
        static const uint64_t kWalk   = 1ull << 16;    // instructions back, per frame
        static const int      kFrames = 32;
        auto module_of = [&mods](uint64_t a) -> size_t
        {
            for ( size_t i = 0; i < mods.size(); i++ )
                if ( a >= mods[i].first && a < mods[i].first + mods[i].second )
                    return i;
            return (size_t)-1;
        };
        std::optional<ttd::access_event> call = entering_call(t, sys_step - 1, tid, kWalk, false);
        if ( !call )
            return;
        if ( std::optional<ttd::access_event> entry = t.next_instruction(call->step, tid) )
            m->api = entry->ip;
        size_t last = (size_t)-2;
        for ( int f = 0; call && f < kFrames && m->chain_n < ITTD_CHAIN_MAX; f++ )
        {
            size_t mi = module_of(call->ip);
            const bool own = mi == (size_t)-1 || mods[mi].first == main_base;
            if ( m->chain_n == 0 || mi != last || own )
            {
                m->chain[m->chain_n++] = call->ip;
                last = mi;
            }
            call = entering_call(t, call->step - 1, tid, kWalk, false);
        }
    }

    // The memory map at the start and every change to it, from the trace's
    // memory regions section (format section 17). Each entry is what
    // NtQueryVirtualMemory showed for its range from its position on, i.e.
    // ITTD_MAP_STATE, which the core folds by overwriting the range. The
    // values are already Windows' own.
    int query_mapping_changes(ittd_backend *hb, ittd_mapping_change *buf, size_t cap,
                              size_t *out_count, int *out_truncated, const ittd_progress *progress)
    {
        backend_t *b = B(hb);
        if ( b == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            query_reader reader(b);
            const ttd::trace &t = reader.trace();
            if ( !t.has_memory_regions() )
            {
                b->error.set("this trace was recorded before Sogen recorded the memory map");
                return ITTD_E_UNSUPPORTED;
            }
            const std::vector<ttd::memory_region> &v = t.memory_regions().regions;
            std::span<const ttd::syscall_entry> sys = t.syscalls();
            std::vector<std::pair<uint64_t, uint64_t>> mods;
            for ( const ttd::module_entry &me : t.modules() )
                mods.emplace_back(me.base, me.size);
            const ttd::module_entry *mainm = main_module(t);
            const uint64_t main_base = mainm != nullptr ? mainm->base : UINT64_MAX;
            const uint64_t start = first_position(t);
            set_truncated(out_truncated, v.size(), cap, buf != nullptr);
            auto conv = [&](const ttd::memory_region &r)
            {
                ittd_mapping_change m{};
                m.pos           = at(r.step);
                m.call_pos      = NONE;
                m.api           = ITTD_BADADDR;
                m.base          = r.address;
                m.size          = r.size;
                m.kind          = ITTD_MAP_STATE;
                m.flags         = ITTD_MAP_F_EXACT;
                m.protect       = r.protection;
                m.alloc_base    = r.allocation_base;
                m.state         = r.state;
                m.mem_type      = r.type;
                m.alloc_protect = r.allocation_protection;
                m.region_type   = region_type_of(r.kind);
                m.file          = r.name == UINT32_MAX ? 0 : r.name + 1;
                if ( r.step == start && r.event_number == 0 )
                {
                    m.flags |= ITTD_MAP_F_AT_START;
                    return m;
                }
                m.tid = t.thread_at(r.step).value_or(0);
                // The syscall that made the change, if any, so the listing
                // can travel to where the memory was asked for.
                auto it = std::lower_bound(sys.begin(), sys.end(), r.step,
                                           [](const ttd::syscall_entry &e, uint64_t s) { return e.step < s; });
                if ( it != sys.end() && it->step == r.step )
                {
                    m.call_pos = before_step(it->step);
                    syscall_chain(reader.trace(), it->step, m.tid, mods, main_base, &m);
                }
                return m;
            };
            if ( out_count != nullptr )
                *out_count = v.size();
            if ( buf == nullptr )
                return ITTD_OK;
            // Each change made by a syscall walks back for its call chain
            // (syscall_chain), so thousands of allocations take a while:
            // with progress and Cancel, unlike a plain fill().
            const size_t n = std::min(v.size(), cap);
            for ( size_t i = 0; i < n; i++ )
            {
                if ( (i & 63) == 0 && progress != nullptr )
                {
                    if ( progress->cancelled != nullptr && progress->cancelled(progress->ud) != 0 )
                    {
                        // What was filled, so the rest is not read as
                        // (empty) changes.
                        if ( out_count != nullptr )
                            *out_count = i;
                        b->error.set("cancelled");
                        return ITTD_E_CANCELLED;
                    }
                    if ( progress->report != nullptr )
                        progress->report(progress->ud, uint32_t(i * 1000 / n));
                }
                buf[i] = conv(v[i]);
            }
            return ITTD_OK;
        });
    }

    int query_mapping_files(ittd_backend *hb, ittd_name *buf, size_t cap, size_t *out_count)
    {
        backend_t *b = B(hb);
        if ( b == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            std::lock_guard<std::mutex> lock(b->mtx);
            return fill(b->trace->memory_regions().names, buf, cap, out_count, [](const std::string &n)
            {
                ittd_name out{};
                copy_str(out.name, sizeof(out.name), n);
                return out;
            });
        });
    }

    int regs_at(ittd_backend *hb, const ittd_position *positions, size_t count,
                ittd_regs *out, const ittd_progress *progress)
    {
        backend_t *b = B(hb);
        if ( b == nullptr || ((positions == nullptr || out == nullptr) && count != 0) )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            query_reader reader(b);
            ttd::trace &t = reader.trace();
            ttd::operation_control ctl = control(progress);
            // The positions that exist, in position order, each with the slot
            // its registers go to. Positions that do not exist keep have == 0.
            std::vector<std::pair<uint64_t, size_t>> want;
            want.reserve(count);
            for ( size_t i = 0; i < count; i++ )
            {
                out[i] = ittd_regs{};
                uint64_t p = 0;
                if ( resolve(t, positions[i], &p) )
                    want.emplace_back(p, i);
            }
            std::sort(want.begin(), want.end());

            // cpu_views_at replays each register snapshot interval once for
            // all its positions (Sogen measured 4-6x over a cpu_view each, on
            // both ends of every call to a function). Positions go in chunks
            // so progress and Cancel are heard; a chunk boundary inside an
            // interval costs that interval one more replay. A position that
            // diverges fails its whole chunk, which is then rebuilt one
            // position at a time so the others survive.
            constexpr size_t kChunk = 1024;
            std::vector<uint64_t> steps;
            steps.reserve(std::min(want.size(), kChunk));
            for ( size_t first = 0; first < want.size(); first += kChunk )
            {
                const size_t last = std::min(want.size(), first + kChunk);
                steps.clear();
                for ( size_t k = first; k < last; k++ )
                    steps.push_back(want[k].first);
                try
                {
                    std::vector<ttd::cpu_view> views = ttd::cpu_views_at(t, steps);
                    for ( size_t k = first; k < last; k++ )
                        read_regs(views[k - first], &out[want[k].second]);
                }
                catch ( const ttd::divergence_error & )
                {
                    for ( size_t k = first; k < last; k++ )
                    {
                        try
                        {
                            read_regs(ttd::cpu_view(t, want[k].first), &out[want[k].second]);
                        }
                        catch ( const ttd::divergence_error & )
                        {
                            // Left with have == 0: this position could not be rebuilt.
                        }
                    }
                }
                ctl.report(last, want.size());
            }
            return ITTD_OK;
        });
    }
}
