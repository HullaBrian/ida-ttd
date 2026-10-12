#include "debugger/trace_manager.h"
#include "debugger/msttd_position.h"
#include "analysis/trace_store.h"
#include "debugger/registers.h"
#include "common/trace_link.h"

using namespace TTD;
using namespace TTD::Replay;

namespace idattd
{
    // to_utf8 / to_wstring / base_name and the index builder live in
    // trace_open.{h,cpp}: the .run loader is a separate binary that needs the
    // same four things and cannot reach into TraceManager.

    //=======================================================================
    // Startup failure reporting
    //=======================================================================
    // Report a start_process failure through errbuf (IDA shows that to the user)
    // and the output window, then hand back the drc code to return. Returning a
    // bare DRC_* with an untouched errbuf leaves IDA to print a generic "cannot
    // start process" while the actual reason is buried in the log.
    AS_PRINTF(3, 4) static ssize_t start_failed(qstring *errbuf, ssize_t drc,
                                                const char *format, ...)
    {
        qstring m;
        va_list va;
        va_start(va, format);
        m.vsprnt(format, va);
        va_end(va);
        if ( errbuf != nullptr )
            *errbuf = m;
        msg("[ida-ttd] %s\n", m.c_str());
        return drc;
    }

    //=======================================================================
    // TraceManager
    //=======================================================================
    thid_t TraceManager::current_tid() const
    {
        const ThreadInfo &ti = m_cursor->GetThreadInfo();
        return (thid_t)(uint32_t)ti.Id;
    }

    ea_t TraceManager::program_counter() const
    {
        return (ea_t)(uint64_t)m_cursor->GetProgramCounter();
    }

    std::map<uint32_t, thid_t> TraceManager::snapshot_threads() const
    {
        std::map<uint32_t, thid_t> result;
        size_t n = m_cursor->GetThreadCount();
        const ActiveThreadInfo *list = m_cursor->GetThreadList();
        for ( size_t i = 0; i < n; i++ )
            result[(uint32_t)list[i]->UniqueId] = (thid_t)(uint32_t)list[i]->Id;
        return result;
    }

    std::set<const Module *> TraceManager::snapshot_modules() const
    {
        std::set<const Module *> result;
        size_t n = m_cursor->GetModuleCount();
        const ModuleInstance *list = m_cursor->GetModuleList();
        for ( size_t i = 0; i < n; i++ )
            result.insert(list[i].pModule);
        return result;
    }

    bool TraceManager::is_target_module(const Module &m) const
    {
        if ( m_targetName.empty() )
            return false;
        std::string bn = base_name(to_utf8(m.pName, m.NameLength));
        return _stricmp(bn.c_str(), m_targetName.c_str()) == 0;
    }

    void TraceManager::emit_module_load(const Module &m)
    {
        std::string name = to_utf8(m.pName, m.NameLength);
        ea_t base   = (ea_t)(uint64_t)m.Address;
        ea_t rebase = is_target_module(m) ? base : BADADDR;
        m_events.add_lib_load(m_pid, current_tid(), name, base, rebase, (asize_t)m.Size);
    }

    ssize_t TraceManager::on_init()
    {
        // Nothing to show yet: the backend has merely been selected. The TTD
        // actions/toolbar appear in on_start_process, once a trace is really
        // loaded.
        return DRC_OK;
    }

    ssize_t TraceManager::on_term()
    {
        if ( m_hooks.on_end )
            m_hooks.on_end();
        set_current_trace(0);
        // Anything still queued describes the OLD trace's modules and threads.
        m_events.clear();
        if ( m_afSaved )
        {
            inf_set_af(m_savedAf);   // restore the analysis flags we changed
            m_afSaved = false;
        }
        reset_session_state();
        m_engine.reset();
        return DRC_OK;
    }

    void TraceManager::reset_session_state()
    {
        m_cursor.reset();
        m_frameCursor.reset();
        m_code.reset();

        m_events.clear();
        m_activeBpts = 0;
        m_userWatchpoints.clear();

        m_modules.reset();
        m_memory.reset();

        m_layout.reset();

        m_isForward       = true;
        m_resumeMode      = RESMOD_NONE;
        m_pending         = PendingRequest{};
        m_pendingBoundary = BOUNDARY_NONE;
        m_pendingNotice.clear();
    }

    ssize_t TraceManager::on_get_processes(procinfo_vec_t *procs)
    {
        process_info_t info;
        info.pid  = m_pid;
        info.name = "TTD trace";
        procs->push_back(info);
        return DRC_OK;
    }

    ssize_t TraceManager::on_get_debapp_attrs(debapp_attrs_t *attrs)
    {
        attrs->addrsize = m_is64 ? 8 : 4;
        attrs->is_be    = false;
        return DRC_OK;
    }

    ssize_t TraceManager::on_start_process(const char *path, const char *input_path, qstring *errbuf)
    {
        // A session can be torn down without its events being drained, and the
        // caches below describe the previous recording's addresses.
        reset_session_state();
        m_is64 = inf_is_64bit();

        // Stop the analysis cascade: each on-stop add_func() traces the current
        // function, and AF_PROC ("create functions if call is present") would make
        // IDA recursively create+analyze every callee (stack frames, vars, FLIRT),
        // fanning out across whole modules and making navigation crawl. We define
        // the function the user is actually looking at explicitly, so disable the
        // auto-create-from-calls features for the session (restored in on_term).
        if ( !m_afSaved )
        {
            m_savedAf = inf_get_af();
            m_afSaved = true;
        }
        inf_set_af(m_savedAf & ~(uint32)(AF_PROC | AF_PROCPTR));
        // Which module the database is of, so a load of it can trigger a
        // rebase. A database created by the .run loader states this outright;
        // otherwise it is the name of the file IDA thinks it opened.
        {
            TraceLink link;
            if ( trace_link_read(&link) && !link.module_name.empty() )
                m_targetName = link.module_name.c_str();
            else
                m_targetName = base_name(input_path != nullptr ? input_path : "");
        }

        // We load module PDBs ourselves, silently (see load_module_pdb), so turn
        // OFF IDA's automatic debug-file loading -- otherwise it pops a "load
        // symbols?" confirmation for every module. (set_debugger_options REPLACES
        // the option set and returns the old one, so clear just this bit.)
        uint dopts = set_debugger_options(0);
        set_debugger_options(dopts & ~(uint)DOPT_LOAD_DINFO);

        if ( path == nullptr || !std::filesystem::exists(path) )
        {
            return start_failed(errbuf, DRC_NOFILE,
                       "Trace file not found: %s\n\n"
                       "Put the .run trace path in the 'Application' field of the "
                       "debugger dialog.", path != nullptr ? path : "(null)");
        }

        // Validate the TTD magic ("TTDLog").
        {
            std::ifstream f(path, std::ios::binary);
            char magic[6] = { 0 };
            if ( !f.is_open() || !f.read(magic, sizeof(magic))
              || memcmp(magic, "TTDLog", sizeof(magic)) != 0 )
            {
                return start_failed(errbuf, DRC_NOFILE,
                           "Not a valid TTD trace (bad magic): %s", path);
            }
        }

        auto made = MakeReplayEngine();
        m_engine = std::move(made.first);
        if ( made.second != 0 || !m_engine )
        {
            return start_failed(errbuf, DRC_FAILED,
                       "Failed to create the TTD replay engine (0x%08X).\n\n"
                       "Are TTDReplay.dll / TTDReplayCPU.dll next to ida.exe?",
                       made.second);
        }

        m_engine->RegisterDebugModeAndLogging(DebugModeType::None, &m_err);

        std::wstring wpath = to_wstring(path);
        if ( !m_engine->Initialize(wpath.c_str()) )
        {
            return start_failed(errbuf, DRC_FAILED, "Failed to load the trace: %s", path);
        }

        // Build the memory index if it is not already present. Without it,
        // memory reads are severely limited. The .run loader may already have
        // built it when the database was created, in which case this returns
        // immediately.
        build_trace_index(m_engine.get());

        // The module registry answers every lookup from the engine's module
        // list, so it cannot be bound before the engine exists.
        m_modules.bind(m_engine.get(), m_is64, m_targetName.c_str());
        m_memory.bind(m_engine.get(), &m_modules);
        m_code.bind(m_engine.get(), &m_modules, &m_memory, m_is64);
        m_layout.bind(&m_modules, m_is64);

        m_cursor = UniqueCursor{ m_engine->NewCursor() };
        if ( !m_cursor )
        {
            return start_failed(errbuf, DRC_FAILED,
                       "Failed to create a replay cursor over the trace.");
        }
        m_cursor->SetPosition(TtdPosition::Min);
        clamp_to_trace();       // TtdPosition::Min is a sentinel; land on a real one

        // Serve memory like WinDbg/Binja: the Default policy resolves to a
        // thread-local query that only returns memory the current thread touched
        // around the current position, so unpacked/written-earlier bytes (e.g. the
        // rest of a shellcode buffer) read back as zeros. GloballyAggressive looks
        // across the whole trace to reconstruct the value (lower confidence, but it
        // is what WinDbg/Binja effectively show) so far fewer bytes come back 0.
        m_cursor->SetDefaultMemoryPolicy(QueryMemoryPolicy::GloballyAggressive);

        // A memory map costs a full replay, so one saved against this recording
        // is reused rather than rebuilt. A map saved against a different trace
        // fails the fingerprint check and is ignored.
        // Tell the analysis stores which recording they are being read against,
        // so results saved for a different one are not shown against this one.
        set_current_trace(trace_fingerprint());

        if ( m_layout.map_for_update().load(trace_fingerprint()) )
            msg("[ida-ttd] loaded a saved memory map: %d recorded change(s).\n",
                (int)m_layout.map().size());

        if ( m_hooks.on_start )
            m_hooks.on_start();

        // ---- Build the initial set of debug events -------------------------
        size_t modCount = m_engine->GetModuleCount();
        const Module *mods = m_engine->GetModuleList();

        ea_t mainBase = BADADDR;
        if ( modCount > 0 )
        {
            const Module &main = mods[0];
            mainBase = (ea_t)(uint64_t)main.Address;
            std::string name = to_utf8(main.pName, main.NameLength);
            ea_t rebase = is_target_module(main) ? mainBase : BADADDR;
            m_events.add_process_start(m_pid, current_tid(), name, mainBase, rebase, (asize_t)main.Size);
        }
        else
        {
            m_events.add_process_start(m_pid, current_tid(), "trace", BADADDR, BADADDR, 0);
        }

        // Threads currently alive (other than the current one).
        thid_t cur_tid = current_tid();
        for ( const auto &kv : snapshot_threads() )
        {
            if ( kv.second != cur_tid )
                m_events.add_thread_start(m_pid, kv.second);
        }

        // Modules currently loaded (other than the main one already reported).
        {
            size_t n = m_cursor->GetModuleCount();
            const ModuleInstance *list = m_cursor->GetModuleList();
            for ( size_t i = 0; i < n; i++ )
            {
                const Module &m = *list[i].pModule;
                if ( (ea_t)(uint64_t)m.Address == mainBase )
                    continue;
                emit_module_load(m);
            }
        }

        // Finally, suspend at the entry position.
        emit_stop(false);
        return DRC_OK;
    }

    ssize_t TraceManager::on_get_debug_event(gdecode_t *code, debug_event_t *event, int /*timeout_ms*/)
    {
        if ( !m_events.try_pop(event) )
        {
            *code = GDE_NO_EVENT;
            return DRC_OK;
        }
        *code = m_events.empty() ? GDE_ONE_EVENT : GDE_MANY_EVENTS;
        return DRC_OK;
    }

    ssize_t TraceManager::on_read_memory(size_t *nbytes, ea_t ea, void *buffer, size_t size)
    {
        return m_memory.read(m_cursor.get(), nbytes, ea, buffer, size);
    }

    ssize_t TraceManager::on_get_memory_info(meminfo_vec_t *ranges)
    {
        return m_layout.on_get_memory_info(m_cursor.get(), ranges);
    }

    ssize_t TraceManager::on_read_registers(thid_t tid, int /*clsmask*/, regval_t *values)
    {
        if ( !m_cursor )
            return DRC_FAILED;
        ThreadId t = tid == NO_THREAD ? ThreadId::Invalid : (ThreadId)(uint32_t)tid;
        CROSS_PLATFORM_CONTEXT ctx = m_cursor->GetCrossPlatformContext(t);
        fill_regvals(ctx, m_is64, values);
        return DRC_OK;
    }

    ssize_t TraceManager::on_rebase_if_required_to(ea_t new_base)
    {
        // A database the .run loader created already has the main image at its
        // recorded base, so the delta is zero. rebase_program(0) is not free --
        // it runs the whole segment-move machinery, shows its own progress box
        // and dirties the database -- so say no rather than doing nothing slowly.
        ea_t delta = new_base - get_imagebase();
        if ( delta == 0 )
            return DRC_OK;
        rebase_program(delta, MSF_FIXONCE);
        return DRC_OK;
    }

    static DataAccessMask access_mask_from_bpt(bpttype_t type)
    {
        switch ( type )
        {
            case BPT_WRITE:   return DataAccessMask::Write;
            case BPT_READ:    return DataAccessMask::Read;
            case BPT_RDWR:    return DataAccessMask::Read | DataAccessMask::Write;
            case BPT_EXEC:    return DataAccessMask::Execute;
            default:          return DataAccessMask::Execute;
        }
    }

    ssize_t TraceManager::on_update_bpts(int *nbpts, update_bpt_info_t *bpts, int nadd, int ndel)
    {
        *nbpts = 0;
        if ( !m_cursor )
            return DRC_FAILED;

        for ( int i = 0; i < nadd; i++ )
        {
            DataAccessMask mask = access_mask_from_bpt(bpts[i].type);
            uint64_t sz = mask == DataAccessMask::Execute
                        ? 1
                        : (bpts[i].size > 0 ? (uint64_t)bpts[i].size : 1);
            MemoryWatchpointData wp{};
            wp.Address    = GuestAddress{ (uint64_t)bpts[i].ea };
            wp.Size       = sz;
            wp.AccessMask = mask;
            // Report the truth: if the engine refuses the watchpoint the
            // breakpoint will never fire, and claiming BPT_OK would leave IDA
            // showing an active breakpoint that silently does nothing.
            if ( m_cursor->AddMemoryWatchpoint(wp) )
            {
                m_activeBpts++;
                m_userWatchpoints.insert(wp);
                bpts[i].code = BPT_OK;
                (*nbpts)++;
            }
            else
            {
                bpts[i].code = BPT_BAD_ADDR;
                msg("[ida-ttd] could not set a TTD watchpoint for the breakpoint at 0x%llX.\n",
                    (uint64_t)bpts[i].ea);
            }
        }

        for ( int i = 0; i < ndel; i++ )
        {
            update_bpt_info_t &b = bpts[nadd + i];
            DataAccessMask mask = access_mask_from_bpt(b.type);
            uint64_t sz = mask == DataAccessMask::Execute
                        ? 1
                        : (b.size > 0 ? (uint64_t)b.size : 1);
            MemoryWatchpointData wp{};
            wp.Address    = GuestAddress{ (uint64_t)b.ea };
            wp.Size       = sz;
            wp.AccessMask = mask;
            if ( m_cursor->RemoveMemoryWatchpoint(wp) && m_activeBpts > 0 )
                m_activeBpts--;
            m_userWatchpoints.erase(wp);
            b.code = BPT_OK;
            (*nbpts)++;
        }

        m_cursor->SetEventMask(m_activeBpts > 0 ? EventMask::MemoryWatchpoint : EventMask::None);
        return DRC_OK;
    }

    ssize_t TraceManager::on_set_backwards(bool backwards)
    {
        m_isForward = !backwards;
        return DRC_OK;
    }

    ssize_t TraceManager::on_set_resume_mode(thid_t /*tid*/, resume_mode_t resmod)
    {
        m_resumeMode = resmod;
        return DRC_OK;
    }

    EventType TraceManager::navigate_steps(bool forward, StepCount steps)
    {
        auto threads_before = snapshot_threads();
        auto mods_before    = snapshot_modules();

        // A bounded step must start from a position that exists in the recording.
        // Replaying backward "one step" from the end-of-trace sentinel does not
        // move one instruction -- it runs all the way to the limit, i.e. to the
        // start of the trace.
        if ( steps != StepCount::Max )
            clamp_to_trace();
        const TtdPosition before = m_cursor->GetPosition();

        ICursorView::ReplayResult r = forward
            ? m_cursor->ReplayForward(TtdPosition::Max, steps)
            : m_cursor->ReplayBackward(TtdPosition::Min, steps);

        // A bounded backward step that lands on the trace's first position moved
        // to the start instead of stepping, which means the cursor began somewhere
        // the engine could not step from. Say so rather than silently teleporting
        // the user.
        if ( !forward && steps != StepCount::Max )
        {
            const TtdPosition after = m_cursor->GetPosition();
            const TtdPosition first = m_engine ? m_engine->GetFirstPosition() : TtdPosition::Invalid;
            if ( first.IsValid() && after <= first && before.Sequence != first.Sequence )
            {
                msg("[ida-ttd] backward step from %llX:%llX landed at the start of "
                    "the trace (%llX:%llX) instead of stepping.\n",
                    (uint64_t)before.Sequence, (uint64_t)before.Steps,
                    (uint64_t)after.Sequence, (uint64_t)after.Steps);
            }
        }

        auto threads_after = snapshot_threads();
        auto mods_after    = snapshot_modules();
        apply_differences(threads_before, threads_after, mods_before, mods_after);
        return r.StopReason;
    }

    bool TraceManager::add_temp_exec_watchpoint(ea_t addr, MemoryWatchpointData &wp)
    {
        wp = MemoryWatchpointData{};
        wp.Address    = GuestAddress{ (uint64_t)addr };
        wp.Size       = 1;
        wp.AccessMask = DataAccessMask::Execute;
        // An identical user breakpoint is this watchpoint as far as the engine is
        // concerned. Leave it alone: the replay already stops there, and removing
        // "ours" afterwards would silently delete the user's breakpoint.
        if ( m_userWatchpoints.find(wp) != m_userWatchpoints.end() )
            return false;
        return m_cursor->AddMemoryWatchpoint(wp);
    }

    void TraceManager::drop_temp_exec_watchpoint(const MemoryWatchpointData &wp, bool owned)
    {
        if ( owned )
            m_cursor->RemoveMemoryWatchpoint(wp);
    }

    // Run forward to 'addr' on a specific thread/frame, honoring breakpoints.
    TraceManager::RunStop TraceManager::run_to_addr_guarded(ea_t addr, uint64_t min_sp, uint32_t utid)
    {
        MemoryWatchpointData wp{};
        bool owned = add_temp_exec_watchpoint(addr, wp);

        // The callback is shared by all watchpoints on the cursor: accept the
        // step-target only on the right thread/frame, but always stop on any
        // other (user) breakpoint.
        auto stop_cb = [addr, min_sp, utid](ICursorView::MemoryWatchpointResult const &w,
                                            IThreadView const *t) noexcept -> bool
        {
            if ( (uint64_t)w.Address == (uint64_t)addr )
                return (uint32_t)t->GetThreadInfo().UniqueId == utid
                    && (uint64_t)t->GetStackPointer() >= min_sp;
            return true; // user breakpoint
        };
        m_cursor->SetMemoryWatchpointCallback(stop_cb);
        m_cursor->SetEventMask(EventMask::MemoryWatchpoint);

        ICursorView::ReplayResult r = m_cursor->ReplayForward();

        drop_temp_exec_watchpoint(wp, owned);
        m_cursor->SetMemoryWatchpointCallback(nullptr, 0);
        m_cursor->SetEventMask(m_activeBpts > 0 ? EventMask::MemoryWatchpoint : EventMask::None);

        if ( r.StopReason != EventType::MemoryWatchpoint )
            return RunStop::TraceBoundary;
        return program_counter() == addr ? RunStop::Reached : RunStop::Breakpoint;
    }

    // Run backward to 'addr': set a temporary Execute watchpoint there and replay
    // backward. The engine seeks straight to the previous execution of 'addr' (one
    // ReplayBackward -- cheap, not a backward single-step loop), stopping there or
    // at any user breakpoint hit on the way, or at the start of the trace.
    EventType TraceManager::navigate_backward_to(ea_t addr)
    {
        auto threads_before = snapshot_threads();
        auto mods_before    = snapshot_modules();

        MemoryWatchpointData wp{};
        bool owned = add_temp_exec_watchpoint(addr, wp);
        m_cursor->SetEventMask(EventMask::MemoryWatchpoint);

        ICursorView::ReplayResult r = m_cursor->ReplayBackward();

        drop_temp_exec_watchpoint(wp, owned);
        m_cursor->SetEventMask(m_activeBpts > 0 ? EventMask::MemoryWatchpoint : EventMask::None);

        auto threads_after = snapshot_threads();
        auto mods_after    = snapshot_modules();
        apply_differences(threads_before, threads_after, mods_before, mods_after);
        return r.StopReason;
    }

    // Run forward to 'addr': set a temporary Execute watchpoint there and replay
    // forward. The engine seeks straight to the next execution of 'addr' (one
    // ReplayForward -- cheap), stopping there, at any user breakpoint hit on the
    // way, or at the end of the trace. If the cursor is already on 'addr', step
    // once first so we advance to the next occurrence instead of matching here.
    EventType TraceManager::navigate_forward_to(ea_t addr)
    {
        auto threads_before = snapshot_threads();
        auto mods_before    = snapshot_modules();

        if ( program_counter() == addr )
            m_cursor->ReplayForward(TtdPosition::Max, StepCount{ 1 });

        MemoryWatchpointData wp{};
        bool owned = add_temp_exec_watchpoint(addr, wp);
        m_cursor->SetEventMask(EventMask::MemoryWatchpoint);

        ICursorView::ReplayResult r = m_cursor->ReplayForward();

        drop_temp_exec_watchpoint(wp, owned);
        m_cursor->SetEventMask(m_activeBpts > 0 ? EventMask::MemoryWatchpoint : EventMask::None);

        auto threads_after = snapshot_threads();
        auto mods_after    = snapshot_modules();
        apply_differences(threads_before, threads_after, mods_before, mods_after);
        return r.StopReason;
    }

    void TraceManager::clamp_to_trace()
    {
        if ( !m_engine || !m_cursor )
            return;
        const TtdPosition first = m_engine->GetFirstPosition();
        const TtdPosition last  = m_engine->GetLastPosition();
        if ( !first.IsValid() || !last.IsValid() )
            return;
        const TtdPosition p = m_cursor->GetPosition();
        if ( p > last )
            m_cursor->SetPosition(last);
        else if ( p < first )
            m_cursor->SetPosition(first);
    }

    void TraceManager::settle_after_navigation(EventType sr, bool forward)
    {
        if ( !m_engine || !m_cursor )
            return;

        // Do this FIRST and unconditionally: a run that reached either end of the
        // trace leaves the cursor on the limit sentinel, not on a real recorded
        // position, and everything downstream (the next step, the frame search,
        // the memory cursor, the position readout) then works from an address in
        // the timeline that does not exist.
        clamp_to_trace();

        // A breakpoint stop is not a trace edge.
        if ( sr == EventType::MemoryWatchpoint )
            return;
        TtdPosition p = m_cursor->GetPosition();
        if ( forward && !(p < m_engine->GetLastPosition()) )
            m_pendingBoundary = BOUNDARY_END;
        else if ( !forward && !(m_engine->GetFirstPosition() < p) )
            m_pendingBoundary = BOUNDARY_START;
    }

    // Forward step-over / step-out implemented on the main cursor: step-over a
    // call by running to the return site; step-out by repeating until the frame
    // is unwound. Single instructions are stepped directly.
    EventType TraceManager::navigate_over(bool step_out)
    {
        auto threads_before = snapshot_threads();
        auto mods_before    = snapshot_modules();

        TtdPosition start_pos = m_cursor->GetPosition();
        uint64_t    start_sp  = (uint64_t)m_cursor->GetStackPointer();
        uint32_t    utid      = (uint32_t)m_cursor->GetThreadInfo().UniqueId;
        bool hit_bpt  = false;
        bool boundary = false;      // ran out of recording rather than unwinding

        // Both of these can run for a long time: stepping over a call that never
        // returns (exception, longjmp, ExitThread) replays to the END of the
        // trace, and step-out repeats that until the frame unwinds. Without this
        // IDA simply appears hung with no way out.
        //
        // The box is safe to raise even for a fast step-over: without NODELAY /
        // HIDECANCEL, IDA only materialises the dialog after its grace threshold,
        // so ordinary quick steps never show anything. Keeping the Cancel button
        // (i.e. not passing HIDECANCEL) is the whole point here.
        show_wait_box("%s (Cancel to stop)...", step_out ? "Stepping out" : "Stepping over");
        const int CAP = 100000;                 // backstop against a pathological frame
        int iters = 0;
        for ( ;; )
        {
            if ( user_cancelled() )
                break;
            if ( ++iters > CAP )
            {
                msg("[ida-ttd] step out: giving up after %d iterations without unwinding the frame.\n", CAP);
                break;
            }

            ea_t  pc = program_counter();
            insn_t insn;
            int len = decode_insn(&insn, pc);
            bool is_call = len > 0 && is_call_insn(insn);

            if ( is_call )
            {
                // The guard belongs to THIS call, not to the frame being stepped
                // out of. By the time a nested call is reached the stack has
                // grown down past that frame's entry level, so guarding on
                // start_sp would reject the very return being waited for and
                // replay to the end of the recording instead. For a step-over
                // the two are the same value, which is why only step-out broke.
                uint64_t call_sp = (uint64_t)m_cursor->GetStackPointer();
                RunStop oc = run_to_addr_guarded((ea_t)((uint64_t)pc + len), call_sp, utid);
                if ( oc == RunStop::Breakpoint ) { hit_bpt = true; break; }
                if ( oc == RunStop::TraceBoundary ) { boundary = true; break; }
            }
            else
            {
                ICursorView::ReplayResult r = m_cursor->ReplayForward(TtdPosition::Max, StepCount{ 1 });
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
            if ( (uint64_t)m_cursor->GetStackPointer() > start_sp )
                break;                                  // step-out: frame has returned
        }
        hide_wait_box();

        // The recording ran out before the frame unwound: the thread exited
        // inside it, or the call it was in never returned. The end of the
        // recording is not an answer to "step out", so stay where we were.
        if ( step_out && boundary
          && (uint64_t)m_cursor->GetStackPointer() <= start_sp )
        {
            m_cursor->SetPosition(start_pos);
            m_pendingNotice = "This frame does not return anywhere in the "
                              "recording, so there is nothing to step out to.\n\n"
                              "The position has been left where it was.";
        }

        auto threads_after = snapshot_threads();
        auto mods_after    = snapshot_modules();
        apply_differences(threads_before, threads_after, mods_before, mods_after);

        return hit_bpt ? EventType::MemoryWatchpoint : EventType::Position;
    }

    // Backward step-out: find the CALL instruction that entered the frame we are
    // standing in, so the caller can seek straight to it in one engine hop.
    //
    // We never single-step backward to do this -- that re-seeks a keyframe per
    // step and takes minutes. Instead we seek to a position before the playhead
    // and replay forward to it, tracking a per-thread stack of open calls; the
    // top of our thread's stack at the playhead is the call we want. The window
    // widens until it captures that call.
    ICursorView *TraceManager::frame_cursor()
    {
        if ( m_engine && !m_frameCursor )
        {
            m_frameCursor = UniqueCursor{ m_engine->NewCursor() };
            if ( m_frameCursor )
            {
                m_frameCursor->SetReplayFlags(ReplayFlags::ReplayAllSegmentsWithoutFiltering
                                            | ReplayFlags::ReplaySegmentsSequentially);
            }
        }
        return m_frameCursor.get();
    }

    bool TraceManager::find_frame_entry_position(TtdPosition &out, bool &cancelled)
    {
        cancelled = false;
        out       = TtdPosition::Invalid;
        if ( frame_cursor() == nullptr )
            return false;

        const ThreadInfo &ti  = m_cursor->GetThreadInfo();
        const uint32_t    tid = (uint32_t)ti.UniqueId;
        const TtdPosition    last = m_engine->GetLastPosition();

        // Floor for the search. ActiveTime is the span in which this thread
        // actually executed instructions, so nothing it did can lie before
        // ActiveTime.Min: a window that reaches it without finding an open call
        // means the thread genuinely is in its outermost frame, and that is a
        // real answer rather than a search that ran out of patience.
        TtdPosition first = m_engine->GetFirstPosition();
        if ( ti.ActiveTime.Min.IsValid() && first < ti.ActiveTime.Min )
            first = ti.ActiveTime.Min;

        // Work from a position that exists in the recording. settle_after_navigation
        // normally guarantees this, but a sentinel here would make every look-back
        // window (cur.Sequence - N) land past the end of the trace and replay
        // nothing, which reads to the user as "the call cannot be found".
        TtdPosition cur = m_cursor->GetPosition();
        if ( last.IsValid() && cur > last )
            cur = last;
        // The thread-accurate ceiling. GetLastPosition() is the end of the whole
        // recording and can belong to some other thread, so a cursor clamped to it
        // may sit past the point where this thread last ran -- and a window ending
        // there contains none of its instructions, so no call of its own to find.
        if ( ti.ActiveTime.Max.IsValid() && cur > ti.ActiveTime.Max )
            cur = ti.ActiveTime.Max;
        if ( first.IsValid() && cur < first )
            cur = first;

        // Per-thread stack of open CALL positions. A CALL pushes, a RET pops; when
        // the replay reaches the playhead the top of our thread's stack is the call
        // that entered the frame we are standing in. ReplayForward(cur) stops AT
        // the playhead without executing it, so a cursor sitting on a call does not
        // push that call -- which is what we want.
        // A RET with nothing on the stack is a frame that was already open when the
        // window began; ignoring it is what makes a PARTIAL window still give the
        // right answer. Any call left on the stack at the playhead is genuinely an
        // open frame, so the top of the stack is the innermost one -- ours. If the
        // entering call happened before the window, the stack ends up empty and the
        // caller widens.
        std::map<uint32_t, std::vector<TtdPosition>> stacks;
        uint64_t seen_all  = 0;     // call/ret callbacks dispatched in this window
        uint64_t seen_mine = 0;     // ...of those, ones on the thread we stand in
        auto on_call_ret = [&](GuestAddress, GuestAddress fall_through,
                               IThreadView const *t) noexcept
        {
            // Engine callbacks are noexcept: an allocation that throws in here
            // terminates the process, so cap the depth instead of trusting it.
            static const size_t kMaxDepth = 8192;
            uint32_t utid = (uint32_t)t->GetThreadInfo().UniqueId;
            seen_all++;
            if ( utid == tid )
                seen_mine++;
            try
            {
                if ( (uint64_t)fall_through != 0 )
                {
                    std::vector<TtdPosition> &st = stacks[utid];
                    if ( st.size() < kMaxDepth )
                        st.push_back(t->GetPosition());
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

        // Look-back schedule: a slice of the current sequence, then the whole of
        // it, then progressively more whole sequences. Each attempt is one
        // SetPosition plus one bulk forward replay. Deliberately capped: a frame
        // entered near the start of a long recording would otherwise mean
        // replaying the entire trace, and it is better to say so than to hang.
        //
        // Sequence ids do not advance at a uniform rate. Process teardown in
        // particular bumps one per thread-exit event, so "64 sequences" can be a
        // few hundred instructions at the end of a trace where it is millions in
        // the middle -- which is why the schedule keeps widening well past that
        // instead of giving up early.
        struct Attempt { bool by_steps; uint64_t back; };
        static const Attempt kAttempts[] = {
            { true,  4096  }, { true,  65536 },
            { false, 1     }, { false, 4     }, { false, 16    },
            { false, 64    }, { false, 256   }, { false, 1024  },
            { false, 4096  }, { false, 16384 },
        };

        show_wait_box("Looking for the call that entered this frame "
                      "(Cancel to stop)...");
        bool     found     = false;
        TtdPosition lastStart = TtdPosition::Invalid;
        TtdPosition winStart  = TtdPosition::Invalid;   // window actually replayed last
        uint64_t winInsns  = 0;                   // ...and what it executed
        for ( size_t i = 0; i < qnumber(kAttempts) && !found; i++ )
        {
            if ( user_cancelled() )
            {
                cancelled = true;
                break;
            }
            replace_wait_box("Looking for the call that entered this frame "
                             "(Cancel to stop)...\nsearch %d of %d",
                             (int)i + 1, (int)qnumber(kAttempts));

            TtdPosition s = cur;
            if ( kAttempts[i].by_steps )
            {
                uint64_t st = (uint64_t)cur.Steps;
                s.Steps = (StepCount)(st > kAttempts[i].back ? st - kAttempts[i].back : 0);
            }
            else
            {
                uint64_t sq = (uint64_t)cur.Sequence;
                uint64_t bk = kAttempts[i].back;
                s.Sequence = (SequenceId)(sq > bk ? sq - bk : 0);
                s.Steps    = StepCount::Min;
            }
            if ( s < first )
                s = first;
            // Near the start of a sequence the step-based windows collapse onto the
            // same position; do not replay the identical range twice.
            if ( s == lastStart )
                continue;
            lastStart = s;

            stacks.clear();
            seen_all  = 0;
            seen_mine = 0;
            m_frameCursor->SetPosition(s);
            m_frameCursor->SetCallReturnCallback(on_call_ret);
            ICursorView::ReplayResult rr = m_frameCursor->ReplayForward(cur);
            m_frameCursor->SetCallReturnCallback(nullptr, 0);
            winStart = s;
            winInsns = (uint64_t)rr.InstructionsExecuted;

            auto it = stacks.find(tid);
            if ( it != stacks.end() && !it->second.empty() )
            {
                out   = it->second.back();
                found = true;
                break;
            }
            if ( !(first < s) )
                break;      // the window already reached the start of the trace
        }
        hide_wait_box();
        if ( !found && !cancelled )
        {
            // Two very different failures reach this point and the user cannot
            // tell them apart from the popup: a thread that really is in its
            // outermost frame, and a window that replayed nothing. Say which.
            msg("[ida-ttd] no entering call for thread %X searching back from "
                "%llX:%llX. Last window %llX:%llX replayed %llu instructions, "
                "%llu call/ret events, %llu of them on this thread.\n",
                tid, (uint64_t)cur.Sequence, (uint64_t)cur.Steps,
                (uint64_t)winStart.Sequence, (uint64_t)winStart.Steps,
                winInsns, seen_all, seen_mine);
        }
        return found;
    }

    EventType TraceManager::rewind_to(const TtdPosition &p)
    {
        auto threads_before = snapshot_threads();
        auto mods_before    = snapshot_modules();

        // one engine call rather than a step loop. User breakpoints stay armed,
        // so anything hit between here and 'p' still stops us there instead.
        ICursorView::ReplayResult r = m_cursor->ReplayBackward(p);
        bool hit_bpt = r.StopReason == EventType::MemoryWatchpoint;

        auto threads_after = snapshot_threads();
        auto mods_after    = snapshot_modules();
        apply_differences(threads_before, threads_after, mods_before, mods_after);

        return hit_bpt ? EventType::MemoryWatchpoint : EventType::Position;
    }

    EventType TraceManager::navigate_out_backward()
    {
        TtdPosition entry;
        bool     cancelled = false;
        if ( !find_frame_entry_position(entry, cancelled) )
        {
            // Say so rather than leaving the user staring at an unchanged view.
            if ( !cancelled )
                m_pendingNotice = "Could not find the call that entered this frame.\n\n"
                                  "It happened further back than the search window "
                                  "reaches, or this thread is in its outermost frame.";
            return EventType::Position;     // leave the cursor where it is
        }
        return rewind_to(entry);
    }

    // Backward step-over. One backward step; if that landed us on the tail of a
    // callee that had just returned (same thread, deeper frame), rewind on out of
    // it so we come to rest on the CALL that entered it -- the backward mirror of
    // stepping over a call.
    //
    // IDA has no RESMOD_BACKOVER: "step over backwards" arrives as ev_set_backwards
    // followed by the ordinary RESMOD_OVER, so on_resume picks this on direction.
    EventType TraceManager::navigate_over_backward()
    {
        auto threads_before = snapshot_threads();
        auto mods_before    = snapshot_modules();

        const uint64_t start_sp = (uint64_t)m_cursor->GetStackPointer();
        const uint32_t utid     = (uint32_t)m_cursor->GetThreadInfo().UniqueId;

        ICursorView::ReplayResult r = m_cursor->ReplayBackward(TtdPosition::Min, StepCount{ 1 });
        const bool hit_bpt = r.StopReason == EventType::MemoryWatchpoint;

        // Did that step take us into a callee, or just to the previous instruction
        // of this frame? Only the former needs stepping over.
        //
        // A lower stack pointer alone is not the test: stepping backward over a
        // 'pop' also lands on a lower SP while staying in the same frame. What
        // identifies a returning callee is landing on its RET -- at which point the
        // return address is still stacked, so SP is below where we started. Require
        // both, on the same thread.
        bool deeper = false;
        if ( !hit_bpt
          && (uint32_t)m_cursor->GetThreadInfo().UniqueId == utid
          && (uint64_t)m_cursor->GetStackPointer() < start_sp )
        {
            insn_t insn;
            deeper = decode_insn(&insn, program_counter()) > 0 && is_ret_insn(insn);
        }

        auto threads_after = snapshot_threads();
        auto mods_after    = snapshot_modules();
        apply_differences(threads_before, threads_after, mods_before, mods_after);

        if ( deeper )
        {
            // We are sitting on the callee's RET. Its frame was entered by the very
            // call we want to land on, so ask for that call's position and seek to
            // it. If it cannot be found we simply stay on the RET: the step already
            // moved, and a popup about an unfindable frame would be noise for what
            // the user asked (step back one), unlike an explicit "step out".
            TtdPosition entry;
            bool     cancelled = false;
            if ( find_frame_entry_position(entry, cancelled) )
                return rewind_to(entry);
        }
        return hit_bpt ? EventType::MemoryWatchpoint : EventType::Position;
    }


    // FNV-1a hash of up to 'n' bytes at 'ea' (read through the debugger memory,
    // i.e. the live bytes at the current position). Returns 0 on a short read so a
    void TraceManager::analyze_whole_function()
    {
        if ( !m_cursor )
        {
            warning("Analysis is only available while replaying a trace.");
            return;
        }
        m_code.analyze_whole_function(m_cursor.get());
    }

    void TraceManager::on_suspended()
    {
        if ( !m_cursor )
            return;

        // Time travel breaks IDA's "process memory only changes going forward"
        // assumption: the same address can hold different bytes at different
        // positions (e.g. a buffer that's zero before it's unpacked). After a jump
        // IDA keeps the previous position's cached bytes for everything it doesn't
        // re-read.
        //
        // invalidate_dbgmem_contents() flushes and refreshes, so the listing
        // re-reads through on_read_memory. invalidate_dbg_state(DBGINV_MEMORY)
        // only marks the cache dirty and would leave the first bytes IDA cached
        // on screen.
        //
        // Like IDA's own post-stop handling, this brings the disassembly view to
        // the front. Plugin::keep_decompiler_focused() puts the user back in the
        // decompiler afterwards.
        invalidate_dbgmem_contents(BADADDR, 0);

        // Time travel can move us across an allocation, a protection change or a
        // free, so the regions in force here may not be the ones IDA was last
        // given. This is a no-op unless a memory map has been built.
        m_layout.refresh(m_cursor.get());

        // Name exports of any module loaded at this position first, so a call to a
        // freshly-revealed export renders with its name rather than loc_/sub_.
        m_modules.resolve_loaded(m_cursor.get());
        m_code.on_stop(m_cursor.get(), program_counter());

        // If the last navigation came to rest on the very first/last position of
        // the trace, tell the user. Done here (after the stop is fully processed)
        // rather than inside on_resume, where a modal popup would be unsafe.
        if ( m_pendingBoundary == BOUNDARY_START )
            info("Reached the start of the trace.");
        else if ( m_pendingBoundary == BOUNDARY_END )
            info("Reached the end of the trace.");
        m_pendingBoundary = BOUNDARY_NONE;

        if ( !m_pendingNotice.empty() )
        {
            info("%s", m_pendingNotice.c_str());
            m_pendingNotice.clear();
        }
    }

    void TraceManager::emit_stop(bool is_step)
    {
        // Just queue the stop event here (during ev_resume). The memory-cache
        // invalidation and disassembly/symbol work happen in on_suspended(), once
        // the process is actually in the stopped state.
        ea_t pc = program_counter();
        if ( is_step )
            m_events.add_step(m_pid, current_tid(), pc);
        else
            m_events.add_breakpoint(m_pid, current_tid(), pc);
    }

    void TraceManager::navigate_to(const TtdPosition &p)
    {
        auto threads_before = snapshot_threads();
        auto mods_before    = snapshot_modules();
        m_cursor->SetPosition(p);
        // "Go to position" and the timeline both land here, and a user can type a
        // Sequence:Steps past the end of the recording.
        clamp_to_trace();
        auto threads_after = snapshot_threads();
        auto mods_after    = snapshot_modules();
        apply_differences(threads_before, threads_after, mods_before, mods_after);
    }

    void TraceManager::apply_differences(const std::map<uint32_t, thid_t> &threads_before,
                                         const std::map<uint32_t, thid_t> &threads_after,
                                         const std::set<const Module *> &mods_before,
                                         const std::set<const Module *> &mods_after)
    {
        for ( const auto &kv : threads_before )
            if ( threads_after.find(kv.first) == threads_after.end() )
                m_events.add_thread_exit(m_pid, kv.second);

        for ( const auto &kv : threads_after )
            if ( threads_before.find(kv.first) == threads_before.end() )
                m_events.add_thread_start(m_pid, kv.second);

        for ( const Module *m : mods_before )
            if ( mods_after.find(m) == mods_after.end() && !is_target_module(*m) )
                m_events.add_lib_unload(m_pid, current_tid(),
                                        to_utf8(m->pName, m->NameLength), (ea_t)(uint64_t)m->Address);

        for ( const Module *m : mods_after )
            if ( mods_before.find(m) == mods_before.end() )
                emit_module_load(*m);
    }

    ssize_t TraceManager::on_resume(debug_event_t *event)
    {
        // Only act when continuing from a stop (breakpoint or single step).
        if ( event->eid() != BREAKPOINT && event->eid() != STEP )
            return DRC_OK;

        // A queued request wins over IDA's resume mode: it is the user asking
        // for a movement IDA has no action of its own for.
        //
        // The request is taken and cleared before it is carried out, not after.
        // These navigations show wait boxes, which pump the message loop, so a
        // second ev_resume can arrive in the middle of one -- and a request
        // still set would be performed twice.
        if ( m_pending.kind != Request::None )
        {
            const PendingRequest req = m_pending;
            m_pending    = PendingRequest{};
            m_resumeMode = RESMOD_NONE;

            switch ( req.kind )
            {
                case Request::GotoPosition:
                    navigate_to(req.position);
                    emit_stop(false);
                    break;

                case Request::Step:
                {
                    EventType sr = navigate_steps(req.forward, StepCount{ 1 });
                    settle_after_navigation(sr, req.forward);
                    emit_stop(false);
                    break;
                }

                case Request::Run:
                {
                    EventType sr = navigate_steps(req.forward, StepCount::Max);
                    settle_after_navigation(sr, req.forward);
                    emit_stop(false);
                    break;
                }

                case Request::StepOutBackward:
                {
                    EventType sr = navigate_out_backward();
                    settle_after_navigation(sr, false);
                    emit_stop(false);
                    break;
                }

                case Request::RunToCursor:
                {
                    EventType sr = req.forward ? navigate_forward_to(req.address)
                                               : navigate_backward_to(req.address);
                    settle_after_navigation(sr, req.forward);
                    emit_stop(false);
                    break;
                }

                case Request::None:
                    break;      // excluded by the guard above
            }
            return DRC_OK;
        }

        switch ( m_resumeMode )
        {
            case RESMOD_INTO:
            {
                EventType sr = navigate_steps(true, StepCount{ 1 });
                settle_after_navigation(sr, true);
                emit_stop(sr != EventType::MemoryWatchpoint);
                break;
            }
            case RESMOD_BACKINTO:
            {
                EventType sr = navigate_steps(false, StepCount{ 1 });
                settle_after_navigation(sr, false);
                emit_stop(sr != EventType::MemoryWatchpoint);
                break;
            }
            case RESMOD_OVER:
            {
                // In backward mode this is a real backward step-over, not a plain
                // backward single step.
                EventType sr = m_isForward ? navigate_over(false)
                                           : navigate_over_backward();
                settle_after_navigation(sr, m_isForward);
                emit_stop(sr != EventType::MemoryWatchpoint);
                break;
            }
            case RESMOD_OUT:
            {
                // Likewise: backward step-out is the frame walk, not one step.
                EventType sr = m_isForward ? navigate_over(true)
                                           : navigate_out_backward();
                settle_after_navigation(sr, m_isForward);
                emit_stop(sr != EventType::MemoryWatchpoint);
                break;
            }
            case RESMOD_NONE:
            {
                // Run/continue in the currently selected direction until a
                // watchpoint hits or the trace boundary is reached.
                EventType sr = navigate_steps(m_isForward, StepCount::Max);
                settle_after_navigation(sr, m_isForward);
                emit_stop(false);
                break;
            }
            default:
            {
                // A resume mode this backend does not implement: source-level
                // stepping, RESMOD_USER, RESMOD_HANDLE, or anything IDA adds
                // later. None is advertised in dbg.resume_modes, so none should
                // arrive. Step once rather than falling through to RESMOD_NONE,
                // which would replay to the end of the trace.
                msg("[ida-ttd] unsupported resume mode %d; stepping once instead.\n",
                    (int)m_resumeMode);
                EventType sr = navigate_steps(m_isForward, StepCount{ 1 });
                settle_after_navigation(sr, m_isForward);
                emit_stop(true);
                break;
            }
        }

        m_resumeMode = RESMOD_NONE;
        return DRC_OK;
    }

    ssize_t TraceManager::on_exit_process()
    {
        m_events.add_process_exit(m_pid);
        return DRC_OK;
    }

    //=======================================================================
    // UI helpers
    //=======================================================================
    void TraceManager::set_next_position(const Position &p)
    {
        m_pending          = PendingRequest{};
        m_pending.kind     = Request::GotoPosition;
        m_pending.position = from_core(p);
    }

    Position TraceManager::current_position() const
    {
        if ( !m_cursor )
            return Position::none();
        return to_core(m_cursor->GetPosition());
    }

    Position TraceManager::last_position() const
    {
        return m_engine ? to_core(m_engine->GetLastPosition()) : Position::none();
    }

    void TraceManager::request_backward_step()
    {
        if ( !m_cursor )
        {
            warning("Time travel is only available while replaying a trace.");
            return;
        }
        m_pending         = PendingRequest{};
        m_pending.kind    = Request::Step;
        m_pending.forward = false;
        request_continue_process();
        run_requests();
    }

    void TraceManager::request_single_step(bool forward)
    {
        if ( !m_cursor )
        {
            warning("Time travel is only available while replaying a trace.");
            return;
        }
        m_pending         = PendingRequest{};
        m_pending.kind    = Request::Step;
        m_pending.forward = forward;
        request_continue_process();
        run_requests();
    }

    void TraceManager::request_run(bool forward)
    {
        if ( !m_cursor )
        {
            warning("Time travel is only available while replaying a trace.");
            return;
        }
        m_pending         = PendingRequest{};
        m_pending.kind    = Request::Run;
        m_pending.forward = forward;
        request_continue_process();
        run_requests();
    }

    void TraceManager::request_step_out_backward()
    {
        if ( !m_cursor )
        {
            warning("Time travel is only available while replaying a trace.");
            return;
        }
        m_pending         = PendingRequest{};
        m_pending.kind    = Request::StepOutBackward;
        m_pending.forward = false;
        request_continue_process();
        run_requests();
    }

    void TraceManager::request_run_to_cursor_backward(ea_t addr)
    {
        if ( !m_cursor )
        {
            warning("Time travel is only available while replaying a trace.");
            return;
        }
        if ( addr == BADADDR )
            return;
        m_pending         = PendingRequest{};
        m_pending.kind    = Request::RunToCursor;
        m_pending.forward = false;
        m_pending.address = addr;
        request_continue_process();
        run_requests();
    }

    void TraceManager::request_run_to_cursor_forward(ea_t addr)
    {
        if ( !m_cursor )
        {
            warning("Time travel is only available while replaying a trace.");
            return;
        }
        if ( addr == BADADDR )
            return;
        m_pending         = PendingRequest{};
        m_pending.kind    = Request::RunToCursor;
        m_pending.forward = true;
        m_pending.address = addr;
        request_continue_process();
        run_requests();
    }

    TTD::Replay::UniqueCursor TraceManager::make_cursor()
    {
        if ( !m_engine )
            return TTD::Replay::UniqueCursor{};
        return TTD::Replay::UniqueCursor{ m_engine->NewCursor() };
    }

    ea_t TraceManager::current_pc_ea() const
    {
        return m_cursor ? program_counter() : BADADDR;
    }

    uint64_t TraceManager::trace_fingerprint() const
    {
        if ( !m_engine )
            return 0;
        // Process id, the extent of the recording and how many modules it saw.
        // Not a hash of the file -- that would mean reading gigabytes -- but
        // enough that two different recordings do not collide in practice, and
        // it costs nothing.
        const SystemInfo &si = m_engine->GetSystemInfo();
        uint64_t v = (uint64_t)si.ProcessId;
        v = v * 1099511628211ull ^ (uint64_t)m_engine->GetFirstPosition().Sequence;
        v = v * 1099511628211ull ^ (uint64_t)m_engine->GetLastPosition().Sequence;
        v = v * 1099511628211ull ^ (uint64_t)m_engine->GetLastPosition().Steps;
        v = v * 1099511628211ull ^ (uint64_t)m_engine->GetModuleCount();
        return v;
    }

    void TraceManager::goto_position()
    {
        if ( !m_cursor )
        {
            warning("Time travel is only available while replaying a trace.");
            return;
        }

        qstring prompt;
        prompt.sprnt("Go to position (%s)", position_syntax());
        qstring str;
        if ( !ask_str(&str, 0, "%s", prompt.c_str()) )
            return;

        Position p;
        if ( !parse_position(str.c_str(), &p) )
        {
            warning("Invalid position. Expected %s, e.g. 4B17B:1D4D", position_syntax());
            return;
        }

        set_next_position(p);
        request_continue_process();
        run_requests();
    }

    std::vector<TraceManager::NamedPosition> TraceManager::collect_positions() const
    {
        std::vector<NamedPosition> out;
        if ( !m_engine )
            return out;

        // NB: the pThreadInfo / pModule back-pointers are checked before use --
        // resolve_symbols() already guards pModule, so a null is possible here too
        // and would otherwise crash the Timeline.
        {
            size_t n = m_engine->GetThreadCreatedEventCount();
            const ThreadCreatedEvent *list = m_engine->GetThreadCreatedEventList();
            for ( size_t i = 0; i < n; i++ )
            {
                if ( list[i].pThreadInfo == nullptr )
                    continue;
                qstring nm;
                nm.sprnt("Thread 0x%X created", (uint32_t)list[i].pThreadInfo->Id);
                out.push_back({ std::string(nm.c_str()), to_core(list[i].Position) });
            }
        }
        {
            size_t n = m_engine->GetThreadTerminatedEventCount();
            const ThreadTerminatedEvent *list = m_engine->GetThreadTerminatedEventList();
            for ( size_t i = 0; i < n; i++ )
            {
                if ( list[i].pThreadInfo == nullptr )
                    continue;
                qstring nm;
                nm.sprnt("Thread 0x%X exited", (uint32_t)list[i].pThreadInfo->Id);
                out.push_back({ std::string(nm.c_str()), to_core(list[i].Position) });
            }
        }
        {
            size_t n = m_engine->GetModuleLoadedEventCount();
            const ModuleLoadedEvent *list = m_engine->GetModuleLoadedEventList();
            for ( size_t i = 0; i < n; i++ )
            {
                if ( list[i].pModule == nullptr )
                    continue;
                std::string nm = "Load " + base_name(to_utf8(list[i].pModule->pName, list[i].pModule->NameLength));
                out.push_back({ nm, to_core(list[i].Position) });
            }
        }
        {
            size_t n = m_engine->GetModuleUnloadedEventCount();
            const ModuleUnloadedEvent *list = m_engine->GetModuleUnloadedEventList();
            for ( size_t i = 0; i < n; i++ )
            {
                if ( list[i].pModule == nullptr )
                    continue;
                std::string nm = "Unload " + base_name(to_utf8(list[i].pModule->pName, list[i].pModule->NameLength));
                out.push_back({ nm, to_core(list[i].Position) });
            }
        }
        {
            size_t n = m_engine->GetExceptionEventCount();
            const ExceptionEvent *list = m_engine->GetExceptionEventList();
            for ( size_t i = 0; i < n; i++ )
            {
                qstring nm;
                nm.sprnt("Exception 0x%08X @ 0x%llX", list[i].Code, (uint64_t)list[i].ProgramCounter);
                out.push_back({ std::string(nm.c_str()), to_core(list[i].Position) });
            }
        }

        std::sort(out.begin(), out.end(),
                  [](const NamedPosition &a, const NamedPosition &b) { return a.pos < b.pos; });
        return out;
    }
}
