#include "debugger/trace_manager.h"
#include "analysis/trace_store.h"
#include "core/backend_module.h"
#include "core/backend_registry.h"
#include "debugger/registers.h"
#include "common/trace_link.h"
#include "common/symsrv.h"

namespace idattd
{
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
        return (thid_t)m_cursor->thread_id();
    }

    ea_t TraceManager::program_counter() const
    {
        return m_cursor->program_counter();
    }

    std::set<uint32_t> TraceManager::snapshot_threads() const
    {
        std::set<uint32_t> out;
        for ( const ThreadInfo &t : m_cursor->live_threads() )
            out.insert(t.tid);
        return out;
    }

    std::map<std::pair<ea_t, Position>, const ModuleInfo *> TraceManager::snapshot_modules() const
    {
        // Keyed by base and load position, so a module unloaded and loaded
        // again at the same address is seen as the two loads it was.
        std::map<std::pair<ea_t, Position>, const ModuleInfo *> out;
        for ( const ModuleInfo *m : m_modules.loaded_at(m_cursor->position()) )
            out[{ m->base, m->loaded }] = m;
        return out;
    }

    bool TraceManager::is_target_module(const ModuleInfo &m) const
    {
        if ( m_targetName.empty() )
            return false;
        std::string bn = base_name(m.path.empty() ? m.name.c_str() : m.path.c_str());
        return _stricmp(bn.c_str(), m_targetName.c_str()) == 0;
    }

    void TraceManager::emit_module_load(const ModuleInfo &m)
    {
        ea_t rebase = is_target_module(m) ? m.base : BADADDR;
        m_events.add_lib_load(m_pid, current_tid(), m.path.empty() ? m.name.c_str() : m.path.c_str(),
                              m.base, rebase, (asize_t)m.size);
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
        // Before anything else: the download workers hold no IDA state, but
        // they must not outlive the session that asked for their work.
        symsrv_shutdown();
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
        return DRC_OK;
    }

    void TraceManager::reset_session_state()
    {
        // Everything that holds a cursor goes before the backend that made it.
        m_code.reset();
        m_nav.reset();
        m_cursor.reset();
        m_modules.reset();
        m_memory.reset();
        m_layout.reset();
        if ( m_backend != nullptr )
            m_backend->close();
        m_backend = nullptr;
        set_position_backend(nullptr);

        m_events.clear();
        m_bpts.clear();

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
        // IDA recursively create+analyze every callee, fanning out across whole
        // modules and making navigation crawl. We define the function the user is
        // actually looking at explicitly, so disable the auto-create-from-calls
        // features for the session (restored in on_term).
        if ( !m_afSaved )
        {
            m_savedAf = inf_get_af();
            m_afSaved = true;
        }
        inf_set_af(m_savedAf & ~(uint32)(AF_PROC | AF_PROCPTR));
        // Which module the database is of, so a load of it can trigger a
        // rebase. A database created by the loader states this outright;
        // otherwise it is the name of the file IDA thinks it opened.
        {
            TraceLink link;
            if ( trace_link_read(&link) && !link.module_name.empty() )
                m_targetName = link.module_name.c_str();
            else
                m_targetName = base_name(input_path != nullptr ? input_path : "");
        }

        // We load module PDBs ourselves, silently (see ModuleRegistry::load_pdb),
        // so turn OFF IDA's automatic debug-file loading -- otherwise it pops a
        // "load symbols?" confirmation for every module. (set_debugger_options
        // REPLACES the option set and returns the old one, so clear just this
        // bit.)
        uint dopts = set_debugger_options(0);
        set_debugger_options(dopts & ~(uint)DOPT_LOAD_DINFO);

        if ( path == nullptr || !std::filesystem::exists(std::filesystem::u8path(path)) )
        {
            return start_failed(errbuf, DRC_NOFILE,
                       "Trace file not found: %s\n\n"
                       "Put the trace path in the 'Application' field of the "
                       "debugger dialog.", path != nullptr ? path : "(null)");
        }

        // Whichever backend reads this kind of recording: Microsoft TTD, built
        // in, for a .run; one loaded from plugins/ida-ttd-backends for others.
        load_backend_modules();
        ITraceBackend *backend = BackendRegistry::instance().for_file(path);
        if ( backend == nullptr )
        {
            return start_failed(errbuf, DRC_NOFILE,
                       "No installed backend reads %s.\n\n"
                       "A Microsoft TTD trace (.run) is read by the plugin itself; "
                       "other kinds need their backend in plugins\\ida-ttd-backends.",
                       path);
        }
        qstring err;
        if ( !backend->open(path, &err) )
            return start_failed(errbuf, DRC_FAILED, "%s", err.c_str());
        m_backend = backend;
        set_position_backend(m_backend);
        // Microsoft's memory index; returns at once when the loader built it.
        if ( !m_backend->prepared() )
            m_backend->prepare(nullptr);
        msg("[ida-ttd] %s is a %s recording.\n", path, m_backend->display_name());

        m_modules.bind(m_backend, m_is64, m_targetName.c_str());
        m_memory.bind(&m_modules);
        m_code.bind(m_backend, &m_modules, &m_memory, m_is64);
        m_layout.bind(&m_modules, m_is64);

        m_cursor = m_backend->make_cursor();
        if ( m_cursor )
            m_nav = m_backend->make_navigator(m_cursor.get());
        if ( !m_cursor || !m_nav )
        {
            reset_session_state();
            return start_failed(errbuf, DRC_FAILED, "Failed to create a cursor over the trace.");
        }
        m_cursor->seek(m_backend->info().first);

        // Tell the analysis stores which recording they are being read against,
        // so results saved for a different one are not shown against this one.
        set_current_trace(trace_fingerprint());

        // Put our own symbol store ahead of whatever IDA would reach for, so
        // the PDB plugin only ever resolves files that are already local.
        symsrv_install_path();

        // A memory map costs a full replay, so one saved against this recording
        // is reused rather than rebuilt. A map saved against a different trace
        // fails the fingerprint check and is ignored.
        if ( m_layout.map_for_update().load(trace_fingerprint()) )
            msg("[ida-ttd] loaded a saved memory map: %d recorded change(s).\n",
                (int)m_layout.map().size());

        if ( m_hooks.on_start )
            m_hooks.on_start();

        // ---- Build the initial set of debug events -------------------------
        const ModuleInfo *main = m_modules.main_module();
        ea_t mainBase = BADADDR;
        if ( main != nullptr )
        {
            mainBase = main->base;
            ea_t rebase = is_target_module(*main) ? mainBase : BADADDR;
            m_events.add_process_start(m_pid, current_tid(),
                                       main->path.empty() ? main->name.c_str() : main->path.c_str(),
                                       mainBase, rebase, (asize_t)main->size);
        }
        else
        {
            m_events.add_process_start(m_pid, current_tid(), "trace", BADADDR, BADADDR, 0);
        }

        // Threads currently alive (other than the current one).
        thid_t cur_tid = current_tid();
        for ( uint32_t t : snapshot_threads() )
            if ( (thid_t)t != cur_tid )
                m_events.add_thread_start(m_pid, (thid_t)t);

        // Modules currently loaded (other than the main one already reported).
        for ( const auto &kv : snapshot_modules() )
            if ( kv.second->base != mainBase )
                emit_module_load(*kv.second);

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
        qstring line;
        line.sprnt("event %d at %a", (int)event->eid(), event->ea);
        log_event(line);
        return DRC_OK;
    }

    void TraceManager::log_event(const qstring &line)
    {
        if ( m_eventLog.size() >= 16 )
            m_eventLog.pop_front();
        m_eventLog.push_back(line);
    }

    ssize_t TraceManager::on_read_memory(size_t *nbytes, ea_t ea, void *buffer, size_t size)
    {
        if ( !m_cursor )
        {
            *nbytes = 0;
            return DRC_FAILED;
        }
        return m_memory.read(m_cursor.get(), nbytes, ea, buffer, size);
    }

    size_t TraceManager::reread_range(ea_t lo, ea_t hi)
    {
        if ( !m_cursor || lo >= hi )
            return 0;

        // A range this large is a mis-click, not a request: reconstruction
        // allocates a buffer of the whole span.
        static const uint64_t kMaxReread = 64u * 1024 * 1024;
        if ( (uint64_t)(hi - lo) > kMaxReread )
        {
            warning("That range is %llu MB. Select at most %llu MB to re-read.",
                    (uint64_t)(hi - lo) >> 20, kMaxReread >> 20);
            return 0;
        }

        size_t recovered = m_memory.reread(m_cursor.get(), lo, hi);

        // Flush IDA's cache for the range so the next read goes through
        // on_read_memory again, then re-analyze what came back.
        invalidate_dbgmem_contents(lo, hi - lo);
        del_items(lo, DELIT_SIMPLE, (asize_t)(hi - lo));
        plan_range(lo, hi);
        auto_wait();
        return recovered;
    }

    ssize_t TraceManager::on_get_memory_info(meminfo_vec_t *ranges)
    {
        if ( !m_cursor )
            return DRC_FAILED;
        return m_layout.on_get_memory_info(m_cursor->position(), ranges);
    }

    ssize_t TraceManager::on_read_registers(thid_t tid, int /*clsmask*/, regval_t *values)
    {
        if ( !m_cursor )
            return DRC_FAILED;
        ittd_regs r{};
        bool ok = tid == NO_THREAD || tid == current_tid()
                ? m_cursor->read_registers(&r)
                : m_cursor->read_thread_registers((uint32_t)tid, &r);
        if ( !ok || (r.have & ITTD_REGS_GP) == 0 )
            return DRC_FAILED;
        fill_regvals(r, m_is64, values);
        return DRC_OK;
    }

    ssize_t TraceManager::on_rebase_if_required_to(ea_t new_base)
    {
        // A database the loader created already has the main image at its
        // recorded base, so the delta is zero. rebase_program(0) is not free --
        // it runs the whole segment-move machinery, shows its own progress box
        // and dirties the database -- so say no rather than doing nothing slowly.
        ea_t delta = new_base - get_imagebase();
        if ( delta == 0 )
            return DRC_OK;
        rebase_program(delta, MSF_FIXONCE);
        return DRC_OK;
    }

    static Breakpoint breakpoint_of(const update_bpt_info_t &b)
    {
        Breakpoint bp;
        bp.addr = b.ea;
        switch ( b.type )
        {
            case BPT_WRITE: bp.kinds = ACCESS_WRITE; break;
            case BPT_READ:  bp.kinds = ACCESS_READ; break;
            case BPT_RDWR:  bp.kinds = ACCESS_READ | ACCESS_WRITE; break;
            default:        bp.kinds = ACCESS_EXEC; break;
        }
        bp.size = bp.kinds == ACCESS_EXEC ? 1 : (b.size > 0 ? (uint64_t)b.size : 1);
        return bp;
    }

    ssize_t TraceManager::on_update_bpts(int *nbpts, update_bpt_info_t *bpts, int nadd, int ndel)
    {
        *nbpts = 0;
        if ( !m_nav )
            return DRC_FAILED;

        for ( int i = 0; i < ndel; i++ )
        {
            Breakpoint bp = breakpoint_of(bpts[nadd + i]);
            auto it = std::find(m_bpts.begin(), m_bpts.end(), bp);
            if ( it != m_bpts.end() )
                m_bpts.erase(it);
        }
        size_t first_new = m_bpts.size();
        for ( int i = 0; i < nadd; i++ )
            m_bpts.push_back(breakpoint_of(bpts[i]));

        // The navigator takes the whole set, and says which it could arm:
        // claiming BPT_OK for one the engine refused would leave IDA showing a
        // breakpoint that silently never fires.
        std::vector<bool> accepted;
        m_nav->set_breakpoints(m_bpts, &accepted);
        for ( int i = 0; i < nadd; i++ )
        {
            size_t k = first_new + (size_t)i;
            bool ok = k < accepted.size() && accepted[k];
            bpts[i].code = ok ? BPT_OK : BPT_BAD_ADDR;
            if ( ok )
                (*nbpts)++;
        }
        // A refused breakpoint is not kept, so it is not offered again.
        for ( size_t k = m_bpts.size(); k-- > first_new; )
            if ( k >= accepted.size() || !accepted[k] )
                m_bpts.erase(m_bpts.begin() + (ptrdiff_t)k);
        for ( int i = 0; i < ndel; i++ )
        {
            bpts[nadd + i].code = BPT_OK;
            (*nbpts)++;
        }
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

    StopReason TraceManager::navigate(bool forward, const std::function<StopReason()> &move)
    {
        auto threads_before = snapshot_threads();
        auto mods_before    = snapshot_modules();

        StopReason sr = move();

        auto threads_after = snapshot_threads();
        auto mods_after    = snapshot_modules();
        apply_differences(threads_before, threads_after, mods_before, mods_after);

        if ( sr == StopReason::TraceBoundary )
            m_pendingBoundary = forward ? BOUNDARY_END : BOUNDARY_START;
        qstring notice = m_nav->take_notice();
        if ( !notice.empty() )
            m_pendingNotice = notice;
        return sr;
    }

    void TraceManager::navigate_to(Position p)
    {
        navigate(true, [&]() { return m_nav->seek_to(p); });
        // Arriving somewhere is not running into an edge.
        m_pendingBoundary = BOUNDARY_NONE;
    }

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
        // positions. After a jump IDA keeps the previous position's cached bytes
        // for everything it doesn't re-read.
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
        m_layout.refresh(m_cursor->position());

        // Apply any PDB that finished downloading since the last stop. This is
        // the main thread, which is the only place IDA's symbol machinery may be
        // driven from.
        m_modules.apply_finished_pdbs();

        // Name exports of any module loaded at this position first, so a call to a
        // freshly-revealed export renders with its name rather than loc_/sub_.
        m_modules.resolve_loaded(m_cursor->position());
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

    void TraceManager::apply_differences(
            const std::set<uint32_t> &threads_before,
            const std::set<uint32_t> &threads_after,
            const std::map<std::pair<ea_t, Position>, const ModuleInfo *> &mods_before,
            const std::map<std::pair<ea_t, Position>, const ModuleInfo *> &mods_after)
    {
        for ( uint32_t t : threads_before )
            if ( threads_after.find(t) == threads_after.end() )
                m_events.add_thread_exit(m_pid, (thid_t)t);

        for ( uint32_t t : threads_after )
            if ( threads_before.find(t) == threads_before.end() )
                m_events.add_thread_start(m_pid, (thid_t)t);

        for ( const auto &kv : mods_before )
            if ( mods_after.find(kv.first) == mods_after.end() && !is_target_module(*kv.second) )
                m_events.add_lib_unload(m_pid, current_tid(),
                                        kv.second->path.empty() ? kv.second->name.c_str()
                                                                : kv.second->path.c_str(),
                                        kv.second->base);

        for ( const auto &kv : mods_after )
            if ( mods_before.find(kv.first) == mods_before.end() )
                emit_module_load(*kv.second);
    }

    ssize_t TraceManager::on_resume(debug_event_t *event)
    {
        m_lastResume.sprnt("event %d, resume mode %d, %s, request %d",
                           (int)event->eid(), (int)m_resumeMode,
                           m_isForward ? "forward" : "backward", (int)m_pending.kind);
        log_event(qstring("resume: ") + m_lastResume);
        // Only act when continuing from a stop (breakpoint or single step).
        if ( event->eid() != BREAKPOINT && event->eid() != STEP )
            return DRC_OK;
        if ( !m_nav )
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
                    navigate(req.forward, [&]() { return m_nav->step(req.forward); });
                    emit_stop(false);
                    break;

                case Request::Run:
                    navigate(req.forward, [&]() { return m_nav->run(req.forward); });
                    emit_stop(false);
                    break;

                case Request::StepOutBackward:
                    navigate(false, [&]() { return m_nav->step_out(false); });
                    emit_stop(false);
                    break;

                case Request::RunToCursor:
                    navigate(req.forward, [&]() { return m_nav->run_to(req.address, req.forward); });
                    emit_stop(false);
                    break;

                case Request::None:
                    break;      // excluded by the guard above
            }
            return DRC_OK;
        }

        switch ( m_resumeMode )
        {
            case RESMOD_INTO:
            {
                StopReason sr = navigate(true, [&]() { return m_nav->step(true); });
                emit_stop(sr != StopReason::Breakpoint);
                break;
            }
            case RESMOD_BACKINTO:
            {
                StopReason sr = navigate(false, [&]() { return m_nav->step(false); });
                emit_stop(sr != StopReason::Breakpoint);
                break;
            }
            case RESMOD_OVER:
            {
                // In backward mode this is a real backward step-over, not a
                // plain backward single step. A backend without one steps once.
                bool fwd = m_isForward;
                StopReason sr = navigate(fwd, [&]()
                {
                    StopReason r = m_nav->step_over(fwd);
                    return r == StopReason::Failed ? m_nav->step(fwd) : r;
                });
                emit_stop(sr != StopReason::Breakpoint);
                break;
            }
            case RESMOD_OUT:
            {
                // Likewise: backward step-out is the frame walk, not one step.
                bool fwd = m_isForward;
                StopReason sr = navigate(fwd, [&]() { return m_nav->step_out(fwd); });
                if ( sr == StopReason::Failed && m_pendingNotice.empty() )
                    m_pendingNotice = "This recording's backend cannot step out in that direction.";
                emit_stop(sr != StopReason::Breakpoint);
                break;
            }
            case RESMOD_NONE:
            {
                // Run/continue in the currently selected direction until a
                // breakpoint hits or the trace boundary is reached.
                bool fwd = m_isForward;
                navigate(fwd, [&]() { return m_nav->run(fwd); });
                emit_stop(false);
                break;
            }
            default:
            {
                // A resume mode this backend does not implement: source-level
                // stepping, RESMOD_USER, RESMOD_HANDLE, or anything IDA adds
                // later. None is advertised in dbg.resume_modes, so none should
                // arrive. Step once rather than falling through to RESMOD_NONE,
                // which would run to the end of the trace.
                msg("[ida-ttd] unsupported resume mode %d; stepping once instead.\n",
                    (int)m_resumeMode);
                bool fwd = m_isForward;
                navigate(fwd, [&]() { return m_nav->step(fwd); });
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
        m_pending.position = p;
    }

    Position TraceManager::current_position() const
    {
        return m_cursor ? m_cursor->position() : Position::none();
    }

    Position TraceManager::last_position() const
    {
        return m_backend != nullptr ? m_backend->info().last : Position::none();
    }

    static bool need_session(const CursorPtr &cursor)
    {
        if ( cursor )
            return true;
        warning("Time travel is only available while replaying a trace.");
        return false;
    }

    void TraceManager::request_backward_step()
    {
        request_single_step(false);
    }

    void TraceManager::request_single_step(bool forward)
    {
        if ( !need_session(m_cursor) )
            return;
        m_pending         = PendingRequest{};
        m_pending.kind    = Request::Step;
        m_pending.forward = forward;
        request_continue_process();
        run_requests();
    }

    void TraceManager::request_run(bool forward)
    {
        if ( !need_session(m_cursor) )
            return;
        m_pending         = PendingRequest{};
        m_pending.kind    = Request::Run;
        m_pending.forward = forward;
        request_continue_process();
        run_requests();
    }

    void TraceManager::request_step_out_backward()
    {
        if ( !need_session(m_cursor) )
            return;
        m_pending         = PendingRequest{};
        m_pending.kind    = Request::StepOutBackward;
        m_pending.forward = false;
        request_continue_process();
        run_requests();
    }

    void TraceManager::request_run_to_cursor_backward(ea_t addr)
    {
        if ( !need_session(m_cursor) || addr == BADADDR )
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
        if ( !need_session(m_cursor) || addr == BADADDR )
            return;
        m_pending         = PendingRequest{};
        m_pending.kind    = Request::RunToCursor;
        m_pending.forward = true;
        m_pending.address = addr;
        request_continue_process();
        run_requests();
    }

    ea_t TraceManager::current_pc_ea() const
    {
        return m_cursor ? program_counter() : BADADDR;
    }

    uint64_t TraceManager::trace_fingerprint() const
    {
        return m_backend != nullptr ? m_backend->info().fingerprint : 0;
    }

    void TraceManager::goto_position()
    {
        if ( !need_session(m_cursor) )
            return;

        qstring prompt;
        prompt.sprnt("Go to position (%s)", position_syntax());
        qstring str;
        if ( !ask_str(&str, 0, "%s", prompt.c_str()) )
            return;

        Position p;
        if ( !parse_position(str.c_str(), &p) )
        {
            warning("Invalid position. Expected %s.", position_syntax());
            return;
        }

        set_next_position(p);
        request_continue_process();
        run_requests();
    }

    std::vector<TraceManager::NamedPosition> TraceManager::collect_positions() const
    {
        std::vector<NamedPosition> out;
        if ( m_backend == nullptr )
            return out;
        for ( const TraceEvent &e : m_backend->timeline() )
            out.push_back({ std::string(e.what.c_str()), e.pos });
        std::stable_sort(out.begin(), out.end(),
                         [](const NamedPosition &a, const NamedPosition &b) { return a.pos < b.pos; });
        return out;
    }
}
