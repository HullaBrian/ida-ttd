#include "debugger/trace_manager.h"
#include "core/diag.h"
#include "common/strings.h"
#include "analysis/query_runner.h"
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
    // Report a start_process failure through errbuf (which IDA shows) and the
    // output window, and return 'drc'. A bare DRC_* with an empty errbuf makes
    // IDA print a generic "cannot start process" and hides the real reason.
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
    // SessionOptions
    //=======================================================================
    // Set DOPT_LOAD_DINFO on or off and return the options as they were.
    // set_debugger_options replaces the options and returns the old ones,
    // with no getter, so the old set goes straight back with only this bit
    // changed (CLAUDE.md: it is never called to read them alone).
    static uint swap_load_dinfo(bool on)
    {
        uint dopts = set_debugger_options(0);
        set_debugger_options(on ? dopts | DOPT_LOAD_DINFO : dopts & ~(uint)DOPT_LOAD_DINFO);
        return dopts;
    }

    SessionOptions::SessionOptions()
    {
        m_savedAf    = inf_get_af();
        m_dinfoWasOn = (swap_load_dinfo(false) & DOPT_LOAD_DINFO) != 0;
        apply();
    }

    void SessionOptions::apply() const
    {
        // Stop the analysis cascade: with AF_PROC ("create functions if call
        // is present") each on-stop add_func() would make IDA create and
        // analyze every callee recursively, across whole modules. CodeAnalyzer
        // defines the current function and its direct callees itself.
        inf_set_af(m_savedAf & ~(uint32)(AF_PROC | AF_PROCPTR));
        // ModuleRegistry::load_pdb loads module PDBs silently, so IDA's
        // automatic debug-file loading (which asks "load symbols?" per
        // module) is turned off.
        swap_load_dinfo(false);
    }

    SessionOptions::~SessionOptions()
    {
        inf_set_af(m_savedAf);
        // Only put back if the user had it on; off, it is already as it was.
        if ( m_dinfoWasOn )
            swap_load_dinfo(true);
    }

    //=======================================================================
    // ForkDraft
    //=======================================================================
    ssize_t ForkDraft::overlay_read(size_t *nbytes, ea_t ea, void *buffer, size_t size, ssize_t rc) const
    {
        if ( bytes.empty() )
            return rc;
        // A read is a prefix of the range (MemoryReader zero-fills past it).
        // Fork bytes written right after that prefix, or where the recording
        // has nothing at all, are readable too, so the prefix is extended
        // over consecutive draft bytes; the user sees what was written rather
        // than unreadable memory.
        size_t n = rc == DRC_OK ? *nbytes : 0;
        while ( n < size && bytes.count(ea + n) != 0 )
            n++;
        uchar *out = (uchar *)buffer;
        for ( auto it = bytes.lower_bound(ea); it != bytes.end() && it->first < ea + n; ++it )
            out[it->first - ea] = it->second;
        if ( n == 0 )
            return rc;
        *nbytes = n;
        return DRC_OK;
    }

    void ForkDraft::overlay_registers(regval_t *values) const
    {
        for ( const auto &[idx, v] : regs )
            values[idx].set_int(v);
    }

    void ForkDraft::fill_request(ForkRequest *req, bool is64) const
    {
        req->at = at;
        req->regs.clear();
        req->memory.clear();
        for ( const auto &[idx, v] : regs )
            req->regs.emplace_back(fork_register_index(idx, is64), (uint64_t)v);
        // Runs of consecutive bytes, one write each.
        for ( auto it = bytes.begin(); it != bytes.end(); )
        {
            ea_t start = it->first;
            bytevec_t run;
            ea_t next = start;
            for ( ; it != bytes.end() && it->first == next; ++it, ++next )
                run.push_back(it->second);
            req->memory.emplace_back(start, std::move(run));
        }
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
        // Nothing to show yet: the debugger has only been selected. The TTD
        // actions appear in on_start_process, once a trace is loaded.
        return DRC_OK;
    }

    ssize_t TraceManager::on_term()
    {
        // First: the download workers hold no IDA state, but must not outlive
        // the session that asked for their work.
        symsrv_shutdown();
        // Usually done already (on_exit_process); without it, this is the
        // last chance before the segments go.
        m_kept.capture_all();
        if ( m_hooks.on_end )
            m_hooks.on_end();
        set_current_trace(0);
        m_options.reset();      // the analysis flags and debugger options go back
        // Also drops queued events, which describe this trace's modules and
        // threads.
        reset_session_state();
        return DRC_OK;
    }

    void TraceManager::reset_session_state()
    {
        // A query's wait loop pumps the UI, so the session can end while its
        // worker is inside the backend (and may hold cursors from it): stop
        // it before anything below is torn down.
        stop_running_query();
        end_travel_wait();
        // Everything that holds a cursor goes before the backend that made it.
        m_code.reset();
        m_kept.reset();
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
        m_toldThreads.clear();
        m_toldMods.clear();
        m_stepMode = false;
        m_draft    = ForkDraft{};
        m_shownAt  = Position::none();
        m_shownCaptured = false;
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
        diag_rotate();
        diag("session start: %s", path != nullptr ? path : "(null)");
        DiagTimer diag_timer("session start", 0);
        // A session can end without its events being drained, and the caches
        // describe the previous recording's addresses.
        reset_session_state();
        m_is64 = inf_is_64bit();

        // The analysis flags and debugger options a session runs with
        // (SessionOptions), until on_term.
        if ( !m_options )
            m_options.emplace();
        else
            m_options->apply();
        // The module the database is of, so its load can trigger a rebase. A
        // loader-created database records it; otherwise it is the name of the
        // file IDA opened.
        {
            TraceLink link;
            if ( trace_link_read(&link) && !link.module_name.empty() )
                m_targetName = link.module_name.c_str();
            else
                m_targetName = base_name(input_path != nullptr ? input_path : "");
        }

        if ( path == nullptr || !std::filesystem::exists(std::filesystem::u8path(path)) )
        {
            return start_failed(errbuf, DRC_NOFILE,
                       "Trace file not found: %s\n\n"
                       "Put the trace path in the 'Application' field of the "
                       "debugger dialog.", path != nullptr ? path : "(null)");
        }

        // The backend for this kind of recording: the bundled Microsoft one for
        // a .run, a user-installed one (load_backend_modules) for others.
        load_backend_modules();
        m_tracePath = path;
        ITraceBackend *backend = BackendRegistry::instance().for_file(path);
        if ( backend == nullptr )
        {
            return start_failed(errbuf, DRC_NOFILE,
                       "No installed backend reads %s.\n\n"
                       "A Microsoft TTD trace (.run) is read by the plugin itself; "
                       "other kinds need their backend DLL in the ida-ttd\\backends folder of "
                       "your IDA user directory (%%APPDATA%%\\Hex-Rays\\IDA Pro); "
                       "TTD > Backends installs the Sogen one.",
                       path);
        }
        qstring err;
        if ( !backend->open(path, &err) )
            return start_failed(errbuf, DRC_FAILED, "%s", err.c_str());
        m_backend = backend;
        set_position_backend(m_backend);
        // Microsoft's memory index; returns at once when the loader built it.
        prepare_backend(m_backend);
        msg("[ida-ttd] %s is a %s recording.\n", path, m_backend->display_name());

        m_modules.bind(m_backend, m_is64, m_targetName.c_str());
        m_memory.bind(&m_modules);
        m_kept.bind(&m_modules, &m_memory);
        m_code.bind(m_backend, &m_modules, &m_memory, &m_kept, m_is64);
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
        m_modules.set_now(m_cursor->position());

        // Tell the analysis stores which recording is open, so results saved
        // for another one are not shown.
        set_current_trace(trace_fingerprint());

        // Put the plugin's symbol store first in the symbol path, so the PDB
        // plugin only resolves files that are already local.
        symsrv_install_path();

        // A memory map costs a full replay, so one saved for this recording is
        // reused; one saved for another trace fails the fingerprint check.
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

        // Live threads other than the current one, and loaded modules other
        // than the main one; this becomes what IDA has been told.
        m_toldThreads = snapshot_threads();
        m_toldMods    = snapshot_modules();
        thid_t cur_tid = current_tid();
        for ( uint32_t t : m_toldThreads )
            if ( (thid_t)t != cur_tid )
                m_events.add_thread_start(m_pid, (thid_t)t);
        for ( const auto &kv : m_toldMods )
            if ( kv.second->base != mainBase )
                emit_module_load(*kv.second);

        // Finally, suspend at the entry position.
        emit_stop(StopEvent::Suspended);
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
        if ( m_eventLog.size() >= EVENT_LOG_LINES )
            m_eventLog.pop_front();
        m_eventLog.push_back(line);
        diag("event log: %s", line.c_str());
    }

    ssize_t TraceManager::on_read_memory(size_t *nbytes, ea_t ea, void *buffer, size_t size)
    {
        // During a movement the navigator is replaying m_cursor, and the wait
        // box's message pump can deliver this read; reading the cursor then
        // would re-enter the backend. The stop flushes IDA's memory cache
        // (on_suspended), so the failed read is not kept.
        if ( !m_cursor || m_navigating )
        {
            *nbytes = 0;
            return DRC_FAILED;
        }
        ssize_t rc = m_memory.read(m_cursor.get(), nbytes, ea, buffer, size);
        if ( at_fork_draft() )
            rc = m_draft.overlay_read(nbytes, ea, buffer, size, rc);
        return rc;
    }

    size_t TraceManager::reread_range(ea_t lo, ea_t hi)
    {
        if ( !m_cursor || lo >= hi )
            return 0;

        // A range this large is a mis-click; reconstruction allocates a buffer
        // of the whole span.
        static const uint64_t kMaxReread = 64u * 1024 * 1024;
        if ( (uint64_t)(hi - lo) > kMaxReread )
        {
            warning("That range is %llu MB. Select at most %llu MB to re-read.",
                    (uint64_t)(hi - lo) >> 20, kMaxReread >> 20);
            return 0;
        }

        size_t recovered = m_memory.reread(m_cursor.get(), lo, hi);

        // Flush IDA's cache for the range so the next read goes through
        // on_read_memory, then re-analyze it.
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
        // Not mid-movement: the cursor's position is in flux (see
        // on_read_memory). What IDA has still describes the position it was
        // shown, so it is told nothing changed (the SDK's DRC_NOCHG, as its
        // own debuggers answer an unchanged layout) rather than that the
        // layout cannot be had; the stop compares again (SegmentLayout::
        // refresh) and has IDA re-read a layout that did change.
        if ( m_navigating )
            return m_layout.has_layout() ? DRC_NOCHG : DRC_FAILED;
        const Position here = m_cursor->position();
        // IDA may ask while it handles the module loads and unloads queued
        // before the stop, so before on_suspended: the layout it is about to
        // get deletes the functions laid out for the shown position.
        if ( here != m_shownAt && m_layout.changes_at(here) )
            capture_kept_at_shown(here);
        return m_layout.on_get_memory_info(here, ranges);
    }

    ssize_t TraceManager::on_read_registers(thid_t tid, int /*clsmask*/, regval_t *values)
    {
        // Not mid-movement (see on_read_memory); IDA re-reads the registers
        // after the stop.
        if ( !m_cursor || m_navigating )
            return DRC_FAILED;
        ittd_regs r{};
        bool ok = tid == NO_THREAD || tid == current_tid()
                ? m_cursor->read_registers(&r)
                : m_cursor->read_thread_registers((uint32_t)tid, &r);
        if ( !ok || (r.have & ITTD_REGS_GP) == 0 )
            return DRC_FAILED;
        fill_regvals(r, m_is64, values);
        if ( at_fork_draft() && (tid == NO_THREAD ? current_tid() : tid) == m_draft.tid )
            m_draft.overlay_registers(values);
        return DRC_OK;
    }

    void TraceManager::begin_fork_draft()
    {
        m_draft        = ForkDraft{};
        m_draft.active = is_active();
        m_draft.at     = current_position();
        m_draft.tid    = current_tid();
    }

    bool TraceManager::at_fork_draft() const
    {
        return m_cursor && m_draft.here(m_cursor->position());
    }

    // Changes are allowed only at the draft's position; elsewhere the
    // recording is what the program did and cannot be edited.
    static const char NOT_FORKING[] =
        "a recording cannot be changed. TTD > Fork here makes the current position a fork, "
        "whose registers and memory can be changed before it is recorded";
    static const char FORK_ELSEWHERE[] =
        "the fork is at another position; go back to it to change it";
    static const char MOVING[] =
        "a movement through the recording is in progress; try again once it stops";

    // Refuse a write through IDA: say why in the output window and to IDA.
    static ssize_t refuse_write(const qstring &err, qstring *errbuf)
    {
        msg("[ida-ttd] %s.\n", err.c_str());
        if ( errbuf != nullptr )
            *errbuf = err;
        return DRC_FAILED;
    }

    ssize_t TraceManager::on_write_register(thid_t tid, int regidx, const regval_t *value, qstring *errbuf)
    {
        qstring err;
        int fidx = fork_register_index(regidx, m_is64);
        if ( m_navigating )
            err = MOVING;
        else if ( !at_fork_draft() )
            err = m_draft.active ? FORK_ELSEWHERE : NOT_FORKING;
        else if ( (tid == NO_THREAD ? current_tid() : tid) != m_draft.tid )
            err.sprnt("only the registers of the thread that runs next (%X) can be changed", (uint)m_draft.tid);
        else if ( fidx < 0 || value == nullptr || value->rvtype != RVT_INT )
            err = "a fork can change the general registers, the instruction pointer and the flags";
        if ( !err.empty() )
            return refuse_write(err, errbuf);
        m_draft.regs[regidx] = value->ival;
        return DRC_OK;
    }

    ssize_t TraceManager::on_write_memory(size_t *nbytes, ea_t ea, const void *buffer, size_t size, qstring *errbuf)
    {
        *nbytes = 0;
        if ( m_navigating )
            return refuse_write(MOVING, errbuf);
        if ( !at_fork_draft() )
            return refuse_write(m_draft.active ? FORK_ELSEWHERE : NOT_FORKING, errbuf);
        const uchar *in = (const uchar *)buffer;
        for ( size_t i = 0; i < size; i++ )
            m_draft.bytes[ea + i] = in[i];
        *nbytes = size;
        return DRC_OK;
    }

    ssize_t TraceManager::on_rebase_if_required_to(ea_t new_base)
    {
        // A loader-created database already has the main image at its recorded
        // base, so the delta is zero. rebase_program(0) is not free (it runs
        // the segment-move machinery, shows a progress box and dirties the
        // database), so it is skipped.
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
        for ( int i = 0; i < nadd + ndel; i++ )
        {
            qstring line;
            line.sprnt("bpt %s %a type %d size %d", i < nadd ? "add" : "del",
                       bpts[i].ea, (int)bpts[i].type, (int)bpts[i].size);
            log_event(line);
        }

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

        // Mid-movement (the wait box pumps messages) the navigator is running
        // with its breakpoint set, so the new set is handed over once the
        // movement ends (navigate). Until then every change is reported as
        // accepted; one the navigator refuses later is dropped there.
        if ( m_navigating )
        {
            m_bptsDeferred = true;
            for ( int i = 0; i < nadd + ndel; i++ )
                bpts[i].code = BPT_OK;
            *nbpts = nadd + ndel;
            return DRC_OK;
        }

        // The navigator takes the whole set and says which it could arm.
        // BPT_OK for a refused one would show a breakpoint that never fires.
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
        if ( m_navigating )
            log_event(qstring().sprnt("set %s during a movement", backwards ? "backwards" : "forwards"));
        return DRC_OK;
    }

    ssize_t TraceManager::on_set_resume_mode(thid_t /*tid*/, resume_mode_t resmod)
    {
        m_resumeMode = resmod;
        // Logged when it arrives mid-movement, where it belongs to a later
        // resume; the log explains a step that goes somewhere unexpected.
        if ( m_navigating )
            log_event(qstring().sprnt("resume mode %d set during a movement", (int)resmod));
        return DRC_OK;
    }

    StopReason TraceManager::navigate(bool forward, const std::function<StopReason()> &move)
    {
        // Thread and module changes are reported with the stop (emit_stop). A
        // movement can replay a long stretch, so it gets a wait box with
        // Cancel.
        StopReason sr;
        {
            WaitBoxSink sink(forward ? "Moving forward through the recording"
                                     : "Moving back through the recording");
            // Undone however move() leaves, so a throw cannot leave queries
            // refused for the session or the navigator holding a dead sink.
            // Declared after the sink, so it is undone before the sink goes.
            struct Moving
            {
                INavigator *nav;
                Moving(INavigator *n, ProgressSink *s) : nav(n)
                {
                    nav->set_progress(s);
                    set_trace_moving(true);     // no query may start from the box's pump
                }
                ~Moving()
                {
                    set_trace_moving(false);
                    nav->set_progress(nullptr);
                }
            } moving(m_nav.get(), &sink);
            sr = move();
        }
        // Module lookups that take no position answer for the playhead's,
        // from now on (never mid-movement: see ModuleRegistry::set_now).
        m_modules.set_now(m_cursor->position());

        // Breakpoints IDA changed during the movement (on_update_bpts).
        if ( m_bptsDeferred )
        {
            m_bptsDeferred = false;
            std::vector<bool> accepted;
            m_nav->set_breakpoints(m_bpts, &accepted);
            for ( size_t k = m_bpts.size(); k-- > 0; )
            {
                if ( k < accepted.size() && accepted[k] )
                    continue;
                msg("[ida-ttd] the breakpoint at %a cannot be set in this recording.\n",
                    (ea_t)m_bpts[k].addr);
                m_bpts.erase(m_bpts.begin() + (ptrdiff_t)k);
            }
        }

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
        diag("on_suspended begin");
        DiagTimer diag_timer("on_suspended");
        if ( !m_cursor )
            return;

        // Time travel breaks IDA's assumption that memory only changes going
        // forward: after a travel IDA keeps the previous position's cached
        // bytes for whatever it does not re-read.
        //
        // invalidate_dbgmem_contents() flushes and refreshes, so the listing
        // re-reads through on_read_memory. invalidate_dbg_state(DBGINV_MEMORY)
        // only marks the cache dirty and leaves the old bytes on screen.
        //
        // This brings the disassembly view to the front, like IDA's own
        // post-stop handling; Plugin::keep_decompiler_focused() restores the
        // decompiler afterwards.
        //
        // A travel can cross an allocation, protection change or free, so the
        // regions here may differ from what IDA was given. A new layout makes
        // IDA rebuild its debugger segments, deleting every function in them,
        // so the user's work on those is copied first, from the position IDA
        // was showing: the bytes are hashed to tell versions of the code
        // apart, and hashed here they would be the new position's, filing the
        // work under code it was never done on.
        const Position here = m_cursor->position();
        const bool relayout = m_layout.changes_at(here);
        if ( relayout )
        {
            DiagTimer t("stop: kept functions before the new layout");
            capture_kept_at_shown(here);
        }
        invalidate_dbgmem_contents(BADADDR, 0);
        {
            DiagTimer t("stop: memory layout");
            m_layout.refresh(here);
        }

        // A short slice of PDB naming (downloads and reads run on worker
        // threads; only set_name runs here). The plugin's poll timer sets the
        // rest while the user looks at the stop.
        {
            DiagTimer t("stop: PDB names");
            m_modules.advance_pdbs(10);
        }

        // Name exports of modules loaded here first, so a call to a newly
        // mapped export renders with its name rather than loc_/sub_.
        {
            DiagTimer t("stop: module symbols");
            m_modules.resolve_loaded(m_cursor->position());
            // The module stopped in gets its PDB now if it did not at load
            // (backends without cheap reads; see load_pdb).
            ea_t lo = 0, hi = 0;
            if ( m_modules.range_at(program_counter(), lo, hi) )
                m_modules.load_pdb(lo, true);
        }
        {
            DiagTimer t("stop: code layout");
            m_code.on_stop(m_cursor.get(), program_counter());
        }
        {
            // Before IDA decompiles the stop, so the pseudocode shows the
            // names and types that came back.
            DiagTimer t("stop: kept functions");
            restore_kept();
        }

        // Tell the user when the movement ended at the first or last position.
        // Done here, after the stop, because a modal box inside on_resume is
        // unsafe.
        // A ttd() command waiting for this stop gets them in the output window
        // instead: a modal box would leave the script (or an MCP caller)
        // waiting on someone to dismiss it.
        auto tell = [this](const char *text)
        {
            if ( m_quietStops > 0 )
                msg("[ida-ttd] %s\n", text);
            else
                info("%s", text);
        };
        if ( m_pendingBoundary == BOUNDARY_START )
            tell("Reached the start of the trace.");
        else if ( m_pendingBoundary == BOUNDARY_END )
            tell("Reached the end of the trace.");
        m_pendingBoundary = BOUNDARY_NONE;

        if ( !m_pendingNotice.empty() )
        {
            tell(m_pendingNotice.c_str());
            m_pendingNotice.clear();
        }
        // IDA's views now show this position's memory.
        m_shownAt       = m_cursor->position();
        m_shownCaptured = false;
    }

    void TraceManager::capture_kept_at_shown(Position here)
    {
        // Seeking the playhead itself, not a scratch cursor: bytes rebuilt
        // from recorded writes are served by the cursor that rebuilt them,
        // and a scratch cursor would read zeros there. A position belongs to
        // one thread's instruction, so seeking back lands on the same state;
        // the thread is checked anyway. Two seeks (about 17 ms each on
        // Microsoft TTD), only on the stops that change the layout.
        //
        // Once per shown position: IDA asking for the layout while it handles
        // the module events queued before the stop (on_get_memory_info), and
        // the stop itself (on_suspended), both call this, and whichever sees
        // the change first does the copy, so IDA's order does not matter.
        // Never during a movement, so nothing else is replaying the playhead.
        if ( m_shownCaptured || !m_shownAt.is_valid() )
            return;
        m_shownCaptured = true;
        diag("kept functions: copying before a layout change (shown %s, playhead %s)",
             format_position(m_shownAt).c_str(), format_position(here).c_str());
        const uint32_t tid = m_cursor->thread_id();
        const bool back = m_shownAt != here && m_cursor->seek(m_shownAt);
        // IDA's cache may hold reads made during the movement; the copy must
        // read the shown position's bytes throughout.
        invalidate_dbgmem_contents(BADADDR, 0);
        m_kept.capture_all();
        if ( back )
        {
            m_cursor->seek(here);
            if ( m_cursor->position() != here || m_cursor->thread_id() != tid )
                msg("[ida-ttd] after copying function work the playhead is at %s, thread %u, not %s, "
                    "thread %u.\n", format_position(m_cursor->position()).c_str(), m_cursor->thread_id(),
                    format_position(here).c_str(), tid);
        }
    }

    void TraceManager::emit_stop(StopEvent kind)
    {
        // Only queues the stop (this runs inside ev_resume). Cache invalidation
        // and disassembly/symbol work happen in on_suspended(), once IDA has
        // the process stopped. The kept-functions copy is not made here
        // either: it reads the database and flushes IDA's memory cache, which
        // is no work for inside ev_resume. If IDA asks for the layout while it
        // handles the module events queued here, on_get_memory_info copies
        // first; otherwise on_suspended does.
        ea_t pc = program_counter();
        auto stop = [&]()
        {
            switch ( kind )
            {
                case StopEvent::Step:       m_events.add_step(m_pid, current_tid(), pc);       break;
                case StopEvent::Breakpoint: m_events.add_breakpoint(m_pid, current_tid(), pc); break;
                case StopEvent::Suspended:  m_events.add_suspended(m_pid, current_tid(), pc);  break;
            }
        };
        if ( !m_stepMode )
            report_differences();
        stop();
    }

    void TraceManager::report_differences()
    {
        std::set<uint32_t> threads = snapshot_threads();
        auto mods = snapshot_modules();
        apply_differences(m_toldThreads, threads, m_toldMods, mods);
        m_toldThreads = std::move(threads);
        m_toldMods    = std::move(mods);
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
        diag("resume begin: event %d, mode %d", (int)event->eid(), (int)m_resumeMode);
        DiagTimer diag_timer("resume");
        m_resumeSerial++;
        m_lastResume.sprnt("event %d, resume mode %d, %s, request %d",
                           (int)event->eid(), (int)m_resumeMode,
                           m_isForward ? "forward" : "backward", (int)m_pending.kind);
        log_event(qstring("resume: ") + m_lastResume);
        // Act only when continuing from a stop (breakpoint, step, or a travel
        // or trace edge, reported as a suspension).
        if ( event->eid() != BREAKPOINT && event->eid() != STEP && event->eid() != PROCESS_SUSPENDED )
            return DRC_OK;
        // The movement can land where a function's bytes differ, and the
        // stop's analysis then deletes it: what the user set on it while
        // stopped is copied now.
        m_kept.capture_dirty();
        if ( !m_nav )
            return DRC_OK;

        // A resume that arrives during a movement (its wait box pumps
        // messages, and IDA's step actions stay enabled until ev_resume
        // returns) is dropped: carrying it out would move the navigator from
        // inside its own progress callback. The outer movement's stop answers
        // both resumes, since IDA only waits for the process to stop again. A
        // request queued for it is dropped too, so it cannot surprise the next
        // step.
        if ( m_navigating )
        {
            msg("[ida-ttd] a movement is already in progress; ignoring the new one.\n");
            log_event("resume ignored: a movement is in progress");
            m_pending    = PendingRequest{};
            m_resumeMode = RESMOD_NONE;
            return DRC_OK;
        }
        // Likewise during a whole-recording query (its wait box pumps too):
        // the backend is busy with the query's replay. Nothing outer will
        // stop, so the stop is reported where the cursor already is.
        if ( query_in_progress() )
        {
            msg("[ida-ttd] a trace query is running; staying at the current position.\n");
            log_event("resume ignored: a query is in progress");
            m_pending    = PendingRequest{};
            m_resumeMode = RESMOD_NONE;
            emit_stop(StopEvent::Suspended);
            return DRC_OK;
        }
        struct NavigatingFlag
        {
            bool &f;
            explicit NavigatingFlag(bool &flag) : f(flag) { f = true; }
            ~NavigatingFlag() { f = false; }
        } navigating(m_navigating);

        // Take this resume's mode and clear it before moving, not after. IDA
        // can set the next resume's mode while the wait box pumps messages (a
        // second step pressed during a long backward step). Cleared afterwards,
        // that mode was lost, the next resume read RESMOD_NONE, and with the
        // direction still backwards the step ran to the start of the trace.
        const resume_mode_t mode = m_resumeMode;
        m_resumeMode = RESMOD_NONE;

        // IDA's own step modes, as opposed to a run or a queued request.
        m_stepMode = m_pending.kind == Request::None && mode != RESMOD_NONE;

        // A queued request wins over IDA's resume mode: it is a movement IDA
        // has no action of its own for.
        if ( m_pending.kind != Request::None )
        {
            // Taken and cleared before it is carried out: the wait box pumps
            // messages, so a second ev_resume can arrive meanwhile and would
            // perform a request still set a second time.
            const PendingRequest req = m_pending;
            m_pending = PendingRequest{};

            // A breakpoint event only where the movement stopped on one: IDA
            // complains about any other ("unknown debugger breakpoint").
            switch ( req.kind )
            {
                case Request::GotoPosition:
                    navigate_to(req.position);
                    emit_stop(StopEvent::Suspended);
                    break;

                case Request::Step:
                    emit_stop(stop_event(navigate(req.forward, [&]() { return m_nav->step(req.forward); })));
                    break;

                case Request::Run:
                    emit_stop(stop_event(navigate(req.forward, [&]() { return m_nav->run(req.forward); })));
                    break;

                case Request::StepOutBackward:
                    emit_stop(stop_event(navigate(false, [&]() { return m_nav->step_out(false); })));
                    break;

                case Request::RunToCursor:
                    emit_stop(stop_event(navigate(req.forward,
                                                  [&]() { return m_nav->run_to(req.address, req.forward); })));
                    break;

                case Request::None:
                    break;      // excluded by the guard above
            }
            return DRC_OK;
        }

        switch ( mode )
        {
            case RESMOD_INTO:
                emit_stop(step_event(navigate(true, [&]() { return m_nav->step(true); })));
                break;

            case RESMOD_BACKINTO:
                emit_stop(step_event(navigate(false, [&]() { return m_nav->step(false); })));
                break;

            case RESMOD_OVER:
            {
                // Backwards this is a real backward step-over, not a single
                // step. A backend without one steps once.
                bool fwd = m_isForward;
                emit_stop(step_event(navigate(fwd, [&]()
                {
                    StopReason r = m_nav->step_over(fwd);
                    return r == StopReason::Failed ? m_nav->step(fwd) : r;
                })));
                break;
            }
            case RESMOD_OUT:
            {
                // Likewise: backward step-out is the frame walk, not one step.
                bool fwd = m_isForward;
                StopReason sr = navigate(fwd, [&]() { return m_nav->step_out(fwd); });
                if ( sr == StopReason::Failed && m_pendingNotice.empty() )
                    m_pendingNotice = "This recording's backend cannot step out in that direction.";
                emit_stop(step_event(sr));
                break;
            }
            case RESMOD_NONE:
            {
                // Run in the selected direction to a breakpoint or the trace
                // edge.
                bool fwd = m_isForward;
                emit_stop(stop_event(navigate(fwd, [&]() { return m_nav->run(fwd); })));
                break;
            }
            default:
            {
                // A resume mode not implemented here (source-level stepping,
                // RESMOD_USER, RESMOD_HANDLE, later additions). None is
                // advertised in dbg.resume_modes. Step once rather than fall
                // through to RESMOD_NONE, which would run to the trace's end.
                // A breakpoint on the instruction stepped to is reported as
                // one, as for the step modes above.
                msg("[ida-ttd] unsupported resume mode %d; stepping once instead.\n",
                    (int)mode);
                bool fwd = m_isForward;
                emit_stop(step_event(navigate(fwd, [&]() { return m_nav->step(fwd); })));
                break;
            }
        }
        return DRC_OK;
    }

    bool TraceManager::restore_kept()
    {
        if ( !m_cursor || m_navigating || !m_kept.has_pending() )
            return false;
        return m_kept.restore_pending(m_cursor.get()) != 0;
    }

    ssize_t TraceManager::on_exit_process()
    {
        // The segments are still there; once the exit is reported, IDA
        // deletes them.
        m_kept.capture_all();
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
        // Only when a resume will follow to take it down, and not in batch
        // mode.
        if ( !m_travelWait && !batch && get_process_state() == DSTATE_SUSP )
        {
            show_wait_box("HIDECANCEL\nGoing to position %s...", format_position(p).c_str());
            m_travelWait = true;
        }
    }

    void TraceManager::end_travel_wait()
    {
        if ( m_travelWait )
        {
            m_travelWait = false;
            hide_wait_box();
        }
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

    void TraceManager::queue_request(Request kind, bool forward, ea_t address)
    {
        if ( !need_session(m_cursor) )
            return;
        m_pending         = PendingRequest{};
        m_pending.kind    = kind;
        m_pending.forward = forward;
        m_pending.address = address;
        request_continue_process();
        run_requests();
    }

    void TraceManager::request_single_step(bool forward)
    {
        queue_request(Request::Step, forward);
    }

    void TraceManager::request_run(bool forward)
    {
        queue_request(Request::Run, forward);
    }

    void TraceManager::request_step_out_backward()
    {
        queue_request(Request::StepOutBackward, false);
    }

    void TraceManager::request_run_to_cursor_backward(ea_t addr)
    {
        if ( addr != BADADDR )
            queue_request(Request::RunToCursor, false, addr);
    }

    void TraceManager::request_run_to_cursor_forward(ea_t addr)
    {
        if ( addr != BADADDR )
            queue_request(Request::RunToCursor, true, addr);
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
