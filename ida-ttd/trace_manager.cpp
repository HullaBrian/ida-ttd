#include "trace_manager.h"
#include "registers.h"
#include "plugin.h"
#include "symbols.h"

using namespace TTD;
using namespace TTD::Replay;

namespace idattd
{
    //=======================================================================
    // String helpers
    //=======================================================================
    static std::string to_utf8(const wchar_t *w, size_t len)
    {
        if ( w == nullptr || len == 0 )
            return std::string();
        int n = WideCharToMultiByte(CP_UTF8, 0, w, (int)len, nullptr, 0, nullptr, nullptr);
        if ( n <= 0 )
            return std::string();
        std::string s((size_t)n, '\0');
        WideCharToMultiByte(CP_UTF8, 0, w, (int)len, s.data(), n, nullptr, nullptr);
        return s;
    }

    static std::string to_utf8(const wchar_t *w)
    {
        return to_utf8(w, w != nullptr ? wcslen(w) : 0);
    }

    static std::wstring to_wstring(const char *s)
    {
        if ( s == nullptr || *s == '\0' )
            return std::wstring();
        int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, nullptr, 0);
        if ( n <= 0 )
            return std::wstring();
        std::wstring w((size_t)n, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, s, -1, w.data(), n);
        if ( !w.empty() && w.back() == L'\0' )
            w.pop_back();
        return w;
    }

    static std::string base_name(const std::string &path)
    {
        size_t p = path.find_last_of("\\/");
        return p == std::string::npos ? path : path.substr(p + 1);
    }

    //=======================================================================
    // IdaErrorReporting
    //=======================================================================
    void __fastcall IdaErrorReporting::VPrintError(char const *pFmt, va_list argList)
    {
        char buf[2048];
        qvsnprintf(buf, sizeof(buf), pFmt, argList);
        msg("[ida-ttd] TTD: %s\n", buf);
    }

    //=======================================================================
    // Index build progress
    //=======================================================================
    static void __stdcall index_progress(void const * /*ctx*/, IndexBuildProgressType const *d) noexcept
    {
        if ( d != nullptr && d->KeyframeCount > 0 )
        {
            int pct = (int)((uint64_t)d->KeyframesProcessed * 100 / d->KeyframeCount);
            replace_wait_box("Building TTD index... %d%%", pct);
        }
    }

    //=======================================================================
    // TraceManager
    //=======================================================================
    TraceManager::TraceManager()
    {
        m_nextPosition = Position::Min;
    }

    //-----------------------------------------------------------------------
    thid_t TraceManager::current_tid() const
    {
        const ThreadInfo &ti = m_cursor->GetThreadInfo();
        return (thid_t)(uint32_t)ti.Id;
    }

    //-----------------------------------------------------------------------
    ea_t TraceManager::program_counter() const
    {
        return (ea_t)(uint64_t)m_cursor->GetProgramCounter();
    }

    //-----------------------------------------------------------------------
    std::map<uint32_t, thid_t> TraceManager::snapshot_threads() const
    {
        std::map<uint32_t, thid_t> result;
        size_t n = m_cursor->GetThreadCount();
        const ActiveThreadInfo *list = m_cursor->GetThreadList();
        for ( size_t i = 0; i < n; i++ )
            result[(uint32_t)list[i]->UniqueId] = (thid_t)(uint32_t)list[i]->Id;
        return result;
    }

    //-----------------------------------------------------------------------
    std::set<const Module *> TraceManager::snapshot_modules() const
    {
        std::set<const Module *> result;
        size_t n = m_cursor->GetModuleCount();
        const ModuleInstance *list = m_cursor->GetModuleList();
        for ( size_t i = 0; i < n; i++ )
            result.insert(list[i].pModule);
        return result;
    }

    //-----------------------------------------------------------------------
    bool TraceManager::is_target_module(const Module &m) const
    {
        if ( m_targetName.empty() )
            return false;
        std::string bn = base_name(to_utf8(m.pName, m.NameLength));
        return _stricmp(bn.c_str(), m_targetName.c_str()) == 0;
    }

    //-----------------------------------------------------------------------
    void TraceManager::emit_module_load(const Module &m)
    {
        std::string name = to_utf8(m.pName, m.NameLength);
        ea_t base   = (ea_t)(uint64_t)m.Address;
        ea_t rebase = is_target_module(m) ? base : BADADDR;
        m_events.add_lib_load(name, base, rebase, (asize_t)m.Size);
    }

    //-----------------------------------------------------------------------
    ssize_t TraceManager::on_init()
    {
        if ( m_plugin != nullptr )
            m_plugin->show_actions();
        return DRC_OK;
    }

    //-----------------------------------------------------------------------
    ssize_t TraceManager::on_term()
    {
        if ( m_plugin != nullptr )
            m_plugin->hide_actions();
        m_cursor.reset();
        m_symCursor.reset();
        m_anaCursor.reset();
        m_engine.reset();
        m_resolvedBases.clear();
        m_pdbBases.clear();
        m_funcRanges.clear();
        return DRC_OK;
    }

    //-----------------------------------------------------------------------
    ssize_t TraceManager::on_get_processes(procinfo_vec_t *procs)
    {
        process_info_t info;
        info.pid  = m_pid;
        info.name = "TTD trace";
        procs->push_back(info);
        return DRC_OK;
    }

    //-----------------------------------------------------------------------
    ssize_t TraceManager::on_get_debapp_attrs(debapp_attrs_t *attrs)
    {
        attrs->addrsize = m_is64 ? 8 : 4;
        attrs->is_be    = false;
        return DRC_OK;
    }

    //-----------------------------------------------------------------------
    ssize_t TraceManager::on_start_process(const char *path, const char *input_path, qstring *errbuf)
    {
        m_isForward          = true;
        m_resumeMode         = RESMOD_NONE;
        m_hasNextPosition    = false;
        m_backwardSingleStep = false;
        m_forwardSingleStep  = false;
        m_runOnce            = false;
        m_stepOutBackward    = false;
        m_activeBpts         = 0;
        m_resolvedBases.clear();
        m_pdbBases.clear();
        m_funcRanges.clear();
        m_winLo              = BADADDR;
        m_winHi              = 0;
        m_is64               = inf_is_64bit();
        m_targetName         = base_name(input_path != nullptr ? input_path : "");

        // We load module PDBs ourselves, silently (see load_module_pdb), so turn
        // OFF IDA's automatic debug-file loading — otherwise it pops a "load
        // symbols?" confirmation for every module. (set_debugger_options REPLACES
        // the option set and returns the old one, so clear just this bit.)
        uint dopts = set_debugger_options(0);
        set_debugger_options(dopts & ~(uint)DOPT_LOAD_DINFO);

        if ( path == nullptr || !std::filesystem::exists(path) )
        {
            msg("[ida-ttd] trace file not found: %s\n", path != nullptr ? path : "(null)");
            msg("[ida-ttd] Put the .run trace path in the 'Application' field of the debugger dialog.\n");
            return DRC_NOFILE;
        }

        // Validate the TTD magic ("TTDLog").
        {
            std::ifstream f(path, std::ios::binary);
            char magic[6] = { 0 };
            if ( !f.is_open() || !f.read(magic, sizeof(magic))
              || memcmp(magic, "TTDLog", sizeof(magic)) != 0 )
            {
                msg("[ida-ttd] not a valid TTD trace (bad magic): %s\n", path);
                return DRC_NOFILE;
            }
        }

        auto made = MakeReplayEngine();
        m_engine = std::move(made.first);
        if ( made.second != 0 || !m_engine )
        {
            msg("[ida-ttd] failed to create the TTD replay engine (0x%08X).\n", made.second);
            msg("[ida-ttd] Are TTDReplay.dll / TTDReplayCPU.dll next to ida.exe?\n");
            return DRC_FAILED;
        }

        m_engine->RegisterDebugModeAndLogging(DebugModeType::None, &m_err);

        std::wstring wpath = to_wstring(path);
        if ( !m_engine->Initialize(wpath.c_str()) )
        {
            msg("[ida-ttd] failed to load the trace: %s\n", path);
            return DRC_FAILED;
        }

        // Build the memory index if it is not already present. Without it,
        // memory reads are severely limited.
        if ( m_engine->GetIndexStatus() != IndexStatus::IndexFileLoaded )
        {
            show_wait_box("Building TTD index...");
            m_engine->BuildIndex(index_progress, nullptr, IndexBuildFlags::None);
            hide_wait_box();
        }

        m_cursor = UniqueCursor{ m_engine->NewCursor() };
        if ( !m_cursor )
        {
            msg("[ida-ttd] failed to create a cursor.\n");
            return DRC_FAILED;
        }
        m_cursor->SetPosition(Position::Min);

        if ( m_plugin != nullptr )
            m_plugin->show_actions();

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

    //-----------------------------------------------------------------------
    ssize_t TraceManager::on_get_debug_event(gdecode_t *code, debug_event_t *event, int /*timeout_ms*/)
    {
        if ( m_events.empty() )
        {
            *code = GDE_NO_EVENT;
            return DRC_OK;
        }
        *event = m_events.pop();
        *code  = m_events.empty() ? GDE_ONE_EVENT : GDE_MANY_EVENTS;
        return DRC_OK;
    }

    //-----------------------------------------------------------------------
    ssize_t TraceManager::on_read_memory(size_t *nbytes, ea_t ea, void *buffer, size_t size)
    {
        *nbytes = 0;
        if ( !m_cursor || buffer == nullptr || size == 0 )
            return DRC_OK;

        MemoryBuffer mb = m_cursor->QueryMemoryBuffer(
            GuestAddress{ (uint64_t)ea },
            BufferView{ buffer, size });
        *nbytes = mb.Memory.Size;
        return DRC_OK;
    }

    //-----------------------------------------------------------------------
    ssize_t TraceManager::on_get_memory_info(meminfo_vec_t *ranges)
    {
        memory_info_t mi;
        mi.start_ea = 0;
        mi.end_ea   = m_is64 ? (ea_t)0x7FFFFFFFFFFFull : (ea_t)0xFFFFFFFFull;
        mi.name     = "TTD";
        mi.bitness  = m_is64 ? 2 : 1;
        mi.perm     = SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC;
        ranges->push_back(mi);
        return DRC_OK;
    }

    //-----------------------------------------------------------------------
    ssize_t TraceManager::on_read_registers(thid_t tid, int /*clsmask*/, regval_t *values)
    {
        if ( !m_cursor )
            return DRC_FAILED;
        ThreadId t = tid == NO_THREAD ? ThreadId::Invalid : (ThreadId)(uint32_t)tid;
        CROSS_PLATFORM_CONTEXT ctx = m_cursor->GetCrossPlatformContext(t);
        fill_regvals(ctx, m_is64, values);
        return DRC_OK;
    }

    //-----------------------------------------------------------------------
    ssize_t TraceManager::on_rebase_if_required_to(ea_t new_base)
    {
        rebase_program(new_base - get_imagebase(), MSF_FIXONCE);
        return DRC_OK;
    }

    //-----------------------------------------------------------------------
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

    //-----------------------------------------------------------------------
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
            if ( m_cursor->AddMemoryWatchpoint(wp) )
                m_activeBpts++;
            bpts[i].code = BPT_OK;
            (*nbpts)++;
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
            b.code = BPT_OK;
            (*nbpts)++;
        }

        m_cursor->SetEventMask(m_activeBpts > 0 ? EventMask::MemoryWatchpoint : EventMask::None);
        return DRC_OK;
    }

    //-----------------------------------------------------------------------
    ssize_t TraceManager::on_set_backwards(bool backwards)
    {
        m_isForward = !backwards;
        return DRC_OK;
    }

    //-----------------------------------------------------------------------
    ssize_t TraceManager::on_set_resume_mode(thid_t /*tid*/, resume_mode_t resmod)
    {
        m_resumeMode = resmod;
        return DRC_OK;
    }

    //-----------------------------------------------------------------------
    EventType TraceManager::navigate_steps(bool forward, StepCount steps)
    {
        auto threads_before = snapshot_threads();
        auto mods_before    = snapshot_modules();

        ICursorView::ReplayResult r = forward
            ? m_cursor->ReplayForward(Position::Max, steps)
            : m_cursor->ReplayBackward(Position::Min, steps);

        auto threads_after = snapshot_threads();
        auto mods_after    = snapshot_modules();
        apply_differences(threads_before, threads_after, mods_before, mods_after);
        return r.StopReason;
    }

    //-----------------------------------------------------------------------
    // Run forward to 'addr' on a specific thread/frame, honoring breakpoints.
    int TraceManager::run_to_addr_guarded(ea_t addr, uint64_t min_sp, uint32_t utid)
    {
        MemoryWatchpointData wp{};
        wp.Address    = GuestAddress{ (uint64_t)addr };
        wp.Size       = 1;
        wp.AccessMask = DataAccessMask::Execute;
        m_cursor->AddMemoryWatchpoint(wp);

        // The callback is shared by ALL watchpoints on the cursor: accept the
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

        m_cursor->RemoveMemoryWatchpoint(wp);
        m_cursor->SetMemoryWatchpointCallback(nullptr, 0);
        m_cursor->SetEventMask(m_activeBpts > 0 ? EventMask::MemoryWatchpoint : EventMask::None);

        if ( r.StopReason != EventType::MemoryWatchpoint )
            return 2; // hit the trace boundary
        ea_t pc = program_counter();
        return pc == addr ? 0 : 1; // 0 = landed at target, 1 = user breakpoint
    }

    //-----------------------------------------------------------------------
    // Forward step-over / step-out implemented on the main cursor: step-over a
    // call by running to the return site; step-out by repeating until the frame
    // is unwound. Single instructions are stepped directly.
    EventType TraceManager::navigate_over(bool step_out)
    {
        auto threads_before = snapshot_threads();
        auto mods_before    = snapshot_modules();

        uint64_t start_sp = (uint64_t)m_cursor->GetStackPointer();
        uint32_t utid     = (uint32_t)m_cursor->GetThreadInfo().UniqueId;
        bool hit_bpt = false;

        for ( ;; )
        {
            ea_t  pc = program_counter();
            insn_t insn;
            int len = decode_insn(&insn, pc);
            bool is_call = len > 0 && is_call_insn(insn);

            if ( is_call )
            {
                int oc = run_to_addr_guarded((ea_t)((uint64_t)pc + len), start_sp, utid);
                if ( oc == 1 ) { hit_bpt = true; break; }
                if ( oc == 2 ) break; // boundary
            }
            else
            {
                ICursorView::ReplayResult r = m_cursor->ReplayForward(Position::Max, StepCount{ 1 });
                if ( r.StopReason == EventType::MemoryWatchpoint ) { hit_bpt = true; break; }
                if ( r.StopReason == EventType::Position
                  || r.StopReason == EventType::Process
                  || r.StopReason == EventType::Error )
                    break;
            }

            if ( !step_out )
                break;                                  // step-over: a single iteration
            if ( (uint64_t)m_cursor->GetStackPointer() > start_sp )
                break;                                  // step-out: frame has returned
        }

        auto threads_after = snapshot_threads();
        auto mods_after    = snapshot_modules();
        apply_differences(threads_before, threads_after, mods_before, mods_after);

        return hit_bpt ? EventType::MemoryWatchpoint : EventType::Position;
    }

    //-----------------------------------------------------------------------
    // Backward step-out: run the cursor backward until we leave the current
    // function, i.e. land on the call instruction that entered this frame. We
    // reconstruct call depth from the executed instructions (a call seen at
    // depth 0 going backward is that entry call), stepping over nested callees.
    // This single-steps backward, so it shows a cancellable wait box.
    EventType TraceManager::navigate_out_backward()
    {
        auto threads_before = snapshot_threads();
        auto mods_before    = snapshot_modules();

        uint32_t utid = (uint32_t)m_cursor->GetThreadInfo().UniqueId;
        int  depth   = 0;
        bool hit_bpt = false;
        Position prev = m_cursor->GetPosition();

        show_wait_box("Stepping out backwards (Cancel to stop)...");
        const int CAP = 5000000;
        for ( int i = 0; i < CAP; i++ )
        {
            if ( (i & 0x3FF) == 0 && user_cancelled() )
                break;

            ICursorView::ReplayResult r = m_cursor->ReplayBackward(Position::Min, StepCount{ 1 });
            if ( r.StopReason == EventType::MemoryWatchpoint ) { hit_bpt = true; break; }

            Position now = m_cursor->GetPosition();
            if ( now.Sequence == prev.Sequence && now.Steps == prev.Steps )
                break;                                  // reached the start of the trace
            prev = now;

            if ( (uint32_t)m_cursor->GetThreadInfo().UniqueId != utid )
                continue;                               // other thread; keep rewinding

            ea_t   pc = program_counter();
            insn_t insn;
            bool   call = false, ret = false;
            if ( decode_insn(&insn, pc) > 0 )
            {
                call = is_call_insn(insn);
                ret  = is_ret_insn(insn);
            }
            if ( call )
            {
                if ( depth == 0 )
                    break;                              // the call that entered this frame
                depth--;
            }
            else if ( ret )
            {
                depth++;
            }
        }
        hide_wait_box();

        auto threads_after = snapshot_threads();
        auto mods_after    = snapshot_modules();
        apply_differences(threads_before, threads_after, mods_before, mods_after);

        return hit_bpt ? EventType::MemoryWatchpoint : EventType::Position;
    }

    //-----------------------------------------------------------------------
    // Define an instruction at the exact address 'ea'. Addresses passed here come
    // from the trace (real executed PCs), so they are true instruction
    // boundaries; clear any stale/garbage item overlapping ea first so we never
    // leave RIP pointing inside a wrongly-sized instruction.
    static void force_insn(ea_t ea)
    {
        flags64_t fl = get_flags(ea);
        if ( is_code(fl) && get_item_head(ea) == ea )
            return;                          // already a correct instruction head
        del_items(ea, DELIT_EXPAND);         // drop any item overlapping ea
        create_insn(ea);
    }

    //-----------------------------------------------------------------------
    // Lay out the function around PC. Runs on every stop, so it must be CHEAP —
    // no trace replay.
    //
    // Primary path (x64, WinDbg-style): the module's .pdata exception table gives
    // the EXACT [start,end) of the enclosing function (recovered offline in
    // resolve_symbols). We disassemble the whole range at once, so the code BEFORE
    // PC is already laid out — stepping backward no longer reveals one instruction
    // at a time. The bounds are authoritative, so there's no mis-alignment or
    // "RIP not code" prompt.
    //
    // Fallback (x86, or a module with no .pdata): linear forward layout from PC.
    // PC is RIP — a real boundary — so a straight-line decode is exact; we stop at
    // the first return. (Lines above PC only appear as you reach them; the deep,
    // user-triggered "Analyze whole function" can still recover the rest.)
    void TraceManager::analyze_current_function(ea_t pc)
    {
        segment_t *seg = getseg(pc);
        if ( seg == nullptr )
            return;
        if ( get_func(pc) != nullptr )
            return;             // already inside a defined function

        ea_t fstart, fend;
        if ( function_range_at(pc, fstart, fend) && fstart < fend && fend <= seg->end_ea )
        {
            // Disassemble the whole function. Embedded data (e.g. jump tables)
            // can't be decoded — skip a byte and keep going rather than abort.
            ea_t ip = fstart;
            for ( int guard = 0; ip < fend && guard < 0x20000; guard++ )
            {
                if ( is_code(get_flags(ip)) )
                {
                    ea_t nxt = get_item_end(ip);
                    ip = nxt > ip ? nxt : ip + 1;
                    continue;
                }
                int len = create_insn(ip);
                ip += len > 0 ? len : 1;
            }
            add_func(fstart, fend);     // define it with the authoritative bounds
            return;
        }

        // ---- runtime-allocated code (no module / no .pdata): shellcode, unpacked
        // code, JIT. Use the trace to lay out a window of actually-executed code
        // around PC (correct boundaries, both directions). ----
        lay_out_window(pc);
    }

    //-----------------------------------------------------------------------
    void TraceManager::lay_out_window(ea_t pc)
    {
        if ( !m_engine || !m_cursor )
            return;

        // Already have a laid-out window comfortably surrounding PC? Skip the
        // replay (cheap path while stepping inside the same region).
        if ( pc >= m_winLo + 0x40 && pc + 0x40 <= m_winHi && is_code(get_flags(pc)) )
            return;

        if ( !m_anaCursor )
            m_anaCursor = UniqueCursor{ m_engine->NewCursor() };
        if ( !m_anaCursor )
        {
            force_insn(pc);
            return;
        }

        const uint64_t BEFORE = 64;    // instructions of context before PC
        const uint64_t AFTER  = 192;   // instructions after PC
        const ea_t     W      = 0x2000;// only realize code within +/-W of PC

        Position cur = m_cursor->GetPosition();
        uint32_t tid = (uint32_t)m_cursor->GetThreadInfo().UniqueId;

        // Seek the scratch cursor a little before the current position, then
        // replay FORWARD (cheap — no per-step keyframe re-seek like going back).
        Position start = cur;
        start.Steps = (StepCount)((uint64_t)cur.Steps > BEFORE ? (uint64_t)cur.Steps - BEFORE : 0);
        m_anaCursor->SetPosition(start);

        std::set<ea_t> pcs;
        int budget = (int)((BEFORE + AFTER) * 3) + 256;  // extra for thread interleaving
        Position prev = m_anaCursor->GetPosition();
        for ( int i = 0; i < budget; i++ )
        {
            if ( (uint32_t)m_anaCursor->GetThreadInfo().UniqueId == tid )
            {
                ea_t a = (ea_t)(uint64_t)m_anaCursor->GetProgramCounter();
                ea_t d = a > pc ? a - pc : pc - a;
                if ( d <= W )
                    pcs.insert(a);
            }
            m_anaCursor->ReplayForward(Position::Max, StepCount{ 1 });
            Position now = m_anaCursor->GetPosition();
            if ( now.Sequence == prev.Sequence && now.Steps == prev.Steps )
                break;                  // reached the end of the trace
            prev = now;
        }

        // Realize the exact executed instructions (these are real boundaries).
        for ( ea_t a : pcs )
            force_insn(a);

        if ( pcs.empty() )
        {
            force_insn(pc);             // at least the current instruction
            m_winLo = m_winHi = BADADDR;
            return;
        }

        // Extend forward by linear decode from the furthest laid-out instruction
        // (exact: it starts on a real boundary) so the user can scroll ahead.
        ea_t ip = *pcs.rbegin();
        ea_t flimit = pc + 0x200;
        for ( int g = 0; ip < flimit && g < 4096; g++ )
        {
            if ( is_code(get_flags(ip)) )
            {
                ea_t nxt = get_item_end(ip);
                ip = nxt > ip ? nxt : ip + 1;
                continue;
            }
            int len = create_insn(ip);
            if ( len <= 0 )
                break;
            ip += len;
        }

        m_winLo = *pcs.begin();
        m_winHi = ip > *pcs.rbegin() ? ip : *pcs.rbegin();
    }

    //-----------------------------------------------------------------------
    // Deep, on-demand analysis: reconstruct the current thread's call structure by
    // walking the trace backward (stepping over nested calls via a call-depth
    // counter) to find the enclosing function's entry, then define it. This is the
    // expensive path the per-stop handler intentionally avoids, so it runs on a
    // private cursor behind a cancellable wait box.
    void TraceManager::analyze_whole_function()
    {
        if ( !m_cursor || !m_engine )
        {
            warning("Analysis is only available while replaying a trace.");
            return;
        }
        ea_t pc = program_counter();
        if ( getseg(pc) == nullptr )
            return;
        if ( get_func(pc) != nullptr )
        {
            info("0x%llX is already inside a defined function.", (uint64_t)pc);
            return;
        }

        UniqueCursor cur{ m_engine->NewCursor() };
        if ( !cur )
            return;
        cur->SetPosition(m_cursor->GetPosition());
        uint32_t target_tid = (uint32_t)cur->GetThreadInfo().Id;

        std::vector<ea_t> frame_pcs;
        std::set<ea_t>    seen;
        frame_pcs.push_back(pc);
        seen.insert(pc);
        ea_t entry   = BADADDR;
        ea_t last_pc = pc;
        int  depth   = 0;

        const int MAX_INSN = 50000;
        const int MAX_STEP = 1000000;
        int examined = 0, steps = 0;
        bool cancelled = false;
        Position prev = cur->GetPosition();

        show_wait_box("Analyzing function from the trace (Cancel to stop)...");
        while ( examined < MAX_INSN && steps < MAX_STEP )
        {
            if ( (steps & 0x3FF) == 0 )
            {
                replace_wait_box("Analyzing function: %d instructions examined...", examined);
                if ( user_cancelled() ) { cancelled = true; break; }
            }

            cur->ReplayBackward(Position::Min, StepCount{ 1 });
            steps++;
            Position now = cur->GetPosition();
            if ( now.Sequence == prev.Sequence && now.Steps == prev.Steps )
                break;                              // reached the start of the trace
            prev = now;

            if ( (uint32_t)cur->GetThreadInfo().Id != target_tid )
                continue;
            examined++;

            ea_t   npc = (ea_t)(uint64_t)cur->GetProgramCounter();
            insn_t insn;
            bool   call = false, ret = false;
            if ( decode_insn(&insn, npc) > 0 )
            {
                call = is_call_insn(insn);
                ret  = is_ret_insn(insn);
            }

            if ( call )
            {
                if ( depth == 0 ) { entry = last_pc; break; }
                depth--;
            }
            else if ( ret )
            {
                depth++;
            }

            if ( depth == 0 && seen.insert(npc).second )
                frame_pcs.push_back(npc);
            last_pc = npc;
        }
        hide_wait_box();

        std::sort(frame_pcs.begin(), frame_pcs.end());
        for ( ea_t a : frame_pcs )
            force_insn(a);

        if ( cancelled )
        {
            msg("[ida-ttd] function analysis cancelled (%d instructions, %d defined).\n",
                examined, (int)frame_pcs.size());
        }
        else if ( entry != BADADDR )
        {
            force_insn(entry);
            add_func(entry);
            msg("[ida-ttd] defined function at 0x%llX (entry of the call at the "
                "current position; %d instructions).\n", (uint64_t)entry, examined);
            jumpto(entry);
        }
        else
        {
            warning("Could not find the function entry within %d instructions.\n"
                    "Laid out the %d instruction(s) found in this frame.",
                    examined, (int)frame_pcs.size());
        }
    }

    //-----------------------------------------------------------------------
    void TraceManager::on_suspended()
    {
        if ( !m_cursor )
            return;
        // Name exports of any module loaded at this position first, so a call to a
        // freshly-revealed export renders with its name rather than loc_/sub_.
        resolve_loaded_modules();
        analyze_current_function(program_counter());
    }

    //-----------------------------------------------------------------------
    void TraceManager::resolve_loaded_modules()
    {
        if ( !m_cursor )
            return;
        size_t n = m_cursor->GetModuleCount();
        const ModuleInstance *list = m_cursor->GetModuleList();
        for ( size_t i = 0; i < n; i++ )
            if ( list[i].pModule != nullptr )
                resolve_symbols((ea_t)(uint64_t)list[i].pModule->Address, m_is64);
    }

    void TraceManager::emit_stop(bool is_step)
    {
        // Just queue the stop event here (during ev_resume). The actual
        // disassembly/symbol work happens in on_suspended(), once IDA has
        // invalidated its debugger memory cache for the new position.
        ea_t pc = program_counter();
        if ( is_step )
            m_events.add_step(m_pid, current_tid(), pc);
        else
            m_events.add_breakpoint(m_pid, current_tid(), pc);
    }

    //-----------------------------------------------------------------------
    void TraceManager::navigate_to(const Position &p)
    {
        auto threads_before = snapshot_threads();
        auto mods_before    = snapshot_modules();
        m_cursor->SetPosition(p);
        auto threads_after = snapshot_threads();
        auto mods_after    = snapshot_modules();
        apply_differences(threads_before, threads_after, mods_before, mods_after);
    }

    //-----------------------------------------------------------------------
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
                m_events.add_lib_unload(to_utf8(m->pName, m->NameLength), (ea_t)(uint64_t)m->Address);

        for ( const Module *m : mods_after )
            if ( mods_before.find(m) == mods_before.end() )
                emit_module_load(*m);
    }

    //-----------------------------------------------------------------------
    ssize_t TraceManager::on_resume(debug_event_t *event)
    {
        // Only act when continuing from a stop (breakpoint or single step).
        if ( event->eid() != BREAKPOINT && event->eid() != STEP )
            return DRC_OK;

        if ( m_hasNextPosition )
        {
            navigate_to(m_nextPosition);
            emit_stop(false);
            m_hasNextPosition = false;
            m_resumeMode = RESMOD_NONE;
            return DRC_OK;
        }

        if ( m_backwardSingleStep )
        {
            navigate_steps(false, StepCount{ 1 });
            emit_stop(false);
            m_backwardSingleStep = false;
            m_resumeMode = RESMOD_NONE;
            return DRC_OK;
        }

        if ( m_forwardSingleStep )
        {
            navigate_steps(true, StepCount{ 1 });
            emit_stop(false);
            m_forwardSingleStep = false;
            m_resumeMode = RESMOD_NONE;
            return DRC_OK;
        }

        if ( m_runOnce )
        {
            navigate_steps(m_runForward, StepCount::Max);
            emit_stop(false);
            m_runOnce = false;
            m_resumeMode = RESMOD_NONE;
            return DRC_OK;
        }

        if ( m_stepOutBackward )
        {
            navigate_out_backward();
            emit_stop(false);
            m_stepOutBackward = false;
            m_resumeMode = RESMOD_NONE;
            return DRC_OK;
        }

        switch ( m_resumeMode )
        {
            case RESMOD_INTO:
            {
                EventType sr = navigate_steps(true, StepCount{ 1 });
                emit_stop(sr != EventType::MemoryWatchpoint);
                break;
            }
            case RESMOD_BACKINTO:
            {
                EventType sr = navigate_steps(false, StepCount{ 1 });
                emit_stop(sr != EventType::MemoryWatchpoint);
                break;
            }
            case RESMOD_OVER:
            {
                EventType sr = m_isForward ? navigate_over(false)
                                           : navigate_steps(false, StepCount{ 1 });
                emit_stop(sr != EventType::MemoryWatchpoint);
                break;
            }
            case RESMOD_OUT:
            {
                EventType sr = m_isForward ? navigate_over(true)
                                           : navigate_steps(false, StepCount{ 1 });
                emit_stop(sr != EventType::MemoryWatchpoint);
                break;
            }
            case RESMOD_NONE:
            default:
            {
                // Run/continue in the currently selected direction until a
                // watchpoint hits or the trace boundary is reached.
                navigate_steps(m_isForward, StepCount::Max);
                emit_stop(false);
                break;
            }
        }

        m_resumeMode = RESMOD_NONE;
        return DRC_OK;
    }

    //-----------------------------------------------------------------------
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
        m_nextPosition    = p;
        m_hasNextPosition = true;
    }

    //-----------------------------------------------------------------------
    Position TraceManager::current_position() const
    {
        if ( !m_cursor )
            return Position::Invalid;
        return m_cursor->GetPosition();
    }

    //-----------------------------------------------------------------------
    void TraceManager::request_backward_step()
    {
        if ( !m_cursor )
        {
            warning("Time travel is only available while replaying a trace.");
            return;
        }
        m_backwardSingleStep = true;
        request_continue_process();
        run_requests();
    }

    //-----------------------------------------------------------------------
    void TraceManager::request_single_step(bool forward)
    {
        if ( !m_cursor )
        {
            warning("Time travel is only available while replaying a trace.");
            return;
        }
        if ( forward )
            m_forwardSingleStep = true;
        else
            m_backwardSingleStep = true;
        request_continue_process();
        run_requests();
    }

    //-----------------------------------------------------------------------
    void TraceManager::request_run(bool forward)
    {
        if ( !m_cursor )
        {
            warning("Time travel is only available while replaying a trace.");
            return;
        }
        m_runOnce    = true;
        m_runForward = forward;
        request_continue_process();
        run_requests();
    }

    //-----------------------------------------------------------------------
    void TraceManager::request_step_out_backward()
    {
        if ( !m_cursor )
        {
            warning("Time travel is only available while replaying a trace.");
            return;
        }
        m_stepOutBackward = true;
        request_continue_process();
        run_requests();
    }

    //-----------------------------------------------------------------------
    TTD::Replay::UniqueCursor TraceManager::make_cursor()
    {
        if ( !m_engine )
            return TTD::Replay::UniqueCursor{};
        return TTD::Replay::UniqueCursor{ m_engine->NewCursor() };
    }

    //-----------------------------------------------------------------------
    // Case-insensitive shell wildcard match ('*' = any run, '?' = one char).
    static bool wildcard_match(const char *pat, const char *str)
    {
        const char *star = nullptr;
        const char *ss   = str;
        const char *p    = pat;
        const char *s    = str;
        while ( *s != '\0' )
        {
            if ( *p == '?' || tolower((unsigned char)*p) == tolower((unsigned char)*s) )
            {
                p++;
                s++;
            }
            else if ( *p == '*' )
            {
                star = p++;
                ss   = s;
            }
            else if ( star != nullptr )
            {
                p = star + 1;
                s = ++ss;
            }
            else
            {
                return false;
            }
        }
        while ( *p == '*' )
            p++;
        return *p == '\0';
    }

    //-----------------------------------------------------------------------
    std::vector<ea_t> TraceManager::resolve_function_pattern(const char *pattern) const
    {
        std::vector<ea_t> out;
        if ( !m_engine || pattern == nullptr )
            return out;

        // Split an optional "module!" qualifier off the name pattern.
        std::string pat = pattern;
        std::string modpat, namepat;
        size_t bang = pat.find('!');
        if ( bang != std::string::npos )
        {
            modpat  = pat.substr(0, bang);
            namepat = pat.substr(bang + 1);
        }
        else
        {
            namepat = pat;
        }
        if ( namepat.empty() )
            return out;

        // Build module address ranges (only needed when a module filter exists).
        struct ModRange { ea_t base; ea_t end; std::string name; std::string stem; };
        std::vector<ModRange> mods;
        if ( !modpat.empty() )
        {
            size_t n = m_engine->GetModuleCount();
            const Module *list = m_engine->GetModuleList();
            for ( size_t i = 0; i < n; i++ )
            {
                ea_t b = (ea_t)(uint64_t)list[i].Address;
                std::string bn = base_name(to_utf8(list[i].pName, list[i].NameLength));
                std::string stem = bn;
                size_t dot = stem.find_last_of('.');
                if ( dot != std::string::npos )
                    stem.erase(dot);
                mods.push_back({ b, b + (ea_t)list[i].Size, bn, stem });
            }
        }

        std::set<ea_t> seen;
        size_t nn = get_nlist_size();
        for ( size_t i = 0; i < nn; i++ )
        {
            const char *nm = get_nlist_name(i);
            if ( nm == nullptr || !wildcard_match(namepat.c_str(), nm) )
                continue;
            ea_t ea = get_nlist_ea(i);

            if ( !modpat.empty() )
            {
                bool ok = false;
                for ( const ModRange &m : mods )
                {
                    if ( ea >= m.base && ea < m.end )
                    {
                        ok = wildcard_match(modpat.c_str(), m.name.c_str())
                          || wildcard_match(modpat.c_str(), m.stem.c_str());
                        break;
                    }
                }
                if ( !ok )
                    continue;
            }

            func_t *f = get_func(ea);
            ea_t key = f != nullptr ? f->start_ea : ea;
            if ( seen.insert(key).second )
                out.push_back(key);
        }
        return out;
    }

    //-----------------------------------------------------------------------
    void TraceManager::load_module_pdb(ea_t base)
    {
        if ( base == BADADDR || !m_engine )
            return;
        if ( !m_pdbBases.insert(base).second )
            return;     // already requested for this module

        // The module's path lets the PDB plugin find the PE / its debug directory
        // (it can also read the PE from debugger memory at 'base').
        std::string path;
        size_t n = m_engine->GetModuleCount();
        const Module *list = m_engine->GetModuleList();
        for ( size_t i = 0; i < n; i++ )
        {
            if ( (ea_t)(uint64_t)list[i].Address == base )
            {
                path = to_utf8(list[i].pName, list[i].NameLength);
                break;
            }
        }
        if ( path.empty() )
            return;

        // Drive the PDB plugin with PDB_CC_USER_WITH_DATA (3): it reads the load
        // address + path from the "$ pdb" netnode and applies symbols WITHOUT the
        // "load symbols?" prompt that the automatic DOPT_LOAD_DINFO path shows.
        static const char *PDB_NODE_NAME = "$ pdb";
        const int PDB_DLLBASE_NODE_IDX  = 0;
        const int PDB_DLLNAME_NODE_IDX  = 0;
        const int PDB_CC_USER_WITH_DATA = 3;
        netnode pdbnode;
        pdbnode.create(PDB_NODE_NAME);
        pdbnode.altset(PDB_DLLBASE_NODE_IDX, base);
        pdbnode.supset(PDB_DLLNAME_NODE_IDX, path.c_str(), path.size() + 1);

        // Suppress the plugin's dialogs while it runs: when offline / the PDB
        // can't be found, it would otherwise pop an error or file-locate dialog
        // for every module. With 'batch' set those are turned into log lines, and
        // we report the miss to the output window ourselves.
        bool old_batch = batch;
        batch = true;
        bool ran = load_and_run_plugin("pdb", PDB_CC_USER_WITH_DATA);
        batch = old_batch;

        // The plugin writes its success flag back into the same netnode slot.
        if ( !ran || pdbnode.altval(PDB_DLLBASE_NODE_IDX) == 0 )
            msg("[ida-ttd] PDB symbols not resolved for %s (offline or unavailable).\n",
                base_name(path).c_str());
    }

    //-----------------------------------------------------------------------
    void TraceManager::resolve_symbols(ea_t base, bool is64)
    {
        if ( !m_engine || base == BADADDR )
            return;
        if ( !m_resolvedBases.insert(base).second )
            return;     // already attempted for this module

        // Find the load event for the module at this base so we can park the
        // scratch cursor exactly where the image is recorded as mapped.
        size_t n = m_engine->GetModuleLoadedEventCount();
        const ModuleLoadedEvent *list = m_engine->GetModuleLoadedEventList();
        const ModuleLoadedEvent *hit = nullptr;
        for ( size_t i = 0; i < n; i++ )
        {
            if ( list[i].pModule != nullptr
              && (ea_t)(uint64_t)list[i].pModule->Address == base )
            {
                hit = &list[i];
                break;
            }
        }

        if ( !m_symCursor )
            m_symCursor = TTD::Replay::UniqueCursor{ m_engine->NewCursor() };
        if ( !m_symCursor )
            return;

        m_symCursor->SetPosition(hit != nullptr ? hit->Position : Position::Min);
        size_t named = apply_module_exports(m_symCursor.get(), base, is64);

        // Recover this module's function boundaries from its .pdata exception
        // table so we can lay out whole functions (incl. code before the current
        // PC) when the user steps into runtime-only code — no symbols, no replay.
        // Prefer the on-disk PE (reliable); fall back to recorded memory, since
        // TTD may not have captured the .pdata section.
        std::string modpath = hit != nullptr && hit->pModule != nullptr
                            ? to_utf8(hit->pModule->pName, hit->pModule->NameLength)
                            : std::string();
        std::vector<std::pair<ea_t, ea_t>> ranges;
        size_t nfunc = parse_pdata_functions_from_file(modpath.c_str(), base, is64, ranges);
        if ( nfunc == 0 )
            nfunc = parse_pdata_functions(m_symCursor.get(), base, is64, ranges);
        if ( nfunc > 0 )
            m_funcRanges[base] = std::move(ranges);

        msg("[ida-ttd] %s @ 0x%llX: %u export(s), %u function range(s)\n",
            base_name(modpath).c_str(), (uint64_t)base, (unsigned)named, (unsigned)nfunc);
    }

    //-----------------------------------------------------------------------
    bool TraceManager::function_range_at(ea_t pc, ea_t &start, ea_t &end) const
    {
        if ( !m_engine )
            return false;

        // Which module is PC in?
        ea_t modbase = BADADDR;
        size_t n = m_engine->GetModuleCount();
        const Module *list = m_engine->GetModuleList();
        for ( size_t i = 0; i < n; i++ )
        {
            ea_t b = (ea_t)(uint64_t)list[i].Address;
            ea_t e = b + (ea_t)list[i].Size;
            if ( pc >= b && pc < e ) { modbase = b; break; }
        }
        if ( modbase == BADADDR )
            return false;

        auto it = m_funcRanges.find(modbase);
        if ( it == m_funcRanges.end() )
            return false;

        // Last range whose start <= pc, then verify pc is within it.
        const std::vector<std::pair<ea_t, ea_t>> &v = it->second;
        auto up = std::upper_bound(v.begin(), v.end(), std::make_pair(pc, (ea_t)BADADDR));
        if ( up == v.begin() )
            return false;
        --up;
        if ( pc >= up->first && pc < up->second )
        {
            start = up->first;
            end   = up->second;
            return true;
        }
        return false;
    }

    //-----------------------------------------------------------------------
    void TraceManager::goto_position()
    {
        if ( !m_cursor )
        {
            warning("Time travel is only available while replaying a trace.");
            return;
        }

        qstring str;
        if ( !ask_str(&str, 0, "Go to position (Sequence:Steps in hex)") )
            return;

        const char *s = str.c_str();
        const char *colon = strchr(s, ':');
        if ( colon == nullptr )
        {
            warning("Invalid position. Expected format Sequence:Steps, e.g. 4B17B:1D4D");
            return;
        }

        uint64_t seq   = strtoull(std::string(s, colon).c_str(), nullptr, 16);
        uint64_t steps = strtoull(colon + 1, nullptr, 16);

        Position p{ (SequenceId)seq, (StepCount)steps };
        set_next_position(p);
        request_continue_process();
        run_requests();
    }

    //-----------------------------------------------------------------------
    std::vector<TraceManager::NamedPosition> TraceManager::collect_positions() const
    {
        std::vector<NamedPosition> out;
        if ( !m_engine )
            return out;

        {
            size_t n = m_engine->GetThreadCreatedEventCount();
            const ThreadCreatedEvent *list = m_engine->GetThreadCreatedEventList();
            for ( size_t i = 0; i < n; i++ )
            {
                qstring nm;
                nm.sprnt("Thread 0x%X created", (uint32_t)list[i].pThreadInfo->Id);
                out.push_back({ std::string(nm.c_str()), list[i].Position });
            }
        }
        {
            size_t n = m_engine->GetThreadTerminatedEventCount();
            const ThreadTerminatedEvent *list = m_engine->GetThreadTerminatedEventList();
            for ( size_t i = 0; i < n; i++ )
            {
                qstring nm;
                nm.sprnt("Thread 0x%X exited", (uint32_t)list[i].pThreadInfo->Id);
                out.push_back({ std::string(nm.c_str()), list[i].Position });
            }
        }
        {
            size_t n = m_engine->GetModuleLoadedEventCount();
            const ModuleLoadedEvent *list = m_engine->GetModuleLoadedEventList();
            for ( size_t i = 0; i < n; i++ )
            {
                std::string nm = "Load " + base_name(to_utf8(list[i].pModule->pName, list[i].pModule->NameLength));
                out.push_back({ nm, list[i].Position });
            }
        }
        {
            size_t n = m_engine->GetModuleUnloadedEventCount();
            const ModuleUnloadedEvent *list = m_engine->GetModuleUnloadedEventList();
            for ( size_t i = 0; i < n; i++ )
            {
                std::string nm = "Unload " + base_name(to_utf8(list[i].pModule->pName, list[i].pModule->NameLength));
                out.push_back({ nm, list[i].Position });
            }
        }
        {
            size_t n = m_engine->GetExceptionEventCount();
            const ExceptionEvent *list = m_engine->GetExceptionEventList();
            for ( size_t i = 0; i < n; i++ )
            {
                qstring nm;
                nm.sprnt("Exception 0x%08X @ 0x%llX", list[i].Code, (uint64_t)list[i].ProgramCounter);
                out.push_back({ std::string(nm.c_str()), list[i].Position });
            }
        }

        std::sort(out.begin(), out.end(),
                  [](const NamedPosition &a, const NamedPosition &b) { return a.pos < b.pos; });
        return out;
    }
}
