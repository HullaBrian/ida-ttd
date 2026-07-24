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
    // Percentage published by the TTD indexing threads, consumed by the main
    // thread's wait-box loop in on_start_process(). See index_progress().
    static std::atomic<uint32_t> g_indexPct{ 0 };

    // TTD invokes this from its own indexing WORKER THREADS. It must therefore not
    // touch IDA at all: calling replace_wait_box() here deadlocked IDA outright
    // (process alive at 0% CPU, permanently unresponsive, no window repaint) on the
    // first load of any trace with no prebuilt .idx. Publish the percentage and
    // return; the main thread renders it.
    static void __stdcall index_progress(void const * /*ctx*/, IndexBuildProgressType const *d) noexcept
    {
        if ( d != nullptr && d->KeyframeCount > 0 )
        {
            uint32_t pct = (uint32_t)((uint64_t)d->KeyframesProcessed * 100 / d->KeyframeCount);
            g_indexPct.store(pct, std::memory_order_relaxed);
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
        if ( m_afSaved )
        {
            inf_set_af(m_savedAf);   // restore the analysis flags we changed
            m_afSaved = false;
        }
        m_cursor.reset();
        m_symCursor.reset();
        m_anaCursor.reset();
        m_memCursor.reset();
        m_memPosValid = false;
        m_engine.reset();
        m_resolvedBases.clear();
        m_pdbBases.clear();
        m_funcRanges.clear();
        m_moduleImages.clear();
        m_reconRegions.clear();
        m_dynFuncBytes.clear();
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
        m_runToCursorBackward = false;
        m_runToCursorForward = false;
        m_runToCursorAddr    = BADADDR;
        m_pendingBoundary    = BOUNDARY_NONE;
        m_activeBpts         = 0;
        m_resolvedBases.clear();
        m_pdbBases.clear();
        m_funcRanges.clear();
        m_dynFuncBytes.clear();
        m_winLo              = BADADDR;
        m_winHi              = 0;
        m_is64               = inf_is_64bit();

        // Stop the analysis cascade: each on-stop add_func() traces the current
        // function, and AF_PROC ("create functions if call is present") would make
        // IDA recursively create+analyze EVERY callee (stack frames, vars, FLIRT),
        // fanning out across whole modules and making navigation crawl. We define
        // the function the user is actually looking at explicitly, so disable the
        // auto-create-from-calls features for the session (restored in on_term).
        if ( !m_afSaved )
        {
            m_savedAf = inf_get_af();
            m_afSaved = true;
        }
        inf_set_af(m_savedAf & ~(uint32)(AF_PROC | AF_PROCPTR));
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
            // BuildIndex is fully synchronous and can run for minutes, so it must NOT
            // run on the main thread: doing so blocks IDA's message loop for the whole
            // build (no repaint, no progress). Run it on a worker and let the MAIN
            // thread own the wait box, polling the percentage published by
            // index_progress(). This is also what keeps the progress callback off IDA's
            // UI (see index_progress) — the previous arrangement deadlocked IDA.
            //
            // The build cannot be interrupted: IndexBuildProgressCallback returns void
            // and BuildIndex exposes no cancellation flag, so the box is HIDECANCEL
            // rather than offering a Cancel that could not do anything.
            g_indexPct.store(0, std::memory_order_relaxed);
            std::atomic<bool> done{ false };
            IndexStatus       st = IndexStatus::IndexFileNotPresent;
            IReplayEngine    *eng = m_engine.get();

            std::thread worker([eng, &done, &st]()
            {
                st = eng->BuildIndex(index_progress, nullptr, IndexBuildFlags::None);
                done.store(true, std::memory_order_release);
            });

            show_wait_box("HIDECANCEL\nBuilding TTD index...");
            uint32_t shown = 101;                    // force the first repaint
            while ( !done.load(std::memory_order_acquire) )
            {
                uint32_t pct = g_indexPct.load(std::memory_order_relaxed);
                if ( pct != shown )
                {
                    replace_wait_box("HIDECANCEL\nBuilding TTD index... %u%%", pct);
                    shown = pct;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            worker.join();
            hide_wait_box();

            // Note: IndexFileUnloadable here is NORMAL and does not mean memory reads
            // will fail — the engine builds and uses an in-memory index, while
            // GetIndexStatus()/this result describe the on-disk .idx file only.
            if ( st != IndexStatus::IndexFileLoaded )
                msg("[ida-ttd] TTD index build finished with status %d (in-memory index still usable).\n", (int)st);
        }

        m_cursor = UniqueCursor{ m_engine->NewCursor() };
        if ( !m_cursor )
        {
            msg("[ida-ttd] failed to create a cursor.\n");
            return DRC_FAILED;
        }
        m_cursor->SetPosition(Position::Min);

        // Serve memory like WinDbg/Binja: the Default policy resolves to a
        // thread-local query that only returns memory the current thread touched
        // around the current position, so unpacked/written-earlier bytes (e.g. the
        // rest of a shellcode buffer) read back as zeros. GloballyAggressive looks
        // across the whole trace to reconstruct the value (lower confidence, but it
        // is what WinDbg/Binja effectively show) so far fewer bytes come back 0.
        m_cursor->SetDefaultMemoryPolicy(QueryMemoryPolicy::GloballyAggressive);

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
    bool TraceManager::reconstruct_region(ea_t lo, ea_t hi)
    {
        if ( !m_engine || !m_cursor || hi <= lo )
            return false;

        // Already reconstructed something covering this range?
        for ( const ReconRegion &r : m_reconRegions )
            if ( r.lo <= lo && hi <= r.hi )
                return true;

        UniqueCursor cur{ m_engine->NewCursor() };
        if ( !cur )
            return false;

        const Position target = m_cursor->GetPosition();

        ReconRegion reg;
        reg.lo = lo;
        reg.hi = hi;
        reg.data.assign((size_t)(hi - lo), 0);
        reg.known.assign((size_t)(hi - lo), false);

        size_t hits = 0;
        // On each recorded write touching [lo,hi), copy the just-written bytes (read
        // thread-locally from the writing thread, which definitely has them) into the
        // shadow. Replaying sequentially forward means the last write to each byte
        // before 'target' wins -- i.e. the value as of the current position. Return
        // false so the watchpoint never stops the replay.
        auto on_write = [&](ICursorView::MemoryWatchpointResult const &wp,
                            IThreadView const *t) noexcept -> bool
        {
            uint64_t a  = (uint64_t)wp.Address;
            uint64_t e  = a + wp.Size;
            uint64_t s  = a > (uint64_t)lo ? a : (uint64_t)lo;
            uint64_t en = e < (uint64_t)hi ? e : (uint64_t)hi;
            if ( s >= en )
                return false;
            uint8_t  buf[512];
            uint64_t off = s;
            while ( off < en )
            {
                size_t chunk = (size_t)((en - off) < sizeof(buf) ? (en - off) : sizeof(buf));
                MemoryBuffer mb = t->QueryMemoryBuffer(GuestAddress{ off }, BufferView{ buf, chunk });
                size_t got = mb.Memory.Size;
                if ( got == 0 )
                    break;
                for ( size_t i = 0; i < got; i++ )
                {
                    reg.data[(size_t)(off - lo) + i]  = buf[i];
                    reg.known[(size_t)(off - lo) + i] = true;
                }
                off += got;
            }
            hits++;
            return false;
        };

        MemoryWatchpointData wp{};
        wp.Address    = GuestAddress{ (uint64_t)lo };
        wp.Size       = (uint64_t)(hi - lo);
        wp.AccessMask = DataAccessMask::Write;
        cur->AddMemoryWatchpoint(wp);
        cur->SetMemoryWatchpointCallback(on_write);
        cur->SetEventMask(EventMask::MemoryWatchpoint);
        cur->SetReplayFlags(ReplayFlags::ReplaySegmentsSequentially); // chronological -> last write wins
        cur->SetPosition(Position::Min);

        show_wait_box("HIDECANCEL\nReconstructing memory from recorded writes...");
        cur->ReplayForward(target);
        hide_wait_box();

        cur->SetMemoryWatchpointCallback(nullptr, 0);

        size_t nknown = 0;
        for ( bool b : reg.known )
            if ( b )
                nknown++;
        msg("[ida-ttd] reconstructed 0x%llX-0x%llX: %u/%u byte(s) from %u write(s).\n",
            (uint64_t)lo, (uint64_t)hi, (unsigned)nknown, (unsigned)reg.data.size(), (unsigned)hits);

        if ( nknown == 0 )
            return false;
        m_reconRegions.push_back(std::move(reg));
        return true;
    }

    //-----------------------------------------------------------------------
    const ModuleImage *TraceManager::image_for(ea_t ea, ea_t &base_out)
    {
        if ( !m_engine )
            return nullptr;

        // Which loaded module (if any) contains 'ea'?
        ea_t   base = BADADDR;
        std::string path;
        size_t n = m_engine->GetModuleCount();
        const Module *list = m_engine->GetModuleList();
        for ( size_t i = 0; i < n; i++ )
        {
            ea_t b = (ea_t)(uint64_t)list[i].Address;
            ea_t e = b + (ea_t)list[i].Size;
            if ( ea >= b && ea < e )
            {
                base = b;
                path = to_utf8(list[i].pName, list[i].NameLength);
                break;
            }
        }
        if ( base == BADADDR )
            return nullptr;

        base_out = base;
        auto it = m_moduleImages.find(base);
        if ( it == m_moduleImages.end() )
        {
            ModuleImage img;
            load_module_image(path.c_str(), img);   // img.ok==false on failure
            msg("[ida-ttd] image fallback for %s @ 0x%llX: %s\n",
                base_name(path).c_str(), (uint64_t)base,
                img.ok ? "loaded" : "file unavailable / not a PE");
            it = m_moduleImages.emplace(base, std::move(img)).first;
        }
        return it->second.ok ? &it->second : nullptr;
    }

    //-----------------------------------------------------------------------
    ssize_t TraceManager::on_read_memory(size_t *nbytes, ea_t ea, void *buffer, size_t size)
    {
        *nbytes = 0;
        if ( !m_cursor || buffer == nullptr || size == 0 )
            return DRC_OK;

        // Serve reads from a DEDICATED cursor that is only ever positioned, never
        // executed. The main cursor is our execution cursor (we step/run with it);
        // a cursor left "in execution" answers memory queries with the thread-local
        // policy no matter what policy we request, so non-executed bytes (the rest
        // of a shellcode function) come back as zeros -- the policy arguments below
        // were simply being ignored. A position-only cursor honors the aggressive
        // policies and returns what WinDbg/Binja show. Park it at the playhead,
        // re-seeking only when the position actually changed.
        if ( !m_memCursor )
        {
            m_memCursor = UniqueCursor{ m_engine->NewCursor() };
            if ( m_memCursor )
                m_memCursor->SetDefaultMemoryPolicy(QueryMemoryPolicy::GloballyAggressive);
            m_memPosValid = false;
        }
        ICursorView *mc = m_memCursor ? m_memCursor.get() : m_cursor.get();
        if ( m_memCursor )
        {
            Position cur = m_cursor->GetPosition();
            if ( !m_memPosValid || cur.Sequence != m_memPos.Sequence || cur.Steps != m_memPos.Steps )
            {
                m_memCursor->SetPosition(cur);
                m_memPos      = cur;
                m_memPosValid = true;
            }
        }

        // QueryMemoryBuffer only ever returns the SINGLE contiguous run that begins
        // exactly at the queried address. If that address is a "hole" (a byte TTD
        // didn't record at this position) it returns Size==0 -- and a naive single
        // call then loses every KNOWN byte further into the buffer. So fill the whole
        // range in two passes:
        //
        //   Pass 1 (authoritative): walk the range querying TTD's recorded memory,
        //   skipping over holes, so every recorded byte is delivered. This reflects
        //   the true position-in-time state, including self-modified code.
        //
        //   Pass 2 (image fallback): for bytes TTD never recorded, copy from the
        //   module's on-disk image. TTD only records ACCESSED memory; image-backed
        //   code that was never executed on this run (the other side of a branch, a
        //   cold epilogue, the terminating ret) is in the trace at no position, yet
        //   it is right there in the file -- this is exactly what WinDbg shows. Image
        //   bytes only fill gaps; recorded bytes always win.
        static const QueryMemoryPolicy kPolicies[] = {
            QueryMemoryPolicy::GloballyAggressive,   // the cursor default; cheap first
            QueryMemoryPolicy::InFragmentAggressive, // look across the whole fragment
        };

        uint8_t *out = (uint8_t *)buffer;
        std::vector<bool> filled(size, false);
        size_t resolved_end = 0;     // one past the last byte we resolved (either source)

        // ---- Pass 1: recorded memory ----
        size_t off = 0;
        while ( off < size )
        {
            MemoryBuffer mb{};
            for ( QueryMemoryPolicy p : kPolicies )
            {
                mb = mc->QueryMemoryBuffer(
                    GuestAddress{ (uint64_t)(ea + off) },
                    BufferView{ out + off, size - off }, p);
                if ( mb.Memory.Size > 0 )
                    break;
            }
            if ( mb.Memory.Size > 0 )
            {
                size_t run = mb.Memory.Size;
                for ( size_t i = 0; i < run; i++ )
                    filled[off + i] = true;
                off         += run;
                resolved_end = off;
            }
            else
            {
                out[off] = 0;        // hole: leave 0 for now, later passes may fill it
                off++;
            }
        }

        // ---- Pass R: override with bytes reconstructed from recorded writes ----
        // For non-module memory the position query only zero-fills (it knows the page
        // is mapped but has no recorded value to attribute here). Where we've rebuilt
        // the real bytes from the trace's writes, those win -- they equal the live
        // value as of the reconstruction position, so this also corrects pass 1's
        // zero-fill for never-executed code (the other half of a branch, the ret).
        for ( const ReconRegion &r : m_reconRegions )
        {
            ea_t s = ea > r.lo ? ea : r.lo;
            ea_t e = (ea + (ea_t)size) < r.hi ? (ea + (ea_t)size) : r.hi;
            for ( ea_t a = s; a < e; a++ )
            {
                size_t ri = (size_t)(a - r.lo);
                if ( !r.known[ri] )
                    continue;
                size_t oi = (size_t)(a - ea);
                out[oi]    = r.data[ri];
                filled[oi] = true;
                if ( oi + 1 > resolved_end )
                    resolved_end = oi + 1;
            }
        }

        // ---- Pass 2: on-disk image fills the gaps ----
        size_t o = 0;
        while ( o < size )
        {
            if ( filled[o] )
            {
                o++;
                continue;
            }
            // Measure the contiguous gap so an image run can't clobber recorded bytes.
            size_t gap = 0;
            while ( o + gap < size && !filled[o + gap] )
                gap++;

            ea_t              base = BADADDR;
            const ModuleImage *img = image_for(ea + o, base);
            if ( img == nullptr )
            {
                o += gap;            // not image-backed: the gap stays zero
                continue;
            }
            // Fill the gap one image-run at a time (a run stops at a section edge).
            size_t g = 0;
            while ( g < gap )
            {
                uint32_t rva = (uint32_t)((uint64_t)(ea + o + g) - (uint64_t)base);
                size_t run = read_module_image_rva(*img, rva, out + o + g, gap - g);
                if ( run == 0 )
                {
                    g++;             // zero-fill tail / unmapped rva: leave 0
                    continue;
                }
                for ( size_t i = 0; i < run; i++ )
                    filled[o + g + i] = true;
                if ( o + g + run > resolved_end )
                    resolved_end = o + g + run;
                g += run;
            }
            o += gap;
        }

        *nbytes = resolved_end;
        // Nothing at this address is recorded, reconstructed, or image-backed: it
        // is unmapped/unknown memory. Report a read FAILURE rather than a silent
        // zero-fill — otherwise IDA treats the whole address space (advertised as
        // one big segment) as readable and the register/stack views dereference a
        // garbage pointer into 0, then dereference that 0, ad infinitum.
        return resolved_end == 0 ? DRC_FAILED : DRC_OK;
    }

    //-----------------------------------------------------------------------
    ssize_t TraceManager::on_get_memory_info(meminfo_vec_t *ranges)
    {
        memory_info_t mi;
        // Start above the Windows null page (the low 64 KiB is always reserved /
        // unmapped). Excluding it stops IDA from treating small integers (0, 1, ...)
        // as valid TTD pointers and recursively dereferencing them in the
        // register/stack views.
        mi.start_ea = 0x10000;
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
    // Run backward to 'addr': set a temporary Execute watchpoint there and replay
    // backward. The engine seeks straight to the previous execution of 'addr' (one
    // ReplayBackward — cheap, NOT a backward single-step loop), stopping there or
    // at any user breakpoint hit on the way, or at the start of the trace.
    EventType TraceManager::navigate_backward_to(ea_t addr)
    {
        auto threads_before = snapshot_threads();
        auto mods_before    = snapshot_modules();

        MemoryWatchpointData wp{};
        wp.Address    = GuestAddress{ (uint64_t)addr };
        wp.Size       = 1;
        wp.AccessMask = DataAccessMask::Execute;
        m_cursor->AddMemoryWatchpoint(wp);
        m_cursor->SetEventMask(EventMask::MemoryWatchpoint);

        ICursorView::ReplayResult r = m_cursor->ReplayBackward();

        m_cursor->RemoveMemoryWatchpoint(wp);
        m_cursor->SetEventMask(m_activeBpts > 0 ? EventMask::MemoryWatchpoint : EventMask::None);

        auto threads_after = snapshot_threads();
        auto mods_after    = snapshot_modules();
        apply_differences(threads_before, threads_after, mods_before, mods_after);
        return r.StopReason;
    }

    //-----------------------------------------------------------------------
    // Run forward to 'addr': set a temporary Execute watchpoint there and replay
    // forward. The engine seeks straight to the next execution of 'addr' (one
    // ReplayForward — cheap), stopping there, at any user breakpoint hit on the
    // way, or at the end of the trace. If the cursor is already on 'addr', step
    // once first so we advance to the NEXT occurrence instead of matching here.
    EventType TraceManager::navigate_forward_to(ea_t addr)
    {
        auto threads_before = snapshot_threads();
        auto mods_before    = snapshot_modules();

        if ( program_counter() == addr )
            m_cursor->ReplayForward(Position::Max, StepCount{ 1 });

        MemoryWatchpointData wp{};
        wp.Address    = GuestAddress{ (uint64_t)addr };
        wp.Size       = 1;
        wp.AccessMask = DataAccessMask::Execute;
        m_cursor->AddMemoryWatchpoint(wp);
        m_cursor->SetEventMask(EventMask::MemoryWatchpoint);

        ICursorView::ReplayResult r = m_cursor->ReplayForward();

        m_cursor->RemoveMemoryWatchpoint(wp);
        m_cursor->SetEventMask(m_activeBpts > 0 ? EventMask::MemoryWatchpoint : EventMask::None);

        auto threads_after = snapshot_threads();
        auto mods_after    = snapshot_modules();
        apply_differences(threads_before, threads_after, mods_before, mods_after);
        return r.StopReason;
    }

    //-----------------------------------------------------------------------
    void TraceManager::flag_boundary(EventType sr, bool forward)
    {
        // A breakpoint stop is not a trace edge.
        if ( sr == EventType::MemoryWatchpoint || !m_engine || !m_cursor )
            return;
        Position p = m_cursor->GetPosition();
        if ( forward && !(p < m_engine->GetLastPosition()) )
            m_pendingBoundary = BOUNDARY_END;
        else if ( !forward && !(m_engine->GetFirstPosition() < p) )
            m_pendingBoundary = BOUNDARY_START;
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
    // FNV-1a hash of up to 'n' bytes at 'ea' (read through the debugger memory,
    // i.e. the live bytes at the current position). Returns 0 on a short read so a
    // failed read never looks like a byte change.
    static uint64_t hash_mem(ea_t ea, size_t n)
    {
        uint8_t buf[64];
        if ( n > sizeof(buf) )
            n = sizeof(buf);
        if ( get_bytes(buf, (ssize_t)n, ea) != (ssize_t)n )
            return 0;
        uint64_t h = 1469598103934665603ULL;
        for ( size_t i = 0; i < n; i++ )
        {
            h ^= buf[i];
            h *= 1099511628211ULL;
        }
        return h;
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
        segment_info_t seg;
        if ( !get_segment_info(&seg, pc) )
            return;

        func_entry_info_t cur_fi;
        if ( get_func_entry_info(&cur_fi, pc) )
        {
            // Already defined. For functions WE built in dynamic memory, detect a
            // rewrite (self-modifying / reused region, or time-travel to a position
            // where the same address holds different code) by hashing the bytes and
            // comparing to definition time. If unchanged (or not ours), keep it.
            auto it = m_dynFuncBytes.find(cur_fi.start_ea);
            if ( it == m_dynFuncBytes.end() )
                return;
            uint64_t h = hash_mem(cur_fi.start_ea, 64);
            if ( h == 0 || h == it->second )
                return;
            ea_t fs = cur_fi.start_ea, fe = cur_fi.end_ea;
            del_func(fs);
            del_items(fs, DELIT_EXPAND, (asize_t)(fe - fs));
            m_dynFuncBytes.erase(it);
            // fall through to re-disassemble the new code
        }

        ea_t fstart, fend;
        if ( function_range_at(pc, fstart, fend) && fstart < fend && fend <= seg.end_ea )
        {
            // Module function with authoritative .pdata bounds: disassemble the
            // whole range. Embedded data (jump tables) can't decode — skip a byte.
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
            add_func(fstart, fend);
            // Library (non-target) module code: mark it FUNC_LIB so it renders as
            // <name>+offset and is de-emphasized. The analyzed binary (module 0) is
            // the user's own code, so leave its functions normal.
            bool main_mod = false;
            if ( m_engine && m_engine->GetModuleCount() > 0 )
            {
                const Module &m0 = m_engine->GetModuleList()[0];
                ea_t b = (ea_t)(uint64_t)m0.Address;
                main_mod = pc >= b && pc < b + (ea_t)m0.Size;
            }
            if ( !main_mod && get_func_start(fstart) == fstart
              && (get_func_flags(fstart) & FUNC_LIB) == 0 )
            {
                set_func_flag(fstart, FUNC_LIB, true);
            }
            return;
        }

        // ---- runtime-allocated code (no module / no .pdata): shellcode, unpacked
        // code, JIT. Mirror Binary Ninja's debugger: define a function and let
        // IDA's recursive descent disassemble the WHOLE thing (forward branches +
        // not-taken branches), seeded at the function head so the prologue and all
        // the body above PC are laid out too (so backward stepping reveals code
        // that's already there instead of one instruction at a time). ----
        //
        // Prefer the TRUE head recovered from the trace's call/return structure
        // (the call that entered this frame). Fall back to the executed-address
        // contiguity heuristic when no enclosing call was captured -- e.g. the
        // frame was entered by a jmp/thread-start rather than a call, or the
        // entering call predates the look-back window.
        ea_t start = find_dynamic_function_entry(pc);
        if ( start == BADADDR || start > pc || get_segment_ea(start) != seg.start_ea )
            start = find_dynamic_start(pc);

        // The position-based memory query returns zero-fill for this region's
        // never-executed bytes (it's unpacked/JIT code, not a module). Rebuild the
        // real bytes from the trace's recorded writes so the WHOLE function (not just
        // the executed path) disassembles -- this is what WinDbg shows. Bounded to a
        // window from the head; served thereafter by on_read_memory. Then invalidate
        // IDA's cache for the range so the upcoming create_insn reads the real bytes.
        ea_t rlo = start;
        ea_t rhi = (pc > start ? pc : start) + 0x2000;
        if ( get_segment_ea(rhi - 1) != seg.start_ea )
            rhi = seg.end_ea;
        if ( reconstruct_region(rlo, rhi) )
            invalidate_dbgmem_contents(rlo, rhi - rlo);

        force_insn(start);                  // exact-boundary seed
        add_func(start);                    // BADADDR end -> recursive descent
        ea_t aend = (pc > start ? pc : start) + 0x2000;
        plan_and_wait(start, aend);         // force the descent synchronously, bounded

        ea_t nfs = get_func_start(pc);
        if ( nfs != BADADDR )
        {
            m_dynFuncBytes[nfs] = hash_mem(nfs, 64);
            // Give dynamic (non-module) code its OWN debug name. Debugger views
            // resolve names via the global "nearest debug name <= address" rule, so
            // without an entry here a far-below module symbol (kernel32/ntdll/the exe)
            // bleeds onto shellcode/JIT as "<unrelated>+huge_offset". A local name
            // breaks that bleed for this function's range.
            qstring nm;
            if ( get_func_name(&nm, nfs) > 0 && !nm.empty() )
                set_debug_name(nfs, nm.c_str());
        }
        else
        {
            lay_out_window(pc);             // PC reachable only via an indirect edge
        }
    }

    //-----------------------------------------------------------------------
    void TraceManager::collect_window_pcs(ea_t pc, std::set<ea_t> &pcs)
    {
        pcs.clear();
        if ( !m_engine || !m_cursor )
            return;
        if ( !m_anaCursor )
            m_anaCursor = UniqueCursor{ m_engine->NewCursor() };
        if ( !m_anaCursor )
            return;

        const uint64_t BEFORE = 64;     // instructions of context before PC
        const uint64_t AFTER  = 192;    // instructions after PC
        const ea_t     W      = 0x2000; // only collect addresses within +/-W of PC

        Position cur = m_cursor->GetPosition();
        uint32_t tid = (uint32_t)m_cursor->GetThreadInfo().UniqueId;

        // Seek a little before the current position, then replay FORWARD (cheap —
        // no per-step keyframe re-seek like going backward).
        Position start = cur;
        start.Steps = (StepCount)((uint64_t)cur.Steps > BEFORE ? (uint64_t)cur.Steps - BEFORE : 0);
        m_anaCursor->SetPosition(start);

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
    }

    //-----------------------------------------------------------------------
    ea_t TraceManager::find_dynamic_start(ea_t pc)
    {
        std::set<ea_t> pcs;
        collect_window_pcs(pc, pcs);
        if ( pcs.empty() )
            return pc;                  // nothing collected -> start at PC (BN-style)

        auto it = pcs.upper_bound(pc);  // first executed address > pc
        if ( it == pcs.begin() )
            return pc;                  // none <= pc
        --it;                           // largest executed address <= pc

        // Walk down through executed addresses while they chain by instruction
        // (gap <= max x86 insn length). A larger gap means the lower address is a
        // different basic block reached by a jump, not the linear prologue.
        ea_t lo = *it;
        while ( it != pcs.begin() )
        {
            auto pv = std::prev(it);
            if ( lo - *pv > 15 )
                break;
            lo = *pv;
            --it;
        }
        return lo;
    }

    //-----------------------------------------------------------------------
    // Recover the head of the current frame's function from the trace itself.
    // We replay FORWARD from a position a little before the playhead up to the
    // playhead, watching the call/return structure via the engine's CallReturn
    // callback (the same primitive the tracer uses): a CALL pushes (callee,
    // return-addr) onto a per-thread frame stack, a RET pops it. When we reach
    // the current position the top of the current thread's stack is the call
    // that entered this frame, so its target is the function head -- this is the
    // "change in the callstack" boundary, the dynamic-code analogue of the
    // .pdata bounds used for module code.
    //
    // The look-back is widened until that entering CALL is captured. Each attempt
    // is ONE SetPosition + forward replay, which is cheap; we deliberately never
    // single-step backward (that re-seeks a keyframe per step and freezes the UI).
    ea_t TraceManager::find_dynamic_function_entry(ea_t pc)
    {
        qnotused(pc);
        if ( !m_engine || !m_cursor )
            return BADADDR;
        if ( !m_anaCursor )
            m_anaCursor = UniqueCursor{ m_engine->NewCursor() };
        if ( !m_anaCursor )
            return BADADDR;

        const Position cur = m_cursor->GetPosition();
        const uint32_t tid = (uint32_t)m_cursor->GetThreadInfo().UniqueId;

        struct Frame { ea_t entry; uint64_t ret; };
        std::map<uint32_t, std::vector<Frame>> stacks;

        // CALL: instr == callee (function head), fall_through == return address.
        // RET:  fall_through == 0; pop the innermost open frame on that thread.
        auto on_call_ret = [&](GuestAddress instr, GuestAddress fall_through,
                               IThreadView const *t) noexcept
        {
            uint32_t utid = (uint32_t)t->GetThreadInfo().UniqueId;
            if ( (uint64_t)fall_through != 0 )
            {
                stacks[utid].push_back(Frame{ (ea_t)(uint64_t)instr, (uint64_t)fall_through });
            }
            else
            {
                auto it = stacks.find(utid);
                if ( it != stacks.end() && !it->second.empty() )
                    it->second.pop_back();
            }
        };

        static const uint64_t kWindows[] = { 1024, 8192, 65536 };
        ea_t entry = BADADDR;
        for ( uint64_t back : kWindows )
        {
            stacks.clear();
            Position s = cur;
            s.Steps = (StepCount)((uint64_t)cur.Steps > back ? (uint64_t)cur.Steps - back : 0);
            m_anaCursor->SetPosition(s);
            m_anaCursor->SetCallReturnCallback(on_call_ret);
            m_anaCursor->ReplayForward(cur);                 // stop AT the playhead
            m_anaCursor->SetCallReturnCallback(nullptr, 0);  // detach the local lambda

            auto it = stacks.find(tid);
            if ( it != stacks.end() && !it->second.empty() )
            {
                entry = it->second.back().entry;
                break;
            }
            if ( (uint64_t)cur.Steps <= back )
                break;       // the window already reached the start of the sequence
        }
        return entry;
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

        std::set<ea_t> pcs;
        collect_window_pcs(pc, pcs);

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
        if ( get_segment_ea(pc) == BADADDR )
            return;
        if ( get_func_start(pc) != BADADDR )
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

        // Time travel breaks IDA's "process memory only changes going forward"
        // assumption: the SAME address can hold different bytes at different
        // positions (e.g. a buffer that's zero before it's unpacked). After a jump
        // IDA keeps the previous position's cached bytes for everything it doesn't
        // re-read.
        //
        // invalidate_dbg_state(DBGINV_MEMORY) only marks the cache dirty; it does
        // NOT force the listing to re-read, so IDA kept rendering the bytes it first
        // cached -- which, for code revealed before the index was usable, were the
        // thread-local-only bytes (executed instructions present, never-executed
        // code shown as 0). invalidate_dbgmem_contents() is the SDK-sanctioned
        // "process stopped, re-read memory" call: it flushes AND refreshes, so the
        // listing re-reads via on_read_memory (now GloballyAggressive + write
        // reconstruction) and the previously-zero bytes appear.
        //
        // NOTE: this refresh (like IDA's own post-stop handling) brings the
        // disassembly view to the front. Keeping the user in the decompiler is
        // handled separately by Plugin::keep_decompiler_focused() (a deferred
        // re-activation after the stop), not by weakening this memory refresh.
        invalidate_dbgmem_contents(BADADDR, 0);

        // Name exports of any module loaded at this position first, so a call to a
        // freshly-revealed export renders with its name rather than loc_/sub_.
        resolve_loaded_modules();
        analyze_current_function(program_counter());

        // If the last navigation came to rest on the very first/last position of
        // the trace, tell the user. Done here (after the stop is fully processed)
        // rather than inside on_resume, where a modal popup would be unsafe.
        if ( m_pendingBoundary == BOUNDARY_START )
            info("Reached the start of the trace.");
        else if ( m_pendingBoundary == BOUNDARY_END )
            info("Reached the end of the trace.");
        m_pendingBoundary = BOUNDARY_NONE;
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
        // Just queue the stop event here (during ev_resume). The memory-cache
        // invalidation and disassembly/symbol work happen in on_suspended(), once
        // the process is actually in the stopped state.
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
            EventType sr = navigate_steps(false, StepCount{ 1 });
            flag_boundary(sr, false);
            emit_stop(false);
            m_backwardSingleStep = false;
            m_resumeMode = RESMOD_NONE;
            return DRC_OK;
        }

        if ( m_forwardSingleStep )
        {
            EventType sr = navigate_steps(true, StepCount{ 1 });
            flag_boundary(sr, true);
            emit_stop(false);
            m_forwardSingleStep = false;
            m_resumeMode = RESMOD_NONE;
            return DRC_OK;
        }

        if ( m_runOnce )
        {
            EventType sr = navigate_steps(m_runForward, StepCount::Max);
            flag_boundary(sr, m_runForward);
            emit_stop(false);
            m_runOnce = false;
            m_resumeMode = RESMOD_NONE;
            return DRC_OK;
        }

        if ( m_stepOutBackward )
        {
            EventType sr = navigate_out_backward();
            flag_boundary(sr, false);
            emit_stop(false);
            m_stepOutBackward = false;
            m_resumeMode = RESMOD_NONE;
            return DRC_OK;
        }

        if ( m_runToCursorBackward )
        {
            EventType sr = navigate_backward_to(m_runToCursorAddr);
            flag_boundary(sr, false);
            emit_stop(false);
            m_runToCursorBackward = false;
            m_runToCursorAddr = BADADDR;
            m_resumeMode = RESMOD_NONE;
            return DRC_OK;
        }

        if ( m_runToCursorForward )
        {
            EventType sr = navigate_forward_to(m_runToCursorAddr);
            flag_boundary(sr, true);
            emit_stop(false);
            m_runToCursorForward = false;
            m_runToCursorAddr = BADADDR;
            m_resumeMode = RESMOD_NONE;
            return DRC_OK;
        }

        switch ( m_resumeMode )
        {
            case RESMOD_INTO:
            {
                EventType sr = navigate_steps(true, StepCount{ 1 });
                flag_boundary(sr, true);
                emit_stop(sr != EventType::MemoryWatchpoint);
                break;
            }
            case RESMOD_BACKINTO:
            {
                EventType sr = navigate_steps(false, StepCount{ 1 });
                flag_boundary(sr, false);
                emit_stop(sr != EventType::MemoryWatchpoint);
                break;
            }
            case RESMOD_OVER:
            {
                EventType sr = m_isForward ? navigate_over(false)
                                           : navigate_steps(false, StepCount{ 1 });
                flag_boundary(sr, m_isForward);
                emit_stop(sr != EventType::MemoryWatchpoint);
                break;
            }
            case RESMOD_OUT:
            {
                EventType sr = m_isForward ? navigate_over(true)
                                           : navigate_steps(false, StepCount{ 1 });
                flag_boundary(sr, m_isForward);
                emit_stop(sr != EventType::MemoryWatchpoint);
                break;
            }
            case RESMOD_NONE:
            default:
            {
                // Run/continue in the currently selected direction until a
                // watchpoint hits or the trace boundary is reached.
                EventType sr = navigate_steps(m_isForward, StepCount::Max);
                flag_boundary(sr, m_isForward);
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
    void TraceManager::request_run_to_cursor_backward(ea_t addr)
    {
        if ( !m_cursor )
        {
            warning("Time travel is only available while replaying a trace.");
            return;
        }
        if ( addr == BADADDR )
            return;
        m_runToCursorBackward = true;
        m_runToCursorAddr     = addr;
        request_continue_process();
        run_requests();
    }

    //-----------------------------------------------------------------------
    void TraceManager::request_run_to_cursor_forward(ea_t addr)
    {
        if ( !m_cursor )
        {
            warning("Time travel is only available while replaying a trace.");
            return;
        }
        if ( addr == BADADDR )
            return;
        m_runToCursorForward = true;
        m_runToCursorAddr    = addr;
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

            ea_t fstart = get_func_start(ea);
            ea_t key = fstart != BADADDR ? fstart : ea;
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

        // Never fetch a PDB for the analyzed binary itself (module 0). IDA already
        // owns that file's database (its own symbols/analysis); asking the pdb
        // plugin only triggers a redundant — and possibly slow/networked —
        // symbol-server lookup for the very file the user is analyzing. We match by
        // BASE (authoritative) so a name mismatch can't let it slip through.
        if ( m_engine->GetModuleCount() > 0
          && (ea_t)(uint64_t)m_engine->GetModuleList()[0].Address == base )
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

        // Never fetch a PDB for the input file itself: IDA already owns that
        // module's database (its own symbols/analysis), and asking the PDB plugin
        // for it only triggers a redundant symbol-server lookup for the binary the
        // user is analyzing.
        if ( _stricmp(base_name(path).c_str(), m_targetName.c_str()) == 0 )
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
    bool TraceManager::is_library_address(ea_t ea) const
    {
        if ( !m_engine )
            return false;
        size_t n = m_engine->GetModuleCount();
        const Module *list = m_engine->GetModuleList();
        ea_t mainBase = n > 0 ? (ea_t)(uint64_t)list[0].Address : BADADDR;
        for ( size_t i = 0; i < n; i++ )
        {
            ea_t b = (ea_t)(uint64_t)list[i].Address;
            ea_t e = b + (ea_t)list[i].Size;
            if ( ea >= b && ea < e )
                return b != mainBase;   // inside a module, and not the analyzed binary
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
