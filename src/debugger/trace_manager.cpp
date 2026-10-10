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
        m_anaCursor.reset();
        m_memCursor.reset();
        m_memPosValid = false;

        m_events.clear();
        m_activeBpts = 0;
        m_userWatchpoints.clear();

        m_modules.reset();
        m_reconRegions.clear();
        m_dynFuncBytes.clear();
        m_pdataExtended.clear();

        m_memmap.clear();
        m_lastLayout.qclear();
        m_haveLayout = false;
        m_foldLayout.qclear();
        m_foldValid  = false;

        m_winLo          = BADADDR;
        m_winHi          = 0;
        m_calleeScanFunc = BADADDR;

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

        if ( m_memmap.load(trace_fingerprint()) )
            msg("[ida-ttd] loaded a saved memory map: %d recorded change(s).\n",
                (int)m_memmap.size());

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

    bool TraceManager::reconstruct_region(ea_t lo, ea_t hi)
    {
        if ( !m_engine || !m_cursor || hi <= lo )
            return false;

        // hard CAP on the window. The callers derive 'hi' from segment bounds, and
        // our own memory map advertises one segment spanning the entire user address
        // space -- so a bad bound arrives here as a request to allocate terabytes,
        // which throws bad_alloc out of a plugin that does not catch it and takes
        // IDA down. A megabyte is far more than the code windows we actually ask for.
        static const uint64_t kMaxReconBytes = 1u << 20;
        if ( (uint64_t)(hi - lo) > kMaxReconBytes )
            hi = lo + (ea_t)kMaxReconBytes;

        // Already reconstructed something covering this range?
        for ( const ReconRegion &r : m_reconRegions )
            if ( r.lo <= lo && hi <= r.hi )
                return true;

        UniqueCursor cur{ m_engine->NewCursor() };
        if ( !cur )
            return false;

        const TtdPosition target = m_cursor->GetPosition();

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
        cur->SetPosition(TtdPosition::Min);

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

    // The engine's Module record for the module based at 'base'.
    ICursorView *TraceManager::ana_cursor()
    {
        if ( !m_engine )
            return nullptr;
        if ( !m_anaCursor )
        {
            m_anaCursor = UniqueCursor{ m_engine->NewCursor() };
            if ( m_anaCursor )
            {
                // must be sequential. The engine's default is to replay several
                // segments in parallel and dispatch callbacks from all of those
                // threads at once; find_dynamic_function_entry's call/return
                // callback mutates an unsynchronized std::map, so the default
                // would corrupt the heap. Sequential replay keeps the callback
                // single-threaded (and chronological, which that walk also needs).
                //
                // ReplayAllSegmentsWithoutFiltering matches the whole-trace sweep
                // in tracer.cpp. Every user of this cursor wants a call/return
                // callback, which is not a maskable event, so the segment filter
                // has nothing to work with and costs ~2% either way; setting it
                // removes any question of a bounded replay skipping ahead through
                // the index and dispatching no callbacks at all.
                m_anaCursor->SetReplayFlags(ReplayFlags::ReplayAllSegmentsWithoutFiltering
                                          | ReplayFlags::ReplaySegmentsSequentially);
            }
        }
        return m_anaCursor.get();
    }

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
            TtdPosition cur = m_cursor->GetPosition();
            if ( !m_memPosValid || cur.Sequence != m_memPos.Sequence || cur.Steps != m_memPos.Steps )
            {
                m_memCursor->SetPosition(cur);
                m_memPos      = cur;
                m_memPosValid = true;
            }
        }

        // QueryMemoryBuffer only ever returns the single contiguous run that begins
        // exactly at the queried address. If that address is a "hole" (a byte TTD
        // didn't record at this position) it returns Size==0 -- and a naive single
        // call then loses every known byte further into the buffer. So fill the whole
        // range in two passes:
        //
        //   Pass 1 (authoritative): walk the range querying TTD's recorded memory,
        //   skipping over holes, so every recorded byte is delivered. This reflects
        //   the true position-in-time state, including self-modified code.
        //
        //   Pass 2 (image fallback): for bytes TTD never recorded, copy from the
        //   module's on-disk image. TTD only records accessed memory; image-backed
        //   code that was never executed on this run (the other side of a branch, a
        //   cold epilogue, the terminating ret) is in the trace at no position, yet
        //   it is right there in the file -- this is exactly what WinDbg shows. Image
        //   bytes only fill gaps; recorded bytes always win.
        static const QueryMemoryPolicy kPolicies[] = {
            QueryMemoryPolicy::GloballyAggressive,   // the cursor default; cheap first
            QueryMemoryPolicy::InFragmentAggressive, // look across the whole fragment
        };

        // What we know about each byte of the answer. The distinction between the
        // last two is the whole point of this pass: an engine that says "this page
        // is mapped, here is zero" has not told us the value, and treating that as
        // data is what stopped the image fallback from ever correcting it.
        enum : uint8_t
        {
            FILL_NONE = 0,   // nothing to serve
            FILL_REAL = 1,   // recorded, reconstructed, or read from the image
            FILL_ZERO = 2,   // the engine's zero placeholder; better may exist
        };

        uint8_t *out = (uint8_t *)buffer;
        m_readFilled.assign(size, FILL_NONE);    // reuses capacity; no per-call allocation
        uint8_t *filled = m_readFilled.data();
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

                // A non-zero Size does not mean these bytes are real. For memory
                // the engine knows is mapped but has no value to attribute at the
                // current position -- a byte last written in an EARLIER fragment
                // is the common case -- the aggressive policies answer "here is
                // zero" rather than admitting they do not know. Accepting that as
                // an answer is what made the front of a string literal read back
                // as eight zero bytes, so IDA rendered "[+] Starting...\n" as
                // "ting...\n" and stopped following code at the first such run.
                //
                // ThreadLocal is the one policy that is honest about it, so an
                // all-zero run is only believed if ThreadLocal confirms it was
                // genuinely recorded. Unconfirmed zeros are kept as a PLACEHOLDER:
                // the image fallback below gets first refusal on them, and they
                // are only served if nothing better turns up. The probe is skipped
                // for any run with a non-zero byte in it -- zero-fill is all zeros
                // by definition -- which keeps the extra query off the hot path.
                uint8_t flag = FILL_REAL;
                bool all_zero = true;
                for ( size_t i = 0; i < run && all_zero; i++ )
                    all_zero = out[off + i] == 0;
                if ( all_zero )
                {
                    m_readProbe.assign(run, 0);
                    MemoryBuffer probe = mc->QueryMemoryBuffer(
                        GuestAddress{ (uint64_t)(ea + off) },
                        BufferView{ m_readProbe.data(), run },
                        QueryMemoryPolicy::ThreadLocal);
                    if ( probe.Memory.Size == 0 )
                        flag = FILL_ZERO;
                }

                for ( size_t i = 0; i < run; i++ )
                    filled[off + i] = flag;
                off += run;
                if ( flag == FILL_REAL )
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
                filled[oi] = FILL_REAL;
                if ( oi + 1 > resolved_end )
                    resolved_end = oi + 1;
            }
        }

        // ---- Pass 2: on-disk image fills the gaps ----
        size_t o = 0;
        while ( o < size )
        {
            // Placeholder zeros are not a filled byte here: the whole point is to
            // give the image a chance to supply what the engine could not.
            if ( filled[o] == FILL_REAL )
            {
                o++;
                continue;
            }
            // Measure the contiguous gap so an image run can't clobber recorded bytes.
            size_t gap = 0;
            while ( o + gap < size && filled[o + gap] != FILL_REAL )
                gap++;

            ea_t              base = BADADDR;
            const ModuleImage *img = m_modules.image_for(ea + o, base);
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
                    filled[o + g + i] = FILL_REAL;
                if ( o + g + run > resolved_end )
                    resolved_end = o + g + run;
                g += run;
            }
            o += gap;
        }

        // ---- Pass Z: fall back on the engine's zero-fill placeholders ----
        // Nothing better turned up for these bytes, so serve the zeros after all.
        // This is what the engine says about memory it knows is mapped, and it is
        // what this function returned for them before placeholders were told apart
        // from recorded data -- heap and stack pages with no value at this position
        // must still read as zeros rather than as a failed read.
        for ( size_t i = 0; i < size; i++ )
        {
            if ( filled[i] != FILL_ZERO )
                continue;
            out[i] = 0;
            if ( i + 1 > resolved_end )
                resolved_end = i + 1;
        }

        *nbytes = resolved_end;
        // Nothing at this address is recorded, reconstructed, or image-backed: it
        // is unmapped/unknown memory. Report a read FAILURE rather than a silent
        // zero-fill -- otherwise IDA treats the whole address space (advertised as
        // one big segment) as readable and the register/stack views dereference a
        // garbage pointer into 0, then dereference that 0, ad infinitum.
        return resolved_end == 0 ? DRC_FAILED : DRC_OK;
    }

    // Build the memory layout IDA should see at the cursor's current position.
    //
    // With no reconstructed map this is what it has always been: one flat
    // read/write/execute range over user space. With a map, the regions the
    // recording actually created are reported individually, named and carrying
    // their real protection, and everything between them keeps the flat range.
    //
    // The filler is not optional. Stacks, heaps, the PEB and the TEB are never
    // created by a call we watch, so reporting only the discovered regions would
    // make IDA stop reading them and break the stack and register views. What the
    // map adds is names and honest permissions where we know them, never less
    // reachability than before.
    void TraceManager::build_memory_layout(meminfo_vec_t *out) const
    {
        // Start above the Windows null page (the low 64 KiB is always reserved /
        // unmapped). Excluding it stops IDA from treating small integers (0, 1, ...)
        // as valid TTD pointers and recursively dereferencing them in the
        // register/stack views.
        const ea_t  LO   = 0x10000;
        const ea_t  HI   = m_is64 ? (ea_t)0x7FFFFFFFFFFFull : (ea_t)0xFFFFFFFFull;
        const uchar BITS = m_is64 ? 2 : 1;

        TtdPosition now = m_cursor ? m_cursor->GetPosition()
                                             : TtdPosition::Invalid;
        if ( m_foldValid && now == m_foldPos )
        {
            *out = m_foldLayout;
            return;
        }

        out->qclear();

        // Named pieces of the address space, gathered before anything is
        // emitted so they can be sorted and the gaps filled in one pass.
        struct Named
        {
            ea_t    lo = 0, hi = 0;
            qstring name;
            qstring sclass;
            uchar   perm = 0;
            bool operator<(const Named &o) const { return lo < o.lo; }
        };
        std::vector<Named> named;

        // ---- the regions the recording built ------------------------------
        std::vector<Region> regs;
        if ( !m_memmap.empty() && m_cursor )
            m_memmap.state_at(to_core(now), regs);

        for ( const Region &r : regs )
        {
            ea_t lo = r.base < LO ? LO : r.base;
            ea_t hi = r.end() > HI ? HI : (ea_t)r.end();
            if ( hi <= lo )
                continue;
            uchar perm = protection_perm(r.protect);
            Named nm;
            nm.lo   = lo;
            nm.hi   = hi;
            nm.perm = perm;
            // Name it after the module it belongs to when it belongs to one --
            // a mapped view of kernel32 reads far better as "kernel32_dll" than
            // as "view_7FFA...". The address is kept as a suffix because one
            // module can hold several regions with different protections once a
            // VirtualProtect has split it.
            qstring mod = m_modules.ident_at(lo);
            if ( !mod.empty() )
                nm.name.sprnt("%s_%a", mod.c_str(), lo);
            else
                nm.name.sprnt("%s_%a",
                              r.origin == RC_MAPVIEW ? "view"
                            : r.origin == RC_PROTECT ? "prot" : "alloc", lo);
            nm.sclass = (perm & SEGPERM_EXEC) != 0 ? "CODE" : "DATA";
            named.push_back(nm);
        }
        std::sort(named.begin(), named.end());
        size_t nregions = named.size();

        // ---- the modules mapped at this position --------------------------
        //
        // Without these every module falls into the generic filler below, so a
        // function in kernelbase reads as being in a segment called "TTD". The
        // recording knows exactly where each module is; there is no reason to
        // make the user guess.
        //
        // Read and execute, not read/write/execute: we do not track a module's
        // per-section protections, and marking every module writable would bury
        // the RWX allocations this whole feature exists to make visible.
        if ( m_cursor )
        {
            size_t n = m_cursor->GetModuleCount();
            const ModuleInstance *list = m_cursor->GetModuleList();
            for ( size_t i = 0; i < n; i++ )
            {
                const Module *m = list[i].pModule;
                if ( m == nullptr )
                    continue;
                ea_t mlo = (ea_t)(uint64_t)m->Address;
                ea_t mhi = mlo + (ea_t)m->Size;
                if ( mlo < LO ) mlo = LO;
                if ( mhi > HI ) mhi = HI;
                if ( mhi <= mlo )
                    continue;

                qstring ident = m_modules.ident_at(mlo);
                if ( ident.empty() )
                    ident.sprnt("mod_%a", mlo);

                // A discovered region is more specific than the module it sits
                // in, so the module only claims what the regions leave.
                ea_t cur = mlo;
                for ( size_t k = 0; k < nregions && cur < mhi; k++ )
                {
                    const Named &r = named[k];
                    if ( r.hi <= cur )
                        continue;
                    if ( r.lo >= mhi )
                        break;
                    if ( r.lo > cur )
                    {
                        Named nm;
                        nm.lo     = cur;
                        nm.hi     = r.lo;
                        nm.name   = ident;
                        nm.sclass = "CODE";
                        nm.perm   = SEGPERM_READ | SEGPERM_EXEC;
                        named.push_back(nm);
                    }
                    cur = r.hi > cur ? r.hi : cur;
                }
                if ( cur < mhi )
                {
                    Named nm;
                    nm.lo     = cur;
                    nm.hi     = mhi;
                    nm.name   = ident;
                    nm.sclass = "CODE";
                    nm.perm   = SEGPERM_READ | SEGPERM_EXEC;
                    named.push_back(nm);
                }
            }
        }

        std::sort(named.begin(), named.end());

        // ---- emit, filling every gap --------------------------------------
        //
        // The filler is not optional. Stacks, heaps, the PEB and the TEB are
        // never created by a call we watch and belong to no module, so reporting
        // only what we can name would make IDA stop reading them and break the
        // stack and register views. What the names add is description, never
        // less reachability than before.
        auto filler = [&](ea_t lo, ea_t hi)
        {
            if ( hi <= lo )
                return;
            memory_info_t mi;
            mi.start_ea = lo;
            mi.end_ea   = hi;
            mi.name     = "TTD";
            mi.bitness  = BITS;
            mi.perm     = SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC;
            out->push_back(mi);
        };

        ea_t cur = LO;
        for ( const Named &nm : named )
        {
            // Two modules can overlap in a recording that reused an address;
            // whatever was emitted first keeps the space.
            if ( nm.hi <= cur )
                continue;
            ea_t lo = nm.lo < cur ? cur : nm.lo;
            if ( lo >= nm.hi )
                continue;
            filler(cur, lo);

            memory_info_t mi;
            mi.start_ea = lo;
            mi.end_ea   = nm.hi;
            mi.name     = nm.name;
            mi.sclass   = nm.sclass;
            mi.bitness  = BITS;
            mi.perm     = nm.perm;
            out->push_back(mi);
            cur = nm.hi;
        }
        filler(cur, HI);

        m_foldLayout = *out;
        m_foldPos    = now;
        m_foldValid  = true;
    }

    ssize_t TraceManager::on_get_memory_info(meminfo_vec_t *ranges)
    {
        meminfo_vec_t layout;
        build_memory_layout(&layout);

        // Rebuilding IDA's debugger segments is not cheap, and stepping inside
        // one region changes nothing about the layout. Say so.
        if ( m_haveLayout && layout == m_lastLayout )
            return DRC_NOCHG;

        m_lastLayout = layout;
        m_haveLayout = true;
        *ranges = layout;
        return DRC_OK;
    }

    void TraceManager::refresh_memory_layout()
    {
        // The layout is no longer a constant even without a memory map: it
        // names the modules mapped at the current position, and time travel can
        // cross a module load or unload.
        if ( !m_haveLayout )
            return;
        meminfo_vec_t now;
        build_memory_layout(&now);
        if ( now == m_lastLayout )
            return;
        // Documented as slow, which is exactly why it is behind the comparison
        // rather than called on every stop.
        invalidate_dbgmem_config();
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

        uint64_t start_sp = (uint64_t)m_cursor->GetStackPointer();
        uint32_t utid     = (uint32_t)m_cursor->GetThreadInfo().UniqueId;
        bool hit_bpt = false;

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
                RunStop oc = run_to_addr_guarded((ea_t)((uint64_t)pc + len), start_sp, utid);
                if ( oc == RunStop::Breakpoint ) { hit_bpt = true; break; }
                if ( oc == RunStop::TraceBoundary ) break;
            }
            else
            {
                ICursorView::ReplayResult r = m_cursor->ReplayForward(TtdPosition::Max, StepCount{ 1 });
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
        hide_wait_box();

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
    bool TraceManager::find_frame_entry_position(TtdPosition &out, bool &cancelled)
    {
        cancelled = false;
        out       = TtdPosition::Invalid;
        if ( ana_cursor() == nullptr )
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
            m_anaCursor->SetPosition(s);
            m_anaCursor->SetCallReturnCallback(on_call_ret);
            ICursorView::ReplayResult rr = m_anaCursor->ReplayForward(cur);
            m_anaCursor->SetCallReturnCallback(nullptr, 0);
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

    ea_t TraceManager::call_target_of(const insn_t &insn, ea_t &slot_out)
    {
        slot_out = BADADDR;
        const op_t &op = insn.ops[0];

        // Direct: call rel32 / call far ptr. The operand carries the target.
        if ( op.type == o_near || op.type == o_far )
            return op.addr;

        // Indirect through a memory slot: "call [rip+disp]" (x64, where IDA
        // resolves the rip-relative operand into an absolute o_mem address) or
        // "call ds:xxx" (x86). That slot is an import table entry, and because we
        // are replaying a recording rather than reading a file, it already holds
        // the address the loader wrote there. Follow it.
        if ( op.type == o_mem && op.addr != BADADDR && is_loaded(op.addr) )
        {
            slot_out = op.addr;
            ea_t tgt = m_is64 ? (ea_t)get_qword(op.addr) : (ea_t)get_dword(op.addr);
            // Only trust the value if it lands inside a module the trace has
            // loaded. The slot may hold something else entirely -- it is read at
            // the CURRENT position, which can be before the loader filled the
            // import table in, and a stale or unreadable slot would otherwise send
            // add_func() off to carve a function out of garbage.
            if ( tgt != 0 && tgt != BADADDR && m_modules.index_at(tgt) != (size_t)-1 )
                return tgt;
        }

        // call rax / call [rax+8]: only the trace knows where this went, and the
        // per-stop path must not replay. Left for when execution reaches it.
        return BADADDR;
    }

    void TraceManager::define_function_at(ea_t ea)
    {
        if ( ea == BADADDR || ea == 0 )
            return;
        if ( get_segment_ea(ea) == BADADDR )
            return;                         // not mapped at this position
        if ( get_func_start(ea) == ea )
            return;                         // already a function here

        ea_t fstart, fend;
        if ( m_modules.function_range_at(ea, fstart, fend) && fstart == ea && fstart < fend )
        {
            // The module's .pdata gives exact bounds: lay the whole body out in one
            // linear pass, the same way analyze_current_function does for PC.
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
        }
        else
        {
            // No .pdata (x86, dynamic code, or an address that is not a recorded
            // function head). Seed one instruction and let IDA's recursive descent
            // find the extent. AF_PROC is off, so this does not cascade into the
            // callee's own callees -- which is the whole point of doing it here.
            force_insn(ea);
            add_func(ea);
        }

        ea_t defined = get_func_start(ea);
        if ( defined == ea && m_modules.is_library_address(ea)
          && (get_func_flags(ea) & FUNC_LIB) == 0 )
        {
            set_func_flag(ea, FUNC_LIB, true);
        }
    }

    void TraceManager::define_callees(ea_t lo, ea_t hi)
    {
        if ( lo == BADADDR || hi <= lo )
            return;
        // Stepping inside one function re-enters this on every single stop and
        // there is nothing new to find until the function changes, so remember the
        // last one scanned. (Reset explicitly wherever a function is torn down and
        // rebuilt, so self-modifying code is rescanned.)
        if ( lo == m_calleeScanFunc )
            return;
        m_calleeScanFunc = lo;

        // Bounded on both axes so this stays a per-stop-safe cost: a cap on how
        // far we walk, and a cap on how many targets we define.
        const int MAX_ITEMS   = 0x4000;
        const int MAX_TARGETS = 64;   // more direct calls than any real function has

        std::set<ea_t> seen;
        int defined = 0;
        ea_t ip = lo;
        for ( int guard = 0; ip < hi && guard < MAX_ITEMS && defined < MAX_TARGETS; guard++ )
        {
            if ( !is_code(get_flags(ip)) )
            {
                ip++;                       // embedded data (jump table, padding)
                continue;
            }
            ea_t   nxt = get_item_end(ip);
            insn_t insn;
            if ( decode_insn(&insn, ip) > 0 && is_call_insn(insn) )
            {
                ea_t slot = BADADDR;
                ea_t tgt  = call_target_of(insn, slot);

                if ( tgt != BADADDR && seen.insert(tgt).second )
                {
                    define_function_at(tgt);
                    defined++;
                }

                // Now the slot the call reads through. Turning it into a
                // pointer-sized offset stops it rendering as "call cs:unk_X", and
                // naming it after its target turns it into the import name the
                // reader actually wants: "call cs:__imp_CreateFileW". Only touch a
                // slot that has no name and no type of its own yet.
                if ( slot != BADADDR
                  && !has_any_name(get_flags(slot)) && !is_data(get_flags(slot)) )
                {
                    if ( m_is64 ? create_qword(slot, 8) : create_dword(slot, 4) )
                        op_plain_offset(slot, 0, 0);
                    qstring tn;
                    if ( tgt != BADADDR && get_name(&tn, tgt) > 0 && !tn.empty() )
                    {
                        qstring sn;
                        sn.sprnt("__imp_%s", tn.c_str());
                        set_name(slot, sn.c_str(), SN_NOWARN | SN_FORCE | SN_NOCHECK);
                    }
                }
            }
            ip = nxt > ip ? nxt : ip + 1;
        }
    }

    // Grow an already-defined function to the end its module's exception table
    // gives it. Only ever GROWS, and only into address space nothing else claims:
    // a shorter definition is IDA having lost the flow, but a longer one may be
    // deliberate (the user joined chunks by hand), and a range another function
    // already owns is not ours to take.
    void TraceManager::extend_to_pdata_bounds(ea_t pc, const func_entry_info_t &fi)
    {
        if ( m_pdataExtended.find(fi.start_ea) != m_pdataExtended.end() )
            return;                          // considered once per function

        ea_t ps = BADADDR, pe = BADADDR;
        if ( !m_modules.function_range_at(pc, ps, pe) )
            return;                          // x86, or no .pdata for this module
        m_pdataExtended.insert(fi.start_ea);

        // The .pdata entry must describe this function's own chunk. When it starts
        // elsewhere we are inside a tail chunk, and joining chunks is a different
        // decision than extending one.
        if ( ps != fi.start_ea || pe <= fi.end_ea )
            return;

        segment_info_t seg;
        if ( !get_segment_info(&seg, pc) || pe > seg.end_ea )
            return;

        // Refuse if anything else already lives in the space we would absorb.
        for ( ea_t a = fi.end_ea; a < pe; a++ )
        {
            if ( get_func_start(a) != BADADDR )
                return;
        }

        // Lay the tail out before moving the end: set_func_end over undefined
        // bytes leaves the function containing raw data.
        for ( ea_t ip = fi.end_ea; ip < pe; )
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
        if ( set_func_end(fi.start_ea, pe) )
        {
            msg("[ida-ttd] extended %a..%a to %a from the module's exception "
                "table.\n", fi.start_ea, fi.end_ea, pe);
            m_calleeScanFunc = BADADDR;      // the new tail may call things
        }
    }

    void TraceManager::analyze_current_function(ea_t pc)
    {
        segment_info_t seg;
        if ( !get_segment_info(&seg, pc) )
            return;

        func_entry_info_t cur_fi;
        if ( get_func_entry_info(&cur_fi, pc) )
        {
            // A function IDA already defined can still be defined SHORT. Its
            // static analysis stops where it loses the flow -- at a noreturn call,
            // an opaque tail jump, embedded data -- and the tail then renders as
            // a JUMPOUT to an address outside the function. The module's exception
            // table says exactly where the function ends, and nothing was using it
            // for anything but the not-yet-defined case, so reconcile here.
            extend_to_pdata_bounds(pc, cur_fi);

            // For functions we built in dynamic memory, detect a
            // rewrite (self-modifying / reused region, or time-travel to a position
            // where the same address holds different code) by hashing the bytes and
            // comparing to definition time. If unchanged (or not ours), keep it.
            auto it = m_dynFuncBytes.find(cur_fi.start_ea);
            if ( it == m_dynFuncBytes.end() )
            {
                // Not ours / unchanged: nothing to re-disassemble, but its call
                // targets may still be undefined -- the function could have been
                // defined by the PDB plugin, or on a previous visit before a
                // callee's module was mapped. Cheap thanks to the memo below.
                define_callees(cur_fi.start_ea, cur_fi.end_ea);
                return;
            }
            uint64_t h = hash_mem(cur_fi.start_ea, 64);
            if ( h == 0 || h == it->second )
            {
                define_callees(cur_fi.start_ea, cur_fi.end_ea);
                return;
            }
            ea_t fs = cur_fi.start_ea, fe = cur_fi.end_ea;
            del_func(fs);
            del_items(fs, DELIT_EXPAND, (asize_t)(fe - fs));
            m_dynFuncBytes.erase(it);
            m_calleeScanFunc = BADADDR;     // the code changed: rescan its callees
            // fall through to re-disassemble the new code
        }

        ea_t fstart, fend;
        if ( m_modules.function_range_at(pc, fstart, fend) && fstart < fend && fend <= seg.end_ea )
        {
            // Module function with authoritative .pdata bounds: disassemble the
            // whole range. Embedded data (jump tables) can't decode -- skip a byte.
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
            define_callees(fstart, fend);
            return;
        }

        // ---- runtime-allocated code (no module / no .pdata): shellcode, unpacked
        // code, JIT. Mirror Binary Ninja's debugger: define a function and let
        // IDA's recursive descent disassemble the whole thing (forward branches +
        // not-taken branches), seeded at the function head so the prologue and all
        // the body above PC are laid out too (so backward stepping reveals code
        // that's already there instead of one instruction at a time). ----
        //
        // Prefer the true head recovered from the trace's call/return structure
        // (the call that entered this frame). Fall back to the executed-address
        // contiguity heuristic when no enclosing call was captured -- e.g. the
        // frame was entered by a jmp/thread-start rather than a call, or the
        // entering call predates the look-back window.
        ea_t start = find_dynamic_function_entry(pc);
        if ( start == BADADDR || start > pc || get_segment_ea(start) != seg.start_ea )
            start = find_dynamic_start(pc);

        // The position-based memory query returns zero-fill for this region's
        // never-executed bytes (it's unpacked/JIT code, not a module). Rebuild the
        // real bytes from the trace's recorded writes so the whole function (not just
        // the executed path) disassembles -- this is what WinDbg shows. Bounded to a
        // window from the head; served thereafter by on_read_memory. Then invalidate
        // IDA's cache for the range so the upcoming create_insn reads the real bytes.
        ea_t rlo = start;
        ea_t rhi = (pc > start ? pc : start) + 0x2000;
        // Clamp to the enclosing segment, never widen to it: for dynamic code that
        // segment is the synthetic range covering all of user space.
        if ( rhi > seg.end_ea )
            rhi = seg.end_ea;
        if ( rhi > rlo && reconstruct_region(rlo, rhi) )
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

            // Shellcode and unpacked code call into the real modules constantly
            // (LoadLibrary, VirtualProtect, ...). Defining those targets is what
            // turns "call unk_7FF8xxxx" into a named import.
            func_entry_info_t nfi;
            ea_t nfe = get_func_entry_info(&nfi, nfs) && nfi.end_ea > nfs
                     ? nfi.end_ea : aend;
            define_callees(nfs, nfe);
        }
        else
        {
            lay_out_window(pc);             // PC reachable only via an indirect edge
            define_callees(m_winLo, m_winHi);
        }
    }

    void TraceManager::collect_window_pcs(ea_t pc, std::set<ea_t> &pcs)
    {
        pcs.clear();
        if ( !m_engine || !m_cursor )
            return;
        if ( ana_cursor() == nullptr )
            return;

        const uint64_t BEFORE = 64;     // instructions of context before PC
        const uint64_t AFTER  = 192;    // instructions after PC
        const ea_t     W      = 0x2000; // only collect addresses within +/-W of PC

        TtdPosition cur = m_cursor->GetPosition();
        uint32_t tid = (uint32_t)m_cursor->GetThreadInfo().UniqueId;

        // Seek a little before the current position, then replay forward (cheap --
        // no per-step keyframe re-seek like going backward).
        TtdPosition start = cur;
        start.Steps = (StepCount)((uint64_t)cur.Steps > BEFORE ? (uint64_t)cur.Steps - BEFORE : 0);
        m_anaCursor->SetPosition(start);

        int budget = (int)((BEFORE + AFTER) * 3) + 256;  // extra for thread interleaving
        TtdPosition prev = m_anaCursor->GetPosition();
        for ( int i = 0; i < budget; i++ )
        {
            if ( (uint32_t)m_anaCursor->GetThreadInfo().UniqueId == tid )
            {
                ea_t a = (ea_t)(uint64_t)m_anaCursor->GetProgramCounter();
                ea_t d = a > pc ? a - pc : pc - a;
                if ( d <= W )
                    pcs.insert(a);
            }
            m_anaCursor->ReplayForward(TtdPosition::Max, StepCount{ 1 });
            TtdPosition now = m_anaCursor->GetPosition();
            if ( now.Sequence == prev.Sequence && now.Steps == prev.Steps )
                break;                  // reached the end of the trace
            prev = now;
        }
    }

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

    // Recover the head of the current frame's function from the trace itself.
    // We replay forward from a position a little before the playhead up to the
    // playhead, watching the call/return structure via the engine's CallReturn
    // callback (the same primitive the tracer uses): a CALL pushes (callee,
    // return-addr) onto a per-thread frame stack, a RET pops it. When we reach
    // the current position the top of the current thread's stack is the call
    // that entered this frame, so its target is the function head -- this is the
    // "change in the callstack" boundary, the dynamic-code analogue of the
    // .pdata bounds used for module code.
    //
    // The look-back is widened until that entering CALL is captured. Each attempt
    // is one SetPosition + forward replay, which is cheap; we deliberately never
    // single-step backward (that re-seeks a keyframe per step and freezes the UI).
    ea_t TraceManager::find_dynamic_function_entry(ea_t pc)
    {
        // The head comes from the cursor's own position, not from 'pc'.
        qnotused(pc);
        if ( !m_engine || !m_cursor )
            return BADADDR;
        // ana_cursor() replays segments SEQUENTIALLY. That is load-bearing here:
        // with the engine's default parallel replay the callback below fires from
        // several threads at once and 'stacks' is not synchronized.
        if ( ana_cursor() == nullptr )
            return BADADDR;

        const TtdPosition cur = m_cursor->GetPosition();
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
            TtdPosition s = cur;
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

    void TraceManager::lay_out_window(ea_t pc)
    {
        if ( !m_engine || !m_cursor )
            return;

        // Already have a laid-out window comfortably surrounding PC? Skip the
        // replay (cheap path while stepping inside the same region). The explicit
        // validity test matters: m_winLo == BADADDR means "no window", and without
        // it the +0x40 wraps to 0x3F and this test passes for every code address,
        // permanently disabling the layout pass.
        if ( m_winLo != BADADDR && m_winLo < m_winHi
          && pc >= m_winLo + 0x40 && pc + 0x40 <= m_winHi
          && is_code(get_flags(pc)) )
            return;

        std::set<ea_t> pcs;
        collect_window_pcs(pc, pcs);

        // Realize the exact executed instructions (these are real boundaries).
        for ( ea_t a : pcs )
            force_insn(a);

        if ( pcs.empty() )
        {
            force_insn(pc);             // at least the current instruction
            m_winLo = BADADDR;          // "no window" -- matches the initial state
            m_winHi = 0;
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
        TtdPosition prev = cur->GetPosition();

        show_wait_box("Analyzing function from the trace (Cancel to stop)...");
        while ( examined < MAX_INSN && steps < MAX_STEP )
        {
            if ( (steps & 0x3FF) == 0 )
            {
                replace_wait_box("Analyzing function: %d instructions examined...", examined);
                if ( user_cancelled() ) { cancelled = true; break; }
            }

            cur->ReplayBackward(TtdPosition::Min, StepCount{ 1 });
            steps++;
            TtdPosition now = cur->GetPosition();
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
        refresh_memory_layout();

        // Name exports of any module loaded at this position first, so a call to a
        // freshly-revealed export renders with its name rather than loc_/sub_.
        m_modules.resolve_loaded(m_cursor.get());
        analyze_current_function(program_counter());

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
