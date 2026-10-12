#include "backend-msttd/msttd_backend.h"
#include "backend-msttd/msttd_navigator.h"
#include "core/backend_registry.h"
#include "debugger/msttd_guest.h"
#include "common/symbols.h"

using namespace TTD;
using namespace TTD::Replay;

namespace idattd
{
    //=======================================================================
    // The backend
    //=======================================================================
    MsTtdBackend::MsTtdBackend() = default;

    MsTtdBackend::~MsTtdBackend()
    {
        close();
    }

    bool MsTtdBackend::can_open(const char *path) const
    {
        // The TTD magic, "TTDLog": a signature read and nothing more.
        if ( path == nullptr )
            return false;
        std::ifstream f(std::filesystem::u8path(path), std::ios::binary);
        char magic[6] = { 0 };
        return f.is_open() && f.read(magic, sizeof(magic))
            && memcmp(magic, "TTDLog", sizeof(magic)) == 0;
    }

    bool MsTtdBackend::open(const char *path, qstring *errbuf)
    {
        close();
        auto fail = [errbuf](const char *fmt, auto... args)
        {
            if ( errbuf != nullptr )
                errbuf->sprnt(fmt, args...);
            return false;
        };

        if ( !can_open(path) )
            return fail("Not a valid TTD trace (bad magic): %s", path != nullptr ? path : "(null)");

        auto made = MakeReplayEngine();
        m_engine = std::move(made.first);
        if ( made.second != 0 || !m_engine )
        {
            m_engine.reset();
            return fail("Failed to create the TTD replay engine (0x%08X).\n\n"
                        "Are TTDReplay.dll / TTDReplayCPU.dll next to ida.exe?", made.second);
        }
        m_engine->RegisterDebugModeAndLogging(DebugModeType::None, &m_err);

        std::wstring wpath = to_wstring(path);
        if ( !m_engine->Initialize(wpath.c_str()) )
        {
            m_engine.reset();
            return fail("Failed to load the trace: %s", path);
        }

        // Without the memory index, memory reads are severely limited. The
        // .run loader may already have built it, in which case this returns
        // at once.
        build_trace_index(m_engine.get());

        m_info = TraceInfo{};
        m_info.first        = to_core(m_engine->GetFirstPosition());
        m_info.last         = to_core(m_engine->GetLastPosition());
        m_info.backend_name = display_name();

        // Process id, the extent of the recording and how many modules it saw.
        // Not a hash of the file -- that would mean reading gigabytes -- but
        // enough that two different recordings do not collide in practice. The
        // formula is the one databases were stamped with before backends
        // existed; changing it would orphan every saved result.
        const SystemInfo &si = m_engine->GetSystemInfo();
        uint64_t v = (uint64_t)si.ProcessId;
        v = v * 1099511628211ull ^ (uint64_t)m_engine->GetFirstPosition().Sequence;
        v = v * 1099511628211ull ^ (uint64_t)m_engine->GetLastPosition().Sequence;
        v = v * 1099511628211ull ^ (uint64_t)m_engine->GetLastPosition().Steps;
        v = v * 1099511628211ull ^ (uint64_t)m_engine->GetModuleCount();
        m_info.fingerprint = v;

        // The program is the engine's first module; its bitness is the one the
        // PE header states, read where the module is known to be mapped.
        m_info.is64 = true;
        if ( m_engine->GetModuleCount() > 0 )
        {
            const Module &m0 = m_engine->GetModuleList()[0];
            m_info.main_module = base_name(to_utf8(m0.pName, m0.NameLength)).c_str();
            std::vector<ModuleInfo> mods = modules();
            UniqueCursor c = new_engine_cursor();
            if ( c && !mods.empty() )
            {
                c->SetPosition(from_core(mods[0].loaded));
                GuestPeInfo pe;
                if ( read_guest_pe_info(msttd_read_plain(c.get()), (ea_t)(uint64_t)m0.Address, &pe) )
                    m_info.is64 = pe.is64;
            }
        }

        m_caps = Capabilities{};
        m_caps.access_queries = true;      // by replay with watchpoints armed
        m_caps.call_queries   = true;      // by replay with the call/return callback
        m_caps.cheap_seek     = true;
        m_caps.reverse_step   = true;
        m_caps.exceptions     = true;
        return true;
    }

    void MsTtdBackend::close()
    {
        // Cursors before the engine they belong to.
        m_frameScratch.reset();
        m_insnScratch.reset();
        m_engine.reset();
        m_info = TraceInfo{};
        m_caps = Capabilities{};
    }

    // Microsoft's own notation, Sequence:Steps in hex, which core/position.h
    // has always used and the database's stored positions are written in.
    qstring MsTtdBackend::format_position(Position p) const { return format_hex_position(p); }
    bool MsTtdBackend::parse_position(const char *text, Position *out) const
    { return parse_hex_position(text, out); }
    const char *MsTtdBackend::position_syntax() const { return hex_position_syntax(); }

    UniqueCursor MsTtdBackend::new_engine_cursor() const
    {
        return m_engine ? UniqueCursor{ m_engine->NewCursor() } : UniqueCursor{};
    }

    CursorPtr MsTtdBackend::make_cursor()
    {
        UniqueCursor exec = new_engine_cursor();
        UniqueCursor read = new_engine_cursor();
        if ( !exec )
            return nullptr;
        // Serve memory like WinDbg: the default policy only returns memory
        // the current thread touched around the current position, so bytes
        // written earlier read back as zeros. GloballyAggressive looks across
        // the whole trace for the value.
        exec->SetDefaultMemoryPolicy(QueryMemoryPolicy::GloballyAggressive);
        if ( read )
            read->SetDefaultMemoryPolicy(QueryMemoryPolicy::GloballyAggressive);
        auto c = std::make_unique<MsTtdCursor>(this, std::move(exec), std::move(read));
        c->seek(m_info.first);
        return c;
    }

    std::unique_ptr<INavigator> MsTtdBackend::make_navigator(ITraceCursor *cursor)
    {
        MsTtdCursor *mc = dynamic_cast<MsTtdCursor *>(cursor);
        if ( mc == nullptr )
            return nullptr;
        return std::make_unique<MsTtdNavigator>(this, mc);
    }

    std::vector<ModuleInfo> MsTtdBackend::modules() const
    {
        // One entry per load, so a module loaded twice is listed twice with
        // its own positions -- reading its headers needs a position where that
        // load is mapped.
        std::vector<ModuleInfo> out;
        if ( !m_engine )
            return out;
        size_t nu = m_engine->GetModuleUnloadedEventCount();
        const ModuleUnloadedEvent *un = m_engine->GetModuleUnloadedEventList();
        size_t nl = m_engine->GetModuleLoadedEventCount();
        const ModuleLoadedEvent *ld = m_engine->GetModuleLoadedEventList();
        std::set<const Module *> seen;
        for ( size_t i = 0; i < nl; i++ )
        {
            const Module *m = ld[i].pModule;
            if ( m == nullptr )
                continue;
            seen.insert(m);
            ModuleInfo mi;
            mi.base     = (ea_t)(uint64_t)m->Address;
            mi.size     = m->Size;
            mi.path     = to_utf8(m->pName, m->NameLength).c_str();
            mi.name     = base_name(mi.path.c_str()).c_str();
            mi.loaded    = to_core(ld[i].Position);
            mi.unloaded  = Position::none();
            mi.timestamp = m->Timestamp;
            mi.checksum  = m->Checksum;
            for ( size_t k = 0; k < nu; k++ )
                if ( un[k].pModule == m && ld[i].Position < un[k].Position )
                {
                    mi.unloaded = to_core(un[k].Position);
                    break;
                }
            out.push_back(mi);
        }
        // A module the engine lists with no load event was mapped before the
        // recording began.
        size_t n = m_engine->GetModuleCount();
        const Module *list = m_engine->GetModuleList();
        for ( size_t i = 0; i < n; i++ )
        {
            if ( seen.count(&list[i]) != 0 )
                continue;
            ModuleInfo mi;
            mi.base     = (ea_t)(uint64_t)list[i].Address;
            mi.size     = list[i].Size;
            mi.path     = to_utf8(list[i].pName, list[i].NameLength).c_str();
            mi.name     = base_name(mi.path.c_str()).c_str();
            mi.loaded    = m_info.first;
            mi.unloaded  = Position::none();
            mi.timestamp = list[i].Timestamp;
            mi.checksum  = list[i].Checksum;
            out.push_back(mi);
        }
        return out;
    }

    std::vector<ThreadInfo> MsTtdBackend::threads() const
    {
        std::vector<ThreadInfo> out;
        if ( !m_engine )
            return out;
        size_t nc = m_engine->GetThreadCreatedEventCount();
        const ThreadCreatedEvent *cr = m_engine->GetThreadCreatedEventList();
        size_t nt = m_engine->GetThreadTerminatedEventCount();
        const ThreadTerminatedEvent *te = m_engine->GetThreadTerminatedEventList();
        for ( size_t i = 0; i < nc; i++ )
        {
            if ( cr[i].pThreadInfo == nullptr )
                continue;
            ThreadInfo ti;
            ti.tid     = (uint32_t)cr[i].pThreadInfo->Id;
            ti.created = to_core(cr[i].Position);
            ti.exited  = Position::none();
            for ( size_t k = 0; k < nt; k++ )
                if ( te[k].pThreadInfo == cr[i].pThreadInfo )
                {
                    ti.exited = to_core(te[k].Position);
                    break;
                }
            out.push_back(ti);
        }
        return out;
    }

    std::vector<TraceEvent> MsTtdBackend::timeline() const
    {
        std::vector<TraceEvent> out;
        if ( !m_engine )
            return out;

        // The back-pointers are checked before use: a null is possible and
        // would otherwise crash the Timeline.
        auto add = [&out](const Position &p, const qstring &what)
        {
            TraceEvent e;
            e.pos  = p;
            e.what = what;
            out.push_back(e);
        };
        {
            size_t n = m_engine->GetThreadCreatedEventCount();
            const ThreadCreatedEvent *list = m_engine->GetThreadCreatedEventList();
            for ( size_t i = 0; i < n; i++ )
            {
                if ( list[i].pThreadInfo == nullptr )
                    continue;
                qstring nm;
                nm.sprnt("Thread 0x%X created", (uint32_t)list[i].pThreadInfo->Id);
                add(to_core(list[i].Position), nm);
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
                add(to_core(list[i].Position), nm);
            }
        }
        {
            size_t n = m_engine->GetModuleLoadedEventCount();
            const ModuleLoadedEvent *list = m_engine->GetModuleLoadedEventList();
            for ( size_t i = 0; i < n; i++ )
            {
                if ( list[i].pModule == nullptr )
                    continue;
                qstring nm = "Load ";
                nm.append(base_name(to_utf8(list[i].pModule->pName, list[i].pModule->NameLength)).c_str());
                add(to_core(list[i].Position), nm);
            }
        }
        {
            size_t n = m_engine->GetModuleUnloadedEventCount();
            const ModuleUnloadedEvent *list = m_engine->GetModuleUnloadedEventList();
            for ( size_t i = 0; i < n; i++ )
            {
                if ( list[i].pModule == nullptr )
                    continue;
                qstring nm = "Unload ";
                nm.append(base_name(to_utf8(list[i].pModule->pName, list[i].pModule->NameLength)).c_str());
                add(to_core(list[i].Position), nm);
            }
        }
        {
            size_t n = m_engine->GetExceptionEventCount();
            const TTD::Replay::ExceptionEvent *list = m_engine->GetExceptionEventList();
            for ( size_t i = 0; i < n; i++ )
            {
                qstring nm;
                nm.sprnt("Exception 0x%08X @ 0x%llX", list[i].Code, (uint64_t)list[i].ProgramCounter);
                add(to_core(list[i].Position), nm);
            }
        }
        std::stable_sort(out.begin(), out.end(),
                         [](const TraceEvent &a, const TraceEvent &b) { return a.pos < b.pos; });
        return out;
    }

    QueryResult MsTtdBackend::query_exceptions(std::vector<ExceptionEvent> *out, ProgressSink *)
    {
        QueryResult r;
        if ( !m_engine || out == nullptr )
            return r;
        r.ran = true;
        size_t n = m_engine->GetExceptionEventCount();
        const TTD::Replay::ExceptionEvent *list = m_engine->GetExceptionEventList();
        for ( size_t i = 0; i < n; i++ )
        {
            ExceptionEvent e;
            e.pos       = to_core(list[i].Position);
            e.raise_pos = Position::none();
            e.tid       = list[i].pThreadInfo != nullptr ? (uint32_t)list[i].pThreadInfo->Id : 0;
            e.code      = list[i].Code;
            e.flags     = list[i].Flags;
            e.address   = (ea_t)(uint64_t)list[i].ProgramCounter;
            if ( list[i].ParameterCount > 0 )
                e.information[0] = list[i].Parameters[0];
            if ( list[i].ParameterCount > 1 )
                e.information[1] = list[i].Parameters[1];
            out->push_back(e);
        }
        return r;
    }

    // The instruction stream by single-stepping a scratch cursor: the engine
    // has no "list the instructions" call, and a step is cheap once the cursor
    // is positioned. Sequential replay, so the stream is in program order.
    QueryResult MsTtdBackend::query_instructions(PositionRange when, uint32_t tid, size_t max,
                                                 std::vector<Access> *out, ProgressSink *progress)
    {
        QueryResult r;
        if ( !m_engine || out == nullptr || max == 0 )
            return r;
        // One scratch cursor for every call: this runs on every stop in code
        // without a module, and making a cursor each time is not free.
        if ( !m_insnScratch )
        {
            m_insnScratch = new_engine_cursor();
            if ( !m_insnScratch )
                return r;
            m_insnScratch->SetReplayFlags(ReplayFlags::ReplayAllSegmentsWithoutFiltering
                                        | ReplayFlags::ReplaySegmentsSequentially);
        }
        ICursorView *c = m_insnScratch.get();
        r.ran = true;
        c->SetPosition(from_core(when.first == Position::begin() ? m_info.first : when.first));
        const Position last = when.last == Position::end() ? m_info.last : when.last;

        // A thread can be idle for a long stretch, so the walk is bounded in
        // steps as well as in instructions found: about four steps of any
        // thread per instruction asked for, which is the budget the code
        // analyzer's window has always had.
        const size_t kMaxSteps = max * 4 + 256;
        Position prev = Position::none();
        for ( size_t steps = 0; steps < kMaxSteps; steps++ )
        {
            Position now = to_core(c->GetPosition());
            if ( last < now || now == prev )
                break;
            prev = now;
            if ( progress != nullptr && (steps & 0x3FF) == 0 && progress->cancelled() )
            {
                r.cancelled = true;
                break;
            }
            uint32_t t = (uint32_t)c->GetThreadInfo().Id;
            if ( tid == 0 || t == tid )
            {
                if ( out->size() >= max )
                {
                    r.truncated = true;
                    break;
                }
                Access a;
                a.pos  = now;
                a.tid  = t;
                a.pc   = (ea_t)(uint64_t)c->GetProgramCounter();
                a.addr = a.pc;
                a.kind = ACCESS_EXEC;
                out->push_back(a);
            }
            c->ReplayForward(TtdPosition::Max, StepCount{ 1 });
        }
        return r;
    }

    // Within the position's own sequence, the way the analyzer has always
    // opened its context window: Steps is cheap to move and needs no seek.
    Position MsTtdBackend::position_add(Position p, int64_t delta) const
    {
        if ( !m_engine || !p.is_valid() || p.is_sentinel() )
            return p;
        TtdPosition t = from_core(p);
        uint64_t st = (uint64_t)t.Steps;
        if ( delta < 0 )
            st = st > (uint64_t)(-delta) ? st - (uint64_t)(-delta) : 0;
        else
            st += (uint64_t)delta;
        t.Steps = (StepCount)st;
        TtdPosition last = m_engine->GetLastPosition();
        if ( last.IsValid() && t > last )
            t = last;
        return to_core(t);
    }

    // Replay forward from a little before 'at' up to it with the call/return
    // callback: a CALL pushes its target, a RET pops, and at 'at' the top of
    // the thread's stack is the call that entered the frame. The look-back
    // widens until the call is captured, up to 'max_back' steps; each attempt
    // is one SetPosition plus one forward replay. Never single-steps backward,
    // which re-seeks a keyframe per step.
    bool MsTtdBackend::query_frame_entry(Position at, uint32_t tid, uint64_t max_back,
                                         Position *call_pos, ea_t *entry)
    {
        if ( !m_engine || !at.is_valid() )
            return false;
        if ( !m_frameScratch )
        {
            m_frameScratch = new_engine_cursor();
            if ( !m_frameScratch )
                return false;
            m_frameScratch->SetReplayFlags(ReplayFlags::ReplayAllSegmentsWithoutFiltering
                                         | ReplayFlags::ReplaySegmentsSequentially);
        }

        const TtdPosition cur = from_core(at);
        struct Frame { ea_t entry; TtdPosition pos; };
        std::map<uint32_t, std::vector<Frame>> stacks;
        // CALL: instr == callee (the function head), fall_through == return
        // address. RET: fall_through == 0; pop the innermost open frame.
        auto on_call_ret = [&](GuestAddress instr, GuestAddress fall_through,
                               IThreadView const *t) noexcept
        {
            uint32_t utid = (uint32_t)t->GetThreadInfo().Id;
            try
            {
                if ( (uint64_t)fall_through != 0 )
                {
                    stacks[utid].push_back(Frame{ (ea_t)(uint64_t)instr, t->GetPosition() });
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

        static const uint64_t kWindows[] = { 1024, 8192, 65536 };
        for ( uint64_t back : kWindows )
        {
            if ( back > max_back && back != kWindows[0] )
                break;
            stacks.clear();
            TtdPosition s = cur;
            s.Steps = (StepCount)((uint64_t)cur.Steps > back ? (uint64_t)cur.Steps - back : 0);
            m_frameScratch->SetPosition(s);
            m_frameScratch->SetCallReturnCallback(on_call_ret);
            m_frameScratch->ReplayForward(cur);                 // stop AT the position
            m_frameScratch->SetCallReturnCallback(nullptr, 0);

            auto it = stacks.find(tid);
            if ( it != stacks.end() && !it->second.empty() )
            {
                if ( entry != nullptr )
                    *entry = it->second.back().entry;
                if ( call_pos != nullptr )
                    *call_pos = to_core(it->second.back().pos);
                return true;
            }
            if ( (uint64_t)cur.Steps <= back )
                break;       // the window already reached the start of the sequence
        }
        return false;
    }

    REGISTER_TTD_BACKEND(MsTtdBackend);

    //=======================================================================
    // The cursor
    //=======================================================================
    MsTtdCursor::MsTtdCursor(MsTtdBackend *owner, UniqueCursor exec, UniqueCursor read)
        : m_owner(owner), m_exec(std::move(exec)), m_read(std::move(read))
    {
    }

    Position MsTtdCursor::position() const
    {
        return to_core(m_exec->GetPosition());
    }

    bool MsTtdCursor::seek(Position p)
    {
        if ( p == Position::none() )
            return false;
        m_exec->SetPosition(from_core(p));
        // "Go to position" and the timeline both land here, and a user can
        // type a position past the end of the recording.
        clamp_to_trace();
        return true;
    }

    void MsTtdCursor::clamp_to_trace()
    {
        IReplayEngine *e = m_owner->engine();
        if ( e == nullptr )
            return;
        const TtdPosition first = e->GetFirstPosition();
        const TtdPosition last  = e->GetLastPosition();
        if ( !first.IsValid() || !last.IsValid() )
            return;
        const TtdPosition p = m_exec->GetPosition();
        if ( p > last )
            m_exec->SetPosition(last);
        else if ( p < first )
            m_exec->SetPosition(first);
    }

    uint32_t MsTtdCursor::thread_id() const
    {
        return (uint32_t)m_exec->GetThreadInfo().Id;
    }

    ea_t MsTtdCursor::program_counter() const
    {
        return (ea_t)(uint64_t)m_exec->GetProgramCounter();
    }

    uint64_t MsTtdCursor::stack_pointer() const
    {
        return (uint64_t)m_exec->GetStackPointer();
    }

    bool MsTtdCursor::read_registers(ittd_regs *out) const
    {
        if ( out == nullptr )
            return false;
        regs_from_context(m_exec->GetCrossPlatformContext(), m_owner->is64(), out);
        return true;
    }

    bool MsTtdCursor::read_thread_registers(uint32_t tid, ittd_regs *out) const
    {
        if ( out == nullptr )
            return false;
        regs_from_context(m_exec->GetCrossPlatformContext((ThreadId)tid), m_owner->is64(), out);
        return true;
    }

    std::vector<ThreadInfo> MsTtdCursor::live_threads() const
    {
        std::vector<ThreadInfo> out;
        size_t n = m_exec->GetThreadCount();
        const ActiveThreadInfo *list = m_exec->GetThreadList();
        for ( size_t i = 0; i < n; i++ )
        {
            ThreadInfo ti;
            ti.tid     = (uint32_t)list[i]->Id;
            ti.created = to_core(list[i]->Lifetime.Min);
            ti.exited  = to_core(list[i]->Lifetime.Max);
            out.push_back(ti);
        }
        return out;
    }

    // What MemoryReader's engine half did, minus the module image: that fill is
    // the core's, for every backend. Each byte comes back as the recording's
    // value, a placeholder zero, or nothing.
    size_t MsTtdCursor::read_memory(ea_t ea, void *buffer, size_t size, std::vector<uint8_t> *known)
    {
        std::vector<uint8_t> local;
        std::vector<uint8_t> &filled = known != nullptr ? *known : local;
        filled.assign(size, ITTD_KNOWN_NO);
        if ( buffer == nullptr || size == 0 )
            return 0;

        // The read cursor is parked at the playhead, re-seeking only when the
        // position actually changed.
        ICursorView *mc = m_read ? m_read.get() : m_exec.get();
        if ( m_read )
        {
            TtdPosition cur = m_exec->GetPosition();
            if ( !m_readPosValid || cur.Sequence != m_readPos.Sequence || cur.Steps != m_readPos.Steps )
            {
                m_read->SetPosition(cur);
                m_readPos      = cur;
                m_readPosValid = true;
            }
        }

        // QueryMemoryBuffer only ever returns the single contiguous run that
        // begins exactly at the queried address, so a hole would lose every
        // known byte past it: walk the range, stepping over holes.
        static const QueryMemoryPolicy kPolicies[] = {
            QueryMemoryPolicy::GloballyAggressive,   // the cursor default; cheap first
            QueryMemoryPolicy::InFragmentAggressive, // look across the whole fragment
        };

        uint8_t *out = (uint8_t *)buffer;
        size_t off = 0;
        while ( off < size )
        {
            MemoryBuffer mb{};
            for ( QueryMemoryPolicy p : kPolicies )
            {
                mb = mc->QueryMemoryBuffer(GuestAddress{ (uint64_t)(ea + off) },
                                           BufferView{ out + off, size - off }, p);
                if ( mb.Memory.Size > 0 )
                    break;
            }
            if ( mb.Memory.Size == 0 )
            {
                out[off] = 0;        // hole
                off++;
                continue;
            }
            size_t run = mb.Memory.Size;

            // A non-zero Size does not mean these bytes are real. For memory the
            // engine knows is mapped but has no value for at this position, the
            // aggressive policies answer "here is zero". ThreadLocal is the one
            // policy honest about it, so an all-zero run is only believed if
            // ThreadLocal confirms it; otherwise it is a placeholder, and the
            // core gives the module image first refusal on it. The probe is
            // skipped for any run with a non-zero byte, which keeps the extra
            // query off the hot path.
            uint8_t flag = ITTD_KNOWN_YES;
            bool all_zero = true;
            for ( size_t i = 0; i < run && all_zero; i++ )
                all_zero = out[off + i] == 0;
            if ( all_zero )
            {
                m_probe.assign(run, 0);
                MemoryBuffer probe = mc->QueryMemoryBuffer(GuestAddress{ (uint64_t)(ea + off) },
                                                           BufferView{ m_probe.data(), run },
                                                           QueryMemoryPolicy::ThreadLocal);
                if ( probe.Memory.Size == 0 )
                    flag = ITTD_KNOWN_PLACEHOLDER;
            }
            for ( size_t i = 0; i < run; i++ )
                filled[off + i] = flag;
            off += run;
        }

        // Bytes rebuilt from recorded writes win: the position query only
        // zero-fills that memory.
        for ( const Rebuilt &r : m_rebuilt )
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
                filled[oi] = ITTD_KNOWN_YES;
            }
        }

        size_t n = 0;
        for ( uint8_t f : filled )
            if ( f != ITTD_KNOWN_NO )
                n++;
        return n;
    }

    size_t MsTtdCursor::rebuild_range(ea_t lo, ea_t hi, bool replace)
    {
        if ( lo >= hi )
            return 0;
        if ( replace )
            m_rebuilt.erase(std::remove_if(m_rebuilt.begin(), m_rebuilt.end(),
                                           [lo, hi](const Rebuilt &r) { return r.lo < hi && lo < r.hi; }),
                            m_rebuilt.end());
        size_t recovered = 0;
        if ( rebuild(lo, hi) )
        {
            for ( const Rebuilt &r : m_rebuilt )
            {
                if ( r.lo >= hi || lo >= r.hi )
                    continue;
                for ( size_t i = 0; i < r.known.size(); i++ )
                {
                    ea_t a = r.lo + (ea_t)i;
                    if ( r.known[i] && a >= lo && a < hi )
                        recovered++;
                }
            }
        }
        return recovered;
    }

    // Replay forward to the playhead with a Write watchpoint over the range,
    // keeping the latest written value of each byte -- what WinDbg shows there.
    bool MsTtdCursor::rebuild(ea_t lo, ea_t hi)
    {
        // A hard cap on the window: callers derive 'hi' from segment bounds,
        // and a bad bound would otherwise ask for terabytes.
        static const uint64_t kMaxBytes = 1u << 20;
        if ( (uint64_t)(hi - lo) > kMaxBytes )
            hi = lo + (ea_t)kMaxBytes;

        for ( const Rebuilt &r : m_rebuilt )
            if ( r.lo <= lo && hi <= r.hi )
                return true;

        UniqueCursor cur = m_owner->new_engine_cursor();
        if ( !cur )
            return false;
        const TtdPosition target = m_exec->GetPosition();

        Rebuilt reg;
        reg.lo = lo;
        reg.hi = hi;
        reg.data.assign((size_t)(hi - lo), 0);
        reg.known.assign((size_t)(hi - lo), false);

        size_t hits = 0;
        // On each recorded write touching [lo, hi), copy the just-written bytes
        // (read thread-locally from the writing thread, which has them).
        // Replaying sequentially forward means the last write before 'target'
        // wins. Returning false keeps the watchpoint from stopping the replay.
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
        cur->SetReplayFlags(ReplayFlags::ReplaySegmentsSequentially);
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
        m_rebuilt.push_back(std::move(reg));
        return true;
    }
}
