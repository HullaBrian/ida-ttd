#include "backend-msttd/msttd_backend.h"
#include "backend-msttd/msttd_sweep.h"
#include "backend-msttd/msttd_navigator.h"
#include "backend-msttd/msttd_host.h"
#include "backend-msttd/msttd_guest.h"
#include "common/symbols.h"

using namespace TTD;
using namespace TTD::Replay;

namespace idattd
{
    //=======================================================================
    // The backend
    //=======================================================================
    MsTtdBackend::MsTtdBackend()
    {
        m_err.owner = this;
    }

    qstring MsTtdBackend::last_error() const
    {
        std::lock_guard<std::mutex> lock(m_errorMtx);
        auto it = m_error.find(std::this_thread::get_id());
        return it != m_error.end() ? qstring(it->second.c_str()) : qstring();
    }

    void MsTtdBackend::clear_error()
    {
        std::lock_guard<std::mutex> lock(m_errorMtx);
        m_error.erase(std::this_thread::get_id());
    }

    void MsTtdBackend::set_error(const char *fmt, ...) const
    {
        char buf[2048];
        va_list va;
        va_start(va, fmt);
        vsnprintf(buf, sizeof(buf), fmt, va);
        va_end(va);
        std::lock_guard<std::mutex> lock(m_errorMtx);
        // A thread that fails often still holds one entry; ended threads'
        // entries are few (the core's workers) and small.
        m_error[std::this_thread::get_id()] = buf;
    }

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

    bool MsTtdBackend::prepare(ProgressSink *progress)
    {
        if ( !m_engine )
            return false;
        m_indexed = build_trace_index(m_engine.get(), progress);
        return m_indexed;
    }

    bool MsTtdBackend::prepared() const
    {
        // An index the engine could not save is still built and in memory, so
        // the status alone does not say; what this session built does.
        return m_engine && (m_indexed
                         || m_engine->GetIndexStatus() == TTD::Replay::IndexStatus::IndexFileLoaded);
    }

    // The user's IDA directories: each entry of %IDAUSR%, or else the
    // default one, as IDA itself picks them.
    static std::vector<std::filesystem::path> user_ida_dirs()
    {
        std::vector<std::filesystem::path> dirs;
        wchar_t buf[4096];
        DWORD n = GetEnvironmentVariableW(L"IDAUSR", buf, (DWORD)std::size(buf));
        if ( n > 0 && n < std::size(buf) )
        {
            std::wstring all(buf, n);
            for ( size_t start = 0; start <= all.size(); )
            {
                size_t end = all.find(L';', start);
                if ( end == std::wstring::npos )
                    end = all.size();
                if ( end > start )
                    dirs.emplace_back(all.substr(start, end - start));
                start = end + 1;
            }
            return dirs;
        }
        n = GetEnvironmentVariableW(L"APPDATA", buf, (DWORD)std::size(buf));
        if ( n > 0 && n < std::size(buf) )
            dirs.push_back(std::filesystem::path(std::wstring(buf, n)) / L"Hex-Rays" / L"IDA Pro");
        return dirs;
    }

    // The replay runtime, tried in this order:
    //  - a TTDReplay.dll the process already loaded;
    //  - next to the process's executable (ida.exe, or the probe);
    //  - next to this backend, or in plugins\ida-ttd-backends\ two levels
    //    up (for a package install, whose folder hcli replaces on upgrade);
    //  - $IDAUSR\ida-ttd\windbg\, where TTD > Backends > Install the TTD
    //    runtime puts it (scripts/ida_ttd_runtime.py), or the older
    //    $IDAUSR\plugins\ida-ttd-backends\windbg\.
    // Only by full path, never by bare name: the default search order
    // includes the current directory and PATH, so a TTDReplay.dll planted
    // beside a recording someone opens would run inside IDA.
    // An installed WinDbg cannot be used in place: Windows refuses to load a
    // DLL from a package folder (WindowsApps) into another process
    // (ERROR_ACCESS_DENIED), so the installer copies the runtime out.
    // Never shipped with the plugin: Microsoft's terms forbid that.
    // TTDReplayCPU.dll is TTDReplay.dll's only non-system import, a static
    // one (it is not loaded by name later), so LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR
    // resolves it from the same folder and from nowhere else.
    static bool load_ttd_runtime()
    {
        if ( GetModuleHandleW(L"TTDReplay.dll") != nullptr )
            return true;
        namespace fs = std::filesystem;
        std::vector<fs::path> candidates;
        wchar_t buf[MAX_PATH] = { 0 };
        DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
        if ( n > 0 && n < MAX_PATH )
            candidates.push_back(fs::path(std::wstring(buf, n)).parent_path() / L"TTDReplay.dll");
        HMODULE self = nullptr;
        if ( GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
                              | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                (LPCWSTR)(void *)&load_ttd_runtime, &self) )
        {
            n = GetModuleFileNameW(self, buf, MAX_PATH);
            if ( n > 0 && n < MAX_PATH )
            {
                fs::path dir = fs::path(std::wstring(buf, n)).parent_path();
                candidates.push_back(dir / L"TTDReplay.dll");
                candidates.push_back(dir.parent_path().parent_path() / L"ida-ttd-backends" / L"TTDReplay.dll");
            }
        }
        const fs::path ttd = fs::path(L"amd64") / L"ttd" / L"TTDReplay.dll";
        for ( const fs::path &u : user_ida_dirs() )
        {
            candidates.push_back(u / L"ida-ttd" / L"windbg" / ttd);
            candidates.push_back(u / L"plugins" / L"ida-ttd-backends" / L"windbg" / ttd);
        }

        for ( const fs::path &p : candidates )
        {
            std::error_code ec;
            // A relative entry (an %IDAUSR% written that way) would resolve
            // against the current directory, which is what this avoids.
            if ( !p.is_absolute() || !fs::is_regular_file(p, ec) )
                continue;
            if ( LoadLibraryExW(p.c_str(), nullptr,
                                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS) != nullptr )
                return true;
        }
        return false;
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

        // TTDReplay.dll is delay-loaded, so a missing one would surface as a
        // fault in the first engine call. Load it here, where it can be
        // explained.
        if ( !load_ttd_runtime() )
            return fail("Microsoft's TTD replay runtime (TTDReplay.dll) was not found.\n\n"
                        "It comes with WinDbg, which ida-ttd may not include. "
                        "TTD > Backends > Install the TTD runtime (WinDbg)... copies it from an "
                        "installed WinDbg, or downloads WinDbg from Microsoft (in IDAPython: "
                        "import ida_ttd_runtime; ida_ttd_runtime.install_runtime()). "
                        "Then start the debugger again.");

        auto made = MakeReplayEngine();
        m_engine = std::move(made.first);
        if ( made.second != 0 || !m_engine )
        {
            m_engine.reset();
            return fail("Failed to create the TTD replay engine (0x%08X).\n\n"
                        "The TTD runtime may be incomplete (TTDReplayCPU.dll belongs beside "
                        "TTDReplay.dll) or from an incompatible WinDbg. "
                        "TTD > Backends > Install the TTD runtime (WinDbg)... installs it afresh.",
                        made.second);
        }
        m_engine->RegisterDebugModeAndLogging(DebugModeType::None, &m_err);

        std::wstring wpath = to_wstring(path);
        if ( !m_engine->Initialize(wpath.c_str()) )
        {
            m_engine.reset();
            return fail("Failed to load the trace: %s", path);
        }

        m_info = TraceInfo{};
        m_info.first        = to_core(m_engine->GetFirstPosition());
        m_info.last         = to_core(m_engine->GetLastPosition());
        m_info.backend_name = display_name();

        // Process id, the recording's extent and its module count: not a hash
        // of the file (gigabytes), but enough to tell recordings apart. Saved
        // results are stamped with this formula; changing it orphans them.
        const SystemInfo &si = m_engine->GetSystemInfo();
        uint64_t v = (uint64_t)si.ProcessId;
        v = v * 1099511628211ull ^ (uint64_t)m_engine->GetFirstPosition().Sequence;
        v = v * 1099511628211ull ^ (uint64_t)m_engine->GetLastPosition().Sequence;
        v = v * 1099511628211ull ^ (uint64_t)m_engine->GetLastPosition().Steps;
        v = v * 1099511628211ull ^ (uint64_t)m_engine->GetModuleCount();
        m_info.fingerprint = v;

        // The program is the engine's first module. Its bitness comes from its
        // PE header, read at its own load event (the first load event can be
        // another module's), or at the start if it was mapped before the
        // recording began.
        m_info.is64 = true;
        if ( m_engine->GetModuleCount() > 0 )
        {
            const Module &m0 = m_engine->GetModuleList()[0];
            m_info.main_module = base_name(to_utf8(m0.pName, m0.NameLength)).c_str();
            TtdPosition mapped = m_engine->GetFirstPosition();
            size_t nl = m_engine->GetModuleLoadedEventCount();
            const ModuleLoadedEvent *ld = m_engine->GetModuleLoadedEventList();
            for ( size_t i = 0; i < nl; i++ )
                if ( ld[i].pModule == &m0 )
                {
                    mapped = ld[i].Position;
                    break;
                }
            UniqueCursor c = new_engine_cursor();
            if ( c )
            {
                c->SetPosition(mapped);
                GuestPeInfo pe;
                if ( read_guest_pe_info(msttd_read_plain(c.get()), (ea_t)(uint64_t)m0.Address, &pe) )
                    m_info.is64 = pe.is64;
            }
        }

        m_caps = Capabilities{};
        m_caps.access_queries = true;      // by replay with watchpoints armed
        m_caps.call_queries   = true;      // by replay with the call/return callback
        // Not mapping_changes: the map is reconstructed from the memory
        // syscalls rather than read out of the recording (see the ABI).
        m_caps.cheap_seek     = true;
        m_caps.reverse_step   = true;
        m_caps.exceptions     = true;
        m_caps.cheap_reads    = true;      // the engine's memory index
        m_caps.syscalls       = true;      // KernelCall gaps (msttd_syscalls.cpp)
        m_caps.self_modifying = true;      // replays watching writes (msttd_scans.cpp)
        m_caps.replay_scans   = true;      // strings and buffers, from the same replays
        // registers_at spreads its seeks over worker cursors, so a batch is
        // cheaper than a seek per position: the tracer then reads the calls'
        // memory in batches too.
        m_caps.batch_regs     = true;
        return true;
    }

    void MsTtdBackend::close()
    {
        // Cursors before the engine they belong to.
        {
            std::lock_guard<std::mutex> lock(m_frameMtx);
            m_frameScratch.reset();
        }
        {
            std::lock_guard<std::mutex> lock(m_insnMtx);
            m_insnScratch.reset();
        }
        {
            std::lock_guard<std::mutex> lock(m_regsMtx);
            m_regsScratch.reset();
            m_syscallRegs.clear();
        }
        {
            std::lock_guard<std::mutex> lock(m_censusMtx);
            m_census.reset();
        }
        {
            std::lock_guard<std::mutex> lock(m_scansMtx);
            m_scans.reset();
        }
        m_engine.reset();
        m_info = TraceInfo{};
        m_caps = Capabilities{};
        m_indexed = false;
    }

    // Microsoft's own notation, Sequence:Steps in hex, which core/position.h
    // has always used and the database's stored positions are written in.
    qstring MsTtdBackend::format_position(Position p) const { return format_hex_position(p); }
    bool MsTtdBackend::parse_position(const char *text, Position *out) const
    { return parse_hex_position(text, out); }
    const char *MsTtdBackend::position_syntax() const { return hex_position_syntax(); }

    UniqueCursor MsTtdBackend::new_engine_cursor() const
    {
        if ( !m_engine )
        {
            set_error("no recording is open");
            return UniqueCursor{};
        }
        UniqueCursor c{ m_engine->NewCursor() };
        // Every query starts with a cursor of its own; one the engine will
        // not make (out of memory, mostly) is the reason the query failed.
        if ( !c )
            set_error("the TTD replay engine could not create a cursor");
        return c;
    }

    QueryResult MsTtdBackend::read_memory_at(const std::vector<MemAt> &reads, std::vector<uint8_t> *data,
                                             std::vector<uint8_t> *known, ProgressSink *progress)
    {
        QueryResult r;
        if ( !m_engine || data == nullptr || known == nullptr )
            return r;
        size_t total = 0;
        for ( const MemAt &m : reads )
            total = std::max(total, m.offset + m.size);
        data->assign(total, 0);
        known->assign(total, ITTD_KNOWN_NO);
        r.ran = true;

        // The reads in position order, cut into runs that share a position:
        // one seek a run.
        std::vector<size_t> order(reads.size());
        for ( size_t i = 0; i < order.size(); i++ )
            order[i] = i;
        std::stable_sort(order.begin(), order.end(),
                         [&](size_t a, size_t b) { return reads[a].pos < reads[b].pos; });
        std::vector<size_t> starts;
        for ( size_t i = 0; i < order.size(); i++ )
            if ( i == 0 || reads[order[i]].pos != reads[order[i - 1]].pos )
                starts.push_back(i);
        const size_t runs = starts.size();
        starts.push_back(order.size());

        // Seeking is the cost (a replay forward from the previous position
        // costs as much as a seek), and no single replay can stand in for it:
        // memory queries from a replay's callbacks are thread-local only, and
        // a syscall's position is reported from after the transition. So the
        // positions are shared between cursors (msttd_parallel). Each worker
        // writes only its own reads' bytes.
        const bool complete = msttd_parallel(runs, 8, progress,
            [&](size_t begin, size_t end, std::atomic<size_t> &done, const std::atomic<bool> &stop)
        {
            UniqueCursor exec = new_engine_cursor();
            if ( !exec )
                return;
            exec->SetDefaultMemoryPolicy(QueryMemoryPolicy::GloballyAggressive);
            // Only ever positioned, never executed, so it serves the reads
            // itself rather than through a second cursor.
            MsTtdCursor c(this, std::move(exec), UniqueCursor{});
            std::vector<uint8_t> k;
            for ( size_t run = begin; run < end && !stop.load(); run++, done++ )
            {
                if ( !c.seek(reads[order[starts[run]]].pos) )
                    continue;
                for ( size_t j = starts[run]; j < starts[run + 1]; j++ )
                {
                    const MemAt &m = reads[order[j]];
                    if ( m.size == 0 )
                        continue;
                    c.read_memory(m.addr, data->data() + m.offset, m.size, &k);
                    for ( size_t b = 0; b < m.size && b < k.size(); b++ )
                        (*known)[m.offset + b] = k[b];
                }
            }
        });
        r.cancelled = !complete;
        return r;
    }

    // Each position once, on worker cursors set up as read_memory_at's: one
    // engine cursor each, read directly. A reader that must follow pointers
    // (a syscall's arguments to a structure to a string) does it all at one
    // seek, where read_memory_at would need a round, and a seek, per level;
    // and 'after' (just past a syscall, say) is a step of the same cursor,
    // about a third of a seek. An ordinary cursor would not do: it reads
    // through a second engine cursor that has to follow the first.
    QueryResult MsTtdBackend::visit_positions(const std::vector<Position> &at, const std::vector<Position> *after,
                                              const VisitFn &fn, ProgressSink *progress)
    {
        QueryResult r;
        if ( !m_engine )
            return r;
        r.ran = true;
        if ( at.empty() )
            return r;
        const bool complete = msttd_parallel(at.size(), 8, progress,
            [&](size_t begin, size_t end, std::atomic<size_t> &done, const std::atomic<bool> &stop)
        {
            UniqueCursor exec = new_engine_cursor();
            if ( !exec )
                return;
            exec->SetDefaultMemoryPolicy(QueryMemoryPolicy::GloballyAggressive);
            MsTtdCursor c(this, std::move(exec), UniqueCursor{});
            // The memory of this visit, by 256-byte block: a decoder reads a
            // pointer, then a length, then a few bytes of string, and each
            // engine query costs far more than its bytes (a visit that read
            // one block a syscall took 19 s for 2,232 syscalls, the decoder's
            // many small reads 34 s). Dropped at every move.
            struct Block
            {
                uint8_t data[256];
                uint8_t known[256];
            };
            std::unordered_map<uint64_t, Block> blocks;
            std::vector<uint8_t> k;
            auto block_at = [&](uint64_t base) -> const Block &
            {
                auto it = blocks.find(base);
                if ( it != blocks.end() )
                    return it->second;
                Block blk;
                memset(blk.data, 0, sizeof(blk.data));
                c.read_memory((ea_t)base, blk.data, sizeof(blk.data), &k);
                for ( size_t j = 0; j < sizeof(blk.known); j++ )
                    blk.known[j] = j < k.size() ? k[j] : ITTD_KNOWN_NO;
                return blocks.emplace(base, blk).first->second;
            };
            const VisitRead read = [&](uint64_t addr, void *buf, size_t size) -> size_t
            {
                if ( buf == nullptr || size == 0 )
                    return 0;
                memset(buf, 0, size);
                // Not past the top of the address space.
                if ( addr + size < addr )
                    size = (size_t)(0 - addr);
                uint8_t *out = static_cast<uint8_t *>(buf);
                size_t n = 0;
                bool whole = true;
                for ( size_t off = 0; off < size; )
                {
                    const uint64_t a    = addr + off;
                    const uint64_t base = a & ~uint64_t(0xFF);
                    const size_t   in   = (size_t)(a - base);
                    const size_t   take = std::min<size_t>(256 - in, size - off);
                    const Block &blk = block_at(base);
                    memcpy(out + off, blk.data + in, take);
                    for ( size_t j = 0; j < take && whole; j++ )
                    {
                        if ( blk.known[in + j] == ITTD_KNOWN_NO )
                            whole = false;
                        else
                            n++;
                    }
                    off += take;
                }
                return n;
            };
            for ( size_t i = begin; i < end && !stop.load(); i++, done++ )
            {
                blocks.clear();
                if ( !c.seek(at[i]) )
                    continue;
                fn(i, 0, read);
                blocks.clear();
                if ( after != nullptr && i < after->size() && (*after)[i].is_valid() && c.seek((*after)[i]) )
                    fn(i, 1, read);
            }
        });
        r.cancelled = !complete;
        return r;
    }

    uint32_t MsTtdBackend::unique_thread_id(uint32_t tid, Position at) const
    {
        if ( !m_engine )
            return 0;
        const TtdPosition p = from_core(at);
        uint32_t last_with_id = 0;
        size_t n = m_engine->GetThreadCount();
        const TTD::Replay::ThreadInfo *list = m_engine->GetThreadList();
        for ( size_t i = 0; i < n; i++ )
        {
            if ( (uint32_t)list[i].Id != tid )
                continue;
            last_with_id = (uint32_t)list[i].UniqueId;
            if ( !(p < list[i].Lifetime.Min) && !(list[i].Lifetime.Max < p) )
                return last_with_id;
        }
        return last_with_id;
    }

    CursorPtr MsTtdBackend::make_cursor()
    {
        UniqueCursor exec = new_engine_cursor();
        UniqueCursor read = new_engine_cursor();
        if ( !exec )
            return nullptr;
        // Serve memory like WinDbg: the default policy returns only memory the
        // current thread touched near this position (earlier writes read as
        // zeros); GloballyAggressive searches the whole trace.
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
        // One entry per load: a module loaded twice is listed twice, each with
        // its own positions, because reading its headers needs a position
        // where that load is mapped.
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
        std::lock_guard<std::mutex> lock(m_insnMtx);
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
        {
            const uint64_t back = 0 - (uint64_t)delta;   // not -delta: INT64_MIN overflows
            st = st > back ? st - back : 0;
        }
        else
            st += (uint64_t)delta;
        t.Steps = (StepCount)st;
        TtdPosition last = m_engine->GetLastPosition();
        if ( last.IsValid() && t > last )
            t = last;
        return to_core(t);
    }

    // The last instruction of a thread that changed a register, found without
    // stepping backward (each backward step re-seeks a keyframe: tens of ms).
    // A window of the thread's steps before 'at' is replayed forward with an
    // execute watchpoint over all of user space, which calls back before
    // every instruction with the thread's registers. A window with no change
    // is followed by one four times longer further back, up to 'max_back'.
    bool MsTtdBackend::query_register_change(Position at, uint32_t tid, uint32_t reg, uint64_t max_back,
                                             Position *where, bool *found, ProgressSink *progress)
    {
        if ( !m_engine || !at.is_valid() )
            return false;
        const bool is_xmm = reg >= ITTD_ORIGIN_XMM0;
        if ( is_xmm ? reg - ITTD_ORIGIN_XMM0 >= 16 : reg >= ITTD_REG_GP_COUNT )
            return false;
        // regs_from_context fills no XMM register for a 32-bit context, so
        // the search would compare zeros with zeros and report "not found".
        if ( is_xmm && !m_info.is64 )
        {
            set_error("the XMM registers are not read from this 32-bit recording");
            return false;
        }
        UniqueCursor cur = new_engine_cursor();
        if ( !cur )
            return false;
        const bool is64 = m_info.is64;

        // The register's 16 bytes (a general-purpose one in the first 8).
        struct Value
        {
            uint8_t b[16] = { 0 };
            bool operator!=(const Value &o) const { return memcmp(b, o.b, sizeof(b)) != 0; }
        };
        auto value_of = [&](const CROSS_PLATFORM_CONTEXT &ctx) -> Value
        {
            ittd_regs r{};
            regs_from_context(ctx, is64, &r);
            Value v;
            if ( is_xmm )
                memcpy(v.b, r.xmm[reg - ITTD_ORIGIN_XMM0], 16);
            else
                memcpy(v.b, &r.gp[reg], 8);
            return v;
        };

        // The thread, by its unique id, standing at 'at'.
        cur->SetPosition(from_core(at));
        const uint32_t utid = (uint32_t)cur->GetThreadInfo().Id == tid
                            ? (uint32_t)cur->GetThreadInfo().UniqueId
                            : unique_thread_id(tid, at);
        if ( utid == 0 )
            return false;
        if ( (uint32_t)cur->GetThreadInfo().UniqueId != utid )
            cur->SetPositionOnThread((UniqueThreadId)utid, from_core(at));

        TtdPosition end   = from_core(at);
        Value       after = value_of(cur->GetCrossPlatformContext((ThreadId)tid));
        uint64_t    searched = 0, window = 4096;
        *found = false;

        MemoryWatchpointData wp{};
        wp.Address    = GuestAddress{ 0 };
        wp.Size       = user_space_end();
        wp.AccessMask = DataAccessMask::Execute;
        cur->SetReplayFlags(ReplayFlags::ReplaySegmentsSequentially);

        while ( searched < max_back )
        {
            if ( progress != nullptr && progress->cancelled() )
                return true;
            // The window's start: 'window' of the thread's steps before 'end'.
            cur->SetPositionOnThread((UniqueThreadId)utid, end);
            cur->ReplayBackward(TtdPosition::Min, (StepCount)window);
            const TtdPosition start = cur->GetPosition();
            if ( !(start < end) )
                return true;                            // the thread's beginning

            bool        have = false;
            Value       prev;
            TtdPosition prev_pos = TtdPosition::Invalid;
            TtdPosition change   = TtdPosition::Invalid;
            Value       first;
            bool        have_first = false;
            auto on_exec = [&](ICursorView::MemoryWatchpointResult const &, IThreadView const *t) noexcept -> bool
            {
                if ( (uint32_t)t->GetThreadInfo().UniqueId != utid )
                    return false;
                const TtdPosition p = t->GetPosition();
                if ( end < p )
                    return false;
                Value v = value_of(t->GetCrossPlatformContext());
                if ( !have_first )
                {
                    first = v;
                    have_first = true;
                }
                if ( have && v != prev )
                    change = prev_pos;
                prev = v;
                prev_pos = p;
                have = true;
                return false;
            };
            cur->SetPosition(start);
            cur->AddMemoryWatchpoint(wp);
            cur->SetMemoryWatchpointCallback(on_exec);
            cur->SetEventMask(EventMask::MemoryWatchpoint);
            const bool complete = msttd_sweep(cur.get(), start, end, progress);
            cur->SetMemoryWatchpointCallback(nullptr, 0);
            cur->RemoveMemoryWatchpoint(wp);
            if ( !complete )
                return true;
            // The last instruction before 'end' changes it to what 'end' has.
            if ( have && prev_pos < end && prev != after )
                change = prev_pos;
            if ( change.IsValid() )
            {
                *where = to_core(change);
                *found = true;
                return true;
            }
            searched += window;
            window   *= 4;
            // A window the thread did not run in (it was waiting while
            // others ran) leaves the value as it was: widen past it.
            end = start;
            if ( have_first )
                after = first;
        }
        return true;
    }

    // Find the CALL that entered a frame without single-stepping backward (a
    // keyframe re-seek per step, minutes in all): seek before 'here' and
    // replay forward to it, tracking the thread's open calls, widening the
    // window until the entering call is captured. One seek and one forward
    // replay per window.
    MsTtdBackend::FrameSearch MsTtdBackend::find_frame_entry(ICursorView *scratch, TtdPosition here,
                                                             uint32_t utid, uint64_t here_sp,
                                                             const FrameWindow *windows, size_t nwindows,
                                                             ProgressSink *progress, bool log_miss,
                                                             FrameEntry *out) const
    {
        if ( !m_engine || scratch == nullptr || out == nullptr || utid == 0 )
            return FrameSearch::NotFound;

        // Floor: nothing the thread did lies before its ActiveTime, so a
        // window reaching it with no open call means the outermost frame.
        // Work from a recorded position the thread reached: the end of the
        // recording can belong to another thread.
        TtdPosition first = m_engine->GetFirstPosition();
        const TtdPosition last = m_engine->GetLastPosition();
        {
            size_t n = m_engine->GetThreadCount();
            const TTD::Replay::ThreadInfo *list = m_engine->GetThreadList();
            for ( size_t i = 0; i < n; i++ )
            {
                if ( (uint32_t)list[i].UniqueId != utid )
                    continue;
                if ( list[i].ActiveTime.Min.IsValid() && first < list[i].ActiveTime.Min )
                    first = list[i].ActiveTime.Min;
                if ( list[i].ActiveTime.Max.IsValid() && here > list[i].ActiveTime.Max )
                    here = list[i].ActiveTime.Max;
                break;
            }
        }
        if ( last.IsValid() && here > last )
            here = last;
        if ( first.IsValid() && here < first )
            here = first;

        // A CALL pushes; a RET pops the innermost open call it returns to and
        // drops the calls above it, which left without returning (a syscall,
        // context switch, exception or longjmp). A RET matching no open call
        // closes a frame opened before the window began; ignoring it keeps a
        // partial window correct. Engine callbacks are noexcept: the depth is
        // capped rather than let an allocation throw in here.
        struct Open { TtdPosition pos; uint64_t sp; ea_t entry; uint64_t ret; };
        std::vector<Open> stack;
        uint64_t seen_all  = 0;
        uint64_t seen_mine = 0;
        auto on_call_ret = [&](GuestAddress instr, GuestAddress fall_through, IThreadView const *t) noexcept
        {
            static const size_t kMaxDepth = 8192;
            seen_all++;
            if ( (uint32_t)t->GetThreadInfo().UniqueId != utid )
                return;
            seen_mine++;
            try
            {
                // CALL: instr is the callee, fall_through the return address.
                // RET: fall_through is 0 and instr the address returned to.
                if ( (uint64_t)fall_through != 0 )
                {
                    if ( stack.size() < kMaxDepth )
                        stack.push_back(Open{ t->GetPosition(), (uint64_t)t->GetStackPointer(),
                                              (ea_t)(uint64_t)instr, (uint64_t)fall_through });
                }
                else
                {
                    for ( size_t k = stack.size(); k-- > 0; )
                        if ( stack[k].ret == (uint64_t)instr )
                        {
                            stack.resize(k);
                            break;
                        }
                }
            }
            catch ( ... )
            {
            }
        };

        bool        cancelled = false;
        TtdPosition lastStart = TtdPosition::Invalid;
        TtdPosition winStart  = TtdPosition::Invalid;
        uint64_t    winInsns  = 0;
        for ( size_t i = 0; i < nwindows; i++ )
        {
            if ( progress != nullptr )
            {
                if ( progress->cancelled() )
                {
                    cancelled = true;
                    break;
                }
                progress->report((uint32_t)(i * 100 / nwindows));
            }

            TtdPosition s = here;
            const uint64_t back = windows[i].back;
            switch ( windows[i].kind )
            {
                case FrameWindowKind::InSequence:
                    s.Steps = (StepCount)((uint64_t)here.Steps > back ? (uint64_t)here.Steps - back : 0);
                    break;
                case FrameWindowKind::ThreadSteps:
                    // Within the sequence the steps are this thread's, so the
                    // common case needs no seek. Past its start, the thread's
                    // own steps back are counted by a backward replay, which
                    // skips other threads' sequences in between.
                    if ( (uint64_t)here.Steps >= back )
                        s.Steps = (StepCount)((uint64_t)here.Steps - back);
                    else
                    {
                        scratch->SetPositionOnThread((UniqueThreadId)utid, here);
                        scratch->ReplayBackward(TtdPosition::Min, (StepCount)back);
                        s = scratch->GetPosition();
                    }
                    break;
                case FrameWindowKind::Sequences:
                {
                    uint64_t sq = (uint64_t)here.Sequence;
                    s.Sequence = (SequenceId)(sq > back ? sq - back : 0);
                    s.Steps    = StepCount::Min;
                    break;
                }
            }
            if ( s < first )
                s = first;
            if ( s == lastStart )
                continue;           // the windows collapse near a sequence or thread start
            lastStart = s;

            stack.clear();
            seen_all  = 0;
            seen_mine = 0;
            scratch->SetPosition(s);
            scratch->SetCallReturnCallback(on_call_ret);
            ICursorView::ReplayResult rr = scratch->ReplayForward(here);    // stop AT the position
            scratch->SetCallReturnCallback(nullptr, 0);
            winStart = s;
            winInsns = (uint64_t)rr.InstructionsExecuted;

            // The innermost open call made at or above the stack pointer
            // here; equal is possible at the callee's first instruction,
            // depending on whether the engine reports the stack before or
            // after the push. Anything deeper never returned.
            for ( auto o = stack.rbegin(); o != stack.rend(); ++o )
                if ( o->sp >= here_sp )
                {
                    out->pos      = o->pos;
                    out->entry    = o->entry;
                    out->ret_addr = o->ret;
                    return FrameSearch::Found;
                }
            if ( !(first < s) )
                break;      // the window already reached the thread's start
        }
        if ( cancelled )
            return FrameSearch::Cancelled;
        if ( log_miss )
        {
            // An outermost frame and a window that replayed nothing look the
            // same to the user; log which.
            msttd_log("[ida-ttd] no entering call for thread %X searching back from "
                "%llX:%llX. Last window %llX:%llX replayed %llu instructions, "
                "%llu call/ret events, %llu of them on this thread.\n",
                utid, (uint64_t)here.Sequence, (uint64_t)here.Steps,
                (uint64_t)winStart.Sequence, (uint64_t)winStart.Steps,
                winInsns, seen_all, seen_mine);
        }
        return FrameSearch::NotFound;
    }

    // Runs on every stop in code outside any module, so the look-back is
    // short and grows only up to 'max_back' of the thread's instructions.
    bool MsTtdBackend::query_frame_entry(Position at, uint32_t tid, uint64_t max_back,
                                         Position *call_pos, ea_t *entry)
    {
        if ( !m_engine || !at.is_valid() )
            return false;
        std::lock_guard<std::mutex> lock(m_frameMtx);
        if ( !m_frameScratch )
        {
            m_frameScratch = new_engine_cursor();
            if ( !m_frameScratch )
                return false;
            m_frameScratch->SetReplayFlags(ReplayFlags::ReplayAllSegmentsWithoutFiltering
                                         | ReplayFlags::ReplaySegmentsSequentially);
        }

        // The thread by its unique id: an OS id can be reused. Only the
        // thread standing at 'at' has its stack pointer known; for any other,
        // the innermost open call is the best answer.
        const TtdPosition here = from_core(at);
        m_frameScratch->SetPosition(here);
        const bool     standing = (uint32_t)m_frameScratch->GetThreadInfo().Id == tid;
        const uint32_t utid     = standing ? (uint32_t)m_frameScratch->GetThreadInfo().UniqueId
                                           : unique_thread_id(tid, at);
        const uint64_t sp_at    = standing ? (uint64_t)m_frameScratch->GetStackPointer() : 0;

        // The first window always; the wider ones while within 'max_back'.
        static const uint64_t kBacks[] = { 1024, 8192, 65536 };
        FrameWindow windows[qnumber(kBacks)];
        size_t n = 0;
        for ( uint64_t back : kBacks )
        {
            if ( back > max_back && n != 0 )
                break;
            windows[n++] = FrameWindow{ FrameWindowKind::ThreadSteps, back };
        }

        FrameEntry fe;
        if ( find_frame_entry(m_frameScratch.get(), here, utid, sp_at, windows, n,
                              nullptr, false, &fe) != FrameSearch::Found )
            return false;
        if ( entry != nullptr )
            *entry = fe.entry;
        if ( call_pos != nullptr )
            *call_pos = to_core(fe.pos);
        return true;
    }

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
            // Only the 32-bit side of a WoW64 process is recorded, so an x86
            // recording's TEB is the 32-bit one.
            ea_t teb = (ea_t)(uint64_t)m_exec->GetTebAddress(list[i]->Id);
            if ( m_owner->is64() )
                ti.teb = teb;
            else
                ti.teb32 = teb;
            out.push_back(ti);
        }
        return out;
    }

    // The recording's part of a memory read; filling from the module image is
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

        // Whether one byte is readable under either policy: what the run
        // query below asks, cut to a single byte.
        auto readable = [&](size_t at) -> bool
        {
            uint8_t b;
            for ( QueryMemoryPolicy p : kPolicies )
                if ( mc->QueryMemoryBuffer(GuestAddress{ (uint64_t)(ea + at) },
                                           BufferView{ &b, 1 }, p).Memory.Size > 0 )
                    return true;
            return false;
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
                // A hole. Probing byte by byte costs two queries a byte (~8K
                // per page), and holes need not end on a page boundary (a
                // stack page mixes recorded and unrecorded stretches). On the
                // reference recordings every run after a hole holds a
                // 32-byte-aligned address, so probe only 8-byte-aligned
                // addresses and, on a hit, walk back to the run's start: an
                // eighth of the queries for the same bytes. Only a run under
                // 8 bytes holding no aligned address can be missed.
                static const size_t kStride = 8;
                size_t hi = size;    // the start of the next run, or the end
                size_t at = (size_t)((((uint64_t)ea + off) | (kStride - 1)) + 1 - (uint64_t)ea);
                for ( ; at < size; at += kStride )
                {
                    if ( !readable(at) )
                        continue;
                    hi = at;
                    while ( hi - 1 > off && readable(hi - 1) )
                        hi--;
                    break;
                }
                memset(out + off, 0, hi - off);
                off = hi;
                continue;
            }
            // Never past the buffer, whatever the engine claims: 'filled' is
            // indexed by it below.
            size_t run = std::min<size_t>(mb.Memory.Size, size - off);

            // A non-zero Size does not mean the bytes are real: for mapped
            // memory with no value at this position the aggressive policies
            // return zeros. Only ThreadLocal is honest about that, so an
            // all-zero run counts as known only if ThreadLocal confirms it;
            // otherwise it is a placeholder, which the core may fill from the
            // module image. Runs with any non-zero byte skip the extra query.
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
        // zero-fills that memory. Only a rebuild made at this very position.
        const TtdPosition here = m_exec->GetPosition();
        for ( const Rebuilt &r : m_rebuilt )
        {
            if ( !(r.pos == here) )
                continue;
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
        const TtdPosition here = m_exec->GetPosition();
        if ( replace )
            m_rebuilt.erase(std::remove_if(m_rebuilt.begin(), m_rebuilt.end(),
                                           [lo, hi, &here](const Rebuilt &r)
                                           { return r.pos == here && r.lo < hi && lo < r.hi; }),
                            m_rebuilt.end());
        size_t recovered = 0;
        if ( rebuild(lo, hi) )
        {
            for ( const Rebuilt &r : m_rebuilt )
            {
                if ( !(r.pos == here) || r.lo >= hi || lo >= r.hi )
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
    // keeping the latest written value of each byte (what WinDbg shows there).
    bool MsTtdCursor::rebuild(ea_t lo, ea_t hi)
    {
        // A hard cap on the window: callers derive 'hi' from segment bounds,
        // and a bad bound would otherwise ask for terabytes.
        static const uint64_t kMaxBytes = 1u << 20;
        if ( (uint64_t)(hi - lo) > kMaxBytes )
            hi = lo + (ea_t)kMaxBytes;

        const TtdPosition target = m_exec->GetPosition();
        for ( const Rebuilt &r : m_rebuilt )
            if ( r.pos == target && r.lo <= lo && hi <= r.hi )
                return true;

        UniqueCursor cur = m_owner->new_engine_cursor();
        if ( !cur )
            return false;

        Rebuilt reg;
        reg.lo  = lo;
        reg.hi  = hi;
        reg.pos = target;
        reg.data.assign((size_t)(hi - lo), 0);
        reg.known.assign((size_t)(hi - lo), false);

        size_t hits = 0;
        // On each recorded write touching [lo, hi), copy the just-written bytes
        // (read thread-locally from the writing thread, which has them). The
        // replay is sequential, so the last write before 'target' wins.
        // Returning false keeps the replay going.
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
                size_t got = std::min<size_t>(mb.Memory.Size, chunk);
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

        cur->ReplayForward(target);
        cur->SetMemoryWatchpointCallback(nullptr, 0);

        size_t nknown = 0;
        for ( bool b : reg.known )
            if ( b )
                nknown++;
        msttd_log("[ida-ttd] reconstructed 0x%llX-0x%llX: %u/%u byte(s) from %u write(s).\n",
            (uint64_t)lo, (uint64_t)hi, (unsigned)nknown, (unsigned)reg.data.size(), (unsigned)hits);
        if ( nknown == 0 )
            return false;
        // Up to a megabyte of data plus its bitmap each, so only the most
        // recent few are kept.
        static const size_t kMaxRebuilt = 8;
        if ( m_rebuilt.size() >= kMaxRebuilt )
            m_rebuilt.erase(m_rebuilt.begin(), m_rebuilt.begin() + (m_rebuilt.size() - kMaxRebuilt + 1));
        m_rebuilt.push_back(std::move(reg));
        return true;
    }
}
