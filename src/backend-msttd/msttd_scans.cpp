// The Microsoft backend's replay scans: self-modifying code, strings and
// buffers, which Sogen gets from hooks on its emulator and this backend from
// the engine's memory watchpoints.
//
// One write watchpoint can cover the whole address space, and at its callback
// memory already holds the written value. So:
//
//   1. A replay with that watchpoint finds every range the program wrote.
//   2. A second replay watches the writes again plus the execution of only
//      those ranges, so never-written code costs nothing. Each write feeds
//      all three scanners; each execution is matched against earlier writes.
//
// System writes (a syscall filling a buffer, the loader mapping an image)
// arrive as other access types and are left out, as Sogen leaves them out.
// All three answers come from the same two replays and are kept, so the
// second one asked for is free.
//
// The scanners (common/write_scans.h) implement docs/scan-rules.md and are
// shared with the Sogen backend, so lists read the same from either kind of
// recording. Every callback is noexcept and guards its growth.

#include "backend-msttd/msttd_backend.h"
#include "backend-msttd/msttd_sweep.h"
#include "backend-msttd/msttd_host.h"
#include "common/write_scans.h"
#include <chrono>

using namespace TTD;
using namespace TTD::Replay;

namespace idattd
{
    namespace
    {
        // ---- limits -------------------------------------------------------
        const size_t   kMaxStrings       = 500000;
        const size_t   kMaxSelfMod       = 100000;
        const size_t   kMaxWriteNodes    = 4000000;        // the last-write map
        const size_t   kMaxExecRanges    = 4096;           // execute watchpoints
        const uint32_t kStringMinimum    = 4;              // kept; callers ask for more
        const uint64_t kStringWindowMax  = 64 * 1024;

        using scans::kStringContext;

        // Sogen measures "the same burst of writing" as 250,000 instructions;
        // the engine's callbacks count writes, about a fifth as many.
        const uint64_t kNearbyWrites = 50000;

        using StringScan = scans::StringScan<TtdPosition>;
        using BufferScan = scans::BufferScan<TtdPosition>;

        // ---- the last write to every byte ---------------------------------
        //
        // [start, end) -> the write that last stored it, as non-overlapping
        // spans: a write splits whatever it lands on.
        class LastWrites
        {
        public:
            struct Write
            {
                uint64_t    end;
                TtdPosition pos;
                uint64_t    ip;
            };
            bool truncated = false;

            void assign(uint64_t lo, uint64_t hi, const TtdPosition &pos, uint64_t ip)
            {
                if ( lo >= hi )
                    return;
                auto it = m_map.lower_bound(lo);
                if ( it != m_map.begin() )
                {
                    auto prev = std::prev(it);
                    if ( prev->second.end > lo )
                    {
                        Write tail = prev->second;
                        prev->second.end = lo;
                        if ( tail.end > hi )
                            m_map.emplace(hi, tail);
                    }
                }
                while ( it != m_map.end() && it->first < hi )
                {
                    if ( it->second.end > hi )
                    {
                        Write tail = it->second;
                        it = m_map.erase(it);
                        m_map.emplace(hi, tail);
                        break;
                    }
                    it = m_map.erase(it);
                }
                if ( m_map.size() >= kMaxWriteNodes )
                {
                    truncated = true;
                    return;
                }
                m_map.emplace(lo, Write{ hi, pos, ip });
            }

            // The latest write to any byte of [lo, hi); nullptr when none.
            const Write *latest(uint64_t lo, uint64_t hi) const
            {
                const Write *best = nullptr;
                auto it = m_map.upper_bound(lo);
                if ( it != m_map.begin() )
                    --it;
                for ( ; it != m_map.end() && it->first < hi; ++it )
                    if ( it->second.end > lo && (best == nullptr || best->pos < it->second.pos) )
                        best = &it->second;
                return best;
            }

        private:
            std::map<uint64_t, Write> m_map;
        };

        // The ranges a replay saw written, merged.
        using Ranges = std::map<uint64_t, uint64_t>;   // start -> end

        void add_range(Ranges &r, uint64_t lo, uint64_t hi, uint64_t gap)
        {
            auto it = r.upper_bound(lo);
            if ( it != r.begin() )
            {
                auto prev = std::prev(it);
                if ( prev->second + gap >= lo )
                {
                    lo = prev->first;
                    hi = std::max(hi, prev->second);
                    it = r.erase(prev);
                }
            }
            while ( it != r.end() && it->first <= hi + gap )
            {
                hi = std::max(hi, it->second);
                it = r.erase(it);
            }
            r.emplace(lo, hi);
        }

        // Merge until there are few enough to watch, never across a module's
        // edge: a range that reached into code nobody wrote would call back on
        // every instruction run there.
        std::vector<std::pair<uint64_t, uint64_t>> watch_ranges(const Ranges &written,
                                                                 const std::vector<ModuleInfo> &mods,
                                                                 bool *capped)
        {
            auto module_of = [&mods](uint64_t a) -> size_t
            {
                for ( size_t i = 0; i < mods.size(); i++ )
                    if ( mods[i].base <= a && a < mods[i].base + mods[i].size )
                        return i;
                return (size_t)-1;
            };
            std::vector<std::pair<uint64_t, uint64_t>> v(written.begin(), written.end());
            for ( uint64_t gap = 0x1000; v.size() > kMaxExecRanges && gap <= 0x100000; gap *= 4 )
            {
                std::vector<std::pair<uint64_t, uint64_t>> m;
                for ( const auto &r : v )
                {
                    if ( !m.empty() && r.first - m.back().second <= gap
                      && module_of(m.back().second - 1) == module_of(r.first) )
                        m.back().second = std::max(m.back().second, r.second);
                    else
                        m.push_back(r);
                }
                v.swap(m);
            }
            *capped = v.size() > kMaxExecRanges;
            if ( *capped )
                v.resize(kMaxExecRanges);
            return v;
        }
    }

    // What the two replays found, kept for the backend's lifetime.
    struct MsTtdScanResults
    {
        StringScan               strings{ kStringMinimum, kMaxStrings };
        std::vector<BufferHit>   buffers;
        std::vector<SelfModHit>  selfmod;
        bool                     truncated = false;
    };

    MsTtdBackend::ScanResultsPtr::~ScanResultsPtr() { delete p; }

    void MsTtdBackend::ScanResultsPtr::reset()
    {
        delete p;
        p = nullptr;
    }

    bool MsTtdBackend::run_scans(ProgressSink *progress, QueryResult *qr)
    {
        if ( m_scans.p != nullptr )
            return true;
        const uint64_t space = user_space_end();

        // ---- 1: where the program writes ------------------------------------
        Ranges written;
        bool   capped = false;
        // ITTD_MSTTD_SCAN_STATS=1: how large the engine's write events get,
        // on stderr. Pass 2 takes at most 4096 bytes of a write; this says
        // whether a recording ever has a larger one. Callbacks run one at a
        // time (msttd_sweep replays segments sequentially).
        const bool stats = getenv("ITTD_MSTTD_SCAN_STATS") != nullptr;
        uint64_t writes = 0, over_4k = 0, largest = 0;
        {
            UniqueCursor cur = new_engine_cursor();
            if ( !cur )
                return false;
            auto on_write = [&](ICursorView::MemoryWatchpointResult const &w, IThreadView const *) noexcept -> bool
            {
                if ( w.AccessType != DataAccessType::Write )
                    return false;
                if ( stats )
                {
                    writes++;
                    if ( w.Size > 4096 )
                        over_4k++;
                    if ( w.Size > largest )
                        largest = w.Size;
                }
                try
                {
                    add_range(written, (uint64_t)w.Address, (uint64_t)w.Address + w.Size, 16);
                }
                catch ( ... )
                {
                    capped = true;
                }
                return false;
            };
            MemoryWatchpointData wp{};
            wp.Address    = GuestAddress{ 0 };
            wp.Size       = space;
            wp.AccessMask = DataAccessMask::Write;
            cur->AddMemoryWatchpoint(wp);
            cur->SetMemoryWatchpointCallback(on_write);
            cur->SetEventMask(EventMask::MemoryWatchpoint);
            cur->SetReplayFlags(ReplayFlags::ReplaySegmentsSequentially);
            ScaledProgress stage(progress, 0, 30);
            const auto t_pass = std::chrono::steady_clock::now();
            bool complete = msttd_sweep(cur.get(), TtdPosition::Min, TtdPosition::Max, &stage);
            if ( stats )
                fprintf(stderr, "[msttd scans] %s: %.1f s\n", "pass 1",
                        std::chrono::duration<double>(std::chrono::steady_clock::now() - t_pass).count());
            cur->SetMemoryWatchpointCallback(nullptr, 0);
            if ( stats )
                fprintf(stderr, "[msttd scans] %llu write event(s), %llu over 4096 bytes, largest %llu\n",
                        (unsigned long long)writes, (unsigned long long)over_4k, (unsigned long long)largest);
            if ( !complete )
            {
                qr->cancelled = true;
                return false;
            }
        }
        const std::vector<ModuleInfo> mods = modules();
        bool exec_capped = false;
        const std::vector<std::pair<uint64_t, uint64_t>> exec = watch_ranges(written, mods, &exec_capped);

        // ---- 2: the writes again, and what ran of them ------------------------
        std::unique_ptr<MsTtdScanResults> res(new MsTtdScanResults);
        BufferScan  buffers(kNearbyWrites);
        LastWrites  last;
        std::map<uint64_t, SelfModHit> selfmod;
        bool        truncated = capped || exec_capped;

        // Strings are scanned one burst of writing at a time, per thread: the
        // bytes a thread writes forwards through memory, plus what was just
        // before them. A copy is kept as written, so a later overwrite does not
        // change what is scanned.
        struct Window
        {
            uint64_t             base = 0;      // bytes[0] is here
            uint64_t             lo = 0, hi = 0; // what was written
            std::vector<uint8_t> bytes;
            TtdPosition          pos;
            bool                 live = false;
        };
        std::map<uint32_t, Window> windows;
        auto read = [](IThreadView const *t, uint64_t a, size_t n, uint8_t *out) -> bool
        {
            MemoryBuffer mb = t->QueryMemoryBuffer(GuestAddress{ a }, BufferView{ out, n });
            return mb.Memory.Size == n;
        };
        auto flush = [&](Window &w, IThreadView const *t)
        {
            if ( !w.live )
                return;
            w.live = false;
            // The terminator after the last byte, as memory has it now.
            uint8_t tail[2] = { 0xFF, 0xFF };
            if ( t != nullptr )
                read(t, w.hi, 2, tail);
            w.bytes.push_back(tail[0]);
            w.bytes.push_back(tail[1]);
            res->strings.inspect(w.base, w.bytes, w.pos);
        };

        uint64_t clock = 0;
        // A write too long for the callback's stack buffer is read into
        // this, which keeps its capacity from one such write to the next.
        std::vector<uint8_t> large_write;
        UniqueCursor cur = new_engine_cursor();
        if ( !cur )
            return false;
        auto on_hit = [&](ICursorView::MemoryWatchpointResult const &w, IThreadView const *t) noexcept -> bool
        {
            try
            {
                const uint64_t a = (uint64_t)w.Address;
                if ( w.AccessType == DataAccessType::Execute )
                {
                    const size_t n = w.Size != 0 ? (size_t)w.Size : 1;
                    buffers.executed(a, n);
                    auto hit = selfmod.find(a);
                    if ( hit != selfmod.end() )
                    {
                        hit->second.executions++;
                        return false;
                    }
                    // The write that made it is the one that wrote its first
                    // byte, the opcode, as Sogen has it; then any of its others.
                    const LastWrites::Write *lw = last.latest(a, a + 1);
                    if ( lw == nullptr )
                        lw = last.latest(a, a + n);
                    if ( lw == nullptr )
                        return false;
                    if ( selfmod.size() >= kMaxSelfMod )
                    {
                        truncated = true;
                        return false;
                    }
                    SelfModHit h;
                    h.address     = (ea_t)a;
                    h.size        = n;
                    h.write_pos   = to_core(lw->pos);
                    h.write_ip    = (ea_t)lw->ip;
                    h.execute_pos = to_core(t->GetPosition());
                    h.executions  = 1;
                    selfmod.emplace(a, h);
                    return false;
                }
                if ( w.AccessType != DataAccessType::Write || w.Size == 0 )
                    return false;
                const size_t n = (size_t)std::min<uint64_t>(w.Size, 4096);
                uint8_t stack[64];
                uint8_t *bytes = stack;
                if ( n > sizeof(stack) )
                {
                    if ( large_write.size() < n )
                        large_write.resize(n);
                    bytes = large_write.data();
                }
                if ( !read(t, a, n, bytes) )
                    return false;
                const TtdPosition pos = t->GetPosition();
                const uint64_t    ip  = (uint64_t)t->GetProgramCounter();
                ++clock;
                last.assign(a, a + n, pos, ip);
                buffers.ingest(a, bytes, n, clock, pos, ip);

                Window &win = windows[(uint32_t)t->GetThreadInfo().UniqueId];
                if ( win.live && a >= win.hi && a <= win.hi + 16 && a + n - win.lo <= kStringWindowMax )
                {
                    // Onwards from the last write: the gap, then these bytes.
                    size_t gap = size_t(a - win.hi);
                    size_t at  = win.bytes.size();
                    win.bytes.resize(at + gap + n);
                    if ( gap != 0 && !read(t, win.hi, gap, win.bytes.data() + at) )
                        memset(win.bytes.data() + at, 0xFF, gap);
                    memcpy(win.bytes.data() + at + gap, bytes, n);
                    win.hi  = a + n;
                    win.pos = pos;
                    return false;
                }
                flush(win, t);
                // What was there just before, which a string written in
                // pieces may have begun with.
                const uint64_t before = std::min<uint64_t>(a, kStringContext);
                win.base = a - before;
                win.lo   = a;
                win.hi   = a + n;
                win.pos  = pos;
                win.bytes.assign(size_t(before), 0xFF);
                if ( before != 0 && !read(t, win.base, size_t(before), win.bytes.data()) )
                {
                    // Partly unreadable: take the part next to the write.
                    for ( uint64_t k = 0; k < before; k += 16 )
                    {
                        uint64_t chunk = std::min<uint64_t>(16, before - k);
                        read(t, a - before + k, size_t(chunk), win.bytes.data() + k);
                    }
                }
                win.bytes.insert(win.bytes.end(), bytes, bytes + n);
                win.live = true;
            }
            catch ( ... )
            {
                truncated = true;
            }
            return false;
        };

        MemoryWatchpointData wp{};
        wp.Address    = GuestAddress{ 0 };
        wp.Size       = space;
        wp.AccessMask = DataAccessMask::Write;
        cur->AddMemoryWatchpoint(wp);
        for ( const auto &[lo, hi] : exec )
        {
            MemoryWatchpointData x{};
            x.Address    = GuestAddress{ lo };
            x.Size       = hi - lo;
            x.AccessMask = DataAccessMask::Execute;
            cur->AddMemoryWatchpoint(x);
        }
        cur->SetMemoryWatchpointCallback(on_hit);
        cur->SetEventMask(EventMask::MemoryWatchpoint);
        cur->SetReplayFlags(ReplayFlags::ReplaySegmentsSequentially);
        ScaledProgress stage(progress, 30, 60);
        const auto t_pass = std::chrono::steady_clock::now();
        bool complete = msttd_sweep(cur.get(), TtdPosition::Min, TtdPosition::Max, &stage);
        if ( stats )
            fprintf(stderr, "[msttd scans] %s: %.1f s\n", "pass 2",
                    std::chrono::duration<double>(std::chrono::steady_clock::now() - t_pass).count());
        cur->SetMemoryWatchpointCallback(nullptr, 0);
        if ( !complete )
        {
            qr->cancelled = true;
            return false;
        }

        // The bursts still open at the end, read where the recording ends.
        cur->SetPosition(TtdPosition::Max);
        for ( auto &[tid, win] : windows )
        {
            if ( !win.live )
                continue;
            win.live = false;
            uint8_t tail[2] = { 0xFF, 0xFF };
            cur->QueryMemoryBuffer(GuestAddress{ win.hi }, BufferView{ tail, 2 }, QueryMemoryPolicy::GloballyAggressive);
            win.bytes.push_back(tail[0]);
            win.bytes.push_back(tail[1]);
            res->strings.inspect(win.base, win.bytes, win.pos);
        }

        // ---- 3: the text the modules brought with them ----------------------
        //
        // What was in memory from the start (Sogen scans its initial memory):
        // each image, at its load position.
        {
            ScaledProgress stage3(progress, 90, 10);
            std::vector<uint8_t> bytes;      // one buffer for every chunk
            for ( size_t i = 0; i < mods.size(); i++ )
            {
                if ( progress != nullptr && progress->cancelled() )
                {
                    qr->cancelled = true;
                    return false;
                }
                stage3.report(uint32_t(i * 100 / std::max<size_t>(mods.size(), 1)));
                const ModuleInfo &m = mods[i];
                cur->SetPosition(from_core(m.loaded));
                const TtdPosition at = cur->GetPosition();
                const uint64_t chunk = 0x10000;
                for ( uint64_t off = 0; off < m.size; off += chunk )
                {
                    const uint64_t b = off > kStringContext ? off - kStringContext : 0;
                    const uint64_t e = std::min<uint64_t>(m.size, off + chunk + kStringContext);
                    bytes.assign(size_t(e - b), 0);
                    MemoryBuffer mb = cur->QueryMemoryBuffer(GuestAddress{ m.base + b },
                                                             BufferView{ bytes.data(), bytes.size() },
                                                             QueryMemoryPolicy::GloballyAggressive);
                    if ( mb.Memory.Size == 0 )
                        continue;
                    bytes.resize(size_t(mb.Memory.Size));
                    res->strings.inspect(m.base + b, bytes, at);
                }
            }
        }

        buffers.finish();
        res->buffers.reserve(buffers.results.size());
        for ( const scans::FoundBuffer<TtdPosition> &f : buffers.results )
        {
            BufferHit h;
            h.address   = (ea_t)f.address;
            h.size      = f.size;
            h.first_pos = to_core(f.first);
            h.last_pos  = to_core(f.last);
            h.writer_ip = (ea_t)f.writer_ip;
            h.writes    = f.writes;
            h.kind      = f.kind.c_str();
            h.preview   = f.preview.c_str();
            res->buffers.push_back(std::move(h));
        }
        res->selfmod.reserve(selfmod.size());
        for ( auto &[a, h] : selfmod )
            res->selfmod.push_back(h);
        res->truncated = truncated || buffers.truncated || last.truncated || res->strings.truncated;
        msttd_log("[ida-ttd] write scan: %d range(s) written, %d watched for execution%s; %d self-modifying "
                  "instruction(s), %d buffer(s).\n", (int)written.size(), (int)exec.size(),
                  exec_capped ? " (capped)" : "", (int)res->selfmod.size(), (int)res->buffers.size());
        m_scans.p = res.release();
        return true;
    }

    QueryResult MsTtdBackend::query_self_modifying(std::vector<SelfModHit> *out, ProgressSink *progress)
    {
        QueryResult r;
        if ( !m_engine || out == nullptr )
            return r;
        r.ran = true;
        if ( !run_scans(progress, &r) )
            return r;
        out->insert(out->end(), m_scans.p->selfmod.begin(), m_scans.p->selfmod.end());
        r.truncated = m_scans.p->truncated;
        return r;
    }

    QueryResult MsTtdBackend::query_strings(const ReplaySettings &, uint32_t min_length,
                                            std::vector<StringHit> *out, ProgressSink *progress)
    {
        QueryResult r;
        if ( !m_engine || out == nullptr )
            return r;
        r.ran = true;
        if ( !run_scans(progress, &r) )
            return r;
        const uint32_t want = std::max(min_length, kStringMinimum);
        m_scans.p->strings.for_each([&](uint64_t address, const StringScan::Entry &e)
        {
            if ( e.value.size() < want )
                return;
            StringHit h;
            h.address = (ea_t)address;
            h.pos     = to_core(e.pos);
            h.wide    = e.wide;
            h.length  = (uint32_t)e.value.size();
            h.text    = e.value.c_str();
            out->push_back(std::move(h));
        });
        r.truncated = m_scans.p->truncated;
        return r;
    }

    QueryResult MsTtdBackend::query_buffers(const ReplaySettings &, std::vector<BufferHit> *out,
                                            ProgressSink *progress)
    {
        QueryResult r;
        if ( !m_engine || out == nullptr )
            return r;
        r.ran = true;
        if ( !run_scans(progress, &r) )
            return r;
        out->insert(out->end(), m_scans.p->buffers.begin(), m_scans.p->buffers.end());
        r.truncated = m_scans.p->truncated;
        return r;
    }

    //=======================================================================
    // The memory heatmap
    //=======================================================================
    // One replay with a read/write/execute watchpoint over the whole address
    // space, each access counted against its page and time slice. Time is
    // sliced by sequence number, the engine's clock, which advances with
    // every thread switch.
    //
    // A window (the heatmap zoomed in) replays only its own stretch, so
    // zooming in is cheaper than the first count.

    // The window's ends on the engine's clock, the open ends taken as the
    // recording's.
    static void heat_window(TTD::Replay::IReplayEngineView *engine, PositionRange when,
                            TtdPosition *first, TtdPosition *last)
    {
        *first = when.first == Position::begin() ? engine->GetFirstPosition() : from_core(when.first);
        *last  = when.last  == Position::end()   ? engine->GetLastPosition()  : from_core(when.last);
        if ( *first < engine->GetFirstPosition() )
            *first = engine->GetFirstPosition();
        if ( engine->GetLastPosition() < *last )
            *last = engine->GetLastPosition();
    }

    QueryResult MsTtdBackend::query_access_heat(uint32_t page_shift, uint32_t slices,
                                                std::vector<HeatCell> *out, ProgressSink *progress)
    {
        return query_access_heat_window(page_shift, slices, PositionRange{}, out, progress);
    }

    QueryResult MsTtdBackend::query_access_heat_window(uint32_t page_shift, uint32_t slices,
                                                       PositionRange when, std::vector<HeatCell> *out,
                                                       ProgressSink *progress)
    {
        QueryResult r;
        if ( !m_engine || out == nullptr || slices == 0 || slices > 4096 || page_shift < 8 || page_shift > 30 )
            return r;
        TtdPosition first, last;
        heat_window(m_engine.get(), when, &first, &last);
        if ( last < first )
            return r;
        UniqueCursor cur = new_engine_cursor();
        if ( !cur )
            return r;
        r.ran = true;
        const uint64_t s0   = (uint64_t)first.Sequence;
        const uint64_t s1   = (uint64_t)last.Sequence;
        const uint64_t span = std::max<uint64_t>(s1 - s0 + 1, 1);
        const uint64_t space = user_space_end();

        std::unordered_map<uint64_t, HeatCell> cells;
        bool capped = false;
        auto on_hit = [&](ICursorView::MemoryWatchpointResult const &w, IThreadView const *t) noexcept -> bool
        {
            const DataAccessType k = w.AccessType;
            if ( k != DataAccessType::Read && k != DataAccessType::Write && k != DataAccessType::Execute )
                return false;
            const uint64_t seq   = (uint64_t)t->GetPosition().Sequence;
            if ( seq < s0 || seq > s1 )
                return false;           // the sweep's edges, outside the window
            uint64_t       slice = (seq - s0) * slices / span;
            if ( slice >= slices )
                slice = slices - 1;
            const uint64_t page = (uint64_t)w.Address >> page_shift;
            try
            {
                HeatCell &c = cells[(page << 12) | slice];
                c.page  = page;
                c.slice = (uint32_t)slice;
                if ( k == DataAccessType::Read )
                    c.reads++;
                else if ( k == DataAccessType::Write )
                    c.writes++;
                else
                    c.executes++;
            }
            catch ( ... )
            {
                capped = true;
            }
            return false;
        };
        MemoryWatchpointData wp{};
        wp.Address    = GuestAddress{ 0 };
        wp.Size       = space;
        wp.AccessMask = (DataAccessMask)((uint8_t)DataAccessMask::Read | (uint8_t)DataAccessMask::Write
                                       | (uint8_t)DataAccessMask::Execute);
        cur->AddMemoryWatchpoint(wp);
        cur->SetMemoryWatchpointCallback(on_hit);
        cur->SetEventMask(EventMask::MemoryWatchpoint);
        cur->SetReplayFlags(ReplayFlags::ReplaySegmentsSequentially);
        const bool whole    = when.whole_trace();
        const bool complete = msttd_sweep(cur.get(), whole ? TtdPosition::Min : first,
                                          whole ? TtdPosition::Max : last, progress);
        cur->SetMemoryWatchpointCallback(nullptr, 0);
        r.cancelled = !complete;
        r.truncated = capped;
        const size_t before = out->size();
        out->reserve(before + cells.size());
        for ( const auto &[key, c] : cells )
            out->push_back(c);
        std::sort(out->begin() + (ptrdiff_t)before, out->end(), [](const HeatCell &a, const HeatCell &b)
        {
            return a.page != b.page ? a.page < b.page : a.slice < b.slice;
        });
        return r;
    }

    Position MsTtdBackend::heat_slice_position(uint32_t slices, uint32_t slice)
    {
        return heat_window_slice_position(slices, slice, PositionRange{});
    }

    Position MsTtdBackend::heat_window_slice_position(uint32_t slices, uint32_t slice, PositionRange when)
    {
        if ( !m_engine || slices == 0 )
            return Position::none();
        TtdPosition first, last;
        heat_window(m_engine.get(), when, &first, &last);
        const uint64_t s0   = (uint64_t)first.Sequence;
        const uint64_t span = std::max<uint64_t>((uint64_t)last.Sequence - s0 + 1, 1);
        TtdPosition p;
        p.Sequence = (SequenceId)(s0 + std::min<uint64_t>(slice, slices) * span / slices);
        p.Steps    = StepCount::Zero;
        if ( !(first < p) )
            p = first;
        return to_core(p);
    }
}
