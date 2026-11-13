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
                // The same span written again (a stack slot, a loop's
                // variable), which is most writes: updated in place rather
                // than erased and allocated again. The spans do not overlap,
                // so nothing before it reaches past 'lo'.
                if ( it != m_map.end() && it->first == lo && it->second.end == hi )
                {
                    it->second.pos = pos;
                    it->second.ip  = ip;
                    return;
                }
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

    namespace
    {
        // ---- 1: where the program writes ------------------------------------
        // False when stopped.
        bool scan_written(ICursorView *cur, uint64_t space, ProgressSink *progress, Ranges *written, bool *capped)
        {
            auto on_write = [&](ICursorView::MemoryWatchpointResult const &w, IThreadView const *) noexcept -> bool
            {
                if ( w.AccessType != DataAccessType::Write )
                    return false;
                try
                {
                    add_range(*written, (uint64_t)w.Address, (uint64_t)w.Address + w.Size, 16);
                }
                catch ( ... )
                {
                    *capped = true;
                }
                return false;
            };
            MemoryWatchpointData wp{};
            wp.Address    = GuestAddress{ 0 };
            wp.Size       = space;
            wp.AccessMask = DataAccessMask::Write;
            ArmedSweep arm(cur, ReplayFlags::ReplaySegmentsSequentially, EventMask::MemoryWatchpoint);
            arm.watch(wp);
            arm.on_watchpoint(on_write);
            return arm.sweep(TtdPosition::Min, TtdPosition::Max, progress);
        }

        // ---- 2: the writes again, and what ran of them ------------------------
        //
        // Each write feeds the buffer scan, the string windows and, when it
        // lands in code watched for execution, the last-write map; each
        // execution is matched against that map. The callback is all of it,
        // on the replay thread.
        class WriteReplay
        {
        public:
            WriteReplay(const std::vector<std::pair<uint64_t, uint64_t>> &exec, StringScan &strings)
                : m_exec(exec), m_strings(strings), m_buffers(kNearbyWrites) {}

            bool on_hit(ICursorView::MemoryWatchpointResult const &w, IThreadView const *t) noexcept
            {
                try
                {
                    if ( w.AccessType == DataAccessType::Execute )
                        executed(w, t);
                    else if ( w.AccessType == DataAccessType::Write && w.Size != 0 )
                        wrote(w, t);
                }
                catch ( ... )
                {
                    truncated = true;
                }
                return false;
            }

            // The bursts still open at the end, read where the recording
            // ends ('cur' is positioned there).
            void finish_windows(ICursorView *cur)
            {
                for ( auto &[tid, win] : m_windows )
                {
                    if ( !win.live )
                        continue;
                    win.live = false;
                    uint8_t tail[2] = { 0xFF, 0xFF };
                    cur->QueryMemoryBuffer(GuestAddress{ win.hi }, BufferView{ tail, 2 },
                                           QueryMemoryPolicy::GloballyAggressive);
                    win.bytes.push_back(tail[0]);
                    win.bytes.push_back(tail[1]);
                    m_strings.inspect(win.base, win.bytes, win.pos);
                }
            }

            BufferScan &buffers() { return m_buffers; }
            const std::map<uint64_t, SelfModHit> &selfmod() const { return m_selfmod; }
            bool last_truncated() const { return m_last.truncated; }

            bool truncated = false;

        private:
            // Strings are scanned one burst of writing at a time, per thread:
            // the bytes a thread writes forwards through memory, plus what
            // was just before them. A copy is kept as written, so a later
            // overwrite does not change what is scanned.
            struct Window
            {
                uint64_t             base = 0;          // bytes[0] is here
                uint64_t             lo = 0, hi = 0;    // what was written
                std::vector<uint8_t> bytes;
                TtdPosition          pos;
                bool                 live = false;
            };

            static bool read(IThreadView const *t, uint64_t a, size_t n, uint8_t *out)
            {
                MemoryBuffer mb = t->QueryMemoryBuffer(GuestAddress{ a }, BufferView{ out, n });
                return mb.Memory.Size == n;
            }

            void flush(Window &w, IThreadView const *t)
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
                m_strings.inspect(w.base, w.bytes, w.pos);
            }

            // Whether [lo, hi) touches code watched for execution. Only those
            // bytes are ever asked about (an execution is matched against
            // its own bytes), so only those writes go in the last-write map.
            // The ranges were made from these same writes, so while they are
            // not capped every write lands in one (measured: none left out
            // on either test recording); past the cap, the writes to what is
            // not watched stay out of the map instead of filling it. The
            // writes of one stretch of code mostly land in one range, which
            // is cached.
            bool watched_for_exec(uint64_t lo, uint64_t hi)
            {
                if ( m_lastExec != nullptr && m_lastExec->first < hi && lo < m_lastExec->second )
                    return true;
                auto it = std::upper_bound(m_exec.begin(), m_exec.end(), lo,
                                           [](uint64_t v, const std::pair<uint64_t, uint64_t> &r) { return v < r.first; });
                if ( it != m_exec.begin() && std::prev(it)->second > lo )
                {
                    m_lastExec = &*std::prev(it);
                    return true;
                }
                if ( it != m_exec.end() && it->first < hi )
                {
                    m_lastExec = &*it;
                    return true;
                }
                return false;
            }

            void executed(ICursorView::MemoryWatchpointResult const &w, IThreadView const *t)
            {
                const uint64_t a = (uint64_t)w.Address;
                const size_t n = w.Size != 0 ? (size_t)w.Size : 1;
                m_buffers.executed(a, n);
                auto hit = m_selfmod.find(a);
                if ( hit != m_selfmod.end() )
                {
                    hit->second.executions++;
                    return;
                }
                // The write that made it is the one that wrote its first
                // byte, the opcode, as Sogen has it; then any of its others.
                const LastWrites::Write *lw = m_last.latest(a, a + 1);
                if ( lw == nullptr )
                    lw = m_last.latest(a, a + n);
                if ( lw == nullptr )
                    return;
                if ( m_selfmod.size() >= kMaxSelfMod )
                {
                    truncated = true;
                    return;
                }
                SelfModHit h;
                h.address     = (ea_t)a;
                h.size        = n;
                h.write_pos   = to_core(lw->pos);
                h.write_ip    = (ea_t)lw->ip;
                h.execute_pos = to_core(t->GetPosition());
                h.executions  = 1;
                m_selfmod.emplace(a, h);
            }

            void wrote(ICursorView::MemoryWatchpointResult const &w, IThreadView const *t)
            {
                const uint64_t a = (uint64_t)w.Address;
                const size_t n = (size_t)std::min<uint64_t>(w.Size, 4096);
                uint8_t stack[64];
                uint8_t *bytes = stack;
                if ( n > sizeof(stack) )
                {
                    if ( m_largeWrite.size() < n )
                        m_largeWrite.resize(n);
                    bytes = m_largeWrite.data();
                }
                if ( !read(t, a, n, bytes) )
                    return;
                const TtdPosition pos = t->GetPosition();
                const uint64_t    ip  = (uint64_t)t->GetProgramCounter();
                ++m_clock;
                if ( watched_for_exec(a, a + n) )
                    m_last.assign(a, a + n, pos, ip);
                m_buffers.ingest(a, bytes, n, m_clock, pos, ip);

                // Threads write in bursts, so the window lookup is cached.
                const uint32_t utid = (uint32_t)t->GetThreadInfo().UniqueId;
                if ( m_lastWin == nullptr || utid != m_lastUtid )
                {
                    m_lastWin  = &m_windows[utid];
                    m_lastUtid = utid;
                }
                Window &win = *m_lastWin;
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
                    return;
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

            const std::vector<std::pair<uint64_t, uint64_t>> &m_exec;
            const std::pair<uint64_t, uint64_t> *m_lastExec = nullptr;
            StringScan                     &m_strings;
            BufferScan                      m_buffers;
            LastWrites                      m_last;
            std::map<uint64_t, SelfModHit>  m_selfmod;
            std::map<uint32_t, Window>      m_windows;
            Window                         *m_lastWin  = nullptr;   // std::map nodes stay put
            uint32_t                        m_lastUtid = 0;
            uint64_t                        m_clock    = 0;
            // A write too long for the callback's stack buffer is read into
            // this, which keeps its capacity from one such write to the next.
            std::vector<uint8_t>            m_largeWrite;
        };

        // ---- 3: the text the modules brought with them ----------------------
        //
        // What was in memory from the start (Sogen scans its initial memory):
        // each image, at its load position. False when cancelled.
        bool scan_module_strings(ICursorView *cur, const std::vector<ModuleInfo> &mods, StringScan &strings,
                                 ProgressSink *progress)
        {
            std::vector<uint8_t> bytes;      // one buffer for every chunk
            for ( size_t i = 0; i < mods.size(); i++ )
            {
                if ( progress != nullptr )
                {
                    if ( progress->cancelled() )
                        return false;
                    progress->report(uint32_t(i * 100 / std::max<size_t>(mods.size(), 1)));
                }
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
                    strings.inspect(m.base + b, bytes, at);
                }
            }
            return true;
        }
    }

    bool MsTtdBackend::run_scans(ProgressSink *progress, QueryResult *qr)
    {
        {
            std::lock_guard<std::mutex> lock(m_scansMtx);
            if ( m_scans.p != nullptr )
                return true;
        }
        // A second query asking while the first replays waits for its answer
        // (the strings and the buffers are often asked for together).
        auto ready = [this]
        {
            std::lock_guard<std::mutex> lock(m_scansMtx);
            return m_scans.p != nullptr;
        };
        switch ( m_scansRun.enter(progress, ready) )
        {
            case SharedRun::Turn::Ready:
                return true;
            case SharedRun::Turn::Cancelled:
                qr->cancelled = true;
                return false;
            case SharedRun::Turn::Run:
                break;
        }
        SharedRun::Runner runner(m_scansRun, progress);
        const uint64_t space = user_space_end();

        UniqueCursor cur = new_engine_cursor();
        if ( !cur )
            return false;
        Ranges written;
        bool   capped = false;
        {
            ScaledProgress stage(&runner, 0, 30);
            if ( !scan_written(cur.get(), space, &stage, &written, &capped) )
            {
                qr->cancelled = true;
                return false;
            }
        }
        const std::vector<ModuleInfo> mods = modules();
        bool exec_capped = false;
        const std::vector<std::pair<uint64_t, uint64_t>> exec = watch_ranges(written, mods, &exec_capped);

        std::unique_ptr<MsTtdScanResults> res(new MsTtdScanResults);
        WriteReplay pass(exec, res->strings);
        // A fresh cursor for the second replay, as for the first.
        cur = new_engine_cursor();
        if ( !cur )
            return false;
        {
            auto on_hit = [&pass](ICursorView::MemoryWatchpointResult const &w, IThreadView const *t) noexcept -> bool
            {
                return pass.on_hit(w, t);
            };
            ArmedSweep arm(cur.get(), ReplayFlags::ReplaySegmentsSequentially, EventMask::MemoryWatchpoint);
            MemoryWatchpointData wp{};
            wp.Address    = GuestAddress{ 0 };
            wp.Size       = space;
            wp.AccessMask = DataAccessMask::Write;
            arm.watch(wp);
            for ( const auto &[lo, hi] : exec )
            {
                MemoryWatchpointData x{};
                x.Address    = GuestAddress{ lo };
                x.Size       = hi - lo;
                x.AccessMask = DataAccessMask::Execute;
                arm.watch(x);
            }
            arm.on_watchpoint(on_hit);
            ScaledProgress stage(&runner, 30, 60);
            if ( !arm.sweep(TtdPosition::Min, TtdPosition::Max, &stage) )
            {
                qr->cancelled = true;
                return false;
            }
        }
        cur->SetPosition(TtdPosition::Max);
        pass.finish_windows(cur.get());

        {
            ScaledProgress stage(&runner, 90, 10);
            if ( !scan_module_strings(cur.get(), mods, res->strings, &stage) )
            {
                qr->cancelled = true;
                return false;
            }
        }

        BufferScan &buffers = pass.buffers();
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
        res->selfmod.reserve(pass.selfmod().size());
        for ( const auto &[a, h] : pass.selfmod() )
            res->selfmod.push_back(h);
        res->truncated = capped || exec_capped || pass.truncated || buffers.truncated || pass.last_truncated()
                      || res->strings.truncated;
        msttd_log("[ida-ttd] write scan: %d range(s) written, %d watched for execution%s; %d self-modifying "
                  "instruction(s), %d buffer(s).\n", (int)written.size(), (int)exec.size(),
                  exec_capped ? " (capped)" : "", (int)res->selfmod.size(), (int)res->buffers.size());
        std::lock_guard<std::mutex> lock(m_scansMtx);
        if ( m_scans.p == nullptr )
            m_scans.p = res.release();
        return true;
    }

    QueryResult MsTtdBackend::query_self_modifying(std::vector<SelfModHit> *out, ProgressSink *progress)
    {
        QueryResult r;
        if ( !m_engine || out == nullptr )
            return r;
        // Ran only once the scans exist: a failed run (no cursor, say) must
        // not read as a complete, empty answer that a caller would save. A
        // cancelled one did run, and says so (cancelled, not unsupported).
        if ( !run_scans(progress, &r) )
        {
            r.ran = r.cancelled;
            return r;
        }
        r.ran = true;
        const MsTtdScanResults *s = m_scans.p;
        out->insert(out->end(), s->selfmod.begin(), s->selfmod.end());
        r.truncated = s->truncated;
        return r;
    }

    QueryResult MsTtdBackend::query_strings(const ReplaySettings &, uint32_t min_length,
                                            std::vector<StringHit> *out, ProgressSink *progress)
    {
        QueryResult r;
        if ( !m_engine || out == nullptr )
            return r;
        // Ran only once the scans exist: a failed run (no cursor, say) must
        // not read as a complete, empty answer that a caller would save. A
        // cancelled one did run, and says so (cancelled, not unsupported).
        if ( !run_scans(progress, &r) )
        {
            r.ran = r.cancelled;
            return r;
        }
        r.ran = true;
        const uint32_t want = std::max(min_length, kStringMinimum);
        const MsTtdScanResults *s = m_scans.p;
        s->strings.for_each([&](uint64_t address, const StringScan::Entry &e)
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
        r.truncated = s->truncated;
        return r;
    }

    QueryResult MsTtdBackend::query_buffers(const ReplaySettings &, std::vector<BufferHit> *out,
                                            ProgressSink *progress)
    {
        QueryResult r;
        if ( !m_engine || out == nullptr )
            return r;
        // Ran only once the scans exist: a failed run (no cursor, say) must
        // not read as a complete, empty answer that a caller would save. A
        // cancelled one did run, and says so (cancelled, not unsupported).
        if ( !run_scans(progress, &r) )
        {
            r.ran = r.cancelled;
            return r;
        }
        r.ran = true;
        const MsTtdScanResults *s = m_scans.p;
        out->insert(out->end(), s->buffers.begin(), s->buffers.end());
        r.truncated = s->truncated;
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
        const bool whole = when.whole_trace();
        bool complete;
        {
            ArmedSweep arm(cur.get(), ReplayFlags::ReplaySegmentsSequentially, EventMask::MemoryWatchpoint);
            arm.watch(wp);
            arm.on_watchpoint(on_hit);
            complete = arm.sweep(whole ? TtdPosition::Min : first, whole ? TtdPosition::Max : last, progress);
        }
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
