// SPDX-License-Identifier: GPL-2.0-only
//
// ida-ttd's Sogen backend: the string and buffer scans, by a replay or
// from the recorded writes, and read_memory_at, which shares their pass.
// See sogen_state.h.

#include "backend-sogen/sogen_state.h"

#include <common/write_scans.h>

#include <windows_emulator.hpp>
#include <ttd_session.hpp>
#include <ttd_string_scan.hpp>
#include <ttd_buffer_scan.hpp>

namespace idattd::sogen
{
    // ------------------------------------------------------------ replay scans

    // The position of text that appeared at 'step'. A step at or before the
    // recording's start means "there from the start"; for a fork's recording,
    // which starts at the fork position, before_step would give a position
    // before its first.
    ittd_position appeared_at(const ttd::trace &t, uint64_t step)
    {
        return step <= first_position(t) ? at(first_position(t)) : before_step(step);
    }

    // Replay the whole recording with a scanner attached. A divergence
    // (typically this machine's files differing from those a host recording
    // ran against) does not end the scan: the next checkpoint holds the
    // recording's own state, so the scan restores it and goes on. 'leaving'
    // runs before the restore and 'restored' after it. A scanner that cannot
    // watch a restore (the buffer scanner owns the emulator's only
    // mapping-change callback, which seek needs) is put away and a new one
    // attached; one that can is shown the restored memory. Returns what was
    // skipped, in words, or "" when nothing was. Strict replays still fail at
    // the first divergence.
    std::string replay_scan(::sogen::windows_emulator &emu, ttd::trace &t, const std::function<void()> &attach,
                            const std::function<void()> &leaving, const std::function<void()> &restored,
                            bool strict, const ittd_progress *progress)
    {
        try
        {
            ttd::replay_to_end(emu, t, attach, strict, true, control(progress));
            return std::string();
        }
        catch ( const ttd::divergence_error &e )
        {
            if ( strict )
                throw;
            std::string first = e.what();
            const uint64_t end = t.metadata().instruction_count;
            uint64_t skipped = 0;
            int gaps = 0;
            for ( ;; )
            {
                const uint64_t at = emu.get_executed_instructions();
                uint64_t next = end;
                for ( const auto &c : t.checkpoints() )
                    if ( c.step > at )
                    {
                        next = c.step;
                        break;
                    }
                skipped += next - at;
                gaps++;
                if ( next >= end )
                    break;
                leaving();
                ttd::seek(emu, t, next, strict, control(progress));
                restored();
                try
                {
                    ttd::run_to(emu, t, end, strict, control(progress));
                    break;
                }
                catch ( const ttd::divergence_error & )
                {
                }
            }
            // A fork's recording starts where it was forked, not at 0.
            const uint64_t total = end - std::min(end, t.start_position());
            char head[160];
            snprintf(head, sizeof(head), "the replay diverged from the recording %d time%s; %llu of %llu "
                     "instructions (%.1f%%) were skipped up to the next checkpoint. First: ",
                     gaps, gaps == 1 ? "" : "s", (unsigned long long)skipped, (unsigned long long)total,
                     total == 0 ? 0.0 : 100.0 * (double)skipped / (double)total);
            return head + first;
        }
    }

    // ------------------------------------------------------------ scans of the recorded writes
    //
    // A recording with write events and their bytes (the chunked formats, 7
    // on) already holds everything a string or buffer scan looks at: every
    // write, its step, the instruction that made it and what it stored. Read
    // from there, the scans run nothing (no registry, no emulation root, no
    // program re-run on this machine) and cannot diverge. The scanners
    // (common/write_scans.h) apply Sogen's rules, fed what its emulator hooks
    // would see:
    //
    //   - buffers: every guest write with its bytes, each execution and each
    //     mapping change, in recording order;
    //   - strings: after each instruction that wrote, the bytes around the
    //     write as memory then held them; and at the start, all committed
    //     memory.
    //
    // A recording without write data falls back to the replay.

    bool scans_from_recording(ttd::trace &t)
    {
        const uint64_t W = (uint64_t)ttd::access_kind::write;
        return t.has_access_data() && (t.access_mask() & W) == W;
    }

    // Guest memory as it stood after some step, for the string scan's reads.
    // A page is fetched from the recording when first read, then kept current
    // by every later write.
    class ShadowMemory
    {
    public:
        explicit ShadowMemory(ttd::trace &t) : m_t(t) {}

        // [addr, addr + n) as of 'position'. False when any of it is not
        // mapped (the emulator's read would fail); those bytes read as 0xFF.
        bool read(uint64_t addr, size_t n, uint8_t *out, uint64_t position)
        {
            bool all = true;
            while ( n != 0 )
            {
                const uint64_t page = addr / kPage;
                const size_t   off  = size_t(addr % kPage);
                const size_t   take = std::min<size_t>(n, kPage - off);
                const Page &p = fetch(page, position);
                memcpy(out, p.bytes.data() + off, take);
                if ( all && !p.all_mapped(off, take) )
                    all = false;
                out += take;
                addr += take;
                n -= take;
            }
            return all;
        }

        // As cursor_read_memory answers: [addr, addr + n) as of 'position',
        // known[i] 1 where the byte is mapped (out[i] its value), else 0
        // (out[i] 0).
        void read_known(uint64_t addr, size_t n, uint8_t *out, uint8_t *known, uint64_t position)
        {
            while ( n != 0 )
            {
                const uint64_t page = addr / kPage;
                const size_t   off  = size_t(addr % kPage);
                const size_t   take = std::min<size_t>(n, kPage - off);
                const Page &p = fetch(page, position);
                for ( size_t i = 0; i < take; i++ )
                {
                    const bool k = p.all_mapped(off + i, 1);
                    known[i] = k ? 1 : 0;
                    out[i]   = k ? p.bytes[off + i] : 0;
                }
                out += take;
                known += take;
                addr += take;
                n -= take;
            }
        }

        // A write, applied to the pages held; pages not held already have it
        // when fetched later.
        void apply(uint64_t addr, const uint8_t *b, size_t n)
        {
            while ( n != 0 )
            {
                const uint64_t page = addr / kPage;
                const size_t   off  = size_t(addr % kPage);
                const size_t   take = std::min<size_t>(n, kPage - off);
                auto it = m_pages.find(page);
                if ( it != m_pages.end() )
                {
                    memcpy(it->second.bytes.data() + off, b, take);
                    it->second.set_mapped(off, take);
                }
                b += take;
                addr += take;
                n -= take;
            }
        }

        // A mapping change: what the pages held is no longer there.
        void drop(uint64_t addr, uint64_t size)
        {
            if ( size == 0 )
                return;
            const uint64_t first = addr / kPage;
            const uint64_t last  = (addr + size - 1) / kPage;
            for ( auto it = m_pages.lower_bound(first); it != m_pages.end() && it->first <= last; )
                it = m_pages.erase(it);
        }

    private:
        // Every page read stays held for the rest of the pass (the scan of
        // the start reads all committed memory), so which bytes are mapped
        // is a bitmap: an eighth of the size of a flag per byte.
        struct Page
        {
            std::vector<uint8_t> bytes;
            uint64_t mapped[kPage / 64] = {};

            // The bits of word 'w' that [off, off + n) covers.
            static uint64_t word_mask(size_t w, size_t off, size_t n)
            {
                const size_t lo = std::max(off, w * 64) - w * 64;
                const size_t hi = std::min(off + n, w * 64 + 64) - w * 64;
                const uint64_t upto = hi == 64 ? ~0ull : (1ull << hi) - 1;
                return upto & ~((1ull << lo) - 1);
            }

            void set_mapped(size_t off, size_t n)
            {
                if ( n == 0 )
                    return;
                for ( size_t w = off / 64; w <= (off + n - 1) / 64; w++ )
                    mapped[w] |= word_mask(w, off, n);
            }

            bool all_mapped(size_t off, size_t n) const
            {
                if ( n == 0 )
                    return true;
                for ( size_t w = off / 64; w <= (off + n - 1) / 64; w++ )
                {
                    const uint64_t m = word_mask(w, off, n);
                    if ( (mapped[w] & m) != m )
                        return false;
                }
                return true;
            }
        };
        ttd::trace &m_t;
        std::map<uint64_t, Page> m_pages;

        const Page &fetch(uint64_t page, uint64_t position)
        {
            auto it = m_pages.find(page);
            if ( it != m_pages.end() )
                return it->second;
            Page p;
            p.bytes.assign(kPage, 0xFF);
            std::vector<std::optional<uint8_t>> got = m_t.memory_at(position, page * kPage, kPage);
            for ( size_t i = 0; i < got.size() && i < kPage; i++ )
            {
                if ( got[i] )
                {
                    p.bytes[i] = *got[i];
                    p.set_mapped(i, 1);
                }
            }
            return m_pages.emplace(page, std::move(p)).first->second;
        }
    };

    // ittd_backend_api::read_memory_at: many reads, each at its own position,
    // in one forward pass over the recording's writes instead of a cursor
    // seek and read per position. A cursor read at a position walks back from
    // it to the writes there, which for the stack pages a syscall decoder
    // reads is a fresh walk per syscall (about 6 ms each: 35 s for the 5,599
    // syscalls of a test recording). Here each page is read once, where it is
    // first needed, and kept up to date by applying the writes that follow,
    // as the string scan does (ShadowMemory).
    //
    // Exact only with checkpoint memory, where a position's bytes are the
    // latest write or host write before it, else the checkpoint's: a pass of
    // writes reproduces that. Without it memory_at also takes bytes from reads
    // and executions, which the pass would not see, so such a recording is
    // refused (ITTD_E_UNSUPPORTED) and the core reads per position as
    // before. MMIO pages, which no write describes, are read directly.
    int read_memory_at(ittd_backend *hb, const ittd_mem_read *reads, size_t count,
                       uint8_t *buf, uint8_t *known, const ittd_progress *progress)
    {
        backend_t *b = B(hb);
        if ( b == nullptr || (count != 0 && (reads == nullptr || buf == nullptr || known == nullptr)) )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            std::vector<std::pair<uint64_t, uint64_t>> mmio;
            {
                std::lock_guard<std::mutex> lock(b->mtx);
                if ( !b->trace->has_checkpoint_memory() )
                {
                    b->error.set("read_memory_at needs checkpoint memory; read per position instead");
                    return ITTD_E_UNSUPPORTED;
                }
                mmio = b->mmio;
            }
            if ( count == 0 )
                return ITTD_OK;

            // The pass's own readers: one for the events, one for memory_at,
            // so neither disturbs the other (as scan_recorded_writes).
            std::unique_ptr<ttd::trace> t = open_forward_trace(b->path);
            std::unique_ptr<ttd::trace> mem_trace = open_forward_trace(b->path);
            ShadowMemory shadow(*mem_trace);

            struct Item
            {
                uint64_t pos = 0;
                size_t   index = 0;
            };
            std::vector<Item> items;
            items.reserve(count);
            for ( size_t i = 0; i < count; i++ )
            {
                if ( reads[i].size == 0 )
                    continue;
                memset(known + reads[i].offset, 0, (size_t)reads[i].size);
                Item it;
                if ( !resolve(*t, reads[i].pos, &it.pos) )
                    continue;           // not a position: stays unknown
                it.index = i;
                items.push_back(it);
            }
            std::stable_sort(items.begin(), items.end(), [](const Item &x, const Item &y) { return x.pos < y.pos; });

            auto in_mmio = [&](uint64_t lo, uint64_t hi)
            {
                for ( const auto &[mlo, mhi] : mmio )
                    if ( lo < mhi && mlo < hi )
                        return true;
                return false;
            };
            size_t next = 0;
            // Every read at a position before 'limit' (all of them for
            // UINT64_MAX): the writes at or before it are applied by now.
            auto answer = [&](uint64_t limit)
            {
                for ( ; next < items.size() && items[next].pos < limit; next++ )
                {
                    const ittd_mem_read &r = reads[items[next].index];
                    uint8_t *out = buf + r.offset;
                    uint8_t *kn  = known + r.offset;
                    if ( in_mmio(r.addr, r.addr + r.size) )
                    {
                        std::vector<std::optional<uint8_t>> v = mem_trace->memory_at(items[next].pos, r.addr, r.size);
                        for ( size_t k = 0; k < (size_t)r.size; k++ )
                        {
                            const bool have = k < v.size() && v[k].has_value();
                            out[k] = have ? *v[k] : 0;
                            kn[k]  = have ? 1 : 0;
                        }
                        continue;
                    }
                    shadow.read_known(r.addr, (size_t)r.size, out, kn, items[next].pos);
                }
            };

            std::span<const ttd::mapping_change> maps =
                t->has_mapping_changes() ? t->mapping_changes() : std::span<const ttd::mapping_change>();
            size_t next_map = 0;
            const uint64_t kinds = (uint64_t)ttd::access_kind::write | (uint64_t)ttd::access_kind::host_write;
            const uint64_t total_events = std::max<uint64_t>(t->metadata().event_count, 1);
            const ttd::operation_control ctl = control(progress);
            ttd::event_reader reader(*t, 0);
            uint64_t seen = 0;
            while ( next < items.size() )
            {
                std::optional<ttd::access_event> ev = reader.next(kinds);
                if ( !ev )
                    break;
                const uint64_t number = reader.last_number();
                if ( (++seen & 0xFFFF) == 0 )
                {
                    ctl.check();
                    ctl.report(number, total_events);
                }
                // Mapping changes up to this event drop what the pages held.
                // The reads before each change are answered first: a page
                // fetched again for one of them would show the memory before
                // the change, and the reads after it would then be answered
                // from that. Never past this event's step, whose writes are
                // not applied yet.
                while ( next_map < maps.size() && maps[next_map].event_number <= number )
                {
                    const ttd::mapping_change &m = maps[next_map++];
                    answer(std::min(m.step, ev->step));
                    shadow.drop(m.address, m.size);
                }
                // The reads before this write's instruction see everything up
                // to and including their own (memory_at's "after the
                // instruction at the position").
                answer(ev->step);
                if ( ev->size == 0 )
                    continue;
                std::vector<std::byte> data = t->access_data(*ev);
                if ( data.size() != ev->size )
                    continue;
                shadow.apply(ev->address, reinterpret_cast<const uint8_t *>(data.data()), data.size());
            }
            while ( next_map < maps.size() )
            {
                const ttd::mapping_change &m = maps[next_map++];
                answer(m.step);
                shadow.drop(m.address, m.size);
            }
            answer(UINT64_MAX);
            return ITTD_OK;
        });
    }

    // A buffer the scanners found, as the ABI lists it.
    ittd_buffer_hit buffer_hit(uint64_t address, uint64_t size, uint64_t first_step, uint64_t last_step,
                               uint64_t writer_ip, uint64_t writes, const std::string &kind,
                               const std::string &preview)
    {
        ittd_buffer_hit h{};
        h.address   = address;
        h.size      = size;
        h.first_pos = before_step(first_step);
        h.last_pos  = before_step(last_step);
        h.writer_ip = writer_ip;
        h.writes    = writes;
        copy_str(h.kind, sizeof(h.kind), kind);
        copy_str(h.preview, sizeof(h.preview), preview);
        return h;
    }

    // A kept string as the ABI lists it.
    ittd_string_hit string_hit(const kept_string &s)
    {
        ittd_string_hit h{};
        h.address = s.address;
        h.pos     = s.pos;
        h.wide    = s.wide ? 1 : 0;
        h.length  = s.length;
        copy_str(h.text, sizeof(h.text), s.text);
        return h;
    }

    // The text a string's listing shows: what copy_str would put in its
    // ittd_string_hit, and no more.
    std::string listed_text(const std::string &value)
    {
        return value.substr(0, fitted_length(value, sizeof(ittd_string_hit::text)));
    }

    // One pass over the recording for both answers. 'string_minimum' is the
    // shortest string kept. Without 'strings_out' the string scanner does not
    // run: it is most of the pass's work (a read of memory around every
    // write), which a listing of buffers alone has no use for.
    // '*strings_truncated' and '*buffers_truncated' say whether a scanner hit
    // its own limit on results, so the answer is a prefix.
    void scan_recorded_writes(const std::filesystem::path &path, size_t string_minimum,
                              const ittd_progress *progress,
                              std::vector<kept_string> *strings_out,
                              std::vector<ittd_buffer_hit> *buffers_out,
                              bool *strings_truncated, bool *buffers_truncated)
    {
        const bool want_strings = strings_out != nullptr;
        std::unique_ptr<ttd::trace> own = open_forward_trace(path);
        ttd::trace &t = *own;
        // The shadow's page reads use a reader of their own, so they never
        // disturb the event stream's.
        std::unique_ptr<ttd::trace> mem_trace = open_forward_trace(path);
        ShadowMemory shadow(*mem_trace);

        using namespace idattd::scans;
        StringScan<uint64_t> strings(string_minimum);
        BufferScan<uint64_t> buffers(250000);       // Sogen's: instructions

        const uint64_t start = t.start_position();
        const uint64_t last  = last_position(t);

        // One buffer reused for every read: this runs after each instruction
        // that wrote, and shadow.read fills all of what it is given.
        std::vector<uint8_t> window;
        // Cancel is checked per chunk while the start's memory is scanned:
        // every committed region, which can be hundreds of megabytes, before
        // the event loop's own checks begin.
        const ttd::operation_control start_ctl = control(progress);
        bool at_start = false;
        auto scan_range = [&](uint64_t address, uint64_t size, uint64_t read_at, uint64_t step)
        {
            for ( uint64_t off = 0; off < size; off += kScanChunk )
            {
                if ( at_start )
                    start_ctl.check();
                const uint64_t b = off > kStringContext ? off - kStringContext : 0;
                const uint64_t e = std::min<uint64_t>(size, off + kScanChunk + kStringContext);
                window.resize(size_t(e - b));
                if ( shadow.read(address + b, window.size(), window.data(), read_at) )
                {
                    strings.inspect(address + b, window, step);
                    continue;
                }
                // Part of the window is unreadable: read it a page at a time,
                // on whole-page boundaries. Pieces taken from the window's
                // own (unaligned) start would each straddle the unmapped page
                // and fail too, losing everything near it.
                const uint64_t hi = address + e;
                for ( uint64_t p = address + b; p < hi; )
                {
                    const uint64_t next = std::min<uint64_t>(hi, (p & ~uint64_t(kPage - 1)) + kPage);
                    window.resize(size_t(next - p));
                    if ( shadow.read(p, window.size(), window.data(), read_at) )
                        strings.inspect(p, window, step);
                    p = next;
                }
            }
        };

        // ---- what memory held at the start ------------------------------------
        if ( want_strings && t.has_memory_regions() )
        {
            at_start = true;
            for ( const ttd::memory_region &r : t.memory_regions().regions )
            {
                if ( r.event_number != 0 || r.step != start )
                    continue;                           // a change, not the start map
                static const uint32_t MEM_COMMIT_ = 0x1000;
                if ( r.state != MEM_COMMIT_ || r.kind == 5 || r.kind == 6 )
                    continue;                           // MMIO, host-reserved
                scan_range(r.address, r.size, start, start);
            }
            at_start = false;
        }

        // ---- the writes, in order ----------------------------------------------
        const std::span<const ttd::mapping_change> maps =
            t.has_mapping_changes() ? t.mapping_changes() : std::span<const ttd::mapping_change>();
        size_t next_map = 0;

        // The guest writes of the current instruction, scanned for strings
        // once it is done, as Sogen does at the next instruction.
        std::vector<std::pair<uint64_t, uint64_t>> pending;
        uint64_t pending_step = 0;
        auto flush = [&]()
        {
            if ( pending.empty() )
                return;
            // The step after the writes, as the emulator counts it there.
            const uint64_t step = std::min(pending_step + 1, std::max<uint64_t>(last, pending_step));
            for ( const auto &[addr, size] : pending )
            {
                const uint64_t begin = addr > kStringContext ? addr - kStringContext : 0;
                const uint64_t end   = addr + size;
                scan_range(begin, end - begin + kStringContext, pending_step, step);
            }
            pending.clear();
        };

        const uint64_t kinds = (uint64_t)ttd::access_kind::write | (uint64_t)ttd::access_kind::host_write
                             | (uint64_t)ttd::access_kind::execute;
        const uint64_t total_events = std::max<uint64_t>(t.metadata().event_count, 1);
        const ttd::operation_control ctl = control(progress);
        ttd::event_reader reader(t, 0);
        uint64_t seen = 0;
        while ( std::optional<ttd::access_event> ev = reader.next(kinds) )
        {
            const uint64_t number = reader.last_number();
            if ( (++seen & 0xFFFF) == 0 )
                ctl.report(number, total_events);
            if ( ev->step != pending_step )
                flush();
            while ( next_map < maps.size() && maps[next_map].event_number <= number )
            {
                const ttd::mapping_change &m = maps[next_map++];
                shadow.drop(m.address, m.size);
                buffers.mapping_changed(m.address, m.size);
            }
            pending_step = ev->step;

            if ( ev->kind == ttd::access_kind::execute )
            {
                buffers.executed(ev->address, (size_t)ev->size);
                continue;
            }
            if ( ev->size == 0 )
                continue;
            std::vector<std::byte> data = t.access_data(*ev);
            if ( data.size() != ev->size )
                continue;
            const uint8_t *bytes = reinterpret_cast<const uint8_t *>(data.data());
            if ( want_strings )
                shadow.apply(ev->address, bytes, data.size());
            // Sogen's scanners hook the guest CPU's writes, not those Sogen
            // makes for the program (a syscall filling a buffer).
            if ( ev->kind != ttd::access_kind::write )
                continue;
            if ( want_strings )
                pending.emplace_back(ev->address, ev->size);
            for ( size_t off = 0; off < data.size(); off += kMaximumRegion )
            {
                const size_t n = std::min(kMaximumRegion, data.size() - off);
                buffers.ingest(ev->address + off, bytes + off, n, ev->step, ev->step, ev->ip);
            }
        }
        flush();
        buffers.finish();
        if ( strings_truncated != nullptr )
            *strings_truncated = strings.truncated;
        if ( buffers_truncated != nullptr )
            *buffers_truncated = buffers.truncated;

        if ( strings_out != nullptr )
        {
            strings.for_each([&](uint64_t address, const StringScan<uint64_t>::Entry &e)
            {
                kept_string s;
                s.address = address;
                s.pos     = appeared_at(t, e.pos);
                s.wide    = e.wide;
                s.length  = (uint32_t)e.value.size();
                s.text    = listed_text(e.value);
                strings_out->push_back(std::move(s));
            });
        }
        if ( buffers_out != nullptr )
            for ( const FoundBuffer<uint64_t> &r : buffers.results )
                buffers_out->push_back(buffer_hit(r.address, r.size, r.first, r.last, r.writer_ip, r.writes,
                                                  r.kind, r.preview));
    }

    // What a replay scan's answer depends on besides the recording.
    std::string scan_key(const ittd_fork_settings *settings)
    {
        std::string key;
        if ( const uint32_t *v = setting_flags(settings); v != nullptr )
            key += std::to_string(*v);
        key += '|';
        if ( const char *const *v = setting_registry_dir(settings); v != nullptr && *v != nullptr )
            key += *v;
        key += '|';
        if ( const char *const *v = setting_emulation_root(settings); v != nullptr && *v != nullptr )
            key += *v;
        return key;
    }

    // Whether the open recording's scans read its writes (scans_from_recording).
    bool recorded_scans(backend_t *b)
    {
        std::lock_guard<std::mutex> lock(b->mtx);
        return scans_from_recording(*b->trace);
    }

    // The scan of the recorded writes for 'scan_min', run once and kept. The
    // same pass also fills the buffer answer.
    // '*truncated', when given, says whether the scan hit the string scanner's
    // own limit.
    const std::vector<kept_string> &recorded_strings(backend_t *b, size_t scan_min, const ittd_progress *progress,
                                                     bool *truncated)
    {
        const std::string key = "recorded|" + std::to_string(scan_min);
        auto found = b->scans.strings.find(key);
        if ( found == b->scans.strings.end() )
        {
            std::vector<kept_string> s;
            std::vector<ittd_buffer_hit> v;
            bool s_cut = false, v_cut = false;
            scan_recorded_writes(b->path, scan_min, progress, &s, &v, &s_cut, &v_cut);
            // The first scan's buffers are kept, so is the first scan's flag.
            if ( b->scans.buffers.emplace("recorded", std::move(v)).second )
                b->scans.buffers_truncated["recorded"] = v_cut;
            b->scans.strings_truncated[key] = s_cut;
            found = b->scans.strings.emplace(key, std::move(s)).first;
        }
        if ( truncated != nullptr )
            *truncated = b->scans.strings_truncated[key];
        return found->second;
    }

    // The buffers of the recorded writes, from a string scan that ran, or
    // else from a pass of their own without the string scanner.
    const std::vector<ittd_buffer_hit> &recorded_buffers(backend_t *b, const ittd_progress *progress, bool *truncated)
    {
        auto found = b->scans.buffers.find("recorded");
        if ( found == b->scans.buffers.end() )
        {
            std::vector<ittd_buffer_hit> v;
            bool v_cut = false;
            scan_recorded_writes(b->path, 4, progress, nullptr, &v, nullptr, &v_cut);
            b->scans.buffers_truncated["recorded"] = v_cut;
            found = b->scans.buffers.emplace("recorded", std::move(v)).first;
        }
        *truncated = b->scans.buffers_truncated["recorded"];
        return found->second;
    }

    // Count the strings of 'all' at least 'min_length' long, and convert the
    // first 'cap' of them into 'buf' (when given) on the way.
    size_t fill_strings(const std::vector<kept_string> &all, uint32_t min_length, ittd_string_hit *buf, size_t cap)
    {
        size_t n = 0;
        for ( const kept_string &s : all )
        {
            if ( s.length < min_length )
                continue;
            if ( buf != nullptr && n < cap )
                buf[n] = string_hit(s);
            n++;
        }
        return n;
    }

    // set_truncated, also reporting a scanner that stopped at its own limit.
    void set_scan_truncated(int *out_truncated, size_t have, size_t cap, bool buf_given, bool scanner_cut)
    {
        set_truncated(out_truncated, have, cap, buf_given);
        if ( out_truncated != nullptr && scanner_cut )
            *out_truncated = 1;
    }

    int query_strings(ittd_backend *hb, const ittd_fork_settings *settings, uint32_t min_length,
                      ittd_string_hit *buf, size_t cap, size_t *out_count,
                      int *out_truncated, const ittd_progress *progress)
    {
        backend_t *b = B(hb);
        if ( b == nullptr )
            return ITTD_E_BAD_ARG;
        if ( min_length < 2 )
            min_length = 2;
        return guarded(b->error, [&]()
        {
            std::lock_guard<std::mutex> lock(b->scans.mtx);
            if ( recorded_scans(b) )
            {
                // Scanned at the shortest length likely to be asked for, and
                // filtered for this request.
                bool cut = false;
                const std::vector<kept_string> *scanned =
                    &recorded_strings(b, std::min<size_t>(min_length, 4), progress, &cut);
                // The short scan filled the scanner's cap: 4 to 7 character
                // strings may have crowded out longer ones asked for. A scan
                // at the length asked for has the cap to itself. Only then,
                // as it is another full pass.
                if ( cut && min_length > 4 )
                    scanned = &recorded_strings(b, min_length, progress, &cut);
                const size_t n = fill_strings(*scanned, min_length, buf, cap);
                b->scan_note.clear();
                set_scan_truncated(out_truncated, n, cap, buf != nullptr, cut);
                if ( out_count != nullptr )
                    *out_count = n;
                return ITTD_OK;
            }
            const std::string key = std::to_string(min_length) + "|" + scan_key(settings);
            auto found = b->scans.strings.find(key);
            if ( found == b->scans.strings.end() )
            {
                std::unique_ptr<ttd::trace> t = open_forward_trace(b->path);
                bool strict = false;
                auto emu = replay_emulator(*t, settings, &strict);
                std::optional<ttd::string_scanner> scanner;
                b->scans.notes[key] = replay_scan(*emu, *t, [&]()
                {
                    scanner.emplace(*emu, min_length);
                    scanner->scan_initial_memory();
                }, []() {}, [&]()
                {
                    // Attached by now, unless the replay failed before it
                    // started.
                    if ( !scanner )
                        scanner.emplace(*emu, min_length);
                    scanner->scan_initial_memory();
                }, strict, progress);
                if ( !scanner )
                    throw std::runtime_error("the replay did not start");
                scanner->finish();
                std::vector<kept_string> v;
                for ( const ttd::recovered_string &s : scanner->results() )
                {
                    kept_string k;
                    k.address = s.address;
                    k.pos     = appeared_at(*t, s.step);
                    k.wide    = s.encoding.find("16") != std::string::npos;
                    k.text    = listed_text(s.value);
                    // Characters, not bytes: UTF-8 continuation bytes do not count.
                    for ( unsigned char ch : s.value )
                        if ( (ch & 0xC0) != 0x80 )
                            k.length++;
                    v.push_back(std::move(k));
                }
                found = b->scans.strings.emplace(key, std::move(v)).first;
            }
            b->scan_note.set(b->scans.notes[key]);
            set_truncated(out_truncated, found->second.size(), cap, buf != nullptr);
            return fill(found->second, buf, cap, out_count, string_hit);
        });
    }

    int query_buffers(ittd_backend *hb, const ittd_fork_settings *settings,
                      ittd_buffer_hit *buf, size_t cap, size_t *out_count,
                      int *out_truncated, const ittd_progress *progress)
    {
        backend_t *b = B(hb);
        if ( b == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            std::lock_guard<std::mutex> lock(b->scans.mtx);
            if ( recorded_scans(b) )
            {
                bool cut = false;
                const std::vector<ittd_buffer_hit> &v = recorded_buffers(b, progress, &cut);
                b->scan_note.clear();
                set_scan_truncated(out_truncated, v.size(), cap, buf != nullptr, cut);
                return fill(v, buf, cap, out_count, [](const ittd_buffer_hit &h) { return h; });
            }
            const std::string key = scan_key(settings);
            auto found = b->scans.buffers.find(key);
            if ( found == b->scans.buffers.end() )
            {
                std::unique_ptr<ttd::trace> t = open_forward_trace(b->path);
                bool strict = false;
                auto emu = replay_emulator(*t, settings, &strict);
                std::optional<ttd::buffer_scanner> scanner;
                // What each scanner put away at a restore found, then the
                // last one's.
                std::vector<ttd::recovered_buffer> found_before;
                // A scanner checks every write against the recording and, at
                // the end, that none is missing. One put away at a divergence
                // fails both checks by definition; its results are kept
                // (finish hands them out before it throws).
                auto put_away = [&](bool diverged)
                {
                    if ( !scanner )
                        return;
                    try
                    {
                        scanner->finish();
                    }
                    catch ( const std::runtime_error & )
                    {
                        if ( !diverged )
                            throw;
                    }
                    found_before.insert(found_before.end(), scanner->results().begin(), scanner->results().end());
                    scanner.reset();
                };
                b->scans.notes[key] = replay_scan(*emu, *t, [&]() { scanner.emplace(*emu, *t); },
                                                 [&]() { put_away(true); }, [&]() { scanner.emplace(*emu, *t); },
                                                 strict, progress);
                // The last scanner ran to the end unless the last divergence
                // had no checkpoint after it.
                put_away(!b->scans.notes[key].empty());
                std::vector<ittd_buffer_hit> v;
                for ( const ttd::recovered_buffer &r : found_before )
                    v.push_back(buffer_hit(r.address, r.size, r.first_step, r.last_step, r.writer_ip, r.writes,
                                           r.kind, r.preview));
                found = b->scans.buffers.emplace(key, std::move(v)).first;
            }
            b->scan_note.set(b->scans.notes[key]);
            set_truncated(out_truncated, found->second.size(), cap, buf != nullptr);
            return fill(found->second, buf, cap, out_count, [](const ittd_buffer_hit &h) { return h; });
        });
    }
}
