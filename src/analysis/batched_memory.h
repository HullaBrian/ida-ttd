#pragma once

#include "common/pch.h"
#include "core/backend.h"
#include "core/guest_view.h"
#include "analysis/query_runner.h"

namespace idattd
{
    // Guest memory at many positions, fetched from the backend in batches
    // (ITraceBackend::read_memory_at) instead of by seeking a cursor to each:
    // on Microsoft TTD a seek costs about 15 ms, and decoding a recording's
    // syscalls one seek at a time took minutes. A decoder reads through
    // reader(), which serves what has been fetched and notes what has not;
    // fetch() gets all of that at once, and the decoder runs again over the
    // items that missed something (decode_in_rounds). A pointer followed to a
    // structure followed to a string is three rounds.
    class BatchedMemory
    {
    public:
        GuestRead reader(Position at)
        {
            return [this, at](uint64_t addr, void *buf, size_t size) -> size_t
            {
                return read(at, addr, buf, size);
            };
        }

        // How many blocks reads have asked for and not found, ever: a caller
        // compares it before and after a decode.
        uint64_t misses() const { return m_misses; }

        // What the fetches cost, for measuring: fetches made, blocks and
        // distinct positions asked for, and the time spent in them.
        struct Stats
        {
            uint64_t fetches = 0, blocks = 0, positions = 0;
            double   seconds = 0;
        };
        const Stats &stats() const { return m_stats; }

        // Everything missed since the last fetch. False when cancelled.
        bool fetch(ITraceBackend *b, ProgressSink *progress)
        {
            if ( m_wanted.empty() )
                return true;
            std::vector<MemAt> reads;
            reads.reserve(m_wanted.size());
            for ( const Key &k : m_wanted )
            {
                MemAt m;
                m.pos    = k.first;
                m.addr   = (ea_t)(k.second * kBlock);
                m.offset = reads.size() * kBlock;
                m.size   = kBlock;
                reads.push_back(m);
            }
            std::vector<uint8_t> data, known;
            m_stats.fetches++;
            m_stats.blocks += reads.size();
            {
                std::set<Position> at;
                for ( const MemAt &m : reads )
                    at.insert(m.pos);
                m_stats.positions += at.size();
            }
            const auto t0 = std::chrono::steady_clock::now();
            QueryResult r = b->read_memory_at(reads, &data, &known, progress);
            m_stats.seconds += std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
            if ( r.cancelled )
                return false;
            // A block that could not be read is kept as unknown, so it is not
            // asked for again.
            size_t i = 0;
            for ( const Key &k : m_wanted )
            {
                Block &blk = m_blocks[k];
                const size_t off = i++ * kBlock;
                if ( r.ran && off + kBlock <= data.size() )
                {
                    memcpy(blk.data, data.data() + off, kBlock);
                    memcpy(blk.known, known.data() + off, kBlock);
                }
            }
            m_wanted.clear();
            return true;
        }

    private:
        static constexpr uint64_t kBlock = 0x100;
        // A read longer than this asks for its first blocks only; the rest
        // come in a later round if it still wants them.
        static constexpr size_t kMaxMissesPerRead = 16;

        struct Block
        {
            uint8_t data[kBlock]  = { 0 };
            uint8_t known[kBlock] = { 0 };      // ITTD_KNOWN_NO
        };
        using Key = std::pair<Position, uint64_t>;      // (where, block number)

        // As guest_read: the leading bytes known (a placeholder counts as a
        // real zero), with buf zero-filled past what is available.
        size_t read(Position at, uint64_t addr, void *buf, size_t size)
        {
            if ( buf == nullptr || size == 0 )
                return 0;
            memset(buf, 0, size);
            // Not past the top of the address space.
            if ( addr + size < addr )
                size = (size_t)(0 - addr);
            uint8_t *out = (uint8_t *)buf;
            size_t prefix = 0, missed = 0, off = 0;
            bool whole = true;
            while ( off < size && missed < kMaxMissesPerRead )
            {
                const uint64_t a       = addr + off;
                const uint64_t blockno = a / kBlock;
                const size_t   in      = (size_t)(a % kBlock);
                const size_t   n       = std::min<size_t>((size_t)kBlock - in, size - off);
                auto it = m_blocks.find(Key{ at, blockno });
                if ( it == m_blocks.end() )
                {
                    m_wanted.insert(Key{ at, blockno });
                    m_misses++;
                    missed++;
                    whole = false;
                }
                else
                {
                    memcpy(out + off, it->second.data + in, n);
                    for ( size_t j = 0; j < n && whole; j++ )
                    {
                        if ( it->second.known[in + j] == ITTD_KNOWN_NO )
                            whole = false;
                        else
                            prefix++;
                    }
                }
                off += n;
            }
            return prefix;
        }

        std::map<Key, Block> m_blocks;
        std::set<Key>        m_wanted;
        uint64_t             m_misses = 0;
        Stats                m_stats;
    };

    // Rounds of fetching before a decode stands with what it has.
    constexpr int kMaxFetchRounds = 8;

    // Decode each of 'todo' with 'once', reading through 'mem'; fetch what
    // the decodes missed and decode again those that missed something, until
    // nothing is missing or the rounds run out. 'once' must start its item
    // afresh each time (it runs again with more memory available). Progress
    // goes to 'sink' as lo..hi. False when cancelled.
    inline bool decode_in_rounds(BatchedMemory &mem, ITraceBackend *b, ProgressSink *sink,
                                 std::vector<size_t> todo, const std::function<void(size_t)> &once,
                                 uint32_t lo, uint32_t hi, int *rounds_out = nullptr)
    {
        for ( int round = 0; !todo.empty(); round++ )
        {
            if ( rounds_out != nullptr )
                *rounds_out = round + 1;
            std::vector<size_t> again;
            for ( size_t n = 0; n < todo.size(); n++ )
            {
                if ( (n & 255) == 0 && sink != nullptr && sink->cancelled() )
                    return false;
                const uint64_t before = mem.misses();
                once(todo[n]);
                if ( mem.misses() != before )
                    again.push_back(todo[n]);
            }
            if ( again.empty() || round + 1 == kMaxFetchRounds )
                break;
            // The first fetch is most of the work; later ones share the last
            // fifth of the stage.
            const uint32_t mid = lo + (hi - lo) * 4 / 5;
            const uint32_t a = round == 0 ? lo : mid + (hi - mid) * (round - 1) / kMaxFetchRounds;
            const uint32_t z = round == 0 ? mid : mid + (hi - mid) * round / kMaxFetchRounds;
            StageSink fetch_stage(sink, a, z);
            if ( !mem.fetch(b, &fetch_stage) )
                return false;
            todo.swap(again);
        }
        return true;
    }
}
