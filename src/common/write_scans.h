#pragma once

// Strings and buffers recovered from a recording's memory writes, the way
// Sogen's windows-ttd scanners find them (ttd_string_scan.cpp and
// ttd_buffer_scan.cpp): the same tests, the same kinds and the same limits, so
// a list reads the same whichever backend produced it.
//
// Fed by each backend from its own write stream -- the Microsoft engine's
// watchpoints, Sogen's recorded write events -- and so written against the
// standard library alone: the Sogen backend builds without the rest of the
// plugin. 'Pos' is the backend's own position type, carried through untouched.

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace idattd::scans
{
    inline bool printable(uint8_t c) { return c >= 0x20 && c <= 0x7E; }

    // ---- strings --------------------------------------------------------------
    const size_t   kStringMaximum = 4096;          // Sogen's
    const uint64_t kStringContext = 512;           // Sogen's
    const uint64_t kScanChunk     = 65536;         // Sogen's

    template <typename Pos>
    class StringScan
    {
    public:
        struct Entry
        {
            Pos         pos;
            bool        wide;
            std::string value;
        };

        explicit StringScan(size_t minimum, size_t cap = 500000) : m_minimum(minimum), m_cap(cap) {}
        bool truncated = false;

        // Every NUL-terminated ASCII or UTF-16LE run in 'bytes' of at least
        // the minimum length.
        void inspect(uint64_t address, const std::vector<uint8_t> &bytes, const Pos &pos)
        {
            for ( size_t i = 0; i < bytes.size(); )
            {
                if ( !printable(bytes[i]) )
                {
                    ++i;
                    continue;
                }
                size_t end = i;
                while ( end < bytes.size() && printable(bytes[end]) )
                    ++end;
                if ( end - i >= m_minimum && end - i <= kStringMaximum && end < bytes.size() && bytes[end] == 0 )
                    add(address + i, pos, false, std::string(bytes.begin() + i, bytes.begin() + end));
                i = end;
            }
            for ( size_t i = 0; i + 1 < bytes.size(); ++i )
            {
                if ( !printable(bytes[i]) || bytes[i + 1] != 0 || (i >= 2 && printable(bytes[i - 2]) && bytes[i - 1] == 0) )
                    continue;
                size_t end = i;
                std::string value;
                while ( end + 1 < bytes.size() && printable(bytes[end]) && bytes[end + 1] == 0 && value.size() < kStringMaximum )
                {
                    value.push_back((char)bytes[end]);
                    end += 2;
                }
                if ( value.size() >= m_minimum && end + 1 < bytes.size() && bytes[end] == 0 && bytes[end + 1] == 0 )
                    add(address + i, pos, true, std::move(value));
            }
        }

        // fn(address, const Entry &) for each, in address order.
        template <typename Fn>
        void for_each(Fn fn) const
        {
            for ( const auto &[address, entries] : m_strings )
                for ( const Entry &e : entries )
                    fn(address, e);
        }

        size_t minimum() const { return m_minimum; }

    private:
        std::map<uint64_t, std::vector<Entry>> m_strings;
        size_t m_count = 0;
        size_t m_minimum;
        size_t m_cap;

        // A string that grew in place replaces what it grew from.
        void add(uint64_t address, const Pos &pos, bool wide, std::string value)
        {
            auto found = m_strings.find(address);
            if ( found != m_strings.end() )
            {
                for ( Entry &e : found->second )
                {
                    if ( e.wide != wide )
                        continue;
                    if ( e.value == value )
                        return;
                    if ( value.size() > e.value.size() && value.compare(0, e.value.size(), e.value) == 0 )
                    {
                        e.value = std::move(value);
                        e.pos   = pos;
                        return;
                    }
                }
            }
            // Checked before an address gets its entry, so a full scan does
            // not go on growing the map with empty ones.
            if ( m_count >= m_cap )
            {
                truncated = true;
                return;
            }
            if ( found == m_strings.end() )
                found = m_strings.emplace(address, std::vector<Entry>()).first;
            found->second.push_back(Entry{ pos, wide, std::move(value) });
            m_count++;
        }
    };

    // ---- buffers --------------------------------------------------------------
    const uint64_t kNearbyBytes   = 16;
    const size_t   kMaximumRegion = 256 * 1024;
    const size_t   kMaximumActive = 16384;
    const size_t   kMaxBuffers    = 20000;          // Sogen's

    inline bool begins(const uint8_t *b, size_t n, std::initializer_list<uint8_t> prefix)
    {
        return n >= prefix.size() && std::equal(prefix.begin(), prefix.end(), b);
    }

    inline uint32_t little32(const uint8_t *b, size_t off)
    {
        return uint32_t(b[off]) | (uint32_t(b[off + 1]) << 8) | (uint32_t(b[off + 2]) << 16) | (uint32_t(b[off + 3]) << 24);
    }

    inline std::string signature(const uint8_t *b, size_t n)
    {
        if ( begins(b, n, { 'M', 'Z' }) && n >= 0x40 )
        {
            uint32_t pe = little32(b, 0x3C);
            if ( pe <= n - 4 && begins(b + pe, n - pe, { 'P', 'E', 0, 0 }) )
                return "pe_image";
        }
        if ( begins(b, n, { 0x7F, 'E', 'L', 'F' }) )                         return "elf_image";
        if ( begins(b, n, { 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A }) )  return "png_image";
        if ( begins(b, n, { 0xFF, 0xD8, 0xFF }) )                            return "jpeg_image";
        if ( begins(b, n, { 'G', 'I', 'F', '8' }) )                          return "gif_image";
        if ( begins(b, n, { 'B', 'M' }) )                                    return "bmp_image";
        if ( begins(b, n, { '%', 'P', 'D', 'F', '-' }) )                     return "pdf_document";
        if ( begins(b, n, { 'P', 'K', 3, 4 }) )                              return "zip_archive";
        if ( begins(b, n, { 0x1F, 0x8B, 0x08 }) )                            return "gzip_stream";
        if ( begins(b, n, { 'S', 'Q', 'L', 'i', 't', 'e', ' ', 'f', 'o', 'r', 'm', 'a', 't', ' ', '3', 0 }) )
            return "sqlite_database";
        if ( begins(b, n, { '-', '-', '-', '-', '-', 'B', 'E', 'G', 'I', 'N', ' ' }) )
        {
            std::string text((const char *)b, std::min<size_t>(n, 128));
            if ( text.find("PRIVATE KEY-----") != std::string::npos )
                return "pem_private_key";
            if ( text.find("PUBLIC KEY-----") != std::string::npos )
                return "pem_public_key";
        }
        return std::string();
    }

    inline double entropy(const uint8_t *b, size_t n)
    {
        size_t counts[256] = { 0 };
        for ( size_t i = 0; i < n; i++ )
            counts[b[i]]++;
        double v = 0;
        for ( size_t c : counts )
        {
            if ( c != 0 )
            {
                double p = double(c) / double(n);
                v -= p * std::log2(p);
            }
        }
        return v;
    }

    inline std::string preview(const uint8_t *b, size_t n, bool as_text)
    {
        static const char hex[] = "0123456789abcdef";
        std::string s;
        for ( size_t i = 0; i < std::min<size_t>(n, 48); i++ )
        {
            if ( as_text )
            {
                s.push_back(printable(b[i]) ? (char)b[i] : '.');
            }
            else
            {
                s.push_back(hex[b[i] >> 4]);
                s.push_back(hex[b[i] & 15]);
            }
        }
        return s;
    }

    template <typename Pos>
    struct FoundBuffer
    {
        uint64_t    address = 0;
        uint64_t    size = 0;
        Pos         first, last;
        uint64_t    writer_ip = 0;
        uint64_t    writes = 0;
        std::string kind;
        std::string preview;
    };

    // Writes grouped into the regions they filled. 'nearby' is how far apart,
    // on the backend's clock, two writes still count as one burst of writing:
    // Sogen counts instructions (250,000); a backend that can only count
    // writes passes a smaller number.
    template <typename Pos>
    class BufferScan
    {
    public:
        explicit BufferScan(uint64_t nearby) : m_nearby(nearby) {}
        bool truncated = false;
        std::vector<FoundBuffer<Pos>> results;

        void ingest(uint64_t address, const uint8_t *bytes, size_t size, uint64_t clock,
                    const Pos &pos, uint64_t ip)
        {
            if ( size == 0 || address > UINT64_MAX - size )
                return;
            const uint64_t end = address + size;
            auto it = m_active.upper_bound(address);
            if ( it != m_active.begin() )
            {
                --it;
                const uint64_t old_end = it->first + it->second.bytes.size();
                if ( old_end + kNearbyBytes < address )
                    ++it;
            }
            if ( it != m_active.end() && it->first <= end + kNearbyBytes )
            {
                Region &cur = it->second;
                const uint64_t cbegin = std::min(it->first, address);
                const uint64_t cend   = std::max(it->first + cur.bytes.size(), end);
                bool changes_executed = false;
                if ( address < it->first + cur.bytes.size() )
                {
                    const uint64_t ob = std::max(it->first, address);
                    const uint64_t oe = std::min(it->first + cur.bytes.size(), end);
                    for ( uint64_t a = ob; a < oe; ++a )
                    {
                        size_t off = size_t(a - it->first);
                        if ( cur.executed[off] && cur.bytes[off] != bytes[a - address] )
                        {
                            changes_executed = true;
                            break;
                        }
                    }
                }
                if ( changes_executed )
                {
                    emit_at(it->first, std::move(cur));
                    m_active.erase(it);
                }
                else if ( (address < it->first + cur.bytes.size() || clock - cur.last_clock <= m_nearby)
                       && cend - cbegin <= kMaximumRegion )
                {
                    if ( cbegin < it->first )
                    {
                        size_t prefix = size_t(it->first - cbegin);
                        cur.bytes.insert(cur.bytes.begin(), prefix, 0);
                        cur.known.insert(cur.known.begin(), prefix, 0);
                        cur.executed.insert(cur.executed.begin(), prefix, 0);
                        auto node = m_active.extract(it);
                        node.key() = cbegin;
                        it = m_active.insert(std::move(node)).position;
                    }
                    Region &r = it->second;
                    r.bytes.resize(size_t(cend - cbegin));
                    r.known.resize(r.bytes.size());
                    r.executed.resize(r.bytes.size());
                    size_t off = size_t(address - cbegin);
                    std::copy(bytes, bytes + size, r.bytes.begin() + off);
                    std::fill_n(r.known.begin() + off, size, uint8_t(1));
                    std::fill_n(r.executed.begin() + off, size, uint8_t(0));
                    r.last_clock = clock;
                    r.last_pos   = pos;
                    r.writer_ip  = ip;
                    r.writes++;
                    return;
                }
                else if ( address < it->first + cur.bytes.size() )
                {
                    emit_at(it->first, std::move(cur));
                    m_active.erase(it);
                }
            }
            Region v;
            v.bytes.assign(bytes, bytes + size);
            v.known.assign(size, 1);
            v.executed.assign(size, 0);
            v.first_pos  = v.last_pos = pos;
            v.last_clock = clock;
            v.writer_ip  = ip;
            v.writes     = 1;
            auto existing = m_active.find(address);
            if ( existing != m_active.end() )
            {
                emit_at(existing->first, std::move(existing->second));
                m_active.erase(existing);
            }
            m_active.emplace(address, std::move(v));
            if ( m_active.size() > kMaximumActive )
                evict_oldest();
        }

        void executed(uint64_t address, size_t size)
        {
            auto it = m_active.upper_bound(address);
            while ( it != m_active.begin() )
            {
                --it;
                if ( address - it->first >= kMaximumRegion )
                    break;
                Region &r = it->second;
                if ( address - it->first < r.known.size() )
                {
                    size_t off = size_t(address - it->first);
                    for ( size_t b = off; b < std::min(r.known.size(), off + size); ++b )
                        if ( r.known[b] )
                            r.executed[b] = 1;
                }
            }
        }

        // [address, address + size) was mapped, unmapped or remapped: what a
        // region held there is finished.
        void mapping_changed(uint64_t address, uint64_t size)
        {
            if ( size == 0 )
                return;
            const uint64_t end = address + std::min<uint64_t>(size, UINT64_MAX - address);
            for ( auto it = m_active.begin(); it != m_active.end(); )
            {
                Region &v = it->second;
                if ( !(it->first < end && it->first + v.bytes.size() > address) )
                {
                    ++it;
                    continue;
                }
                const size_t cb = size_t(std::max(it->first, address) - it->first);
                const size_t ce = size_t(std::min<uint64_t>(it->first + v.bytes.size(), end) - it->first);
                Region removed;
                removed.bytes.assign(v.bytes.begin() + cb, v.bytes.begin() + ce);
                removed.known.assign(v.known.begin() + cb, v.known.begin() + ce);
                removed.executed.assign(v.executed.begin() + cb, v.executed.begin() + ce);
                removed.first_pos  = v.first_pos;
                removed.last_pos   = v.last_pos;
                removed.last_clock = v.last_clock;
                removed.writer_ip  = v.writer_ip;
                removed.writes     = v.writes;
                emit_at(it->first + cb, std::move(removed));
                std::fill(v.known.begin() + cb, v.known.begin() + ce, uint8_t(0));
                std::fill(v.executed.begin() + cb, v.executed.begin() + ce, uint8_t(0));
                if ( std::none_of(v.known.begin(), v.known.end(), [](uint8_t x) { return x != 0; }) )
                    it = m_active.erase(it);
                else
                    ++it;
            }
        }

        void finish()
        {
            for ( auto &[a, r] : m_active )
                emit_at(a, std::move(r));
            m_active.clear();
        }

    private:
        struct Region
        {
            std::vector<uint8_t> bytes, known, executed;
            Pos      first_pos, last_pos;
            uint64_t last_clock = 0;
            uint64_t writer_ip = 0;
            uint64_t writes = 0;
        };
        std::map<uint64_t, Region> m_active;
        uint64_t m_nearby;

        void evict_oldest()
        {
            auto oldest = std::min_element(m_active.begin(), m_active.end(), [](const auto &a, const auto &b)
            {
                bool as = a.second.bytes.size() < 512, bs = b.second.bytes.size() < 512;
                return as != bs ? as : a.second.last_clock < b.second.last_clock;
            });
            emit_at(oldest->first, std::move(oldest->second));
            m_active.erase(oldest);
        }

        void add(uint64_t base, const Region &r, size_t begin, const uint8_t *b, size_t n, const char *kind,
                 bool text, bool utf16 = false)
        {
            if ( n == 0 )
                return;
            if ( results.size() >= kMaxBuffers )
            {
                truncated = true;
                return;
            }
            std::string display;
            if ( utf16 )
            {
                for ( size_t i = 0; i + 1 < std::min<size_t>(n, 96); i += 2 )
                    display.push_back((char)b[i]);
            }
            else
            {
                display = preview(b, n, text);
            }
            FoundBuffer<Pos> h;
            h.address   = base + begin;
            h.size      = n;
            h.first     = r.first_pos;
            h.last      = r.last_pos;
            h.writer_ip = r.writer_ip;
            h.writes    = r.writes;
            h.kind      = kind;
            h.preview   = std::move(display);
            results.push_back(std::move(h));
        }

        void emit_at(uint64_t base, Region &&r)
        {
            for ( size_t offset = 0; offset < r.known.size() && results.size() < kMaxBuffers; )
            {
                while ( offset < r.known.size() && !r.known[offset] )
                    ++offset;
                const size_t begin = offset;
                while ( offset < r.known.size() && r.known[offset] )
                    ++offset;
                if ( offset - begin < 16 )
                    continue;
                const uint8_t *b = r.bytes.data() + begin;
                const size_t   n = offset - begin;
                std::string kind = signature(b, n);
                const size_t text_count = (size_t)std::count_if(b, b + n, printable);
                const bool text = n >= 32 && text_count * 100 >= n * 90;
                if ( kind.empty() && std::any_of(r.executed.begin() + begin, r.executed.begin() + offset,
                                                 [](uint8_t x) { return x != 0; }) )
                    kind = "contains_executed_code";
                if ( kind.empty() && text )
                    kind = "ascii_text";
                if ( kind.empty() && n >= 32 )
                {
                    size_t pairs = 0;
                    for ( size_t i = 0; i + 1 < n; i += 2 )
                        pairs += printable(b[i]) && b[i + 1] == 0;
                    if ( pairs * 100 >= (n / 2) * 85 )
                        kind = "utf16le_text";
                }
                if ( kind.empty() && n >= 256 && entropy(b, n) >= 7.5 )
                    kind = "high_entropy_buffer";
                if ( kind.empty() && n >= 512 )
                    kind = "buffer";
                if ( !kind.empty() )
                    add(base, r, begin, b, n, kind.c_str(), text);

                size_t strings = 0;
                for ( size_t i = 0; i < n && strings < 128 && results.size() < kMaxBuffers; )
                {
                    if ( !printable(b[i]) )
                    {
                        ++i;
                        continue;
                    }
                    size_t end = i;
                    while ( end < n && printable(b[end]) )
                        ++end;
                    if ( end - i >= 16 && !(text && i == 0 && end == n) )
                    {
                        add(base, r, begin + i, b + i, end - i, "ascii_string", true);
                        ++strings;
                    }
                    i = end;
                }
                strings = 0;
                for ( size_t i = 0; i + 1 < n && strings < 128 && results.size() < kMaxBuffers; ++i )
                {
                    if ( !printable(b[i]) || b[i + 1] != 0 || (i >= 2 && printable(b[i - 2]) && b[i - 1] == 0) )
                        continue;
                    size_t end = i;
                    while ( end + 1 < n && printable(b[end]) && b[end + 1] == 0 )
                        end += 2;
                    if ( end - i >= 24 )
                    {
                        add(base, r, begin + i, b + i, end - i, "utf16le_string", false, true);
                        ++strings;
                    }
                    i = end - 1;
                }
                size_t signatures = 0;
                for ( size_t i = 1; i + 16 < n && signatures < 64 && results.size() < kMaxBuffers; ++i )
                {
                    const uint8_t first = b[i];
                    if ( first != 'M' && first != 0x89 && first != 'G' && first != '%' && first != 'P'
                      && first != 'S' && first != '-' )
                        continue;
                    std::string embedded = signature(b + i, n - i);
                    if ( !embedded.empty() && embedded != "bmp_image" && embedded != "jpeg_image" )
                    {
                        add(base, r, begin + i, b + i, n - i, embedded.c_str(), false);
                        ++signatures;
                    }
                }
            }
        }
    };
}
