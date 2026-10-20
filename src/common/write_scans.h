// The string and buffer scanners both backends feed: the Microsoft backend
// from its watchpoint replays, the Sogen backend from recorded write events.
// This implements docs/scan-rules.md and is written from that description,
// not ported from another project. The rules themselves follow Sogen's, so
// that a list reads the same whichever kind of recording it came from.
//
// Header-only and standard-library-only on purpose: the Sogen backend builds
// without the rest of the plugin.

#pragma once

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <vector>

namespace idattd::scans
{
    // ---- limits callers see ----------------------------------------------
    inline constexpr size_t kStringMaximum = 4096;      // longest string, in characters
    inline constexpr size_t kStringContext = 512;       // overlap callers give each window
    inline constexpr size_t kScanChunk     = 65536;     // the window callers step by
    inline constexpr size_t kMaximumRegion = 256 * 1024; // longest a region may grow

    // ---- byte tests shared by both scanners --------------------------------
    namespace detail
    {
        inline bool printable(uint8_t b)
        {
            return b >= 0x20 && b <= 0x7E;
        }

        // A UTF-16LE character of the kind both scanners accept: a printable
        // low byte and a zero high byte, both inside [0, size).
        inline bool wide_pair(const uint8_t *p, size_t size, size_t k)
        {
            return k + 1 < size && printable(p[k]) && p[k + 1] == 0;
        }

        // Whether [p, p + n) begins with the 'len' bytes of 'sig'. A prefix
        // only matches when there are at least that many bytes.
        inline bool starts_with(const uint8_t *p, size_t n, const char *sig, size_t len)
        {
            return n >= len && memcmp(p, sig, len) == 0;
        }

        inline bool contains(const uint8_t *p, size_t n, const char *needle)
        {
            const size_t len = strlen(needle);
            if ( n < len )
                return false;
            for ( size_t i = 0; i + len <= n; i++ )
                if ( memcmp(p + i, needle, len) == 0 )
                    return true;
            return false;
        }
    }

    //=======================================================================
    // Strings
    //=======================================================================
    // Every NUL-terminated ASCII or UTF-16LE string seen in the windows of
    // memory the caller offers, keyed by address. A string that grows in
    // place (written a piece at a time, each window seeing more of it) keeps
    // one entry, which ends up with the longest text and the position it was
    // last extended at.
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

        bool truncated = false;

        StringScan(size_t minimum, size_t cap = 500000) : m_minimum(minimum), m_cap(cap) {}

        size_t minimum() const { return m_minimum; }

        // One window: 'bytes' at 'address', as memory held them at 'pos'.
        // All ASCII strings go in first, then all UTF-16 ones, because that
        // order decides which entry an address's later offers land on.
        void inspect(uint64_t address, const std::vector<uint8_t> &bytes, const Pos &pos)
        {
            scan_ascii(address, bytes.data(), bytes.size(), pos);
            scan_wide(address, bytes.data(), bytes.size(), pos);
        }

        // fn(uint64_t address, const Entry &): addresses ascending, then each
        // address's entries in the order they were first added.
        template <typename Fn>
        void for_each(Fn fn) const
        {
            for ( const auto &[address, entries] : m_entries )
                for ( const Entry &e : entries )
                    fn(address, e);
        }

    private:
        size_t m_minimum;
        size_t m_cap;
        size_t m_count = 0;
        std::map<uint64_t, std::vector<Entry>> m_entries;

        // A run of printable bytes counts only when the window shows the NUL
        // after it; a run cut off by the window's end may go on, and the
        // overlapping next window will see it whole.
        void scan_ascii(uint64_t address, const uint8_t *p, size_t size, const Pos &pos)
        {
            size_t i = 0;
            while ( i < size )
            {
                if ( !detail::printable(p[i]) )
                {
                    i++;
                    continue;
                }
                size_t e = i;
                while ( e < size && detail::printable(p[e]) )
                    e++;
                const size_t len = e - i;
                if ( len >= m_minimum && len <= kStringMaximum && e < size && p[e] == 0 )
                    offer(address + i, pos, false, std::string(reinterpret_cast<const char *>(p + i), len));
                i = e;
            }
        }

        // Every offset is tried, odd ones too, since a wide string need not
        // be aligned. An offset continuing the pair two bytes before it is
        // the middle of a string, not a start.
        void scan_wide(uint64_t address, const uint8_t *p, size_t size, const Pos &pos)
        {
            std::string text;
            for ( size_t i = 0; i + 1 < size; i++ )
            {
                if ( !detail::wide_pair(p, size, i) )
                    continue;
                if ( i >= 2 && detail::wide_pair(p, size, i - 2) )
                    continue;
                text.clear();
                size_t k = i;
                while ( text.size() < kStringMaximum && detail::wide_pair(p, size, k) )
                {
                    text.push_back(char(p[k]));
                    k += 2;
                }
                if ( text.size() >= m_minimum && k + 1 < size && p[k] == 0 && p[k + 1] == 0 )
                    offer(address + i, pos, true, text);
            }
        }

        void offer(uint64_t address, const Pos &pos, bool wide, const std::string &value)
        {
            auto it = m_entries.find(address);
            if ( it != m_entries.end() )
            {
                // The first entry of the same kind that is this text, or a
                // prefix of it, absorbs the offer.
                for ( Entry &e : it->second )
                {
                    if ( e.wide != wide )
                        continue;
                    if ( e.value == value )
                        return;
                    if ( value.size() > e.value.size() && value.compare(0, e.value.size(), e.value) == 0 )
                    {
                        e.value = value;
                        e.pos   = pos;
                        return;
                    }
                }
            }
            if ( m_count >= m_cap )
            {
                truncated = true;
                return;
            }
            // Only now is the address's slot made, so a refused offer leaves
            // nothing behind for for_each to visit.
            if ( it == m_entries.end() )
                it = m_entries.emplace(address, std::vector<Entry>()).first;
            it->second.push_back(Entry{ pos, wide, value });
            m_count++;
        }
    };

    //=======================================================================
    // Buffers
    //=======================================================================

    template <typename Pos>
    struct FoundBuffer
    {
        uint64_t    address = 0, size = 0;
        Pos         first, last;
        uint64_t    writer_ip = 0, writes = 0;
        std::string kind, preview;
    };

    // Groups the program's writes into regions -- bytes written close
    // together in space, and either touching or close together in time --
    // and, as each region is retired, classifies what it held: files, text,
    // code that ran, random-looking data, plain buffers, and the strings and
    // embedded files inside them.
    template <typename Pos>
    class BufferScan
    {
    public:
        bool truncated = false;
        std::vector<FoundBuffer<Pos>> results;

        // 'nearby' is how many clock ticks after a region's last write a
        // write just beyond it still counts as the same burst.
        explicit BufferScan(uint64_t nearby) : m_nearby(nearby) {}

        void ingest(uint64_t address, const uint8_t *bytes, size_t size, uint64_t clock, const Pos &pos, uint64_t ip)
        {
            if ( size == 0 || uint64_t(size) > UINT64_MAX - address )
                return;
            const uint64_t end = address + size;

            auto cand = candidate(address);
            if ( cand != m_regions.end() && cand->first <= end + kGap )
            {
                Region &r = cand->second;
                const uint64_t s = cand->first;
                const uint64_t t = r.end(s);
                const uint64_t lo = std::min(s, address);
                const uint64_t hi = std::max(t, end);
                // Deliberately weaker than overlapping: a write wholly
                // before the region also counts, as Sogen has it.
                const bool reaches = address < t;

                if ( reaches && rewrites_executed(s, r, address, bytes, size) )
                {
                    retire(cand);
                }
                else if ( (reaches || clock - r.last_clock <= m_nearby) && hi - lo <= kMaximumRegion )
                {
                    grow(cand, lo, hi, address, bytes, size, clock, pos, ip);
                    return;
                }
                else if ( reaches )
                {
                    retire(cand);
                }
            }
            start_region(address, bytes, size, clock, pos, ip);
        }

        // [address, address + size) ran. Only the bytes the program wrote
        // count as code it made; an execution never reaches a region that
        // starts above it.
        void executed(uint64_t address, size_t size)
        {
            const uint64_t end = saturating_end(address, size);
            auto it = m_regions.upper_bound(address);
            while ( it != m_regions.begin() )
            {
                --it;
                const uint64_t s = it->first;
                if ( address - s >= kMaximumRegion )
                    break;
                Region &r = it->second;
                const uint64_t t = r.end(s);
                if ( t <= address )
                    continue;
                const size_t from = size_t(address - s);
                const size_t to   = size_t(std::min(t, end) - s);
                for ( size_t k = from; k < to; k++ )
                    if ( r.known[k] )
                        r.exec[k] = 1;
            }
        }

        // Memory in [address, address + size) was mapped, unmapped or
        // remapped: what the regions held there is gone. Each region's part
        // in the range is reported now, as it stood, and forgotten.
        void mapping_changed(uint64_t address, uint64_t size)
        {
            if ( size == 0 )
                return;
            const uint64_t end = address > UINT64_MAX - size ? UINT64_MAX : address + size;
            for ( auto it = m_regions.begin(); it != m_regions.end() && it->first < end; )
            {
                const uint64_t s = it->first;
                Region &r = it->second;
                const uint64_t t = r.end(s);
                if ( t <= address )
                {
                    ++it;
                    continue;
                }
                const size_t from = size_t(std::max(s, address) - s);
                const size_t to   = size_t(std::min(t, end) - s);
                emit(s, r, from, to);
                bool any = false;
                for ( size_t k = 0; k < r.bytes.size(); k++ )
                {
                    if ( k >= from && k < to )
                    {
                        r.known[k] = 0;
                        r.exec[k]  = 0;
                    }
                    any = any || r.known[k] != 0;
                }
                if ( any )
                {
                    ++it;
                }
                else
                {
                    m_order.erase(order_key(s, r));
                    it = m_regions.erase(it);
                }
            }
        }

        // The end of the recording: every region still open is reported.
        void finish()
        {
            for ( const auto &[s, r] : m_regions )
                emit(s, r, 0, r.bytes.size());
            m_regions.clear();
            m_order.clear();
        }

    private:
        static constexpr uint64_t kGap          = 16;      // how far apart writes may be and still join
        static constexpr size_t   kMaxRegions   = 16384;   // active at once
        static constexpr size_t   kSmallRegion  = 512;     // evicted before longer ones
        static constexpr size_t   kMaxResults   = 20000;
        static constexpr size_t   kMinSegment   = 16;
        static constexpr size_t   kMinText      = 32;
        static constexpr size_t   kMinEntropy   = 256;
        static constexpr size_t   kMinBuffer    = 512;
        static constexpr size_t   kMinAscii     = 16;      // printable bytes, for ascii_string
        static constexpr size_t   kMinWideBytes = 24;      // bytes of pairs, for utf16le_string
        static constexpr size_t   kMaxStrings   = 128;     // of each kind, per segment
        static constexpr size_t   kMaxEmbedded  = 64;      // per segment
        static constexpr size_t   kTextPreview  = 48;
        static constexpr size_t   kWidePreview  = 96;
        static constexpr size_t   kPemWindow    = 128;

        // One region. Its start is the key it is stored under. The flags are
        // per byte: 'known' when the program wrote it (bytes gained by
        // growing over a gap are not), 'exec' when a known byte later ran.
        struct Region
        {
            std::vector<uint8_t> bytes, known, exec;
            Pos                  first, last;
            uint64_t             last_clock = 0;
            uint64_t             writer_ip = 0;
            uint64_t             writes = 0;

            uint64_t end(uint64_t start) const { return start + bytes.size(); }
        };
        using Regions = std::map<uint64_t, Region>;

        // Eviction order: short regions first, then the one written longest
        // ago, then the lowest start. std::set keeps it sorted as regions
        // change, so finding the victim does not walk every region.
        using OrderKey = std::tuple<int, uint64_t, uint64_t>;

        uint64_t           m_nearby;
        Regions            m_regions;
        std::set<OrderKey> m_order;

        static OrderKey order_key(uint64_t start, const Region &r)
        {
            return OrderKey(r.bytes.size() < kSmallRegion ? 0 : 1, r.last_clock, start);
        }

        static uint64_t saturating_end(uint64_t address, uint64_t size)
        {
            return address > UINT64_MAX - size ? UINT64_MAX : address + size;
        }

        // The region a write at 'address' may belong to: the one starting at
        // or below it if that ends no more than kGap before it, else the
        // next one up. The caller still checks that one is close enough.
        typename Regions::iterator candidate(uint64_t address)
        {
            auto next = m_regions.upper_bound(address);
            if ( next != m_regions.begin() )
            {
                auto prev = std::prev(next);
                if ( prev->second.end(prev->first) + kGap >= address )
                    return prev;
            }
            return next;
        }

        // Whether the write puts a different value over a byte that already
        // ran: new code over old, so what ran is reported as it was.
        static bool rewrites_executed(uint64_t s, const Region &r, uint64_t address, const uint8_t *bytes, size_t size)
        {
            const uint64_t lo = std::max(s, address);
            const uint64_t hi = std::min(r.end(s), address + size);
            for ( uint64_t a = lo; a < hi; a++ )
            {
                const size_t k = size_t(a - s);
                if ( r.exec[k] && r.bytes[k] != bytes[a - address] )
                    return true;
            }
            return false;
        }

        void grow(typename Regions::iterator it, uint64_t lo, uint64_t hi, uint64_t address,
                  const uint8_t *bytes, size_t size, uint64_t clock, const Pos &pos, uint64_t ip)
        {
            const uint64_t s = it->first;
            m_order.erase(order_key(s, it->second));
            // A region growing downwards changes its key. No other region
            // can start at 'lo' then: it would have been the candidate.
            Region r = std::move(it->second);
            if ( lo != s )
            {
                m_regions.erase(it);
                const size_t front = size_t(s - lo);
                r.bytes.insert(r.bytes.begin(), front, 0);
                r.known.insert(r.known.begin(), front, 0);
                r.exec.insert(r.exec.begin(), front, 0);
            }
            const size_t length = size_t(hi - lo);
            r.bytes.resize(length, 0);
            r.known.resize(length, 0);
            r.exec.resize(length, 0);
            const size_t at = size_t(address - lo);
            memcpy(r.bytes.data() + at, bytes, size);
            std::fill_n(r.known.begin() + at, size, uint8_t(1));
            std::fill_n(r.exec.begin() + at, size, uint8_t(0));
            r.last_clock = clock;
            r.last       = pos;
            r.writer_ip  = ip;
            r.writes++;
            m_order.insert(order_key(lo, r));
            if ( lo != s )
                m_regions.emplace(lo, std::move(r));
            else
                it->second = std::move(r);
        }

        void start_region(uint64_t address, const uint8_t *bytes, size_t size, uint64_t clock,
                          const Pos &pos, uint64_t ip)
        {
            auto old = m_regions.find(address);
            if ( old != m_regions.end() )
                retire(old);
            Region r;
            r.bytes.assign(bytes, bytes + size);
            r.known.assign(size, 1);
            r.exec.assign(size, 0);
            r.first      = pos;
            r.last       = pos;
            r.last_clock = clock;
            r.writer_ip  = ip;
            r.writes     = 1;
            m_order.insert(order_key(address, r));
            m_regions.emplace(address, std::move(r));
            if ( m_regions.size() > kMaxRegions )
            {
                const uint64_t victim = std::get<2>(*m_order.begin());
                retire(m_regions.find(victim));
            }
        }

        // Report a region and forget it.
        void retire(typename Regions::iterator it)
        {
            emit(it->first, it->second, 0, it->second.bytes.size());
            m_order.erase(order_key(it->first, it->second));
            m_regions.erase(it);
        }

        // ---- reporting ------------------------------------------------------

        // Bytes [from, to) of the region starting at 's', one segment (run
        // of known bytes) at a time.
        void emit(uint64_t s, const Region &r, size_t from, size_t to)
        {
            size_t i = from;
            while ( i < to )
            {
                if ( !r.known[i] )
                {
                    i++;
                    continue;
                }
                size_t e = i;
                while ( e < to && r.known[e] )
                    e++;
                if ( e - i >= kMinSegment )
                    emit_segment(s + i, r, i, e - i);
                i = e;
            }
        }

        void emit_segment(uint64_t address, const Region &r, size_t begin, size_t n)
        {
            const uint8_t *p = r.bytes.data() + begin;
            const bool text = is_text(p, n);

            std::string kind = signature(p, n);
            if ( kind.empty() )
            {
                if ( std::find(r.exec.begin() + begin, r.exec.begin() + begin + n, uint8_t(1))
                     != r.exec.begin() + begin + n )
                    kind = "contains_executed_code";
                else if ( text )
                    kind = "ascii_text";
                else if ( is_wide_text(p, n) )
                    kind = "utf16le_text";
                else if ( n >= kMinEntropy && entropy(p, n) >= 7.5 )
                    kind = "high_entropy_buffer";
                else if ( n >= kMinBuffer )
                    kind = "buffer";
            }
            if ( !kind.empty() )
                record(r, address, p, n, kind, text ? Preview::text : Preview::hex);

            // ASCII strings: runs of printable bytes, bounded by the
            // segment. The one run that is the whole of a text segment would
            // only repeat it.
            size_t count = 0;
            for ( size_t i = 0; i < n && count < kMaxStrings; )
            {
                if ( !detail::printable(p[i]) )
                {
                    i++;
                    continue;
                }
                size_t e = i;
                while ( e < n && detail::printable(p[e]) )
                    e++;
                if ( e - i >= kMinAscii && !(text && i == 0 && e == n) )
                {
                    record(r, address + i, p + i, e - i, "ascii_string", Preview::text);
                    count++;
                }
                i = e;
            }

            // UTF-16LE strings: the walk skips past each run of pairs, long
            // enough or not, so a run is only ever looked at from its start.
            count = 0;
            for ( size_t i = 0; i + 1 < n && count < kMaxStrings; )
            {
                if ( !detail::wide_pair(p, n, i) || (i >= 2 && detail::wide_pair(p, n, i - 2)) )
                {
                    i++;
                    continue;
                }
                size_t k = i;
                while ( detail::wide_pair(p, n, k) )
                    k += 2;
                if ( k - i >= kMinWideBytes )
                {
                    record(r, address + i, p + i, k - i, "utf16le_string", Preview::wide);
                    count++;
                }
                i = k;
            }

            // Files inside the segment, past its first byte (a file at the
            // start is the segment's own kind). The first-byte test is only
            // a quick filter for the signatures worth looking for here.
            count = 0;
            for ( size_t i = 1; i + 16 < n && count < kMaxEmbedded; i++ )
            {
                const uint8_t b = p[i];
                if ( b != 'M' && b != 0x89 && b != 'G' && b != '%' && b != 'P' && b != 'S' && b != '-' )
                    continue;
                const std::string inner = signature(p + i, n - i);
                if ( inner.empty() || inner == "bmp_image" || inner == "jpeg_image" )
                    continue;
                record(r, address + i, p + i, n - i, inner, Preview::hex);
                count++;
            }
        }

        enum class Preview { text, hex, wide };

        void record(const Region &r, uint64_t address, const uint8_t *p, size_t n,
                    const std::string &kind, Preview style)
        {
            if ( n == 0 )
                return;
            if ( results.size() >= kMaxResults )
            {
                truncated = true;
                return;
            }
            FoundBuffer<Pos> f;
            f.address   = address;
            f.size      = n;
            f.first     = r.first;
            f.last      = r.last;
            f.writer_ip = r.writer_ip;
            f.writes    = r.writes;
            f.kind      = kind;
            f.preview   = preview(p, n, style);
            results.push_back(std::move(f));
        }

        static std::string preview(const uint8_t *p, size_t n, Preview style)
        {
            std::string out;
            if ( style == Preview::wide )
            {
                // The characters' low bytes, as they are.
                const size_t limit = std::min(n, kWidePreview);
                for ( size_t k = 0; k + 1 < limit; k += 2 )
                    out.push_back(char(p[k]));
                return out;
            }
            const size_t limit = std::min(n, kTextPreview);
            static const char hex[] = "0123456789abcdef";
            for ( size_t k = 0; k < limit; k++ )
            {
                if ( style == Preview::text )
                {
                    out.push_back(detail::printable(p[k]) ? char(p[k]) : '.');
                }
                else
                {
                    out.push_back(hex[p[k] >> 4]);
                    out.push_back(hex[p[k] & 0xF]);
                }
            }
            return out;
        }

        // ---- classification ---------------------------------------------------
        // The percentage tests stay in integers so that a boundary case
        // comes out the same on every compiler.

        static bool is_text(const uint8_t *p, size_t n)
        {
            if ( n < kMinText )
                return false;
            const size_t printable = size_t(std::count_if(p, p + n, detail::printable));
            return printable * 100 >= n * 90;
        }

        // Pairs counted at even offsets only, as an aligned UTF-16 text has
        // them.
        static bool is_wide_text(const uint8_t *p, size_t n)
        {
            if ( n < kMinText )
                return false;
            size_t pairs = 0;
            for ( size_t k = 0; k + 1 < n; k += 2 )
                if ( detail::wide_pair(p, n, k) )
                    pairs++;
            return pairs * 100 >= (n / 2) * 85;
        }

        // Shannon entropy in bits per byte.
        static double entropy(const uint8_t *p, size_t n)
        {
            size_t counts[256] = {};
            for ( size_t k = 0; k < n; k++ )
                counts[p[k]]++;
            double h = 0.0;
            for ( size_t c : counts )
            {
                if ( c == 0 )
                    continue;
                const double q = double(c) / double(n);
                h -= q * std::log2(q);
            }
            return h;
        }

        // The kind of file [p, p + n) begins with; empty when none.
        static std::string signature(const uint8_t *p, size_t n)
        {
            if ( n >= 64 && p[0] == 'M' && p[1] == 'Z' )
            {
                // The PE header the DOS header points at must lie inside.
                const uint32_t e = uint32_t(p[0x3C]) | uint32_t(p[0x3D]) << 8
                                 | uint32_t(p[0x3E]) << 16 | uint32_t(p[0x3F]) << 24;
                if ( e <= n - 4 && memcmp(p + e, "PE\0\0", 4) == 0 )
                    return "pe_image";
            }
            if ( detail::starts_with(p, n, "\x7F" "ELF", 4) )
                return "elf_image";
            if ( detail::starts_with(p, n, "\x89" "PNG\r\n\x1A\n", 8) )
                return "png_image";
            if ( detail::starts_with(p, n, "\xFF\xD8\xFF", 3) )
                return "jpeg_image";
            if ( detail::starts_with(p, n, "GIF8", 4) )
                return "gif_image";
            if ( detail::starts_with(p, n, "BM", 2) )
                return "bmp_image";
            if ( detail::starts_with(p, n, "%PDF-", 5) )
                return "pdf_document";
            if ( detail::starts_with(p, n, "PK\x03\x04", 4) )
                return "zip_archive";
            if ( detail::starts_with(p, n, "\x1F\x8B\x08", 3) )
                return "gzip_stream";
            if ( detail::starts_with(p, n, "SQLite format 3\0", 16) )
                return "sqlite_database";
            if ( detail::starts_with(p, n, "-----BEGIN ", 11) )
            {
                const size_t window = std::min(n, kPemWindow);
                if ( detail::contains(p, window, "PRIVATE KEY-----") )
                    return "pem_private_key";
                if ( detail::contains(p, window, "PUBLIC KEY-----") )
                    return "pem_public_key";
            }
            return std::string();
        }
    };
}
