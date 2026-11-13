// SPDX-License-Identifier: GPL-2.0-only
//
// ida-ttd's Sogen backend: a cursor's memory reads, and the page cache
// its cursors share.
// See sogen_state.h.

#include "backend-sogen/sogen_state.h"

namespace idattd::sogen
{
    constexpr size_t   kMaxCachedPages = 8192;      // 64 MiB of bytes and flags

    // Narrow [*from, *to] around 'position' by every change to the mapping
    // of 'page' (memory freed and allocated again reads as zeros with no
    // write): the latest at or before the position raises 'from', the first
    // after it lowers 'to' to just before it.
    void narrow_by_mapping(const region_index &regions, uint64_t page, uint64_t position,
                           uint64_t *from, uint64_t *to)
    {
        regions.for_each(page, page + kPage, [&](uint64_t step)
        {
            if ( step <= position && step > *from )
                *from = step;
            else if ( step > position && step - 1 < *to )
                *to = step - 1;
        });
    }

    // The positions around 'position' over which the page cannot change: from
    // the last write to it at or before the position to just before the next,
    // narrowed by any mapping change in between. MMIO is read from its
    // accesses, reads included, so for an MMIO page ('mmio') reads bound the
    // span too.
    void stable_span(ttd::trace &t, const region_index &regions, uint64_t page, uint64_t position, bool mmio,
                     uint64_t *from, uint64_t *to)
    {
        uint64_t W = (uint64_t)ttd::access_kind::write | (uint64_t)ttd::access_kind::host_write;
        if ( mmio )
            W |= (uint64_t)ttd::access_kind::read;
        std::optional<ttd::access_event> before = t.previous_access(page, kPage, position + 1, W);
        std::optional<ttd::access_event> after  = t.next_access(page, kPage, position, W);
        *from = before ? before->step : 0;
        *to   = after ? after->step - 1 : UINT64_MAX;
        narrow_by_mapping(regions, page, position, from, to);
    }

    // Drop the least recently used half once the cache is full.
    void trim(page_cache &pc)
    {
        if ( pc.count <= kMaxCachedPages )
            return;
        std::vector<uint64_t> uses;
        uses.reserve(pc.count);
        for ( auto &[page, v] : pc.pages )
            for ( const cached_page &e : v )
                uses.push_back(e.used);
        std::nth_element(uses.begin(), uses.begin() + uses.size() / 2, uses.end());
        uint64_t cut = uses[uses.size() / 2];
        for ( auto it = pc.pages.begin(); it != pc.pages.end(); )
        {
            auto &v = it->second;
            size_t before = v.size();
            v.erase(std::remove_if(v.begin(), v.end(), [cut](const cached_page &e) { return e.used < cut; }),
                    v.end());
            pc.count -= before - v.size();
            it = v.empty() ? pc.pages.erase(it) : std::next(it);
        }
    }

    // An MMIO page as of 'position', from the accesses within kMmioWindow
    // steps of it. memory_at shows a byte of MMIO by the latest access up to
    // the position, else the first after it, and a byte no access touches
    // sends it through every access to the page in the recording, both ways.
    // KUSER_SHARED_DATA is MMIO in Sogen recordings, read all the time, and
    // most of it never: a 0x400-byte read there took 24 s in a 488 MB
    // recording, at every step that crossed one of its reads (the cached page
    // holds only between accesses). Bytes not shown within the window are
    // left unknown here; read_page fills them from other reads of the page.
    static const uint64_t kMmioWindow = 1ull << 20;

    void mmio_page_near(ttd::trace &t, const region_index &regions, uint64_t page, uint64_t position,
                        uint8_t *dst, uint8_t *kn)
    {
        memset(dst, 0, kPage);
        memset(kn, 0, kPage);
        // Not across a change to the page's mapping.
        uint64_t lo = position > kMmioWindow ? position - kMmioWindow : 0;
        uint64_t hi = position + kMmioWindow;
        narrow_by_mapping(regions, page, position, &lo, &hi);
        const uint64_t W = (uint64_t)ttd::access_kind::write | (uint64_t)ttd::access_kind::host_write;
        auto bytes_of = [&t](const ttd::access_event &e) -> std::vector<std::byte>
        {
            if ( e.kind == ttd::access_kind::execute )
            {
                const std::byte *p = reinterpret_cast<const std::byte *>(e.payload.data());
                return std::vector<std::byte>(p, p + std::min<uint64_t>(e.size, e.payload.size()));
            }
            return t.access_data(e);
        };
        auto by_step = [](const ttd::access_event &a, const ttd::access_event &b) { return a.step < b.step; };

        // The latest access up to the position shows a byte.
        std::vector<ttd::access_event> before = t.accesses(page, kPage, lo, position);
        std::stable_sort(before.begin(), before.end(), by_step);
        for ( const ttd::access_event &e : before )
        {
            std::vector<std::byte> d = bytes_of(e);
            for ( uint64_t a = std::max(e.address, page); a < std::min(e.address + e.size, page + kPage); a++ )
            {
                const size_t i = (size_t)(a - e.address);
                if ( i < d.size() )
                {
                    dst[a - page] = (uint8_t)d[i];
                    kn[a - page]  = 1;
                }
            }
        }
        // Any other byte still holds what the first later read shows, unless
        // something wrote it first.
        if ( position >= hi )
            return;
        std::vector<bool> settled(kPage);
        for ( size_t i = 0; i < kPage; i++ )
            settled[i] = kn[i] != 0;
        std::vector<ttd::access_event> after = t.accesses(page, kPage, position + 1, hi);
        std::stable_sort(after.begin(), after.end(), by_step);
        for ( const ttd::access_event &e : after )
        {
            const bool shows = ((uint64_t)e.kind & W) == 0;
            std::vector<std::byte> d;
            for ( uint64_t a = std::max(e.address, page); a < std::min(e.address + e.size, page + kPage); a++ )
            {
                const size_t o = (size_t)(a - page);
                if ( settled[o] )
                    continue;
                settled[o] = true;
                if ( !shows )
                    continue;
                if ( d.empty() )
                    d = bytes_of(e);
                const size_t i = (size_t)(a - e.address);
                if ( i < d.size() )
                {
                    dst[o] = (uint8_t)d[i];
                    kn[o]  = 1;
                }
            }
        }
    }

    // The page at 'page' as of the cursor's position, from the cache or from
    // memory_at. 'dst' and 'kn' receive kPage bytes each.
    void read_page(cursor_t *c, uint64_t page, uint8_t *dst, uint8_t *kn)
    {
        page_cache &pc = c->owner->pages;
        {
            std::lock_guard<std::mutex> lock(pc.mtx);
            auto it = pc.pages.find(page);
            if ( it != pc.pages.end() )
                for ( cached_page &e : it->second )
                    if ( e.from <= c->position && c->position <= e.to )
                    {
                        e.used = ++pc.clock;
                        memcpy(dst, e.bytes.data(), kPage);
                        memcpy(kn, e.known.data(), kPage);
                        return;
                    }
        }

        // Never caching MMIO pages made every read of KUSER_SHARED_DATA (MMIO
        // in Sogen recordings, and read constantly by IDA's analysis of
        // ntdll) cost over a second, freezing IDA. They are cached over the
        // shorter span between accesses instead.
        bool mmio = false, all_mmio = false;
        for ( const auto &[lo, hi] : c->owner->mmio )
            if ( lo < page + kPage && page < hi )
            {
                mmio = true;
                all_mmio = all_mmio || (lo <= page && page + kPage <= hi);
            }

        const region_index &regions = c->owner->regions;
        cached_page e;
        e.bytes.assign(kPage, 0);
        e.known.assign(kPage, 0);
        if ( all_mmio )
        {
            // From the accesses near the position (mmio_page_near). What they
            // do not show comes from the page's other cached reads, nearest
            // first: most of KUSER_SHARED_DATA is read once, as the process
            // starts, and never changes. The first read of the page also
            // reads it at the start for that.
            mmio_page_near(*c->trace, regions, page, c->position, e.bytes.data(), e.known.data());
            bool cached = false;
            {
                std::lock_guard<std::mutex> lock(pc.mtx);
                auto it = pc.pages.find(page);
                cached = it != pc.pages.end() && !it->second.empty();
            }
            std::optional<cached_page> start;
            if ( !cached && c->position > kMmioWindow )
            {
                start.emplace();
                start->bytes.assign(kPage, 0);
                start->known.assign(kPage, 0);
                mmio_page_near(*c->trace, regions, page, 0, start->bytes.data(), start->known.data());
                stable_span(*c->trace, regions, page, 0, true, &start->from, &start->to);
                for ( size_t i = 0; i < kPage; i++ )
                    if ( start->known[i] )
                        start->known_at.push_back((uint16_t)i);
            }
            std::lock_guard<std::mutex> lock(pc.mtx);
            if ( start.has_value() )
            {
                start->used = ++pc.clock;
                pc.pages[page].push_back(std::move(*start));
                pc.count++;
            }
            // The other versions are read in place, under the lock, instead
            // of copied out a page each.
            std::vector<const cached_page *> others;
            if ( auto it = pc.pages.find(page); it != pc.pages.end() )
                for ( const cached_page &o : it->second )
                    others.push_back(&o);
            auto distance = [&](const cached_page *o)
            {
                return c->position < o->from ? o->from - c->position
                     : c->position > o->to   ? c->position - o->to : 0;
            };
            std::sort(others.begin(), others.end(),
                      [&](const cached_page *a, const cached_page *b) { return distance(a) < distance(b); });
            for ( const cached_page *o : others )
                for ( uint16_t i : o->known_at )
                    if ( !e.known[i] )
                    {
                        e.bytes[i] = o->bytes[i];
                        e.known[i] = 1;
                    }
            for ( size_t i = 0; i < kPage; i++ )
                if ( e.known[i] )
                    e.known_at.push_back((uint16_t)i);
        }
        else
        {
            std::vector<std::optional<uint8_t>> v = c->trace->memory_at(c->position, page, kPage);
            for ( size_t i = 0; i < kPage && i < v.size(); i++ )
                if ( v[i] )
                {
                    e.bytes[i] = *v[i];
                    e.known[i] = 1;
                }
        }
        memcpy(dst, e.bytes.data(), kPage);
        memcpy(kn, e.known.data(), kPage);
        stable_span(*c->trace, regions, page, c->position, mmio, &e.from, &e.to);

        std::lock_guard<std::mutex> lock(pc.mtx);
        e.used = ++pc.clock;
        pc.pages[page].push_back(std::move(e));
        pc.count++;
        trim(pc);
    }

    int cursor_read_memory(ittd_cursor *hc, uint64_t ea, void *buf, uint8_t *known,
                           size_t size, size_t *out_known)
    {
        cursor_t *c = C(hc);
        if ( c == nullptr || (buf == nullptr && size != 0) )
            return ITTD_E_BAD_ARG;
        return guarded(c->owner->error, [&]()
        {
            uint8_t page[kPage], kn[kPage];
            uint8_t *dst = static_cast<uint8_t *>(buf);
            // A request past the top of the address space reads up to it and
            // marks the rest unknown. (Comparing against ea + size wrapped,
            // read nothing and left 'known' unwritten.)
            const uint64_t room = ea == 0 ? UINT64_MAX : 0ull - ea;
            const size_t   span = (size_t)std::min<uint64_t>(size, room);
            size_t n = 0;
            for ( size_t done = 0; done < span; )
            {
                const uint64_t a    = ea + done;
                const uint64_t base = a & ~(kPage - 1);
                const size_t   off  = (size_t)(a - base);
                const size_t   take = std::min<size_t>(kPage - off, span - done);
                read_page(c, base, page, kn);
                for ( size_t i = 0; i < take; i++ )
                {
                    if ( kn[off + i] )
                    {
                        dst[done + i] = page[off + i];
                        n++;
                    }
                    if ( known != nullptr )
                        known[done + i] = kn[off + i] ? 1 : 0;
                }
                done += take;
            }
            if ( known != nullptr && span < size )
                std::memset(known + span, 0, size - span);
            if ( out_known != nullptr )
                *out_known = n;
            return ITTD_OK;
        });
    }
}
