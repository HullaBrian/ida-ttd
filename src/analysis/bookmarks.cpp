#include "analysis/bookmarks.h"

using namespace TTD;
using namespace TTD::Replay;

namespace idattd
{
    // IDB storage. The "$ " prefix is the SDK's convention for a plugin-owned
    // netnode, so the name can never collide with a program byte name.
    static const char BM_NODE[]  = "$ ida-ttd bookmarks";
    static const nodeidx_t BM_IDX = 0;
    static const uchar     BM_TAG = 'B';

    // Blob layout. Versioned from the start: a bookmark list is user-authored
    // data that has to survive the plugin changing shape around it, and the
    // reader below rejects anything it does not recognise rather than guessing.
    //   u32 magic, u32 version, u32 count
    //   count * { u64 sequence, u64 steps, u64 ea, u32 tid, str name, str comment }
    // where str = u32 length followed by that many bytes, no terminator.
    static const uint32_t BM_MAGIC   = 0x4B4D4254;  // 'TBMK'
    static const uint32_t BM_VERSION = 1;

    // A bookmark list is small, but the blob is IDB data and IDB data can be
    // stale, truncated or written by something else entirely. Cap what we are
    // willing to believe before allocating from it.
    static const uint32_t BM_MAX_ITEMS = 100000;
    static const uint32_t BM_MAX_STR   = 4096;

    static void put_u32(bytevec_t &b, uint32_t v)
    {
        for ( int i = 0; i < 4; i++ )
            b.push_back((uchar)((v >> (i * 8)) & 0xFF));
    }

    static void put_u64(bytevec_t &b, uint64_t v)
    {
        for ( int i = 0; i < 8; i++ )
            b.push_back((uchar)((v >> (i * 8)) & 0xFF));
    }

    static void put_str(bytevec_t &b, const qstring &s)
    {
        uint32_t n = (uint32_t)qmin(s.length(), (size_t)BM_MAX_STR);
        put_u32(b, n);
        for ( uint32_t i = 0; i < n; i++ )
            b.push_back((uchar)s[i]);
    }

    // Bounds-checked reader over the blob. Every get_* returns false rather than
    // reading past the end, and one false abandons the whole parse.
    struct BlobReader
    {
        const uchar *p   = nullptr;
        size_t       n   = 0;
        size_t       off = 0;

        bool get_u32(uint32_t *out)
        {
            if ( off + 4 > n )
                return false;
            *out = (uint32_t)p[off] | ((uint32_t)p[off + 1] << 8)
                 | ((uint32_t)p[off + 2] << 16) | ((uint32_t)p[off + 3] << 24);
            off += 4;
            return true;
        }

        bool get_u64(uint64_t *out)
        {
            uint32_t lo = 0, hi = 0;
            if ( !get_u32(&lo) || !get_u32(&hi) )
                return false;
            *out = (uint64_t)lo | ((uint64_t)hi << 32);
            return true;
        }

        bool get_str(qstring *out)
        {
            uint32_t len = 0;
            if ( !get_u32(&len) || len > BM_MAX_STR || off + len > n )
                return false;
            out->qclear();
            out->append((const char *)p + off, len);
            off += len;
            return true;
        }
    };

    void BookmarkStore::load()
    {
        m_loaded = true;
        m_items.clear();

        netnode nn(BM_NODE);
        if ( nn == BADNODE )
            return;                     // nothing saved in this database yet

        bytevec_t blob;
        if ( nn.getblob(&blob, BM_IDX, BM_TAG) <= 0 )
            return;

        BlobReader r{ blob.begin(), blob.size(), 0 };
        uint32_t magic = 0, version = 0, count = 0;
        if ( !r.get_u32(&magic) || magic != BM_MAGIC
          || !r.get_u32(&version) || version != BM_VERSION
          || !r.get_u32(&count) || count > BM_MAX_ITEMS )
        {
            msg("[ida-ttd] the bookmark record in this database is not one we "
                "understand; leaving it untouched.\n");
            return;
        }

        for ( uint32_t i = 0; i < count; i++ )
        {
            uint64_t seq = 0, steps = 0, ea = 0;
            uint32_t tid = 0;
            Bookmark b;
            if ( !r.get_u64(&seq) || !r.get_u64(&steps) || !r.get_u64(&ea)
              || !r.get_u32(&tid) || !r.get_str(&b.name) || !r.get_str(&b.comment) )
            {
                msg("[ida-ttd] the bookmark record ends early; recovered %d of %d "
                    "entries.\n", (int)m_items.size(), (int)count);
                break;
            }
            b.pos = Replay::Position{ (SequenceId)seq, (StepCount)steps };
            b.ea  = (ea_t)ea;
            b.tid = tid;
            m_items.push_back(b);
        }
    }

    void BookmarkStore::save() const
    {
        netnode nn(BM_NODE, 0, true);   // create on first save
        if ( nn == BADNODE )
        {
            warning("ida-ttd could not open its bookmark storage; this bookmark "
                    "will not survive closing the database.");
            return;
        }

        if ( m_items.empty() )
        {
            nn.delblob(BM_IDX, BM_TAG);
            return;
        }

        bytevec_t blob;
        put_u32(blob, BM_MAGIC);
        put_u32(blob, BM_VERSION);
        put_u32(blob, (uint32_t)m_items.size());
        for ( const Bookmark &b : m_items )
        {
            put_u64(blob, (uint64_t)b.pos.Sequence);
            put_u64(blob, (uint64_t)b.pos.Steps);
            put_u64(blob, (uint64_t)b.ea);
            put_u32(blob, b.tid);
            put_str(blob, b.name);
            put_str(blob, b.comment);
        }
        nn.setblob(blob.begin(), blob.size(), BM_IDX, BM_TAG);
    }

    size_t BookmarkStore::size()
    {
        if ( !m_loaded )
            load();
        return m_items.size();
    }

    const Bookmark *BookmarkStore::at(size_t i)
    {
        if ( !m_loaded )
            load();
        return i < m_items.size() ? &m_items[i] : nullptr;
    }

    size_t BookmarkStore::add(const Bookmark &b)
    {
        if ( !m_loaded )
            load();
        // Ordered by position, so the list reads as a walk through the recording
        // no matter what order the analyst dropped the marks in.
        auto it = std::lower_bound(m_items.begin(), m_items.end(), b,
                                   [](const Bookmark &a, const Bookmark &c)
                                   { return a.pos < c.pos; });
        size_t idx = (size_t)(it - m_items.begin());
        m_items.insert(it, b);
        save();
        return idx;
    }

    void BookmarkStore::update(size_t i, const Bookmark &b)
    {
        if ( !m_loaded )
            load();
        if ( i >= m_items.size() )
            return;
        m_items[i] = b;
        save();
    }

    void BookmarkStore::remove(size_t i)
    {
        if ( !m_loaded )
            load();
        if ( i >= m_items.size() )
            return;
        m_items.erase(m_items.begin() + i);
        save();
    }
}
