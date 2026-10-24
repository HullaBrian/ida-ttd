#include "analysis/bookmarks.h"
#include "analysis/trace_store.h"
#include "common/dbstore.h"

namespace idattd
{
    // IDB storage. The "$ " prefix is the SDK's convention for a plugin-owned
    // netnode, so the name can never collide with a program byte name.
    static const char BM_NODE[]  = "$ ida-ttd bookmarks";
    static const nodeidx_t BM_IDX = 0;
    static const uchar     BM_TAG = 'B';

    // Blob layout. Versioned because bookmarks are user data that must survive
    // plugin changes; the reader rejects anything it does not recognise.
    //   u32 magic, u32 version, u32 count
    //   count * { u64 sequence, u64 steps, u64 ea, u32 tid, str name, str comment,
    //             u64 trace (version 2 on) }
    // where str = u32 length followed by that many bytes, no terminator.
    // Version 1 is still read (marks without a recording); the next change
    // rewrites the list as version 2.
    static const uint32_t BM_MAGIC   = 0x4B4D4254;  // 'TBMK'
    static const uint32_t BM_VERSION = 2;

    // IDB data may be stale, truncated or foreign, so the count is capped
    // before anything is allocated from it. Strings are capped at DB_MAX_STR
    // (common/dbstore.h) on both sides.
    static const uint32_t BM_MAX_ITEMS = 100000;

    void BookmarkStore::load()
    {
        m_loaded  = true;
        m_foreign = false;
        m_items.clear();

        netnode nn(BM_NODE);
        if ( nn == BADNODE )
            return;                     // nothing saved in this database yet

        bytevec_t blob;
        if ( nn.getblob(&blob, BM_IDX, BM_TAG) <= 0 )
            return;

        // Not PluginNode::get(): bookmarks predate its header, and the blob
        // format is kept so existing databases keep their marks.
        BlobReader r(blob.begin(), blob.size());
        uint32_t magic   = r.u32();
        uint32_t version = r.u32();
        uint32_t count   = r.u32();
        if ( !r.ok() || magic != BM_MAGIC || version < 1 || version > BM_VERSION
          || count > BM_MAX_ITEMS )
        {
            msg("[ida-ttd] the bookmark record in this database is not one this "
                "build understands; leaving it untouched.\n");
            m_foreign = true;
            return;
        }

        for ( uint32_t i = 0; i < count; i++ )
        {
            Bookmark b;
            uint64_t seq   = r.u64();
            uint64_t steps = r.u64();
            uint64_t ea    = r.u64();
            uint32_t tid   = r.u32();
            r.str(&b.name);
            r.str(&b.comment);
            if ( version >= 2 )
                b.trace = r.u64();
            if ( !r.ok() )
            {
                msg("[ida-ttd] the bookmark record ends early; recovered %d of %d "
                    "entries.\n", (int)m_items.size(), (int)count);
                break;
            }
            b.pos = Position{ seq, steps };
            b.ea  = (ea_t)ea;
            b.tid = tid;
            m_items.push_back(b);
        }
    }

    void BookmarkStore::save() const
    {
        if ( m_foreign )
        {
            msg("[ida-ttd] bookmarks: not saved, so as not to overwrite the record "
                "this build could not read; the change lasts only for this session.\n");
            return;
        }
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

        BlobWriter w;
        w.u32(BM_MAGIC);
        w.u32(BM_VERSION);
        w.u32((uint32_t)m_items.size());
        for ( const Bookmark &b : m_items )
        {
            w.u64(b.pos.hi);
            w.u64(b.pos.lo);
            w.u64((uint64_t)b.ea);
            w.u32(b.tid);
            w.str(b.name);
            w.str(b.comment);
            w.u64(b.trace);
        }
        nn.setblob(w.data(), w.size(), BM_IDX, BM_TAG);
    }

    bool Bookmark::from_other_recording() const
    {
        uint64_t now = current_trace();
        return trace != 0 && now != 0 && trace != now;
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
        // Ordered by position, so the list reads as a walk through the recording.
        auto it = std::lower_bound(m_items.begin(), m_items.end(), b,
                                   [](const Bookmark &a, const Bookmark &c)
                                   { return a.pos < c.pos; });
        size_t idx = (size_t)(it - m_items.begin());
        m_items.insert(it, b);
        save();
        return idx;
    }

    size_t BookmarkStore::update(size_t i, const Bookmark &b)
    {
        if ( !m_loaded )
            load();
        if ( i >= m_items.size() )
            return i;
        // Taken out and inserted again, as in add(): the edit may have moved
        // it, and the list must stay in position order.
        m_items.erase(m_items.begin() + i);
        auto it = std::lower_bound(m_items.begin(), m_items.end(), b,
                                   [](const Bookmark &a, const Bookmark &c)
                                   { return a.pos < c.pos; });
        size_t idx = (size_t)(it - m_items.begin());
        m_items.insert(it, b);
        save();
        return idx;
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
