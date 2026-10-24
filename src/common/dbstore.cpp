#include "common/dbstore.h"

namespace idattd
{
    void BlobWriter::u32(uint32_t v)
    {
        for ( int i = 0; i < 4; i++ )
            m_b.push_back((uchar)((v >> (i * 8)) & 0xFF));
    }

    void BlobWriter::u64(uint64_t v)
    {
        for ( int i = 0; i < 8; i++ )
            m_b.push_back((uchar)((v >> (i * 8)) & 0xFF));
    }

    void BlobWriter::str(const qstring &s)
    {
        uint32_t n = (uint32_t)qmin(s.length(), (size_t)DB_MAX_STR);
        u32(n);
        for ( uint32_t i = 0; i < n; i++ )
            m_b.push_back((uchar)s[i]);
    }

    bool BlobReader::have(size_t k)
    {
        if ( !m_ok || m_off + k > m_n )
        {
            m_ok = false;
            return false;
        }
        return true;
    }

    uint8_t BlobReader::u8()
    {
        if ( !have(1) )
            return 0;
        return m_p[m_off++];
    }

    uint32_t BlobReader::u32()
    {
        if ( !have(4) )
            return 0;
        uint32_t v = 0;
        for ( int i = 0; i < 4; i++ )
            v |= (uint32_t)m_p[m_off++] << (i * 8);
        return v;
    }

    uint64_t BlobReader::u64()
    {
        uint32_t lo = u32();
        uint32_t hi = u32();
        return (uint64_t)lo | ((uint64_t)hi << 32);
    }

    bool BlobReader::str(qstring *out)
    {
        uint32_t len = u32();
        if ( !m_ok || len > DB_MAX_STR || !have(len) )
        {
            m_ok = false;
            return false;
        }
        out->qclear();
        out->append((const char *)m_p + m_off, len);
        m_off += len;
        return true;
    }

    bool PluginNode::exists() const
    {
        netnode nn(m_name);
        return nn != BADNODE;
    }

    void PluginNode::put(uchar tag, uint32_t magic, uint32_t version,
                         const BlobWriter &w, uint64_t fingerprint)
    {
        netnode nn(m_name, 0, true);   // create on first write
        if ( w.size() == 0 )
        {
            nn.delblob(0, tag);
            return;
        }
        // Header first, so a reader can reject a blob before parsing it.
        BlobWriter hdr;
        hdr.u32(magic);
        hdr.u32(version);
        hdr.u64(fingerprint);

        std::vector<uchar> buf;
        buf.reserve(hdr.size() + w.size());
        buf.insert(buf.end(), hdr.data(), hdr.data() + hdr.size());
        buf.insert(buf.end(), w.data(), w.data() + w.size());
        nn.setblob(buf.data(), buf.size(), 0, tag);
    }

    bool PluginNode::get(uchar tag, uint32_t magic, uint32_t version,
                         uint64_t fingerprint, std::vector<uchar> *out) const
    {
        netnode nn(m_name);
        if ( nn == BADNODE || out == nullptr )
            return false;

        size_t sz = 0;
        void *raw = nn.getblob(nullptr, &sz, 0, tag);
        if ( raw == nullptr )
            return false;

        BlobReader r(raw, sz);
        bool ok = r.u32() == magic && r.u32() == version;
        uint64_t stamp = r.u64();
        // A fingerprint of 0 on either side means "not tied to a recording".
        if ( ok && fingerprint != 0 && stamp != 0 && stamp != fingerprint )
            ok = false;
        if ( ok && r.ok() )
        {
            const uchar *p = (const uchar *)raw;
            out->assign(p + DB_HEADER_SIZE, p + sz);
        }
        else
        {
            ok = false;
        }
        qfree(raw);
        return ok;
    }

    void PluginNode::erase(uchar tag)
    {
        netnode nn(m_name);
        if ( nn != BADNODE )
            nn.delblob(0, tag);
    }

    nodeidx_t PluginNode::alt(nodeidx_t idx, uchar tag) const
    {
        netnode nn(m_name);
        return nn == BADNODE ? 0 : nn.altval(idx, tag);
    }

    void PluginNode::set_alt(nodeidx_t idx, nodeidx_t value, uchar tag)
    {
        netnode nn(m_name, 0, true);
        nn.altset(idx, value, tag);
    }

    void PluginNode::del_alt(nodeidx_t idx, uchar tag)
    {
        netnode nn(m_name);
        if ( nn != BADNODE )
            nn.altdel(idx, tag);
    }

    // Reserved tag, kept away from the tags a feature chooses for itself.
    static const uchar DB_STAMP_TAG = 'Z';

    uint64_t PluginNode::trace_stamp() const
    {
        return (uint64_t)alt(0, DB_STAMP_TAG);
    }

    void PluginNode::set_trace_stamp(uint64_t fingerprint)
    {
        set_alt(0, (nodeidx_t)fingerprint, DB_STAMP_TAG);
    }

    void PluginNode::each_alt(uchar tag,
                              const std::function<void(nodeidx_t, nodeidx_t)> &fn) const
    {
        netnode nn(m_name);
        if ( nn == BADNODE )
            return;
        for ( nodeidx_t i = nn.altfirst(tag); i != BADNODE; i = nn.altnext(i, tag) )
            fn(i, nn.altval(i, tag));
    }
}
