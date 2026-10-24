#pragma once

#include "common/pch.h"

namespace idattd
{
    // Plugin data in the database (bookmarks, coverage, resolved call sites,
    // the memory map), with one shared encoding.
    //
    // Everything read back is untrusted: a blob can be stale, truncated, or
    // from another plugin version. The reader bounds-checks every field and
    // one failure abandons the whole parse.

    // Little-endian writer. Values are appended in the order the reader expects.
    class BlobWriter
    {
    public:
        void u8(uint8_t v)  { m_b.push_back(v); }
        void u32(uint32_t v);
        void u64(uint64_t v);
        // Length-prefixed, not NUL-terminated. Longer strings are truncated.
        void str(const qstring &s);

        const uchar *data() const { return m_b.begin(); }
        size_t       size() const { return m_b.size(); }

    private:
        bytevec_t m_b;
    };

    // Bounds-checked reader. Once ok() is false every further read returns zero
    // and the caller should discard whatever it has built.
    class BlobReader
    {
    public:
        BlobReader(const void *p, size_t n)
            : m_p((const uchar *)p), m_n(n) {}

        uint8_t  u8();
        uint32_t u32();
        uint64_t u64();
        bool     str(qstring *out);

        bool ok() const { return m_ok; }

    private:
        bool have(size_t k);

        const uchar *m_p = nullptr;
        size_t       m_n = 0;
        size_t       m_off = 0;
        bool         m_ok = true;
    };

    // Longest string any feature will write or believe.
    static const uint32_t DB_MAX_STR = 4096;

    // A plugin netnode, named "$ ..." so it cannot collide with a program byte
    // name.
    //
    // Blobs are stamped with the recording they came from, and reading one
    // back against another recording is refused: addresses and positions from
    // one execution mean nothing in another.
    class PluginNode
    {
    public:
        explicit PluginNode(const char *name) : m_name(name) {}

        // True when the node exists at all.
        bool exists() const;

        // Replace the blob under 'tag' with 'w', behind a header carrying
        // 'magic', 'version' and 'fingerprint'. A fingerprint of 0 means the
        // data does not depend on any one recording.
        void put(uchar tag, uint32_t magic, uint32_t version,
                 const BlobWriter &w, uint64_t fingerprint);
        // Read the blob under 'tag'. False when it is absent, when its header
        // does not match 'magic' and 'version', or when it was written against a
        // different recording. The caller owns nothing on failure.
        bool get(uchar tag, uint32_t magic, uint32_t version, uint64_t fingerprint,
                 std::vector<uchar> *out) const;

        void erase(uchar tag);

        // Plain scalar slots, for state small enough not to need a blob.
        nodeidx_t alt(nodeidx_t idx, uchar tag) const;
        void      set_alt(nodeidx_t idx, nodeidx_t value, uchar tag);
        void      del_alt(nodeidx_t idx, uchar tag);
        // Iterate the alt slots under 'tag', in index order.
        void      each_alt(uchar tag, const std::function<void(nodeidx_t idx, nodeidx_t val)> &fn) const;

        // Which recording this node's non-blob state came from (blobs carry
        // the header below instead); zero when unstamped. Callers stamp on
        // write and compare at session start.
        uint64_t trace_stamp() const;
        void     set_trace_stamp(uint64_t fingerprint);

    private:
        const char *m_name;
    };

    // Header every blob carries, written by put() and checked by get():
    //   u32 magic, u32 version, u64 trace fingerprint
    static const size_t DB_HEADER_SIZE = 16;
}
