#include "analysis/fork_registry.h"
#include "common/dbstore.h"

namespace idattd
{
    static const char FR_NODE[]  = "$ ida-ttd forks";
    static const uchar    FR_TAG     = 'F';
    static const uint32_t FR_MAGIC   = 0x4B524F46;  // 'FORK'
    static const uint32_t FR_VERSION = 1;
    static const uint32_t FR_MAX     = 10000;

    std::vector<ForkRecord> load_fork_records()
    {
        std::vector<ForkRecord> out;
        PluginNode node(FR_NODE);
        std::vector<uchar> blob;
        // Not tied to one recording: the records span several.
        if ( !node.exists() || !node.get(FR_TAG, FR_MAGIC, FR_VERSION, 0, &blob) )
            return out;
        BlobReader r(blob.data(), blob.size());
        uint32_t count = r.u32();
        if ( !r.ok() || count > FR_MAX )
            return out;
        for ( uint32_t i = 0; i < count; i++ )
        {
            ForkRecord f;
            r.str(&f.path);
            r.str(&f.parent);
            r.str(&f.at);
            r.str(&f.changes);
            f.instructions = r.u64();
            f.time         = r.u64();
            if ( !r.ok() )
                break;
            out.push_back(std::move(f));
        }
        return out;
    }

    static void save_fork_records(const std::vector<ForkRecord> &v)
    {
        PluginNode node(FR_NODE);
        if ( v.empty() )
        {
            node.erase(FR_TAG);
            return;
        }
        BlobWriter w;
        w.u32((uint32_t)v.size());
        for ( const ForkRecord &f : v )
        {
            w.str(f.path);
            w.str(f.parent);
            w.str(f.at);
            w.str(f.changes);
            w.u64(f.instructions);
            w.u64(f.time);
        }
        node.put(FR_TAG, FR_MAGIC, FR_VERSION, w, 0);
    }

    bool same_trace_path(const qstring &a, const qstring &b)
    {
        if ( a.length() != b.length() )
            return false;
        for ( size_t i = 0; i < a.length(); i++ )
        {
            char x = a[i] == '/' ? '\\' : qtolower(a[i]);
            char y = b[i] == '/' ? '\\' : qtolower(b[i]);
            if ( x != y )
                return false;
        }
        return true;
    }

    void add_fork_record(const ForkRecord &r)
    {
        std::vector<ForkRecord> v = load_fork_records();
        v.erase(std::remove_if(v.begin(), v.end(),
                               [&](const ForkRecord &f) { return same_trace_path(f.path, r.path); }),
                v.end());
        v.push_back(r);
        save_fork_records(v);
    }

    void remove_fork_record(const char *path)
    {
        qstring p(path != nullptr ? path : "");
        std::vector<ForkRecord> v = load_fork_records();
        v.erase(std::remove_if(v.begin(), v.end(),
                               [&](const ForkRecord &f) { return same_trace_path(f.path, p); }),
                v.end());
        save_fork_records(v);
    }
}
