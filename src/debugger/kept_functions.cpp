#include "debugger/kept_functions.h"
#include "debugger/module_registry.h"
#include "debugger/memory_reader.h"
#include "debugger/code_analyzer.h"
#include "common/dbstore.h"

// As in ui/decompiler.cpp: hexrays.hpp warns at this project's level in
// inline code the plugin never calls.
#pragma warning(push)
#pragma warning(disable: 4018)  // signed/unsigned mismatch
#pragma warning(disable: 4244)  // conversion, possible loss of data
#pragma warning(disable: 4267)  // size_t -> int, possible loss of data
#include <hexrays.hpp>
#pragma warning(pop)

namespace idattd
{
    // One netnode for every kept function. Functions are indexed by start
    // (alt KF_INDEX: start -> id), and each id's versions are one blob at
    // id << 16. Not at the start itself: a blob spans one supval per KiB, so
    // blobs at two starts a few bytes apart would overlap.
    static const char     KF_NODE[]       = "$ ida-ttd kept functions";
    static const uchar    KF_INDEX        = 'I';
    static const uchar    KF_COUNTER      = 'N';   // alt 0: the last id handed out
    static const uchar    KF_BLOB         = 'F';
    static const uint32_t KF_MAGIC        = 0x4B465431;   // "KFT1"
    static const uint32_t KF_VERSION      = 1;
    static const size_t   KF_MAX_VERSIONS = 8;     // per start, newest first
    static const size_t   KF_MAX_ITEMS    = 4096;  // comments and labels per function
    static const size_t   KF_MAX_LVARS    = 1024;
    static const uint64_t KF_MAX_BYTES    = 1u << 20;   // function bytes hashed
    static const int      KF_LOOKBACK     = 16;    // kept starts below a pc define_at tries

    static nodeidx_t blob_slot(nodeidx_t id) { return id << 16; }

    //=======================================================================
    // What is kept
    //=======================================================================
    struct Range
    {
        ea_t lo = 0, hi = 0;
    };

    // A type as tinfo_t::serialize writes it. Named types are referenced by
    // name, so they resolve against this database's local types again.
    struct TypeStr
    {
        bool    have = false;
        qstring type, fields, cmts;
    };

    // A Hex-Rays variable locator. Only the kinds a variable normally has
    // (stack, one or two registers, a global): the others hold pointers.
    struct Loc
    {
        uint8_t  atype = ALOC_NONE;
        uint64_t raw   = 0;            // argloc_t's union, for the kinds above
        uint64_t defea = BADADDR;
    };

    enum : uint8_t { IT_CMT = 0, IT_RPTCMT, IT_LABEL };
    struct Item
    {
        ea_t    ea   = BADADDR;
        uint8_t kind = IT_CMT;
        qstring text;
    };

    struct Lvar
    {
        Loc      ll;
        qstring  name;
        TypeStr  type;
        qstring  cmt;
        uint64_t size  = (uint64_t)BADSIZE;
        uint32_t flags = 0;
    };

    struct Ucmt
    {
        ea_t     ea  = BADADDR;
        uint32_t itp = 0;
        qstring  text;
    };

    struct Version
    {
        uint64_t hash = 0;
        std::vector<Range> ranges;      // the entry chunk first
        qstring  name;
        TypeStr  proto;
        qstring  fcmt, frcmt;           // function comment, repeatable
        std::vector<Item> items;
        bool     have_lv = false;
        uint64_t stkoff_delta = 0;
        uint32_t ulv_flags = 0;
        std::vector<Lvar> lvars;
        std::vector<std::pair<Loc, Loc>> lmaps;
        std::vector<Ucmt> ucmts;

        // Bounds alone are not kept: the per-stop analysis finds those again,
        // and only what the user set is worth a copy.
        bool has_work() const
        {
            return !name.empty() || proto.have || !fcmt.empty() || !frcmt.empty()
                || !items.empty() || !lvars.empty() || !lmaps.empty() || !ucmts.empty();
        }
        bool contains(ea_t ea) const
        {
            for ( const Range &r : ranges )
                if ( r.lo <= ea && ea < r.hi )
                    return true;
            return false;
        }
    };

    //=======================================================================
    // Encoding
    //=======================================================================
    static void put_type(BlobWriter &w, const TypeStr &t)
    {
        w.u8(t.have ? 1 : 0);
        if ( !t.have )
            return;
        w.str(t.type);
        w.str(t.fields);
        w.str(t.cmts);
    }

    static void get_type(BlobReader &r, TypeStr *t)
    {
        t->have = r.u8() != 0;
        if ( !t->have )
            return;
        r.str(&t->type);
        r.str(&t->fields);
        r.str(&t->cmts);
    }

    static void put_loc(BlobWriter &w, const Loc &l)
    {
        w.u8(l.atype);
        w.u64(l.raw);
        w.u64(l.defea);
    }

    static void get_loc(BlobReader &r, Loc *l)
    {
        l->atype = r.u8();
        l->raw   = r.u64();
        l->defea = r.u64();
    }

    static void put_version(BlobWriter &w, const Version &v)
    {
        w.u64(v.hash);
        w.u32((uint32_t)v.ranges.size());
        for ( const Range &rg : v.ranges )
        {
            w.u64(rg.lo);
            w.u64(rg.hi);
        }
        w.str(v.name);
        put_type(w, v.proto);
        w.str(v.fcmt);
        w.str(v.frcmt);
        w.u32((uint32_t)v.items.size());
        for ( const Item &it : v.items )
        {
            w.u64(it.ea);
            w.u8(it.kind);
            w.str(it.text);
        }
        w.u8(v.have_lv ? 1 : 0);
        w.u64(v.stkoff_delta);
        w.u32(v.ulv_flags);
        w.u32((uint32_t)v.lvars.size());
        for ( const Lvar &lv : v.lvars )
        {
            put_loc(w, lv.ll);
            w.str(lv.name);
            put_type(w, lv.type);
            w.str(lv.cmt);
            w.u64(lv.size);
            w.u32(lv.flags);
        }
        w.u32((uint32_t)v.lmaps.size());
        for ( const auto &m : v.lmaps )
        {
            put_loc(w, m.first);
            put_loc(w, m.second);
        }
        w.u32((uint32_t)v.ucmts.size());
        for ( const Ucmt &c : v.ucmts )
        {
            w.u64(c.ea);
            w.u32(c.itp);
            w.str(c.text);
        }
    }

    // False on any inconsistency; the caller drops the whole blob.
    static bool get_version(BlobReader &r, Version *v)
    {
        v->hash = r.u64();
        uint32_t n = r.u32();
        if ( !r.ok() || n == 0 || n > 4096 )
            return false;
        for ( uint32_t i = 0; i < n && r.ok(); i++ )
        {
            Range rg;
            rg.lo = (ea_t)r.u64();
            rg.hi = (ea_t)r.u64();
            if ( rg.hi <= rg.lo )
                return false;
            v->ranges.push_back(rg);
        }
        r.str(&v->name);
        get_type(r, &v->proto);
        r.str(&v->fcmt);
        r.str(&v->frcmt);
        n = r.u32();
        if ( !r.ok() || n > KF_MAX_ITEMS )
            return false;
        for ( uint32_t i = 0; i < n && r.ok(); i++ )
        {
            Item it;
            it.ea   = (ea_t)r.u64();
            it.kind = r.u8();
            r.str(&it.text);
            v->items.push_back(it);
        }
        v->have_lv      = r.u8() != 0;
        v->stkoff_delta = r.u64();
        v->ulv_flags    = r.u32();
        n = r.u32();
        if ( !r.ok() || n > KF_MAX_LVARS )
            return false;
        for ( uint32_t i = 0; i < n && r.ok(); i++ )
        {
            Lvar lv;
            get_loc(r, &lv.ll);
            r.str(&lv.name);
            get_type(r, &lv.type);
            r.str(&lv.cmt);
            lv.size  = r.u64();
            lv.flags = r.u32();
            v->lvars.push_back(lv);
        }
        n = r.u32();
        if ( !r.ok() || n > KF_MAX_LVARS )
            return false;
        for ( uint32_t i = 0; i < n && r.ok(); i++ )
        {
            std::pair<Loc, Loc> m;
            get_loc(r, &m.first);
            get_loc(r, &m.second);
            v->lmaps.push_back(m);
        }
        n = r.u32();
        if ( !r.ok() || n > KF_MAX_ITEMS )
            return false;
        for ( uint32_t i = 0; i < n && r.ok(); i++ )
        {
            Ucmt c;
            c.ea  = (ea_t)r.u64();
            c.itp = r.u32();
            r.str(&c.text);
            v->ucmts.push_back(c);
        }
        return r.ok();
    }

    //=======================================================================
    // The netnode
    //=======================================================================
    static std::vector<Version> load(ea_t start)
    {
        std::vector<Version> out;
        netnode nn(KF_NODE);
        if ( nn == BADNODE )
            return out;
        nodeidx_t id = nn.altval((nodeidx_t)start, KF_INDEX);
        if ( id == 0 )
            return out;
        bytevec_t blob;
        if ( nn.getblob(&blob, blob_slot(id), KF_BLOB) <= 0 )
            return out;
        BlobReader r(blob.begin(), blob.size());
        if ( r.u32() != KF_MAGIC || r.u32() != KF_VERSION )
            return out;
        uint32_t n = r.u32();
        if ( !r.ok() || n > KF_MAX_VERSIONS )
            return out;
        for ( uint32_t i = 0; i < n; i++ )
        {
            Version v;
            if ( !get_version(r, &v) )
            {
                out.clear();
                break;
            }
            out.push_back(std::move(v));
        }
        return out;
    }

    // The blob store() writes for 'versions'.
    static void encode(BlobWriter &w, const std::vector<Version> &versions)
    {
        w.u32(KF_MAGIC);
        w.u32(KF_VERSION);
        w.u32((uint32_t)versions.size());
        for ( const Version &v : versions )
            put_version(w, v);
    }

    static void store(ea_t start, const std::vector<Version> &versions)
    {
        netnode nn(KF_NODE, 0, true);
        nodeidx_t id = nn.altval((nodeidx_t)start, KF_INDEX);
        if ( versions.empty() )
        {
            if ( id != 0 )
            {
                nn.delblob(blob_slot(id), KF_BLOB);
                nn.altdel((nodeidx_t)start, KF_INDEX);
            }
            return;
        }
        if ( id == 0 )
        {
            id = nn.altval(0, KF_COUNTER) + 1;
            nn.altset(0, id, KF_COUNTER);
            nn.altset((nodeidx_t)start, id, KF_INDEX);
        }
        BlobWriter w;
        encode(w, versions);
        nn.delblob(blob_slot(id), KF_BLOB);     // a shorter blob leaves no tail
        nn.setblob(w.data(), w.size(), blob_slot(id), KF_BLOB);
    }

    //=======================================================================
    // Reading the database
    //=======================================================================
    // FNV-1a over every range, in order. False when a byte cannot be read or
    // the function is implausibly large.
    static bool hash_ranges(const std::vector<Range> &ranges, uint64_t *out)
    {
        uint64_t h = 1469598103934665603ULL;
        uint64_t total = 0;
        bytevec_t buf;
        for ( const Range &rg : ranges )
        {
            uint64_t n = (uint64_t)(rg.hi - rg.lo);
            total += n;
            if ( n == 0 || total > KF_MAX_BYTES )
                return false;
            buf.resize((size_t)n);
            if ( get_bytes(buf.begin(), (ssize_t)n, rg.lo) != (ssize_t)n )
                return false;
            for ( uchar b : buf )
            {
                h ^= b;
                h *= 1099511628211ULL;
            }
        }
        *out = h;
        return true;
    }

    static std::vector<Range> function_ranges(ea_t start)
    {
        std::vector<Range> out;
        func_entry_info_t fi;
        if ( !get_func_entry_info(&fi, start) || fi.end_ea <= fi.start_ea )
            return out;
        out.push_back(Range{ fi.start_ea, fi.end_ea });
        rangevec_t tails;
        if ( get_func_tails(&tails, start) )
            for ( const range_t &t : tails )
                if ( t.end_ea > t.start_ea )
                    out.push_back(Range{ t.start_ea, t.end_ea });
        return out;
    }

    static TypeStr type_of(const tinfo_t &tif)
    {
        TypeStr t;
        qtype ty, fl, fc;
        if ( tif.empty() || !tif.serialize(&ty, &fl, &fc) )
            return t;
        // A string the blob would truncate would deserialize as garbage.
        if ( ty.length() > DB_MAX_STR || fl.length() > DB_MAX_STR || fc.length() > DB_MAX_STR )
            return t;
        t.type   = qstring((const char *)ty.c_str(), ty.length());
        t.fields = qstring((const char *)fl.c_str(), fl.length());
        t.cmts   = qstring((const char *)fc.c_str(), fc.length());
        t.have   = !t.type.empty();
        return t;
    }

    static bool type_from(const TypeStr &t, tinfo_t *out)
    {
        if ( !t.have )
            return false;
        qtype ty((const uchar *)t.type.c_str(), t.type.length());
        qtype fl((const uchar *)t.fields.c_str(), t.fields.length());
        qtype fc((const uchar *)t.cmts.c_str(), t.cmts.length());
        return out->deserialize(get_idati(), &ty,
                                fl.empty() ? nullptr : &fl,
                                fc.empty() ? nullptr : &fc);
    }

    static bool loc_from(const lvar_locator_t &ll, Loc *out)
    {
        const argloc_type_t t = ll.location.atype();
        if ( t != ALOC_STACK && t != ALOC_STATIC && t != ALOC_REG1 && t != ALOC_REG2 )
            return false;
        out->atype = (uint8_t)t;
        out->raw   = (uint64_t)ll.location.get_biggest();
        out->defea = (uint64_t)ll.defea;
        return true;
    }

    static void loc_to(const Loc &l, lvar_locator_t *out)
    {
        // A fresh locator holds nothing to clean up, so the raw setter is
        // safe for these pointer-free kinds.
        out->location._set_biggest((argloc_type_t)l.atype, (argloc_t::biggest_t)l.raw);
        out->defea = (ea_t)l.defea;
    }

    // Everything the user set on the function at 'start', with its ranges,
    // but not their hash: that reads the function's bytes (up to a MiB
    // through the debugger), and most functions have no work to keep. False
    // when there is no function at 'start'.
    static bool read_work(ea_t start, Version *v)
    {
        v->ranges = function_ranges(start);
        if ( v->ranges.empty() )
            return false;

        if ( has_user_name(get_flags(start)) )
            get_ea_name(&v->name, start);
        if ( is_userti(start) )
        {
            tinfo_t tif;
            if ( get_tinfo(&tif, start) )
                v->proto = type_of(tif);
        }
        get_func_cmt_ea(&v->fcmt, start, false);
        get_func_cmt_ea(&v->frcmt, start, true);

        for ( const Range &rg : v->ranges )
        {
            for ( ea_t ea = rg.lo; ea != BADADDR && ea < rg.hi && v->items.size() < KF_MAX_ITEMS;
                  ea = next_head(ea, rg.hi) )
            {
                const flags64_t f = get_flags(ea);
                qstring s;
                if ( has_cmt(f) )
                {
                    if ( get_cmt(&s, ea, false) > 0 )
                        v->items.push_back(Item{ ea, IT_CMT, s });
                    if ( get_cmt(&s, ea, true) > 0 )
                        v->items.push_back(Item{ ea, IT_RPTCMT, s });
                }
                if ( ea != start && has_user_name(f) && get_ea_name(&s, ea) > 0 )
                    v->items.push_back(Item{ ea, IT_LABEL, s });
            }
        }

        if ( init_hexrays_plugin() )
        {
            lvar_uservec_t lv;
            if ( restore_user_lvar_settings(&lv, start) && !lv.empty() )
            {
                v->have_lv      = true;
                v->stkoff_delta = lv.stkoff_delta;
                v->ulv_flags    = (uint32_t)lv.ulv_flags;
                for ( const lvar_saved_info_t &s : lv.lvvec )
                {
                    Lvar x;
                    if ( v->lvars.size() >= KF_MAX_LVARS || !loc_from(s.ll, &x.ll) )
                        continue;
                    x.name  = s.name;
                    x.type  = type_of(s.type);
                    x.cmt   = s.cmt;
                    x.size  = (uint64_t)s.size;
                    x.flags = s.flags;
                    v->lvars.push_back(x);
                }
                for ( const auto &m : lv.lmaps )
                {
                    std::pair<Loc, Loc> p;
                    if ( v->lmaps.size() < KF_MAX_LVARS
                      && loc_from(m.first, &p.first) && loc_from(m.second, &p.second) )
                        v->lmaps.push_back(p);
                }
            }
            user_cmts_t *uc = restore_user_cmts(start);
            if ( uc != nullptr )
            {
                for ( user_cmts_iterator_t p = user_cmts_begin(uc); p != user_cmts_end(uc);
                      p = user_cmts_next(p) )
                {
                    if ( v->ucmts.size() >= KF_MAX_ITEMS )
                        break;
                    const treeloc_t &tl = user_cmts_first(p);
                    v->ucmts.push_back(Ucmt{ tl.ea, (uint32_t)tl.itp, qstring(user_cmts_second(p).c_str()) });
                }
                user_cmts_free(uc);
            }
        }
        return true;
    }

    //=======================================================================
    // Writing the database
    //=======================================================================
    // Give the function at 'start' the kept bounds: the entry chunk's end,
    // then every tail it does not have yet.
    static void apply_bounds(ea_t start, const Version &v)
    {
        func_entry_info_t fi;
        if ( !get_func_entry_info(&fi, start) )
            return;
        const Range &entry = v.ranges[0];
        if ( entry.lo == start && entry.hi != fi.end_ea )
        {
            if ( entry.hi > fi.end_ea )
                lay_out_linear(fi.end_ea, entry.hi);
            set_func_end(start, entry.hi);
        }
        for ( size_t i = 1; i < v.ranges.size(); i++ )
        {
            const Range &t = v.ranges[i];
            if ( get_func_start(t.lo) == start )
                continue;
            lay_out_linear(t.lo, t.hi);
            append_func_tail_ea(start, t.lo, t.hi);
        }
    }

    // Put the kept work back on the function at 'start'. Only where the
    // database has nothing of the user's: what was set since wins.
    static void apply(ea_t start, const Version &v)
    {
        apply_bounds(start, v);

        if ( !v.name.empty() && !has_user_name(get_flags(start)) )
            set_name(start, v.name.c_str(), SN_NOWARN | SN_FORCE);
        if ( v.proto.have && !is_userti(start) )
        {
            tinfo_t tif;
            if ( type_from(v.proto, &tif) )
                apply_tinfo(start, tif, TINFO_DEFINITE);
        }
        qstring cur;
        if ( !v.fcmt.empty() && get_func_cmt_ea(&cur, start, false) <= 0 )
            set_func_cmt_ea(start, v.fcmt.c_str(), false);
        if ( !v.frcmt.empty() && get_func_cmt_ea(&cur, start, true) <= 0 )
            set_func_cmt_ea(start, v.frcmt.c_str(), true);
        for ( const Item &it : v.items )
        {
            if ( it.kind == IT_LABEL )
            {
                if ( !has_user_name(get_flags(it.ea)) )
                    set_name(it.ea, it.text.c_str(), SN_NOWARN | SN_FORCE);
            }
            else
            {
                const bool rpt = it.kind == IT_RPTCMT;
                if ( get_cmt(&cur, it.ea, rpt) <= 0 )
                    set_cmt(it.ea, it.text.c_str(), rpt);
            }
        }

        if ( !init_hexrays_plugin() )
            return;
        if ( v.have_lv )
        {
            lvar_uservec_t have;
            if ( !restore_user_lvar_settings(&have, start) || have.empty() )
            {
                lvar_uservec_t lv;
                lv.stkoff_delta = (uval_t)v.stkoff_delta;
                lv.ulv_flags    = (int)v.ulv_flags;
                for ( const Lvar &x : v.lvars )
                {
                    lvar_saved_info_t s;
                    loc_to(x.ll, &s.ll);
                    s.name = x.name;
                    if ( x.type.have )
                        type_from(x.type, &s.type);
                    s.cmt   = x.cmt;
                    s.size  = (ssize_t)x.size;
                    s.flags = x.flags;
                    lv.lvvec.push_back(s);
                }
                for ( const auto &m : v.lmaps )
                {
                    lvar_locator_t a, b;
                    loc_to(m.first, &a);
                    loc_to(m.second, &b);
                    lv.lmaps[a] = b;
                }
                save_user_lvar_settings(start, lv);
            }
        }
        if ( !v.ucmts.empty() )
        {
            user_cmts_t *have = restore_user_cmts(start);
            const bool none = have == nullptr || user_cmts_begin(have) == user_cmts_end(have);
            if ( have != nullptr )
                user_cmts_free(have);
            if ( none )
            {
                user_cmts_t *uc = user_cmts_new();
                for ( const Ucmt &c : v.ucmts )
                {
                    treeloc_t tl;
                    tl.ea  = c.ea;
                    tl.itp = (item_preciser_t)c.itp;
                    user_cmts_insert(uc, tl, citem_cmt_t(c.text.c_str()));
                }
                save_user_cmts(start, uc);
                user_cmts_free(uc);
            }
        }
        // A decompilation cached before the work came back would show none
        // of it.
        mark_cfunc_dirty(start);
    }

    //=======================================================================
    // KeptFunctions
    //=======================================================================
    void KeptFunctions::bind(ModuleRegistry *modules, MemoryReader *memory)
    {
        reset();
        m_modules = modules;
        m_memory  = memory;
    }

    void KeptFunctions::reset()
    {
        m_modules = nullptr;
        m_memory  = nullptr;
        m_pending.clear();
        m_dirty.clear();
        m_rebuilt.clear();
    }

    bool KeptFunctions::covers(ea_t ea) const
    {
        if ( m_modules == nullptr || ea == BADADDR )
            return false;
        segment_info_t si;
        if ( !get_segment_info(&si, ea) || !si.is_debugger_segm() )
            return false;
        ea_t lo = 0, hi = 0;
        return !m_modules->range_at(ea, lo, hi);
    }

    void KeptFunctions::note_changed(ea_t ea)
    {
        if ( !covers(ea) )
            return;
        ea_t start = get_func_start(ea);
        if ( start != BADADDR )
            m_dirty.insert(start);
    }

    void KeptFunctions::capture(ea_t start)
    {
        if ( !covers(start) || get_func_start(start) != start )
            return;
        // Defined again but not restored yet: what is there is the remains
        // (a prototype IDA kept at the address, say), and copying it would
        // replace the full copy of the same bytes. A save between the two
        // did exactly that.
        if ( m_pending.count(start) != 0 )
            return;
        // The work first: a function without any is skipped before its bytes
        // are read, which keeps a layout change, a save (autosave included)
        // and the session's end cheap.
        Version v;
        if ( !read_work(start, &v) || !v.has_work() || !hash_ranges(v.ranges, &v.hash) )
            return;
        const std::vector<Version> was = load(start);
        std::vector<Version> kept = was;
        // Superseded: the same bytes (this copy's hash), or an older copy
        // whose bytes still match what is here, so the work is this one's.
        kept.erase(std::remove_if(kept.begin(), kept.end(), [&](const Version &o)
        {
            uint64_t h = 0;
            return o.hash == v.hash || (hash_ranges(o.ranges, &h) && h == o.hash);
        }), kept.end());
        kept.insert(kept.begin(), std::move(v));
        if ( kept.size() > KF_MAX_VERSIONS )
            kept.resize(KF_MAX_VERSIONS);
        // Rewriting an unchanged copy would dirty the database, so a save
        // with nothing new would leave it unsaved again.
        BlobWriter a, b;
        encode(a, was);
        encode(b, kept);
        if ( a.size() == b.size() && memcmp(a.data(), b.data(), a.size()) == 0 )
            return;
        store(start, kept);
    }

    void KeptFunctions::capture_dirty()
    {
        std::set<ea_t> todo;
        todo.swap(m_dirty);
        for ( ea_t start : todo )
            capture(start);
    }

    void KeptFunctions::capture_all()
    {
        m_dirty.clear();
        if ( m_modules == nullptr )
            return;
        for ( int i = 0, n = get_segm_qty(); i < n; i++ )
        {
            segment_info_t si;
            if ( !get_segment_info_by_num(&si, i) || !si.is_debugger_segm() )
                continue;
            ea_t lo = 0, hi = 0;
            if ( m_modules->range_at(si.start_ea, lo, hi) )
                continue;
            ea_t f = get_func_start(si.start_ea) == si.start_ea ? si.start_ea
                                                                : get_next_func_ea(si.start_ea);
            for ( ; f != BADADDR && f < si.end_ea; f = get_next_func_ea(f) )
                capture(f);
        }
    }

    bool KeptFunctions::note_added(ea_t start)
    {
        if ( !covers(start) )
            return false;
        m_pending.insert(start);
        return true;
    }

    // The newest kept version at 'start' whose bytes match here, rebuilding
    // the bytes from recorded writes once if none does at first: code that
    // never ran reads as zeros until it is rebuilt, and the copy was hashed
    // after the analysis had rebuilt it.
    static const Version *match(const std::vector<Version> &kept, ea_t pc_or_bad,
                                ITraceCursor *playhead, MemoryReader *memory,
                                std::set<uint64_t> &rebuilt)
    {
        for ( int pass = 0; pass < 2; pass++ )
        {
            for ( const Version &v : kept )
            {
                if ( pc_or_bad != BADADDR && !v.contains(pc_or_bad) )
                    continue;
                if ( pass == 1 )
                {
                    if ( playhead == nullptr || memory == nullptr || rebuilt.count(v.hash) != 0 )
                        continue;
                    rebuilt.insert(v.hash);
                    bool any = false;
                    for ( const Range &rg : v.ranges )
                        if ( memory->reconstruct(playhead, rg.lo, rg.hi) )
                        {
                            invalidate_dbgmem_contents(rg.lo, rg.hi - rg.lo);
                            any = true;
                        }
                    if ( !any )
                        continue;
                }
                uint64_t h = 0;
                if ( hash_ranges(v.ranges, &h) && h == v.hash )
                    return &v;
            }
        }
        return nullptr;
    }

    size_t KeptFunctions::restore_pending(ITraceCursor *playhead)
    {
        std::set<ea_t> todo;
        todo.swap(m_pending);
        size_t restored = 0;
        for ( ea_t start : todo )
        {
            if ( get_func_start(start) != start || !covers(start) )
                continue;
            std::vector<Version> kept = load(start);
            if ( kept.empty() )
                continue;
            const Version *v = match(kept, BADADDR, playhead, m_memory, m_rebuilt[start]);
            if ( v == nullptr )
                continue;
            apply(start, *v);
            restored++;
        }
        if ( restored != 0 )
            msg("[ida-ttd] restored your work on %d function(s) in memory outside the modules.\n",
                (int)restored);
        return restored;
    }

    ea_t KeptFunctions::define_at(ITraceCursor *playhead, ea_t pc)
    {
        if ( !covers(pc) || get_func_start(pc) != BADADDR )
            return BADADDR;
        netnode nn(KF_NODE);
        if ( nn == BADNODE )
            return BADADDR;
        nodeidx_t s = nn.altprev((nodeidx_t)pc + 1, KF_INDEX);
        for ( int k = 0; s != BADNODE && k < KF_LOOKBACK; k++, s = nn.altprev(s, KF_INDEX) )
        {
            const ea_t start = (ea_t)s;
            if ( get_func_start(start) != BADADDR || !covers(start) )
                continue;
            std::vector<Version> kept = load(start);
            const Version *v = match(kept, pc, playhead, m_memory, m_rebuilt[start]);
            if ( v == nullptr )
                continue;
            for ( const Range &rg : v->ranges )
                lay_out_linear(rg.lo, rg.hi);
            if ( !add_func(v->ranges[0].lo, v->ranges[0].hi) )
                continue;
            for ( size_t i = 1; i < v->ranges.size(); i++ )
                append_func_tail_ea(start, v->ranges[i].lo, v->ranges[i].hi);
            // Analyzed now, stack frame included: Hex-Rays matches the kept
            // variables to the frame, and a decompilation of the stop made
            // before IDA's queue got to the function showed none of them.
            for ( const Range &rg : v->ranges )
                plan_and_wait(rg.lo, rg.hi);
            m_pending.insert(start);
            return start;
        }
        return BADADDR;
    }
}
