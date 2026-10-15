#include "analysis/address_space.h"
#include "analysis/memmap.h"
#include "common/guest_pe.h"
#include "debugger/trace_manager.h"

namespace idattd
{
    const char *region_type_name(uint32_t type)
    {
        switch ( type )
        {
            case ITTD_REGION_PRIVATE: return "Private";
            case ITTD_REGION_IMAGE:   return "Image";
            case ITTD_REGION_MAPPED:  return "Mapped";
            case ITTD_REGION_SECTION: return "Section";
            case ITTD_REGION_MMIO:    return "MMIO";
            case ITTD_REGION_HOST:    return "Host";
            default:                  return "";
        }
    }

    namespace
    {
        const uint32_t PAGE_NOACCESS_  = 0x01;
        const uint32_t PAGE_READONLY_  = 0x02;
        const uint32_t PAGE_READWRITE_ = 0x04;
        const uint32_t PAGE_WRITECOPY_ = 0x08;
        const uint32_t PAGE_EXECUTE_   = 0x10;
        const uint32_t PAGE_EXECUTE_READ_      = 0x20;
        const uint32_t PAGE_EXECUTE_WRITECOPY_ = 0x80;
        const uint32_t PAGE_GUARD_     = 0x100;

        const ea_t     SHARED_USER_DATA = 0x7FFE0000;
        const uint64_t PAGE = 0x1000;

        uint64_t page_up(uint64_t v) { return (v + PAGE - 1) & ~(PAGE - 1); }

        // The protection a section header asks for. Writable image pages are
        // copy-on-write, which is what the loader maps them as.
        uint32_t section_protect(uint32_t ch)
        {
            const uint32_t SCN_MEM_EXECUTE = 0x20000000;    // IMAGE_SCN_MEM_*
            const uint32_t SCN_MEM_READ    = 0x40000000;
            const uint32_t SCN_MEM_WRITE   = 0x80000000;
            bool x = (ch & SCN_MEM_EXECUTE) != 0;
            bool r = (ch & SCN_MEM_READ) != 0;
            bool w = (ch & SCN_MEM_WRITE) != 0;
            if ( x )
                return w ? PAGE_EXECUTE_WRITECOPY_ : r ? PAGE_EXECUTE_READ_ : PAGE_EXECUTE_;
            if ( w )
                return PAGE_WRITECOPY_;
            return r ? PAGE_READONLY_ : PAGE_NOACCESS_;
        }

        struct Piece
        {
            ea_t     lo = 0, hi = 0;
            uint32_t protect = 0;
            bool     reserved = false;
            uint32_t type = 0;
            Position since = Position::none();
        };

        struct Label
        {
            ea_t    lo = 0, hi = 0;
            qstring text;
        };

        // Non-overlapping pieces keyed by start. A piece put later wins where
        // it overlaps an earlier one.
        class Layout
        {
        public:
            void put(const Piece &p)
            {
                if ( p.hi <= p.lo )
                    return;
                cut(p.lo, p.hi, nullptr);
                m[p.lo] = p;
            }

            // Change the protection of what is already there in [lo, hi).
            void protect(ea_t lo, ea_t hi, uint32_t prot)
            {
                std::vector<Piece> hit;
                cut(lo, hi, &hit);
                for ( const Piece &h : hit )
                {
                    if ( h.lo < lo )  { Piece a = h; a.hi = lo; m[a.lo] = a; }
                    if ( h.hi > hi )  { Piece b = h; b.lo = hi; m[b.lo] = b; }
                    Piece mid = h;
                    mid.lo = std::max(h.lo, lo);
                    mid.hi = std::min(h.hi, hi);
                    mid.protect = prot;
                    if ( mid.hi > mid.lo )
                        m[mid.lo] = mid;
                }
            }

            bool covered(ea_t ea) const
            {
                auto it = m.upper_bound(ea);
                if ( it == m.begin() )
                    return false;
                --it;
                return ea < it->second.hi;
            }

            std::map<ea_t, Piece> m;

        private:
            // Remove [lo, hi), keeping what falls outside it. 'removed' gets
            // the pieces it overlapped, whole.
            void cut(ea_t lo, ea_t hi, std::vector<Piece> *removed)
            {
                auto it = m.upper_bound(lo);
                if ( it != m.begin() )
                    --it;
                while ( it != m.end() && it->first < hi )
                {
                    Piece p = it->second;
                    if ( p.hi <= lo )
                    {
                        ++it;
                        continue;
                    }
                    it = m.erase(it);
                    if ( removed != nullptr )
                    {
                        removed->push_back(p);
                        continue;
                    }
                    if ( p.lo < lo ) { Piece a = p; a.hi = lo; m[a.lo] = a; }
                    if ( p.hi > hi ) { Piece b = p; b.lo = hi; m[b.lo] = b; it = m.find(b.lo); ++it; }
                }
            }
        };

        // The fields of a TEB and PEB this needs, for either pointer size.
        struct Tib
        {
            uint64_t stack_base = 0, stack_limit = 0, dealloc = 0, peb = 0;
        };

        uint64_t read_ptr(const GuestRead &rd, uint64_t addr, bool p64)
        {
            uint64_t v = 0;
            if ( p64 )
                return rd(addr, &v, 8) == 8 ? v : 0;
            uint32_t v32 = 0;
            return rd(addr, &v32, 4) == 4 ? v32 : 0;
        }

        Tib read_tib(const GuestRead &rd, uint64_t teb, bool p64)
        {
            // NT_TIB.StackBase and StackLimit, TEB.DeallocationStack and
            // TEB.ProcessEnvironmentBlock.
            Tib t;
            t.stack_base  = read_ptr(rd, teb + (p64 ? 0x08 : 0x04), p64);
            t.stack_limit = read_ptr(rd, teb + (p64 ? 0x10 : 0x08), p64);
            t.dealloc     = read_ptr(rd, teb + (p64 ? 0x1478 : 0xE0C), p64);
            t.peb         = read_ptr(rd, teb + (p64 ? 0x60 : 0x30), p64);
            return t;
        }
    }

    void address_space_at(TraceManager *mgr, std::vector<AddressRegion> *out)
    {
        out->clear();
        if ( mgr == nullptr || !mgr->is_active() || mgr->cursor() == nullptr )
            return;

        const Position now  = mgr->current_position();
        const bool     is64 = mgr->is64();
        const ea_t     HI   = is64 ? (ea_t)0x7FFFFFFFFFFFull : (ea_t)0xFFFFFFFFull;
        // Through the same reader IDA's views use, so a module header the
        // recording never read still comes from the image on disk.
        GuestRead rd = [mgr](uint64_t addr, void *buf, size_t size) -> size_t
        {
            size_t n = 0;
            return mgr->on_read_memory(&n, (ea_t)addr, buf, size) == DRC_OK ? n : 0;
        };
        auto sane = [HI](uint64_t a) { return a >= 0x10000 && a < HI; };

        Layout lay;
        std::vector<Label> labels;
        auto label = [&labels](ea_t lo, ea_t hi, const qstring &text)
        {
            Label l;
            l.lo = lo;
            l.hi = hi;
            l.text = text;
            labels.push_back(l);
        };

        // ---- what the kernel made: stacks, TEBs, the PEB ----------------------
        //
        // Put first, so a region the recording itself reported replaces the
        // guess wherever the two meet.
        std::set<uint64_t> pebs;
        auto add_thread = [&](uint32_t tid, uint64_t teb, bool p64, const char *suffix)
        {
            if ( !sane(teb) )
                return;
            Tib t = read_tib(rd, teb, p64);
            qstring who;
            who.sprnt("thread 0x%X", tid);

            Piece tp;
            tp.lo = (ea_t)teb;
            tp.hi = (ea_t)(teb + (p64 ? 0x2000 : PAGE));
            tp.protect = PAGE_READWRITE_;
            tp.type = ITTD_REGION_PRIVATE;
            lay.put(tp);
            qstring tl;
            tl.sprnt("TEB%s (%s)", suffix, who.c_str());
            label(tp.lo, tp.hi, tl);

            if ( sane(t.stack_base) && sane(t.stack_limit) && t.stack_limit < t.stack_base )
            {
                Piece c;
                c.lo = (ea_t)t.stack_limit;
                c.hi = (ea_t)t.stack_base;
                c.protect = PAGE_READWRITE_;
                c.type = ITTD_REGION_PRIVATE;
                lay.put(c);
                ea_t lo = c.lo;
                if ( sane(t.dealloc) && t.dealloc + PAGE <= t.stack_limit )
                {
                    Piece g;
                    g.lo = (ea_t)(t.stack_limit - PAGE);
                    g.hi = (ea_t)t.stack_limit;
                    g.protect = PAGE_READWRITE_ | PAGE_GUARD_;
                    g.type = ITTD_REGION_PRIVATE;
                    lay.put(g);
                    Piece r;
                    r.lo = (ea_t)t.dealloc;
                    r.hi = g.lo;
                    r.reserved = true;
                    r.type = ITTD_REGION_PRIVATE;
                    lay.put(r);
                    lo = (ea_t)t.dealloc;
                }
                qstring sl;
                sl.sprnt("Stack%s (%s)", suffix, who.c_str());
                label(lo, (ea_t)t.stack_base, sl);
            }
            if ( sane(t.peb) && pebs.insert(t.peb).second )
            {
                Piece pp;
                pp.lo = (ea_t)t.peb;
                pp.hi = (ea_t)(t.peb + PAGE);
                pp.protect = PAGE_READWRITE_;
                pp.type = ITTD_REGION_PRIVATE;
                lay.put(pp);
                qstring pl;
                pl.sprnt("PEB%s", suffix);
                label(pp.lo, pp.hi, pl);

                // What the PEB points at, labelling whichever region holds it.
                struct Field { uint32_t off64, off32; const char *what; };
                static const Field fields[] =
                {
                    { 0x20, 0x10, "Process parameters" },
                    { 0x68, 0x38, "API set map" },
                    { 0x88, 0x4C, "Read-only shared memory" },
                    { 0xA0, 0x58, "Code page tables" },
                };
                for ( const Field &f : fields )
                {
                    uint64_t a = read_ptr(rd, t.peb + (p64 ? f.off64 : f.off32), p64);
                    if ( sane(a) )
                        label((ea_t)a, (ea_t)a + 1, f.what);
                }
                // PEB.NumberOfHeaps and PEB.ProcessHeaps.
                uint32_t nheaps = 0;
                rd(t.peb + (p64 ? 0xE8 : 0x88), &nheaps, 4);
                uint64_t heaps = read_ptr(rd, t.peb + (p64 ? 0xF0 : 0x90), p64);
                for ( uint32_t i = 0; sane(heaps) && i < nheaps && i < 256; i++ )
                {
                    uint64_t h = read_ptr(rd, heaps + (uint64_t)i * (p64 ? 8 : 4), p64);
                    if ( !sane(h) )
                        continue;
                    qstring hl;
                    if ( i == 0 )
                        hl.sprnt("Process heap%s", suffix);
                    else
                        hl.sprnt("Heap %u%s", i, suffix);
                    label((ea_t)h, (ea_t)h + 1, hl);
                }
            }
        };
        for ( const ThreadInfo &t : mgr->cursor()->live_threads() )
        {
            if ( is64 )
            {
                add_thread(t.tid, t.teb, true, "");
            }
            else
            {
                // A WoW64 thread has both; the 32-bit side is the program's.
                add_thread(t.tid, t.teb32, false, "");
                if ( t.teb != 0 && t.teb != t.teb32 )
                    add_thread(t.tid, t.teb, true, "64");
            }
        }
        {
            Piece s;
            s.lo = SHARED_USER_DATA;
            s.hi = SHARED_USER_DATA + PAGE;
            s.protect = PAGE_READONLY_;
            lay.put(s);
            label(s.lo, s.hi, "Shared user data");
        }

        // ---- what the recording allocated and mapped ---------------------------
        const MemoryMap &map = mgr->memmap();
        bool reports_state = false;     // the backend reports regions as they are
        // The protection changes up to here, gathered once for every module
        // below rather than found in the whole timeline per module.
        std::vector<const RegionChange *> protects;
        for ( size_t i = 0; i < map.size(); i++ )
        {
            const RegionChange &c = map.at(i);
            if ( c.kind == RC_STATE )
                reports_state = true;
            if ( !(c.pos > now) && c.kind == RC_PROTECT && !c.other_process && c.size != 0 && c.base != BADADDR )
                protects.push_back(&c);
        }
        if ( !map.empty() )
        {
            std::vector<Region> regs;
            map.state_at(now, regs);
            for ( const Region &r : regs )
            {
                Piece p;
                p.lo = r.base;
                p.hi = r.end();
                p.protect = r.reserved ? 0 : r.protect;
                p.reserved = r.reserved;
                p.type = r.type;
                p.since = r.since;
                lay.put(p);
            }
        }

        // ---- the modules loaded here ------------------------------------------
        for ( const ModuleInfo *m : mgr->modules().loaded_at(now) )
        {
            if ( m == nullptr || m->base == BADADDR || m->size == 0 )
                continue;
            ea_t mlo = m->base, mhi = (ea_t)(m->base + m->size);
            qstring name = m->name;
            {
                // "ntdll", the way a debugger qualifies a symbol.
                ssize_t dot = name.rfind('.');
                if ( dot > 0 )
                    name.resize((size_t)dot);
            }
            label(mlo, mhi, name);

            GuestPeInfo pe;
            bool have_pe = read_guest_pe_info(rd, mlo, &pe);
            std::vector<Piece> secs;
            if ( have_pe )
            {
                Piece h;
                h.lo = mlo;
                h.hi = (ea_t)std::min<uint64_t>(mlo + page_up(pe.size_of_headers ? pe.size_of_headers : PAGE), mhi);
                h.protect = PAGE_READONLY_;
                secs.push_back(h);
                qstring hl;
                hl.sprnt("%s (headers)", name.c_str());
                label(h.lo, h.hi, hl);
                for ( const GuestPeSection &s : pe.sections )
                {
                    uint64_t vs = s.vsize != 0 ? s.vsize : s.rawsize;
                    Piece p;
                    p.lo = (ea_t)(mlo + s.va);
                    p.hi = (ea_t)std::min<uint64_t>(mlo + s.va + page_up(vs), mhi);
                    if ( p.hi <= p.lo )
                        continue;
                    p.protect = section_protect(s.characteristics);
                    secs.push_back(p);
                    qstring sl;
                    sl.sprnt("%s %s", name.c_str(), s.name);
                    label(p.lo, p.hi, sl);
                }
            }

            // A backend that reports its own image regions knows their real
            // protections; only the labels above are added to them.
            if ( reports_state )
                continue;

            if ( secs.empty() )
            {
                Piece whole;
                whole.lo = mlo;
                whole.hi = mhi;
                secs.push_back(whole);
            }
            for ( Piece &p : secs )
            {
                p.type  = ITTD_REGION_IMAGE;
                p.since = m->loaded;
                lay.put(p);
            }
            // Then every protection change the recording made inside it since
            // it loaded, in order: a loader patching its imports, or an
            // unpacker making its own code writable.
            for ( const RegionChange *c : protects )
            {
                if ( m->loaded.is_valid() && c->pos < m->loaded )
                    continue;
                ea_t lo = std::max(c->base, mlo);
                ea_t hi = std::min((ea_t)(c->base + c->size), mhi);
                if ( lo < hi )
                    lay.protect(lo, hi, c->protect);
            }
        }

        // ---- out, with what each region is used for ---------------------------
        std::sort(labels.begin(), labels.end(),
                  [](const Label &a, const Label &b) { return a.lo < b.lo; });
        for ( const auto &kv : lay.m )
        {
            const Piece &p = kv.second;
            AddressRegion r;
            r.base = p.lo;
            r.size = (uint64_t)(p.hi - p.lo);
            r.protect = p.protect;
            r.reserved = p.reserved;
            r.type = p.type;
            r.since = p.since;
            // The most specific label wins: a section over its module, a heap
            // over the region it sits in. Narrower is more specific.
            const Label *best = nullptr;
            for ( const Label &l : labels )
            {
                if ( l.lo >= p.hi )
                    break;
                if ( l.hi <= p.lo )
                    continue;
                // A point label (a heap, a PEB field) names only the region it
                // falls in.
                if ( best == nullptr || (l.hi - l.lo) < (best->hi - best->lo) )
                    best = &l;
            }
            if ( best != nullptr )
                r.use = best->text;
            out->push_back(r);
        }
    }
}
