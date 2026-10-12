#include "ui/names.h"
#include "debugger/trace_manager.h"

namespace idattd
{
    qstring func_display_name(ea_t ea)
    {
        qstring name;
        get_func_name(&name, ea);
        if ( name.empty() )
            get_name(&name, ea);
        qstring dem;
        if ( !name.empty() && demangle_name(&dem, name.c_str(), 0) > 0 && !dem.empty() )
            return dem;
        if ( name.empty() )
            name.sprnt("0x%llX", (uint64_t)ea);
        return name;
    }

    // How far below an address a name may sit and still be taken to belong to
    // it, when there is no exception table to settle the question.
    static const ea_t MAX_NAME_OFFSET = 0x1000;

    // "name+0x10". Callers must pass an anchor at or below the address; an
    // anchor above it would mean the name belongs to something the address is
    // not part of, so the offset is dropped rather than rendered backwards.
    static qstring name_with_offset(const qstring &name, ea_t ea, ea_t anchor)
    {
        qstring out = name;
        if ( ea > anchor )
            out.cat_sprnt("+0x%llX", (uint64_t)(ea - anchor));
        return out;
    }

    qstring describe_address(TraceManager *mgr, ea_t ea)
    {
        qstring out;
        if ( ea == BADADDR )
            return out;

        qstring mod = mgr != nullptr ? mgr->modules().name_at(ea) : qstring();
        auto qualify = [&mod](const qstring &what)
        {
            qstring r;
            if ( mod.empty() )
                r = what;
            else
                r.sprnt("%s!%s", mod.c_str(), what.c_str());
            return r;
        };

        // 1. Inside a function IDA has actually defined. Let IDA render it:
        //    a function can own chunks placed anywhere, including below its
        //    entry, and only IDA knows how it names an address in one. Measuring
        //    from the entry ourselves would report an address inside a function
        //    as an offset before it.
        //
        //    GNCN_REQFUNC makes this answer only for an address that really is
        //    in a function, which is what keeps it from borrowing the nearest
        //    unrelated name the way the fallbacks below have to guard against.
        qstring nice;
        if ( get_nice_colored_name(&nice, ea, GNCN_NOSEG | GNCN_NOCOLOR | GNCN_REQFUNC) > 0
          && !nice.empty() )
        {
            return qualify(nice);
        }

        func_entry_info_t fi;
        if ( get_func_entry_info(&fi, ea) )
        {
            // In a function, but IDA had no name for the address. Name the
            // function and leave the offset out rather than measure from an
            // entry chunk the address may sit below.
            qstring fn = func_display_name(fi.start_ea);
            if ( !fn.empty() )
                return qualify(name_with_offset(fn, ea, fi.start_ea));
        }

        // 2. The exception table of the address's module knows exactly where its
        //    function starts, symbols or not. Anything named before that start
        //    belongs to a different function and must not be borrowed.
        ea_t fnstart = BADADDR, fnend = BADADDR;
        bool have_fn = mgr != nullptr && mgr->modules().function_range_at(ea, fnstart, fnend);

        // 3. The nearest name at or below the address. get_nlist_idx returns the
        //    closest match, which can sit above the address, so step back until
        //    it does not.
        size_t idx = get_nlist_idx(ea);
        size_t n   = get_nlist_size();
        while ( idx < n && get_nlist_ea(idx) > ea )
        {
            if ( idx == 0 )
            {
                idx = n;    // nothing at or below
                break;
            }
            idx--;
        }
        if ( idx < n )
        {
            ea_t at = get_nlist_ea(idx);
            const char *nm = get_nlist_name(idx);
            bool usable = nm != nullptr && at <= ea;
            // Inside the real function, or -- with no exception table to consult
            // -- merely close enough to be plausible.
            if ( usable )
                usable = have_fn ? at >= fnstart : (ea - at <= MAX_NAME_OFFSET);
            if ( usable )
                return qualify(name_with_offset(qstring(nm), ea, at));
        }

        // 4. No name inside the function, but we do know where it starts. Name it
        //    the way IDA names an unnamed function, so the row agrees with the
        //    disassembly the user lands in.
        if ( have_fn )
        {
            qstring what;
            what.sprnt("sub_%llX", (uint64_t)fnstart);
            return qualify(name_with_offset(what, ea, fnstart));
        }

        // 5. Relative to the module, which is unambiguous even with no symbols.
        ea_t lo = 0, hi = 0;
        if ( mgr != nullptr && mgr->modules().range_at(ea, lo, hi) && !mod.empty() )
        {
            out.sprnt("%s+0x%llX", mod.c_str(), (uint64_t)(ea - lo));
            return out;
        }
        out.sprnt("0x%llX", (uint64_t)ea);
        return out;
    }
}
