#include "ui/decompiler.h"
#include "analysis/coverage.h"

// hexrays.hpp is the one SDK header that warns at this project's level
// (narrowing and a signed/unsigned compare, in inline code the plugin never
// calls). Silence it around the include only, so the plugin's own code stays
// held to a clean build.
#pragma warning(push)
#pragma warning(disable: 4018)  // signed/unsigned mismatch
#pragma warning(disable: 4244)  // conversion, possible loss of data
#pragma warning(disable: 4267)  // size_t -> int, possible loss of data
#include <hexrays.hpp>
#pragma warning(pop)

namespace idattd
{
    static bool g_hooked           = false;
    static bool g_reported_missing = false;

    // Every address a pseudocode line was decompiled from.
    //
    // Generated pseudocode carries invisible COLOR_ADDR tags holding ctree
    // anchors (indices into cfunc_t::treeitems, each of which knows its
    // address); hxe_func_printed documents this. get_line_item() is no
    // substitute: it answers for one column, and column zero is indentation,
    // which belongs to no item.
    //
    // All anchors, not just the first: one line holds many items (statement,
    // assigned variable, call, arguments) from different instructions. In
    // "v11 = v7(...)" the first anchor is the assignment, while the call's
    // annotation is on the call instruction a few bytes earlier.
    static void line_addresses(const cfunc_t *cf, const char *line,
                               std::vector<ea_t> &out)
    {
        out.clear();
        // Caps a pathological line, since this runs on every repaint.
        static const size_t kMaxPerLine = 32;

        for ( const char *p = line; p[0] != '\0' && out.size() < kMaxPerLine; )
        {
            if ( p[0] != COLOR_ON || p[1] != (char)COLOR_ADDR )
            {
                p++;
                continue;
            }
            // COLOR_ON, the tag byte, then COLOR_ADDR_SIZE hex digits, with no
            // closing COLOR_OFF. A truncated tag ends the scan.
            uval_t v  = 0;
            bool   ok = true;
            for ( size_t i = 0; i < COLOR_ADDR_SIZE; i++ )
            {
                char c = p[2 + i];
                int  d;
                if ( c >= '0' && c <= '9' )      d = c - '0';
                else if ( c >= 'A' && c <= 'F' ) d = c - 'A' + 10;
                else if ( c >= 'a' && c <= 'f' ) d = c - 'a' + 10;
                else { ok = false; break; }
                v = (v << 4) | (uval_t)d;
            }
            if ( !ok )
                break;
            p += 2 + COLOR_ADDR_SIZE;

            ctree_anchor_t anc;
            anc.value = v;
            if ( !anc.is_citem_anchor() )
                continue;                   // a local variable, not a statement
            int idx = anc.get_index();
            if ( idx < 0 || (size_t)idx >= cf->treeitems.size() )
                continue;
            const citem_t *it = cf->treeitems[idx];
            if ( it == nullptr || it->ea == BADADDR )
                continue;
            // Colours and comments live on item heads, and an item's address
            // need not be one.
            ea_t ea = it->ea;
            ea_t head = get_item_head(ea);
            if ( head != BADADDR )
                ea = head;
            if ( std::find(out.begin(), out.end(), ea) == out.end() )
                out.push_back(ea);
        }
    }

    // Marks a line that already carries the plugin's note, so repainting the
    // same text does not append it again.
    static const char TTD_CMT_MARK[] = "// TTD: ";

    // Whether 'joined' (notes separated by "; ") already holds 'note' as a
    // whole entry. A substring test would drop "-> foo" next to
    // "-> foo_impl". A note may itself contain "; " (a flattened
    // multi-target note), so it is matched as one unit at entry boundaries
    // rather than by splitting.
    static bool has_note(const qstring &joined, const char *note)
    {
        const size_t n = strlen(note);
        if ( n == 0 )
            return true;
        for ( size_t at = joined.find(note); at != qstring::npos; at = joined.find(note, at + 1) )
        {
            const bool starts = at == 0 || (at >= 2 && joined[at - 2] == ';' && joined[at - 1] == ' ');
            const size_t end = at + n;
            const bool ends = end == joined.length()
                           || (end + 1 < joined.length() && joined[end] == ';' && joined[end + 1] == ' ');
            if ( starts && ends )
                return true;
        }
        return false;
    }

    // Show the annotation an indirect call site carries on its pseudocode line.
    // The decompiler does not surface a repeatable comment on an arbitrary
    // instruction, so the note is appended here.
    static void append_ttd_comments(simpleline_t &sl, const std::vector<ea_t> &eas,
                                    std::set<ea_t> &already)
    {
        // Painted by an earlier pass (every open or refresh of a cached view
        // paints again). Its call sites still count as annotated; otherwise
        // the next line naming the same call (an argument on its own line)
        // would take the note too, one line further down per repaint.
        if ( strstr(sl.line.c_str(), TTD_CMT_MARK) != nullptr )
        {
            already.insert(eas.begin(), eas.end());
            return;
        }

        // A line with two indirect calls shows both notes; identical notes
        // are shown once.
        qstring joined;
        for ( ea_t ea : eas )
        {
            // A call with one argument per line names the same instruction on
            // each of those lines; the note goes on the first only.
            if ( already.find(ea) != already.end() )
                continue;

            qstring cmt;
            if ( get_cmt(&cmt, ea, true) <= 0 || cmt.empty() )
                continue;
            if ( strncmp(cmt.c_str(), "TTD: ", 5) != 0 )
                continue;                    // somebody else's comment

            qstring flat;
            for ( size_t i = 0; i < cmt.length(); i++ )
            {
                char c = cmt[i];
                if ( c == '\n' || c == '\r' )
                {
                    // A newline inside a simpleline_t corrupts the view, so a
                    // multi-target note is flattened: collapse the run of line
                    // breaks and the indentation after it.
                    if ( !flat.empty() && !flat.ends_with("; ") )
                        flat.append("; ");
                    while ( i + 1 < cmt.length() && (cmt[i + 1] == ' ' || cmt[i + 1] == '\n'
                                                  || cmt[i + 1] == '\r' || cmt[i + 1] == '\t') )
                        i++;
                    continue;
                }
                flat.append(c);
            }
            const char *body = flat.c_str() + 5;   // past the "TTD: " prefix
            already.insert(ea);
            if ( has_note(joined, body) )
                continue;                          // same note twice on one line
            if ( !joined.empty() )
                joined.append("; ");
            joined.append(body);
        }
        if ( joined.empty() )
            return;

        // Not the automatic comment colour: too dim on a coverage colour.
        sl.line.append("  ");
        sl.line.append(SCOLOR_ON);
        sl.line.append(SCOLOR_REGCMT);
        sl.line.append(TTD_CMT_MARK);
        sl.line.append(joined);
        sl.line.append(SCOLOR_OFF);
        sl.line.append(SCOLOR_REGCMT);
    }

    // On a coverage colour, dim grey text (Hex-Rays' argument names) in the
    // normal text colour, so it stays readable.
    static void brighten_dim_text(qstring &line)
    {
        for ( size_t i = 0; i + 1 < line.length(); i++ )
        {
            if ( (line[i] == COLOR_ON || line[i] == COLOR_OFF) && line[i + 1] == COLOR_AUTOCMT )
                line[i + 1] = COLOR_DEFAULT;
            else if ( line[i] == COLOR_ON && line[i + 1] == COLOR_ADDR )
                i += 1 + COLOR_ADDR_SIZE;   // skip an address tag's digits
        }
    }

    // Paint one function's pseudocode from the colours already in the database.
    // A line is covered when an address it came from carries one of the
    // plugin's coverage colours, and takes that colour, so a database
    // highlighted in two shades reads the same here as in the disassembly.
    static void paint(cfunc_t *cf)
    {
        if ( cf == nullptr )
            return;
        std::set<bgcolor_t> ours = coverage_colors();
        std::vector<ea_t>   eas;              // reused; no per-line allocation
        // Call sites whose note is already placed (see append_ttd_comments).
        std::set<ea_t>      annotated;

        for ( size_t i = 0; i < cf->sv.size(); i++ )
        {
            simpleline_t &sl = cf->sv[i];

            // Clear only the plugin's colours first: a line no longer covered
            // (sweep cleared, shade changed) loses a stale highlight, and a
            // colour set by something else is left alone.
            if ( ours.find(sl.bgcolor) != ours.end() )
                sl.bgcolor = DEFCOLOR;

            line_addresses(cf, sl.line.c_str(), eas);
            if ( eas.empty() )
                continue;

            // Covered if any instruction it came from ran. This recording's
            // shade wins over another recording's (a fork's parent, or a fork).
            for ( ea_t ea : eas )
            {
                bgcolor_t c = get_item_color(ea);
                if ( c != DEFCOLOR && ours.find(c) != ours.end() )
                {
                    sl.bgcolor = c;
                    if ( !coverage_is_previous(c) )
                        break;
                }
            }
            if ( sl.bgcolor != DEFCOLOR )
                brighten_dim_text(sl.line);

            append_ttd_comments(sl, eas, annotated);
        }
    }

    static ssize_t idaapi hx_callback(void *, hexrays_event_t ev, va_list va)
    {
        switch ( ev )
        {
            case hxe_func_printed:
                // The text has just been generated; sv may be coloured now.
                paint(va_arg(va, cfunc_t *));
                break;

            case hxe_open_pseudocode:
            case hxe_refresh_pseudocode:
            {
                // A cached decompilation was printed before the function was
                // highlighted, and raises no hxe_func_printed: paint it here.
                vdui_t *vu = va_arg(va, vdui_t *);
                if ( vu != nullptr && vu->cfunc != nullptr )
                    paint(vu->cfunc);
                break;
            }

            default:
                break;
        }
        return 0;
    }

    // Cheap, and called repeatedly on purpose. Hex-Rays is itself a plugin, and
    // while this plugmod is being constructed init_hexrays_plugin() can still
    // report no decompiler. Like the SDK samples, this is retried at each
    // point of use: session start and every stop.
    bool init_decompiler()
    {
        if ( g_hooked )
            return true;
        if ( !init_hexrays_plugin() )
        {
            // Say so once: silence would look like broken painting.
            if ( !g_reported_missing )
            {
                g_reported_missing = true;
                msg("[ida-ttd] no decompiler available yet: pseudocode will not be "
                    "highlighted. (Retried at every stop; this is only said once.)\n");
            }
            return false;
        }
        g_hooked = install_hexrays_callback(hx_callback, nullptr);
        msg("[ida-ttd] decompiler found: pseudocode %s follow the execution "
            "highlight.\n", g_hooked ? "will" : "could NOT be hooked to");
        return g_hooked;
    }

    void term_decompiler()
    {
        if ( g_hooked )
        {
            remove_hexrays_callback(hx_callback, nullptr);
            g_hooked = false;
        }
    }

    void refresh_pseudocode_views()
    {
        if ( !g_hooked )
            return;
        // Ask IDA for the open views rather than remember those seen opening:
        // a view that predates the hook was never seen, and needs the repaint
        // most.
        std::vector<TWidget *> views;
        list_pseudocode_views(views);
        for ( TWidget *w : views )
        {
            vdui_t *vu = get_widget_vdui(w);
            if ( vu == nullptr || vu->cfunc == nullptr )
                continue;

            // Repaint the text the view already shows, then redraw the widget.
            // A decompiler refresh only regenerates the text, so the highlight
            // did not appear until something else redrew the window; and only
            // colours and notes changed, so regenerating would be wasted work.
            paint(vu->cfunc);
            refresh_custom_viewer(vu->ct);
        }
    }

    // Pseudocode windows are titled Pseudocode-A onwards.
    void list_pseudocode_views(std::vector<TWidget *> &out)
    {
        out.clear();
        for ( char c = 'A'; c <= 'Z'; c++ )
        {
            char title[16];
            qsnprintf(title, sizeof(title), "Pseudocode-%c", c);
            TWidget *w = find_widget(title);
            if ( w != nullptr && get_widget_type(w) == BWN_PSEUDOCODE )
                out.push_back(w);
        }
    }

    ea_t pseudocode_function(TWidget *view)
    {
        if ( !g_hooked || view == nullptr )
            return BADADDR;
        vdui_t *vu = get_widget_vdui(view);
        if ( vu == nullptr || vu->cfunc == nullptr )
            return BADADDR;
        return vu->cfunc->entry_ea;
    }

    bool can_decompile(ea_t func_ea)
    {
        if ( !g_hooked )
            return false;
        hexrays_failure_t hf;
        return decompile_function(func_ea, &hf, DECOMP_NO_WAIT) != nullptr;
    }

    // Put the caret of a pseudocode view on line 'line', column 'x'.
    //
    // The place comes from the view's own: a pseudocode view's position is a
    // hexrays_place_t, larger than simpleline_place_t, and Hex-Rays reads the
    // rest of it (the function among other things). Jumping with a
    // simpleline_place_t made IDA store that smaller object as the view's
    // position, and Hex-Rays then read past its end: decompilations of
    // "<garbage>: bad input ranges" on every step from pseudocode, crashes,
    // and a database whose saved window position crashed IDA on reopening.
    static void jump_to_line(TWidget *ct, int line, int x)
    {
        const place_t *cur = get_custom_viewer_place(ct, false, nullptr, nullptr);
        if ( cur == nullptr )
            return;
        void *ud = get_viewer_user_data(ct);
        place_t *pl = cur->makeplace(ud, (uval_t)line, 0);
        if ( pl == nullptr )
            return;
        jumpto(ct, pl, x, 0);
        // Whether makeplace() handed over a new object or a static one
        // depends on the class.
        int flags = 0;
        if ( get_place_class(&flags, nullptr, pl->id()) != nullptr
          && (flags & PCF_MAKEPLACE_ALLOCATES) != 0 )
        {
            delete pl;
        }
    }

    bool show_in_pseudocode(TWidget *view, ea_t ea)
    {
        if ( !g_hooked || view == nullptr )
            return false;
        vdui_t *vu = get_widget_vdui(view);
        func_entry_info_t fi;
        if ( vu == nullptr || !get_func_entry_info(&fi, ea) )
            return false;

        // Decompile first and switch only on success. open_pseudocode() does
        // both, but picks the window itself (the wrong one) and shows a
        // failure dialog on every step.
        if ( vu->cfunc == nullptr || vu->cfunc->entry_ea != fi.start_ea )
        {
            hexrays_failure_t hf;
            cfuncptr_t cf = decompile_function(fi.start_ea, &hf, DECOMP_NO_WAIT);
            if ( cf == nullptr )
                return false;
            vu->switch_to(cf, false);
        }

        // Caret on the first line of the statement holding ea: for code
        // setting up a call's argument, the call, not the argument's line.
        const citem_t *best = nullptr;
        for ( const citem_t *it : vu->cfunc->treeitems )
        {
            if ( it == nullptr || it->ea != ea )
                continue;
            if ( best == nullptr || (best->is_expr() && !it->is_expr()) )
                best = it;
        }
        while ( best != nullptr && best->is_expr() )
            best = vu->cfunc->body.find_parent_of(best);
        int x = 0;
        int y = 0;
        if ( best != nullptr && vu->cfunc->find_item_coords(best, &x, &y) )
            jump_to_line(vu->ct, y, x);
        return true;
    }

    void redecompile_pseudocode_views()
    {
        if ( !g_hooked )
            return;
        std::vector<TWidget *> views;
        list_pseudocode_views(views);
        for ( TWidget *w : views )
        {
            vdui_t *vu = get_widget_vdui(w);
            if ( vu != nullptr && vu->cfunc != nullptr )
            {
                mark_cfunc_dirty(vu->cfunc->entry_ea, false);
                vu->refresh_view(true);
            }
        }
    }

    void close_volatile_pseudocode_views()
    {
        if ( !g_hooked )
            return;
        int closed = 0;
        std::vector<TWidget *> views;
        list_pseudocode_views(views);
        for ( TWidget *w : views )
        {
            vdui_t *vu = get_widget_vdui(w);
            if ( vu == nullptr || vu->cfunc == nullptr )
                continue;

            // Keep views backed by a loader segment. Written so the answer is
            // the same whether or not the debugger segments are torn down yet:
            // ephemeral and vanished segments both fail to survive.
            segment_info_t si;
            if ( get_segment_info(&si, vu->cfunc->entry_ea) && !si.is_ephemeral_segm() )
                continue;

            // No WCLS_SAVE: keep it out of the saved desktop.
            close_widget(w, WCLS_CLOSE_LATER);
            closed++;
        }
        if ( closed != 0 )
            msg("[ida-ttd] closed %d pseudocode view(s) of runtime-allocated code: "
                "those bytes exist only while a trace is loaded, and a view left "
                "open on them fails to decompile when the database is reopened.\n",
                closed);
    }
}
