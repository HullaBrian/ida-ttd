#include "ui/decompiler.h"
#include "analysis/coverage.h"

// hexrays.hpp is the one SDK header that does not compile warning-free at this
// project's level (narrowing conversions and a signed/unsigned compare, all in
// inline code we do not call). Silence them around the include only, so the
// plugin's own code keeps being held to a clean build.
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
    // anchors: an index into cfunc_t::treeitems, each of which knows its own
    // address. That is the mechanism hxe_func_printed documents, and it is what
    // this reads. The obvious alternative, get_line_item(), answers about one
    // column of the line -- and column zero, where the first attempt at this
    // asked, is indentation, which belongs to no item. Every line came back with
    // nothing and not a single one was ever painted.
    //
    // all of them, not just the first. One line is many ctree items: the
    // statement, the variable assigned, the call, each argument -- and they come
    // from different instructions. Taking the first one to have an address is why
    // "v11 = v7(...)" showed no note for its call: the first anchor on that line
    // is the assignment, and the annotation lives on the call instruction a few
    // bytes earlier.
    static void line_addresses(const cfunc_t *cf, const char *line,
                               std::vector<ea_t> &out)
    {
        out.clear();
        // A line has a handful of items; the cap is only here so a pathological
        // one cannot make this loop expensive on every repaint.
        static const size_t kMaxPerLine = 32;

        for ( const char *p = line; p[0] != '\0' && out.size() < kMaxPerLine; )
        {
            if ( p[0] != COLOR_ON || p[1] != (char)COLOR_ADDR )
            {
                p++;
                continue;
            }
            // COLOR_ON, the tag byte, then COLOR_ADDR_SIZE hex digits, with no
            // closing COLOR_OFF. A truncated tag ends the scan rather than
            // reading past the end of the line.
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
            // Colours and comments live on item HEADS, and an item's address
            // need not be one. Normalise here so callers compare like with like.
            ea_t ea = it->ea;
            ea_t head = get_item_head(ea);
            if ( head != BADADDR )
                ea = head;
            if ( std::find(out.begin(), out.end(), ea) == out.end() )
                out.push_back(ea);
        }
    }

    // Marker that says a line already carries our note, so repainting the same
    // text twice does not append it twice.
    static const char TTD_CMT_MARK[] = "// TTD: ";

    // Show the annotation an indirect call site carries on its pseudocode line.
    //
    // The decompiler does not surface a repeatable comment on an arbitrary
    // instruction, so the note is appended to the line here. Multi-line comments
    // are flattened: a newline inside a simpleline_t would corrupt the view.
    static void append_ttd_comments(simpleline_t &sl, const std::vector<ea_t> &eas,
                                    std::set<ea_t> &already)
    {
        if ( strstr(sl.line.c_str(), TTD_CMT_MARK) != nullptr )
            return;                          // already on this line

        // Every address on the line can carry one, and a line with two indirect
        // calls in it wants both. Identical notes are shown once.
        qstring joined;
        for ( ea_t ea : eas )
        {
            // A call whose arguments print one per line puts the same call
            // instruction on every one of those lines, so the note would repeat
            // down the whole call. It belongs on the first line that mentions
            // the call and nowhere else.
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
                    // A newline inside a simpleline_t would corrupt the view, so
                    // a multi-target note is flattened; collapse the run and the
                    // indentation that follows it.
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
            if ( strstr(joined.c_str(), body) != nullptr )
                continue;                          // same note twice on one line
            if ( !joined.empty() )
                joined.append("; ");
            joined.append(body);
        }
        if ( joined.empty() )
            return;

        sl.line.append(COLSTR("  ", SCOLOR_AUTOCMT));
        sl.line.append(SCOLOR_ON);
        sl.line.append(SCOLOR_AUTOCMT);
        sl.line.append(TTD_CMT_MARK);
        sl.line.append(joined);
        sl.line.append(SCOLOR_OFF);
        sl.line.append(SCOLOR_AUTOCMT);
    }

    // Paint one function's pseudocode from the colours already in the database.
    //
    // Each ctree item knows the address it was decompiled from, so a line is
    // covered exactly when that address carries one of our coverage colours.
    // The line keeps the colour it was painted with, so a database highlighted
    // in two shades reads the same in the decompiler as in the disassembly.
    static void paint(cfunc_t *cf)
    {
        if ( cf == nullptr )
            return;
        std::set<bgcolor_t> ours = coverage_colors();
        std::vector<ea_t>   eas;              // reused; no per-line allocation
        // Call sites whose note has already been placed, so a call printed
        // across several lines is annotated once rather than on every one.
        std::set<ea_t>      annotated;

        for ( size_t i = 0; i < cf->sv.size(); i++ )
        {
            simpleline_t &sl = cf->sv[i];

            // Only ever repaint our colour. Clearing it first means a line that
            // stops being covered (the sweep was cleared, the shade changed)
            // loses the highlight instead of keeping a stale one, and a colour
            // something else set is left alone.
            if ( ours.find(sl.bgcolor) != ours.end() )
                sl.bgcolor = DEFCOLOR;

            line_addresses(cf, sl.line.c_str(), eas);
            if ( eas.empty() )
                continue;

            // A line is covered if ANY instruction it came from ran. A statement
            // that spans several instructions is not half-executed in any sense
            // the reader cares about.
            for ( ea_t ea : eas )
            {
                bgcolor_t c = get_item_color(ea);
                if ( c != DEFCOLOR && ours.find(c) != ours.end() )
                {
                    sl.bgcolor = c;
                    break;
                }
            }

            append_ttd_comments(sl, eas, annotated);
        }
    }

    static ssize_t idaapi hx_callback(void *, hexrays_event_t ev, va_list va)
    {
        switch ( ev )
        {
            case hxe_func_printed:
                // The text has just been generated; sv is ours to colour now.
                paint(va_arg(va, cfunc_t *));
                break;

            default:
                break;
        }
        return 0;
    }

    // Safe and cheap to call repeatedly, and it is called repeatedly on purpose.
    // Hex-Rays is itself a plugin: asking for it while our own plugmod is being
    // constructed can be too early, init_hexrays_plugin() then says there is no
    // decompiler, and if that were the only attempt nothing would ever be hooked.
    // The SDK's own samples call it at each point of use for the same reason, so
    // this runs again at session start, when the UI is ready, and on every stop.
    bool init_decompiler()
    {
        if ( g_hooked )
            return true;
        if ( !init_hexrays_plugin() )
        {
            // Say so once. Silence here is indistinguishable from the painting
            // being broken, which is exactly the confusion to avoid.
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
        // Find the open views by asking IDA for them rather than by remembering
        // the ones we saw opened. A view that already existed before the hook was
        // installed was never seen, and that is precisely the view most in need of
        // a repaint. Pseudocode windows are titled Pseudocode-A onwards.
        for ( char c = 'A'; c <= 'Z'; c++ )
        {
            char title[16];
            qsnprintf(title, sizeof(title), "Pseudocode-%c", c);
            TWidget *w = find_widget(title);
            if ( w == nullptr )
                continue;
            vdui_t *vu = get_widget_vdui(w);
            if ( vu == nullptr || vu->cfunc == nullptr )
                continue;

            // Repaint the text the view is ALREADY showing, then tell the widget
            // to redraw it. Asking the decompiler to refresh instead only
            // regenerates the text, which is why the highlight did not appear
            // until something else forced the window to redraw. Nothing about
            // the decompilation has changed here -- only line colours and notes
            // -- so regenerating it would be wasted work as well as ineffective.
            paint(vu->cfunc);
            refresh_custom_viewer(vu->ct);
        }
    }

    void close_volatile_pseudocode_views()
    {
        if ( !g_hooked )
            return;
        int closed = 0;
        for ( char c = 'A'; c <= 'Z'; c++ )
        {
            char title[16];
            qsnprintf(title, sizeof(title), "Pseudocode-%c", c);
            TWidget *w = find_widget(title);
            if ( w == nullptr )
                continue;
            vdui_t *vu = get_widget_vdui(w);
            if ( vu == nullptr || vu->cfunc == nullptr )
                continue;

            // Keep anything backed by a segment that came from the file. The
            // test is written this way on purpose so it gives the same answer
            // whether the debugger segments have been torn down yet or not: an
            // ephemeral segment and a vanished one are both "will not survive",
            // and only a loader segment is "will".
            segment_info_t si;
            if ( get_segment_info(&si, vu->cfunc->entry_ea) && !si.is_ephemeral_segm() )
                continue;

            // No WCLS_SAVE: the point is to keep it OUT of the saved desktop.
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
