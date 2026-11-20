#include "ui/decompiler.h"
#include "analysis/coverage.h"
#include "analysis/callsites.h"

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
    static void (*g_edit_hook)(ea_t) = nullptr;

    void set_function_edit_hook(void (*hook)(ea_t func_ea))
    {
        g_edit_hook = hook;
    }

    // What a paint reads changes only with an item's color or comment, so
    // the stop-time repaint is skipped for a view painted since the last
    // such change. Any writer counts (a sweep, an annotation, the user, a
    // script): the database's own events bump the generation, rather than
    // each of the plugin's writers remembering to.
    static uint64_t g_paint_generation = 1;
    // The generation each function's text was last painted at. Keyed by the
    // cfunc_t: regenerated text is painted on hxe_func_printed and recorded
    // again, so a stale entry is never trusted for new text.
    static std::map<const cfunc_t *, uint64_t> g_painted_at;

    struct PaintInputsListener : public event_listener_t
    {
        ssize_t idaapi on_event(ssize_t code, va_list) override
        {
            if ( code == idb_event::item_color_changed || code == idb_event::cmt_changed )
                g_paint_generation++;
            return 0;
        }
    };
    static PaintInputsListener g_paint_inputs;

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
    //
    // 'items', when given, receives the items themselves.
    static void line_addresses(const cfunc_t *cf, const char *line,
                               std::vector<ea_t> &out,
                               std::vector<const citem_t *> *items = nullptr)
    {
        out.clear();
        if ( items != nullptr )
            items->clear();
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
            if ( items != nullptr )
                items->push_back(it);
            // Colors and comments live on item heads, and an item's address
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

    // The text of the function's lines that show a note already, without
    // color tags, one per line. From 9.5 Hex-Rays prints a call
    // instruction's repeatable comment itself, the annotation's note
    // included; before, it printed none. It puts the comment wherever its own
    // map of instructions to statements says, which is often not a line
    // naming the call: a neighbouring statement, or a comment line of its own
    // above it. So what it shows is matched by text, over the whole function,
    // and those notes are not added a second time. Notes the plugin appended
    // in an earlier paint are in it too, which keeps a repaint from adding
    // one again on an earlier line naming the same call.
    static qstring notes_already_shown(const cfunc_t *cf)
    {
        qstring shown, text;
        for ( const simpleline_t &sl : cf->sv )
        {
            // Cheap first: the note's prefix survives the color tags whole.
            if ( strstr(sl.line.c_str(), "TTD: ") == nullptr )
                continue;
            tag_remove(&text, sl.line.c_str());
            shown.append(text);
            shown.append('\n');
        }
        return shown;
    }

    // Whether 'shown' holds the note whose first line is 'note' as a whole
    // note: "calls a!foo" must not count as shown because of "calls a!foo_impl".
    static bool note_shown(const qstring &shown, const qstring &note)
    {
        if ( note.empty() || shown.empty() )
            return false;
        for ( const char *at = strstr(shown.c_str(), note.c_str()); at != nullptr;
              at = strstr(at + 1, note.c_str()) )
        {
            const char end = at[note.length()];
            if ( end == '\0' || end == '\n' || end == ' ' || end == ';' )
                return true;
        }
        return false;
    }

    // Show the annotation an indirect call site carries on its pseudocode line,
    // unless the function's text shows it already (notes_already_shown).
    static void append_ttd_comments(simpleline_t &sl, const std::vector<ea_t> &eas,
                                    std::set<ea_t> &already, const qstring &shown)
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

            // The flag first: most anchors have no comment, and this runs
            // for every line on every repaint.
            qstring full;
            if ( !has_cmt(get_flags(ea)) || get_cmt(&full, ea, true) <= 0 || full.empty() )
                continue;
            // Only the annotation's note, which follows the user's own text
            // when the site has some.
            qstring cmt = ttd_call_note(full);
            if ( cmt.empty() )
                continue;
            if ( note_shown(shown, qstring(cmt.c_str(), strcspn(cmt.c_str(), "\r\n"))) )
            {
                already.insert(ea);
                continue;                          // Hex-Rays prints it
            }

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

        // Not the automatic comment color: too dim on a coverage color.
        sl.line.append("  ");
        sl.line.append(SCOLOR_ON);
        sl.line.append(SCOLOR_REGCMT);
        sl.line.append(TTD_CMT_MARK);
        sl.line.append(joined);
        sl.line.append(SCOLOR_OFF);
        sl.line.append(SCOLOR_REGCMT);
    }

    // The if statement a conditional move at 'ea' became, when 'it' is part
    // of one, else nullptr. Hex-Rays can write one CMOVcc as a whole if:
    // the condition and the assignment in the body are then both items of
    // that instruction, and the condition has its address. '*in_branch' says
    // whether 'it' is in the then or else branch (the assignment the move
    // makes, which only happens when the condition holds) rather than the
    // condition itself (which always runs).
    static const cinsn_t *cmov_if_of(const cfunc_t *cf, const citem_t *it, ea_t ea, bool *in_branch)
    {
        *in_branch = false;
        if ( it->op == cit_if && ((const cinsn_t *)it)->cif->expr.ea == ea )
            return (const cinsn_t *)it;
        const citem_t *child = it;
        for ( const citem_t *p = cf->body.find_parent_of(child);
              p != nullptr;
              child = p, p = cf->body.find_parent_of(p) )
        {
            if ( p->op != cit_if )
                continue;
            const cinsn_t *ifs = (const cinsn_t *)p;
            const cif_t *ci = ifs->cif;
            if ( ci->expr.ea != ea )
                continue;                   // another if, around this one
            *in_branch = child == ci->ithen || child == ci->ielse;
            return ifs;
        }
        return nullptr;
    }

    // Whether a line is the body of an if made from a conditional move that
    // never moved in this recording ('untaken'): the instruction ran, so
    // coverage holds it, but what the line says never happened.
    static bool in_untaken_branch(const cfunc_t *cf, const std::vector<const citem_t *> &items,
                                  const std::set<ea_t> &untaken)
    {
        for ( const citem_t *it : items )
        {
            if ( untaken.count(it->ea) == 0 )
                continue;
            bool in_branch = false;
            if ( cmov_if_of(cf, it, it->ea, &in_branch) != nullptr && in_branch )
                return true;
        }
        return false;
    }

    // On a coverage color, dim gray text (Hex-Rays' argument names) in the
    // normal text color, so it stays readable.
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

    // Paint one function's pseudocode from the colors already in the database.
    // A line is covered when an address it came from carries one of the
    // plugin's coverage colors, and takes that color, so a database
    // highlighted in two shades reads the same here as in the disassembly.
    // The exception is the body of an if made from a conditional move that
    // never moved (in_untaken_branch), which is left unpainted.
    //
    // True when a line lost its coverage color: its text was brightened in
    // place (brighten_dim_text), and only regenerating it brings back the
    // dim argument names.
    static bool paint(cfunc_t *cf)
    {
        if ( cf == nullptr )
            return false;
        bool uncovered = false;
        // Both sets once per paint: each is a netnode walk.
        std::set<bgcolor_t> previous, only_here;
        std::set<bgcolor_t> ours = coverage_colors(&previous, &only_here);
        std::vector<ea_t>   eas;              // reused; no per-line allocation
        // Call sites whose note is already placed (see append_ttd_comments).
        std::set<ea_t>      annotated;
        // The function's conditional moves that never moved, and so the
        // lines' items, needed only when there are some.
        std::set<ea_t> untaken;
        func_entry_info_t fi;
        if ( get_func_entry_info(&fi, cf->entry_ea) )
            untaken = untaken_conditional_moves(fi.start_ea, fi.end_ea);
        std::vector<const citem_t *> items;
        const qstring shown = notes_already_shown(cf);

        for ( size_t i = 0; i < cf->sv.size(); i++ )
        {
            simpleline_t &sl = cf->sv[i];

            // Clear only the plugin's colors first: a line no longer covered
            // (sweep cleared, shade changed) loses a stale highlight, and a
            // color set by something else is left alone.
            const bool was_ours = ours.find(sl.bgcolor) != ours.end();
            if ( was_ours )
                sl.bgcolor = DEFCOLOR;

            line_addresses(cf, sl.line.c_str(), eas, untaken.empty() ? nullptr : &items);
            if ( eas.empty() )
                continue;
            if ( !untaken.empty() && in_untaken_branch(cf, items, untaken) )
            {
                if ( was_ours )
                    uncovered = true;
                append_ttd_comments(sl, eas, annotated, shown);
                continue;
            }

            // Covered if any instruction it came from ran. Where they differ,
            // a difference wins: ran only in this recording first, then only
            // in the other one (a fork's parent, or a fork), then in both.
            int rank = 0;
            for ( ea_t ea : eas )
            {
                bgcolor_t c = get_item_color(ea);
                if ( c == DEFCOLOR || ours.find(c) == ours.end() )
                    continue;
                // "Both" ranks with plain coverage: lowest.
                const int r = only_here.count(c) != 0 ? 3 : previous.count(c) != 0 ? 2 : 1;
                if ( r > rank )
                {
                    rank = r;
                    sl.bgcolor = c;
                }
                if ( rank == 3 )
                    break;
            }
            if ( sl.bgcolor != DEFCOLOR )
                brighten_dim_text(sl.line);
            else if ( was_ours )
                uncovered = true;

            append_ttd_comments(sl, eas, annotated, shown);
        }
        // A function printed and dropped again would leave its entry behind;
        // the map only needs the open views, so an overgrown one is reset.
        if ( g_painted_at.size() > 256 )
            g_painted_at.clear();
        g_painted_at[cf] = g_paint_generation;
        return uncovered;
    }

    static ssize_t idaapi hx_callback(void *, hexrays_event_t ev, va_list va)
    {
        switch ( ev )
        {
            case hxe_func_printed:
                // The text has just been generated; sv may be colored now.
                paint(va_arg(va, cfunc_t *));
                break;

            // Variable edits: the view's function changed.
            case lxe_lvar_name_changed:
            case lxe_lvar_type_changed:
            case lxe_lvar_cmt_changed:
            case lxe_lvar_mapping_changed:
            {
                vdui_t *vu = va_arg(va, vdui_t *);
                if ( g_edit_hook != nullptr && vu != nullptr && vu->cfunc != nullptr )
                    g_edit_hook(vu->cfunc->entry_ea);
                break;
            }
            case hxe_cmt_changed:
            {
                cfunc_t *cf = va_arg(va, cfunc_t *);
                if ( g_edit_hook != nullptr && cf != nullptr )
                    g_edit_hook(cf->entry_ea);
                break;
            }

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
        if ( g_hooked )
            hook_event_listener(HT_IDB, &g_paint_inputs, nullptr);
        msg("[ida-ttd] decompiler found: pseudocode %s follow the execution "
            "highlight.\n", g_hooked ? "will" : "could NOT be hooked to");
        return g_hooked;
    }

    void term_decompiler()
    {
        if ( g_hooked )
        {
            remove_hexrays_callback(hx_callback, nullptr);
            unhook_event_listener(HT_IDB, &g_paint_inputs);
            g_painted_at.clear();
            g_hooked = false;
        }
    }

    void pseudocode_paint_inputs_changed()
    {
        g_paint_generation++;
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
            // Nothing a paint reads has changed since this text was painted
            // (most stops: the highlight was already there).
            auto done = g_painted_at.find(vu->cfunc);
            if ( done != g_painted_at.end() && done->second == g_paint_generation )
                continue;

            // Repaint the text the view already shows, then redraw the widget.
            // A decompiler refresh only regenerates the text, so the highlight
            // did not appear until something else redrew the window; and only
            // colors and notes changed, so regenerating would be wasted work.
            // A line that lost its highlight (coverage cleared) keeps the
            // brightened text: regenerate the text then, which paints it
            // again from scratch (hxe_func_printed), no decompiling.
            if ( paint(vu->cfunc) )
                vu->refresh_ctext(false);
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

    // The statement the caret goes to for the instruction at 'ea'.
    //
    // The candidates are the items made from exactly that instruction.
    // Without any (most instructions: an item records one address, while a
    // statement is built from several), they are the statements Hex-Rays'
    // own map of instructions to statements gives (eamap), which is what it
    // follows the instruction pointer by. A function's first instruction maps
    // there to the body, so the caret starts on the first statement rather
    // than the declaration.
    //
    // A conditional move Hex-Rays wrote as a whole if is both the condition's
    // line and the body's: the body when the condition holds now, so a step
    // shows the branch actually taken, and the condition when it does not.
    // Otherwise the first statement among them: for code setting up a call's
    // argument, the call, not the argument's line.
    static const citem_t *caret_statement(cfunc_t *cf, ea_t ea)
    {
        std::vector<const citem_t *> cand;
        for ( const citem_t *it : cf->treeitems )
            if ( it != nullptr && it->ea == ea )
                cand.push_back(it);
        if ( cand.empty() )
        {
            eamap_t &em = cf->get_eamap();
            eamap_iterator_t p = eamap_find(&em, ea);
            if ( p != eamap_end(&em) )
                for ( const cinsn_t *s : eamap_second(p) )
                    if ( s != nullptr )
                        cand.push_back(s);
        }
        if ( cand.empty() )
            return nullptr;

        regval_t efl;
        bool holds = false;
        if ( get_reg_val("EFL", &efl) && conditional_move_at(ea, efl.ival, &holds) )
        {
            const cinsn_t *ifs  = nullptr;
            const citem_t *body = nullptr;
            for ( const citem_t *it : cand )
            {
                bool in_branch = false;
                const cinsn_t *f = cmov_if_of(cf, it, ea, &in_branch);
                if ( f == nullptr )
                    continue;
                ifs = f;
                if ( in_branch && body == nullptr )
                    body = it;
            }
            if ( ifs != nullptr )
            {
                const citem_t *s = holds && body != nullptr ? body : ifs;
                while ( s != nullptr && s->is_expr() )
                    s = cf->body.find_parent_of(s);
                return s;
            }
        }

        const citem_t *best = nullptr;
        for ( const citem_t *it : cand )
            if ( best == nullptr || (best->is_expr() && !it->is_expr()) )
                best = it;
        while ( best != nullptr && best->is_expr() )
            best = cf->body.find_parent_of(best);
        return best;
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

        const citem_t *best = caret_statement(vu->cfunc, ea);
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
