#include "analysis/coverage.h"
#include "analysis/fork_registry.h"
#include "analysis/query_runner.h"
#include "analysis/trace_store.h"
#include "core/backend_registry.h"
#include "debugger/trace_manager.h"
#include "plugin/settings.h"

#include <allins.hpp>

namespace idattd
{
    // Ceiling on the address space one sweep may cover. A backend keeps a bit
    // per byte of scope, so this caps that bitmap at 64 MiB.
    static const uint64_t kMaxCoverageBytes = 512ull << 20;

    // Which colors this database has been painted with. One netnode holds
    // the color last chosen (offered again by the form) and the set of every
    // color used, keyed by color (so clearing also removes paint in a color
    // the user has since changed away from).
    static const char  CV_NODE[]   = "$ ida-ttd coverage";
    static const uchar CV_LAST_TAG = 'L';   // alt 0 -> last color, biased by 1
    static const uchar CV_USED_TAG = 'C';   // alt <color> -> 1
    static const uchar CV_FUNC_TAG = 'F';   // alt <function start> -> 1
    static const uchar CV_PREV_TAG = 'P';   // alt <color> -> 1: shows another recording's coverage
    static const uchar CV_CMOV_TAG = 'M';   // alt <instruction> -> 1: a conditional move that never moved
    static const uchar CV_CMVF_TAG = 'K';   // alt <function start> -> 1: its conditional moves were checked
    // alt <color> -> base color + 1: the comparison's "ran only in this
    // recording" shade (red) of that base, and its "both ran it" shade
    // (purple). The "only the other one" shade (blue) is marked CV_PREV_TAG.
    // (CV_ONLY_TAG was written by one build for a "ran in both" gray; see
    // CV_VERSION.)
    static const uchar CV_ONLY_TAG = 'B';
    static const uchar CV_BOTH_TAG = 'S';
    // Which recording the current paint belongs to, and which one the
    // "previous" paint came from: sup 0 of each, the path. The other
    // recording's path is what lets a sweep tell which of its instructions
    // the two share through a fork's history.
    static const uchar CV_SELF_TAG  = 'R';
    static const uchar CV_OTHER_TAG = 'O';
    // alt 0 -> the scheme the paint follows. 4: plain coverage in the chosen
    // color; with another recording to compare, red for code only this one
    // ran, blue for code only the other one ran, and a lighter purple for
    // code both ran, all at the chosen color's lightness, decided from both
    // recordings' executions. 2 and 3: the chosen color for both, its hue
    // turned one way (green) for this one only and the other way (blue) for
    // the other only. Before: the chosen color for this recording, its
    // complement for the other, and (one build) a gray for both.
    static const uchar     CV_VERSION_TAG = 'V';
    static const nodeidx_t CV_VERSION     = 4;

    // Shade painted by builds before the color was configurable; always
    // cleared too, so those databases can still be cleaned.
    static const bgcolor_t CV_LEGACY_COLOR = 0xD5F2D5;

    // Which functions were swept, and what their conditional moves did,
    // belong to a recording: marks from an older execution must not suppress
    // a fresh sweep. Colors are a user preference and survive.
    static const uchar CV_TRACE_TAGS[] = { CV_FUNC_TAG, CV_CMOV_TAG, CV_CMVF_TAG };

    // A color from hue (degrees), saturation and lightness (0..1).
    static bgcolor_t from_hsl(double h, double sat, double l)
    {
        const double c = (1.0 - std::fabs(2.0 * l - 1.0)) * sat;
        const double hp = std::fmod(h, 360.0) / 60.0;
        const double x = c * (1.0 - std::fabs(std::fmod(hp, 2.0) - 1.0));
        double r = 0, g = 0, b = 0;
        if ( hp < 1 )      { r = c; g = x; }
        else if ( hp < 2 ) { r = x; g = c; }
        else if ( hp < 3 ) { g = c; b = x; }
        else if ( hp < 4 ) { g = x; b = c; }
        else if ( hp < 5 ) { r = x; b = c; }
        else               { r = c; b = x; }
        const double m = l - c / 2.0;
        auto ch = [&](double v) { return bgcolor_t(qmax(0.0, qmin(255.0, (v + m) * 255.0 + 0.5))); };
        return (ch(b) << 16) | (ch(g) << 8) | ch(r);     // bgcolor_t is 0xBBGGRR
    }

    // The three shades of a comparison, made at the chosen color's lightness
    // so they suit the theme the user chose it for: red for code only this
    // recording ran, blue for code only the other one ran, purple for code
    // both ran. Purple sits between the two, so "both" reads as the mix of
    // them, and is a little further from the background (lighter on a dark
    // theme, darker on a light one) so it does not look like a gap. The
    // saturation is enough to tell red from purple from blue at a glance, and
    // low enough that the default text colors stay readable on all three
    // (on IDA's dark theme, about 5:1 for its light gray text).
    struct Shades
    {
        bgcolor_t here, other, both;
    };
    static Shades comparison_shades(bgcolor_t base)
    {
        const int r = base & 0xFF, g = (base >> 8) & 0xFF, b = (base >> 16) & 0xFF;
        const double l = (qmax(r, qmax(g, b)) + qmin(r, qmin(g, b))) / 2.0 / 255.0;
        const bool dark = l < 0.5;
        const double sat = dark ? 0.22 : 0.4;
        const double lb = dark ? qmin(l + 0.05, 0.5) : qmax(l - 0.04, 0.5);
        return Shades{ from_hsl(0, sat, l), from_hsl(220, sat, l), from_hsl(280, sat, lb) };
    }

    // The base a comparison shade was made from, or DEFCOLOR when 'c' is not
    // one ("only the other one" shades are not recorded with their base).
    static bgcolor_t shade_base(netnode &nn, bgcolor_t c)
    {
        if ( nn == BADNODE )
            return DEFCOLOR;
        nodeidx_t v = nn.altval((nodeidx_t)c, CV_ONLY_TAG);
        if ( v == 0 )
            v = nn.altval((nodeidx_t)c, CV_BOTH_TAG);
        return v == 0 ? DEFCOLOR : (bgcolor_t)(v - 1);
    }

    // The old comparison shades (schemes 2 and 3): the hue turned a third of
    // the way round, by moving the channels along one place.
    static bgcolor_t legacy_turn_hue(bgcolor_t c, bool forward)
    {
        const bgcolor_t r = c & 0xFF, g = (c >> 8) & 0xFF, b = (c >> 16) & 0xFF;
        bgcolor_t out = forward ? (g << 16) | (r << 8) | b
                                : (r << 16) | (b << 8) | g;
        if ( out == c )
            out = c ^ (forward ? 0x002000 : 0x200000);
        return out;
    }

    static qstring sup_path(netnode &nn, uchar tag)
    {
        qstring s;
        if ( nn != BADNODE )
            nn.supstr(&s, 0, tag);
        return s;
    }

    // Another recording is being replayed (a fork, or its parent), so the
    // current paint is the other one's coverage. Repaint it in the "only the
    // other one" blue, so it still shows in functions this recording has not
    // swept yet; a sweep then paints what both ran purple and what only this
    // one ran red. A comparison shade goes the same way, by its base.
    static void repaint_as_previous(netnode &nn)
    {
        std::map<bgcolor_t, bgcolor_t> to;
        auto add = [&](bgcolor_t c)
        {
            if ( c == DEFCOLOR || nn.altval((nodeidx_t)c, CV_PREV_TAG) != 0 )
                return;
            bgcolor_t base = shade_base(nn, c);
            to[c] = comparison_shades(base != DEFCOLOR ? base : c).other;
        };
        add(CV_LEGACY_COLOR);
        for ( nodeidx_t i = nn.altfirst(CV_USED_TAG); i != BADNODE; i = nn.altnext(i, CV_USED_TAG) )
            add((bgcolor_t)i);
        for ( const auto &[from, prev] : to )
        {
            nn.altset((nodeidx_t)prev, 1, CV_USED_TAG);   // so clearing removes it
            nn.altset((nodeidx_t)prev, 1, CV_PREV_TAG);
        }

        size_t n = 0;
        show_wait_box("HIDECANCEL\nMarking the other recording's coverage...");
        for ( int i = 0; i < get_segm_qty(); i++ )
        {
            segment_info_t s;
            if ( !get_segment_info_by_num(&s, i) )
                continue;
            for ( ea_t ea = s.start_ea; ea != BADADDR && ea < s.end_ea; ea = next_head(ea, s.end_ea) )
            {
                auto p = to.find(get_item_color(ea));
                if ( p != to.end() )
                {
                    set_item_color(ea, p->second);
                    n++;
                }
            }
        }
        hide_wait_box();
        if ( n != 0 )
            msg("[ida-ttd] coverage: %llu instruction(s) painted by another recording are now in its "
                "shade; this recording's sweeps compare the two.\n", (uint64_t)n);
    }

    // The recording changed; the previous one's paint still needs repainting.
    static bool g_repaint_pending = false;
    // The paint follows an older scheme (CV_VERSION) and needs converting:
    // the scheme it follows, or 0 when it does not.
    static nodeidx_t g_upgrade_from = 0;
    static bool      g_upgrade_pending = false;

    // The opposite hue at the same lightness: each channel mirrored about the
    // midpoint of the brightest and darkest. Builds before CV_VERSION 2
    // painted the other recording's coverage in it.
    static bgcolor_t legacy_complement(bgcolor_t c)
    {
        int ch[3] = { int(c & 0xFF), int((c >> 8) & 0xFF), int((c >> 16) & 0xFF) };
        int sum = qmax(ch[0], qmax(ch[1], ch[2])) + qmin(ch[0], qmin(ch[1], ch[2]));
        bgcolor_t out = 0;
        for ( int i = 0; i < 3; i++ )
            out |= bgcolor_t(sum - ch[i]) << (8 * i);
        return out == c ? (c ^ 0x202000) : out;
    }

    // Convert paint from an older scheme to the current shades; each
    // function is also swept again (its marks were dropped), which decides
    // afresh what it ran. What can be converted without a sweep is what
    // marked the other recording's code, whose current shade is blue:
    //  - the old complement of a chosen color (before scheme 2), and the old
    //    blue (schemes 2 and 3);
    //  - before scheme 2, the one build that painted a gray for "both" kept
    //    it under CV_ONLY_TAG: that gray goes to blue too.
    // The old "only this one" green of schemes 2 and 3 goes to red. The
    // chosen color stays: it was this recording's, or both, which only a
    // sweep can tell apart.
    static void upgrade_paint(netnode &nn, nodeidx_t from_version)
    {
        std::map<bgcolor_t, bgcolor_t> to, here;
        for ( nodeidx_t i = nn.altfirst(CV_ONLY_TAG); i != BADNODE; i = nn.altnext(i, CV_ONLY_TAG) )
        {
            const bgcolor_t base = (bgcolor_t)(nn.altval(i, CV_ONLY_TAG) - 1);
            const Shades sh = comparison_shades(base);
            if ( (bgcolor_t)i == sh.here )
                continue;                               // already current
            if ( from_version < 2 )
                to[(bgcolor_t)i] = sh.other;
            else
                here[(bgcolor_t)i] = sh.here;
        }
        // The chosen colors: used, and neither another recording's shade
        // nor a comparison shade.
        std::set<bgcolor_t> bases;
        for ( nodeidx_t i = nn.altfirst(CV_USED_TAG); i != BADNODE; i = nn.altnext(i, CV_USED_TAG) )
            if ( nn.altval(i, CV_PREV_TAG) == 0 && shade_base(nn, (bgcolor_t)i) == DEFCOLOR )
                bases.insert((bgcolor_t)i);
        bases.insert(CV_LEGACY_COLOR);
        for ( bgcolor_t b : bases )
        {
            const bgcolor_t now = comparison_shades(b).other;
            for ( bgcolor_t old : { legacy_complement(b), legacy_turn_hue(b, false) } )
                if ( old != now && nn.altval((nodeidx_t)old, CV_PREV_TAG) != 0 && to.count(old) == 0 )
                    to[old] = now;
        }
        for ( const auto &[from, now] : here )
        {
            const nodeidx_t base = nn.altval((nodeidx_t)from, CV_ONLY_TAG);
            nn.altdel((nodeidx_t)from, CV_ONLY_TAG);
            nn.altset((nodeidx_t)now, 1, CV_USED_TAG);
            nn.altset((nodeidx_t)now, base, CV_ONLY_TAG);
            to[from] = now;
        }
        for ( const auto &[from, prev] : to )
        {
            if ( here.count(from) != 0 )
                continue;                               // retagged above
            nn.altdel((nodeidx_t)from, CV_ONLY_TAG);
            nn.altset((nodeidx_t)prev, 1, CV_USED_TAG);
            nn.altset((nodeidx_t)prev, 1, CV_PREV_TAG);
        }
        if ( to.empty() )
            return;
        show_wait_box("HIDECANCEL\nUpdating the coverage colors...");
        for ( int i = 0; i < get_segm_qty(); i++ )
        {
            segment_info_t s;
            if ( !get_segment_info_by_num(&s, i) )
                continue;
            for ( ea_t ea = s.start_ea; ea != BADADDR && ea < s.end_ea; ea = next_head(ea, s.end_ea) )
            {
                auto p = to.find(get_item_color(ea));
                if ( p != to.end() )
                    set_item_color(ea, p->second);
            }
        }
        hide_wait_box();
    }

    // The coverage node, with marks from another recording dropped. Every
    // access goes through here so the check cannot be skipped.
    static netnode cv_node(bool create)
    {
        netnode nn(CV_NODE, 0, create);
        if ( nn != BADNODE && !trace_store_matches(nn) )
        {
            trace_store_reset(nn, CV_TRACE_TAGS, qnumber(CV_TRACE_TAGS));
            // The recording that painted is now the other one. Kept even when
            // unknown (a database painted before this was recorded), so an
            // older path does not stand in for it.
            qstring self = sup_path(nn, CV_SELF_TAG);
            nn.supset(0, self.c_str(), self.length() + 1, CV_OTHER_TAG);
            nn.supdel(0, CV_SELF_TAG);
            msg("[ida-ttd] coverage: this database was last measured against a "
                "different recording, so its per-function marks were dropped and "
                "functions will be measured again.\n");
            // Not repainted here: this runs wherever coverage is first asked
            // about, including pseudocode printing and debugger notifications,
            // and repainting there crashed IDA (internal error 40183). The
            // plugin settles it after the stop
            // (coverage_settle_recording_change).
            g_repaint_pending = true;
        }
        else if ( nn != BADNODE && create )
        {
            trace_store_stamp(nn);
        }
        // Paint in an older scheme: its functions are swept again, and the
        // paint converted after the stop (upgrade_paint), for the same
        // reason the repaint above waits.
        if ( nn != BADNODE && nn.altval(0, CV_VERSION_TAG) < CV_VERSION )
        {
            for ( uchar tag : CV_TRACE_TAGS )
                for ( nodeidx_t i = nn.altfirst(tag); i != BADNODE; )
                {
                    nodeidx_t next = nn.altnext(i, tag);
                    nn.altdel(i, tag);
                    i = next;
                }
            if ( !g_upgrade_pending )
                g_upgrade_from = (nodeidx_t)nn.altval(0, CV_VERSION_TAG);
            nn.altset(0, CV_VERSION, CV_VERSION_TAG);
            g_upgrade_pending = true;
        }
        return nn;
    }

    bgcolor_t coverage_color()
    {
        netnode nn = cv_node(false);
        if ( nn != BADNODE )
        {
            nodeidx_t v = nn.altval(0, CV_LAST_TAG);
            if ( v != 0 )                   // 0 is "never set", hence the bias
                return (bgcolor_t)(v - 1);
        }
        return COVERAGE_DEFAULT_COLOR;
    }

    static void remember_color(bgcolor_t c)
    {
        if ( c == DEFCOLOR )
            return;                         // never record "no color"
        netnode nn = cv_node(true);
        if ( nn == BADNODE )
            return;
        nn.altset(0, (nodeidx_t)c + 1, CV_LAST_TAG);
        nn.altset((nodeidx_t)c, 1, CV_USED_TAG);
    }

    std::set<bgcolor_t> coverage_colors(std::set<bgcolor_t> *previous, std::set<bgcolor_t> *only_here,
                                        std::set<bgcolor_t> *both)
    {
        std::set<bgcolor_t> out;
        out.insert(CV_LEGACY_COLOR);
        if ( previous != nullptr )
            previous->clear();
        if ( only_here != nullptr )
            only_here->clear();
        if ( both != nullptr )
            both->clear();
        netnode nn = cv_node(false);
        if ( nn != BADNODE )
        {
            for ( nodeidx_t i = nn.altfirst(CV_USED_TAG);
                  i != BADNODE;
                  i = nn.altnext(i, CV_USED_TAG) )
            {
                if ( (bgcolor_t)i == DEFCOLOR )
                    continue;
                out.insert((bgcolor_t)i);
                if ( previous != nullptr && nn.altval(i, CV_PREV_TAG) != 0 )
                    previous->insert((bgcolor_t)i);
                if ( only_here != nullptr && nn.altval(i, CV_ONLY_TAG) != 0 )
                    only_here->insert((bgcolor_t)i);
                if ( both != nullptr && nn.altval(i, CV_BOTH_TAG) != 0 )
                    both->insert((bgcolor_t)i);
            }
            // The legacy color is in the set without a 'C' entry of its own.
            if ( previous != nullptr && nn.altval((nodeidx_t)CV_LEGACY_COLOR, CV_PREV_TAG) != 0 )
                previous->insert(CV_LEGACY_COLOR);
        }
        return out;
    }

    void coverage_settle_recording_change()
    {
        netnode nn = cv_node(false);        // notices a change not seen yet
        if ( nn == BADNODE )
            return;
        // The conversion first: it marks the old shades as the other
        // recording's, which the repaint then leaves alone.
        if ( g_upgrade_pending )
        {
            g_upgrade_pending = false;
            upgrade_paint(nn, g_upgrade_from);
        }
        if ( !g_repaint_pending )
            return;
        g_repaint_pending = false;
        repaint_as_previous(nn);
    }

    // The auto_coverage setting. The old per-database answer (alt 0, tag 'A',
    // of the coverage node) is no longer read.
    bool coverage_auto_enabled()
    {
        return settings().auto_coverage;
    }

    // Functions swept this session in debugger segments. Those segments (a
    // Microsoft recording's system DLLs) and their colors vanish when the
    // session ends, so a saved mark would block repainting in later sessions.
    static std::set<ea_t> g_session_done;
    // The same for the conditional-move check: the functions checked, and
    // the moves found never to have moved.
    static std::set<ea_t> g_session_cmov_done;
    static std::set<ea_t> g_session_cmov_untaken;

    static bool in_debug_segment(ea_t ea)
    {
        segment_info_t s;
        return get_segment_info(&s, ea) && s.is_debugger_segm();
    }

    // Recordings opened beside the session to read a fork's history, by path
    // (lower case); null for one that would not open, so it is not retried
    // on every sweep. Kept for the session: opening one costs more than a
    // sweep does.
    static std::map<qstring, std::unique_ptr<ITraceBackend>> g_lineage_backends;

    void coverage_session_ended()
    {
        g_lineage_backends.clear();
        g_session_done.clear();
        g_session_cmov_done.clear();
        g_session_cmov_untaken.clear();
    }

    bool coverage_function_done(ea_t start)
    {
        if ( in_debug_segment(start) )
            return g_session_done.count(start) != 0;
        netnode nn = cv_node(false);
        return nn != BADNODE && nn.altval((nodeidx_t)start, CV_FUNC_TAG) != 0;
    }

    static void mark_function_done(ea_t start)
    {
        if ( in_debug_segment(start) )
        {
            g_session_done.insert(start);
            return;
        }
        netnode nn = cv_node(true);
        if ( nn != BADNODE )
            nn.altset((nodeidx_t)start, 1, CV_FUNC_TAG);
    }

    bool cover_function(TraceManager *mgr, ea_t start, ea_t end)
    {
        if ( start == BADADDR || start >= end )
            return false;
        std::vector<std::pair<ea_t, ea_t>> one{ { start, end } };
        CoverageResult r;
        if ( !run_coverage(mgr, one, coverage_color(), &r) )
        {
            // Automatic: said in the output window, not in a dialog.
            msg("[ida-ttd] coverage of the function at 0x%llX: %s\n", (uint64_t)start, r.error.c_str());
            return false;
        }
        if ( r.cancelled )
            return false;
        // Recorded even when nothing ran: "none" is a result, and re-measuring
        // on every stop would not change it.
        mark_function_done(start);
        return true;
    }

    // Sort and merge [lo,hi) spans, dropping empty ones. Overlapping
    // watchpoints would report an instruction twice.
    static std::vector<std::pair<ea_t, ea_t>> normalize(
            const std::vector<std::pair<ea_t, ea_t>> &in)
    {
        std::vector<std::pair<ea_t, ea_t>> v;
        for ( const auto &r : in )
            if ( r.first < r.second )
                v.push_back(r);
        std::sort(v.begin(), v.end());

        std::vector<std::pair<ea_t, ea_t>> out;
        for ( const auto &r : v )
        {
            if ( !out.empty() && r.first <= out.back().second )
                out.back().second = qmax(out.back().second, r.second);
            else
                out.push_back(r);
        }
        return out;
    }

    //-----------------------------------------------------------------------
    // A recording's lineage
    //-----------------------------------------------------------------------
    // A fork's own file starts at its fork position; what ran before that is
    // in its parent's file, up to that position, and so on up the tree. A
    // recording ran its own file and each such piece of its ancestors'. Two
    // recordings share the pieces of the same file, up to the earlier of
    // their two limits: a fork and its parent share the parent's file up to
    // the fork position; two forks of one parent, the parent's up to the
    // earlier of theirs.
    struct LineagePiece
    {
        qstring path;
        qstring limit;          // the position it ends at, as recorded; empty: the whole file
    };

    static std::vector<LineagePiece> lineage_of(const qstring &path, const std::vector<ForkRecord> &forks)
    {
        std::vector<LineagePiece> out;
        qstring cur = path, limit;
        // Bounded, and stopped at a file seen already: the records are edited
        // by hand through the Fork manager and could loop.
        while ( !cur.empty() && out.size() < 64 )
        {
            for ( const LineagePiece &p : out )
                if ( same_trace_path(p.path, cur) )
                    return out;
            out.push_back({ cur, limit });
            auto it = std::find_if(forks.begin(), forks.end(),
                                   [&](const ForkRecord &f) { return same_trace_path(f.path, cur); });
            if ( it == forks.end() )
                break;
            limit = it->at;
            cur   = it->parent;
        }
        return out;
    }

    // The backend to read 'path' through: the session's own for its
    // recording, else one opened beside it (kept for the session). Main
    // thread. Null, said once in the output window, when it cannot be opened.
    static ITraceBackend *lineage_backend(TraceManager *mgr, const qstring &path)
    {
        if ( same_trace_path(path, mgr->trace_path()) )
            return mgr->backend();
        qstring key = path;
        key.replace("/", "\\");
        qstrlwr(key.begin());
        auto it = g_lineage_backends.find(key);
        if ( it != g_lineage_backends.end() )
            return it->second.get();

        std::unique_ptr<ITraceBackend> b;
        qstring why;
        ITraceBackend *kind = qfileexist(path.c_str()) ? BackendRegistry::instance().for_file(path.c_str()) : nullptr;
        if ( !qfileexist(path.c_str()) )
            why = "the file is not there";
        else if ( kind == nullptr )
            why = "no loaded backend reads it";
        else if ( (b = kind->new_instance()) == nullptr )
            why.sprnt("the %s backend cannot open a second recording", kind->id());
        else
        {
            // Opening reads the recording's index, which takes a moment on a
            // long one: without the box it would look like a hang.
            show_wait_box_now("HIDECANCEL\nOpening the parent recording for coverage...");
            bool ok = b->open(path.c_str(), &why);
            hide_wait_box();
            if ( !ok )
                b.reset();
        }
        if ( b == nullptr )
            msg("[ida-ttd] coverage: cannot read %s (%s), so what this fork ran before its fork "
                "position, or shares with the other recording there, is not counted.\n",
                path.c_str(), why.c_str());
        ITraceBackend *raw = b.get();
        g_lineage_backends[key] = std::move(b);
        return raw;
    }

    // One piece of a recording's lineage, ready to read: its file's backend
    // and the positions before 'limit' (or all of it).
    struct SweepPiece
    {
        ITraceBackend *backend = nullptr;
        bool           whole   = true;         // no limit: query_executed
        Position       limit;
    };

    // The pieces to read for the recording at 'path', from the fork records.
    // Main thread: it may open files. Empty when not even its own file can
    // be read; shorter when an ancestor's cannot (what lies beyond is then
    // not counted, and the output window says why).
    static std::vector<SweepPiece> plan_lineage(TraceManager *mgr, const qstring &path,
                                                const std::vector<ForkRecord> &forks)
    {
        std::vector<LineagePiece> pieces = lineage_of(path, forks);
        if ( pieces.empty() )
            pieces.push_back({ path, qstring() });
        std::vector<SweepPiece> out;
        for ( const LineagePiece &lp : pieces )
        {
            SweepPiece sp;
            sp.backend = lineage_backend(mgr, lp.path);
            if ( sp.backend == nullptr )
                break;                          // nor anything further up
            sp.whole = lp.limit.empty();
            if ( !sp.whole && !sp.backend->parse_position(lp.limit.c_str(), &sp.limit) )
            {
                msg("[ida-ttd] coverage: the fork position %s in %s does not read as a position, so "
                    "what ran there before it is not counted.\n", lp.limit.c_str(), lp.path.c_str());
                break;
            }
            out.push_back(sp);
        }
        return out;
    }

    // Every address in 'spans' executed before 'limit', a stretch of
    // positions at a time so a hot loop never holds all its executions at
    // once. Appended in no particular order. Worker thread.
    static QueryResult executions_before(ITraceBackend *b, const std::vector<std::pair<ea_t, ea_t>> &spans,
                                         Position limit, std::vector<ea_t> *out, ProgressSink *p)
    {
        static const int64_t kSlice = 1 << 20;
        QueryResult res;
        res.ran = true;
        const Position first = b->info().first;
        std::set<ea_t> seen;
        for ( size_t s = 0; s < spans.size(); s++ )
        {
            Position at = first;
            while ( at < limit )
            {
                if ( p != nullptr && p->cancelled() )
                {
                    res.cancelled = true;
                    return res;
                }
                Position next = b->position_add(at, kSlice);
                // A backend that cannot step positions answers in one go.
                if ( next <= at || next > limit )
                    next = limit;
                std::vector<Access> v;
                QueryResult q = b->query_accesses(spans[s].first, spans[s].second, ACCESS_EXEC,
                                                  PositionRange{ at, next }, &v, p);
                if ( !q.ran || q.cancelled )
                    return q;
                for ( const Access &a : v )
                    if ( a.kind == ACCESS_EXEC && a.pos < limit && a.pc >= spans[s].first && a.pc < spans[s].second )
                        seen.insert(a.pc);
                at = next;
            }
        }
        out->insert(out->end(), seen.begin(), seen.end());
        return res;
    }

    // What a recording ran in 'spans', through its lineage: sorted, each
    // address once. Worker thread. Not run when even its own file could not
    // be read; a failed ancestor is skipped and counted in 'unread'.
    static QueryResult executed_by(const std::vector<SweepPiece> &plan,
                                   const std::vector<std::pair<ea_t, ea_t>> &spans,
                                   std::vector<ea_t> *out, size_t *unread, ProgressSink *p)
    {
        QueryResult r;
        r.ran = true;
        const uint32_t n = (uint32_t)plan.size();
        for ( uint32_t i = 0; i < n; i++ )
        {
            const SweepPiece &sp = plan[i];
            StageSink stage(p, i * 100 / n, (i + 1) * 100 / n);
            QueryResult q = sp.whole ? sp.backend->query_executed(spans, out, &stage)
                                     : executions_before(sp.backend, spans, sp.limit, out, &stage);
            if ( q.cancelled )
            {
                r.cancelled = true;
                return r;
            }
            if ( !q.ran )
            {
                if ( i == 0 )
                    return q;                   // its own file is the sweep
                ++*unread;
            }
        }
        std::sort(out->begin(), out->end());
        out->erase(std::unique(out->begin(), out->end()), out->end());
        return r;
    }

    bool run_coverage(TraceManager *mgr,
                      const std::vector<std::pair<ea_t, ea_t>> &ranges,
                      bgcolor_t color,
                      CoverageResult *out)
    {
        CoverageResult res;
        // Why it did not run goes in out->error, for the caller to show: a
        // dialog raised here would hang a script (ttd("an.coverage")).
        auto refuse = [&](const qstring &why)
        {
            if ( out != nullptr )
                out->error = why;
            return false;
        };
        if ( out != nullptr )
            *out = res;
        if ( mgr == nullptr || !mgr->is_active() || mgr->backend() == nullptr )
            return refuse("Execution coverage is only available while replaying a trace.");

        // Repaint another recording's coverage first, or this sweep's paint
        // would be repainted with it.
        coverage_settle_recording_change();

        std::vector<std::pair<ea_t, ea_t>> spans = normalize(ranges);
        if ( spans.empty() )
            return refuse("Nothing to measure: the chosen scope covers no addresses.");

        uint64_t total = 0;
        for ( const auto &r : spans )
            total += (uint64_t)(r.second - r.first);
        if ( total > kMaxCoverageBytes )
        {
            qstring why;
            why.sprnt("That scope spans %llu MiB of address space, more than the "
                      "%llu MiB this command will map at once.\n\n"
                      "Measure a single module or function instead.",
                      total >> 20, kMaxCoverageBytes >> 20);
            return refuse(why);
        }

        ITraceBackend *backend = mgr->backend();
        // The other recording: the one replayed before this one.
        qstring other;
        {
            netnode nn = cv_node(false);
            other = sup_path(nn, CV_OTHER_TAG);
        }
        std::vector<ForkRecord> forks = load_fork_records(nullptr);
        // Painted before the database kept who painted: for a fork, the
        // other recording is most likely the one it was forked from.
        if ( other.empty() )
        {
            for ( const ForkRecord &f : forks )
                if ( same_trace_path(f.path, mgr->trace_path()) )
                    other = f.parent;
        }
        if ( same_trace_path(other, mgr->trace_path()) )
            other.clear();

        // Which files to read, and how far: opened here, on the main thread,
        // before the worker reads them. Both recordings are read, each with
        // its fork history, so what they share is known from what they ran,
        // not guessed from paint (which covers only what the other one's
        // session happened to sweep, and may be older).
        std::vector<SweepPiece> mine = plan_lineage(mgr, mgr->trace_path(), forks);
        if ( mine.empty() || mine[0].backend != backend )
            mine.insert(mine.begin(), SweepPiece{ backend, true, Position() });
        std::vector<SweepPiece> theirs;
        if ( !other.empty() )
            theirs = plan_lineage(mgr, other, forks);

        std::vector<ea_t> executed, executed_other;
        size_t unread = 0;
        bool   other_read = false;
        QueryResult qr = run_query("Measuring execution coverage", [&](ProgressSink *p)
        {
            const uint32_t split = theirs.empty() ? 100 : 60;
            StageSink here(p, 0, split);
            QueryResult r = executed_by(mine, spans, &executed, &unread, &here);
            if ( !r.ran || r.cancelled || theirs.empty() )
                return r;
            StageSink there(p, split, 100);
            QueryResult q = executed_by(theirs, spans, &executed_other, &unread, &there);
            if ( q.cancelled )
                return q;
            other_read = q.ran;
            if ( !q.ran )
                unread++;
            return r;
        });
        if ( !qr.ran )
            return refuse(query_error(mgr, backend, qr, "The replay session ended during the coverage sweep.",
                                      "This recording's backend could not measure execution coverage."));
        res.cancelled = qr.cancelled;
        if ( unread != 0 )
            msg("[ida-ttd] coverage: %llu part(s) of the other recording or a fork history could not be "
                "read, so what ran there is not counted in the comparison.\n", (uint64_t)unread);

        // A cancelled sweep is partial, and partial paint would look complete.
        if ( res.cancelled )
        {
            if ( out != nullptr )
                *out = res;
            return true;
        }

        // Only instruction heads are colored. Elsewhere there is no line to
        // color, and creating code there would claim more than "this ran".
        show_wait_box("HIDECANCEL\nColoring executed instructions...");
        remember_color(color);
        // With another recording to compare against, three shades
        // (comparison_shades): red for what only this recording ran, blue for
        // what only the other one ran, purple for what both ran. With none,
        // every instruction this one ran is in 'color', as plain coverage.
        // When the other recording could not be read, its paint (from its own
        // session) is the best there is: what it painted and this one ran
        // counts as both.
        const bool comparing = !other.empty();
        const Shades sh = comparison_shades(color);
        const bgcolor_t only_here  = sh.here;
        const bgcolor_t only_other = sh.other;
        const bgcolor_t in_both_c  = comparing ? sh.both : color;
        std::set<bgcolor_t> previous;
        coverage_colors(&previous);
        {
            netnode nn = cv_node(true);
            if ( nn != BADNODE )
            {
                if ( comparing )
                {
                    nn.altset((nodeidx_t)only_here, 1, CV_USED_TAG);
                    nn.altset((nodeidx_t)only_here, (nodeidx_t)color + 1, CV_ONLY_TAG);
                    nn.altset((nodeidx_t)only_other, 1, CV_USED_TAG);
                    nn.altset((nodeidx_t)only_other, 1, CV_PREV_TAG);
                    nn.altset((nodeidx_t)sh.both, 1, CV_USED_TAG);
                    nn.altset((nodeidx_t)sh.both, (nodeidx_t)color + 1, CV_BOTH_TAG);
                }
                const qstring &self = mgr->trace_path();
                nn.supset(0, self.c_str(), self.length() + 1, CV_SELF_TAG);
            }
        }
        auto paint = [&](ea_t ea, bgcolor_t c)
        {
            if ( !is_code(get_flags(ea)) || get_item_head(ea) != ea )
                return false;
            set_item_color(ea, c);
            return true;
        };
        // Both lists are sorted: one merge walk. What only the other one ran
        // is painted too, so the comparison is whole within the scope even
        // where the other one's session never swept it.
        size_t j = 0;
        for ( ea_t ea : executed )
        {
            res.executed++;
            while ( other_read && j < executed_other.size() && executed_other[j] < ea )
                paint(executed_other[j++], only_other);
            bool in_both;
            if ( !comparing )
                in_both = true;
            else if ( other_read )
                in_both = j < executed_other.size() && executed_other[j] == ea;
            else
            {
                bgcolor_t was = get_item_color(ea);
                in_both = was != DEFCOLOR && previous.count(was) != 0;
            }
            if ( other_read && in_both )
                j++;
            if ( paint(ea, in_both ? in_both_c : only_here) )
            {
                res.colored++;
                if ( in_both && comparing )
                    res.both++;
            }
            else
            {
                res.undefined++;
            }
        }
        while ( other_read && j < executed_other.size() )
            paint(executed_other[j++], only_other);
        hide_wait_box();

        if ( out != nullptr )
            *out = res;
        return true;
    }

    size_t clear_coverage()
    {
        // Every color ever used, so paint in an old shade is not stranded.
        std::set<bgcolor_t> ours = coverage_colors();

        // Also forget which functions were measured, so the automatic pass
        // paints them again, and what their conditional moves did.
        g_session_done.clear();
        g_session_cmov_done.clear();
        g_session_cmov_untaken.clear();
        netnode nn = cv_node(true);
        if ( nn != BADNODE )
        {
            for ( uchar tag : { CV_FUNC_TAG, CV_PREV_TAG, CV_CMOV_TAG, CV_CMVF_TAG } )
                for ( nodeidx_t i = nn.altfirst(tag); i != BADNODE; )
                {
                    nodeidx_t next = nn.altnext(i, tag);
                    nn.altdel(i, tag);
                    i = next;
                }
        }

        size_t n = 0;
        show_wait_box("HIDECANCEL\nClearing execution coverage...");
        for ( int i = 0; i < get_segm_qty(); i++ )
        {
            segment_info_t s;
            if ( !get_segment_info_by_num(&s, i) )
                continue;
            for ( ea_t ea = s.start_ea; ea != BADADDR && ea < s.end_ea;
                  ea = next_head(ea, s.end_ea) )
            {
                if ( ours.find(get_item_color(ea)) != ours.end() )
                {
                    del_item_color(ea);
                    n++;
                }
            }
        }
        hide_wait_box();
        return n;
    }

    //-----------------------------------------------------------------------
    // Conditional moves
    //-----------------------------------------------------------------------
    // How many executions a move may have and still be tested, and how many
    // positions go to the backend at once. One that ran more often than that
    // is not tested and counts as having moved, which keeps its body painted,
    // as it was before this check: reading the flags at every run of a move
    // in a hot loop would cost more than the answer is worth.
    static const size_t kCmovMaxTested = 4096;
    static const size_t kCmovBatch     = 256;

    // The instruction's condition code as its itype, or 0 when 'ea' holds no
    // conditional move. Only x86 has them in this sense.
    static uint16 cmov_itype(ea_t ea)
    {
        if ( PH.id != PLFM_386 )
            return 0;
        insn_t insn;
        if ( decode_insn(&insn, ea) <= 0 )
            return 0;
        return insn.itype >= NN_cmova && insn.itype <= NN_cmovz ? insn.itype : 0;
    }

    // Whether a conditional move of this itype moves under 'rflags'. Pure, so
    // the worker thread can call it.
    static bool cmov_holds(uint16 itype, uint64_t rflags)
    {
        const bool cf = (rflags & 0x001) != 0;
        const bool pf = (rflags & 0x004) != 0;
        const bool zf = (rflags & 0x040) != 0;
        const bool sf = (rflags & 0x080) != 0;
        const bool of = (rflags & 0x800) != 0;
        switch ( itype )
        {
            case NN_cmova:  return !cf && !zf;
            case NN_cmovb:  return cf;
            case NN_cmovbe: return cf || zf;
            case NN_cmovg:  return !zf && sf == of;
            case NN_cmovge: return sf == of;
            case NN_cmovl:  return sf != of;
            case NN_cmovle: return zf || sf != of;
            case NN_cmovnb: return !cf;
            case NN_cmovno: return !of;
            case NN_cmovnp: return !pf;
            case NN_cmovns: return !sf;
            case NN_cmovnz: return !zf;
            case NN_cmovo:  return of;
            case NN_cmovp:  return pf;
            case NN_cmovs:  return sf;
            case NN_cmovz:  return zf;
            default:        return true;
        }
    }

    bool conditional_move_at(ea_t ea, uint64_t rflags, bool *holds)
    {
        uint16 itype = cmov_itype(ea);
        if ( itype == 0 )
            return false;
        if ( holds != nullptr )
            *holds = cmov_holds(itype, rflags);
        return true;
    }

    std::set<ea_t> untaken_conditional_moves(ea_t start, ea_t end)
    {
        std::set<ea_t> out;
        for ( auto p = g_session_cmov_untaken.lower_bound(start);
              p != g_session_cmov_untaken.end() && *p < end; ++p )
            out.insert(*p);
        netnode nn = cv_node(false);
        if ( nn == BADNODE )
            return out;
        // altnext() steps to the next index that exists, so this walks only
        // the marks inside the range, not every address in it.
        nodeidx_t i = start == 0 ? nn.altfirst(CV_CMOV_TAG) : nn.altnext((nodeidx_t)start - 1, CV_CMOV_TAG);
        for ( ; i != BADNODE && (ea_t)i < end; i = nn.altnext(i, CV_CMOV_TAG) )
            out.insert((ea_t)i);
        return out;
    }

    bool condmoves_function_done(ea_t start)
    {
        if ( in_debug_segment(start) )
            return g_session_cmov_done.count(start) != 0;
        netnode nn = cv_node(false);
        return nn != BADNODE && nn.altval((nodeidx_t)start, CV_CMVF_TAG) != 0;
    }

    bool check_conditional_moves(TraceManager *mgr, ea_t start, ea_t end)
    {
        if ( start == BADADDR || start >= end || mgr == nullptr || !mgr->is_active()
          || mgr->backend() == nullptr )
            return false;

        // The moves that ran: those coverage painted in this recording's
        // shade. Another recording's shade says nothing about this one.
        std::set<bgcolor_t> previous;
        std::set<bgcolor_t> ours = coverage_colors(&previous);
        struct Move
        {
            ea_t   ea;
            uint16 itype;
            bool   untaken = false;     // ran, and never moved
        };
        std::vector<Move> moves;
        for ( ea_t ea = start; ea != BADADDR && ea < end; ea = next_head(ea, end) )
        {
            bgcolor_t c = get_item_color(ea);
            if ( c == DEFCOLOR || ours.count(c) == 0 || previous.count(c) != 0 )
                continue;
            if ( uint16 it = cmov_itype(ea); it != 0 )
                moves.push_back({ ea, it });
        }

        if ( !moves.empty() )
        {
            ITraceBackend *backend = mgr->backend();
            QueryResult qr = run_query("Checking conditional moves", [&](ProgressSink *p)
            {
                QueryResult r;
                r.ran = true;
                for ( size_t i = 0; i < moves.size(); i++ )
                {
                    if ( p != nullptr )
                    {
                        if ( p->cancelled() )
                        {
                            r.cancelled = true;
                            break;
                        }
                        p->report(uint32_t(i * 100 / moves.size()));
                    }
                    Move &m = moves[i];
                    std::vector<Access> runs;
                    QueryResult q = backend->query_accesses(m.ea, m.ea + 1, ACCESS_EXEC, PositionRange{},
                                                            &runs, nullptr);
                    if ( !q.ran || q.truncated )
                        continue;                   // unknown: counts as moved
                    std::vector<Position> at;
                    for ( const Access &a : runs )
                        if ( a.kind == ACCESS_EXEC && a.pc == m.ea )
                            at.push_back(a.pos);
                    if ( at.empty() || at.size() > kCmovMaxTested )
                        continue;

                    // Untaken only when every execution was read and none
                    // moved. The registers at an execution's position are
                    // those before it runs, which is what decides the move;
                    // the instruction pointer confirms the position.
                    bool moved = false, all_read = true;
                    for ( size_t k = 0; k < at.size() && !moved && all_read; k += kCmovBatch )
                    {
                        if ( p != nullptr && p->cancelled() )
                        {
                            r.cancelled = true;
                            return r;
                        }
                        std::vector<Position> chunk(at.begin() + k,
                                                    at.begin() + std::min(k + kCmovBatch, at.size()));
                        std::vector<ittd_regs> regs;
                        QueryResult rq = backend->registers_at(chunk, &regs, nullptr);
                        if ( !rq.ran || rq.cancelled || regs.size() != chunk.size() )
                        {
                            all_read = false;
                            break;
                        }
                        for ( const ittd_regs &g : regs )
                        {
                            if ( (g.have & ITTD_REGS_GP) == 0 || g.gp[ITTD_REG_RIP] != m.ea )
                            {
                                all_read = false;
                                break;
                            }
                            if ( cmov_holds(m.itype, g.rflags) )
                            {
                                moved = true;
                                break;
                            }
                        }
                    }
                    m.untaken = all_read && !moved;
                }
                return r;
            });
            // A partial check would leave some moves unmarked for good.
            if ( !qr.ran || qr.cancelled )
            {
                if ( !qr.ran )
                    msg("[ida-ttd] conditional moves of the function at 0x%llX: %s\n", (uint64_t)start,
                        query_error(mgr, backend, qr, "The replay session ended during the check.",
                                    "This recording's backend could not list the moves' executions.").c_str());
                return false;
            }
        }

        // Each move set or cleared, so a check run again after the function's
        // bounds or code changed leaves no stale mark behind.
        if ( in_debug_segment(start) )
        {
            for ( const Move &m : moves )
                if ( m.untaken )
                    g_session_cmov_untaken.insert(m.ea);
                else
                    g_session_cmov_untaken.erase(m.ea);
            g_session_cmov_done.insert(start);
            return true;
        }
        netnode nn = cv_node(true);
        if ( nn == BADNODE )
            return false;
        for ( const Move &m : moves )
            if ( m.untaken )
                nn.altset((nodeidx_t)m.ea, 1, CV_CMOV_TAG);
            else
                nn.altdel((nodeidx_t)m.ea, CV_CMOV_TAG);
        nn.altset((nodeidx_t)start, 1, CV_CMVF_TAG);
        return true;
    }
}
