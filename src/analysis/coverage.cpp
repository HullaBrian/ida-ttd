#include "analysis/coverage.h"
#include "analysis/query_runner.h"
#include "analysis/trace_store.h"
#include "debugger/trace_manager.h"

namespace idattd
{
    // Ceiling on how much address space one sweep may cover. A backend keeps
    // a bit per byte of scope while it sweeps, so the cap is really "do not
    // quietly allocate 64 MiB".
    static const uint64_t kMaxCoverageBytes = 512ull << 20;

    // Which colours has this database been painted with?
    //
    // Two things are stored, under separate tags on one netnode: the colour last
    // chosen (so the form can offer it again), and the set of every colour used
    // (so clearing removes highlighting applied with a colour the user has since
    // changed away from). The set is keyed by the colour itself, which is what
    // makes it a set rather than a list that could grow duplicates.
    static const char  CV_NODE[]   = "$ ida-ttd coverage";
    static const uchar CV_LAST_TAG = 'L';   // alt 0 -> last colour, biased by 1
    static const uchar CV_USED_TAG = 'C';   // alt <colour> -> 1
    static const uchar CV_AUTO_TAG = 'A';   // alt 0 -> 1 off, 2 on (0 = never set)
    static const uchar CV_FUNC_TAG = 'F';   // alt <function start> -> 1
    static const uchar CV_PREV_TAG = 'P';   // alt <colour> -> 1: shows another recording's coverage

    // Shade painted by builds that predate the configurable colour. Always
    // cleared as well, so those databases can still be cleaned up.
    static const bgcolor_t CV_LEGACY_COLOR = 0xD5F2D5;

    // Which functions have been swept is the one thing here that belongs to a
    // recording rather than to the database: re-record the program and the
    // answer changes, so the marks from the old execution must not suppress a
    // fresh sweep. The colours are a user preference and survive.
    static const uchar CV_TRACE_TAGS[] = { CV_FUNC_TAG };

    // The same shade turned to the opposite hue: each channel mirrored about
    // the middle of the brightest and darkest, so the lightness stays and the
    // colour reads as well on the theme the user picked the first one for.
    static bgcolor_t complement(bgcolor_t c)
    {
        int ch[3] = { int(c & 0xFF), int((c >> 8) & 0xFF), int((c >> 16) & 0xFF) };
        int sum = qmax(ch[0], qmax(ch[1], ch[2])) + qmin(ch[0], qmin(ch[1], ch[2]));
        bgcolor_t out = 0;
        for ( int i = 0; i < 3; i++ )
            out |= bgcolor_t(sum - ch[i]) << (8 * i);
        // A grey has no opposite hue; shift it so it still differs.
        return out == c ? (c ^ 0x202000) : out;
    }

    // Another recording is being replayed (a fork, or the recording a fork
    // came from): what is painted now is the other one's coverage. Repaint
    // it in the complementary shade, so this recording's sweeps, painted in
    // the usual one, show where its path differs.
    static void repaint_as_previous(netnode &nn)
    {
        std::map<bgcolor_t, bgcolor_t> to;
        auto add = [&](bgcolor_t c)
        {
            if ( c != DEFCOLOR && nn.altval((nodeidx_t)c, CV_PREV_TAG) == 0 )
                to[c] = complement(c);
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
            msg("[ida-ttd] coverage: %llu instruction(s) painted by another recording are now in the "
                "complementary shade; this recording's are painted in the usual one.\n", (uint64_t)n);
    }

    // The coverage node, with any marks left over from another recording
    // dropped. Every access goes through here so the check cannot be skipped.
    static netnode cv_node(bool create)
    {
        netnode nn(CV_NODE, 0, create);
        if ( nn != BADNODE && !trace_store_matches(nn) )
        {
            trace_store_reset(nn, CV_TRACE_TAGS, qnumber(CV_TRACE_TAGS));
            msg("[ida-ttd] coverage: this database was last measured against a "
                "different recording, so its per-function marks were dropped and "
                "functions will be measured again.\n");
            repaint_as_previous(nn);
        }
        else if ( nn != BADNODE && create )
        {
            trace_store_stamp(nn);
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
            return;                         // never record "no colour"
        netnode nn = cv_node(true);
        if ( nn == BADNODE )
            return;
        nn.altset(0, (nodeidx_t)c + 1, CV_LAST_TAG);
        nn.altset((nodeidx_t)c, 1, CV_USED_TAG);
    }

    std::set<bgcolor_t> coverage_colors()
    {
        std::set<bgcolor_t> out;
        out.insert(CV_LEGACY_COLOR);
        netnode nn = cv_node(false);
        if ( nn != BADNODE )
        {
            for ( nodeidx_t i = nn.altfirst(CV_USED_TAG);
                  i != BADNODE;
                  i = nn.altnext(i, CV_USED_TAG) )
            {
                if ( (bgcolor_t)i != DEFCOLOR )
                    out.insert((bgcolor_t)i);
            }
        }
        return out;
    }

    bool coverage_is_previous(bgcolor_t c)
    {
        netnode nn = cv_node(false);
        return nn != BADNODE && c != DEFCOLOR && nn.altval((nodeidx_t)c, CV_PREV_TAG) != 0;
    }

    bool coverage_auto_enabled()
    {
        netnode nn = cv_node(false);
        if ( nn == BADNODE )
            return true;                    // never asked: on by default
        nodeidx_t v = nn.altval(0, CV_AUTO_TAG);
        return v != 1;                      // 0 = never set, 1 = off, 2 = on
    }

    void set_coverage_auto_enabled(bool on)
    {
        netnode nn = cv_node(true);
        if ( nn != BADNODE )
            nn.altset(0, on ? 2 : 1, CV_AUTO_TAG);
    }

    bool coverage_function_done(ea_t start)
    {
        netnode nn = cv_node(false);
        return nn != BADNODE && nn.altval((nodeidx_t)start, CV_FUNC_TAG) != 0;
    }

    static void mark_function_done(ea_t start)
    {
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
        if ( !run_coverage(mgr, one, coverage_color(), &r) || r.cancelled )
            return false;
        // Record it even when nothing in the function ran: "measured, answer was
        // none" is a result, and re-measuring it on every stop would not change it.
        mark_function_done(start);
        return true;
    }

    // Sort and merge [lo,hi) spans, dropping empty ones. Overlapping watchpoints
    // would double-report the same instruction and overlapping bins would make
    // the lookup below ambiguous, so this is not just tidiness.
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

    bool run_coverage(TraceManager *mgr,
                      const std::vector<std::pair<ea_t, ea_t>> &ranges,
                      bgcolor_t color,
                      CoverageResult *out)
    {
        CoverageResult res;
        if ( out != nullptr )
            *out = res;
        if ( mgr == nullptr || !mgr->is_active() || mgr->backend() == nullptr )
        {
            warning("Execution coverage is only available while replaying a trace.");
            return false;
        }

        std::vector<std::pair<ea_t, ea_t>> spans = normalize(ranges);
        if ( spans.empty() )
        {
            warning("Nothing to measure: the chosen scope covers no addresses.");
            return false;
        }

        uint64_t total = 0;
        for ( const auto &r : spans )
            total += (uint64_t)(r.second - r.first);
        if ( total > kMaxCoverageBytes )
        {
            warning("That scope spans %llu MiB of address space, more than the "
                    "%llu MiB this command will map at once.\n\n"
                    "Measure a single module or function instead.",
                    total >> 20, kMaxCoverageBytes >> 20);
            return false;
        }

        ITraceBackend *backend = mgr->backend();
        std::vector<ea_t> executed;
        QueryResult qr = run_query("Measuring execution coverage", [&](ProgressSink *p)
        {
            return backend->query_executed(spans, &executed, p);
        });
        if ( !qr.ran )
        {
            warning("This recording's backend could not measure execution coverage.");
            return false;
        }
        res.cancelled = qr.cancelled;

        // A cancelled sweep measured only part of the trace, and a partial result
        // painted into the database is indistinguishable from a complete one.
        if ( res.cancelled )
        {
            if ( out != nullptr )
                *out = res;
            return true;
        }

        // Only instruction heads are coloured: an address inside an instruction,
        // or one IDA has no code at, has no line to colour, and forcing code
        // there from a sweep would claim more than "this ran".
        show_wait_box("HIDECANCEL\nColouring executed instructions...");
        remember_color(color);
        // 'executed' is sorted and distinct, as query_executed promises.
        for ( ea_t ea : executed )
        {
            res.executed++;
            if ( is_code(get_flags(ea)) && get_item_head(ea) == ea )
            {
                set_item_color(ea, color);
                res.colored++;
            }
            else
            {
                res.undefined++;
            }
        }
        hide_wait_box();

        if ( out != nullptr )
            *out = res;
        return true;
    }

    size_t clear_coverage()
    {
        // Every colour this database has ever been painted with, so changing the
        // shade does not strand the instructions painted with the old one.
        std::set<bgcolor_t> ours = coverage_colors();

        // Clearing also forgets which functions were measured, so the automatic
        // pass will paint them again rather than treating an empty view as done.
        netnode nn = cv_node(true);
        if ( nn != BADNODE )
        {
            for ( uchar tag : { CV_FUNC_TAG, CV_PREV_TAG } )
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
}
