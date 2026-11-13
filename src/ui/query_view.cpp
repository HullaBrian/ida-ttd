// What run_query shows while a query runs: IDA's wait box, or the recording
// window. Moved out of analysis/query_runner.cpp, which keeps the worker,
// the sink and the GIL.
#include "ui/query_view.h"
#include "ui/graph_view.h"
#include "core/backend_module.h"

namespace idattd
{
    namespace
    {
        // A running time to the second: "45 s", "3 min 07 s", "2 h 05 min 09 s".
        qstring clock_text(uint64 ms)
        {
            const unsigned long long s = ms / 1000;
            qstring t;
            if ( s >= 3600 )
                t.sprnt("%llu h %02llu min %02llu s", s / 3600, s / 60 % 60, s % 60);
            else if ( s >= 60 )
                t.sprnt("%llu min %02llu s", s / 60, s % 60);
            else
                t.sprnt("%llu s", s);
            return t;
        }

        // The longest log line the wait box shows whole: it grows with its
        // text. The recording window scrolls instead, and shows lines whole.
        const size_t LOG_LINE_CHARS = 110;

        // A log line as both show it: tabs as spaces, no surrounding blanks.
        qstring tidy_log_line(qstring l)
        {
            l.replace("\t", "    ");
            l.trim2();
            return l;
        }

        // Control characters as spaces, for the recording window: the log
        // carries the guest's console output, colour escapes and all.
        void blank_controls(qstring *s)
        {
            for ( size_t i = 0; i < s->length(); i++ )
            {
                const uchar c = (uchar)(*s)[i];
                if ( (c < 0x20 && c != '\n') || c == 0x7F )
                    (*s)[i] = ' ';
            }
        }

        // ida_ttd_qt.<fn>(args...) as a Python expression, each argument a
        // string literal (json_str writes one Python reads as well).
        qstring py_call(const char *fn, std::initializer_list<const char *> args)
        {
            qstring expr;
            expr.sprnt("ida_ttd_qt.%s(", fn);
            bool first = true;
            for ( const char *a : args )
            {
                if ( !first )
                    expr.append(", ");
                first = false;
                json_str(&expr, a);
            }
            return expr;
        }
    }

    QueryProgressView::QueryProgressView(const char *what, bool cancellable, const QueryShow *show)
        : m_what(what), m_cancellable(cancellable), m_show(show), m_started(GetTickCount64())
    {
        // A recording gets the recording window, when there is Qt to show
        // it; everything else, and a recording without it, IDA's wait box.
        if ( show == nullptr || show->log_lines == 0 || !cancellable )
        {
            open_wait_box();
            return;
        }
        extlang_object_t py = find_extlang_by_name("Python");
        qstring err;
        if ( py == nullptr || py->eval_snippet == nullptr || py->eval_expr == nullptr
          || !py->eval_snippet("import ida_ttd_qt\n", &err) )
        {
            open_wait_box();
            return;
        }
        qstring expr = py_call("recording_window_open", { show->title != nullptr ? show->title : what, what });
        expr.append(show->pausable ? ", True)" : ", False)");
        idc_value_t rv;
        if ( !py->eval_expr(&rv, BADADDR, expr.c_str(), &err) || rv.vtype != VT_LONG || rv.num == 0 )
        {
            if ( !err.empty() )
                msg("[ida-ttd] the recording window did not open (%s); using a wait box.\n", err.c_str());
            open_wait_box();
            return;
        }
        m_py.emplace(py);
        m_windowed = true;
        m_winSeq   = emulator_log_tail(0, nullptr);
    }

    QueryProgressView::~QueryProgressView()
    {
        close();
    }

    void QueryProgressView::open_wait_box()
    {
        show_wait_box("%s", wait_text(0, false, 0).c_str());
    }

    void QueryProgressView::close()
    {
        if ( m_closed )
            return;
        m_closed = true;
        if ( !m_windowed )
        {
            hide_wait_box();
        }
        else if ( m_py )
        {
            qstring err;
            (*m_py)->eval_snippet("ida_ttd_qt.recording_window_close()\n", &err);
            m_py.reset();
        }
    }

    QueryProgressView::Ask QueryProgressView::poll(uint32_t percent, bool holding)
    {
        if ( m_closed )
            return ASK_NONE;
        return m_windowed ? poll_window(holding) : poll_wait_box(percent);
    }

    // The window is driven from here ten times a second: update() also runs
    // Qt's events, since this loop is all that runs while the recording does.
    QueryProgressView::Ask QueryProgressView::poll_window(bool holding)
    {
        const ULONGLONG t = GetTickCount64();
        qstrvec_t fresh;
        m_winSeq = emulator_log_since(m_winSeq, &fresh);
        qstring lines;
        for ( const qstring &l : fresh )
        {
            if ( !lines.empty() )
                lines.append('\n');
            lines.append(tidy_log_line(l));
        }
        blank_controls(&lines);
        const uint64 ran = t - m_started - m_pausedMs - (m_paused ? t - m_pausedAt : 0);
        qstring status;
        if ( m_cancelled )
            status = "Stopping: finishing the recording...";
        else if ( m_paused )
            status.sprnt(holding ? "Paused after %s" : "Pausing after %s...", clock_text(ran).c_str());
        else
            status.sprnt("Running for %s", clock_text(ran).c_str());

        // No percentage: a recording runs until the program exits, so the
        // backend's progress (the share of an instruction limit, if any)
        // says little about how far along it is.
        // "stop", "pause", "resume", "" or "gone" (see the Python side).
        qstring asked("gone");
        if ( m_py )
        {
            qstring expr = py_call("recording_window_update", { status.c_str(), lines.c_str() });
            expr.append(')');
            idc_value_t rv;
            qstring err;
            if ( (*m_py)->eval_expr(&rv, BADADDR, expr.c_str(), &err) && rv.vtype == VT_STR )
            {
                asked = rv.qstr();
            }
            else
            {
                msg("[ida-ttd] the recording window failed (%s); stopping the recording.\n", err.c_str());
                m_py.reset();
            }
        }

        if ( m_cancelled )
            return ASK_NONE;
        if ( asked == "stop" || asked == "gone" )
        {
            m_cancelled = true;
            return ASK_STOP;
        }
        if ( asked == "pause" && !m_paused )
        {
            m_paused   = true;
            m_pausedAt = t;
            return ASK_PAUSE;
        }
        if ( asked == "resume" && m_paused )
        {
            m_paused    = false;
            m_pausedMs += t - m_pausedAt;
            return ASK_RESUME;
        }
        return ASK_NONE;
    }

    QueryProgressView::Ask QueryProgressView::poll_wait_box(uint32_t percent)
    {
        // user_cancelled() is also what pumps the UI, without which the wait
        // box never appears (it shows only after a grace period while
        // messages run). So it is called every time, and its answer is
        // ignored for a box without Cancel (HIDECANCEL offers no way to ask,
        // so it reports false anyway).
        const bool asked = user_cancelled();
        if ( m_cancelled )
            return ASK_NONE;
        if ( m_cancellable && asked )
        {
            m_cancelled = true;
            replace_wait_box("HIDECANCEL\nStopping...");
            return ASK_STOP;
        }
        // Recordings (the ones with a title) show no percentage, as in the
        // recording window; scans over a recording do.
        const QueryShow *show = m_show;
        const uint32_t now = show != nullptr && show->title != nullptr ? 0 : percent;
        const ULONGLONG t = GetTickCount64();
        const uint64 secs = show != nullptr && show->elapsed ? (t - m_started) / 1000 : 0;
        const uint64_t seq = show != nullptr && show->log_lines != 0 ? emulator_log_tail(0, nullptr) : 0;
        // New log lines repaint at most four times a second: a busy log
        // would otherwise repaint at every poll.
        if ( now != m_shown || secs != m_shownSecs || (seq != m_shownSeq && t - m_paintedAt >= 250) )
        {
            replace_wait_box("%s", wait_text(now, true, t - m_started).c_str());
            m_shown     = now;
            m_shownSecs = secs;
            m_shownSeq  = seq;
            m_paintedAt = t;
        }
        return ASK_NONE;
    }

    // The wait box's text: the first line as before, then what 'show' asks
    // for. The percentage is left out while it is 0 for work that shows its
    // time instead (a recording without a limit never reports one).
    qstring QueryProgressView::wait_text(uint32_t percent, bool painted, uint64 elapsed_ms) const
    {
        qstring t;
        t.sprnt("%s%s%s...", m_cancellable ? "" : "HIDECANCEL\n", m_what.c_str(),
                m_cancellable ? " (Cancel to stop)" : "");
        const QueryShow *show = m_show;
        if ( painted && (show == nullptr || percent != 0) )
            t.cat_sprnt(" %u%%", percent);
        if ( show == nullptr )
            return t;
        if ( show->elapsed )
            t.cat_sprnt("\nRunning for %s", clock_text(elapsed_ms).c_str());
        if ( show->log_lines != 0 )
        {
            qstrvec_t lines;
            emulator_log_tail(show->log_lines, &lines);
            t.append("\n\nSogen's log");
            if ( lines.empty() )
                t.append("\n(nothing yet)");
            for ( const qstring &raw : lines )
            {
                qstring l = tidy_log_line(raw);
                if ( l.length() > LOG_LINE_CHARS )
                {
                    l.resize(LOG_LINE_CHARS - 3);
                    l.append("...");
                }
                t.append('\n');
                t.append(l);
            }
        }
        return t;
    }
}
