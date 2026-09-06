#include "ui.h"
#include "coverage.h"
#include "decompiler.h"
#include "callsites.h"

using namespace TTD;

namespace idattd
{
    //=======================================================================
    // Small helper: a function's display name (demangled when possible).
    //=======================================================================
    static qstring func_display_name(ea_t ea)
    {
        qstring name;
        get_func_name(&name, ea);
        // The call target often has no DEFINED function (it lives in a module we
        // haven't laid out), but it usually has a name (an export or a PDB symbol).
        // Fall back to that, then to the bare address, so the Function column is
        // never blank.
        if ( name.empty() )
            get_name(&name, ea);
        qstring dem;
        if ( !name.empty() && demangle_name(&dem, name.c_str(), 0) > 0 && !dem.empty() )
            return dem;
        if ( name.empty() )
            name.sprnt("0x%llX", (uint64_t)ea);
        return name;
    }

    //=======================================================================
    // PositionChooser
    //=======================================================================
    static const int   g_pos_widths[] = { 16, 48 };
    static const char *g_pos_header[] = { "Position", "Event" };

    // NB: these choosers are heap-allocated and handed to choose(), so they must
    // NOT set CH_KEEP. CH_KEEP means "the chooser's lifetime is NOT tied to the
    // widget" -- IDA then never deletes it (kernwin.hpp: the instance "will be
    // delete()d unless CH_KEEP is specified"). It is for static/global or
    // stack-allocated choosers. Setting it here leaked the object, and with it the
    // whole frozen event snapshot, every time one of these windows was opened.
    PositionChooser::PositionChooser(TraceManager *mgr)
        : chooser_t(0, qnumber(g_pos_widths), g_pos_widths, g_pos_header, "TTD Timeline"),
          m_mgr(mgr)
    {
        if ( m_mgr != nullptr )
            m_positions = m_mgr->collect_positions();
    }

    size_t idaapi PositionChooser::get_count() const
    {
        return m_positions.size();
    }

    void idaapi PositionChooser::get_row(qstrvec_t *cols, int * /*icon*/,
                                         chooser_item_attrs_t * /*attrs*/, size_t n) const
    {
        if ( n >= m_positions.size() )
            return;
        const TraceManager::NamedPosition &e = m_positions[n];
        cols->at(0).sprnt("%llX:%llX",
                          (uint64_t)e.pos.Sequence, (uint64_t)e.pos.Steps);
        cols->at(1) = e.name.c_str();
    }

    // Double-click / Enter: queue navigation to the selected position. We must
    // NOT resume the debugger synchronously from inside a chooser callback, and
    // we must never do it from get_ea() (IDA calls get_ea while rendering rows,
    // which would resume the debugger once per visible row). Hence: defer with
    // request_continue_process() + run_requests().
    chooser_t::cbret_t idaapi PositionChooser::enter(size_t n)
    {
        if ( m_mgr != nullptr && m_mgr->is_active() && n < m_positions.size() )
        {
            m_mgr->set_next_position(m_positions[n].pos);
            request_continue_process();
            run_requests();
        }
        return cbret_t(n, NOTHING_CHANGED);
    }

    //=======================================================================
    // TracedFunctionsChooser
    //=======================================================================
    static const int   g_trc_widths[] = { 18, 48 };
    static const char *g_trc_header[] = { "Offset", "Function name" };

    TracedFunctionsChooser::TracedFunctionsChooser(TraceManager *mgr, FunctionTracer *tracer)
        : chooser_t(CH_CAN_DEL | CH_CAN_INS,
                    qnumber(g_trc_widths), g_trc_widths, g_trc_header, "Traced functions"),
          m_mgr(mgr), m_tracer(tracer)
    {
    }

    size_t idaapi TracedFunctionsChooser::get_count() const
    {
        return m_tracer != nullptr ? m_tracer->count_traced() : 0;
    }

    void idaapi TracedFunctionsChooser::get_row(qstrvec_t *cols, int * /*icon*/,
                                                chooser_item_attrs_t * /*attrs*/, size_t n) const
    {
        if ( m_tracer == nullptr )
            return;
        ea_t ea = m_tracer->traced_at(n);
        cols->at(0).sprnt("0x%llX", (uint64_t)ea);
        cols->at(1) = func_display_name(ea);
    }

    // Side-effect-free: lets Enter jump the disassembly to the function.
    ea_t idaapi TracedFunctionsChooser::get_ea(size_t n) const
    {
        return m_tracer != nullptr ? m_tracer->traced_at(n) : BADADDR;
    }

    chooser_t::cbret_t idaapi TracedFunctionsChooser::ins(ssize_t /*n*/)
    {
        ea_t fea = choose_func_ea("Choose a function to trace", get_screen_ea());
        if ( fea == BADADDR || m_tracer == nullptr )
            return cbret_t();
        m_tracer->add_func(fea);
        return ALL_CHANGED;
    }

    chooser_t::cbret_t idaapi TracedFunctionsChooser::del(size_t n)
    {
        if ( m_tracer != nullptr )
            m_tracer->remove_trace(n);
        return ALL_CHANGED;
    }

    //=======================================================================
    // TraceEventsChooser
    //=======================================================================
    EventColumns::EventColumns(FunctionTracer *tracer)
    {
        // One column per parameter only makes sense when a single function is
        // traced (all rows share its signature). Otherwise fall back to one
        // combined "Arguments" column.
        ea_t single = (tracer != nullptr && tracer->count_traced() == 1)
                    ? tracer->traced_at(0) : BADADDR;

        std::vector<qstring> arg_names;
        if ( single != BADADDR )
        {
            tinfo_t          t;
            func_type_data_t fd;
            if ( get_tinfo(&t, single) && t.is_func() && t.get_func_details(&fd) )
            {
                per_arg = true;
                argc    = (int)fd.size();
                for ( size_t i = 0; i < fd.size(); i++ )
                {
                    qstring nm = fd[i].name;
                    if ( nm.empty() )
                        nm.sprnt("arg%d", (int)i);
                    arg_names.push_back(nm);
                }
            }
            else
            {
                // No prototype: four generic register/stack arg columns.
                per_arg = true;
                argc    = 4;
                for ( int i = 0; i < 4; i++ )
                {
                    qstring nm;
                    nm.sprnt("arg%d", i);
                    arg_names.push_back(nm);
                }
            }
        }

        // Fixed leading columns (LEAD == 4): call/return positions, thread, name.
        header_strs.push_back("Start");     widths.push_back(16);
        header_strs.push_back("End");       widths.push_back(16);
        header_strs.push_back("Thread");    widths.push_back(8);
        header_strs.push_back("Function");  widths.push_back(22);
        if ( per_arg )
        {
            for ( const qstring &nm : arg_names )
            {
                header_strs.push_back(nm);
                widths.push_back(24);
            }
        }
        else
        {
            header_strs.push_back("Arguments");
            widths.push_back(72);
        }
        header_strs.push_back("Return");    widths.push_back(26);

        // Build the pointer array only after header_strs is final (so the
        // c_str() pointers stay valid for the chooser's lifetime).
        for ( const qstring &s : header_strs )
            header_ptrs.push_back(s.c_str());

        // A unique, descriptive title so multiple events tabs can coexist (IDA
        // keys widgets by title and would otherwise just re-focus the first).
        static int seq = 0;
        qstring fname = single != BADADDR ? func_display_name(single) : qstring("calls");
        title_str.sprnt("TTD calls: %s [%d]", fname.c_str(), ++seq);
    }

    TraceEventsChooser::TraceEventsChooser(TraceManager *mgr, FunctionTracer *tracer)
        : EventColumns(tracer),
          chooser_t(CH_CAN_DEL,
                    EventColumns::n(), EventColumns::w(), EventColumns::h(), EventColumns::t()),
          m_mgr(mgr),
          m_events(tracer != nullptr ? tracer->snapshot_events() : std::vector<FunctionInvocation>())
    {
    }

    size_t idaapi TraceEventsChooser::get_count() const
    {
        return m_events.size();
    }

    void idaapi TraceEventsChooser::get_row(qstrvec_t *cols, int * /*icon*/,
                                            chooser_item_attrs_t * /*attrs*/, size_t n) const
    {
        if ( n >= m_events.size() )
            return;
        const FunctionInvocation &ev = m_events[n];

        cols->at(0).sprnt("%llX:%llX", (uint64_t)ev.pos.Sequence, (uint64_t)ev.pos.Steps);
        if ( ev.has_ret )
            cols->at(1).sprnt("%llX:%llX", (uint64_t)ev.end_pos.Sequence, (uint64_t)ev.end_pos.Steps);
        cols->at(2).sprnt("%X", ev.tid);
        cols->at(3) = func_display_name(ev.func_ea);

        if ( per_arg )
        {
            for ( int i = 0; i < argc; i++ )
                cols->at(LEAD + i) = i < (int)ev.args.size() ? ev.args[i] : qstring();
            if ( ev.has_ret )
                cols->at(LEAD + argc) = ev.retval;
        }
        else
        {
            // Multiple functions share this column, so label each value with its
            // parameter name (from the row's own signature) when available.
            tinfo_t          t;
            func_type_data_t fd;
            bool named = get_tinfo(&t, ev.func_ea) && t.is_func() && t.get_func_details(&fd);

            qstring joined;
            for ( size_t i = 0; i < ev.args.size(); i++ )
            {
                if ( i != 0 )
                    joined.append(", ");
                if ( named && i < fd.size() && !fd[i].name.empty() )
                {
                    joined.append(fd[i].name);
                    joined.append("=");
                }
                joined.append(ev.args[i]);
            }
            cols->at(LEAD) = joined;
            if ( ev.has_ret )
                cols->at(LEAD + 1) = ev.retval;
        }
    }

    // Double-click / Enter: time-travel to this call's position. Deferred resume
    // only (never continue_process() directly, never from get_ea()).
    chooser_t::cbret_t idaapi TraceEventsChooser::enter(size_t n)
    {
        if ( m_mgr != nullptr && m_mgr->is_active() && n < m_events.size() )
        {
            m_mgr->set_next_position(m_events[n].pos);
            request_continue_process();
            run_requests();
        }
        return cbret_t(n, NOTHING_CHANGED);
    }

    chooser_t::cbret_t idaapi TraceEventsChooser::del(size_t n)
    {
        if ( n < m_events.size() )
            m_events.erase(m_events.begin() + n);
        return ALL_CHANGED;
    }

    //=======================================================================
    // TTD navigation action handlers
    //=======================================================================
    int idaapi RunBackHandler::activate(action_activation_ctx_t *)
    {
        if ( mgr != nullptr )
            mgr->request_run(false);
        return 1;
    }

    int idaapi StepOutBackHandler::activate(action_activation_ctx_t *)
    {
        if ( mgr != nullptr )
            mgr->request_step_out_backward();
        return 1;
    }

    int idaapi RunToCursorBackHandler::activate(action_activation_ctx_t *ctx)
    {
        if ( mgr == nullptr )
            return 1;
        // The address under the cursor (works from disasm or pseudocode); fall back
        // to the screen ea if the context didn't carry one.
        ea_t ea = ctx != nullptr && ctx->cur_ea != BADADDR ? ctx->cur_ea : get_screen_ea();
        mgr->request_run_to_cursor_backward(ea);
        return 1;
    }

    int idaapi RunToCursorFwdHandler::activate(action_activation_ctx_t *ctx)
    {
        if ( mgr == nullptr )
            return 1;
        // The address under the cursor (works from disasm or pseudocode); fall back
        // to the screen ea if the context didn't carry one.
        ea_t ea = ctx != nullptr && ctx->cur_ea != BADADDR ? ctx->cur_ea : get_screen_ea();
        mgr->request_run_to_cursor_forward(ea);
        return 1;
    }

    int idaapi OpenTimelineHandler::activate(action_activation_ctx_t *)
    {
        if ( mgr == nullptr || !mgr->is_active() )
        {
            warning("The TTD timeline is only available while replaying a trace.");
            return 1;
        }
        // No CH_KEEP: IDA deletes the chooser when its widget closes.
        PositionChooser *ch = new PositionChooser(mgr);
        ch->choose();
        return 1;
    }

    int idaapi GotoPositionHandler::activate(action_activation_ctx_t *)
    {
        if ( mgr != nullptr )
            mgr->goto_position();
        return 1;
    }

    // Copy ASCII text to the Windows clipboard (IDA exposes no clipboard API).
    static void copy_to_clipboard(const char *text)
    {
        if ( text == nullptr || !OpenClipboard(nullptr) )
            return;
        EmptyClipboard();
        size_t  n = qstrlen(text) + 1;
        HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, n);
        if ( h != nullptr )
        {
            void *p = GlobalLock(h);
            if ( p != nullptr )
            {
                memcpy(p, text, n);
                GlobalUnlock(h);
                // The clipboard only takes ownership of the block when
                // SetClipboardData SUCCEEDS; on failure it is still ours to free.
                if ( SetClipboardData(CF_TEXT, h) == nullptr )
                    GlobalFree(h);
            }
            else
            {
                GlobalFree(h);
            }
        }
        CloseClipboard();
    }

    int idaapi PositionCopyHandler::activate(action_activation_ctx_t *)
    {
        if ( mgr == nullptr || !mgr->is_active() )
            return 1;
        TTD::Replay::Position p = mgr->current_position();
        qstring s;
        s.sprnt("%llX:%llX", (uint64_t)p.Sequence, (uint64_t)p.Steps);
        copy_to_clipboard(s.c_str());
        msg("[ida-ttd] copied position %s to clipboard.\n", s.c_str());
        return 1;
    }

    int idaapi AnalyzeFuncHandler::activate(action_activation_ctx_t *)
    {
        if ( mgr == nullptr || !mgr->is_active() )
        {
            warning("Analysis is only available while replaying a trace.");
            return 1;
        }
        mgr->analyze_whole_function();
        return 1;
    }

    //=======================================================================
    // Tracer action handlers
    //=======================================================================
    // One click: trace the function under the cursor, sweep the whole trace,
    // and open the results.
    int idaapi TraceFuncHandler::activate(action_activation_ctx_t *ctx)
    {
        if ( tracer == nullptr )
            return 1;
        if ( mgr == nullptr || !mgr->is_active() )
        {
            warning("Tracing is only available while replaying a trace.");
            return 1;
        }
        ea_t ea = ctx != nullptr && ctx->cur_ea != BADADDR ? ctx->cur_ea : get_screen_ea();
        ea_t fstart = get_func_start(ea);
        ea_t target = fstart != BADADDR ? fstart : ea;

        // This is a focused "calls to THIS function" query: replace any prior
        // traced set so results aren't polluted by earlier picks. (Use the
        // 'Traced functions' chooser + 'Re-run trace' to accumulate several.)
        tracer->reset();
        tracer->add_func(target);
        tracer->run_sweep();

        TraceEventsChooser *ch = new TraceEventsChooser(mgr, tracer);
        ch->choose();
        return 1;
    }

    action_state_t idaapi TraceFuncHandler::update(action_update_ctx_t *ctx)
    {
        // Meaningful over any address with code (the handler warns if no trace is
        // being replayed when invoked).
        if ( ctx != nullptr && ctx->cur_ea != BADADDR )
            return AST_ENABLE;
        return AST_DISABLE;
    }

    // Prompt for a "module!Glob*" pattern, trace every matching function in one
    // sweep, and open the results. With more than one match the events chooser
    // automatically condenses arguments into a single column.
    int idaapi TracePatternHandler::activate(action_activation_ctx_t *)
    {
        if ( tracer == nullptr )
            return 1;
        if ( mgr == nullptr || !mgr->is_active() )
        {
            warning("Tracing is only available while replaying a trace.");
            return 1;
        }

        qstring pat;
        if ( !ask_str(&pat, 0, "Trace calls to functions matching (wildcards * ?, "
                               "optional module!, e.g. kernel32!Virtual*)")
          || pat.empty() )
            return 1;

        std::vector<ea_t> hits = mgr->resolve_function_pattern(pat.c_str());
        if ( hits.empty() )
        {
            info("No functions matched '%s'.\n\n"
                 "Patterns match symbol names (exports/PDB). Make sure the module "
                 "is loaded in the trace and try e.g. 'kernel32!Virtual*'.", pat.c_str());
            return 1;
        }

        tracer->reset();
        for ( ea_t ea : hits )
            tracer->add_func(ea);
        tracer->run_sweep();

        TraceEventsChooser *ch = new TraceEventsChooser(mgr, tracer);
        ch->choose();
        return 1;
    }

    int idaapi OpenTracedHandler::activate(action_activation_ctx_t *)
    {
        TracedFunctionsChooser *ch = new TracedFunctionsChooser(mgr, tracer);
        ch->choose();
        return 1;
    }

    int idaapi OpenEventsHandler::activate(action_activation_ctx_t *)
    {
        TraceEventsChooser *ch = new TraceEventsChooser(mgr, tracer);
        ch->choose();
        return 1;
    }

    int idaapi RunTraceHandler::activate(action_activation_ctx_t *)
    {
        if ( mgr == nullptr || !mgr->is_active() )
        {
            warning("Tracing is only available while replaying a trace.");
            return 1;
        }
        if ( tracer != nullptr )
            tracer->run_sweep();
        return 1;
    }

    //=======================================================================
    // BookmarkChooser
    //=======================================================================
    static const int   g_bm_widths[] = { 16, 18, 8, 28, 40 };
    static const char *g_bm_header[] = { "Position", "Address", "Thread", "Name", "Comment" };

    // Prompt for a bookmark's name and note. 'b' carries the defaults in and the
    // answers out; false means the user cancelled.
    static bool ask_bookmark_details(Bookmark &b, bool is_new)
    {
        // The form text is a format string to IDA as well, so only the hex
        // position is interpolated into it -- never a symbol name, which could
        // contain characters the form parser treats as syntax.
        qstring fmt;
        fmt.sprnt("%s TTD bookmark\n"
                  "\n"
                  "\n"
                  "Position %llX:%llX\n"
                  "\n"
                  "<~N~ame:q:256:60::>\n"
                  "<~C~omment:t::60:::>\n"
                  "\n",
                  is_new ? "New" : "Edit",
                  (uint64_t)b.pos.Sequence, (uint64_t)b.pos.Steps);

        qstring         name = b.name;
        textctrl_info_t ti;
        ti.cb   = sizeof(textctrl_info_t);
        ti.text = b.comment;
        if ( ask_form(fmt.c_str(), &name, &ti) <= 0 )
            return false;
        b.name    = name;
        b.comment = ti.text;
        return true;
    }

    // Build a bookmark for wherever the cursor is standing right now.
    static bool bookmark_here(TraceManager *mgr, Bookmark &b)
    {
        if ( mgr == nullptr || !mgr->is_active() )
        {
            warning("Bookmarks are only available while replaying a trace.");
            return false;
        }
        b.pos = mgr->current_position();
        b.ea  = mgr->current_pc_ea();
        b.tid = (uint32_t)get_current_thread();
        // A default label so a bookmark dropped without typing anything still
        // says something useful in the list.
        if ( b.ea != BADADDR )
            b.name = func_display_name(b.ea);
        return true;
    }

    BookmarkChooser::BookmarkChooser(TraceManager *mgr, BookmarkStore *store)
        : chooser_t(CH_CAN_INS | CH_CAN_DEL | CH_CAN_EDIT,
                    qnumber(g_bm_widths), g_bm_widths, g_bm_header, "TTD Bookmarks"),
          m_mgr(mgr), m_store(store)
    {
    }

    size_t idaapi BookmarkChooser::get_count() const
    {
        return m_store != nullptr ? m_store->size() : 0;
    }

    void idaapi BookmarkChooser::get_row(qstrvec_t *cols, int * /*icon*/,
                                         chooser_item_attrs_t * /*attrs*/, size_t n) const
    {
        const Bookmark *b = m_store != nullptr ? m_store->at(n) : nullptr;
        if ( b == nullptr )
            return;
        cols->at(0).sprnt("%llX:%llX", (uint64_t)b->pos.Sequence, (uint64_t)b->pos.Steps);
        if ( b->ea != BADADDR )
            cols->at(1).sprnt("0x%llX", (uint64_t)b->ea);
        cols->at(2).sprnt("0x%X", b->tid);
        cols->at(3) = b->name;
        cols->at(4) = b->comment;
        // A note spanning several lines would break the row; show the first only.
        size_t nl = cols->at(4).find('\n');
        if ( nl != qstring::npos )
        {
            cols->at(4).resize(nl);
            cols->at(4).append(" ...");
        }
    }

    // Side-effect-free: lets the chooser follow the selection in the disassembly.
    ea_t idaapi BookmarkChooser::get_ea(size_t n) const
    {
        const Bookmark *b = m_store != nullptr ? m_store->at(n) : nullptr;
        return b != nullptr ? b->ea : BADADDR;
    }

    // Deferred resume only, for the same reason as the timeline: we must not
    // drive the debugger synchronously from inside a chooser callback.
    chooser_t::cbret_t idaapi BookmarkChooser::enter(size_t n)
    {
        const Bookmark *b = m_store != nullptr ? m_store->at(n) : nullptr;
        if ( b != nullptr && m_mgr != nullptr && m_mgr->is_active() )
        {
            m_mgr->set_next_position(b->pos);
            request_continue_process();
            run_requests();
        }
        return cbret_t(n, NOTHING_CHANGED);
    }

    chooser_t::cbret_t idaapi BookmarkChooser::ins(ssize_t /*n*/)
    {
        Bookmark b;
        if ( m_store == nullptr || !bookmark_here(m_mgr, b) || !ask_bookmark_details(b, true) )
            return cbret_t();
        return cbret_t((ssize_t)m_store->add(b), ALL_CHANGED);
    }

    chooser_t::cbret_t idaapi BookmarkChooser::del(size_t n)
    {
        if ( m_store != nullptr )
            m_store->remove(n);
        return ALL_CHANGED;
    }

    chooser_t::cbret_t idaapi BookmarkChooser::edit(size_t n)
    {
        const Bookmark *cur = m_store != nullptr ? m_store->at(n) : nullptr;
        if ( cur == nullptr )
            return cbret_t();
        Bookmark b = *cur;              // copy: at() points into the store
        if ( !ask_bookmark_details(b, false) )
            return cbret_t();
        m_store->update(n, b);
        return cbret_t((ssize_t)n, ALL_CHANGED);
    }

    //=======================================================================
    // Bookmark action handlers
    //=======================================================================
    int idaapi AddBookmarkHandler::activate(action_activation_ctx_t *)
    {
        Bookmark b;
        if ( store == nullptr || !bookmark_here(mgr, b) || !ask_bookmark_details(b, true) )
            return 1;
        store->add(b);
        msg("[ida-ttd] bookmarked %llX:%llX (%s).\n",
            (uint64_t)b.pos.Sequence, (uint64_t)b.pos.Steps, b.name.c_str());
        // Any open bookmark window reads the same store, so tell it to re-read
        // rather than leaving the new entry invisible until it is reopened.
        refresh_chooser("TTD Bookmarks");
        return 1;
    }

    int idaapi OpenBookmarksHandler::activate(action_activation_ctx_t *)
    {
        // No CH_KEEP: IDA deletes the chooser when its widget closes.
        BookmarkChooser *ch = new BookmarkChooser(mgr, store);
        ch->choose();
        return 1;
    }

    //=======================================================================
    // Execution coverage
    //=======================================================================
    // Which addresses should the sweep watch? A narrower answer is not just
    // tidier: the watchpoints are what let the engine skip parts of the
    // recording, so the scope is the difference between seconds and minutes.
    // The colour has to be asked for too. IDA has no API for "is the theme dark",
    // and a shade that reads on a light theme is nearly invisible on a dark one,
    // so the only honest default is the last one this database used.
    static bool ask_coverage_options(int &scope, bgcolor_t &color)
    {
        static const char form[] =
            "TTD execution coverage\n"
            "\n"
            "\n"
            "Colour every instruction the recording actually executed.\n"
            "A narrower scope replays much less of the trace.\n"
            "\n"
            "<~S~cope:b:0:40::>\n"
            "<~C~olour:K::6::>\n"
            "\n";
        qstrvec_t items;
        items.push_back("Function under the cursor");
        items.push_back("Module under the cursor");
        items.push_back("All loaded modules");
        static int sel = 0;             // remember the last choice within a session
        color = coverage_color();
        if ( ask_form(form, &items, &sel, &color) <= 0 )
            return false;
        scope = sel;
        return true;
    }

    int idaapi CoverageHandler::activate(action_activation_ctx_t *ctx)
    {
        if ( mgr == nullptr || !mgr->is_active() )
        {
            warning("Execution coverage is only available while replaying a trace.");
            return 1;
        }

        int       scope = 0;
        bgcolor_t color = COVERAGE_DEFAULT_COLOR;
        if ( !ask_coverage_options(scope, color) )
            return 1;

        ea_t ea = ctx != nullptr && ctx->cur_ea != BADADDR ? ctx->cur_ea : get_screen_ea();
        std::vector<std::pair<ea_t, ea_t>> ranges;
        if ( scope == 0 )
        {
            func_entry_info_t fi;
            if ( !get_func_entry_info(&fi, ea) )
            {
                warning("There is no defined function at 0x%llX.\n\n"
                        "Define one first, or measure the whole module instead.",
                        (uint64_t)ea);
                return 1;
            }
            ranges.push_back({ fi.start_ea, fi.end_ea });
        }
        else if ( scope == 1 )
        {
            ea_t lo = 0, hi = 0;
            if ( !mgr->module_range_at(ea, lo, hi) )
            {
                warning("0x%llX is not inside a module loaded by the trace.\n\n"
                        "Dynamically allocated code has no module to measure; "
                        "use the function scope there.", (uint64_t)ea);
                return 1;
            }
            ranges.push_back({ lo, hi });
        }
        else
        {
            ranges = mgr->module_ranges();
        }

        CoverageResult r;
        if ( !run_coverage(mgr, ranges, color, &r) )
            return 1;

        msg("[ida-ttd] coverage%s: %llu addresses executed, %llu instructions "
            "coloured, %llu with no code defined.\n",
            r.cancelled ? " (stopped early, results are partial)" : "",
            r.executed, r.colored, r.undefined);
        if ( r.cancelled )
            info("The sweep was stopped early, so the highlight shows only the "
                 "part of the recording that had been replayed.");
        else if ( r.executed == 0 )
            info("Nothing in that range executed anywhere in the recording.");
        refresh_idaview_anyway();
        return 1;
    }

    int idaapi ClearCoverageHandler::activate(action_activation_ctx_t *)
    {
        size_t n = clear_coverage();
        msg("[ida-ttd] cleared the execution highlight from %d instructions.\n", (int)n);
        refresh_idaview_anyway();
        refresh_pseudocode_views();
        return 1;
    }

    int idaapi AutoCoverageHandler::activate(action_activation_ctx_t *)
    {
        bool on = !coverage_auto_enabled();
        set_coverage_auto_enabled(on);
        update_action_checked(actions::COVERAGE_AUTO, on);
        msg("[ida-ttd] automatic coverage of the function you stop in is now %s.\n",
            on ? "on" : "off");
        return 1;
    }

    action_state_t idaapi AutoCoverageHandler::update(action_update_ctx_t *)
    {
        // The tick has to be re-asserted here: IDA asks for the state when it
        // draws the menu, and the answer lives in the database, not in this
        // object, so it can change under us when a different IDB is opened.
        update_action_checked(actions::COVERAGE_AUTO, coverage_auto_enabled());
        return AST_ENABLE_ALWAYS;
    }

    //=======================================================================
    // MemAccessChooser
    //=======================================================================
    static const int   g_ma_widths[] = { 16, 8, 8, 18, 6, 28 };
    static const char *g_ma_header[] = { "Position", "Thread", "Access",
                                         "Address", "Size", "Instruction" };

    MemAccessChooser::MemAccessChooser(TraceManager *mgr, ea_t lo, ea_t hi,
                                       std::vector<MemAccess> &&hits)
        : chooser_t(CH_CAN_DEL, qnumber(g_ma_widths), g_ma_widths, g_ma_header, nullptr),
          m_mgr(mgr), m_hits(std::move(hits))
    {
        // A unique title per search, so two searches open as two tabs instead of
        // one replacing the other. The string is a member because chooser_base_t
        // keeps the pointer it is given rather than copying it.
        if ( hi - lo <= 1 )
            m_title.sprnt("TTD accesses: 0x%llX [%d]", (uint64_t)lo, (int)m_hits.size());
        else
            m_title.sprnt("TTD accesses: 0x%llX..0x%llX [%d]",
                          (uint64_t)lo, (uint64_t)hi, (int)m_hits.size());
        title = m_title.c_str();
    }

    size_t idaapi MemAccessChooser::get_count() const
    {
        return m_hits.size();
    }

    void idaapi MemAccessChooser::get_row(qstrvec_t *cols, int * /*icon*/,
                                          chooser_item_attrs_t * /*attrs*/, size_t n) const
    {
        if ( n >= m_hits.size() )
            return;
        const MemAccess &a = m_hits[n];
        cols->at(0).sprnt("%llX:%llX", (uint64_t)a.pos.Sequence, (uint64_t)a.pos.Steps);
        cols->at(1).sprnt("0x%X", a.tid);
        cols->at(2) = access_name(a.kind);
        cols->at(3).sprnt("0x%llX", (uint64_t)a.addr);
        cols->at(4).sprnt("%u", a.size);
        // Where the access came from, as a name plus offset when we have one --
        // the raw address alone rarely says anything.
        qstring where;
        ea_t fs = get_func_start(a.pc);
        if ( fs != BADADDR )
        {
            qstring fn = func_display_name(fs);
            if ( a.pc == fs )
                where = fn;
            else
                where.sprnt("%s+0x%llX", fn.c_str(), (uint64_t)(a.pc - fs));
        }
        else
        {
            where.sprnt("0x%llX", (uint64_t)a.pc);
        }
        cols->at(5) = where;
    }

    // Side-effect-free: lets the chooser follow the selection in the disassembly.
    ea_t idaapi MemAccessChooser::get_ea(size_t n) const
    {
        return n < m_hits.size() ? m_hits[n].pc : BADADDR;
    }

    // Deferred resume only, as everywhere else: never drive the debugger
    // synchronously from inside a chooser callback.
    chooser_t::cbret_t idaapi MemAccessChooser::enter(size_t n)
    {
        if ( m_mgr != nullptr && m_mgr->is_active() && n < m_hits.size() )
        {
            m_mgr->set_next_position(m_hits[n].pos);
            request_continue_process();
            run_requests();
        }
        return cbret_t(n, NOTHING_CHANGED);
    }

    chooser_t::cbret_t idaapi MemAccessChooser::del(size_t n)
    {
        if ( n < m_hits.size() )
            m_hits.erase(m_hits.begin() + n);
        return ALL_CHANGED;
    }

    //=======================================================================
    // Memory access search
    //=======================================================================
    int idaapi MemSearchHandler::activate(action_activation_ctx_t *ctx)
    {
        if ( mgr == nullptr || !mgr->is_active() )
        {
            warning("Memory searching is only available while replaying a trace.");
            return 1;
        }

        static const char form[] =
            "TTD memory access search\n"
            "\n"
            "\n"
            "Find every time the recording touched this memory.\n"
            "\n"
            "<~A~ddress:$::18::>\n"
            "<~L~ength in bytes:D::18::>\n"
            "<##Access##~R~ead:C>\n"
            "<~W~rite:C>\n"
            "<E~x~ecute:C>>\n"
            "\n";

        // Seed from wherever the user is, which is usually what they mean.
        static sval_t  len  = 1;
        static ushort  bits = ACC_READ | ACC_WRITE;
        ea_t addr = ctx != nullptr && ctx->cur_ea != BADADDR ? ctx->cur_ea : get_screen_ea();
        if ( ask_form(form, &addr, &len, &bits) <= 0 )
            return 1;
        if ( len <= 0 )
            len = 1;

        std::vector<MemAccess> hits;
        bool truncated = false, cancelled = false;
        if ( !search_memory(mgr, addr, addr + (ea_t)len, (uint8_t)bits,
                            &hits, &truncated, &cancelled) )
            return 1;

        msg("[ida-ttd] memory search: %d access(es) to 0x%llX..0x%llX%s%s.\n",
            (int)hits.size(), (uint64_t)addr, (uint64_t)(addr + (ea_t)len),
            truncated ? " (record limit reached, results are partial)" : "",
            cancelled ? " (stopped early)" : "");
        if ( hits.empty() )
        {
            info("Nothing in the recording read, wrote or executed that memory.");
            return 1;
        }

        // No CH_KEEP: IDA deletes the chooser when its widget closes.
        MemAccessChooser *ch = new MemAccessChooser(mgr, addr, addr + (ea_t)len,
                                                    std::move(hits));
        ch->choose();
        return 1;
    }

    //=======================================================================
    // Indirect call annotation
    //=======================================================================
    int idaapi IndirectCallsHandler::activate(action_activation_ctx_t *ctx)
    {
        if ( mgr == nullptr || !mgr->is_active() )
        {
            warning("This is only available while replaying a trace.");
            return 1;
        }

        int       scope = 0;
        bgcolor_t unused = 0;
        qnotused(unused);
        static const char form[] =
            "TTD indirect calls\n"
            "\n"
            "\n"
            "Watch where every indirect call actually goes, and write that\n"
            "back as a comment and a real cross-reference.\n"
            "\n"
            "The whole recording is replayed whichever scope you pick: a call\n"
            "is not something the engine can skip ahead to. The scope decides\n"
            "which call sites get annotated.\n"
            "\n"
            "<~S~cope:b:0:40::>\n"
            "\n";
        qstrvec_t items;
        items.push_back("Function under the cursor");
        items.push_back("Module under the cursor");
        items.push_back("All loaded modules");
        static int sel = 0;             // the function you are looking at
        if ( ask_form(form, &items, &sel) <= 0 )
            return 1;
        scope = sel;

        ea_t ea = ctx != nullptr && ctx->cur_ea != BADADDR ? ctx->cur_ea : get_screen_ea();
        std::vector<std::pair<ea_t, ea_t>> ranges;
        if ( scope == 0 )
        {
            func_entry_info_t fi;
            if ( !get_func_entry_info(&fi, ea) )
            {
                warning("There is no defined function at 0x%llX.", (uint64_t)ea);
                return 1;
            }
            ranges.push_back({ fi.start_ea, fi.end_ea });
        }
        else if ( scope == 1 )
        {
            ea_t lo = 0, hi = 0;
            if ( !mgr->module_range_at(ea, lo, hi) )
            {
                warning("0x%llX is not inside a module loaded by the trace.",
                        (uint64_t)ea);
                return 1;
            }
            ranges.push_back({ lo, hi });
        }
        else
        {
            ranges = mgr->module_ranges();
        }

        CallSiteResult r;
        if ( !annotate_indirect_calls(mgr, ranges, &r) )
            return 1;

        msg("[ida-ttd] indirect calls: %d site(s) annotated, %d distinct target(s), "
            "%d site(s) reached more than one%s%s.\n",
            (int)r.sites, (int)r.targets, (int)r.polymorphic,
            r.truncated ? " (site limit reached)" : "",
            r.cancelled ? " (stopped early)" : "");
        if ( r.undefined != 0 )
            msg("[ida-ttd] %d call site(s) were skipped: IDA has no instruction "
                "defined there, so a cross-reference cannot be attached.\n",
                (int)r.undefined);
        if ( r.sites == 0 )
            info("No indirect call in that scope was executed by the recording.");
        refresh_idaview_anyway();
        refresh_pseudocode_views();
        return 1;
    }

    int idaapi ClearIndirectCallsHandler::activate(action_activation_ctx_t *)
    {
        size_t n = clear_indirect_call_annotations();
        msg("[ida-ttd] removed the indirect-call annotation from %d site(s).\n", (int)n);
        refresh_idaview_anyway();
        refresh_pseudocode_views();
        return 1;
    }
}
