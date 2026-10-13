// Forking the recording: beginning a fork, recording it, and what a replay
// asks the user for.
#include "ui/ui.h"
#include "analysis/fork.h"

namespace idattd
{
    static bool backend_forks(TraceManager *mgr)
    {
        return mgr != nullptr && mgr->is_active() && mgr->backend() != nullptr
            && mgr->backend()->capabilities().fork;
    }

    static bool has_changes(const TraceManager::ForkDraft &d)
    {
        return !d.regs.empty() || !d.bytes.empty();
    }

    // Text for an ask_form description: '#', '<', '>', '~' and '@' mean
    // something there, and a message from a backend may hold any of them.
    static qstring form_text(const qstring &s)
    {
        qstring out;
        for ( char c : s )
            out.append(strchr("#<>~@", c) != nullptr ? '\'' : c);
        return out;
    }

    // ------------------------------------------------------- replay consent

    // The recording this IDA was given consent to replay against the host,
    // so the question is asked once per recording, not once per replay.
    static qstring g_hostConsent;

    ReplaySettings initial_replay_settings(TraceManager *mgr)
    {
        ReplaySettings rs;
        rs.registry_dir = saved_registry_dir();
        rs.allow_host   = mgr != nullptr && !g_hostConsent.empty() && g_hostConsent == mgr->trace_path();
        return rs;
    }

    bool ask_replay_needs(TraceManager *mgr, ReplaySettings *rs)
    {
        ITraceBackend *b = mgr != nullptr ? mgr->backend() : nullptr;
        if ( b == nullptr )
            return false;
        switch ( b->last_replay_block() )
        {
            case ReplayBlock::HostConsent:
                if ( rs->allow_host )
                    return false;
                if ( ask_yn(ASKBTN_NO,
                            "HIDECANCEL\n"
                            "This recording was made against this machine's own files, not an\n"
                            "emulation root.\n\n"
                            "Replaying it runs the program again, and its file and network\n"
                            "operations happen again on this machine: whatever it created,\n"
                            "renamed, deleted or sent, it does again.\n\n"
                            "Replay it anyway? Only for programs you trust.") != ASKBTN_YES )
                    return false;
                g_hostConsent   = mgr->trace_path();
                rs->allow_host  = true;
                return true;

            case ReplayBlock::Registry:
            {
                static const char form[] =
                    "Registry hives\n"
                    "\n"
                    "\n"
                    "Replaying the program loads the registry it ran against, and none was found.\n"
                    "%A\n"
                    "\n"
                    "Choose the folder holding the hives the recording was made with\n"
                    "(SYSTEM, SOFTWARE, SAM, SECURITY, HARDWARE, NTUSER.DAT).\n"
                    "\n"
                    "<~F~older:F::64::>\n"
                    "\n";
                qstring why = form_text(b->last_error());
                char dir[QMAXPATH];
                qstrncpy(dir, rs->registry_dir.c_str(), sizeof(dir));
                if ( ask_form(form, why.c_str(), dir) <= 0 || dir[0] == '\0' )
                    return false;
                save_registry_dir(dir);
                rs->registry_dir = dir;
                return true;
            }

            case ReplayBlock::None:
                break;
        }
        return false;
    }

    // ------------------------------------------------------------ Fork here

    int idaapi ForkHandler::activate(action_activation_ctx_t *)
    {
        TraceManager *m = mgr();
        if ( !backend_forks(m) )
        {
            warning("This recording cannot be forked. Sogen recordings can: the program "
                    "is replayed to the position and runs on in Sogen's emulator.");
            return 1;
        }
        const TraceManager::ForkDraft &d = m->fork_draft();
        if ( d.active && d.at == m->current_position() )
        {
            info("This position is already the fork. Change registers and memory here, "
                 "then use TTD > Record fork.");
            return 1;
        }
        if ( d.active && has_changes(d)
          && ask_yn(ASKBTN_NO, "HIDECANCEL\nThere is a fork at %s with changes.\n\n"
                               "Drop it and fork here instead?",
                    format_position(d.at).c_str()) != ASKBTN_YES )
            return 1;

        m->begin_fork_draft();
        if ( ctx->refresh_position )
            ctx->refresh_position();
        msg("[ida-ttd] Forking at %s. Change registers (the registers window) and memory "
            "(the hex view, or Edit > Patch program) as on a live target, then TTD > "
            "Record fork. The changes stay with this position while you move around.\n",
            format_position(m->fork_draft().at).c_str());
        return 1;
    }

    action_state_t idaapi ForkHandler::update(action_update_ctx_t *)
    {
        return backend_forks(mgr()) ? AST_ENABLE : AST_DISABLE;
    }

    // -------------------------------------------------------- Record fork

    // "2 registers and 3 bytes at 1 address changed", for the dialog.
    static qstring describe_changes(const ForkRequest &req)
    {
        size_t bytes = 0;
        for ( const auto &m : req.memory )
            bytes += m.second.size();
        if ( req.regs.empty() && bytes == 0 )
            return qstring("Nothing changed: the fork runs on as the recording did, from this machine's replay.");
        qstring s;
        if ( !req.regs.empty() )
            s.sprnt("%u register%s", (uint)req.regs.size(), req.regs.size() == 1 ? "" : "s");
        if ( bytes != 0 )
            s.cat_sprnt("%s%u byte%s at %u address%s", s.empty() ? "" : " and ", (uint)bytes,
                        bytes == 1 ? "" : "s", (uint)req.memory.size(), req.memory.size() == 1 ? "" : "es");
        s.append(" changed.");
        return s;
    }

    int idaapi ForkRecordHandler::activate(action_activation_ctx_t *)
    {
        TraceManager *m = mgr();
        if ( !backend_forks(m) || !m->fork_draft().active )
        {
            warning("There is no fork. Use TTD > Fork here first.");
            return 1;
        }
        ForkRequest req;
        m->fill_fork_request(&req);

        static const char form[] =
            "Record the fork\n"
            "\n"
            "\n"
            "Replay the program to position %A, apply the changes, and let it run on,\n"
            "recording into a new trace. This recording is not touched.\n"
            "%A\n"
            "\n"
            "<~N~ew trace:f:1:64::>\n"
            "<~I~nstructions to record, 0 for no limit:D::18::>\n"
            "\n";
        qstring where   = form_text(format_position(req.at));
        qstring changes = form_text(describe_changes(req));
        char path[QMAXPATH];
        qstrncpy(path, default_fork_path(m, req.at).c_str(), sizeof(path));
        static sval_t count = 1000000;
        for ( ;; )
        {
            if ( ask_form(form, where.c_str(), changes.c_str(), path, &count) <= 0 )
                return 1;
            if ( path[0] == '\0' )
            {
                warning("Name the file the new trace goes into.");
                continue;
            }
            if ( qfileexist(path)
              && ask_yn(ASKBTN_NO, "HIDECANCEL\n%s already exists. Replace it?", path) != ASKBTN_YES )
                continue;
            break;
        }

        req.path             = path;
        req.max_instructions = count > 0 ? (uint64_t)count : 0;
        req.note.sprnt("forked at %s", format_position(req.at).c_str());
        for ( const auto &[idx, v] : req.regs )
            req.note.cat_sprnt("; reg %d = 0x%llX", idx, (unsigned long long)v);
        for ( const auto &[ea, bytes] : req.memory )
            req.note.cat_sprnt("; %u byte(s) at 0x%llX", (uint)bytes.size(), (unsigned long long)ea);

        ReplaySettings rs = initial_replay_settings(m);
        ForkResult r;
        for ( ;; )
        {
            req.registry_dir = rs.registry_dir;
            req.allow_host   = rs.allow_host;
            r = run_fork(m, req);
            if ( r.ok || r.cancelled || !ask_replay_needs(m, &rs) )
                break;
        }
        if ( !r.ok )
        {
            if ( r.cancelled )
                msg("[ida-ttd] fork cancelled.\n");
            else if ( m->backend()->last_replay_block() == ReplayBlock::None )
                warning("The fork failed: %s", r.error.c_str());
            else
                msg("[ida-ttd] fork not recorded: %s.\n", r.error.c_str());
            return 1;
        }
        msg("[ida-ttd] forked at %s: %llu instruction(s) recorded into %s%s.\n",
            format_position(req.at).c_str(), (unsigned long long)r.instructions, path,
            r.cancelled ? " (stopped early; what ran is a complete trace)" : "");
        if ( ask_yn(ASKBTN_YES, "HIDECANCEL\nRecorded %llu instruction(s) into\n%s\n\n"
                                "Open it in a new IDA window?",
                    (unsigned long long)r.instructions, path) == ASKBTN_YES
          && !open_in_new_ida(path) )
            warning("Could not start another IDA. Open %s from IDA's File menu.", path);
        return 1;
    }

    action_state_t idaapi ForkRecordHandler::update(action_update_ctx_t *)
    {
        return backend_forks(mgr()) && mgr()->fork_draft().active ? AST_ENABLE : AST_DISABLE;
    }

    // ------------------------------------------------------- Discard fork

    int idaapi ForkDiscardHandler::activate(action_activation_ctx_t *)
    {
        TraceManager *m = mgr();
        if ( m == nullptr || !m->fork_draft().active )
            return 1;
        bool shown = m->at_fork_draft() && has_changes(m->fork_draft());
        m->discard_fork_draft();
        if ( ctx->refresh_position )
            ctx->refresh_position();
        // The views showed the fork's changes; have IDA read the recording again.
        if ( shown )
        {
            invalidate_dbg_state(DBGINV_REGS);
            invalidate_dbgmem_contents(BADADDR, 0);
            refresh_idaview_anyway();
        }
        msg("[ida-ttd] fork discarded.\n");
        return 1;
    }

    action_state_t idaapi ForkDiscardHandler::update(action_update_ctx_t *)
    {
        return mgr() != nullptr && mgr()->fork_draft().active ? AST_ENABLE : AST_DISABLE;
    }
}
