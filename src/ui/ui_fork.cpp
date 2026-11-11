// Forking the recording: beginning a fork, recording it, and what a replay
// asks the user for.
#include "ui/ui.h"
#include "analysis/fork.h"
#include "core/backend_module.h"
#include "plugin/settings.h"
#include "common/trace_link.h"

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

    // The recording this IDA may replay against the host, so consent is asked
    // once per recording rather than per replay.
    static qstring g_hostConsent;

    // For the Registry hives dialog: what a replay needs, and what each
    // searched folder holds.
    static qstring replay_needs_text(TraceManager *mgr)
    {
        ITraceBackend *b = mgr->backend();
        ReplayEnv env;
        bool known = b->replay_env(&env);
        qstring s;
        if ( known )
        {
            if ( env.host )
                s = "This recording was made against its machine's own files";
            else
                s.sprnt("This recording was made in the emulation root %s", env.emulation_root.c_str());
            if ( !env.windows_version.empty() )
                s.cat_sprnt(", on Windows %s", env.windows_version.c_str());
            s.append(".\n");
            if ( env.system_dlls == ITTD_DLLS_DIFFER )
                s.append(env.host
                       ? "This machine's system DLLs (ntdll, kernel32, kernelbase) are not the ones it\n"
                         "ran with, so a replay here stops early, whatever the hives: replay it on the\n"
                         "machine it was recorded on.\n"
                       : "The emulation root's system DLLs are not the ones it ran with, so a replay\n"
                         "stops early, whatever the hives.\n");
        }
        if ( known && env.registry_carried )
            s.append("It carries what it read of its registry hives, so a replay needs no hive\n"
                     "files. This one reads further than the recording did, so it needs the very\n"
                     "hive files Sogen was given when it recorded.\n");
        else
            s.append("A replay needs the very hive files Sogen was given when it recorded\n"
                     "(SYSTEM, SOFTWARE, SAM, SECURITY, HARDWARE, NTUSER.DAT). A new copy of the\n"
                     "same machine's registry is not the same: the registry changes all the time.\n");
        if ( known && !env.host )
            s.append("A replay in an emulation root loads the root's registry folder, so choose\n"
                     "the root itself where it is elsewhere on this machine.\n");
        else
            s.append("Keep them in a registry folder beside the recording to have them found.\n");
        s.append("\nLooked in:");
        for ( const qstring &dir : registry_candidates(mgr) )
        {
            const char *what = "no hives";
            switch ( b->check_registry(dir.c_str(), nullptr) )
            {
                case HiveCheck::Match:      what = "the recording's hives"; break;
                case HiveCheck::Unverified: what = "hives (the recording does not say which it used)"; break;
                case HiveCheck::Mismatch:   what = "other hives than the recording's"; break;
                case HiveCheck::Missing:    break;
            }
            s.cat_sprnt("\n  %s: %s", dir.c_str(), what);
        }
        return s;
    }

    ReplaySettings initial_replay_settings(TraceManager *mgr)
    {
        ReplaySettings rs;
        rs.registry_dir = find_registry_dir(mgr);
        rs.emulation_root = chosen_emulation_root(mgr);
        rs.allow_host   = mgr != nullptr && !g_hostConsent.empty() && g_hostConsent == mgr->trace_path();
        rs.rec          = recording_options();
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
                            "Replaying it runs the program again, and its file operations\n"
                            "happen again on this machine: whatever it created, renamed or\n"
                            "deleted, it does again. (The network stays offline, unless a fork\n"
                            "is given network access, and then only from its position on.)\n\n"
                            "Replay it anyway? Only for programs you trust.") != ASKBTN_YES )
                    return false;
                g_hostConsent   = mgr->trace_path();
                rs->allow_host  = true;
                return true;

            case ReplayBlock::Registry:
            case ReplayBlock::RegistryMismatch:
            {
                // A replay in an emulation root loads only <root>\registry,
                // so there the question is where the root is.
                ReplayEnv env;
                const bool in_root = b->replay_env(&env) && !env.host;
                static const char form[] =
                    "Registry hives\n"
                    "\n"
                    "\n"
                    "%A\n"
                    "\n"
                    "%A\n"
                    "\n"
                    "<~F~older:F::64::>\n"
                    "<~R~eplay with these hives even if they are not the recording's:C>>\n"
                    "\n";
                static const char root_form[] =
                    "Emulation root\n"
                    "\n"
                    "\n"
                    "%A\n"
                    "\n"
                    "%A\n"
                    "\n"
                    "<~E~mulation root:F::64::>\n"
                    "<~R~eplay with its hives even if they are not the recording's:C>>\n"
                    "\n";
                qstring why = form_text(b->last_error());
                qstring about = form_text(replay_needs_text(mgr));
                char dir[QMAXPATH];
                qstrncpy(dir, in_root ? (rs->emulation_root.empty() ? env.emulation_root.c_str()
                                                                     : rs->emulation_root.c_str())
                                      : rs->registry_dir.c_str(), sizeof(dir));
                ushort anyway = 0;
                if ( ask_form(in_root ? root_form : form, why.c_str(), about.c_str(), dir, &anyway) <= 0
                  || dir[0] == '\0' )
                    return false;
                if ( in_root )
                {
                    choose_emulation_root(mgr, dir);
                    rs->emulation_root = dir;
                }
                else
                {
                    save_registry_dir(dir);
                    rs->registry_dir = dir;
                }
                rs->any_registry = anyway != 0;
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

        bool shown = m->at_fork_draft() && has_changes(d);
        m->begin_fork_draft();
        fork_draft_changed(ctx, shown);
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
            "\n"
            "<~G~ive the program network access from this position on:C>>\n"
            "(The replay up to the position stays offline either way.)\n"
            "\n";
        qstring where   = form_text(format_position(req.at));
        qstring changes = form_text(describe_changes(req));
        char path[QMAXPATH];
        qstrncpy(path, default_fork_path(m, req.at).c_str(), sizeof(path));
        // The fork_instructions setting at first, then the last answer this
        // session.
        static sval_t count = (sval_t)qmin(settings().fork_instructions, (uint64)INT64_MAX);
        // The sogen_network setting each time: network access is not
        // something to carry over unnoticed from an earlier fork.
        ushort network = settings().sogen_network ? 1 : 0;
        for ( ;; )
        {
            if ( ask_form(form, where.c_str(), changes.c_str(), path, &count, &network) <= 0 )
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
        req.note.cat_sprnt("; %s", describe_fork_changes(req).c_str());

        ReplaySettings rs = initial_replay_settings(m);
        rs.rec.network = network != 0;
        ForkResult r;
        for ( ;; )
        {
            req.registry_dir = rs.registry_dir;
            req.allow_host   = rs.allow_host;
            req.any_registry = rs.any_registry;
            req.emulation_root = rs.emulation_root;
            req.rec          = rs.rec;
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
        refresh_fork_manager();
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

    // -------------------------------------------- Record a program with Sogen

    static bool has_hives(const qstring &dir)
    {
        qstring system = dir;
        system.append("\\SYSTEM");
        return !dir.empty() && qfileexist(system.c_str());
    }

    // Why 'root' cannot be an emulation root, or empty when it can: it must
    // hold filesys\ and registry\ (with hives). Picking one of those two
    // instead of the root is the likely mistake, so the parent is suggested.
    static qstring emulation_root_problem(const char *root)
    {
        qstring dir = root;
        while ( !dir.empty() && (dir.last() == '\\' || dir.last() == '/') )
            dir.remove_last();
        qstring fs = dir + "\\filesys";
        if ( !qisdir(fs.c_str()) )
        {
            qstring s;
            s.sprnt("%s is not an emulation root. An emulation root is the folder that holds "
                    "filesys (the program's drives) and registry (its hives).", dir.c_str());
            ssize_t slash = dir.rfind('\\');
            if ( slash > 0 )
            {
                qstring parent = dir.substr(0, slash);
                if ( qisdir((parent + "\\filesys").c_str()) )
                    s.cat_sprnt("\n\nDid you mean %s?", parent.c_str());
            }
            return s;
        }
        if ( !has_hives(dir + "\\registry") )
        {
            qstring s;
            s.sprnt("The emulation root %s has no registry hives in its registry folder "
                    "(SYSTEM, SOFTWARE, NTUSER.DAT, ...), which Sogen needs to run the program.", dir.c_str());
            return s;
        }
        return qstring();
    }

    // The executable this database was made from, if it is one (a
    // recording's database has the recording as its input file).
    static qstring database_program()
    {
        char path[QMAXPATH] = {};
        if ( get_input_file_path(path, sizeof(path)) <= 0 )
            return qstring();
        const char *ext = get_file_ext(path);
        if ( ext == nullptr || (stricmp(ext, "exe") != 0 && stricmp(ext, "dll") != 0) || !qfileexist(path) )
            return qstring();
        return qstring(path);
    }

    // Whether IDA itself runs elevated. Sogen's "elevated" only changes the
    // token the program sees; what it does to this machine's files is done
    // with IDA's rights.
    static bool ida_is_elevated()
    {
        HANDLE tok = nullptr;
        if ( !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok) )
            return false;
        TOKEN_ELEVATION el{};
        DWORD n = 0;
        const bool ok = GetTokenInformation(tok, TokenElevation, &el, sizeof(el), &n) != 0;
        CloseHandle(tok);
        return ok && el.TokenIsElevated != 0;
    }

    // The base name of a path, without case, for comparing programs.
    static qstring base_name_lower(const char *path)
    {
        const char *slash = strrchr(path, '\\');
        const char *fwd = strrchr(path, '/');
        if ( fwd != nullptr && (slash == nullptr || fwd > slash) )
            slash = fwd;
        qstring s = slash != nullptr ? slash + 1 : path;
        for ( size_t i = 0; i < s.length(); i++ )
            s[i] = (char)qtolower(s[i]);
        return s;
    }

    // Whether this database is of the program just recorded, so the new
    // recording can be replayed here: its input file is that executable, or
    // it was made from a recording of it.
    static bool database_is_of(const char *program)
    {
        const qstring want = base_name_lower(program);
        TraceLink link;
        if ( trace_link_read(&link) && !link.module_name.empty() )
            return base_name_lower(link.module_name.c_str()) == want;
        char path[QMAXPATH] = {};
        return get_input_file_path(path, sizeof(path)) > 0 && base_name_lower(path) == want;
    }

    int idaapi RecordProgramHandler::activate(action_activation_ctx_t *)
    {
        if ( find_recorder() == nullptr )
        {
            warning("No installed backend can record programs (the Sogen backend can).");
            return 1;
        }
        // Short labels, the details in the tooltips. IDA places a field
        // right after its label's characters, so the labels are padded with
        // spaces to one length (17, the longest) to line the fields up.
        static const char form[] =
            "Record a program with Sogen\n"
            "\n"
            "<#The program to run from its start#~P~rogram          :f:0:60::>\n"
            "<#Passed to the program as typed#~A~rguments        :q::60::>\n"
            "<#Empty for the program's own folder#~W~orking folder   :F::60::>\n"
            "<#The new Sogen recording#~O~utput file      :f:1:60::>\n"
            "<#0 records until the program exits#~I~nstruction limit:D::16::>\n"
            "\n"
            "<#The folder holding filesys and registry. Empty runs the program against this machine's own files#~E~mulation root   :F::60::>\n"
            "<#The guest folder a program from outside the root is copied to#~C~opy into root at:q::60::>\n"
            "<#The hives to run against when there is no emulation root#~R~egistry hives   :F::60::>\n"
            "\n"
            "<#Let the program reach the real network#~N~etwork access:C>\n"
            "<#The program's token says administrator (high integrity). Its file and registry operations still have only IDA's own rights#Run as a~d~ministrator:C>>\n"
            "\n";
        // The last answers this session. The program starts as the database's
        // own executable, the hives as the first folder that has some, and
        // the copy goes to a folder of its own, so none of the root's files
        // is replaced unasked.
        static qstring s_program, s_args, s_cwd, s_root, s_hives, s_place = "C:\\ida-ttd";
        static sval_t s_count = 0;
        if ( s_program.empty() )
            s_program = database_program();
        if ( s_hives.empty() )
            for ( const qstring &dir : registry_candidates(nullptr) )
                if ( has_hives(dir) )
                {
                    s_hives = dir;
                    break;
                }
        char program[QMAXPATH], cwd[QMAXPATH], out[QMAXPATH], root[QMAXPATH], hives[QMAXPATH];
        qstrncpy(program, s_program.c_str(), sizeof(program));
        qstrncpy(cwd, s_cwd.c_str(), sizeof(cwd));
        qstrncpy(root, s_root.c_str(), sizeof(root));
        qstrncpy(hives, s_hives.c_str(), sizeof(hives));
        out[0] = '\0';
        if ( program[0] != '\0' )
            set_file_ext(out, sizeof(out), qstring(program).c_str(), "sogttd");
        qstring args = s_args;
        qstring place = s_place;
        qstring run_program;        // the program as recorded: a copy in the root, or itself
        sval_t count = s_count;
        const RecordOptions defaults = recording_options();
        ushort checks = (defaults.network ? 1 : 0) | (defaults.elevated ? 2 : 0);
        for ( ;; )
        {
            if ( ask_form(form, program, &args, cwd, out, &count, root, &place, hives, &checks) <= 0 )
                return 1;
            place.trim2();
            if ( program[0] == '\0' || !qfileexist(program) )
            {
                warning("Choose the program to record.");
                continue;
            }
            if ( out[0] == '\0' )
            {
                warning("Choose the output file.");
                continue;
            }
            // The replay reads it as it goes: writing over it would change
            // the recording under the session. (The backend refuses any file
            // that is open, in another IDA too; this says it before asking
            // anything else.)
            if ( ctx != nullptr && ctx->mgr != nullptr && ctx->mgr->is_active()
              && stricmp(ctx->mgr->trace_path().c_str(), out) == 0 )
            {
                warning("That recording is open in this window. Choose another output file.");
                continue;
            }
            if ( root[0] != '\0' )
            {
                const qstring problem = emulation_root_problem(root);
                if ( !problem.empty() )
                {
                    warning("%s", problem.c_str());
                    continue;
                }
                if ( !visible_in_emulation_root(root, program) && place.empty() )
                {
                    warning("The program is outside the emulation root. Name a folder to copy it to.");
                    continue;
                }
                if ( cwd[0] != '\0' && !visible_in_emulation_root(root, cwd) )
                {
                    warning("The working folder must be inside the emulation root.");
                    continue;
                }
            }
            else if ( !has_hives(hives) )
            {
                warning("Choose a folder of registry hives (SYSTEM, SOFTWARE, NTUSER.DAT, ...).");
                continue;
            }
            if ( qfileexist(out)
              && ask_yn(ASKBTN_NO, "HIDECANCEL\n%s already exists. Replace it?", out) != ASKBTN_YES )
                continue;
            // Last, once everything else holds: the copy into the root.
            run_program = program;
            if ( root[0] != '\0' && !visible_in_emulation_root(root, program) )
            {
                qstring placed, err;
                PlaceResult pr = place_in_emulation_root(root, program, place.c_str(), false, &placed, &err);
                if ( pr == PlaceResult::Differs )
                {
                    if ( ask_yn(ASKBTN_NO, "HIDECANCEL\nThe emulation root already has a different\n%s\n\n"
                                           "Replace it?", placed.c_str()) != ASKBTN_YES )
                        continue;
                    pr = place_in_emulation_root(root, program, place.c_str(), true, &placed, &err);
                }
                if ( pr == PlaceResult::Failed )
                {
                    warning("Could not copy the program into the emulation root: %s", err.c_str());
                    continue;
                }
                if ( pr == PlaceResult::Placed )
                    msg("[ida-ttd] copied %s into the emulation root: %s\n", program, placed.c_str());
                run_program = placed;
            }
            break;
        }
        s_program = program;
        s_args    = args;
        s_cwd     = cwd;
        s_root    = root;
        s_hives   = hives;
        s_place   = place;
        s_count   = count;
        if ( root[0] == '\0' )
            save_registry_dir(hives);

        RecordRequest req;
        req.application      = run_program;
        req.arguments        = args;
        req.working_dir      = cwd;
        req.path             = out;
        req.max_instructions = count > 0 ? (uint64_t)count : 0;
        req.emulation_root   = root;
        req.registry_dir     = root[0] == '\0' ? qstring(hives) : qstring();
        req.rec              = defaults;
        req.rec.network      = (checks & 1) != 0;
        req.rec.elevated     = (checks & 2) != 0;
        // Each time: consent for one program is not consent for the next.
        if ( root[0] == '\0' )
        {
            if ( ask_yn(ASKBTN_NO,
                        "HIDECANCEL\n"
                        "Without an emulation root the program runs against this machine's\n"
                        "own files: whatever it creates, changes or deletes happens for real%s.\n\n"
                        "Record it? Only for programs you trust.",
                        req.rec.network ? ", and it reaches the network" : "") != ASKBTN_YES )
                return 1;
            req.allow_host = true;
        }

        if ( req.rec.elevated && !ida_is_elevated() )
            msg("[ida-ttd] the program's token says administrator, but IDA is not running elevated: "
                "operations needing real administrator rights on this machine's files still fail.\n");

        ForkResult r = run_record(req);
        if ( !r.ok )
        {
            if ( r.cancelled )
                msg("[ida-ttd] recording cancelled.\n");
            else
                warning("The program was not recorded: %s", r.error.c_str());
            return 1;
        }
        msg("[ida-ttd] recorded %s: %llu instruction(s) into %s%s.\n", run_program.c_str(),
            (unsigned long long)r.instructions, out,
            r.cancelled ? " (stopped early; what ran is a complete recording)" : "");

        // Replaying it here suits only a database of the same program: this
        // window's analysis then goes on over the new recording.
        const bool here_ok = ctx != nullptr && ctx->switch_trace && database_is_of(program);
        bool here = false, elsewhere = false;
        if ( here_ok )
        {
            const int choice = ask_buttons("~T~his window", "~N~ew window", "~D~on't open", ASKBTN_YES,
                                           "Recorded %llu instruction(s) into\n%s\n\nOpen it?",
                                           (unsigned long long)r.instructions, out);
            here = choice == ASKBTN_YES;
            elsewhere = choice == ASKBTN_NO;
        }
        else
        {
            elsewhere = ask_yn(ASKBTN_YES, "HIDECANCEL\nRecorded %llu instruction(s) into\n%s\n\n"
                                           "Open it in a new IDA window?",
                               (unsigned long long)r.instructions, out) == ASKBTN_YES;
        }
        // Here: the replay switches to it in this database, as the Fork
        // manager's switch does (any running session ends first).
        if ( here )
            ctx->switch_trace(qstring(out));
        else if ( elsewhere && !open_in_new_ida(out) )
            warning("Could not start another IDA. Open %s from IDA's File menu.", out);
        return 1;
    }

    // ------------------------------------------------------- Discard fork

    int idaapi ForkDiscardHandler::activate(action_activation_ctx_t *)
    {
        TraceManager *m = mgr();
        if ( m == nullptr || !m->fork_draft().active )
            return 1;
        bool shown = m->at_fork_draft() && has_changes(m->fork_draft());
        m->discard_fork_draft();
        fork_draft_changed(ctx, shown);
        msg("[ida-ttd] fork discarded.\n");
        return 1;
    }

    void fork_draft_changed(const ActionContext *c, bool views_showed_changes)
    {
        if ( c != nullptr && c->refresh_position )
            c->refresh_position();
        // The views showed the fork's changes: have IDA reread the recording.
        if ( views_showed_changes )
        {
            invalidate_dbg_state(DBGINV_REGS);
            invalidate_dbgmem_contents(BADADDR, 0);
            refresh_idaview_anyway();
        }
    }

    action_state_t idaapi ForkDiscardHandler::update(action_update_ctx_t *)
    {
        return mgr() != nullptr && mgr()->fork_draft().active ? AST_ENABLE : AST_DISABLE;
    }
}
