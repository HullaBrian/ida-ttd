// The an.* script commands on forks and Sogen recordings: forking,
// the fork being prepared, the fork graph, the registry hives a replay
// uses, and recording a program.
#include "plugin/script_internal.h"
#include "plugin/settings.h"
#include "analysis/fork.h"
#include "analysis/fork_registry.h"
#include "analysis/replay_scans.h"

namespace idattd
{
    // an.fork PATH N [registry=DIR] [strict] [REG=VALUE ...] [mem:ADDR=HEXBYTES ...]
    static void cmd_an_fork(const Args &a, JObj &out)
    {
        need_session();
        ForkRequest req;
        req.rec              = recording_options();
        req.at               = mgr().current_position();
        req.path             = a.at(0);
        req.max_instructions = a.u64(1);
        qstring regs, mem;
        for ( size_t i = 2; i < a.count(); i++ )
        {
            const qstring &t = a.at(i);
            if ( replay_option(t, &req) )
                continue;
            if ( t.starts_with("mem:") )
                mem.cat_sprnt("%s;", t.c_str() + 4);
            else
                regs.cat_sprnt("%s ", t.c_str());
        }
        qstring err;
        if ( !parse_fork_registers(regs.c_str(), &req.regs, &err)
          || !parse_fork_memory(mem.c_str(), &req.memory, &err) )
            fail("%s", err.c_str());
        req.note = "ida-ttd script";
        ForkResult r = run_fork(&mgr(), req);
        if ( !r.ok )
            fail("the fork failed: %s", r.error.c_str());
        out.boolean("cancelled", r.cancelled).num("instructions", (int64_t)r.instructions)
           .str("at", format_position(req.at)).str("path", req.path);
    }

    static void draft_json(JObj &out)
    {
        const TraceManager::ForkDraft &d = mgr().fork_draft();
        out.boolean("forking", d.active);
        if ( !d.active )
            return;
        JArr regs, mem;
        ForkRequest req;
        mgr().fill_fork_request(&req);
        for ( const auto &[idx, v] : req.regs )
        {
            JObj o;
            o.num("reg", idx).hex("value", (uint64)v);
            regs.add(o.done());
        }
        for ( const auto &[ea, bytes] : req.memory )
        {
            JObj o;
            qstring hex;
            for ( uchar b : bytes )
                hex.cat_sprnt("%02X", b);
            o.hex("address", ea).str("bytes", hex);
            mem.add(o.done());
        }
        out.str("at", format_position(d.at)).boolean("here", mgr().at_fork_draft())
           .raw("regs", regs.done()).raw("memory", mem.done());
    }

    // an.registry: where the recording's hives are looked for, what each
    // place holds, and the folder a replay would use.
    static void cmd_an_registry(const Args &, JObj &out)
    {
        need_session();
        ITraceBackend *b = mgr().backend();
        ReplayEnv env;
        if ( b->replay_env(&env) )
        {
            out.boolean("host", env.host).boolean("registry_known", env.registry_known)
               .boolean("registry_carried", env.registry_carried)
               .str("chosen_root", chosen_emulation_root(&mgr()))
               .str("emulation_root", env.emulation_root).str("registry_hint", env.registry_hint)
               .str("windows_version", env.windows_version)
               .str("system_dlls", env.system_dlls == ITTD_DLLS_SAME   ? "same"
                                 : env.system_dlls == ITTD_DLLS_DIFFER ? "differ" : "unknown");
        }
        JArr arr;
        for ( const qstring &dir : registry_candidates(&mgr()) )
        {
            qstring why;
            HiveCheck c = b->check_registry(dir.c_str(), &why);
            JObj o;
            o.str("dir", dir)
             .str("holds", c == HiveCheck::Match      ? "match"
                         : c == HiveCheck::Unverified ? "unverified"
                         : c == HiveCheck::Mismatch   ? "mismatch" : "none");
            if ( c == HiveCheck::Mismatch )
                o.str("why", why);
            arr.add(o.done());
        }
        out.raw("candidates", arr.done()).str("chosen", find_registry_dir(&mgr()));
    }

    // an.forks: the forks this database knows of (the Fork manager's graph).
    static void cmd_an_forks(const Args &, JObj &out)
    {
        JArr arr;
        bool ok = true;
        std::vector<ForkRecord> v = load_fork_records(&ok);
        if ( !ok )
            fail("the fork list in this database could not be read");
        for ( const ForkRecord &f : v )
        {
            JObj o;
            o.str("path", f.path).str("parent", f.parent).str("at", f.at).str("changes", f.changes)
             .num("instructions", (int64_t)f.instructions);
            arr.add(o.done());
        }
        out.num("count", (int64_t)v.size()).raw("forks", arr.done());
    }

    // an.forget PATH: take a fork out of the graph.
    static void cmd_an_forget(const Args &a, JObj &out)
    {
        remove_fork_record(a.at(0).c_str());
        out.num("count", (int64_t)load_fork_records(nullptr).size());
    }

    // Whether the views show a fork's changes right now, which is what
    // fork_draft_changed() needs to know to repaint them.
    static bool draft_shown()
    {
        const TraceManager::ForkDraft &d = mgr().fork_draft();
        return mgr().at_fork_draft() && (!d.regs.empty() || !d.bytes.empty());
    }

    // an.forkhere: make the current position a fork (TTD > Fork here); change
    // it through IDA's own debugger calls.
    static void cmd_an_forkhere(const Args &, JObj &out)
    {
        need_session();
        bool shown = draft_shown();
        mgr().begin_fork_draft();
        fork_draft_changed(g_plugin->action_context(), shown);
        draft_json(out);
    }

    // an.forkdraft: the fork being prepared, with its changes.
    static void cmd_an_forkdraft(const Args &, JObj &out)
    {
        need_session();
        draft_json(out);
    }

    static void cmd_an_forkdiscard(const Args &, JObj &out)
    {
        need_session();
        bool shown = draft_shown();
        mgr().discard_fork_draft();
        fork_draft_changed(g_plugin->action_context(), shown);
        draft_json(out);
    }

    // an.forkrecord PATH N [registry=DIR] [strict] [host]: record the fork
    // being prepared (TTD > Record fork).
    static void cmd_an_forkrecord(const Args &a, JObj &out)
    {
        need_session();
        if ( !mgr().fork_draft().active )
            fail("there is no fork; an.forkhere first");
        ForkRequest req;
        mgr().fill_fork_request(&req);
        req.rec              = recording_options();
        req.path             = a.at(0);
        req.max_instructions = a.u64(1);
        for ( size_t i = 2; i < a.count(); i++ )
        {
            const qstring &t = a.at(i);
            if ( !replay_option(t, &req) )
                fail("'%s' is not %s", t.c_str(), REPLAY_OPTIONS);
        }
        req.note = "ida-ttd script";
        ForkResult r = run_fork(&mgr(), req);
        if ( !r.ok )
        {
            need_session();     // the session may have ended during the fork
            ReplayBlock b = mgr().backend()->last_replay_block();
            fail("the fork failed%s: %s",
                 b == ReplayBlock::HostConsent ? " (needs host)"
                 : b == ReplayBlock::Registry ? " (needs registry=DIR)"
                 : b == ReplayBlock::RegistryMismatch ? " (wrong hives: registry=DIR or anyregistry)" : "",
                 r.error.c_str());
        }
        out.boolean("cancelled", r.cancelled).num("instructions", (int64_t)r.instructions)
           .str("at", format_position(req.at)).str("path", req.path)
           .num("regs", (int64_t)req.regs.size()).num("writes", (int64_t)req.memory.size());
    }

    // an.record PROGRAM PATH [N] [args="..."] [cwd=DIR] [registry=DIR]
    // [root=DIR] [host] [start=now|1970|DATE] [net] [ckpt=N] [access=rwx]
    // [elevated] [log]: run PROGRAM from its start in Sogen's emulator and
    // record N instructions (hex; none or 0: until it exits) into PATH (TTD >
    // Backends > Record a program with Sogen). Without root=, 'host' is the
    // consent to run it against this machine's files; the hives are
    // registry=, else the first known folder that holds some. start= is the
    // date it starts at (default: the sogen_start_now setting).
    static void cmd_an_record(const Args &a, JObj &out)
    {
        RecordRequest req;
        req.rec         = recording_options();
        req.application = a.at(0);
        req.path        = a.at(1);
        qstring place;
        qstring start = settings().sogen_start_now ? "now" : "1970";
        bool replace = false;
        for ( size_t i = 2; i < a.count(); i++ )
        {
            const qstring &t = a.at(i);
            uint64_t n = 0;
            if ( record_option(t, &req.rec) )
                continue;
            if ( t.starts_with("place=") )
                place = t.substr(6);
            else if ( t == "replace" )
                replace = true;
            else if ( t.starts_with("args=") )
                req.arguments = t.substr(5);
            else if ( t.starts_with("cwd=") )
                req.working_dir = t.substr(4);
            else if ( t.starts_with("registry=") )
                req.registry_dir = t.substr(9);
            else if ( t.starts_with("root=") )
                req.emulation_root = t.substr(5);
            else if ( t == "host" )
                req.allow_host = true;
            else if ( t.starts_with("start=") )
                start = t.substr(6);
            else if ( i == 2 && parse_u64(t, &n) )
                req.max_instructions = n;
            else
                fail("'%s' is not N, args=, cwd=, registry=, root=, place=, replace, host, start=, net, ckpt=N, "
                     "access=rwx, elevated or log", t.c_str());
        }
        // start=now, start=1970 or start=YYYY-MM-DDTHH:MM:SS (UTC): the
        // system time the program starts at.
        if ( start == "now" )
        {
            req.start_time = (int64_t)time(nullptr);
        }
        else if ( start != "1970" )
        {
            int y = 0, mo = 0, d = 0, h = 0, mi = 0, s = 0;
            char tail = '\0';
            const int got = sscanf(start.c_str(), "%4d-%2d-%2dT%2d:%2d:%2d%c", &y, &mo, &d, &h, &mi, &s, &tail);
            struct tm tm = {};
            tm.tm_year = y - 1900;
            tm.tm_mon  = mo - 1;
            tm.tm_mday = d;
            tm.tm_hour = h;
            tm.tm_min  = mi;
            tm.tm_sec  = s;
            const bool shape = got == 6 || (got == 7 && tail == 'Z');
            const time_t when = shape && y >= 1970 && mo >= 1 && mo <= 12 && d >= 1 && d <= 31
                             && h <= 23 && mi <= 59 && s <= 59 ? _mkgmtime(&tm) : (time_t)-1;
            // _mkgmtime normalises 31 February into March: refuse that.
            if ( when == (time_t)-1 || tm.tm_mday != d )
                fail("'start=%s': give now, 1970 or a UTC time as YYYY-MM-DDTHH:MM:SS", start.c_str());
            req.start_time = (int64_t)when;
        }
        // place=DIR: a program outside the emulation root is copied into it
        // first (the guest sees only the root).
        qstring placed_note;
        if ( !place.empty() && !req.emulation_root.empty()
          && !visible_in_emulation_root(req.emulation_root.c_str(), req.application.c_str()) )
        {
            qstring placed, err;
            PlaceResult pr = place_in_emulation_root(req.emulation_root.c_str(), req.application.c_str(),
                                                     place.c_str(), replace, &placed, &err);
            if ( pr == PlaceResult::Differs )
                fail("the emulation root already has a different %s; add 'replace' to overwrite it", placed.c_str());
            if ( pr == PlaceResult::Failed )
                fail("%s", err.c_str());
            placed_note = pr == PlaceResult::Placed ? "copied" : "already there";
            req.application = placed;
        }
        if ( req.emulation_root.empty() && req.registry_dir.empty() )
        {
            for ( const qstring &dir : registry_candidates(nullptr) )
            {
                qstring system = dir;
                system.append("\\SYSTEM");
                if ( qfileexist(system.c_str()) )
                {
                    req.registry_dir = dir;
                    break;
                }
            }
        }
        ForkResult r = run_record(req);
        if ( !r.ok )
            fail("the program was not recorded%s: %s",
                 r.block == ReplayBlock::HostConsent ? " (needs host or root=DIR)"
                 : r.block == ReplayBlock::Registry ? " (needs registry=DIR)" : "",
                 r.error.c_str());
        out.boolean("cancelled", r.cancelled).num("instructions", (int64_t)r.instructions)
           .str("path", req.path).boolean("network", req.rec.network)
           .str("program", req.application).str("placed", placed_note);
    }

    // ------------------------------------------------------------------ commands

    static const Command FORK_COMMANDS[] = {
        { "an.registry",    cmd_an_registry,    "where the recording's registry hives are looked for, and what each place holds" },
        { "an.forks",       cmd_an_forks,       "the forks recorded in this database" },
        { "an.forget",      cmd_an_forget,      "PATH take a fork out of the fork graph" },
        { "an.forkhere",    cmd_an_forkhere,    "make this position a fork; change it with IDA's debugger calls" },
        { "an.forkdraft",   cmd_an_forkdraft,   "the fork being prepared and its changes" },
        { "an.forkdiscard", cmd_an_forkdiscard, "drop the fork being prepared" },
        { "an.forkrecord",  cmd_an_forkrecord,  "PATH N [registry=DIR] [root=DIR] [strict] [host] [anyregistry] [net] [ckpt=N] [access=rwx] [log] record the fork being prepared" },
        { "an.fork",        cmd_an_fork,        "PATH N [registry=DIR] [root=DIR] [strict] [host] [anyregistry] [net] [ckpt=N] [access=rwx] [log] [REG=V ...] [mem:EA=HEX ...] fork here" },
        { "an.record",      cmd_an_record,      "PROGRAM PATH [N] [args=\"...\"] [cwd=DIR] [registry=DIR] [root=DIR] [place=DIR] [replace] [host] [start=now|1970|DATE] [net] [ckpt=N] [access=rwx] [elevated] [log] record a program with Sogen" },
    };

    std::span<const Command> fork_commands() { return FORK_COMMANDS; }
}
