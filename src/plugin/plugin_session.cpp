// Starting a replay of this database's recording, offering it when the
// database opens, switching to another recording (a fork), and source
// debugging switched off for a session.
#include "plugin/plugin_internal.h"
#include "analysis/fork_registry.h"
#include "common/trace_link.h"
#include "plugin/settings.h"

namespace idattd
{
    // How often to re-check whether the initial auto-analysis has drained.
    static const int ATTACH_POLL_MS = 250;

    // Start replaying the recording this database was created from. No
    // prompting: this is the menu action's body, so the user already asked.
    bool Plugin::start_trace_session(qstring *error)
    {
        TraceLink link;
        if ( !trace_link_read(&link) )
        {
            trace_link_mark_start(false);
            if ( error != nullptr )
                *error = "this database was not created from a TTD trace, so there is nothing to replay";
            else
                warning("This database was not created from a TTD trace, so there is "
                        "nothing to replay.\n\nUse Debugger > Switch debugger to attach "
                        "a trace to it instead.");
            return false;
        }
        if ( get_process_state() != DSTATE_NOTASK )
        {
            trace_link_mark_start(false);
            if ( error != nullptr )
                *error = "a debugging session is already running";
            else
                warning("A debugging session is already running.");
            return false;
        }

        // The recording may have moved since the database was made: ask
        // where it went and remember the answer. A script is told instead.
        if ( !qfileexist(link.trace_path.c_str()) && error != nullptr )
        {
            trace_link_mark_start(false);
            error->sprnt("the recording is not at %s; start it once from the TTD menu to locate it, "
                         "or use 'switch PATH'", link.trace_path.c_str());
            return false;
        }
        if ( !qfileexist(link.trace_path.c_str()) )
        {
            qstring prompt;
            prompt.sprnt("Locate the TTD trace for this database (was %s)",
                         link.trace_path.c_str());
            const char *chosen = ask_file(false, link.trace_path.c_str(), "%s", prompt.c_str());
            if ( chosen == nullptr )
            {
                trace_link_mark_start(false);   // the user declined, nothing broke
                return false;
            }
            link.trace_path = chosen;
            trace_link_set_path(chosen);
        }

        if ( !select_trace_debugger(link.trace_path.c_str(), error != nullptr) )
        {
            trace_link_mark_start(false);       // reported already, nothing broke
            if ( error != nullptr )
                *error = "IDA would not select the TTD trace replayer as the debugger (see the output window)";
            return false;
        }
        if ( start_process(link.trace_path.c_str(), "", "") != 1 )
        {
            if ( error != nullptr )
                *error = "IDA did not start the replay";
            return false;
        }
        return true;
    }

    bool Plugin::select_trace_debugger(const char *trace_path, bool quiet)
    {
        // Set the trace path first, whether or not the switch works: it fills
        // Debugger > Process options. IDA's Application browser filters on
        // "*.exe" (no SDK field changes that), so without it the user hunts
        // for the trace behind the wrong filter.
        if ( trace_path != nullptr && trace_path[0] != '\0' )
            set_process_options(trace_path, "", nullptr, "", "", "", -1);

        if ( ::dbg != &m_debugger )
        {
            // What load_debugger() matches on is undocumented, so try each
            // candidate and report which one worked (see plugin_module_name).
            const qstring self = plugin_module_name();
            qstring selfdll = self;
            if ( !selfdll.empty() )
                selfdll.append(".dll");
            const char *candidates[] =
            {
                self.c_str(),                   // plugin file name, e.g. "ida-ttd"
                selfdll.c_str(),                // ...with the extension
                m_debugger.name,                // debugger_t::name, "ttd"
                "TTD trace replayer",           // the plugin's wanted_name
            };
            bool ok = false;
            for ( const char *c : candidates )
            {
                if ( c == nullptr || *c == '\0' )
                    continue;
                if ( load_debugger(c, false) )
                {
                    msg("[ida-ttd] selected the TTD trace replayer (as '%s').\n", c);
                    ok = true;
                    break;
                }
            }
            if ( !ok )
            {
                // Assigning ::dbg by hand is no fallback. init() may, while IDA
                // builds its debugger list; afterwards it leaves the kernel on
                // a debugger it never initialized, and starting a process then
                // crashed IDA.
                if ( !m_switchReported )
                {
                    m_switchReported = true;
                    msg("[ida-ttd] IDA would not switch debuggers for us (tried "
                        "'%s', '%s' and '%s'). Choose 'TTD trace replayer' under "
                        "Debugger > Switch debugger; the trace path is already "
                        "filled in, so starting the process is all that is "
                        "left.\n",
                        self.c_str(),
                        m_debugger.name != nullptr ? m_debugger.name : "",
                        "TTD trace replayer");
                }
                if ( !quiet )
                {
                    warning("Could not select the TTD trace replayer as the "
                            "debugger.\n\n"
                            "Use Debugger > Switch debugger to choose 'TTD trace "
                            "replayer'. The trace path is already filled in, so "
                            "starting the process is all that is left.");
                }
                return false;
            }
        }
        return true;
    }

    // Runs from IDA's request queue (main thread, when idle). Starting a
    // session rebases the program and replaces the loader's segments, so it
    // must not run inside a timer callback partway through the kernel's work.
    struct start_request_t : public ui_request_t
    {
        Plugin *p;
        explicit start_request_t(Plugin *plugin) : p(plugin) {}
        bool idaapi run() override
        {
            if ( p != g_live_plugin )
                return false;
            p->offer_trace_session();
            return false;               // one-shot; IDA deletes the request
        }
    };

    int idaapi Plugin::attach_cb(void *ud)
    {
        Plugin *p = static_cast<Plugin *>(ud);
        // ui_ready_to_run fires while a new database is still being analyzed;
        // starting a session then (rebase, debugger segments over the
        // loader's while analysis walks them) crashed IDA. Wait it out.
        if ( !auto_is_ok() )
            return ATTACH_POLL_MS;      // not yet; ask again
        execute_ui_requests(new start_request_t(p), nullptr);
        return -1;
    }

    // Replay another recording in this database (a fork shares the program
    // and modules).
    //
    // Runs from a timer, outside the caller (the Fork manager's Enter must not
    // see its chooser refreshed under it): end the session, wait until IDA is
    // done with it, start the new one. A switch that cannot happen is
    // dropped, not carried over to a later session's end.
    void Plugin::switch_trace(const qstring &path)
    {
        if ( m_mgr.is_active() && same_trace_path(path, m_mgr.trace_path()) )
            return;
        m_switchTo       = path;
        // Ending the session closes its windows; the Fork manager reopens at
        // the new session's first stop. A pending reopen carries over.
        m_reopenForkManager = m_reopenForkManager || fork_manager_is_open();
        m_switchExitSent = false;
        m_switchTimer.cancel();
        m_switchTimer.arm(10, switch_cb, this);
    }

    // Both halves of a switch run from IDA's request queue, like
    // start_request_t: ending or starting a session inside a timer callback
    // caused internal error 40183.
    struct switch_exit_request_t : public ui_request_t
    {
        Plugin *p;
        explicit switch_exit_request_t(Plugin *plugin) : p(plugin) {}
        bool idaapi run() override
        {
            if ( p != g_live_plugin )
                return false;
            p->switch_exit();
            return false;
        }
    };

    struct switch_start_request_t : public ui_request_t
    {
        Plugin *p;
        qstring path;
        switch_start_request_t(Plugin *plugin, const qstring &to) : p(plugin), path(to) {}
        bool idaapi run() override
        {
            if ( p != g_live_plugin )
                return false;
            if ( get_process_state() != DSTATE_NOTASK )
            {
                msg("[ida-ttd] a session is running again; not switching to %s.\n", path.c_str());
                return false;
            }
            msg("[ida-ttd] switching the replay to %s\n", path.c_str());
            if ( !p->start_trace_at(path.c_str()) )
                warning("Could not start the replay of %s (see the output window).", path.c_str());
            return false;
        }
    };

    void Plugin::switch_exit()
    {
        if ( m_switchTo.empty() )
            return;
        qstring path;
        path.swap(m_switchTo);
        // The session ended between the request being queued and now: there
        // is nothing to exit, so start the switch's replay directly, as
        // switch_cb does without a session. Returning here instead dropped
        // the switch and left the Fork manager to reopen in a later session.
        if ( get_process_state() == DSTATE_NOTASK )
        {
            execute_ui_requests(new switch_start_request_t(this, path), nullptr);
            return;
        }
        // Close the Fork manager while the session is still ordinary rather
        // than let IDA tear it down at session end; it reopens at the new
        // session's first stop.
        close_fork_manager_window();
        // IDA's request queue chains the two, so the start runs once IDA is
        // done with the old session. Starting as soon as the state read "no
        // process" raced IDA's teardown (internal error 40183 at times).
        set_process_options(path.c_str(), "", nullptr, "", "", "", -1);
        msg("[ida-ttd] switching the replay to %s\n", path.c_str());
        request_exit_process();
        request_start_process(path.c_str(), "", "");
        run_requests();
    }

    int idaapi Plugin::switch_cb(void *ud)
    {
        Plugin *p = static_cast<Plugin *>(ud);
        if ( p->m_switchTo.empty() )
            return -1;
        if ( get_process_state() != DSTATE_NOTASK )
        {
            // A session is running: switch_exit ends it and queues the start.
            if ( !p->m_switchExitSent )
            {
                p->m_switchExitSent = true;
                execute_ui_requests(new switch_exit_request_t(p), nullptr);
            }
            return -1;
        }
        qstring path;
        path.swap(p->m_switchTo);
        execute_ui_requests(new switch_start_request_t(p, path), nullptr);
        return -1;
    }

    void Plugin::reopen_fork_manager()
    {
        if ( m_reopenForkManager )
        {
            m_reopenForkManager = false;
            process_ui_action(actions::FORK_MANAGER);
        }
    }

    bool Plugin::start_trace_at(const char *path, bool quiet)
    {
        if ( !select_trace_debugger(path, quiet) )
            return false;
        return start_process(path, "", "") == 1;
    }

    void Plugin::schedule_trace_offer()
    {
        m_attachTimer.arm(ATTACH_POLL_MS, attach_cb, this);
    }

    void Plugin::offer_trace_session()
    {
        if ( !trace_link_present() || get_process_state() != DSTATE_NOTASK )
            return;

        TraceLink link;
        if ( !trace_link_read(&link) )
            return;

        // First, whether or not the replay starts: point the debugger at the
        // trace so Debugger > Start process (F9) replays it. That is also how
        // a replay is started by hand, so the TTD menu has no start item.
        if ( qfileexist(link.trace_path.c_str()) )
            select_trace_debugger(link.trace_path.c_str(), true);

        // Opening a recording is a request to replay it, so nothing is asked.
        // The replay_on_open setting turns this off. (A per-database toggle
        // on the TTD menu used to; its stored answer is ignored now.)
        if ( !settings().replay_on_open )
            return;

        // A leftover mark means the last automatic start never reached a
        // running session (it may have crashed). Clear it and stay put, so the
        // database can open and the automatic start can be switched off.
        if ( trace_link_start_marked() )
        {
            trace_link_mark_start(false);
            msg("[ida-ttd] the last automatic replay start for this database did "
                "not finish, so it was not repeated. Start it with Debugger > "
                "Start process (F9), or turn off \"Replay when a recording's "
                "database opens\" in TTD > Settings.\n");
            return;
        }

        trace_link_mark_start(true);
        start_trace_session();
    }

    // Source-info providers cannot be enumerated, so the ones with line
    // information for native code are named here; an unregistered name yields
    // nullptr.
    static const char *const SRCINFO_PROVIDERS[] = { "PDB", "pdb", "DWARF", "dwarf" };

    void Plugin::suspend_source_debugging()
    {
        for ( const char *n : SRCINFO_PROVIDERS )
        {
            srcinfo_provider_t *sp = get_srcinfo_provider(n);
            // Turn off only what is on, and remember it, so a provider the
            // user had disabled is not re-enabled at session end.
            if ( sp == nullptr || !sp->is_enabled() )
                continue;
            sp->enable_provider(false);
            m_srcProvidersOff.push_back(n);
            msg("[ida-ttd] source-level debugging via '%s' is off for this session: "
                "it offers to map source paths recorded on the machine that made "
                "the trace. It is restored when the trace closes.\n", n);
        }
    }

    void Plugin::restore_source_debugging()
    {
        for ( const char *n : m_srcProvidersOff )
        {
            srcinfo_provider_t *sp = get_srcinfo_provider(n);
            if ( sp != nullptr )
                sp->enable_provider(true);
        }
        m_srcProvidersOff.clear();
    }
}
