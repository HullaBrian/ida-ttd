// The ttd("...") IDC function: the merged command table, 'help',
// dispatch, and the registration. The commands are in script_session.cpp,
// script_analysis.cpp, script_fork.cpp, script_ui.cpp and script_drv.cpp.
#include "plugin/script_api.h"
#include "plugin/script_internal.h"

#include <expr.hpp>

namespace idattd
{
    // ------------------------------------------------------------------ state

    Plugin *g_plugin = nullptr;

    // ------------------------------------------------------------------ dispatch

    static void cmd_help(const Args &, JObj &out);

    static const Command API_COMMANDS[] = {
        { "help",           cmd_help,           "this list; every number is hex (0x optional), 0n10 is decimal ten" },
    };

    // The order 'help' lists the commands in. Each file holds its own rows;
    // this is the one place that orders them.
    static const char *const HELP_ORDER[] = {
        "help", "state", "backends", "settings", "start", "wait", "step", "over", "out", "run",
        "runto", "goto", "regs", "read", "segments", "stop", "an.search", "an.coverage",
        "an.callsites", "an.trace", "an.memmap", "an.regions", "an.handles", "an.origin",
        "an.origingraph", "ui.origingraph", "ui.graph", "ui.graphact", "an.inputs",
        "an.autocalls", "an.decode", "an.syscalls", "an.selfmod", "an.calltree", "an.registry",
        "an.strings", "an.buffers", "switch", "ui.calltree", "ui.heat", "ui.heatnow",
        "ui.heatzoom", "ui.showbytes", "an.heat", "ui.travel", "switch.ui", "an.forks",
        "an.forget", "an.forkhere", "an.forkdraft", "an.forkdiscard", "an.forkrecord",
        "an.fork", "an.record", "drv.open", "drv.close", "drv.info", "drv.modules",
        "drv.threads", "drv.timeline", "drv.pos", "drv.seek", "drv.step", "drv.over", "drv.out",
        "drv.run", "drv.runto", "drv.bp", "drv.insns", "drv.regs", "drv.read", "drv.accesses",
        "drv.calls", "drv.indirect", "drv.exceptions", "drv.syscalls", "drv.map", "drv.symbols",
    };

    // Every file's rows in HELP_ORDER. A row missing from HELP_ORDER still
    // works and is listed last, so forgetting the list loses no command.
    static std::vector<Command> merged_commands()
    {
        const std::span<const Command> parts[] =
        {
            API_COMMANDS, session_commands(), analysis_commands(), ui_commands(),
            fork_commands(), drv_commands(),
        };
        auto listed = [](const std::vector<Command> &v, const char *name)
        {
            for ( const Command &c : v )
                if ( strcmp(c.name, name) == 0 )
                    return true;
            return false;
        };
        std::vector<Command> all;
        for ( const char *name : HELP_ORDER )
            for ( const std::span<const Command> &part : parts )
                for ( const Command &c : part )
                    if ( strcmp(c.name, name) == 0 && !listed(all, name) )
                        all.push_back(c);
        for ( const std::span<const Command> &part : parts )
            for ( const Command &c : part )
                if ( !listed(all, c.name) )
                    all.push_back(c);
        return all;
    }

    // Every row's handler and strings are constants, so the other files'
    // tables are ready before this runs at load.
    static const std::vector<Command> g_commands = merged_commands();

    static void cmd_help(const Args &, JObj &out)
    {
        JArr arr;
        for ( const Command &c : g_commands )
        {
            qstring line = c.name;
            line.append(' ');
            line.append(c.usage);
            qstring j;
            json_escape(&j, line.c_str());
            arr.add(j);
        }
        out.raw("commands", arr.done());
    }

    static qstring dispatch(const char *line)
    {
        JObj out;
        Args a;
        a.v = tokenize(line != nullptr ? line : "");
        if ( a.v.empty() )
            a.v.push_back("help");
        // A query's wait box pumps the UI, so the session can end under a
        // command (a timer, another script, the user). The query then comes
        // back as not run, which most commands report as the backend being
        // unable to answer: say what really happened instead.
        // Not for the commands that end the session themselves.
        const bool ends_session = a.v[0] == "stop" || a.v[0] == "switch" || a.v[0] == "start";
        const bool was_active = !ends_session && g_plugin != nullptr && mgr().is_active();
        auto why = [&](const char *what) -> qstring
        {
            if ( was_active && (g_plugin == nullptr || !mgr().is_active()) )
                return qstring("the replay session ended while the command ran");
            return qstring(what);
        };
        // No modal box from a stop this command waits for (the trace's edge,
        // a notice): the caller is a script.
        struct QuietStops
        {
            TraceManager *m;
            explicit QuietStops(TraceManager *t) : m(t) { if ( m != nullptr ) m->quiet_stops(true); }
            ~QuietStops() { if ( m != nullptr ) m->quiet_stops(false); }
        } quiet(g_plugin != nullptr ? &mgr() : nullptr);
        try
        {
            const Command *found = nullptr;
            for ( const Command &c : g_commands )
            {
                if ( a.v[0] == c.name )
                {
                    found = &c;
                    break;
                }
            }
            if ( found == nullptr )
                fail("unknown command '%s'; see 'help'", a.v[0].c_str());
            JObj body;
            found->fn(a, body);
            out.boolean("ok", true).str("command", a.v[0]);
            qstring s = out.done();
            qstring b = body.done();
            // Merge: {"ok":true,"command":...} + the command's own fields.
            s.remove_last();
            if ( b.length() > 2 )
            {
                s.append(',');
                s.append(b.c_str() + 1);
            }
            else
            {
                s.append('}');
            }
            return s;
        }
        catch ( const ScriptError &e )
        {
            out.boolean("ok", false).str("command", a.v[0]).str("error", why(e.what.c_str()));
        }
        catch ( const std::exception &e )
        {
            out.boolean("ok", false).str("command", a.v[0]).str("error", why(e.what()));
        }
        catch ( ... )
        {
            // Nothing may unwind into IDA's IDC evaluator.
            out.boolean("ok", false).str("command", a.v[0]).str("error", why("the command failed"));
        }
        return out.done();
    }

    // ------------------------------------------------------------------ IDC

    static error_t idaapi idc_ttd(idc_value_t *argv, idc_value_t *res)
    {
        qstring answer = dispatch(argv[0].vtype == VT_STR ? argv[0].c_str() : "help");
        res->_set_string(answer);
        return eOk;
    }

    static const char idc_ttd_args[] = { VT_STR, 0 };
    static const ext_idcfunc_t idc_ttd_desc = { "ttd", idc_ttd, idc_ttd_args, nullptr, 0, EXTFUN_BASE };

    void install_script_api(Plugin *plugin)
    {
        g_plugin = plugin;
        if ( !add_idc_func(idc_ttd_desc) )
            msg("[ida-ttd] could not register the IDC function ttd(); scripting is unavailable.\n");
    }

    void remove_script_api()
    {
        del_idc_func("ttd");
        g_drv.close();
        g_plugin = nullptr;
    }
}
