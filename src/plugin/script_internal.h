#pragma once

// What the script_*.cpp files share: the plugin and the drv.* recording
// the commands work on, the helpers more than one file uses, and the
// command rows. Each command file exports its rows (session_commands()
// and so on); script_api.cpp merges them into the table 'help' lists and
// dispatch searches.
#include "plugin/plugin.h"
#include "plugin/script_args.h"
#include "plugin/script_json.h"

#include <span>

namespace idattd
{
    // The plugin the commands work on (script_api.cpp).
    extern Plugin *g_plugin;

    // A recording opened directly through a backend, without a debugger
    // session: what drv.* works on. Exercises a backend and the core's adapter
    // in-process, headless or not.
    //
    // Its own backend instance, never the registry's: that one belongs to the
    // debugger session, whose recording another open would close.
    struct Driver
    {
        BackendPtr     owned;
        ITraceBackend *backend = nullptr;
        CursorPtr      cursor;
        std::unique_ptr<INavigator> nav;
        qstring        path;
        // Counts drv.open calls. A script holding an older handle (a second
        // Recording in Python closed the first) is told so rather than
        // driving the newer recording by mistake.
        uint64_t       handle = 0;

        void close()
        {
            nav.reset();
            cursor.reset();
            if ( backend != nullptr )
                backend->close();
            backend = nullptr;
            owned.reset();
            path.clear();
        }
    };

    // The one drv.* works on (script_drv.cpp).
    extern Driver g_drv;

    inline TraceManager &mgr() { return g_plugin->manager(); }

    // Fail unless a replay session is running (script_session.cpp).
    void need_session();
    // Bytes as hex pairs, "??" where 'known' says the recording does
    // not account for one, as a JSON string (script_drv.cpp).
    qstring bytes_json(const uint8_t *buf, const uint8_t *known, size_t n);
    // The value origin commands' arguments (script_analysis.cpp): a
    // "from=POS" word, removed from the list, and the target at the front.
    bool from_arg(Args *a, Position *p);
    OriginTarget origin_target_arg(const Args &a, const char *cmd);

    // ------------------------------------------------------------------ commands

    using Handler = void (*)(const Args &, JObj &);
    struct Command
    {
        const char *name;
        Handler     fn;
        const char *usage;
    };

    // Each file's commands. The order 'help' lists them in is
    // script_api.cpp's.
    std::span<const Command> session_commands();
    std::span<const Command> analysis_commands();
    std::span<const Command> fork_commands();
    std::span<const Command> ui_commands();
    std::span<const Command> drv_commands();
}
