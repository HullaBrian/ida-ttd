#pragma once

#include "common/pch.h"

namespace idattd
{
    // The plugin's settings (ida-plugin.json, "settings"). The values come
    // from ida-settings through IDAPython (scripts/ida_ttd_settings.py),
    // read once as the plugin loads, so a change takes effect at the next
    // database. The defaults here must match ida-plugin.json: they are what
    // the plugin uses without IDAPython or without ida-settings.
    struct Settings
    {
        bool     symbol_downloads  = true;
        qstring  symbol_server     = "https://msdl.microsoft.com/download/symbols";
        bool     auto_coverage     = true;      // where the database never set it
        bool     auto_callsites    = false;     // likewise
        uint64   fork_instructions = 1000000;
        qstring  registry_folder;               // empty: none
        bool     diagnostics_log   = true;
    };

    const Settings &settings();

    // Read the values, and hand the ones lower layers keep to them (the
    // symbol downloader, the diagnostics log). Needs ida-ttd-python on
    // sys.path (register_python_module) when IDAPython is there.
    void load_settings();

    // load_settings() again if IDA's settings file (ida-config.json, where
    // ida-settings keeps the values) changed since: called on every stop, so
    // a change in the Settings Editor applies from the next one. A stat when
    // nothing changed.
    void reload_settings_if_changed();
}
