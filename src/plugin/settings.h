#pragma once

#include "common/pch.h"

namespace idattd
{
    // The plugin's settings (ida-plugin.json, "settings"). The values come
    // from ida-settings through IDAPython (scripts/ida_ttd_settings.py), read
    // when the plugin loads and again at a stop after ida-config.json changes
    // (reload_settings_if_changed). The defaults here must match
    // ida-plugin.json: they apply without IDAPython or ida-settings.
    struct Settings
    {
        bool     replay_on_open    = true;
        bool     symbol_downloads  = true;
        qstring  symbol_server     = "https://msdl.microsoft.com/download/symbols";
        bool     auto_coverage     = true;      // where the database never set it
        bool     auto_callsites    = false;     // likewise
        uint64   fork_instructions = 1000000;
        qstring  registry_folder;               // empty: none
        bool     diagnostics_log   = true;
        bool     memmap_flag_code  = true;      // highlight executable memory outside modules
    };

    const Settings &settings();

    // Read the values and pass the relevant ones to lower layers (the symbol
    // downloader, the diagnostics log). Needs ida-ttd-python on sys.path
    // (register_python_module) when IDAPython is present.
    void load_settings();

    // load_settings() again if ida-config.json (where ida-settings keeps the
    // values) changed since the last read. Called on every stop, so a
    // Settings Editor change applies from the next one; costs one stat when
    // nothing changed.
    void reload_settings_if_changed();
}
