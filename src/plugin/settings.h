#pragma once

#include "common/pch.h"
#include "core/backend.h"

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
        qstring  sogen_emulation_root;          // empty: record against this machine's files
        // How Sogen forks and new recordings are made (RecordOptions).
        bool     sogen_network     = false;
        uint64   sogen_checkpoint_interval = 500000;   // 0: Sogen's default
        bool     sogen_record_reads    = true;
        bool     sogen_record_writes   = true;
        bool     sogen_record_executes = true;
        bool     sogen_elevated    = false;
        bool     sogen_log         = false;
        bool     diagnostics_log   = true;
        bool     memmap_flag_code  = true;      // highlight executable memory outside modules
    };

    const Settings &settings();

    // The Sogen settings as what a fork or a new recording is made with; the
    // Fork and Record dialogs start from it.
    RecordOptions recording_options();

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
