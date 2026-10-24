#pragma once

#include "common/pch.h"

namespace idattd
{
    class Plugin;

    // Driving the plugin from a script through one IDC function:
    //
    //     ttd("command arg arg ...")  ->  a JSON string
    //
    // Anything that can evaluate IDC (IDAPython, an MCP server running Python
    // in IDA, the IDC command line) can open recordings, move through them
    // and read what the plugin sees. This is how the plugin is tested without
    // a person at the UI.
    //
    // Arguments are space-separated; double-quote one that holds spaces.
    // Numbers are hex, with or without 0x. Every answer is a JSON object with
    // "ok", plus "error" on failure. "help" lists the commands;
    // scripts/ida_ttd.py wraps this for Python and docs/scripting.md
    // documents it.
    void install_script_api(Plugin *plugin);
    void remove_script_api();
}
