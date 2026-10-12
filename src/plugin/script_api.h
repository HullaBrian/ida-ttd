#pragma once

#include "common/pch.h"

namespace idattd
{
    class Plugin;

    // Driving the plugin from a script: one IDC function,
    //
    //     ttd("command arg arg ...")  ->  a JSON string
    //
    // so that anything able to evaluate IDC -- IDAPython, an MCP server that
    // runs Python inside IDA, the IDC command line -- can open recordings, move
    // through them and read what the plugin sees, and get an answer it can
    // parse. It is how the plugin is tested without a person at the UI.
    //
    // Arguments are separated by spaces; one with spaces in it is written in
    // double quotes. Numbers are hex with or without 0x. Every answer is a JSON
    // object with "ok"; a failure has "error" as well. "help" lists the
    // commands. scripts/ida_ttd.py wraps this for Python, and
    // docs/scripting.md describes the commands.
    void install_script_api(Plugin *plugin);
    void remove_script_api();
}
