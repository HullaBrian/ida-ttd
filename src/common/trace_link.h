#pragma once

#include "common/pch.h"

namespace idattd
{
    // The record a database created from a .run file carries about that file.
    //
    // The loader runs exactly once, when the database is created. Every later
    // open of the .i64 goes straight to the plugin, so anything the plugin needs
    // in order to reconnect the database to its recording has to be written here
    // and not recomputed.
    struct TraceLink
    {
        qstring  trace_path;            // absolute path of the .run, as it was then
        qstring  module_path;           // main module's full path on the RECORDING machine
        qstring  module_name;           // its base name -- what a module load is matched against
        ea_t     module_base = BADADDR; // recorded load address of the main image
        uint64_t module_size = 0;
        int      bitness = 0;           // 0 unknown, 32, or 64
    };

    // True when this database was created by the .run loader.
    bool trace_link_present();
    // Read the record. False when absent or written by a newer schema.
    bool trace_link_read(TraceLink *out);
    void trace_link_write(const TraceLink &link);
    // Point the record at a different .run. Used when the recording has been
    // moved or renamed since the database was made and the user re-locates it.
    void trace_link_set_path(const char *path);

    // Whether the user wants the replay started when this database is opened.
    // 0 = never asked, 1 = declined, 2 = accepted. Kept in the database rather
    // than in the plugin object, because a fresh plugin is constructed on every
    // open and would otherwise ask again every time.
    enum { TL_ASK = 0, TL_NO = 1, TL_YES = 2 };
    int  trace_link_autostart();
    void trace_link_set_autostart(int v);
}
