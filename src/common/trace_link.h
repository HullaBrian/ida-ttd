#pragma once

#include "common/pch.h"

namespace idattd
{
    // The record a database created from a recording keeps about that file.
    //
    // The loader runs only when the database is created; later opens go
    // straight to the plugin, so whatever it needs to reconnect the database
    // to its recording is written here.
    struct TraceLink
    {
        qstring  trace_path;            // absolute path of the recording, as it was then
        qstring  module_path;           // main module's full path on the RECORDING machine
        qstring  module_name;           // its base name, matched against module loads
        ea_t     module_base = BADADDR; // recorded load address of the main image
        uint64_t module_size = 0;
        int      bitness = 0;           // 0 unknown, 32, or 64
    };

    // True when this database was created by the trace loader.
    bool trace_link_present();
    // Read the record. False when absent or written by a newer schema.
    bool trace_link_read(TraceLink *out);
    void trace_link_write(const TraceLink &link);
    // Point the record at a different path, when the user re-locates a
    // recording that was moved or renamed.
    void trace_link_set_path(const char *path);

    // Crash guard for the automatic start.
    //
    // Set just before an automatic start and cleared once the session is up.
    // Still set at the next open means that start crashed, so the open skips
    // it; otherwise a database that takes IDA down could never be opened to
    // turn the automatic start off.
    //
    // Kept in IDA's settings, not the database, which may never have been
    // saved.
    bool trace_link_start_marked();
    void trace_link_mark_start(bool pending);
}
