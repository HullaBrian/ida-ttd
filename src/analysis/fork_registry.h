#pragma once

#include "common/pch.h"

namespace idattd
{
    // The forks recorded from this database's recordings, kept in the
    // database so the Fork manager can draw them as a tree: each fork names
    // the recording it was forked from, which may itself be a fork.
    struct ForkRecord
    {
        qstring  path;          // the fork's own recording
        qstring  parent;        // the recording it was forked from
        qstring  at;            // the position it was forked at, as shown
        qstring  changes;       // what was changed there, in words
        uint64_t instructions = 0;
        uint64_t time = 0;      // when it was recorded (qtime64)
    };

    std::vector<ForkRecord> load_fork_records();
    // Add one, replacing an earlier record of the same path (a fork recorded
    // again over the same file).
    void add_fork_record(const ForkRecord &r);
    // Forget one; its file is not touched.
    void remove_fork_record(const char *path);

    // Paths compare as the same file regardless of case and slashes.
    bool same_trace_path(const qstring &a, const qstring &b);
}
