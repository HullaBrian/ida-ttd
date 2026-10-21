#pragma once

#include "common/pch.h"
#include "core/backend.h"

namespace idattd
{
    class TraceManager;

    // Recovering what the program had in memory by replaying the whole
    // recording with a scanner watching (capabilities().replay_scans: Sogen
    // re-executes it, Microsoft TTD replays it with write watchpoints). Each runs behind a cancellable wait box and costs a full replay;
    // the backend keeps the answer for the session.
    //
    // False when it did not run; 'error' says why when the backend does.

    bool recover_strings(TraceManager *mgr, const ReplaySettings &settings, uint32_t min_length,
                         std::vector<StringHit> *out, bool *cancelled, qstring *error);

    bool recover_buffers(TraceManager *mgr, const ReplaySettings &settings,
                         std::vector<BufferHit> *out, bool *cancelled, qstring *error);

    // The folder of registry hives a replay needs (shared by forks and the
    // scans): the one the user last gave, while it still holds hives; else
    // $IDAUSR\ida-ttd\registry when that does; else whatever was saved, empty
    // for the backend's default (a registry folder beside its DLL).
    qstring saved_registry_dir();
    void    save_registry_dir(const char *dir);
}
