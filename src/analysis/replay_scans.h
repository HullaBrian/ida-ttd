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

    // The folder of registry hives the user last chose (shared by forks and
    // the scans); empty when none.
    qstring saved_registry_dir();
    void    save_registry_dir(const char *dir);

    // Where the open recording's hives may be, best first: the folder the
    // user chose, a registry folder beside the recording (how one is shared
    // with its hives), the emulation root's registry folder, and
    // $IDAUSR\ida-ttd\registry. Without duplicates.
    qstrvec_t registry_candidates(TraceManager *mgr);

    // The folder a replay of the open recording should use: the first
    // candidate holding the recording's own hives; else the first holding
    // hives the recording cannot vouch for; else the first holding other
    // hives (the replay is then refused, saying so); else empty, for the
    // backend's default. Checking reads the hives, once per folder.
    qstring find_registry_dir(TraceManager *mgr);
}
