#pragma once

#include "common/pch.h"
#include "core/backend.h"

namespace idattd
{
    class TraceManager;

    // Recovering what the program had in memory by replaying the whole
    // recording with a scanner (capabilities().replay_scans: Sogen re-executes
    // it, Microsoft TTD replays it with write watchpoints). Each costs a full
    // replay behind a cancellable wait box; the backend keeps the answer for
    // the session.
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

    // The emulation root for replaying a recording made in one: the folder
    // the user chose for this recording this session, or empty for the one
    // the recording names.
    qstring chosen_emulation_root(TraceManager *mgr);
    void    choose_emulation_root(TraceManager *mgr, const char *dir);

    // Where the open recording's hives may be, best first, without
    // duplicates. Made in an emulation root: only that root's registry
    // folder, which a replay loads. Made against the host: the folder the user
    // chose, a registry folder beside the recording (how one is shared with
    // its hives), the registry_folder setting, and $IDAUSR\ida-ttd\registry.
    qstrvec_t registry_candidates(TraceManager *mgr);

    // The registry folder to give a replay of the open recording: the first
    // candidate holding the recording's own hives. Otherwise, unless the
    // recording carries what it read of them, the first holding hives it
    // cannot vouch for, else the first holding other hives (the replay then
    // refuses, saying so); else empty. Always empty for a recording made in
    // an emulation root, whose replay loads the root's own. Checking reads
    // the hives, once per folder.
    qstring find_registry_dir(TraceManager *mgr);
}
