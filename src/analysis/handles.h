#pragma once

#include "common/pch.h"
#include "core/position.h"

namespace idattd
{
    class TraceManager;

    // The handles the recorded process opened and closed (files, keys,
    // sockets, pipes, sections, processes, threads, events, ...).
    //
    // Built from the syscalls (capabilities().syscalls): each create or open
    // is read at the call for what it names (OBJECT_ATTRIBUTES, client id,
    // port name) and after it for the handle written back; NtDuplicateObject
    // copies one, NtClose ends one. A handle closed but never seen opened
    // predates the recording (inherited, or made by the loader).
    struct HandleRecord
    {
        uint64_t handle = 0;
        qstring  type;                  // "File", "Key", "Socket", "Process", ...
        qstring  name;                  // the object's name or path, when it has one
        uint32_t access = 0;            // the access asked for
        Position opened;                // the syscall that made it; none when before the recording
        qstring  opened_by;             // "NtCreateFile"
        uint32_t tid = 0;
        Position closed;                // NtClose (or a duplicate that closed it); none while open
    };

    // Every handle in opening order; one from before the recording sits where
    // it was closed. Behind a cancellable wait box; false when the backend
    // cannot list syscalls. A complete answer is saved for load_handles.
    bool list_handles(TraceManager *mgr, std::vector<HandleRecord> *out, bool *cancelled);

    // The list saved by the last complete list_handles against this
    // recording; false when there is none.
    bool load_handles(std::vector<HandleRecord> *out);
}
