#pragma once

#include "common/pch.h"
#include "core/position.h"

namespace idattd
{
    class TraceManager;

    // The handles the recorded process opened and closed: files, registry
    // keys, sockets, pipes, sections, processes, threads, events and the rest.
    //
    // Built from the syscalls the recording made (capabilities().syscalls):
    // each call that creates or opens an object, read at the call for what it
    // names (OBJECT_ATTRIBUTES, a client id, a port name) and just after it
    // for the handle it wrote back; NtDuplicateObject copies one; NtClose
    // ends one. A handle closed but never seen opened was opened before the
    // recording began (inherited, or made by the loader).
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

    // Every handle, in the order they were opened; one from before the
    // recording comes where it was closed. Runs behind a cancellable wait
    // box; false when the recording's backend cannot list syscalls. A
    // complete answer is saved in the database for load_handles.
    bool list_handles(TraceManager *mgr, std::vector<HandleRecord> *out, bool *cancelled);

    // The list as saved in the database by the last list_handles that ran to
    // the end against this recording. False when there is none.
    bool load_handles(std::vector<HandleRecord> *out);
}
