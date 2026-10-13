#pragma once

#include "common/pch.h"
#include "core/backend.h"

namespace idattd
{
    class TraceManager;

    // The syscalls the recording dispatched, for a backend that records them
    // (capabilities().syscalls -- Sogen). Runs behind a cancellable wait box.
    //
    // Returns false when it could not run at all; 'cancelled' leaves 'out'
    // holding what was gathered so far.
    bool list_syscalls(TraceManager *mgr, std::vector<SyscallEvent> *out, bool *cancelled);

    // The first four arguments of each syscall in [first, first + count): the
    // registers at its position (r10, rdx, r8, r9 -- the kernel's convention,
    // not the user-mode one with rcx). An entry is empty when the registers
    // could not be reconstructed.
    using SyscallArgs = std::array<uint64_t, 4>;
    void syscall_arguments(ITraceBackend *backend, const std::vector<SyscallEvent> &calls,
                           size_t first, size_t count,
                           std::vector<std::optional<SyscallArgs>> *out);

    // "STATUS_SUCCESS"-style text for the common NTSTATUS values a syscall
    // returns, else nullptr.
    const char *ntstatus_name(uint32_t status);
}
