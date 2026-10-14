#pragma once

#include "common/pch.h"
#include "core/backend.h"

namespace idattd
{
    class TraceManager;

    // The syscalls the recording made, for a backend that can list them
    // (capabilities().syscalls: Sogen records them, Microsoft TTD's are its
    // transitions into the kernel). Runs behind a cancellable wait box.
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

    // Every syscall's arguments decoded from the native API metadata (phnt):
    // decoded[i] is "name=value, ..." for calls[i], empty where there is no
    // signature. Each call's arguments are read at it, and what the kernel
    // wrote back after it. Runs behind a cancellable wait box; 'cancelled'
    // leaves 'decoded' empty.
    bool decode_syscalls(TraceManager *mgr, const std::vector<SyscallEvent> &calls,
                         std::vector<qstring> *decoded, bool *cancelled);
    // The list and its decoding, kept in the database against the recording.
    void save_syscalls(const std::vector<SyscallEvent> &calls, const std::vector<qstring> &decoded);
    bool load_syscalls(std::vector<SyscallEvent> *calls, std::vector<qstring> *decoded);

    // Every instruction the program wrote before running it, for a backend
    // that can look (capabilities().self_modifying). One pass over the whole
    // recording behind a cancellable wait box.
    bool find_self_modifying(TraceManager *mgr, std::vector<SelfModHit> *out, bool *cancelled);

    // "STATUS_SUCCESS"-style text for the common NTSTATUS values a syscall
    // returns, else nullptr.
    const char *ntstatus_name(uint32_t status);
}
