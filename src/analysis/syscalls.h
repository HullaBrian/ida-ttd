#pragma once

#include "common/pch.h"
#include "core/backend.h"

namespace idattd
{
    class TraceManager;

    // The recording's syscalls (capabilities().syscalls: Sogen records them;
    // on Microsoft TTD they are the transitions into the kernel). Behind a
    // cancellable wait box. False when it could not run; when cancelled,
    // 'out' holds what was gathered.
    bool list_syscalls(TraceManager *mgr, std::vector<SyscallEvent> *out, bool *cancelled);

    // ITTD_REG_* of an x64 syscall's first four arguments at the syscall
    // instruction: r10, rdx, r8, r9 (the stub copies rcx to r10, since the
    // instruction overwrites rcx). The fifth on is at [rsp+0x28], past the
    // return address and the 32-byte home area.
    constexpr int SYSCALL_ARG_REGS[4] = { ITTD_REG_R8 + 2, ITTD_REG_RDX, ITTD_REG_R8, ITTD_REG_R8 + 1 };

    // The first four arguments (SYSCALL_ARG_REGS) of each syscall in
    // [first, first + count); empty where the registers were not recovered.
    using SyscallArgs = std::array<uint64_t, 4>;
    void syscall_arguments(ITraceBackend *backend, const std::vector<SyscallEvent> &calls,
                           size_t first, size_t count,
                           std::vector<std::optional<SyscallArgs>> *out);

    // Every syscall's arguments decoded from the native API metadata (phnt):
    // decoded[i] is "name=value, ..." for calls[i], empty without a
    // signature. Arguments are read at the call, out values after it. Behind
    // a cancellable wait box; cancelling leaves 'decoded' empty.
    bool decode_syscalls(TraceManager *mgr, const std::vector<SyscallEvent> &calls,
                         std::vector<qstring> *decoded, bool *cancelled);
    // The list and its decoding, kept in the database against the recording.
    void save_syscalls(const std::vector<SyscallEvent> &calls, const std::vector<qstring> &decoded);
    bool load_syscalls(std::vector<SyscallEvent> *calls, std::vector<qstring> *decoded);

    // Every instruction the program wrote before running it
    // (capabilities().self_modifying). One pass over the recording behind a
    // cancellable wait box.
    bool find_self_modifying(TraceManager *mgr, std::vector<SelfModHit> *out, bool *cancelled);

    // "STATUS_SUCCESS"-style name of a common NTSTATUS, else nullptr.
    const char *ntstatus_name(uint32_t status);
}
