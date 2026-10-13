#pragma once

#include "backend-msttd/msttd_pch.h"
#include "core/backend.h"

namespace idattd
{
    class MsTtdBackend;

    // The syscalls of a Microsoft recording.
    //
    // The recording does not list them, but the engine reports every
    // transition into the kernel as a KernelCall gap, on the syscall
    // instruction itself. That catches a syscall wherever it was made -- an
    // ntdll stub or code that issues its own -- which watching ntdll's
    // exports never could. The number is in rax (eax) there; the name comes
    // from the stubs of the ntdll the recording loaded, each of which starts
    // by loading its number.

    static const size_t kKernelCallArgs = 12;

    struct KernelCall
    {
        TTD::Replay::Position pos;          // at the syscall instruction
        uint32_t  utid      = 0;            // UniqueId, for SetPositionOnThread
        uint32_t  tid       = 0;            // the OS thread id
        ea_t      pc        = BADADDR;      // the syscall instruction
        uint64_t  ret_pc    = 0;            // where the kernel returns to; 0 unknown
        uint64_t  sp        = 0;
        uint32_t  number    = 0;
        const char *name    = nullptr;      // in the SyscallTable; nullptr unknown
        ea_t      stub      = BADADDR;      // the ntdll/win32u stub it was made from, if one
        uint64_t  args[kKernelCallArgs] = { 0 };    // as the kernel takes them
        // With chains: innermost first, one frame per module crossed. It
        // starts at the call into the stub, or at the syscall itself when
        // the program made its own.
        ea_t      chain[ITTD_CHAIN_MAX] = { 0 };
        uint8_t   chain_n   = 0;
        // With chains: where the innermost call still out returns to -- for
        // a stub's syscall, back into the stub's caller.
        uint64_t  frame_ret = 0;
        // From the return pass:
        TTD::Replay::Position ret_pos;      // at the instruction the kernel returned to
        bool      returned  = false;
        uint64_t  result    = 0;            // rax (eax) there
    };

    // Syscall number -> Nt* name, from the stubs of every ntdll in the
    // recording.
    struct SyscallTable
    {
        std::map<uint32_t, std::string> names;
        std::multimap<uint32_t, ea_t>   stubs;  // number -> each stub that makes it
        const char *name_of(uint32_t n) const
        {
            auto it = names.find(n);
            return it != names.end() ? it->second.c_str() : nullptr;
        }
        // Every number 'name' is made with (WoW64: a 32-bit one as well).
        std::vector<uint32_t> numbers_of(const char *name) const;
        // The stub syscall 'n' made at 'pc' belongs to; BADADDR when it was
        // made from anywhere else.
        ea_t stub_of(uint32_t n, ea_t pc) const;
    };

    bool build_syscall_table(const MsTtdBackend *backend, SyscallTable *out);

    struct KernelCallOptions
    {
        // Which numbers get their arguments read (and, with chains, their
        // chain). Empty: every one.
        std::function<bool(uint32_t)> args_wanted;
        // The call chain that led to each syscall, which costs a call/return
        // callback on every call in the recording.
        bool chains = false;
        // With chains: told of every call and return the recording makes, on
        // the replay thread, after the shadow stack has taken it. 'target'
        // is the callee, or the address returned to.
        std::function<void(TTD::Replay::IThreadView const *, uint32_t utid, bool is_return,
                           uint64_t target)> on_call_ret;
        // Told of each syscall as the census reads it, on the replay thread.
        std::function<void(const KernelCall &, TTD::Replay::IThreadView const *)> on_syscall;
        // A second replay, to the instructions the kernel returned to, for
        // each syscall's result.
        bool results = true;
    };

    // Every syscall in the recording, in position order. Progress through
    // 'progress' (both replays in one percentage).
    QueryResult collect_kernel_calls(const MsTtdBackend *backend, const SyscallTable &table,
                                     const KernelCallOptions &opts,
                                     std::vector<KernelCall> *out, ProgressSink *progress);
}
