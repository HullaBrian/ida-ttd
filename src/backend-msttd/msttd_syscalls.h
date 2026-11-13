#pragma once

#include "backend-msttd/msttd_pch.h"
#include "core/backend.h"

namespace idattd
{
    class MsTtdBackend;

    // The syscalls of a Microsoft recording.
    //
    // The recording does not list them, but the engine reports every kernel
    // transition as a KernelCall gap on the syscall instruction. That catches
    // syscalls made anywhere (an ntdll stub or the program's own code), which
    // watching ntdll's exports cannot. The number is in rax (eax) there; the
    // name comes from the recorded ntdll's stubs, each of which starts by
    // loading its number.

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
        // The general registers going in (ITTD_REG_*), so a listing of
        // syscalls shows their arguments without seeking to each one.
        uint64_t  gp[ITTD_REG_GP_COUNT] = { 0 };
        uint64_t  rflags    = 0;
        const char *name    = nullptr;      // in the SyscallTable; nullptr unknown
        ea_t      stub      = BADADDR;      // the ntdll/win32u stub it was made from, if one
        uint64_t  args[kKernelCallArgs] = { 0 };    // as the kernel takes them
        // With chains: innermost first, one frame per module crossed. It
        // starts at the call into the stub, or at the syscall itself when
        // the program made its own.
        ea_t      chain[ITTD_CHAIN_MAX] = { 0 };
        uint8_t   chain_n   = 0;
        // With chains: where the innermost open call returns to (for a
        // stub's syscall, back into the stub's caller).
        uint64_t  frame_ret = 0;
        // With chains: rax (eax) where the kernel came back, when the census
        // saw it (see collect_kernel_calls).
        uint64_t  result    = 0;
        bool      returned  = false;
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

    // Every module as [lo, hi), sorted by base, one per distinct base.
    std::vector<std::pair<ea_t, ea_t>> module_ranges(const std::vector<ModuleInfo> &mods);

    struct KernelCallOptions
    {
        // Which numbers get their arguments read (and, with chains, their
        // chain). Empty: every one.
        std::function<bool(uint32_t)> args_wanted;
        // The call chain that led to each syscall, which costs a call/return
        // callback on every call in the recording. The same callback sees
        // each syscall come back (KernelCall::result).
        bool chains = false;
        // With chains: told of every call and return the recording makes, on
        // the replay thread, after the shadow stack has taken it. 'target'
        // is the callee, or the address returned to.
        std::function<void(TTD::Replay::IThreadView const *, uint32_t utid, bool is_return,
                           uint64_t target)> on_call_ret;
        // Told of each syscall as the census reads it, on the replay thread.
        std::function<void(const KernelCall &, TTD::Replay::IThreadView const *)> on_syscall;
    };

    // Every syscall in the recording, in position order: one replay.
    QueryResult collect_kernel_calls(const MsTtdBackend *backend, const SyscallTable &table,
                                     const KernelCallOptions &opts,
                                     std::vector<KernelCall> *out, ProgressSink *progress);

    // One syscall as the census keeps it between queries: what the listing
    // shows and what the return pass needs. The registers are kept apart
    // (SyscallCensus::regs) and the arguments not at all, so a census at the
    // cap of a million syscalls stays near 60 MB.
    struct CensusSyscall
    {
        TTD::Replay::Position pos;          // at the syscall instruction
        uint64_t    ret_pc   = 0;           // where the kernel returns to; 0 unknown
        uint64_t    result   = 0;           // from the census, or the return pass
        const char *name     = nullptr;     // in the census's SyscallTable; nullptr unknown
        uint32_t    utid     = 0;
        uint32_t    tid      = 0;
        uint32_t    number   = 0;
        bool        returned = false;       // seen coming back
        // Left to the return pass: the census cannot tell whether it came
        // back (see syscall_census).
        bool        to_watch = false;
    };

    // The general registers going into one syscall, so the listing's
    // argument column costs no seek per row.
    struct CensusRegs
    {
        TTD::Replay::Position pos;
        uint64_t gp[ITTD_REG_GP_COUNT];
        uint64_t rflags;
    };

    // What the memory map keeps from the census replay (msttd_memmap.cpp).
    struct MemmapRecords;

    // The syscall census, kept by the backend so the listing and the memory
    // map share one replay, whichever is asked first: the map's call/return
    // callback costs little next to the replay itself, so the census always
    // collects the map's records too. Immutable once cached; a return pass
    // that completes caches a copy with the results.
    struct SyscallCensus
    {
        std::shared_ptr<const SyscallTable> table;     // the names point into it
        std::vector<CensusSyscall> calls;              // in position order
        // The first syscalls' registers, in position order (shared by the
        // copy a return pass makes). Capped: they are a convenience, and
        // registers_at seeks for the rest.
        std::shared_ptr<const std::vector<CensusRegs>> regs;
        bool truncated = false;                        // the census was cut short
        // Every result is known: the census took them all, or the return
        // pass ran to the end.
        bool results   = false;
        bool results_truncated = false;
        // Null when the recording names none of the memory syscalls.
        std::shared_ptr<const MemmapRecords> memmap;
    };

    // Records with nothing in them, for a census given up while waiting for
    // another (msttd_memmap.cpp).
    std::shared_ptr<const MemmapRecords> empty_memmap_records();

    // The memory map's part of the census (msttd_memmap.cpp): callbacks that
    // settle each memory syscall as the replay passes its return.
    class MemmapHooks
    {
    public:
        virtual ~MemmapHooks() = default;
        // Sets the options the map needs; the hooks must outlive the replay.
        virtual void arm(KernelCallOptions *opts) = 0;
        // What the replay settled, taken once it has ended.
        virtual std::shared_ptr<const MemmapRecords> finish() = 0;
    };
    // Null when 'table' names none of the memory syscalls.
    std::unique_ptr<MemmapHooks> make_memmap_hooks(const MsTtdBackend *backend, const SyscallTable &table);
}
