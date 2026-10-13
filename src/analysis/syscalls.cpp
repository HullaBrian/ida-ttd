#include "analysis/syscalls.h"
#include "analysis/query_runner.h"
#include "debugger/trace_manager.h"

namespace idattd
{
    bool list_syscalls(TraceManager *mgr, std::vector<SyscallEvent> *out, bool *cancelled)
    {
        if ( cancelled != nullptr )
            *cancelled = false;
        if ( out != nullptr )
            out->clear();
        if ( mgr == nullptr || !mgr->is_active() || mgr->backend() == nullptr || out == nullptr )
            return false;
        ITraceBackend *backend = mgr->backend();
        if ( !backend->capabilities().syscalls )
            return false;
        QueryResult qr = run_query("Listing the recording's syscalls", [&](ProgressSink *p)
        {
            return backend->query_syscalls(out, p);
        });
        if ( cancelled != nullptr )
            *cancelled = qr.cancelled;
        return qr.ran;
    }

    bool find_self_modifying(TraceManager *mgr, std::vector<SelfModHit> *out, bool *cancelled)
    {
        if ( cancelled != nullptr )
            *cancelled = false;
        if ( out != nullptr )
            out->clear();
        if ( mgr == nullptr || !mgr->is_active() || mgr->backend() == nullptr || out == nullptr )
            return false;
        ITraceBackend *backend = mgr->backend();
        if ( !backend->capabilities().self_modifying )
            return false;
        QueryResult qr = run_query("Looking for code the program wrote and then ran", [&](ProgressSink *p)
        {
            return backend->query_self_modifying(out, p);
        });
        if ( cancelled != nullptr )
            *cancelled = qr.cancelled;
        return qr.ran;
    }

    void syscall_arguments(ITraceBackend *backend, const std::vector<SyscallEvent> &calls,
                           size_t first, size_t count,
                           std::vector<std::optional<SyscallArgs>> *out)
    {
        out->clear();
        if ( backend == nullptr || first >= calls.size() )
            return;
        count = std::min(count, calls.size() - first);
        std::vector<Position> where;
        where.reserve(count);
        for ( size_t i = 0; i < count; i++ )
            where.push_back(calls[first + i].pos);
        std::vector<ittd_regs> regs;
        backend->registers_at(where, &regs, nullptr);
        out->resize(count);
        for ( size_t i = 0; i < count && i < regs.size(); i++ )
        {
            const ittd_regs &r = regs[i];
            if ( (r.have & ITTD_REGS_GP) == 0 )
                continue;
            // The syscall stub moves rcx to r10 before the syscall instruction,
            // because the instruction itself overwrites rcx with the return
            // address.
            (*out)[i] = SyscallArgs{ r.gp[10], r.gp[ITTD_REG_RDX], r.gp[ITTD_REG_R8], r.gp[9] };
        }
    }

    const char *ntstatus_name(uint32_t status)
    {
        switch ( status )
        {
            case 0x00000000: return "STATUS_SUCCESS";
            case 0x00000102: return "STATUS_TIMEOUT";
            case 0x00000103: return "STATUS_PENDING";
            case 0x80000005: return "STATUS_BUFFER_OVERFLOW";
            case 0x80000006: return "STATUS_NO_MORE_FILES";
            case 0x8000001A: return "STATUS_NO_MORE_ENTRIES";
            case 0xC0000001: return "STATUS_UNSUCCESSFUL";
            case 0xC0000002: return "STATUS_NOT_IMPLEMENTED";
            case 0xC0000003: return "STATUS_INVALID_INFO_CLASS";
            case 0xC0000004: return "STATUS_INFO_LENGTH_MISMATCH";
            case 0xC0000005: return "STATUS_ACCESS_VIOLATION";
            case 0xC0000008: return "STATUS_INVALID_HANDLE";
            case 0xC000000D: return "STATUS_INVALID_PARAMETER";
            case 0xC000000F: return "STATUS_NO_SUCH_FILE";
            case 0xC0000017: return "STATUS_NO_MEMORY";
            case 0xC0000018: return "STATUS_CONFLICTING_ADDRESSES";
            case 0xC0000022: return "STATUS_ACCESS_DENIED";
            case 0xC0000023: return "STATUS_BUFFER_TOO_SMALL";
            case 0xC0000024: return "STATUS_OBJECT_TYPE_MISMATCH";
            case 0xC0000033: return "STATUS_OBJECT_NAME_INVALID";
            case 0xC0000034: return "STATUS_OBJECT_NAME_NOT_FOUND";
            case 0xC0000035: return "STATUS_OBJECT_NAME_COLLISION";
            case 0xC000003A: return "STATUS_OBJECT_PATH_NOT_FOUND";
            case 0xC0000045: return "STATUS_INVALID_PAGE_PROTECTION";
            case 0xC00000BB: return "STATUS_NOT_SUPPORTED";
            case 0xC0000135: return "STATUS_DLL_NOT_FOUND";
            case 0xC0000139: return "STATUS_ENTRYPOINT_NOT_FOUND";
            case 0xC0000225: return "STATUS_NOT_FOUND";
            default:         return nullptr;
        }
    }
}
