#include "analysis/syscalls.h"
#include "analysis/query_runner.h"
#include "debugger/trace_manager.h"
#include "debugger/apidecode.h"
#include "analysis/trace_store.h"

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

    //=======================================================================
    // Every syscall decoded, once
    //=======================================================================
    bool decode_syscalls(TraceManager *mgr, const std::vector<SyscallEvent> &calls,
                         std::vector<qstring> *decoded, bool *cancelled)
    {
        decoded->assign(calls.size(), qstring());
        *cancelled = false;
        if ( mgr == nullptr || !mgr->is_active() || mgr->backend() == nullptr )
            return false;
        ITraceBackend *b = mgr->backend();

        // Signatures on this thread (loading the index may print), by name.
        std::vector<const win32meta::FuncSig *> sigs(calls.size(), nullptr);
        {
            std::map<qstring, const win32meta::FuncSig *> by_name;
            for ( size_t i = 0; i < calls.size(); i++ )
            {
                auto it = by_name.find(calls[i].name);
                if ( it == by_name.end() )
                    it = by_name.emplace(calls[i].name, api_signature(calls[i].name.c_str())).first;
                sigs[i] = it->second;
            }
        }
        // The syscall convention, from the 64-bit side: always on Sogen; a
        // Microsoft x86 recording holds the 32-bit side, arguments on the stack.
        const bool wide = b->info().is64 || qstrcmp(b->id(), "sogen") == 0;

        QueryResult qr = run_query("Decoding the recording's syscalls", [&](ProgressSink *sink)
        {
            QueryResult r;
            r.ran = true;
            std::vector<Position> where;
            std::vector<size_t>   which;
            for ( size_t i = 0; i < calls.size(); i++ )
                if ( sigs[i] != nullptr )
                {
                    where.push_back(calls[i].pos);
                    which.push_back(i);
                }
            std::vector<ittd_regs> regs;
            StageSink regs_stage(sink, 0, 20);
            b->registers_at(where, &regs, &regs_stage);
            if ( regs_stage.cancelled() )
            {
                r.cancelled = true;
                return r;
            }
            CursorPtr cur = b->make_cursor();
            if ( !cur )
                return r;
            const GuestRead read = guest_read(cur.get());

            // ---- the arguments, at each call ----------------------------
            std::vector<DecodedCall> dc(which.size());
            std::vector<OutSlot>     slots;
            std::vector<std::pair<size_t, size_t>> slot_of;     // (call k, parameter)
            for ( size_t k = 0; k < which.size(); k++ )
            {
                if ( (k & 31) == 0 && sink != nullptr )
                {
                    if ( sink->cancelled() )
                    {
                        r.cancelled = true;
                        return r;
                    }
                    sink->report(uint32_t(20 + k * 30 / std::max<size_t>(which.size(), 1)));
                }
                if ( k >= regs.size() || (regs[k].have & ITTD_REGS_GP) == 0 )
                    continue;
                const SyscallEvent &c = calls[which[k]];
                if ( !cur->seek(c.pos) )
                    continue;
                // At the syscall instruction the arguments are where a callee
                // finds them: r10 for rcx, and the stack one return address
                // deep (two on x86: the return into the stub, then the stub's
                // own). Seen from the call site, which is what the decoder reads.
                ittd_regs g = regs[k];
                if ( wide )
                    g.gp[ITTD_REG_RCX] = g.gp[SYSCALL_ARG_REGS[0]];
                g.gp[ITTD_REG_RSP] += 8;
                GuestView v;
                v.read = read;
                v.regs = [g](ittd_regs *out) { *out = g; return true; };
                decode_api_args(v, *sigs[which[k]], wide, &dc[k]);
                for ( const auto &[param, width] : api_int_outs(dc[k]) )
                {
                    OutSlot s;
                    s.call  = c.pos;
                    s.addr  = (ea_t)dc[k].args[param].raw;
                    s.tid   = c.tid;
                    s.width = width;
                    uint64_t before = 0;
                    read(s.addr, &before, width);
                    s.before = before;
                    slots.push_back(s);
                    slot_of.emplace_back(k, param);
                }
            }

            // ---- what the kernel wrote back -------------------------------
            // Integers and handles from the backend's own search where it has
            // one (Microsoft TTD); everything else from memory just after the
            // call.
            std::vector<std::optional<uint64_t>> values;
            StageSink outs_stage(sink, 50, 75);
            const bool searched = !slots.empty() && b->query_out_values(slots, &values, &outs_stage);
            if ( sink != nullptr && sink->cancelled() )
            {
                r.cancelled = true;
                return r;
            }
            if ( searched )
                for ( size_t i = 0; i < slots.size() && i < values.size(); i++ )
                {
                    DecodedCall &d = dc[slot_of[i].first];
                    d.out_values.resize(d.args.size());
                    d.out_values[slot_of[i].second] = values[i];
                }

            for ( size_t k = 0; k < which.size(); k++ )
            {
                if ( (k & 31) == 0 && sink != nullptr )
                {
                    if ( sink->cancelled() )
                    {
                        r.cancelled = true;
                        return r;
                    }
                    sink->report(uint32_t(75 + k * 25 / std::max<size_t>(which.size(), 1)));
                }
                DecodedCall &d = dc[k];
                if ( d.sig == nullptr )
                    continue;
                bool needs_memory = false;
                for ( size_t p = 0; p < d.args.size(); p++ )
                    if ( d.args[p].out && d.args[p].raw != 0
                      && !(p < d.out_values.size() && d.out_values[p].has_value()) )
                        needs_memory = true;
                GuestView after;
                if ( needs_memory && cur->seek(b->position_add(calls[which[k]].pos, 1)) )
                    after = guest_view(cur.get());
                decode_api_outs(after, &d);
                (*decoded)[which[k]] = api_args_text(d);
            }
            return r;
        });
        *cancelled = qr.cancelled;
        if ( qr.cancelled )
            decoded->assign(calls.size(), qstring());
        return qr.ran;
    }

    //=======================================================================
    // In the database
    //=======================================================================
    static const char     SC_NODE[]  = "$ ida-ttd syscalls";
    static const uchar    SC_TAG     = 'S';
    static const uint32_t SC_VERSION = 1;

    static void put_str(bytevec_t *b, const qstring &s)
    {
        uint32_t n = (uint32_t)s.length();
        b->append(&n, sizeof(n));
        b->append(s.c_str(), n);
    }

    static bool get_str(const uchar **p, const uchar *end, qstring *s)
    {
        uint32_t n = 0;
        if ( end - *p < (ptrdiff_t)sizeof(n) )
            return false;
        memcpy(&n, *p, sizeof(n));
        *p += sizeof(n);
        if ( end - *p < (ptrdiff_t)n )
            return false;
        s->qclear();
        s->append((const char *)*p, n);
        *p += n;
        return true;
    }

    void save_syscalls(const std::vector<SyscallEvent> &calls, const std::vector<qstring> &decoded)
    {
        bytevec_t b;
        uint32_t ver = SC_VERSION, n = (uint32_t)calls.size();
        b.append(&ver, sizeof(ver));
        b.append(&n, sizeof(n));
        for ( size_t i = 0; i < calls.size(); i++ )
        {
            const SyscallEvent &c = calls[i];
            uint64_t words[3] = { c.pos.hi, c.pos.lo, c.result };
            uint32_t small[2] = { c.number, c.tid };
            b.append(words, sizeof(words));
            b.append(small, sizeof(small));
            put_str(&b, c.name);
            put_str(&b, i < decoded.size() ? decoded[i] : qstring());
        }
        netnode nn(SC_NODE, 0, true);
        if ( nn == BADNODE )
            return;
        nn.delblob(0, SC_TAG);
        nn.setblob(b.begin(), b.size(), 0, SC_TAG);
        trace_store_stamp(nn);
    }

    bool load_syscalls(std::vector<SyscallEvent> *calls, std::vector<qstring> *decoded)
    {
        calls->clear();
        decoded->clear();
        netnode nn(SC_NODE);
        if ( nn == BADNODE || !trace_store_matches(nn) )
            return false;
        bytevec_t b;
        if ( nn.getblob(&b, 0, SC_TAG) <= 0 )
            return false;
        const uchar *p = b.begin(), *end = b.end();
        uint32_t ver = 0, n = 0;
        if ( end - p < 8 )
            return false;
        memcpy(&ver, p, 4);
        memcpy(&n, p + 4, 4);
        p += 8;
        if ( ver != SC_VERSION )
            return false;
        for ( uint32_t i = 0; i < n; i++ )
        {
            SyscallEvent c;
            uint64_t words[3];
            uint32_t small[2];
            qstring  text;
            // A truncated blob yields nothing rather than the part before
            // the damage, which would read as the whole list.
            if ( end - p < (ptrdiff_t)(sizeof(words) + sizeof(small)) )
            {
                calls->clear();
                decoded->clear();
                return false;
            }
            memcpy(words, p, sizeof(words));
            p += sizeof(words);
            memcpy(small, p, sizeof(small));
            p += sizeof(small);
            c.pos    = Position{ words[0], words[1] };
            c.result = words[2];
            c.number = small[0];
            c.tid    = small[1];
            if ( !get_str(&p, end, &c.name) || !get_str(&p, end, &text) )
            {
                calls->clear();
                decoded->clear();
                return false;
            }
            calls->push_back(std::move(c));
            decoded->push_back(std::move(text));
        }
        return true;
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
            (*out)[i] = SyscallArgs{ r.gp[SYSCALL_ARG_REGS[0]], r.gp[SYSCALL_ARG_REGS[1]],
                                     r.gp[SYSCALL_ARG_REGS[2]], r.gp[SYSCALL_ARG_REGS[3]] };
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
