#include "analysis/handles.h"
#include "analysis/query_runner.h"
#include "analysis/syscalls.h"
#include "debugger/trace_manager.h"

namespace idattd
{
    namespace
    {
        // What a syscall that makes a handle takes: the argument holding the
        // PHANDLE it writes back, the one holding its OBJECT_ATTRIBUTES (-1
        // for none), and the kind of object.
        struct Maker
        {
            const char *name;
            int         out;        // PHANDLE
            int         attrs;      // POBJECT_ATTRIBUTES
            int         access;     // ACCESS_MASK
            const char *type;
        };
        const Maker MAKERS[] =
        {
            { "NtCreateFile",               0, 2, 1, "File" },
            { "NtOpenFile",                 0, 2, 1, "File" },
            { "NtCreateNamedPipeFile",      0, 2, 1, "Pipe" },
            { "NtCreateMailslotFile",       0, 2, 1, "Mailslot" },
            { "NtCreateKey",                0, 2, 1, "Key" },
            { "NtCreateKeyTransacted",      0, 2, 1, "Key" },
            { "NtOpenKey",                  0, 2, 1, "Key" },
            { "NtOpenKeyEx",                0, 2, 1, "Key" },
            { "NtOpenKeyTransacted",        0, 2, 1, "Key" },
            { "NtOpenKeyTransactedEx",      0, 2, 1, "Key" },
            { "NtCreateSection",            0, 2, 1, "Section" },
            { "NtCreateSectionEx",          0, 2, 1, "Section" },
            { "NtOpenSection",              0, 2, 1, "Section" },
            { "NtCreateEvent",              0, 2, 1, "Event" },
            { "NtOpenEvent",                0, 2, 1, "Event" },
            { "NtCreateEventPair",          0, 2, 1, "EventPair" },
            { "NtCreateMutant",             0, 2, 1, "Mutant" },
            { "NtOpenMutant",               0, 2, 1, "Mutant" },
            { "NtCreateSemaphore",          0, 2, 1, "Semaphore" },
            { "NtOpenSemaphore",            0, 2, 1, "Semaphore" },
            { "NtCreateTimer",              0, 2, 1, "Timer" },
            { "NtCreateTimer2",             0, 2, 3, "Timer" },
            { "NtOpenTimer",                0, 2, 1, "Timer" },
            { "NtCreateIoCompletion",       0, 2, 1, "IoCompletion" },
            { "NtOpenIoCompletion",         0, 2, 1, "IoCompletion" },
            { "NtCreateKeyedEvent",         0, 2, 1, "KeyedEvent" },
            { "NtOpenKeyedEvent",           0, 2, 1, "KeyedEvent" },
            { "NtCreateDirectoryObject",    0, 2, 1, "Directory" },
            { "NtCreateDirectoryObjectEx",  0, 2, 1, "Directory" },
            { "NtOpenDirectoryObject",      0, 2, 1, "Directory" },
            { "NtCreateSymbolicLinkObject", 0, 2, 1, "SymbolicLink" },
            { "NtOpenSymbolicLinkObject",   0, 2, 1, "SymbolicLink" },
            { "NtCreateJobObject",          0, 2, 1, "Job" },
            { "NtOpenJobObject",            0, 2, 1, "Job" },
            { "NtCreateWorkerFactory",      0, 2, 1, "TpWorkerFactory" },
            { "NtCreateWaitCompletionPacket", 0, 2, 1, "WaitCompletionPacket" },
            { "NtCreateTransaction",        0, 2, 1, "Transaction" },
            { "NtOpenTransaction",          0, 2, 1, "Transaction" },
            { "NtCreateProcess",            0, 2, 1, "Process" },
            { "NtCreateProcessEx",          0, 2, 1, "Process" },
            { "NtOpenProcess",              0, 2, 1, "Process" },
            { "NtOpenThread",               0, 2, 1, "Thread" },
            { "NtCreateThread",             0, 2, 1, "Thread" },
            { "NtCreateThreadEx",           0, 2, 1, "Thread" },
            { "NtOpenProcessToken",         2, -1, 1, "Token" },
            { "NtOpenProcessTokenEx",       3, -1, 1, "Token" },
            { "NtOpenThreadToken",          3, -1, 1, "Token" },
            { "NtOpenThreadTokenEx",        4, -1, 1, "Token" },
            { "NtDuplicateToken",           5, 2, 1, "Token" },
            { "NtAlpcCreatePort",           0, 1, -1, "ALPC Port" },
            { "NtAlpcConnectPort",          0, -1, -1, "ALPC Port" },
            { "NtAlpcConnectPortEx",        0, 1, -1, "ALPC Port" },
            { "NtConnectPort",              0, -1, -1, "Port" },
            { "NtSecureConnectPort",        0, -1, -1, "Port" },
            { "NtCreatePort",               0, 1, -1, "Port" },
            { "NtCreateDebugObject",        0, 2, 1, "DebugObject" },
            { "NtCreatePartition",          1, 3, 2, "Partition" },
        };

        const Maker *maker_of(const qstring &name)
        {
            for ( const Maker &m : MAKERS )
                if ( name == m.name )
                    return &m;
            return nullptr;
        }

        // Reads at one position of the recording, in the program's sizes.
        class Reader
        {
        public:
            Reader(ITraceBackend *b, bool wide) : m_b(b), m_wide(wide), m_cur(b->make_cursor()) {}
            bool ok() const { return m_cur != nullptr; }
            size_t ptr_size() const { return m_wide ? 8 : 4; }

            bool at(Position p)
            {
                if ( m_have && m_pos == p )
                    return true;
                m_have = m_cur->seek(p);
                m_pos  = p;
                return m_have;
            }

            bool read(uint64_t addr, void *buf, size_t n)
            {
                if ( addr == 0 || !m_have )
                    return false;
                std::vector<uint8_t> known;
                return m_cur->read_memory((ea_t)addr, buf, n, &known) == n;
            }

            uint64_t ptr(uint64_t addr)
            {
                uint64_t v = 0;
                if ( !read(addr, &v, ptr_size()) )
                    return 0;
                return v;
            }

            // A UNICODE_STRING at 'us'.
            qstring ustr(uint64_t us)
            {
                uint16_t len = 0;
                if ( us == 0 || !read(us, &len, 2) || len == 0 || len > 2048 )
                    return qstring();
                uint64_t buf = ptr(us + (m_wide ? 8 : 4));
                std::vector<wchar16_t> w(len / 2 + 1, 0);
                if ( !read(buf, w.data(), len) )
                    return qstring();
                qstring out;
                utf16_utf8(&out, w.data(), (int)(len / 2));
                return out;
            }

            // The name an OBJECT_ATTRIBUTES gives, and its root directory.
            qstring oa_name(uint64_t oa, uint64_t *root)
            {
                *root = 0;
                if ( oa == 0 )
                    return qstring();
                *root = ptr(oa + (m_wide ? 8 : 4));
                return ustr(ptr(oa + (m_wide ? 16 : 8)));
            }

        private:
            ITraceBackend *m_b;
            bool           m_wide;
            CursorPtr      m_cur;
            Position       m_pos;
            bool           m_have = false;
        };

        bool success(uint64_t status) { return (int32_t)(uint32_t)status >= 0; }

        qstring lower(const qstring &s)
        {
            qstring l = s;
            for ( size_t i = 0; i < l.length(); i++ )
                l[i] = qtolower(l[i]);
            return l;
        }

        const uint64_t CURRENT_PROCESS_32 = 0xFFFFFFFFull;
        bool is_current_process(uint64_t h)
        {
            return h == ~0ull || h == CURRENT_PROCESS_32;
        }
    }

    bool list_handles(TraceManager *mgr, std::vector<HandleRecord> *out, bool *cancelled)
    {
        out->clear();
        *cancelled = false;
        if ( mgr == nullptr || !mgr->is_active() || mgr->backend() == nullptr )
            return false;
        ITraceBackend *b = mgr->backend();
        if ( !b->capabilities().syscalls )
            return false;

        std::vector<SyscallEvent> calls;
        if ( !list_syscalls(mgr, &calls, cancelled) || *cancelled )
            return false;

        // Arguments follow the x64 kernel convention wherever the syscalls
        // were made from 64-bit code: always on Sogen, which runs WoW64's
        // 64-bit side itself. A Microsoft x86 recording holds the 32-bit
        // side only: its arguments are on the stack.
        const bool wide = b->info().is64 || qstrcmp(b->id(), "sogen") == 0;

        QueryResult qr = run_query("Following the handles the program opened", [&](ProgressSink *sink)
        {
            QueryResult r;
            r.ran = true;
            // The syscalls that matter, and their registers in one batch.
            std::vector<size_t> idx;
            for ( size_t i = 0; i < calls.size(); i++ )
                if ( success(calls[i].result)
                  && (calls[i].name == "NtClose" || calls[i].name == "NtDuplicateObject"
                   || calls[i].name == "NtCreateUserProcess" || maker_of(calls[i].name) != nullptr) )
                    idx.push_back(i);
            std::vector<Position> where;
            for ( size_t i : idx )
                where.push_back(calls[i].pos);
            std::vector<ittd_regs> regs;
            b->registers_at(where, &regs, nullptr);

            Reader rd(b, wide);
            if ( !rd.ok() )
                return r;
            auto arg = [&](const ittd_regs &g, int n) -> uint64_t
            {
                if ( wide )
                {
                    static const int first[4] = { 10, ITTD_REG_RDX, ITTD_REG_R8, 9 };
                    if ( n < 4 )
                        return g.gp[first[n]];
                    return rd.ptr(g.gp[ITTD_REG_RSP] + 0x28 + 8 * (n - 4));
                }
                return rd.ptr(g.gp[ITTD_REG_RSP] + 4 + 4 * (uint64_t)n);
            };

            std::map<uint64_t, size_t> live;            // handle -> its record
            std::vector<HandleRecord> recs;
            auto name_of = [&](uint64_t h) -> const HandleRecord *
            {
                auto it = live.find(h);
                return it != live.end() ? &recs[it->second] : nullptr;
            };
            auto close = [&](uint64_t h, Position p)
            {
                auto it = live.find(h);
                if ( it != live.end() )
                {
                    recs[it->second].closed = p;
                    live.erase(it);
                    return;
                }
                // Never seen opened: from before the recording.
                HandleRecord hr;
                hr.handle = h;
                hr.type   = "(before the recording)";
                hr.closed = p;
                recs.push_back(hr);
            };
            auto open = [&](HandleRecord hr)
            {
                // A handle value reused without our seeing its close.
                auto it = live.find(hr.handle);
                if ( it != live.end() )
                    live.erase(it);
                live[hr.handle] = recs.size();
                recs.push_back(std::move(hr));
            };

            for ( size_t k = 0; k < idx.size(); k++ )
            {
                if ( (k & 63) == 0 && sink != nullptr )
                {
                    if ( sink->cancelled() )
                    {
                        r.cancelled = true;
                        break;
                    }
                    sink->report(uint32_t(k * 100 / std::max<size_t>(idx.size(), 1)));
                }
                if ( k >= regs.size() || (regs[k].have & ITTD_REGS_GP) == 0 )
                    continue;
                const SyscallEvent &sc = calls[idx[k]];
                const ittd_regs &g = regs[k];
                if ( !rd.at(sc.pos) )
                    continue;

                if ( sc.name == "NtClose" )
                {
                    close(arg(g, 0), sc.pos);
                    continue;
                }

                // Everything read at the call, then the handle(s) after it.
                const Position after = b->position_add(sc.pos, 1);
                if ( sc.name == "NtDuplicateObject" )
                {
                    const uint64_t src_proc = arg(g, 0), src = arg(g, 1);
                    const uint64_t dst_proc = arg(g, 2), pdst = arg(g, 3);
                    const uint32_t access   = (uint32_t)arg(g, 4);
                    const uint64_t options  = arg(g, 6);
                    HandleRecord hr;
                    if ( is_current_process(src_proc) )
                    {
                        if ( const HandleRecord *s = name_of(src) )
                        {
                            hr.type = s->type;
                            hr.name = s->name;
                        }
                    }
                    else
                    {
                        hr.name.sprnt("handle 0x%llX of another process", (unsigned long long)src);
                    }
                    if ( is_current_process(src_proc) && (options & 1) != 0 )      // DUPLICATE_CLOSE_SOURCE
                        close(src, sc.pos);
                    if ( !is_current_process(dst_proc) || pdst == 0 || !rd.at(after) )
                        continue;
                    hr.handle    = rd.ptr(pdst);
                    hr.access    = access;
                    hr.opened    = sc.pos;
                    hr.opened_by = sc.name;
                    hr.tid       = sc.tid;
                    if ( hr.type.empty() )
                        hr.type = "(duplicated)";
                    if ( hr.handle != 0 )
                        open(hr);
                    continue;
                }

                if ( sc.name == "NtCreateUserProcess" )
                {
                    // Two handles: the process and its first thread, named
                    // after the image (RTL_USER_PROCESS_PARAMETERS ImagePathName).
                    const uint64_t pproc = arg(g, 0), pthread = arg(g, 1), params = arg(g, 8);
                    const qstring image = rd.ustr(params != 0 ? params + (wide ? 0x60 : 0x38) : 0);
                    if ( !rd.at(after) )
                        continue;
                    HandleRecord hp;
                    hp.type      = "Process";
                    hp.name      = image;
                    hp.access    = (uint32_t)arg(g, 2);
                    hp.opened    = sc.pos;
                    hp.opened_by = sc.name;
                    hp.tid       = sc.tid;
                    HandleRecord ht = hp;
                    ht.type   = "Thread";
                    ht.access = (uint32_t)arg(g, 3);
                    if ( !image.empty() )
                        ht.name = qstring("first thread of ") + image;
                    hp.handle = rd.ptr(pproc);
                    ht.handle = rd.ptr(pthread);
                    if ( hp.handle != 0 )
                        open(hp);
                    if ( ht.handle != 0 )
                        open(ht);
                    continue;
                }

                const Maker *m = maker_of(sc.name);
                HandleRecord hr;
                hr.type      = m->type;
                hr.opened    = sc.pos;
                hr.opened_by = sc.name;
                hr.tid       = sc.tid;
                if ( m->access >= 0 )
                    hr.access = (uint32_t)arg(g, m->access);
                const uint64_t pout = arg(g, m->out);
                uint64_t root = 0;
                if ( m->attrs >= 0 )
                    hr.name = rd.oa_name(arg(g, m->attrs), &root);
                if ( sc.name == "NtAlpcConnectPort" || sc.name == "NtConnectPort" || sc.name == "NtSecureConnectPort" )
                    hr.name = rd.ustr(arg(g, 1));
                if ( !hr.name.empty() && hr.name[0] != '\\' && root != 0 )
                {
                    // Relative to a directory or key opened earlier.
                    if ( const HandleRecord *base = name_of(root) )
                        if ( !base->name.empty() )
                            hr.name = base->name + "\\" + hr.name;
                }
                if ( sc.name == "NtOpenProcess" || sc.name == "NtOpenThread" )
                {
                    const uint64_t cid = arg(g, 3);
                    const uint64_t pid = rd.ptr(cid), tid = rd.ptr(cid + rd.ptr_size());
                    if ( sc.name == "NtOpenProcess" && pid != 0 )
                        hr.name.sprnt("process %llu", (unsigned long long)pid);
                    else if ( tid != 0 )
                        hr.name.sprnt("thread %llu", (unsigned long long)tid);
                }
                if ( sc.name == "NtCreateThreadEx" )
                    hr.name.sprnt("starting at 0x%llX", (unsigned long long)arg(g, 4));
                if ( sc.name == "NtCreateSection" || sc.name == "NtCreateSectionEx" )
                {
                    // An image or file section: name it after the file.
                    if ( hr.name.empty() )
                        if ( const HandleRecord *f = name_of(arg(g, 6)) )
                            hr.name = f->name;
                }
                if ( hr.type == "File" )
                {
                    const qstring l = lower(hr.name);
                    if ( l.find("\\device\\afd") == 0 )
                        hr.type = "Socket";
                    else if ( l.find("\\pipe\\") != qstring::npos || l.find("\\device\\namedpipe") == 0 )
                        hr.type = "Pipe";
                }

                if ( !rd.at(after) )
                    continue;
                hr.handle = rd.ptr(pout);
                if ( hr.handle != 0 )
                    open(hr);
            }
            *out = std::move(recs);
            return r;
        });
        if ( qr.cancelled )
            *cancelled = true;
        return qr.ran;
    }
}
