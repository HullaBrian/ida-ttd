#include "analysis/handles.h"
#include "analysis/query_runner.h"
#include "analysis/batched_memory.h"
#include "analysis/syscalls.h"
#include "analysis/trace_store.h"
#include "debugger/trace_manager.h"

namespace idattd
{
    namespace
    {
        // A handle-making syscall's argument indexes (PHANDLE written back,
        // OBJECT_ATTRIBUTES, ACCESS_MASK; -1 for none) and object kind.
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
            { "NtCreateTimer2",             0, 2, 4, "Timer" },
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

        // Reads at one position of the recording, in the program's sizes,
        // through a BatchedMemory reader (use()): a cursor seek per syscall
        // cost about 17 ms each on Microsoft TTD.
        class Reader
        {
        public:
            explicit Reader(bool wide) : m_wide(wide) {}
            void use(GuestRead read) { m_read = std::move(read); }
            size_t ptr_size() const { return m_wide ? 8 : 4; }

            bool read(uint64_t addr, void *buf, size_t n)
            {
                if ( addr == 0 || !m_read )
                    return false;
                return m_read(addr, buf, n) == n;
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
            bool      m_wide;
            GuestRead m_read;
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

    //=======================================================================
    // In the database
    //=======================================================================
    // One blob, stamped with the recording it describes (trace_store).
    static const char     HD_NODE[]   = "$ ida-ttd handles";
    static const uchar    HD_TAG      = 'H';
    static const uint32_t HD_VERSION  = 1;

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

    static void save_handles(const std::vector<HandleRecord> &v)
    {
        bytevec_t b;
        uint32_t ver = HD_VERSION, n = (uint32_t)v.size();
        b.append(&ver, sizeof(ver));
        b.append(&n, sizeof(n));
        for ( const HandleRecord &h : v )
        {
            uint64_t words[5] = { h.handle, h.opened.hi, h.opened.lo, h.closed.hi, h.closed.lo };
            uint32_t small[2] = { h.access, h.tid };
            b.append(words, sizeof(words));
            b.append(small, sizeof(small));
            put_str(&b, h.type);
            put_str(&b, h.name);
            put_str(&b, h.opened_by);
        }
        netnode nn(HD_NODE, 0, true);
        if ( nn == BADNODE )
            return;
        nn.delblob(0, HD_TAG);
        nn.setblob(b.begin(), b.size(), 0, HD_TAG);
        trace_store_stamp(nn);
    }

    bool load_handles(std::vector<HandleRecord> *out)
    {
        out->clear();
        netnode nn(HD_NODE);
        if ( nn == BADNODE || !trace_store_matches(nn) )
            return false;
        bytevec_t b;
        if ( nn.getblob(&b, 0, HD_TAG) <= 0 )
            return false;
        const uchar *p = b.begin(), *end = b.end();
        uint32_t ver = 0, n = 0;
        if ( end - p < 8 )
            return false;
        memcpy(&ver, p, 4);
        memcpy(&n, p + 4, 4);
        p += 8;
        if ( ver != HD_VERSION )
            return false;
        // Built aside, so a truncated blob yields nothing rather than a
        // prefix that would look complete.
        std::vector<HandleRecord> v;
        for ( uint32_t i = 0; i < n; i++ )
        {
            HandleRecord h;
            uint64_t words[5];
            uint32_t small[2];
            if ( end - p < (ptrdiff_t)(sizeof(words) + sizeof(small)) )
                return false;
            memcpy(words, p, sizeof(words));
            p += sizeof(words);
            memcpy(small, p, sizeof(small));
            p += sizeof(small);
            h.handle = words[0];
            h.opened = Position{ words[1], words[2] };
            h.closed = Position{ words[3], words[4] };
            h.access = small[0];
            h.tid    = small[1];
            if ( !get_str(&p, end, &h.type) || !get_str(&p, end, &h.name) || !get_str(&p, end, &h.opened_by) )
                return false;
            v.push_back(std::move(h));
        }
        *out = std::move(v);
        return true;
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

        // x64 syscall convention wherever syscalls came from 64-bit code:
        // always on Sogen, which runs WoW64's 64-bit side itself. A Microsoft
        // x86 recording has only the 32-bit side, with arguments on the stack.
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
            StageSink regs_stage(sink, 0, 30);
            QueryResult rq = b->registers_at(where, &regs, &regs_stage);
            if ( regs_stage.cancelled() || rq.cancelled )
            {
                r.cancelled = true;
                return r;
            }
            // Without the registers, or a cursor to read the arguments with,
            // the list would come out empty and be saved as complete: report
            // the run as failed instead, so nothing is kept.
            if ( !rq.ran || regs.size() != where.size() )
            {
                r.ran = false;
                return r;
            }

            BatchedMemory mem;
            Reader rd(wide);
            auto arg = [&](const ittd_regs &g, int n) -> uint64_t
            {
                if ( wide )
                {
                    if ( n < 4 )
                        return g.gp[SYSCALL_ARG_REGS[n]];
                    return rd.ptr(g.gp[ITTD_REG_RSP] + 0x28 + 8 * (n - 4));
                }
                // [esp] returns into the stub, [esp+4] is the stub's own return.
                return rd.ptr(g.gp[ITTD_REG_RSP] + 8 + 4 * (uint64_t)n);
            };

            // ---- 1: what each call names, and where its handles go -----------
            //
            // Names and arguments are read at the call. The handles are out
            // parameters, resolved together below: on Microsoft TTD the
            // kernel's write surfaces only where the program reads it.
            struct Pending
            {
                enum Kind { Close, Open, Dup } kind = Open;
                HandleRecord rec;               // all but the handle
                int          slot = -1;         // index into 'slots'
                HandleRecord rec2;              // NtCreateUserProcess: its thread
                int          slot2 = -1;
                // Where the call's handles go, and what was there before:
                // read during the rounds, made into slots once they are done.
                uint64_t     out_addr = 0, out_before = 0;
                uint64_t     out2_addr = 0, out2_before = 0;
                uint64_t     handle = 0;        // Close: the handle
                uint64_t     root = 0;          // the name is relative to this handle
                uint64_t     file = 0;          // a section's file handle
                bool         dup_from_us = false, dup_close_source = false, dup_into_us = false;
                uint64_t     dup_src = 0;
            };
            std::vector<Pending> pend;
            std::vector<OutSlot> slots;
            std::vector<Pending> per_call(idx.size());
            std::vector<char>    made(idx.size(), 0);
            // One call, decoded afresh each round (decode_in_rounds runs it
            // again once the memory it missed has been fetched).
            auto decode_call = [&](size_t k)
            {
                const SyscallEvent &sc = calls[idx[k]];
                const ittd_regs &g = regs[k];
                rd.use(mem.reader(sc.pos));
                auto add_slot = [&](uint64_t addr, uint64_t *where, uint64_t *before) -> int
                {
                    *where  = addr;
                    *before = addr != 0 ? rd.ptr(addr) : 0;
                    return addr != 0 ? 0 : -1;      // numbered once the rounds are done
                };

                Pending p;
                p.rec.opened    = sc.pos;
                p.rec.opened_by = sc.name;
                p.rec.tid       = sc.tid;
                if ( sc.name == "NtClose" )
                {
                    p.kind   = Pending::Close;
                    p.handle = arg(g, 0);
                    p.rec.closed = sc.pos;
                }
                else if ( sc.name == "NtDuplicateObject" )
                {
                    const uint64_t src_proc = arg(g, 0), dst_proc = arg(g, 2);
                    p.kind             = Pending::Dup;
                    p.dup_src          = arg(g, 1);
                    p.dup_from_us      = is_current_process(src_proc);
                    p.dup_close_source = p.dup_from_us && (arg(g, 6) & 1) != 0;   // DUPLICATE_CLOSE_SOURCE
                    p.dup_into_us      = is_current_process(dst_proc);
                    p.rec.access       = (uint32_t)arg(g, 4);
                    if ( !p.dup_from_us )
                        p.rec.name.sprnt("handle 0x%llX of another process", (unsigned long long)p.dup_src);
                    if ( p.dup_into_us )
                        p.slot = add_slot(arg(g, 3), &p.out_addr, &p.out_before);
                }
                else if ( sc.name == "NtCreateUserProcess" )
                {
                    // Two handles, process and first thread, named after the
                    // image (RTL_USER_PROCESS_PARAMETERS.ImagePathName).
                    const uint64_t params = arg(g, 8);
                    const qstring image = rd.ustr(params != 0 ? params + (wide ? 0x60 : 0x38) : 0);
                    p.rec.type   = "Process";
                    p.rec.name   = image;
                    p.rec.access = (uint32_t)arg(g, 2);
                    p.rec2       = p.rec;
                    p.rec2.type   = "Thread";
                    p.rec2.access = (uint32_t)arg(g, 3);
                    if ( !image.empty() )
                        p.rec2.name = qstring("first thread of ") + image;
                    p.slot  = add_slot(arg(g, 0), &p.out_addr, &p.out_before);
                    p.slot2 = add_slot(arg(g, 1), &p.out2_addr, &p.out2_before);
                }
                else
                {
                    const Maker *m = maker_of(sc.name);
                    HandleRecord &hr = p.rec;
                    hr.type = m->type;
                    if ( m->access >= 0 )
                        hr.access = (uint32_t)arg(g, m->access);
                    if ( m->attrs >= 0 )
                        hr.name = rd.oa_name(arg(g, m->attrs), &p.root);
                    if ( sc.name == "NtAlpcConnectPort" || sc.name == "NtConnectPort" || sc.name == "NtSecureConnectPort" )
                        hr.name = rd.ustr(arg(g, 1));
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
                        p.file = arg(g, 6);
                    if ( hr.type == "File" )
                    {
                        const qstring l = lower(hr.name);
                        if ( l.find("\\device\\afd") == 0 )
                            hr.type = "Socket";
                        else if ( l.find("\\pipe\\") != qstring::npos || l.find("\\device\\namedpipe") == 0 )
                            hr.type = "Pipe";
                    }
                    p.slot = add_slot(arg(g, m->out), &p.out_addr, &p.out_before);
                }
                per_call[k] = std::move(p);
                made[k]     = 1;
            };
            std::vector<size_t> with_regs;
            for ( size_t k = 0; k < idx.size(); k++ )
                if ( k < regs.size() && (regs[k].have & ITTD_REGS_GP) != 0 )
                    with_regs.push_back(k);
            if ( !decode_in_rounds(mem, b, sink, with_regs, decode_call, 30, 60) )
            {
                r.cancelled = true;
                return r;
            }
            // The out slots, numbered in call order now that each call's
            // reads are final.
            auto number_slot = [&](const SyscallEvent &sc, uint64_t addr, uint64_t before) -> int
            {
                if ( addr == 0 )
                    return -1;
                OutSlot s;
                s.call   = sc.pos;
                s.addr   = (ea_t)addr;
                s.before = before;
                s.tid    = sc.tid;
                s.width  = (uint32_t)rd.ptr_size();
                slots.push_back(s);
                return (int)slots.size() - 1;
            };
            for ( size_t k = 0; k < idx.size(); k++ )
            {
                if ( !made[k] )
                    continue;
                Pending &p = per_call[k];
                const SyscallEvent &sc = calls[idx[k]];
                p.slot  = p.slot  >= 0 ? number_slot(sc, p.out_addr, p.out_before) : -1;
                p.slot2 = p.slot2 >= 0 ? number_slot(sc, p.out2_addr, p.out2_before) : -1;
                pend.push_back(std::move(p));
            }

            // ---- 2: the handles the calls wrote back ---------------------------
            std::vector<std::optional<uint64_t>> values;
            StageSink outs_stage(sink, 60, 100);
            if ( !b->query_out_values(slots, &values, &outs_stage) )
            {
                // The backend has the kernel's writes where they happen: read
                // the slot one position after the call, batched like the rest.
                values.assign(slots.size(), std::nullopt);
                std::vector<size_t> all(slots.size());
                std::vector<Position> one_on(slots.size());
                for ( size_t i = 0; i < slots.size(); i++ )
                {
                    all[i]    = i;
                    one_on[i] = b->position_add(slots[i].call, 1);
                }
                decode_in_rounds(mem, b, &outs_stage, all, [&](size_t i)
                {
                    rd.use(mem.reader(one_on[i]));
                    uint64_t v = 0;
                    if ( rd.read(slots[i].addr, &v, rd.ptr_size()) )
                        values[i] = v;
                    else
                        values[i] = std::nullopt;
                }, 0, 100);
            }
            if ( sink != nullptr && sink->cancelled() )
            {
                r.cancelled = true;
                return r;
            }
            auto value_of = [&](int slot) -> uint64_t
            {
                return slot >= 0 && (size_t)slot < values.size() && values[slot].has_value() ? *values[slot] : 0;
            };

            // ---- 3: opened and closed, in order --------------------------------
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
                // Never seen opened: from before the recording, or its handle
                // could not be recovered.
                HandleRecord hr;
                hr.handle = h;
                hr.type   = "(opened before the recording)";
                hr.closed = p;
                recs.push_back(hr);
            };
            auto open = [&](HandleRecord hr)
            {
                if ( hr.handle == 0 )
                    return;
                // A live value reused without a seen close: the newer wins.
                live[hr.handle] = recs.size();
                recs.push_back(std::move(hr));
            };
            for ( Pending &p : pend )
            {
                switch ( p.kind )
                {
                    case Pending::Close:
                        close(p.handle, p.rec.closed);
                        break;
                    case Pending::Dup:
                        if ( p.dup_from_us )
                            if ( const HandleRecord *s = name_of(p.dup_src) )
                            {
                                p.rec.type = s->type;
                                p.rec.name = s->name;
                            }
                        if ( p.dup_close_source )
                            close(p.dup_src, p.rec.opened);
                        if ( p.dup_into_us )
                        {
                            if ( p.rec.type.empty() )
                                p.rec.type = "(duplicated)";
                            p.rec.handle = value_of(p.slot);
                            open(p.rec);
                        }
                        break;
                    case Pending::Open:
                        if ( !p.rec.name.empty() && p.rec.name[0] != '\\' && p.root != 0 )
                        {
                            // Relative to a directory or key opened earlier.
                            if ( const HandleRecord *base = name_of(p.root) )
                                if ( !base->name.empty() )
                                    p.rec.name = base->name + "\\" + p.rec.name;
                        }
                        if ( p.file != 0 && p.rec.name.empty() )
                            if ( const HandleRecord *f = name_of(p.file) )
                                p.rec.name = f->name;     // an image or file section
                        p.rec.handle = value_of(p.slot);
                        open(p.rec);
                        if ( p.slot2 >= 0 )
                        {
                            p.rec2.handle = value_of(p.slot2);
                            open(p.rec2);
                        }
                        break;
                }
            }
            *out = std::move(recs);
            return r;
        });
        if ( qr.cancelled )
            *cancelled = true;
        else if ( qr.ran )
            save_handles(*out);
        return qr.ran;
    }
}
