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
    namespace
    {
        // Guest memory at many positions, fetched from the backend in
        // batches (ITraceBackend::read_memory_at) instead of by seeking a
        // cursor to each: on Microsoft TTD a seek costs about 15 ms, and
        // decoding a recording's syscalls one seek at a time took minutes.
        // A decoder reads through reader(), which serves what has been
        // fetched and notes what has not; fetch() gets all of that at once,
        // and the decoder runs again over the calls that missed something.
        // A pointer followed to a structure followed to a string is three
        // rounds.
        class BatchedMemory
        {
        public:
            GuestRead reader(Position at)
            {
                return [this, at](uint64_t addr, void *buf, size_t size) -> size_t
                {
                    return read(at, addr, buf, size);
                };
            }

            // How many blocks reads have asked for and not found, ever: a
            // caller compares it before and after a decode.
            uint64_t misses() const { return m_misses; }

            // Everything missed since the last fetch. False when cancelled.
            bool fetch(ITraceBackend *b, ProgressSink *progress)
            {
                if ( m_wanted.empty() )
                    return true;
                std::vector<MemAt> reads;
                reads.reserve(m_wanted.size());
                for ( const Key &k : m_wanted )
                {
                    MemAt m;
                    m.pos    = k.first;
                    m.addr   = (ea_t)(k.second * kBlock);
                    m.offset = reads.size() * kBlock;
                    m.size   = kBlock;
                    reads.push_back(m);
                }
                std::vector<uint8_t> data, known;
                QueryResult r = b->read_memory_at(reads, &data, &known, progress);
                if ( r.cancelled )
                    return false;
                // A block that could not be read is kept as unknown, so it is
                // not asked for again.
                size_t i = 0;
                for ( const Key &k : m_wanted )
                {
                    Block &blk = m_blocks[k];
                    const size_t off = i++ * kBlock;
                    if ( r.ran && off + kBlock <= data.size() )
                    {
                        memcpy(blk.data, data.data() + off, kBlock);
                        memcpy(blk.known, known.data() + off, kBlock);
                    }
                }
                m_wanted.clear();
                return true;
            }

        private:
            static constexpr uint64_t kBlock = 0x100;
            // A read longer than this asks for its first blocks only; the
            // rest come in a later round if it still wants them.
            static constexpr size_t kMaxMissesPerRead = 16;

            struct Block
            {
                uint8_t data[kBlock]  = { 0 };
                uint8_t known[kBlock] = { 0 };      // ITTD_KNOWN_NO
            };
            using Key = std::pair<Position, uint64_t>;      // (where, block number)

            // As guest_read: the leading bytes known (a placeholder counts as
            // a real zero), with buf zero-filled past what is available.
            size_t read(Position at, uint64_t addr, void *buf, size_t size)
            {
                if ( buf == nullptr || size == 0 )
                    return 0;
                memset(buf, 0, size);
                // Not past the top of the address space.
                if ( addr + size < addr )
                    size = (size_t)(0 - addr);
                uint8_t *out = (uint8_t *)buf;
                size_t prefix = 0, missed = 0, off = 0;
                bool whole = true;
                while ( off < size && missed < kMaxMissesPerRead )
                {
                    const uint64_t a       = addr + off;
                    const uint64_t blockno = a / kBlock;
                    const size_t   in      = (size_t)(a % kBlock);
                    const size_t   n       = std::min<size_t>((size_t)kBlock - in, size - off);
                    auto it = m_blocks.find(Key{ at, blockno });
                    if ( it == m_blocks.end() )
                    {
                        m_wanted.insert(Key{ at, blockno });
                        m_misses++;
                        missed++;
                        whole = false;
                    }
                    else
                    {
                        memcpy(out + off, it->second.data + in, n);
                        for ( size_t j = 0; j < n && whole; j++ )
                        {
                            if ( it->second.known[in + j] == ITTD_KNOWN_NO )
                                whole = false;
                            else
                                prefix++;
                        }
                    }
                    off += n;
                }
                return prefix;
            }

            std::map<Key, Block> m_blocks;
            std::set<Key>        m_wanted;
            uint64_t             m_misses = 0;
        };

        // Rounds of fetching before a decode stands with what it has.
        const int kMaxRounds = 8;
    }

    bool decode_syscalls(TraceManager *mgr, const std::vector<SyscallEvent> &calls,
                         std::vector<qstring> *decoded, bool *cancelled)
    {
        decoded->assign(calls.size(), qstring());
        *cancelled = false;
        if ( mgr == nullptr || !mgr->is_active() || mgr->backend() == nullptr )
            return false;
        ITraceBackend *b = mgr->backend();

        // Signatures looked up here on the main thread (loading the index may
        // print), once per name.
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
        // The 64-bit syscall convention: always on Sogen. A Microsoft x86
        // recording has the 32-bit side, with arguments on the stack.
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
            StageSink regs_stage(sink, 0, 10);
            b->registers_at(where, &regs, &regs_stage);
            if ( regs_stage.cancelled() )
            {
                r.cancelled = true;
                return r;
            }
            BatchedMemory mem;

            // Decode 'todo' with 'once', fetching what the decodes missed and
            // decoding again those that missed something, until nothing is
            // missing or the rounds run out. Percentages lo..hi.
            auto in_rounds = [&](std::vector<size_t> todo, const std::function<void(size_t)> &once,
                                 uint32_t lo, uint32_t hi) -> bool
            {
                for ( int round = 0; !todo.empty(); round++ )
                {
                    std::vector<size_t> again;
                    for ( size_t n = 0; n < todo.size(); n++ )
                    {
                        if ( (n & 255) == 0 && sink != nullptr && sink->cancelled() )
                            return false;
                        const uint64_t before = mem.misses();
                        once(todo[n]);
                        if ( mem.misses() != before )
                            again.push_back(todo[n]);
                    }
                    if ( again.empty() || round + 1 == kMaxRounds )
                        break;
                    // The first fetch is most of the work; later ones share
                    // the last fifth of the stage.
                    const uint32_t mid = lo + (hi - lo) * 4 / 5;
                    const uint32_t a = round == 0 ? lo : mid + (hi - mid) * (round - 1) / kMaxRounds;
                    const uint32_t z = round == 0 ? mid : mid + (hi - mid) * round / kMaxRounds;
                    StageSink fetch_stage(sink, a, z);
                    if ( !mem.fetch(b, &fetch_stage) )
                        return false;
                    todo.swap(again);
                }
                return true;
            };

            // ---- the arguments, at each call ----------------------------
            // At the syscall instruction, rcx is in r10 and the stack is one
            // return address deep (two on x86: into the stub, then the stub's
            // own). Shown as the call site sees them, as the decoder expects.
            std::vector<DecodedCall> dc(which.size());
            std::vector<size_t> with_regs;
            for ( size_t k = 0; k < which.size(); k++ )
                if ( k < regs.size() && (regs[k].have & ITTD_REGS_GP) != 0 )
                    with_regs.push_back(k);
            const bool args_done = in_rounds(with_regs, [&](size_t k)
            {
                const SyscallEvent &c = calls[which[k]];
                ittd_regs g = regs[k];
                if ( wide )
                    g.gp[ITTD_REG_RCX] = g.gp[SYSCALL_ARG_REGS[0]];
                g.gp[ITTD_REG_RSP] += 8;
                GuestView v;
                v.read = mem.reader(c.pos);
                v.regs = [g](ittd_regs *out) { *out = g; return true; };
                DecodedCall d;
                decode_api_args(v, *sigs[which[k]], wide, &d);
                dc[k] = std::move(d);
            }, 10, 50);
            if ( !args_done )
            {
                r.cancelled = true;
                return r;
            }

            // ---- what the kernel wrote back -------------------------------
            // Integers and handles from the backend's search where it has one
            // (Microsoft TTD); the rest from memory just after the call.
            std::vector<OutSlot> slots;
            std::vector<std::pair<size_t, size_t>> slot_of;     // (call k, parameter)
            for ( size_t k : with_regs )
            {
                const SyscallEvent &c = calls[which[k]];
                for ( const auto &[param, width] : api_int_outs(dc[k]) )
                {
                    OutSlot s;
                    s.call   = c.pos;
                    s.addr   = (ea_t)dc[k].args[param].raw;
                    s.tid    = c.tid;
                    s.width  = width;
                    s.before = dc[k].args[param].pointee_before.value_or(0);
                    slots.push_back(s);
                    slot_of.emplace_back(k, param);
                }
            }
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

            // ---- the out parameters, just after each call -----------------
            std::vector<DecodedCall> after(dc.size());
            std::vector<size_t> needs_memory;
            for ( size_t k = 0; k < dc.size(); k++ )
            {
                const DecodedCall &d = dc[k];
                if ( d.sig == nullptr )
                    continue;
                bool needs = false;
                for ( size_t p = 0; p < d.args.size(); p++ )
                    if ( d.args[p].out && d.args[p].raw != 0
                      && !(p < d.out_values.size() && d.out_values[p].has_value()) )
                        needs = true;
                if ( needs )
                {
                    needs_memory.push_back(k);
                    continue;
                }
                after[k] = d;
                decode_api_outs(GuestView{}, &after[k]);
            }
            std::vector<Position> one_on(dc.size(), Position::none());
            for ( size_t k : needs_memory )
                one_on[k] = b->position_add(calls[which[k]].pos, 1);
            const bool outs_done = in_rounds(needs_memory, [&](size_t k)
            {
                GuestView v;
                v.read = mem.reader(one_on[k]);
                v.regs = [](ittd_regs *) { return false; };
                after[k] = dc[k];
                decode_api_outs(v, &after[k]);
            }, 75, 100);
            if ( !outs_done )
            {
                r.cancelled = true;
                return r;
            }
            for ( size_t k = 0; k < after.size(); k++ )
                if ( after[k].sig != nullptr )
                    (*decoded)[which[k]] = api_args_text(after[k]);
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
            // A truncated blob yields nothing rather than a prefix that would
            // look complete.
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
