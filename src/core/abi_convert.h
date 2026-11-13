#pragma once

#include "common/pch.h"
#include "core/backend.h"

#include <cstddef>
#include <cstring>

// The conversions between the core's types (core/backend.h) and the C ABI's
// (abi/ida_ttd_backend.h), each written once and used by both sides of the
// boundary: abi_export.cpp turns a C++ backend's answers into ABI structs
// (to_abi), and backend_module.cpp turns a DLL's ABI structs back into core
// types (from_abi). A field added to one direction is then next to its
// partner, rather than in another file.
//
// Where the two directions are not mirror images (a clamp, a default, a
// field one side fills and the other ignores) the difference is the
// historical behaviour of that side, kept on purpose and said at the pair.
//
// Header-only and free of ida.lib calls beyond what qstring needs: the MS
// backend, which does not link ida.lib, includes it through abi_export.cpp.

namespace idattd
{
    // ---------------------------------------------------------------- strings

    // Into a fixed-size ABI field, cut to fit and always terminated. Not
    // qstrncpy: this is built into a backend that does not link ida.dll.
    inline void copy_str(char *dst, size_t cap, const char *src)
    {
        if ( cap == 0 )
            return;
        size_t n = src != nullptr ? strlen(src) : 0;
        if ( n >= cap )
            n = cap - 1;
        if ( n != 0 )
            memcpy(dst, src, n);
        dst[n] = '\0';
    }

    template <size_t N>
    inline void copy_str(char (&dst)[N], const qstring &src)
    {
        copy_str(dst, N, src.c_str());
    }

    // A fixed-size string field of an ABI struct, read without trusting the
    // NUL: a backend that filled it to the brim must not make the core read
    // past the struct.
    template <size_t N>
    inline qstring fixed_str(const char (&s)[N])
    {
        return qstring(s, strnlen(s, N));
    }

    // ---------------------------------------------------------------- positions

    // The core's Position and the ABI's ittd_position are the same two words
    // with the same three sentinels, so the conversion is a copy.
    inline ittd_position to_abi(Position p) { return ittd_position{ p.hi, p.lo }; }
    inline Position from_abi(ittd_position p) { return Position{ p.hi, p.lo }; }

    inline ittd_position_range to_abi(PositionRange r)
    {
        return ittd_position_range{ to_abi(r.first), to_abi(r.last) };
    }
    inline PositionRange from_abi(ittd_position_range r)
    {
        return PositionRange{ from_abi(r.first), from_abi(r.last) };
    }

    // ---------------------------------------------------------------- address ranges

    inline ittd_range to_abi(const std::pair<ea_t, ea_t> &r)
    {
        return ittd_range{ (uint64_t)r.first, (uint64_t)r.second };
    }
    inline std::pair<ea_t, ea_t> from_abi(const ittd_range &r)
    {
        return { (ea_t)r.start, (ea_t)r.end };
    }

    inline std::vector<ittd_range> to_abi(const std::vector<std::pair<ea_t, ea_t>> &ranges)
    {
        std::vector<ittd_range> r;
        r.reserve(ranges.size());
        for ( const auto &p : ranges )
            r.push_back(to_abi(p));
        return r;
    }
    inline std::vector<std::pair<ea_t, ea_t>> from_abi(const ittd_range *ranges, size_t n)
    {
        std::vector<std::pair<ea_t, ea_t>> r;
        r.reserve(n);
        for ( size_t i = 0; i < n; i++ )
            r.push_back(from_abi(ranges[i]));
        return r;
    }

    // ---------------------------------------------------------------- access kinds

    // A set of AccessKind bits as ITTD_ACCESS_* bits, and back.
    inline uint32_t to_abi_kinds(uint8_t kinds)
    {
        return ((kinds & ACCESS_READ)  ? ITTD_ACCESS_READ  : 0)
             | ((kinds & ACCESS_WRITE) ? ITTD_ACCESS_WRITE : 0)
             | ((kinds & ACCESS_EXEC)  ? ITTD_ACCESS_EXEC  : 0);
    }
    inline uint8_t from_abi_kinds(uint32_t k)
    {
        return (uint8_t)(((k & ITTD_ACCESS_READ)  ? ACCESS_READ  : 0)
                       | ((k & ITTD_ACCESS_WRITE) ? ACCESS_WRITE : 0)
                       | ((k & ITTD_ACCESS_EXEC)  ? ACCESS_EXEC  : 0));
    }

    // One access's kind: a single value each way. Not mirror images: going
    // out, a core kind with several bits set gives the first of read, write,
    // execute (and none gives execute); coming in, anything but exactly
    // read or write is execute.
    inline uint32_t to_abi_kind(uint8_t k)
    {
        return (k & ACCESS_READ) ? ITTD_ACCESS_READ : (k & ACCESS_WRITE) ? ITTD_ACCESS_WRITE : ITTD_ACCESS_EXEC;
    }
    inline uint8_t from_abi_kind(uint32_t k)
    {
        return k == ITTD_ACCESS_READ  ? ACCESS_READ
             : k == ITTD_ACCESS_WRITE ? ACCESS_WRITE : ACCESS_EXEC;
    }

    // ---------------------------------------------------------------- stop reasons

    inline int to_abi(StopReason r)
    {
        switch ( r )
        {
            case StopReason::Stepped:       return ITTD_STOP_STEPPED;
            case StopReason::Breakpoint:    return ITTD_STOP_BREAKPOINT;
            case StopReason::TraceBoundary: return ITTD_STOP_BOUNDARY;
            default:                        return ITTD_STOP_FAILED;
        }
    }
    inline StopReason stop_from_abi(int stop)
    {
        switch ( stop )
        {
            case ITTD_STOP_STEPPED:    return StopReason::Stepped;
            case ITTD_STOP_BREAKPOINT: return StopReason::Breakpoint;
            case ITTD_STOP_BOUNDARY:   return StopReason::TraceBoundary;
            default:                   return StopReason::Failed;
        }
    }

    // ---------------------------------------------------------------- trace info

    // The capability bits are converted on their own: ITTD_CAP_PREPARE comes
    // from prepared(), not from Capabilities, and the core also requires the
    // table entries some bits promise (backend_module.cpp).
    inline uint32_t to_abi(const Capabilities &c)
    {
        uint32_t caps = 0;
        if ( c.access_queries )   caps |= ITTD_CAP_ACCESS_QUERIES;
        if ( c.call_queries )     caps |= ITTD_CAP_CALL_QUERIES;
        if ( c.mapping_changes )  caps |= ITTD_CAP_MAPPING_CHANGES;
        if ( c.syscalls )         caps |= ITTD_CAP_SYSCALLS;
        if ( c.recorded_exports ) caps |= ITTD_CAP_RECORDED_EXPORTS;
        if ( c.batch_regs )       caps |= ITTD_CAP_BATCH_REGS;
        if ( c.reverse_step )     caps |= ITTD_CAP_REVERSE_STEP;
        if ( c.exceptions )       caps |= ITTD_CAP_EXCEPTIONS;
        if ( c.self_modifying )   caps |= ITTD_CAP_SELF_MODIFYING;
        if ( c.fork )             caps |= ITTD_CAP_FORK;
        if ( c.replay_scans )     caps |= ITTD_CAP_REPLAY_SCANS;
        if ( c.cheap_reads )      caps |= ITTD_CAP_CHEAP_READS;
        return caps;
    }
    inline Capabilities caps_from_abi(uint32_t c)
    {
        Capabilities x;
        x.access_queries   = (c & ITTD_CAP_ACCESS_QUERIES) != 0;
        x.call_queries     = (c & ITTD_CAP_CALL_QUERIES) != 0;
        x.mapping_changes  = (c & ITTD_CAP_MAPPING_CHANGES) != 0;
        x.syscalls         = (c & ITTD_CAP_SYSCALLS) != 0;
        x.recorded_exports = (c & ITTD_CAP_RECORDED_EXPORTS) != 0;
        x.batch_regs       = (c & ITTD_CAP_BATCH_REGS) != 0;
        x.reverse_step     = (c & ITTD_CAP_REVERSE_STEP) != 0;
        x.exceptions       = (c & ITTD_CAP_EXCEPTIONS) != 0;
        x.self_modifying   = (c & ITTD_CAP_SELF_MODIFYING) != 0;
        x.fork             = (c & ITTD_CAP_FORK) != 0;
        x.replay_scans     = (c & ITTD_CAP_REPLAY_SCANS) != 0;
        x.cheap_reads      = (c & ITTD_CAP_CHEAP_READS) != 0;
        return x;
    }

    // Everything but 'capabilities', which the caller fills (above).
    inline ittd_trace_info to_abi(const TraceInfo &ti)
    {
        ittd_trace_info x{};
        x.is64        = ti.is64 ? 1 : 0;
        x.fingerprint = ti.fingerprint;
        x.first       = to_abi(ti.first);
        x.last        = to_abi(ti.last);
        copy_str(x.main_module, ti.main_module);
        copy_str(x.backend_name, ti.backend_name);
        return x;
    }
    inline TraceInfo from_abi(const ittd_trace_info &x)
    {
        TraceInfo ti;
        ti.is64         = x.is64 != 0;
        ti.fingerprint  = x.fingerprint;
        ti.first        = from_abi(x.first);
        ti.last         = from_abi(x.last);
        ti.main_module  = fixed_str(x.main_module);
        ti.backend_name = fixed_str(x.backend_name);
        return ti;
    }

    // ---------------------------------------------------------------- modules, threads, timeline

    inline ittd_module to_abi(const ModuleInfo &m)
    {
        ittd_module x{};
        x.base      = (uint64_t)m.base;
        x.size      = m.size;
        x.loaded    = to_abi(m.loaded);
        x.unloaded  = to_abi(m.unloaded);
        x.machine   = m.machine;
        x.timestamp = m.timestamp;
        x.checksum  = m.checksum;
        copy_str(x.name, m.name);
        copy_str(x.path, m.path);
        return x;
    }
    // The ABI's machine is 32 bits wide; the core keeps the PE header's 16.
    inline ModuleInfo from_abi(const ittd_module &m)
    {
        ModuleInfo mi;
        mi.base      = (ea_t)m.base;
        mi.size      = m.size;
        mi.name      = fixed_str(m.name);
        mi.path      = fixed_str(m.path);
        mi.loaded    = from_abi(m.loaded);
        mi.unloaded  = from_abi(m.unloaded);
        mi.machine   = (uint16_t)m.machine;
        mi.timestamp = m.timestamp;
        mi.checksum  = m.checksum;
        return mi;
    }

    inline ittd_thread to_abi(const ThreadInfo &t)
    {
        ittd_thread x{};
        x.tid         = t.tid;
        x.created     = to_abi(t.created);
        x.exited      = to_abi(t.exited);
        x.teb         = (uint64_t)t.teb;
        x.teb32       = (uint64_t)t.teb32;
        x.stack_base  = (uint64_t)t.stack_base;
        x.stack_limit = (uint64_t)t.stack_limit;
        copy_str(x.name, t.name);
        return x;
    }
    inline ThreadInfo from_abi(const ittd_thread &t)
    {
        ThreadInfo ti;
        ti.tid         = t.tid;
        ti.created     = from_abi(t.created);
        ti.exited      = from_abi(t.exited);
        ti.name        = fixed_str(t.name);
        ti.teb         = (ea_t)t.teb;
        ti.teb32       = (ea_t)t.teb32;
        ti.stack_base  = (ea_t)t.stack_base;
        ti.stack_limit = (ea_t)t.stack_limit;
        return ti;
    }

    inline ittd_trace_event to_abi(const TraceEvent &e)
    {
        ittd_trace_event x{};
        x.pos  = to_abi(e.pos);
        x.kind = e.kind;
        x.tid  = e.tid;
        copy_str(x.text, e.what);
        return x;
    }
    inline TraceEvent from_abi(const ittd_trace_event &e)
    {
        TraceEvent te;
        te.pos  = from_abi(e.pos);
        te.what = fixed_str(e.text);
        te.kind = e.kind;
        te.tid  = e.tid;
        return te;
    }

    inline ittd_symbol to_abi(const ITraceBackend::Symbol &s)
    {
        ittd_symbol x{};
        x.ea        = (uint64_t)s.ea;
        x.is_export = s.is_export ? 1 : 0;
        copy_str(x.name, s.name);
        return x;
    }
    inline ITraceBackend::Symbol from_abi(const ittd_symbol &s)
    {
        ITraceBackend::Symbol sym;
        sym.ea        = (ea_t)s.ea;
        sym.name      = fixed_str(s.name);
        sym.is_export = s.is_export != 0;
        return sym;
    }

    inline ittd_name to_abi_name(const qstring &s)
    {
        ittd_name n{};
        copy_str(n.name, s);
        return n;
    }
    inline qstring from_abi(const ittd_name &n)
    {
        return fixed_str(n.name);
    }

    // ---------------------------------------------------------------- breakpoints

    // Both directions read a size of 0 as 1.
    inline ittd_breakpoint to_abi(const Breakpoint &b)
    {
        ittd_breakpoint x{};
        x.addr  = (uint64_t)b.addr;
        x.size  = b.size == 0 ? 1 : b.size;
        x.kinds = to_abi_kinds(b.kinds);
        return x;
    }
    inline Breakpoint from_abi(const ittd_breakpoint &x)
    {
        Breakpoint b;
        b.addr  = (ea_t)x.addr;
        b.size  = x.size == 0 ? 1 : x.size;
        b.kinds = from_abi_kinds(x.kinds);
        return b;
    }

    // ---------------------------------------------------------------- query answers

    // BADADDR becomes ITTD_BADADDR going out; coming in the two addresses are
    // plain casts (the same value where ea_t is 64 bits). The kind is one
    // value each way (to_abi_kind, from_abi_kind).
    inline ittd_access to_abi(const Access &a)
    {
        ittd_access x{};
        x.pos  = to_abi(a.pos);
        x.pc   = a.pc == BADADDR ? ITTD_BADADDR : (uint64_t)a.pc;
        x.addr = a.addr == BADADDR ? ITTD_BADADDR : (uint64_t)a.addr;
        x.size = a.size;
        x.kind = to_abi_kind(a.kind);
        x.tid  = a.tid;
        return x;
    }
    inline Access from_abi(const ittd_access &a)
    {
        Access x;
        x.pos  = from_abi(a.pos);
        x.tid  = a.tid;
        x.pc   = (ea_t)a.pc;
        x.addr = (ea_t)a.addr;
        x.size = a.size;
        x.kind = from_abi_kind(a.kind);
        return x;
    }

    // The site maps BADADDR both ways; the target is a plain cast both ways.
    inline ittd_call to_abi(const CallEvent &e)
    {
        ittd_call x{};
        x.pos       = to_abi(e.pos);
        x.entry_pos = to_abi(e.entry_pos);
        x.ret_pos   = to_abi(e.ret_pos);
        x.site      = e.site == BADADDR ? ITTD_BADADDR : (uint64_t)e.site;
        x.target    = (uint64_t)e.target;
        x.tid       = e.tid;
        x.flags     = e.is_call ? 0 : ITTD_CALL_F_NOT_CALL;
        return x;
    }
    inline CallEvent from_abi(const ittd_call &c)
    {
        CallEvent e;
        e.pos       = from_abi(c.pos);
        e.entry_pos = from_abi(c.entry_pos);
        e.ret_pos   = from_abi(c.ret_pos);
        e.tid       = c.tid;
        e.site      = c.site == ITTD_BADADDR ? BADADDR : (ea_t)c.site;
        e.target    = (ea_t)c.target;
        e.is_call   = (c.flags & ITTD_CALL_F_NOT_CALL) == 0;
        return e;
    }

    // The core keeps targets grouped by site, so the site travels beside the
    // IndirectTarget rather than in it.
    inline ittd_call_target to_abi(ea_t site, const IndirectTarget &t)
    {
        ittd_call_target x{};
        x.site      = (uint64_t)site;
        x.target    = (uint64_t)t.target;
        x.hits      = t.hits;
        x.first_pos = to_abi(t.first);
        x.flags     = t.is_call ? 0 : ITTD_CALL_F_NOT_CALL;
        return x;
    }
    inline IndirectTarget from_abi(const ittd_call_target &c)
    {
        IndirectTarget t;
        t.target  = (ea_t)c.target;
        t.hits    = c.hits;
        t.first   = from_abi(c.first_pos);
        t.is_call = (c.flags & ITTD_CALL_F_NOT_CALL) == 0;
        return t;
    }

    inline ittd_exception to_abi(const ExceptionEvent &e)
    {
        ittd_exception x{};
        x.pos            = to_abi(e.pos);
        x.raise_pos      = to_abi(e.raise_pos);
        x.address        = (uint64_t)e.address;
        x.information[0] = e.information[0];
        x.information[1] = e.information[1];
        x.code           = e.code;
        x.flags          = e.flags;
        x.tid            = e.tid;
        return x;
    }
    inline ExceptionEvent from_abi(const ittd_exception &x)
    {
        ExceptionEvent e;
        e.pos            = from_abi(x.pos);
        e.raise_pos      = from_abi(x.raise_pos);
        e.tid            = x.tid;
        e.code           = x.code;
        e.flags          = x.flags;
        e.address        = (ea_t)x.address;
        e.information[0] = x.information[0];
        e.information[1] = x.information[1];
        return e;
    }

    inline ittd_syscall to_abi(const SyscallEvent &e)
    {
        ittd_syscall x{};
        x.pos    = to_abi(e.pos);
        x.result = e.result;
        x.number = e.number;
        x.tid    = e.tid;
        copy_str(x.name, e.name);
        return x;
    }
    inline SyscallEvent from_abi(const ittd_syscall &x)
    {
        SyscallEvent e;
        e.pos    = from_abi(x.pos);
        e.result = x.result;
        e.number = x.number;
        e.tid    = x.tid;
        e.name   = fixed_str(x.name);
        return e;
    }

    inline ittd_string_hit to_abi(const StringHit &e)
    {
        ittd_string_hit x{};
        x.address = (uint64_t)e.address;
        x.pos     = to_abi(e.pos);
        x.wide    = e.wide ? 1 : 0;
        x.length  = e.length;
        copy_str(x.text, e.text);
        return x;
    }
    inline StringHit from_abi(const ittd_string_hit &x)
    {
        StringHit h;
        h.address = (ea_t)x.address;
        h.pos     = from_abi(x.pos);
        h.wide    = x.wide != 0;
        h.length  = x.length;
        h.text    = fixed_str(x.text);
        return h;
    }

    inline ittd_buffer_hit to_abi(const BufferHit &e)
    {
        ittd_buffer_hit x{};
        x.address   = (uint64_t)e.address;
        x.size      = e.size;
        x.first_pos = to_abi(e.first_pos);
        x.last_pos  = to_abi(e.last_pos);
        x.writer_ip = (uint64_t)e.writer_ip;
        x.writes    = e.writes;
        copy_str(x.kind, e.kind);
        copy_str(x.preview, e.preview);
        return x;
    }
    inline BufferHit from_abi(const ittd_buffer_hit &x)
    {
        BufferHit h;
        h.address   = (ea_t)x.address;
        h.size      = x.size;
        h.first_pos = from_abi(x.first_pos);
        h.last_pos  = from_abi(x.last_pos);
        h.writer_ip = (ea_t)x.writer_ip;
        h.writes    = x.writes;
        h.kind      = fixed_str(x.kind);
        h.preview   = fixed_str(x.preview);
        return h;
    }

    inline ittd_selfmod to_abi(const SelfModHit &e)
    {
        ittd_selfmod x{};
        x.address     = (uint64_t)e.address;
        x.size        = e.size;
        x.write_pos   = to_abi(e.write_pos);
        x.write_ip    = (uint64_t)e.write_ip;
        x.execute_pos = to_abi(e.execute_pos);
        x.executions  = e.executions;
        return x;
    }
    inline SelfModHit from_abi(const ittd_selfmod &x)
    {
        SelfModHit h;
        h.address     = (ea_t)x.address;
        h.size        = x.size;
        h.write_pos   = from_abi(x.write_pos);
        h.write_ip    = (ea_t)x.write_ip;
        h.execute_pos = from_abi(x.execute_pos);
        h.executions  = x.executions;
        return h;
    }

    inline ittd_heat_cell to_abi(const HeatCell &c)
    {
        ittd_heat_cell x{};
        x.page     = c.page;
        x.slice    = c.slice;
        x.reads    = c.reads;
        x.writes   = c.writes;
        x.executes = c.executes;
        return x;
    }
    inline HeatCell from_abi(const ittd_heat_cell &x)
    {
        HeatCell c;
        c.page     = x.page;
        c.slice    = x.slice;
        c.reads    = x.reads;
        c.writes   = x.writes;
        c.executes = x.executes;
        return c;
    }

    // ---------------------------------------------------------------- batch inputs

    inline ittd_out_slot to_abi(const OutSlot &s)
    {
        ittd_out_slot x{};
        x.call   = to_abi(s.call);
        x.addr   = (uint64_t)s.addr;
        x.before = s.before;
        x.tid    = s.tid;
        x.width  = s.width;
        return x;
    }
    inline OutSlot from_abi(const ittd_out_slot &x)
    {
        OutSlot s;
        s.call   = from_abi(x.call);
        s.addr   = (ea_t)x.addr;
        s.before = x.before;
        s.tid    = x.tid;
        s.width  = x.width;
        return s;
    }

    inline ittd_mem_read to_abi(const MemAt &m)
    {
        ittd_mem_read x{};
        x.pos    = to_abi(m.pos);
        x.addr   = (uint64_t)m.addr;
        x.offset = (uint64_t)m.offset;
        x.size   = (uint64_t)m.size;
        return x;
    }
    inline MemAt from_abi(const ittd_mem_read &x)
    {
        MemAt m;
        m.pos    = from_abi(x.pos);
        m.addr   = (ea_t)x.addr;
        m.offset = (size_t)x.offset;
        m.size   = (size_t)x.size;
        return m;
    }

    // ---------------------------------------------------------------- replay settings

    // Going out, an empty path is NULL, 'size' is the whole struct, and the
    // log callback and its context are the caller's (backend_module.cpp
    // owns the emulator log). Coming in, each group of fields is read only
    // when 'size' covers it, NULL settings or a NULL path read as empty, and
    // the callback becomes only RecordOptions::log ("there is one"):
    // log_ctx is not kept and log_tail is never set, since the C++ backend
    // gets no callback of its own to call.
    // The settings point into 'registry_dir' and 'root', which must outlive
    // them.
    using AbiLogFn = void (*)(void *log_ctx, const char *line);

    inline ittd_fork_settings to_abi_settings(const qstring &registry_dir, const qstring &root, bool strict,
                                              bool allow_host, bool any_registry, const RecordOptions &rec,
                                              AbiLogFn log, void *log_ctx)
    {
        ittd_fork_settings fs{};
        fs.size  = sizeof(fs);
        fs.flags = (strict ? ITTD_FORK_STRICT : 0) | (allow_host ? ITTD_FORK_ALLOW_HOST : 0)
                 | (any_registry ? ITTD_FORK_ANY_REGISTRY : 0);
        fs.registry_dir   = registry_dir.empty() ? nullptr : registry_dir.c_str();
        fs.emulation_root = root.empty() ? nullptr : root.c_str();
        fs.network        = rec.network ? ITTD_NET_LIVE : ITTD_NET_OFFLINE;
        fs.access_mask    = rec.access_mask;
        fs.checkpoint_interval = rec.checkpoint_interval;
        fs.elevated       = rec.elevated ? 1 : 0;
        fs.log            = log;
        fs.log_ctx        = log_ctx;
        return fs;
    }
    inline ReplaySettings from_abi(const ittd_fork_settings *s)
    {
        // Each field only when the caller's struct is new enough to carry it.
        auto has = [s](size_t offset, size_t size) { return s != nullptr && offset + size <= s->size; };
        ReplaySettings rs;
        if ( has(offsetof(ittd_fork_settings, emulation_root), sizeof(s->emulation_root)) )
        {
            rs.registry_dir   = s->registry_dir != nullptr ? s->registry_dir : "";
            rs.emulation_root = s->emulation_root != nullptr ? s->emulation_root : "";
            rs.strict         = (s->flags & ITTD_FORK_STRICT) != 0;
            rs.allow_host     = (s->flags & ITTD_FORK_ALLOW_HOST) != 0;
            rs.any_registry   = (s->flags & ITTD_FORK_ANY_REGISTRY) != 0;
        }
        if ( has(offsetof(ittd_fork_settings, log_ctx), sizeof(s->log_ctx)) )
        {
            rs.rec.network             = s->network == ITTD_NET_LIVE;
            rs.rec.access_mask         = s->access_mask;
            rs.rec.checkpoint_interval = s->checkpoint_interval;
            rs.rec.elevated            = s->elevated != 0;
            rs.rec.log                 = s->log != nullptr;
        }
        return rs;
    }
}
