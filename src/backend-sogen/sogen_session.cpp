// SPDX-License-Identifier: GPL-2.0-only
//
// ida-ttd's Sogen backend: the recording as a whole (identity, open,
// info, positions, threads, modules, the timeline, symbols, the replay
// environment) and the cursors.
// See sogen_state.h.

#include "backend-sogen/sogen_state.h"

namespace idattd::sogen
{
    text_slot g_module_error;       // last_error(NULL)

    uint64_t fold_id(const std::string &id)
    {
        // At most 33 ASCII characters: 32 hex digits, or "h" and 32 hex digits
        // for traces older than the stored id. Any 64 of the bits will do;
        // this takes the first 16 digits.
        size_t start = !id.empty() && id[0] == 'h' ? 1 : 0;
        uint64_t v = 0;
        for ( size_t i = start; i < id.size() && i < start + 16; i++ )
        {
            char c = id[i];
            uint64_t d = c >= '0' && c <= '9' ? c - '0'
                       : c >= 'a' && c <= 'f' ? c - 'a' + 10
                       : c >= 'A' && c <= 'F' ? c - 'A' + 10 : 0;
            v = v << 4 | d;
        }
        return v;
    }

    // Every thread with the span it ran over, in the order they first ran.
    std::vector<thread_span> thread_spans(const ttd::trace &t)
    {
        std::map<uint32_t, thread_span> by_tid;
        const auto &sw = t.threads().switches;
        for ( size_t i = 0; i < sw.size(); i++ )
        {
            thread_span &s = by_tid[sw[i].thread_id];
            s.tid = sw[i].thread_id;
            s.first_step = std::min(s.first_step, sw[i].step);
            uint64_t end = i + 1 < sw.size() ? sw[i + 1].step : last_position(t) + 1;
            s.end_step = std::max(s.end_step, end);
            s.running_at_end = i + 1 == sw.size();
        }
        std::vector<thread_span> v;
        v.reserve(by_tid.size());
        for ( auto &[tid, s] : by_tid )
            v.push_back(s);
        std::sort(v.begin(), v.end(), [](const thread_span &a, const thread_span &b)
                  { return a.first_step < b.first_step; });
        return v;
    }

    // ------------------------------------------------------------ identity

    const char *id() { return "sogen"; }
    const char *display_name() { return "Sogen"; }
    const char *file_filter() { return "Sogen TTD trace (*.sogttd)"; }

    int can_open(const char *path)
    {
        // Any version: an unsupported one should reach open() and say why,
        // rather than fall through to "IDA does not know this file".
        try
        {
            return path != nullptr && ttd::is_trace_file(utf8_path(path)) ? 1 : 0;
        }
        catch ( ... )
        {
            return 0;
        }
    }

    // ------------------------------------------------------------ session

    ittd_backend *open(const char *path)
    {
        if ( path == nullptr )
        {
            g_module_error.set("no path");
            return nullptr;
        }
        backend_t *opened = nullptr;
        guarded(g_module_error, [&]()
        {
            auto b = std::make_unique<backend_t>();
            b->path  = utf8_path(path);
            b->trace = open_trace(b->path);
            b->trace->set_checkpoint_cache_size(kCheckpointsPerReader);
            b->spans = thread_spans(*b->trace);
            if ( b->trace->has_memory_regions() )
            {
                constexpr uint32_t kMmioKind = 5;
                for ( const ttd::memory_region &r : b->trace->memory_regions().regions )
                    if ( r.kind == kMmioKind && r.size != 0 )
                        b->mmio.emplace_back(r.address, r.address + r.size);
                b->regions.build(b->trace->memory_regions().regions);
            }
            opened = b.release();
            return ITTD_OK;
        });
        return reinterpret_cast<ittd_backend *>(opened);
    }

    void close(ittd_backend *b)
    {
        delete B(b);
    }

    // Both copy the text, which can throw (out of memory); nothing may cross
    // the C ABI, so a failed copy reads as no message.
    const char *last_error(ittd_backend *b)
    {
        try
        {
            return b == nullptr ? g_module_error.get() : B(b)->error.get();
        }
        catch ( ... )
        {
            return "";
        }
    }

    const char *scan_notice(ittd_backend *b)
    {
        try
        {
            return b == nullptr ? "" : B(b)->scan_note.get();
        }
        catch ( ... )
        {
            return "";
        }
    }

    int info(ittd_backend *hb, ittd_trace_info *out)
    {
        backend_t *b = B(hb);
        if ( b == nullptr || out == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            std::lock_guard<std::mutex> lock(b->mtx);
            const ttd::trace &t = *b->trace;
            *out = ittd_trace_info{};
            const ttd::module_entry *m = main_module(t);
            out->is64 = is64(t) ? 1 : 0;
            out->capabilities = ITTD_CAP_ACCESS_QUERIES | ITTD_CAP_CALL_QUERIES
                              | ITTD_CAP_RECORDED_EXPORTS
                              | ITTD_CAP_REVERSE_STEP | ITTD_CAP_BATCH_REGS;
            if ( t.has_syscalls() )
                out->capabilities |= ITTD_CAP_SYSCALLS;
            // Only offered when the recording holds the events the query
            // needs. A chunked recording names its event kinds in its
            // header; an older one would need a walk over every event to
            // find out (access_mask), too slow here, so self-modifying code
            // stays offered and answers with an error that says what is
            // missing, while exceptions, which need chunked data, are not.
            const uint64_t X  = (uint64_t)ttd::access_kind::execute;
            const uint64_t W  = (uint64_t)ttd::access_kind::write;
            const uint64_t HW = (uint64_t)ttd::access_kind::host_write;
            if ( t.has_access_data() )
            {
                const uint64_t mask = b->trace->access_mask();
                if ( (mask & (W | X)) == (W | X) )
                    out->capabilities |= ITTD_CAP_SELF_MODIFYING;
                if ( (mask & (X | HW)) == (X | HW) )
                    out->capabilities |= ITTD_CAP_EXCEPTIONS;
            }
            else
            {
                out->capabilities |= ITTD_CAP_SELF_MODIFYING;
            }
            // Any recording can be replayed to a position; fork_open finds
            // out whether the replay holds on this machine.
            out->capabilities |= ITTD_CAP_FORK | ITTD_CAP_REPLAY_SCANS;
            // The memory map with protections (section 17), in traces
            // recorded since Sogen kept it. Older ones only say that a range
            // was mapped or unmapped, which is not enough to draw a map.
            if ( t.has_memory_regions() )
                out->capabilities |= ITTD_CAP_MAPPING_CHANGES;
            // With checkpoint memory, memory_at starts from the checkpoint and
            // applies the writes since (ttd/next ada569b0): tens of
            // microseconds a page once the checkpoint is decoded. Without it,
            // a page read walks every access to the page.
            if ( t.has_checkpoint_memory() )
                out->capabilities |= ITTD_CAP_CHEAP_READS;
            out->fingerprint = fold_id(t.id());
            out->first = at(first_position(t));
            out->last  = at(last_position(t));
            copy_str(out->main_module, sizeof(out->main_module), m != nullptr ? m->name : std::string());
            copy_str(out->backend_name, sizeof(out->backend_name), "Sogen");
            return ITTD_OK;
        });
    }

    // ------------------------------------------------------------ positions

    int format_position(ittd_backend *, ittd_position p, char *buf, size_t buf_size)
    {
        if ( buf == nullptr || buf_size == 0 )
            return ITTD_E_BAD_ARG;
        if ( same(p, NONE) )
            std::snprintf(buf, buf_size, "-");
        else if ( same(p, END) )
            std::snprintf(buf, buf_size, "end");
        else
            std::snprintf(buf, buf_size, "%llu", (unsigned long long)p.lo);
        return ITTD_OK;
    }

    int parse_position(ittd_backend *, const char *text, ittd_position *out)
    {
        if ( text == nullptr || out == nullptr )
            return ITTD_E_BAD_ARG;
        while ( *text == ' ' || *text == '\t' )
            text++;
        if ( *text == '\0' )
            return ITTD_E_BAD_ARG;
        // What format_position prints for END reads back as END.
        if ( std::strncmp(text, "end", 3) == 0 )
        {
            const char *rest = text + 3;
            while ( *rest == ' ' || *rest == '\t' )
                rest++;
            if ( *rest == '\0' )
            {
                *out = END;
                return ITTD_OK;
            }
        }
        // strtoull accepts a sign and wraps "-1" round to UINT64_MAX.
        if ( *text < '0' || *text > '9' )
            return ITTD_E_BAD_ARG;
        char *end = nullptr;
        unsigned long long v = std::strtoull(text, &end, 10);
        while ( end != nullptr && (*end == ' ' || *end == '\t') )
            end++;
        if ( end == nullptr || *end != '\0' )
            return ITTD_E_BAD_ARG;
        *out = at(v);
        return ITTD_OK;
    }

    const char *position_syntax(ittd_backend *) { return "Instruction number, in decimal"; }

    // ------------------------------------------------------------ cursors

    ittd_cursor *cursor_open(ittd_backend *hb)
    {
        backend_t *b = B(hb);
        if ( b == nullptr )
            return nullptr;
        cursor_t *opened = nullptr;
        guarded(b->error, [&]()
        {
            auto c = std::make_unique<cursor_t>();
            c->owner    = b;
            c->trace    = open_trace(b->path);
            c->trace->set_checkpoint_cache_size(kCheckpointsPerReader);
            c->position = first_position(*c->trace);
            opened = c.release();
            return ITTD_OK;
        });
        return reinterpret_cast<ittd_cursor *>(opened);
    }

    void cursor_close(ittd_cursor *c)
    {
        delete C(c);
    }

    int cursor_position(ittd_cursor *hc, ittd_position *out)
    {
        cursor_t *c = C(hc);
        if ( c == nullptr || out == nullptr )
            return ITTD_E_BAD_ARG;
        *out = at(c->position);
        return ITTD_OK;
    }

    void move(cursor_t *c, uint64_t position)
    {
        if ( position != c->position )
        {
            c->position = position;
            c->view.reset();
        }
    }

    int cursor_seek(ittd_cursor *hc, ittd_position p)
    {
        cursor_t *c = C(hc);
        if ( c == nullptr )
            return ITTD_E_BAD_ARG;
        uint64_t pos = 0;
        if ( !resolve(*c->trace, p, &pos) )
            return ITTD_E_NO_POSITION;
        move(c, pos);
        return ITTD_OK;
    }

    int cursor_thread(ittd_cursor *hc, uint32_t *out)
    {
        cursor_t *c = C(hc);
        if ( c == nullptr || out == nullptr )
            return ITTD_E_BAD_ARG;
        *out = thread_after(*c->trace, c->position);
        return ITTD_OK;
    }

    // Through cpu_view::read_register, which decodes the saved register state
    // on one CPU per thread; view.cpu() would build an emulator per view.
    void read_regs(const ttd::cpu_view &view, ittd_regs *out)
    {
        *out = ittd_regs{};
        for ( int i = 0; i < ITTD_REG_GP_COUNT; i++ )
            out->gp[i] = view.read_register(kGp[i]);
        out->rflags  = view.read_register(x86_register::rflags);
        out->fs_base = view.read_register(x86_register::fs_base);
        out->gs_base = view.read_register(x86_register::gs_base);
        for ( int i = 0; i < ITTD_SEG_COUNT; i++ )
            out->seg[i] = (uint16_t)view.read_register(kSeg[i]);
        for ( int i = 0; i < 16; i++ )
            view.read_register((x86_register)((int)x86_register::xmm0 + i), out->xmm[i], 16);
        out->have = ITTD_REGS_GP | ITTD_REGS_SEG | ITTD_REGS_XMM;
    }

    int cursor_regs(ittd_cursor *hc, ittd_regs *out)
    {
        cursor_t *c = C(hc);
        if ( c == nullptr || out == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(c->owner->error, [&]()
        {
            if ( !c->view )
                c->view = std::make_unique<ttd::cpu_view>(*c->trace, c->position);
            read_regs(*c->view, out);
            return ITTD_OK;
        });
    }

    // ------------------------------------------------------------ threads

    ittd_thread to_thread(const ttd::trace &t, const thread_span &s)
    {
        ittd_thread th{};
        th.tid     = s.tid;
        th.created = before_step(s.first_step);
        // Sogen records when a thread last ran, not when it exited; the thread
        // running at the end is taken to be alive.
        th.exited  = s.running_at_end ? NONE : at(s.end_step - 1);
        auto name = t.threads().names.find(s.tid);
        copy_str(th.name, sizeof(th.name), name != t.threads().names.end() ? name->second : std::string());
        if ( const ttd::thread_stack *st = t.thread_stack_of(s.tid) )
        {
            th.teb         = st->teb;
            th.teb32       = st->teb32;
            th.stack_base  = st->stack_base;
            th.stack_limit = st->stack_limit;
        }
        return th;
    }

    int threads(ittd_backend *hb, ittd_thread *buf, size_t cap, size_t *out_count)
    {
        backend_t *b = B(hb);
        if ( b == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            std::lock_guard<std::mutex> lock(b->mtx);
            const ttd::trace &t = *b->trace;
            return fill(b->spans, buf, cap, out_count,
                        [&](const thread_span &s) { return to_thread(t, s); });
        });
    }

    int cursor_threads(ittd_cursor *hc, ittd_thread *buf, size_t cap, size_t *out_count)
    {
        cursor_t *c = C(hc);
        if ( c == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(c->owner->error, [&]()
        {
            const ttd::trace &t = *c->trace;
            std::vector<thread_span> live;
            for ( const thread_span &s : c->owner->spans )
                if ( s.first_step <= c->position + 1 && (s.running_at_end || c->position < s.end_step) )
                    live.push_back(s);
            return fill(live, buf, cap, out_count,
                        [&](const thread_span &s) { return to_thread(t, s); });
        });
    }

    int position_add(ittd_backend *hb, ittd_position p, int64_t delta, ittd_position *out)
    {
        backend_t *b = B(hb);
        if ( b == nullptr || out == nullptr )
            return ITTD_E_BAD_ARG;
        uint64_t pos = 0;
        if ( !resolve(*b->trace, p, &pos) )
            return ITTD_E_NO_POSITION;
        uint64_t lo = first_position(*b->trace), hi = last_position(*b->trace);
        if ( delta < 0 )
        {
            // In unsigned arithmetic: -delta overflows for INT64_MIN.
            const uint64_t back = 0ull - (uint64_t)delta;
            pos = pos - lo > back ? pos - back : lo;
        }
        else
            pos = hi - pos > (uint64_t)delta ? pos + (uint64_t)delta : hi;
        *out = at(pos);
        return ITTD_OK;
    }

    // ------------------------------------------------------------ enumeration

    int modules(ittd_backend *hb, ittd_module *buf, size_t cap, size_t *out_count)
    {
        backend_t *b = B(hb);
        if ( b == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            std::lock_guard<std::mutex> lock(b->mtx);
            return fill(b->trace->modules(), buf, cap, out_count, [](const ttd::module_entry &m)
            {
                ittd_module out{};
                out.base     = m.base;
                out.size     = m.size;
                out.loaded   = at(m.load_step);
                out.unloaded = m.unload_step ? at(*m.unload_step) : NONE;
                out.machine  = m.machine;
                copy_str(out.name, sizeof(out.name), base_name(m.name.empty() ? m.path : m.name));
                copy_str(out.path, sizeof(out.path), m.path);
                return out;
            });
        });
    }

    int timeline(ittd_backend *hb, ittd_trace_event *buf, size_t cap, size_t *out_count)
    {
        backend_t *b = B(hb);
        if ( b == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            std::lock_guard<std::mutex> lock(b->mtx);
            ttd::trace &t = *b->trace;
            std::vector<ittd_trace_event> v;
            auto add = [&](ittd_position pos, uint32_t kind, uint32_t tid, const std::string &text)
            {
                ittd_trace_event e{};
                e.pos  = pos;
                e.kind = kind;
                e.tid  = tid;
                copy_str(e.text, sizeof(e.text), text);
                v.push_back(e);
            };
            for ( const ttd::module_entry &m : t.modules() )
            {
                std::string name = base_name(m.name.empty() ? m.path : m.name);
                add(at(m.load_step), ITTD_EV_MODULE_LOAD, 0, "Loaded " + name);
                if ( m.unload_step )
                    add(at(*m.unload_step), ITTD_EV_MODULE_UNLOAD, 0, "Unloaded " + name);
            }
            for ( const thread_span &s : b->spans )
            {
                char text[64];
                std::snprintf(text, sizeof(text), "Thread %u first runs", s.tid);
                add(before_step(s.first_step), ITTD_EV_THREAD_START, s.tid, text);
            }
            // Only where info() offers exceptions: trace::exceptions() throws
            // for a recording without the events it needs (an older,
            // unchunked one), which would lose the modules and threads too.
            const uint64_t xhw = (uint64_t)ttd::access_kind::execute | (uint64_t)ttd::access_kind::host_write;
            const bool has_exceptions = t.has_access_data() && (t.access_mask() & xhw) == xhw;
            std::vector<ttd::exception_event> exceptions;
            if ( has_exceptions )
            {
                try
                {
                    exceptions = t.exceptions();
                }
                catch ( const std::exception & )
                {
                    exceptions.clear();
                }
            }
            for ( const ttd::exception_event &e : exceptions )
            {
                char text[96];
                std::snprintf(text, sizeof(text), "Exception 0x%08X at 0x%llX",
                              e.code, (unsigned long long)e.address);
                add(before_step(e.step), ITTD_EV_EXCEPTION, e.thread_id, text);
            }
            std::stable_sort(v.begin(), v.end(), [](const ittd_trace_event &a, const ittd_trace_event &b)
                             { return a.pos.hi != b.pos.hi ? a.pos.hi < b.pos.hi : a.pos.lo < b.pos.lo; });
            return fill(v, buf, cap, out_count, [](const ittd_trace_event &e) { return e; });
        });
    }

    // ------------------------------------------------------------ symbols

    int module_symbols(ittd_backend *hb, uint64_t base, ittd_symbol *buf, size_t cap, size_t *out_count)
    {
        backend_t *b = B(hb);
        if ( b == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            std::lock_guard<std::mutex> lock(b->mtx);
            std::vector<ittd_symbol> v;
            for ( const ttd::module_entry &m : b->trace->modules() )
            {
                if ( m.base != base || m.exports == nullptr )
                    continue;
                for ( const ttd::module_export &e : *m.exports )
                {
                    // A forwarder's RVA points at the forwarder string, not
                    // code; the name belongs to the module it forwards to.
                    if ( !e.forwarder.empty() || e.name.empty() || e.name[0] == '#' )
                        continue;
                    ittd_symbol s{};
                    s.ea        = m.base + e.rva;
                    s.is_export = 1;
                    copy_str(s.name, sizeof(s.name), e.name);
                    v.push_back(s);
                }
                break;
            }
            return fill(v, buf, cap, out_count, [](const ittd_symbol &s) { return s; });
        });
    }

    // ------------------------------------------------------------ the replay environment

    int replay_env(ittd_backend *hb, ittd_replay_env *out)
    {
        backend_t *b = B(hb);
        if ( b == nullptr || out == nullptr || out->size < sizeof(ittd_replay_env) )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            std::lock_guard<std::mutex> lock(b->mtx);
            const ttd::trace &t = *b->trace;
            const uint32_t size = out->size;
            std::memset(out, 0, size);
            out->size = size;
            const std::string root = manifest_value(t, "emulation_root");
            out->host = root.empty() ? 1 : 0;
            out->registry_known = manifest_value(t, "registry").empty() ? 0 : 1;
            out->registry_carried = t.has_registry_hives() ? 1 : 0;
            if ( const std::string dlls = manifest_value(t, "system_dlls"); !dlls.empty() )
            {
                const std::string here = system_dll_fingerprint(root);
                out->system_dlls = here.empty() ? ITTD_DLLS_UNKNOWN
                                 : here == dlls ? ITTD_DLLS_SAME : ITTD_DLLS_DIFFER;
            }
            copy_str(out->emulation_root, sizeof(out->emulation_root), root);
            // Where a replay in the root loads its hives from (whatever
            // registry_dir says), and where create-root.bat puts them.
            if ( !root.empty() )
                copy_str(out->registry_hint, sizeof(out->registry_hint),
                         path_utf8(utf8_path(root.c_str()) / "registry"));
            copy_str(out->windows_version, sizeof(out->windows_version), manifest_value(t, "windows_version"));
            return ITTD_OK;
        });
    }

    int check_registry(ittd_backend *hb, const char *dir)
    {
        backend_t *b = B(hb);
        if ( b == nullptr || dir == nullptr || *dir == '\0' )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            std::string recorded;
            {
                std::lock_guard<std::mutex> lock(b->mtx);
                recorded = manifest_value(*b->trace, "registry");
            }
            std::string why;
            const int rc = check_hives(recorded, utf8_path(dir), &why);
            if ( rc < 0 )
                throw coded_error(rc, why);
            return rc;
        });
    }
}
