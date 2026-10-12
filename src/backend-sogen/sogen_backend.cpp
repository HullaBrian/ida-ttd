// ida-ttd backend for Sogen time-travel traces (.sogttd).
//
// A separate DLL, loaded by the ida-ttd core through the flat C ABI in
// abi/ida_ttd_backend.h. It links Sogen's trace reader and cpu_view
// (windows-ttd-reader, windows-ttd-view) and nothing of ida-ttd's, and it never
// sees an IDA type. See docs/modular-backends.md section 6 for how each entry
// point maps onto Sogen.
//
// Sogen is GPL-2.0-only, so a built ida-ttd-sogen.dll is a GPL-2.0 binary. This
// source is what that binary is built from.
//
// Conventions that run through the whole file:
//
//  - Positions. A Sogen position N is the state after instruction N, which is
//    also the state before instruction N + 1 -- exactly the ABI's meaning. So
//    a cursor position is a Sogen position, unchanged, with hi = 0. What needs
//    translating is an event's step: the 1-based number of the instruction
//    that did it, whose ABI position is step - 1 (the state just before it).
//  - No exception leaves an entry point. Each one runs its body through
//    guarded(), which turns operation_cancelled into ITTD_E_CANCELLED and
//    anything else into ITTD_E_FAILED with the reason in last_error.
//  - One sogen::ttd::trace per handle and per cursor. A trace is not
//    thread-safe (one ifstream, mutable caches, a lazily built CPU), and a
//    second one costs about 25 ms to open, so nothing is shared.

#include <abi/ida_ttd_backend.h>

#include <ttd_trace.hpp>
#include <ttd_view.hpp>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <exception>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace ttd = sogen::ttd;
using sogen::x86_register;

namespace
{
    // ------------------------------------------------------------ handles

    struct backend_t
    {
        std::filesystem::path path;
        std::unique_ptr<ttd::trace> trace;   // for the whole-trace queries
        std::mutex mtx;                      // guards 'trace'
        std::string error;
    };

    struct cursor_t
    {
        backend_t *owner = nullptr;
        std::unique_ptr<ttd::trace> trace;   // this cursor's own reader
        uint64_t position = 0;
        std::vector<ittd_breakpoint> breakpoints;
        // The CPU at 'position', built on first use and dropped on every move.
        std::unique_ptr<ttd::cpu_view> view;
    };

    std::string g_module_error;     // last_error(NULL)

    // ------------------------------------------------------------ helpers

    constexpr ittd_position NONE  = { UINT64_MAX, UINT64_MAX };
    constexpr ittd_position BEGIN = { 0, 0 };
    constexpr ittd_position END   = { UINT64_MAX, UINT64_MAX - 1 };

    bool same(ittd_position a, ittd_position b) { return a.hi == b.hi && a.lo == b.lo; }

    ittd_position at(uint64_t position) { return { 0, position }; }

    // The ABI position of the instruction whose step is 'step': just before it.
    ittd_position before_step(uint64_t step)
    {
        if ( step == UINT64_MAX || step == 0 )
            return NONE;
        return at(step - 1);
    }

    uint64_t first_position(const ttd::trace &t) { return t.start_position(); }
    uint64_t last_position(const ttd::trace &t)  { return t.metadata().instruction_count; }

    // Resolve the sentinels; false for NONE or a position outside the trace.
    bool resolve(const ttd::trace &t, ittd_position p, uint64_t *out)
    {
        if ( same(p, BEGIN) ) { *out = first_position(t); return true; }
        if ( same(p, END) )   { *out = last_position(t);  return true; }
        if ( same(p, NONE) || p.hi != 0 )
            return false;
        if ( p.lo < first_position(t) || p.lo > last_position(t) )
            return false;
        *out = p.lo;
        return true;
    }

    // An ABI position range as the inclusive range of event steps inside it.
    // Position a is just before step a + 1, and position b just after step b, so
    // the events between the two are steps a + 1 .. b.
    void step_range(const ttd::trace &t, ittd_position_range when, uint64_t *lo, uint64_t *hi)
    {
        uint64_t a = first_position(t), b = last_position(t);
        resolve(t, when.first, &a);
        resolve(t, when.last, &b);
        *lo = a + 1;
        *hi = b;
    }

    void copy_str(char *dst, size_t cap, const std::string &src)
    {
        size_t n = std::min(src.size(), cap - 1);
        std::memcpy(dst, src.data(), n);
        dst[n] = '\0';
    }

    std::string base_name(const std::string &path)
    {
        size_t slash = path.find_last_of("/\\");
        return slash == std::string::npos ? path : path.substr(slash + 1);
    }

    // The thread that will run the instruction after 'position' -- whose
    // registers cpu_view shows there, since a snapshot taken at a thread switch
    // already holds the incoming thread.
    uint32_t thread_after(const ttd::trace &t, uint64_t position)
    {
        if ( auto tid = t.thread_at(position + 1) )
            return *tid;
        if ( auto tid = t.thread_at(position) )
            return *tid;
        return 0;
    }

    // An ittd_progress as Sogen's operation_control. Both of Sogen's callbacks
    // run on the calling thread, which the ABI's sink allows.
    ttd::operation_control control(const ittd_progress *p)
    {
        ttd::operation_control c;
        if ( p == nullptr )
            return c;
        if ( p->cancelled != nullptr )
            c.interrupted = [p]() { return p->cancelled(p->ud) != 0; };
        if ( p->report != nullptr )
            c.progress = [p](uint64_t done, uint64_t total)
            {
                p->report(p->ud, total == 0 ? 0 : (uint32_t)std::min<uint64_t>(1000, done * 1000 / total));
            };
        return c;
    }

    // Run 'body', mapping exceptions onto status codes and 'err'.
    template <typename F>
    int guarded(std::string &err, F &&body)
    {
        try
        {
            return body();
        }
        catch ( const ttd::operation_cancelled & )
        {
            err = "canceled";
            return ITTD_E_CANCELLED;
        }
        catch ( const std::exception &e )
        {
            err = e.what();
            return ITTD_E_FAILED;
        }
        catch ( ... )
        {
            err = "unknown error";
            return ITTD_E_FAILED;
        }
    }

    // The count-then-fill convention: write what fits, report the full count.
    template <typename T, typename Src, typename Conv>
    int fill(const std::vector<Src> &src, T *buf, size_t cap, size_t *out_count, Conv conv)
    {
        if ( out_count != nullptr )
            *out_count = src.size();
        if ( buf != nullptr )
            for ( size_t i = 0; i < src.size() && i < cap; i++ )
                buf[i] = conv(src[i]);
        return ITTD_OK;
    }

    // Which ittd_access kind a Sogen event is. A host write -- a syscall
    // writing guest memory -- is a write as far as "who wrote this" goes.
    uint32_t access_kind_of(ttd::access_kind k)
    {
        switch ( k )
        {
            case ttd::access_kind::read:       return ITTD_ACCESS_READ;
            case ttd::access_kind::write:
            case ttd::access_kind::host_write: return ITTD_ACCESS_WRITE;
            case ttd::access_kind::execute:    return ITTD_ACCESS_EXEC;
        }
        return 0;
    }

    uint64_t sogen_mask(uint32_t kinds)
    {
        uint64_t m = 0;
        if ( kinds & ITTD_ACCESS_READ )  m |= (uint64_t)ttd::access_kind::read;
        if ( kinds & ITTD_ACCESS_WRITE ) m |= (uint64_t)ttd::access_kind::write
                                            | (uint64_t)ttd::access_kind::host_write;
        if ( kinds & ITTD_ACCESS_EXEC )  m |= (uint64_t)ttd::access_kind::execute;
        return m;
    }

    // The ABI's strings are UTF-8; a path built from char would be read in the
    // ANSI code page instead.
    std::filesystem::path utf8_path(const char *s)
    {
        return std::filesystem::path(std::u8string(reinterpret_cast<const char8_t *>(s)));
    }

    std::unique_ptr<ttd::trace> open_trace(const std::filesystem::path &path)
    {
        auto version = ttd::trace_file_version(path);
        if ( !version )
            throw std::runtime_error("not a Sogen trace");
        if ( !ttd::is_supported_trace_version(*version) )
        {
            char msg[160];
            std::snprintf(msg, sizeof(msg),
                          "Sogen trace format v%u; this backend reads v%u to v%u",
                          *version, ttd::oldest_trace_version, ttd::newest_trace_version);
            throw std::runtime_error(msg);
        }
        return std::make_unique<ttd::trace>(path);
    }

    uint64_t fold_id(const std::string &id)
    {
        // At most 33 ASCII characters: 32 hex digits, or "h" and 32 hex digits
        // for traces older than the stored id. Any 64 of the bits will do.
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

    const ttd::module_entry *main_module(const ttd::trace &t)
    {
        // The program is the first executable mapped. Not simply the first
        // module: Sogen maps some system DLLs (win32u) before the executable.
        auto mods = t.modules();
        for ( const ttd::module_entry &m : mods )
        {
            std::string n = base_name(m.name.empty() ? m.path : m.name);
            if ( n.size() > 4 && _stricmp(n.c_str() + n.size() - 4, ".exe") == 0 )
                return &m;
        }
        return mods.empty() ? nullptr : &mods.front();
    }

    // ------------------------------------------------------------ identity

    const char *id() { return "sogen"; }
    const char *display_name() { return "Sogen"; }
    const char *file_filter() { return "Sogen TTD trace (*.sogttd)"; }

    int can_open(const char *path)
    {
        // Any version: an unreadable one should reach open() and be told why,
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
            g_module_error = "no path";
            return nullptr;
        }
        auto b = std::make_unique<backend_t>();
        int rc = guarded(g_module_error, [&]()
        {
            b->path  = utf8_path(path);
            b->trace = open_trace(b->path);
            return ITTD_OK;
        });
        if ( rc != ITTD_OK )
            return nullptr;
        return reinterpret_cast<ittd_backend *>(b.release());
    }

    backend_t *B(ittd_backend *b) { return reinterpret_cast<backend_t *>(b); }
    cursor_t  *C(ittd_cursor *c)  { return reinterpret_cast<cursor_t *>(c); }

    void close(ittd_backend *b)
    {
        delete B(b);
    }

    const char *last_error(ittd_backend *b)
    {
        return b == nullptr ? g_module_error.c_str() : B(b)->error.c_str();
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
            out->is64 = m == nullptr || m->machine != 0x14c ? 1 : 0;
            out->capabilities = ITTD_CAP_ACCESS_QUERIES | ITTD_CAP_CALL_QUERIES
                              | ITTD_CAP_RECORDED_EXPORTS | ITTD_CAP_CHEAP_SEEK
                              | ITTD_CAP_REVERSE_STEP | ITTD_CAP_EXCEPTIONS;
            if ( t.has_syscalls() )
                out->capabilities |= ITTD_CAP_SYSCALLS;
            // The memory map with protections, for traces recorded since
            // Sogen kept it (section 17). Older ones only say that a range was
            // mapped or unmapped, which is not enough to draw a map from.
            if ( t.has_memory_regions() )
                out->capabilities |= ITTD_CAP_MAPPING_CHANGES;
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
        auto c = std::make_unique<cursor_t>();
        int rc = guarded(b->error, [&]()
        {
            c->owner    = b;
            c->trace    = open_trace(b->path);
            c->position = first_position(*c->trace);
            return ITTD_OK;
        });
        return rc == ITTD_OK ? reinterpret_cast<ittd_cursor *>(c.release()) : nullptr;
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

    void read_regs(ttd::cpu_view &view, ittd_regs *out)
    {
        auto &cpu = view.cpu();
        static const x86_register gp[ITTD_REG_GP_COUNT] = {
            x86_register::rax, x86_register::rcx, x86_register::rdx, x86_register::rbx,
            x86_register::rsp, x86_register::rbp, x86_register::rsi, x86_register::rdi,
            x86_register::r8,  x86_register::r9,  x86_register::r10, x86_register::r11,
            x86_register::r12, x86_register::r13, x86_register::r14, x86_register::r15,
            x86_register::rip,
        };
        static const x86_register seg[ITTD_SEG_COUNT] = {
            x86_register::cs, x86_register::ss, x86_register::ds,
            x86_register::es, x86_register::fs, x86_register::gs,
        };
        *out = ittd_regs{};
        for ( int i = 0; i < ITTD_REG_GP_COUNT; i++ )
            out->gp[i] = cpu.reg<uint64_t>(gp[i]);
        out->rflags  = cpu.reg<uint64_t>(x86_register::rflags);
        out->fs_base = cpu.reg<uint64_t>(x86_register::fs_base);
        out->gs_base = cpu.reg<uint64_t>(x86_register::gs_base);
        for ( int i = 0; i < ITTD_SEG_COUNT; i++ )
            out->seg[i] = cpu.reg<uint16_t>(seg[i]);
        for ( int i = 0; i < 16; i++ )
            cpu.read_register((x86_register)((int)x86_register::xmm0 + i), out->xmm[i], 16);
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

    int cursor_read_memory(ittd_cursor *hc, uint64_t ea, void *buf, uint8_t *known,
                           size_t size, size_t *out_known)
    {
        cursor_t *c = C(hc);
        if ( c == nullptr || (buf == nullptr && size != 0) )
            return ITTD_E_BAD_ARG;
        return guarded(c->owner->error, [&]()
        {
            std::vector<std::optional<uint8_t>> bytes = c->trace->memory_at(c->position, ea, size);
            size_t n = 0;
            uint8_t *dst = static_cast<uint8_t *>(buf);
            for ( size_t i = 0; i < size && i < bytes.size(); i++ )
            {
                if ( bytes[i] )
                {
                    dst[i] = *bytes[i];
                    n++;
                }
                if ( known != nullptr )
                    known[i] = bytes[i] ? 1 : 0;
            }
            if ( out_known != nullptr )
                *out_known = n;
            return ITTD_OK;
        });
    }

    // ------------------------------------------------------------ threads

    // Every thread with the span it ran over, from the switch table.
    struct thread_span
    {
        uint32_t tid = 0;
        uint64_t first_step = UINT64_MAX;
        uint64_t end_step = 0;          // one past the last step it ran
        bool     running_at_end = false;
    };

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
        for ( auto &[tid, s] : by_tid )
            v.push_back(s);
        std::sort(v.begin(), v.end(), [](const thread_span &a, const thread_span &b)
                  { return a.first_step < b.first_step; });
        return v;
    }

    ittd_thread to_thread(const ttd::trace &t, const thread_span &s)
    {
        ittd_thread th{};
        th.tid     = s.tid;
        th.created = before_step(s.first_step);
        // Sogen records when a thread last ran, not when it exited; a thread
        // that is still the running one at the end is taken to be alive.
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
            return fill(thread_spans(t), buf, cap, out_count,
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
            for ( const thread_span &s : thread_spans(t) )
                if ( s.first_step <= c->position + 1 && (s.running_at_end || c->position < s.end_step) )
                    live.push_back(s);
            return fill(live, buf, cap, out_count,
                        [&](const thread_span &s) { return to_thread(t, s); });
        });
    }

    // ------------------------------------------------------------ navigation

    // Single steps move one position, on whatever thread runs next: that is
    // what a position is in Sogen, and it matches "step into" on a recording.
    int nav_step(ittd_cursor *hc, int forward, int *out_stop)
    {
        cursor_t *c = C(hc);
        if ( c == nullptr )
            return ITTD_E_BAD_ARG;
        const ttd::trace &t = *c->trace;
        int stop = ITTD_STOP_STEPPED;
        if ( forward )
        {
            if ( c->position >= last_position(t) )
                stop = ITTD_STOP_BOUNDARY;
            else
                move(c, c->position + 1);
        }
        else
        {
            if ( c->position <= first_position(t) )
                stop = ITTD_STOP_BOUNDARY;
            else
                move(c, c->position - 1);
        }
        if ( out_stop != nullptr )
            *out_stop = stop;
        return ITTD_OK;
    }

    // The next (or previous) execution of an instruction starting at 'a', by
    // step. An execute event matches any instruction overlapping the address,
    // so one that merely covers it is stepped past.
    //
    // next_access(s) answers steps above s and previous_access(s) steps below
    // s. At cursor position p the instruction about to run is step p + 1: run
    // forward looks at steps after it, run backward at steps up to p, the last
    // one that already ran.
    std::optional<uint64_t> execution_of(ttd::trace &t, uint64_t a, uint64_t position, bool forward)
    {
        const uint64_t X = (uint64_t)ttd::access_kind::execute;
        uint64_t s = position + 1;
        for ( ;; )
        {
            std::optional<ttd::access_event> ev = forward ? t.next_access(a, 1, s, X)
                                                          : t.previous_access(a, 1, s, X);
            if ( !ev )
                return std::nullopt;
            if ( ev->ip == a )
                return ev->step;
            s = ev->step;
        }
    }

    // The next (or previous) read or write of any byte of [a, a + size), by
    // step, with the same "after the instruction about to run" convention as
    // execution_of. A host write -- a syscall writing guest memory -- is a
    // write as far as a breakpoint on "who wrote this" is concerned.
    std::optional<uint64_t> access_of(ttd::trace &t, const ittd_breakpoint &b, uint64_t position,
                                      bool forward)
    {
        uint64_t mask = 0;
        if ( b.kinds & ITTD_ACCESS_READ )
            mask |= (uint64_t)ttd::access_kind::read;
        if ( b.kinds & ITTD_ACCESS_WRITE )
            mask |= (uint64_t)ttd::access_kind::write | (uint64_t)ttd::access_kind::host_write;
        if ( mask == 0 )
            return std::nullopt;
        uint64_t size = b.size == 0 ? 1 : b.size;
        std::optional<ttd::access_event> ev = forward ? t.next_access(b.addr, size, position + 1, mask)
                                                      : t.previous_access(b.addr, size, position + 1, mask);
        if ( !ev )
            return std::nullopt;
        return ev->step;
    }

    // The nearest hit of any of 'bpts' after (or before) the cursor, as the
    // position just before the instruction that hit it, and which breakpoint
    // it was. Each breakpoint is a page-index lookup, so a breakpoint set is
    // answered without replaying.
    bool nearest_hit(cursor_t *c, const std::vector<ittd_breakpoint> &bpts, bool forward,
                     uint64_t *out_pos, size_t *out_index)
    {
        bool found = false;
        uint64_t best = 0;
        for ( size_t i = 0; i < bpts.size(); i++ )
        {
            const ittd_breakpoint &b = bpts[i];
            std::optional<uint64_t> steps[2];
            if ( b.kinds & ITTD_ACCESS_EXEC )
                steps[0] = execution_of(*c->trace, b.addr, c->position, forward);
            steps[1] = access_of(*c->trace, b, c->position, forward);
            for ( const std::optional<uint64_t> &step : steps )
            {
                if ( !step )
                    continue;
                if ( !found || (forward ? *step < best : *step > best) )
                {
                    best       = *step;
                    *out_index = i;
                    found      = true;
                }
            }
        }
        if ( found )
            *out_pos = best - 1;
        return found;
    }

    ittd_breakpoint exec_bp(uint64_t addr)
    {
        ittd_breakpoint b{};
        b.addr  = addr;
        b.size  = 1;
        b.kinds = ITTD_ACCESS_EXEC;
        return b;
    }

    // Whether the instruction bytes of an execute event are a call: E8 rel32,
    // or FF /2 and FF /3 (near and far indirect), after any legacy or REX
    // prefixes.
    bool is_call_insn(const ttd::access_event &e)
    {
        size_t n = (size_t)std::min<uint64_t>(e.size, e.payload.size());
        size_t i = 0;
        for ( ; i < n; i++ )
        {
            uint8_t b = e.payload[i];
            bool prefix = b == 0x66 || b == 0x67 || b == 0xF2 || b == 0xF3 || b == 0x2E || b == 0x3E
                       || b == 0x26 || b == 0x36 || b == 0x64 || b == 0x65 || (b & 0xF0) == 0x40;
            if ( !prefix )
                break;
        }
        if ( i >= n )
            return false;
        if ( e.payload[i] == 0xE8 )
            return true;
        if ( e.payload[i] == 0xFF && i + 1 < n )
        {
            uint8_t reg = (e.payload[i + 1] >> 3) & 7;
            return reg == 2 || reg == 3;
        }
        return false;
    }

    // Forward step over: run the instruction about to execute on this thread,
    // and if it is a call, the whole call. The return comes from calls_to,
    // which pairs a call with its ret through the stack slot the return
    // address was pushed to -- exact under recursion, where "the next time
    // this thread reaches the return address" is not.
    //
    // Backward is not offered yet: stepping back over a call means finding the
    // call from its return, and that wants the frame's entry, which no single
    // reader query gives.
    int nav_step_over(ittd_cursor *hc, int forward, int *out_stop)
    {
        cursor_t *c = C(hc);
        if ( c == nullptr )
            return ITTD_E_BAD_ARG;
        if ( !forward )
            return ITTD_E_UNSUPPORTED;
        return guarded(c->owner->error, [&]()
        {
            ttd::trace &t = *c->trace;
            uint32_t tid = thread_after(t, c->position);
            int stop = ITTD_STOP_BOUNDARY;
            uint64_t dest = last_position(t);

            std::optional<ttd::access_event> cur = t.next_instruction(c->position, tid);
            std::optional<ttd::access_event> after = cur ? t.next_instruction(cur->step, tid) : std::nullopt;
            if ( cur && after )
            {
                if ( is_call_insn(*cur) )
                {
                    // 'after' is the callee's first instruction.
                    for ( const ttd::call_event &e : t.calls_to(after->ip, after->step, after->step) )
                    {
                        if ( e.step == cur->step && e.return_step != UINT64_MAX )
                        {
                            dest = e.return_step;   // just after the ret
                            stop = ITTD_STOP_STEPPED;
                        }
                    }
                }
                else
                {
                    dest = after->step - 1;
                    stop = ITTD_STOP_STEPPED;
                }
            }

            // A breakpoint inside the call stops the step there, as it would
            // on a live process.
            uint64_t bp = 0;
            size_t hit = 0;
            if ( !c->breakpoints.empty() && nearest_hit(c, c->breakpoints, true, &bp, &hit)
              && bp > c->position && bp < dest )
            {
                dest = bp;
                stop = ITTD_STOP_BREAKPOINT;
            }
            move(c, dest);
            if ( out_stop != nullptr )
                *out_stop = stop;
            return ITTD_OK;
        });
    }

    int nav_run_to(ittd_cursor *hc, uint64_t addr, int forward, int *out_stop)
    {
        cursor_t *c = C(hc);
        if ( c == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(c->owner->error, [&]()
        {
            std::vector<ittd_breakpoint> targets = c->breakpoints;
            targets.push_back(exec_bp(addr));
            uint64_t p = 0;
            size_t hit = 0;
            int stop = ITTD_STOP_BOUNDARY;
            if ( nearest_hit(c, targets, forward != 0, &p, &hit) )
            {
                move(c, p);
                stop = hit == targets.size() - 1 ? ITTD_STOP_STEPPED : ITTD_STOP_BREAKPOINT;
            }
            else
            {
                move(c, forward ? last_position(*c->trace) : first_position(*c->trace));
            }
            if ( out_stop != nullptr )
                *out_stop = stop;
            return ITTD_OK;
        });
    }

    int nav_run(ittd_cursor *hc, int forward, int *out_stop)
    {
        cursor_t *c = C(hc);
        if ( c == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(c->owner->error, [&]()
        {
            uint64_t p = 0;
            size_t hit = 0;
            int stop = ITTD_STOP_BOUNDARY;
            if ( nearest_hit(c, c->breakpoints, forward != 0, &p, &hit) )
            {
                move(c, p);
                stop = ITTD_STOP_BREAKPOINT;
            }
            else
            {
                move(c, forward ? last_position(*c->trace) : first_position(*c->trace));
            }
            if ( out_stop != nullptr )
                *out_stop = stop;
            return ITTD_OK;
        });
    }

    int nav_breakpoints(ittd_cursor *hc, const ittd_breakpoint *bpts, size_t count)
    {
        cursor_t *c = C(hc);
        if ( c == nullptr || (bpts == nullptr && count != 0) )
            return ITTD_E_BAD_ARG;
        c->breakpoints.assign(bpts, bpts + count);
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
            auto mods = b->trace->modules();
            std::vector<ttd::module_entry> v(mods.begin(), mods.end());
            return fill(v, buf, cap, out_count, [](const ttd::module_entry &m)
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
            for ( const thread_span &s : thread_spans(t) )
            {
                char text[64];
                std::snprintf(text, sizeof(text), "Thread %u first runs", s.tid);
                add(before_step(s.first_step), ITTD_EV_THREAD_START, s.tid, text);
            }
            for ( const ttd::exception_event &e : t.exceptions() )
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

    // ------------------------------------------------------------ queries
    //
    // Each runs the Sogen query, holds the whole answer, and copies out what
    // fits. A count query's two calls therefore run the query twice; the
    // second is cheap because the decoded chunks are cached in the trace.

    void set_truncated(int *out_truncated, size_t have, size_t cap, bool buf_given)
    {
        if ( out_truncated != nullptr )
            *out_truncated = buf_given && have > cap ? 1 : 0;
    }

    int query_accesses(ittd_backend *hb, uint64_t lo, uint64_t hi, uint32_t kinds,
                       ittd_position_range when, ittd_access *buf, size_t cap,
                       size_t *out_count, int *out_truncated, const ittd_progress *progress)
    {
        backend_t *b = B(hb);
        if ( b == nullptr || hi <= lo )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            std::lock_guard<std::mutex> lock(b->mtx);
            ttd::trace &t = *b->trace;
            uint64_t s0 = 0, s1 = 0;
            step_range(t, when, &s0, &s1);
            std::vector<ttd::access_event> ev = t.accesses(lo, hi - lo, s0, s1, sogen_mask(kinds), control(progress));
            set_truncated(out_truncated, ev.size(), cap, buf != nullptr);
            return fill(ev, buf, cap, out_count, [&](const ttd::access_event &e)
            {
                ittd_access a{};
                a.pos  = before_step(e.step);
                a.pc   = e.ip;
                a.addr = e.address;
                a.size = (uint32_t)e.size;
                a.kind = access_kind_of(e.kind);
                a.tid  = t.thread_at(e.step).value_or(0);
                return a;
            });
        });
    }

    int query_executed(ittd_backend *hb, const ittd_range *ranges, size_t nranges,
                       uint64_t *buf, size_t cap, size_t *out_count,
                       int *out_truncated, const ittd_progress *progress)
    {
        backend_t *b = B(hb);
        if ( b == nullptr || (ranges == nullptr && nranges != 0) )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            std::lock_guard<std::mutex> lock(b->mtx);
            ttd::trace &t = *b->trace;
            std::set<uint64_t> seen;
            ttd::operation_control ctl = control(progress);
            for ( size_t i = 0; i < nranges; i++ )
            {
                if ( ranges[i].end <= ranges[i].start )
                    continue;
                for ( const ttd::access_event &e :
                      t.accesses(ranges[i].start, ranges[i].end - ranges[i].start, 0, UINT64_MAX,
                                 (uint64_t)ttd::access_kind::execute, ctl) )
                {
                    if ( e.ip >= ranges[i].start && e.ip < ranges[i].end )
                        seen.insert(e.ip);
                }
            }
            std::vector<uint64_t> v(seen.begin(), seen.end());
            set_truncated(out_truncated, v.size(), cap, buf != nullptr);
            return fill(v, buf, cap, out_count, [](uint64_t a) { return a; });
        });
    }

    int query_calls(ittd_backend *hb, const uint64_t *targets, size_t ntargets,
                    ittd_position_range when, ittd_call *buf, size_t cap,
                    size_t *out_count, int *out_truncated, const ittd_progress *progress)
    {
        backend_t *b = B(hb);
        if ( b == nullptr )
            return ITTD_E_BAD_ARG;
        if ( ntargets == 0 || targets == nullptr )
        {
            b->error = "Sogen lists calls by target; 'every call' is not supported";
            return ITTD_E_UNSUPPORTED;
        }
        return guarded(b->error, [&]()
        {
            std::lock_guard<std::mutex> lock(b->mtx);
            ttd::trace &t = *b->trace;
            uint64_t s0 = 0, s1 = 0;
            step_range(t, when, &s0, &s1);
            ttd::operation_control ctl = control(progress);
            std::vector<ttd::call_event> all;
            for ( size_t i = 0; i < ntargets; i++ )
            {
                std::vector<ttd::call_event> v = t.calls_to(targets[i], s0, s1, ctl);
                all.insert(all.end(), v.begin(), v.end());
            }
            std::sort(all.begin(), all.end(), [](const ttd::call_event &a, const ttd::call_event &b)
                      { return a.entry_step < b.entry_step; });
            set_truncated(out_truncated, all.size(), cap, buf != nullptr);
            return fill(all, buf, cap, out_count, [](const ttd::call_event &e)
            {
                ittd_call c{};
                c.pos       = before_step(e.step);
                c.entry_pos = before_step(e.entry_step);
                // cpu_view at the ret's own step is the state after it: back at
                // the return address with the result in RAX.
                c.ret_pos   = e.return_step == UINT64_MAX ? NONE : at(e.return_step);
                c.site      = e.step == UINT64_MAX ? ITTD_BADADDR : e.site;
                c.target    = e.target;
                c.tid       = e.thread_id;
                c.flags     = e.is_call ? 0 : ITTD_CALL_F_NOT_CALL;
                return c;
            });
        });
    }

    int query_indirect(ittd_backend *hb, const ittd_range *ranges, size_t nranges, uint32_t flags,
                       ittd_call_target *buf, size_t cap, size_t *out_count,
                       int *out_truncated, const ittd_progress *progress)
    {
        backend_t *b = B(hb);
        if ( b == nullptr || (ranges == nullptr && nranges != 0) )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            std::lock_guard<std::mutex> lock(b->mtx);
            std::vector<std::pair<uint64_t, uint64_t>> r;
            for ( size_t i = 0; i < nranges; i++ )
                if ( ranges[i].end > ranges[i].start )
                    r.emplace_back(ranges[i].start, ranges[i].end - ranges[i].start);
            std::vector<ttd::indirect_branch> v =
                b->trace->indirect_branches(r, (flags & ITTD_INDIRECT_JUMPS) != 0, control(progress));
            set_truncated(out_truncated, v.size(), cap, buf != nullptr);
            return fill(v, buf, cap, out_count, [](const ttd::indirect_branch &e)
            {
                ittd_call_target t{};
                t.site      = e.site;
                t.target    = e.target;
                t.hits      = e.hits;
                t.first_pos = before_step(e.first_step);
                t.flags     = e.is_call ? 0 : ITTD_CALL_F_NOT_CALL;
                return t;
            });
        });
    }

    int query_exceptions(ittd_backend *hb, ittd_exception *buf, size_t cap, size_t *out_count,
                         int *out_truncated, const ittd_progress *progress)
    {
        backend_t *b = B(hb);
        if ( b == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            std::lock_guard<std::mutex> lock(b->mtx);
            std::vector<ttd::exception_event> v = b->trace->exceptions(control(progress));
            set_truncated(out_truncated, v.size(), cap, buf != nullptr);
            return fill(v, buf, cap, out_count, [](const ttd::exception_event &e)
            {
                ittd_exception x{};
                x.pos            = before_step(e.step);
                x.raise_pos      = before_step(e.raise_step);
                x.address        = e.address;
                x.information[0] = e.information[0];
                x.information[1] = e.information[1];
                x.code           = e.code;
                x.flags          = e.flags;
                x.tid            = e.thread_id;
                return x;
            });
        });
    }

    // The instruction stream of one thread (or all) over a range of positions,
    // straight from the execute events: no replay, so a long window costs only
    // the events it reads. Stops after 'cap'.
    int query_instructions(ittd_backend *hb, ittd_position_range when, uint32_t tid,
                           ittd_access *buf, size_t cap, size_t *out_count,
                           int *out_truncated, const ittd_progress *progress)
    {
        backend_t *b = B(hb);
        if ( b == nullptr || (buf == nullptr && cap != 0) )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            std::lock_guard<std::mutex> lock(b->mtx);
            ttd::trace &t = *b->trace;
            ttd::operation_control ctl = control(progress);
            uint64_t s0 = 0, s1 = 0;
            step_range(t, when, &s0, &s1);
            size_t n = 0;
            bool more = false;
            if ( s0 <= s1 )
            {
                const uint64_t X = (uint64_t)ttd::access_kind::execute;
                ttd::event_reader reader(t, t.first_event_after(s0 - 1));
                for ( uint64_t seen = 0;; seen++ )
                {
                    std::optional<ttd::access_event> ev = reader.next(X);
                    if ( !ev || ev->step > s1 )
                        break;
                    if ( (seen & 0xFFFF) == 0 )
                        ctl.check();
                    uint32_t et = t.thread_at(ev->step).value_or(0);
                    if ( tid != 0 && et != tid )
                        continue;
                    if ( n == cap )
                    {
                        more = true;
                        break;
                    }
                    ittd_access &a = buf[n++];
                    a = ittd_access{};
                    a.pos  = before_step(ev->step);
                    a.pc   = ev->ip;
                    a.addr = ev->ip;
                    a.size = (uint32_t)ev->size;
                    a.kind = ITTD_ACCESS_EXEC;
                    a.tid  = et;
                }
            }
            if ( out_count != nullptr )
                *out_count = n;
            if ( out_truncated != nullptr )
                *out_truncated = more ? 1 : 0;
            return ITTD_OK;
        });
    }

    // Sogen's finer region kind, as the ABI's region_type.
    uint32_t region_type_of(uint32_t kind)
    {
        switch ( kind )
        {
            case 1: return ITTD_REGION_PRIVATE;
            case 2: return ITTD_REGION_MAPPED;
            case 3: return ITTD_REGION_SECTION;
            case 4: return ITTD_REGION_IMAGE;
            case 5: return ITTD_REGION_MMIO;
            case 6: return ITTD_REGION_HOST;
            default: return ITTD_REGION_UNKNOWN;
        }
    }

    // The memory map at the start and every change to it, from the trace's
    // memory regions section (format section 17). Each entry is what
    // NtQueryVirtualMemory showed for its range from its position on, which is
    // ITTD_MAP_STATE: the core folds it by overwriting the range. The values
    // are already Windows' own.
    int query_mapping_changes(ittd_backend *hb, ittd_mapping_change *buf, size_t cap,
                              size_t *out_count, int *out_truncated, const ittd_progress *)
    {
        backend_t *b = B(hb);
        if ( b == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            std::lock_guard<std::mutex> lock(b->mtx);
            const ttd::trace &t = *b->trace;
            if ( !t.has_memory_regions() )
            {
                b->error = "this trace was recorded before Sogen recorded the memory map";
                return ITTD_E_UNSUPPORTED;
            }
            const std::vector<ttd::memory_region> &v = t.memory_regions().regions;
            std::span<const ttd::syscall_entry> sys = t.syscalls();
            const uint64_t start = first_position(t);
            set_truncated(out_truncated, v.size(), cap, buf != nullptr);
            return fill(v, buf, cap, out_count, [&](const ttd::memory_region &r)
            {
                ittd_mapping_change m{};
                m.pos           = at(r.step);
                m.call_pos      = NONE;
                m.api           = ITTD_BADADDR;
                m.base          = r.address;
                m.size          = r.size;
                m.kind          = ITTD_MAP_STATE;
                m.flags         = ITTD_MAP_F_EXACT;
                m.protect       = r.protection;
                m.alloc_base    = r.allocation_base;
                m.state         = r.state;
                m.mem_type      = r.type;
                m.alloc_protect = r.allocation_protection;
                m.region_type   = region_type_of(r.kind);
                m.file          = r.name == UINT32_MAX ? 0 : r.name + 1;
                if ( r.step == start && r.event_number == 0 )
                {
                    m.flags |= ITTD_MAP_F_AT_START;
                    return m;
                }
                m.tid = t.thread_at(r.step).value_or(0);
                // The syscall that made the change, when one did: the listing
                // travels to where the memory was asked for.
                auto it = std::lower_bound(sys.begin(), sys.end(), r.step,
                                           [](const ttd::syscall_entry &e, uint64_t s) { return e.step < s; });
                if ( it != sys.end() && it->step == r.step )
                    m.call_pos = before_step(it->step);
                return m;
            });
        });
    }

    int query_mapping_files(ittd_backend *hb, ittd_name *buf, size_t cap, size_t *out_count)
    {
        backend_t *b = B(hb);
        if ( b == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            std::lock_guard<std::mutex> lock(b->mtx);
            return fill(b->trace->memory_regions().names, buf, cap, out_count, [](const std::string &n)
            {
                ittd_name out{};
                copy_str(out.name, sizeof(out.name), n);
                return out;
            });
        });
    }

    int regs_at(ittd_backend *hb, const ittd_position *positions, size_t count,
                ittd_regs *out, const ittd_progress *progress)
    {
        backend_t *b = B(hb);
        if ( b == nullptr || ((positions == nullptr || out == nullptr) && count != 0) )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            std::lock_guard<std::mutex> lock(b->mtx);
            ttd::trace &t = *b->trace;
            ttd::operation_control ctl = control(progress);
            // In position order: neighbouring positions reuse decoded chunks and
            // translated code, which Sogen measured at half the cost of the
            // same positions shuffled (TTD-Club/sogen#33 will do better).
            std::vector<size_t> order(count);
            for ( size_t i = 0; i < count; i++ )
                order[i] = i;
            std::sort(order.begin(), order.end(), [&](size_t a, size_t c)
                      { return positions[a].lo < positions[c].lo; });
            for ( size_t k = 0; k < count; k++ )
            {
                size_t i = order[k];
                out[i] = ittd_regs{};
                uint64_t p = 0;
                if ( !resolve(t, positions[i], &p) )
                    continue;
                try
                {
                    ttd::cpu_view view(t, p);
                    read_regs(view, &out[i]);
                }
                catch ( const ttd::divergence_error & )
                {
                    // Left with have == 0: this position could not be rebuilt.
                }
                ctl.report(k + 1, count);
            }
            return ITTD_OK;
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
                    // A forwarder's RVA points at the forwarder string, not at
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

    // ------------------------------------------------------------ the table

    const ittd_backend_api g_api = []()
    {
        ittd_backend_api a{};
        a.abi_version        = ITTD_ABI_VERSION;
        a.id                 = id;
        a.display_name       = display_name;
        a.file_filter        = file_filter;
        a.can_open           = can_open;
        a.open               = open;
        a.close              = close;
        a.last_error         = last_error;
        a.info               = info;
        a.prepare            = nullptr;     // no keyframes: every seek is a cpu_view
        a.format_position    = format_position;
        a.parse_position     = parse_position;
        a.position_syntax    = position_syntax;
        a.cursor_open        = cursor_open;
        a.cursor_close       = cursor_close;
        a.cursor_position    = cursor_position;
        a.cursor_seek        = cursor_seek;
        a.cursor_thread      = cursor_thread;
        a.cursor_regs        = cursor_regs;
        a.cursor_read_memory = cursor_read_memory;
        a.cursor_threads     = cursor_threads;
        a.nav_step           = nav_step;
        a.nav_step_over      = nav_step_over;   // forward only, see there
        a.nav_step_out       = nullptr;     // not yet: needs the frame's entry
        a.nav_run            = nav_run;
        a.nav_run_to         = nav_run_to;
        a.nav_breakpoints    = nav_breakpoints;
        a.modules            = modules;
        a.threads            = threads;
        a.timeline           = timeline;
        a.query_accesses     = query_accesses;
        a.query_executed     = query_executed;
        a.query_calls        = query_calls;
        a.query_indirect     = query_indirect;
        a.query_mapping_changes = query_mapping_changes;
        a.module_symbols     = module_symbols;
        a.module_functions   = nullptr;     // the core reads .pdata from the file
        a.query_exceptions   = query_exceptions;
        a.regs_at            = regs_at;
        a.query_instructions = query_instructions;
        a.query_mapping_files = query_mapping_files;
        return a;
    }();
}

extern "C" __declspec(dllexport) const ittd_backend_api *ida_ttd_backend(uint32_t abi_version)
{
    return abi_version == ITTD_ABI_VERSION ? &g_api : nullptr;
}
