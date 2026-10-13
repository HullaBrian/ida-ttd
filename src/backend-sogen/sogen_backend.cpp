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

// Forks: the emulator, Sogen's replay and recorder, and the headless UI a
// replay delivers recorded window input to.
#include <windows_emulator.hpp>
#include <ttd_session.hpp>
#include <ttd_ui.hpp>
#include <unicorn_x86_64_emulator.hpp>
#include <platform/ui_backend.hpp>
#include <ttd_string_scan.hpp>
#include <ttd_buffer_scan.hpp>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <exception>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ttd = sogen::ttd;
using sogen::x86_register;

namespace
{
    // ------------------------------------------------------------ handles

    // One page as memory_at showed it, and the positions it holds for.
    //
    // memory_at walks every recorded access to the page until each byte is
    // accounted for, which on a hot code page -- ntdll's, executed millions
    // of times -- costs tens of milliseconds. IDA reads a module's code page
    // by page, and again after every stop, so uncached that froze it for
    // minutes. A page only changes at a write to it or a change to its
    // mapping, so one read answers every position between the two.
    struct cached_page
    {
        uint64_t from = 0, to = 0;      // positions [from, to] it holds for
        uint64_t used = 0;              // for eviction
        std::vector<uint8_t> bytes, known;
    };

    struct page_cache
    {
        std::mutex mtx;
        std::unordered_map<uint64_t, std::vector<cached_page>> pages;   // by page base
        size_t   count = 0;
        uint64_t clock = 0;
    };

    struct backend_t
    {
        std::filesystem::path path;
        std::unique_ptr<ttd::trace> trace;   // for the whole-trace queries
        std::mutex mtx;                      // guards 'trace'
        std::string error;
        page_cache pages;                    // shared by this backend's cursors
        // Replay scan results: each is a full replay, and count-then-fill
        // asks twice. Guarded by their own mutex, not 'mtx', so a scan does
        // not hold up the other queries.
        std::mutex scan_mtx;
        // Keyed by what the replay ran with (scan_key), and for strings the
        // minimum length too: a strict run must not be answered by a lenient one.
        std::map<std::string, std::vector<ittd_string_hit>> strings;
        std::map<std::string, std::vector<ittd_buffer_hit>> buffers;
        // What each cached scan skipped (scan_notice), by the same keys, and
        // the last scan's.
        std::map<std::string, std::string> scan_notes;
        std::string scan_note;
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

    // A recording replayed to a position and held there (fork_open).
    struct fork_t
    {
        backend_t *owner = nullptr;
        std::unique_ptr<ttd::trace> trace;               // its own reader: seek needs one
        std::unique_ptr<sogen::windows_emulator> emu;
        uint64_t position = 0;
        bool     recorded = false;                       // fork_record runs once
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
        // Cut on a character boundary, never inside a UTF-8 sequence.
        while ( n > 0 && n < src.size() && (static_cast<unsigned char>(src[n]) & 0xC0) == 0x80 )
            n--;
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

    // A failure the caller can act on, with its own ITTD_E_* code.
    struct coded_error : std::runtime_error
    {
        int code;
        coded_error(int c, const std::string &what) : std::runtime_error(what), code(c) {}
    };

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
        catch ( const coded_error &e )
        {
            err = e.what();
            return e.code;
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
    template <typename T, typename Range, typename Conv>
    int fill(const Range &src, T *buf, size_t cap, size_t *out_count, Conv conv)
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

    // Decoded checkpoints each reader keeps (Sogen's default is four). Each is
    // about the size of the program's committed memory, and there is a
    // reader per cursor: four each took a session on a large recording past
    // half a gigabyte. Two cover a pass between a call and its return.
    constexpr size_t kCheckpointsPerReader = 2;

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
            b->trace->set_checkpoint_cache_size(kCheckpointsPerReader);
            return ITTD_OK;
        });
        if ( rc != ITTD_OK )
            return nullptr;
        return reinterpret_cast<ittd_backend *>(b.release());
    }

    backend_t *B(ittd_backend *b) { return reinterpret_cast<backend_t *>(b); }
    cursor_t  *C(ittd_cursor *c)  { return reinterpret_cast<cursor_t *>(c); }
    fork_t    *F(ittd_fork *f)    { return reinterpret_cast<fork_t *>(f); }

    void close(ittd_backend *b)
    {
        delete B(b);
    }

    const char *last_error(ittd_backend *b)
    {
        return b == nullptr ? g_module_error.c_str() : B(b)->error.c_str();
    }

    const char *scan_notice(ittd_backend *b)
    {
        return b == nullptr ? "" : B(b)->scan_note.c_str();
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
            // Every Sogen recording can be asked; one recorded without write
            // or execute events answers with an error that says so.
            out->capabilities |= ITTD_CAP_SELF_MODIFYING;
            // Any recording can be replayed to a position; whether the
            // replay holds on this machine is fork_open's to find out.
            out->capabilities |= ITTD_CAP_FORK | ITTD_CAP_REPLAY_SCANS;
            // The memory map with protections, for traces recorded since
            // Sogen kept it (section 17). Older ones only say that a range was
            // mapped or unmapped, which is not enough to draw a map from.
            if ( t.has_memory_regions() )
                out->capabilities |= ITTD_CAP_MAPPING_CHANGES;
            // With checkpoint memory, memory_at starts from the checkpoint and
            // applies the writes since (ttd/next ada569b0): a page is tens of
            // microseconds once its checkpoint is decoded. Without it, a page
            // walks every access to it, and is not cheap.
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
            c->trace->set_checkpoint_cache_size(kCheckpointsPerReader);
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

    constexpr uint64_t kPage = 0x1000;
    constexpr size_t   kMaxCachedPages = 8192;      // 64 MiB of bytes and flags

    // The positions around 'position' over which the page at 'page' cannot
    // change: from the last write to it at or before the position to just
    // before the next one, narrowed by any change to its mapping in between
    // (memory freed and allocated again reads as zeros with no write).
    void stable_span(ttd::trace &t, uint64_t page, uint64_t position, uint64_t *from, uint64_t *to)
    {
        const uint64_t W = (uint64_t)ttd::access_kind::write | (uint64_t)ttd::access_kind::host_write;
        std::optional<ttd::access_event> before = t.previous_access(page, kPage, position + 1, W);
        std::optional<ttd::access_event> after  = t.next_access(page, kPage, position, W);
        *from = before ? before->step : 0;
        *to   = after ? after->step - 1 : UINT64_MAX;
        if ( t.has_memory_regions() )
            for ( const ttd::memory_region &r : t.memory_regions().regions )
            {
                if ( r.address >= page + kPage || r.address + r.size <= page )
                    continue;
                if ( r.step <= position && r.step > *from )
                    *from = r.step;
                else if ( r.step > position && r.step - 1 < *to )
                    *to = r.step - 1;
            }
    }

    // Drop the least recently used half once the cache is full.
    void trim(page_cache &pc)
    {
        if ( pc.count <= kMaxCachedPages )
            return;
        std::vector<uint64_t> uses;
        uses.reserve(pc.count);
        for ( auto &[page, v] : pc.pages )
            for ( const cached_page &e : v )
                uses.push_back(e.used);
        std::nth_element(uses.begin(), uses.begin() + uses.size() / 2, uses.end());
        uint64_t cut = uses[uses.size() / 2];
        for ( auto it = pc.pages.begin(); it != pc.pages.end(); )
        {
            auto &v = it->second;
            size_t before = v.size();
            v.erase(std::remove_if(v.begin(), v.end(), [cut](const cached_page &e) { return e.used < cut; }),
                    v.end());
            pc.count -= before - v.size();
            it = v.empty() ? pc.pages.erase(it) : std::next(it);
        }
    }

    // The page at 'page' as of the cursor's position, from the cache or from
    // memory_at. 'dst' and 'kn' receive kPage bytes each.
    void read_page(cursor_t *c, uint64_t page, uint8_t *dst, uint8_t *kn)
    {
        page_cache &pc = c->owner->pages;
        {
            std::lock_guard<std::mutex> lock(pc.mtx);
            auto it = pc.pages.find(page);
            if ( it != pc.pages.end() )
                for ( cached_page &e : it->second )
                    if ( e.from <= c->position && c->position <= e.to )
                    {
                        e.used = ++pc.clock;
                        memcpy(dst, e.bytes.data(), kPage);
                        memcpy(kn, e.known.data(), kPage);
                        return;
                    }
        }

        cached_page e;
        std::vector<std::optional<uint8_t>> v = c->trace->memory_at(c->position, page, kPage);
        e.bytes.assign(kPage, 0);
        e.known.assign(kPage, 0);
        for ( size_t i = 0; i < kPage && i < v.size(); i++ )
            if ( v[i] )
            {
                e.bytes[i] = *v[i];
                e.known[i] = 1;
            }
        stable_span(*c->trace, page, c->position, &e.from, &e.to);
        memcpy(dst, e.bytes.data(), kPage);
        memcpy(kn, e.known.data(), kPage);

        std::lock_guard<std::mutex> lock(pc.mtx);
        e.used = ++pc.clock;
        pc.pages[page].push_back(std::move(e));
        pc.count++;
        trim(pc);
    }

    int cursor_read_memory(ittd_cursor *hc, uint64_t ea, void *buf, uint8_t *known,
                           size_t size, size_t *out_known)
    {
        cursor_t *c = C(hc);
        if ( c == nullptr || (buf == nullptr && size != 0) )
            return ITTD_E_BAD_ARG;
        return guarded(c->owner->error, [&]()
        {
            uint8_t page[kPage], kn[kPage];
            uint8_t *dst = static_cast<uint8_t *>(buf);
            size_t n = 0;
            for ( uint64_t a = ea; a < ea + size; )
            {
                uint64_t base = a & ~(kPage - 1);
                uint64_t off  = a - base;
                uint64_t take = std::min<uint64_t>(kPage - off, ea + size - a);
                read_page(c, base, page, kn);
                for ( uint64_t i = 0; i < take; i++ )
                {
                    size_t k = (size_t)(a - ea + i);
                    if ( kn[off + i] )
                    {
                        dst[k] = page[off + i];
                        n++;
                    }
                    if ( known != nullptr )
                        known[k] = kn[off + i] ? 1 : 0;
                }
                a += take;
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

    // The next (or previous) execution of an instruction covering 'a', by step.
    //
    // Covering, not starting at: that is what an execute breakpoint means to
    // Microsoft's engine, and IDA relies on it. Its backward step-over puts
    // the temporary breakpoint on the return address minus one -- the last
    // byte of the call -- and runs backward to it.
    //
    // next_access(s) answers steps above s and previous_access(s) steps below
    // s. At cursor position p the instruction about to run is step p + 1: run
    // forward looks at steps after it, run backward at steps up to p, the last
    // one that already ran.
    std::optional<uint64_t> execution_of(ttd::trace &t, uint64_t a, uint64_t position, bool forward)
    {
        const uint64_t X = (uint64_t)ttd::access_kind::execute;
        std::optional<ttd::access_event> ev = forward ? t.next_access(a, 1, position + 1, X)
                                                      : t.previous_access(a, 1, position + 1, X);
        if ( !ev )
            return std::nullopt;
        return ev->step;
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

    // Whether the instruction bytes of an execute event are a return: C3, C2
    // imm16, or the far forms, after any prefixes ("rep ret" included).
    bool is_ret_insn(const ttd::access_event &e)
    {
        size_t n = (size_t)std::min<uint64_t>(e.size, e.payload.size());
        size_t i = 0;
        for ( ; i < n; i++ )
        {
            uint8_t b = e.payload[i];
            bool prefix = b == 0x66 || b == 0x67 || b == 0xF2 || b == 0xF3 || (b & 0xF0) == 0x40;
            if ( !prefix )
                break;
        }
        if ( i >= n )
            return false;
        uint8_t op = e.payload[i];
        return op == 0xC3 || op == 0xC2 || op == 0xCB || op == 0xCA;
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
            pos = pos - lo > (uint64_t)(-delta) ? pos - (uint64_t)(-delta) : lo;
        else
            pos = hi - pos > (uint64_t)delta ? pos + (uint64_t)delta : hi;
        *out = at(pos);
        return ITTD_OK;
    }

    // The stack pointer of the thread about to run after 'position', or
    // nothing when the state there cannot be rebuilt.
    std::optional<uint64_t> sp_at(ttd::trace &t, uint64_t position)
    {
        try
        {
            ttd::cpu_view view(t, position);
            return view.cpu().reg<uint64_t>(x86_register::rsp);
        }
        catch ( const ttd::divergence_error & )
        {
            return std::nullopt;
        }
    }

    // The call that entered the frame thread 'tid' stands in at cursor
    // position 'pos'. Walk the thread's instructions backward from the one
    // about to run, counting returns in and calls out: the first call met at
    // depth zero entered this frame. Each step is a lookup in the thread's
    // runs, so a short walk is cheap enough for every stop.
    //
    // Not every call is matched by a ret: one whose callee leaves by a
    // syscall, a context switch or an exception looks, walking back, exactly
    // like the call that entered this frame. The difference is the stack: the
    // entering call was made from a shallower frame, above the stack pointer
    // here, and one of those is below it. So a call at depth zero is accepted
    // only if its stack pointer was higher -- read just before it, where the
    // thread about to run is certainly this one. That costs a cpu_view per
    // candidate, and there is rarely more than one.
    //
    // 'check_sp' false skips that check, for a caller walking many frames that
    // cannot afford a cpu_view per candidate and takes the small risk instead.
    std::optional<ttd::access_event> entering_call(ttd::trace &t, uint64_t pos, uint32_t tid,
                                                   uint64_t max_back, bool check_sp = true)
    {
        std::optional<uint64_t> here_sp = check_sp && thread_after(t, pos) == tid ? sp_at(t, pos)
                                                                                  : std::nullopt;
        uint64_t s = pos + 1;               // the instruction about to run
        int64_t depth = 0;
        for ( uint64_t n = 0; n < max_back; n++ )
        {
            std::optional<ttd::access_event> ev = t.previous_instruction(s, tid);
            if ( !ev )
                break;
            s = ev->step;
            if ( is_ret_insn(*ev) )
            {
                depth++;
            }
            else if ( is_call_insn(*ev) )
            {
                if ( depth == 0 )
                {
                    std::optional<uint64_t> call_sp = here_sp ? sp_at(t, ev->step - 1) : std::nullopt;
                    if ( !here_sp || !call_sp || *call_sp > *here_sp )
                        return ev;
                    continue;               // a deeper call that never returned
                }
                depth--;
            }
        }
        return std::nullopt;
    }

    int query_frame_entry(ittd_backend *hb, ittd_position where, uint32_t tid, uint64_t max_back,
                          ittd_position *out_call, uint64_t *out_entry)
    {
        backend_t *b = B(hb);
        if ( b == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            std::lock_guard<std::mutex> lock(b->mtx);
            ttd::trace &t = *b->trace;
            uint64_t pos = 0;
            if ( !resolve(t, where, &pos) )
                return ITTD_E_NO_POSITION;
            std::optional<ttd::access_event> call = entering_call(t, pos, tid, max_back);
            if ( !call )
            {
                b->error = "no entering call within the search bound";
                return ITTD_E_FAILED;
            }
            std::optional<ttd::access_event> entry = t.next_instruction(call->step, tid);
            if ( out_call != nullptr )
                *out_call = before_step(call->step);
            if ( out_entry != nullptr )
                *out_entry = entry ? entry->ip : 0;
            return ITTD_OK;
        });
    }

    // How far back the navigator looks for the call that entered a frame.
    // Stepping out of a frame that has run for longer than this (main, say)
    // reports that no entering call was found rather than walking forever.
    static const uint64_t kNavFrameWalk = 1ull << 22;

    // The return of the call made at step 'call_step' on 'tid', as the step of
    // its ret, from calls_to -- which pairs a call with its ret through the
    // stack slot the return address went to, exact under recursion.
    std::optional<uint64_t> return_of(ttd::trace &t, uint64_t call_step, uint32_t tid)
    {
        std::optional<ttd::access_event> entry = t.next_instruction(call_step, tid);
        if ( !entry )
            return std::nullopt;
        for ( const ttd::call_event &e : t.calls_to(entry->ip, entry->step, entry->step) )
            if ( e.step == call_step && e.return_step != UINT64_MAX )
                return e.return_step;
        return std::nullopt;
    }

    // Move to 'dest', unless a breakpoint lies strictly between the cursor and
    // it: then stop on the breakpoint, as a live process would.
    void move_guarded(cursor_t *c, uint64_t dest, bool forward, int *stop)
    {
        uint64_t bp = 0;
        size_t hit = 0;
        if ( !c->breakpoints.empty() && nearest_hit(c, c->breakpoints, forward, &bp, &hit)
          && (forward ? bp > c->position && bp < dest : bp < c->position && bp > dest) )
        {
            dest  = bp;
            *stop = ITTD_STOP_BREAKPOINT;
        }
        move(c, dest);
    }

    // Forward step over: run the instruction about to execute on this thread,
    // and if it is a call, the whole call. The return comes from calls_to,
    // which pairs a call with its ret through the stack slot the return
    // address was pushed to -- exact under recursion, where "the next time
    // this thread reaches the return address" is not.
    //
    // Backward: step back one instruction on this thread, and if that was a
    // ret, on back to just before the call it returned from.
    int nav_step_over(ittd_cursor *hc, int forward, int *out_stop)
    {
        cursor_t *c = C(hc);
        if ( c == nullptr )
            return ITTD_E_BAD_ARG;
        if ( !forward )
        {
            return guarded(c->owner->error, [&]()
            {
                ttd::trace &t = *c->trace;
                uint32_t tid = thread_after(t, c->position);
                int stop = ITTD_STOP_BOUNDARY;
                uint64_t dest = first_position(t);
                // The last instruction this thread ran.
                std::optional<ttd::access_event> prev = t.previous_instruction(c->position + 1, tid);
                if ( prev )
                {
                    dest = prev->step - 1;
                    stop = ITTD_STOP_STEPPED;
                    if ( is_ret_insn(*prev) )
                    {
                        // Standing just before the ret is standing in the callee.
                        std::optional<ttd::access_event> call
                            = entering_call(t, prev->step - 1, tid, kNavFrameWalk);
                        if ( call )
                            dest = call->step - 1;
                    }
                }
                move_guarded(c, dest, false, &stop);
                if ( out_stop != nullptr )
                    *out_stop = stop;
                return ITTD_OK;
            });
        }
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
                    if ( std::optional<uint64_t> ret = return_of(t, cur->step, tid) )
                    {
                        dest = *ret;                // just after the ret
                        stop = ITTD_STOP_STEPPED;
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

    // Step out: find the call that entered this frame. Backward, stand just
    // before it; forward, just after its ret. A frame with no entering call
    // in reach (a thread's outermost, or one older than the walk) or whose
    // call never returns stays put and says why.
    int nav_step_out(ittd_cursor *hc, int forward, int *out_stop)
    {
        cursor_t *c = C(hc);
        if ( c == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(c->owner->error, [&]()
        {
            ttd::trace &t = *c->trace;
            uint32_t tid = thread_after(t, c->position);
            std::optional<ttd::access_event> call = entering_call(t, c->position, tid, kNavFrameWalk);
            if ( !call )
            {
                c->owner->error = "no call entering this frame was found";
                return ITTD_E_FAILED;
            }
            uint64_t dest = 0;
            if ( forward )
            {
                std::optional<uint64_t> ret = return_of(t, call->step, tid);
                if ( !ret )
                {
                    c->owner->error = "this frame does not return within the recording";
                    return ITTD_E_FAILED;
                }
                dest = *ret;                // just after the ret
            }
            else
            {
                dest = call->step - 1;      // just before the call
            }
            int stop = ITTD_STOP_STEPPED;
            move_guarded(c, dest, forward != 0, &stop);
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

    // The return of a function entered by a jump -- a tail call, an import
    // thunk, the CFG dispatcher's 'jmp rax' -- which calls_to cannot pair,
    // having no call of its own to pair with. The call that led to the jump
    // is found walking back; its return address is that call's address plus
    // its length, and the function returned at the ret that the next
    // execution of that address on this thread follows. Index lookups only:
    // no CPU state is rebuilt, which on a reader that rebuilds it from a
    // checkpoint costs tens of milliseconds an entry. UINT64_MAX when there is
    // no such return (the thread ended in it, or it unwound past it).
    uint64_t return_of_jump_entry(ttd::trace &t, uint64_t entry_step, uint32_t tid)
    {
        if ( entry_step == 0 || entry_step == UINT64_MAX )
            return UINT64_MAX;
        std::optional<ttd::access_event> call = entering_call(t, entry_step - 1, tid, 1ull << 16, false);
        if ( !call )
            return UINT64_MAX;
        const uint64_t ra = call->ip + call->size;
        const uint64_t X  = (uint64_t)ttd::access_kind::execute;
        uint64_t s = entry_step;
        for ( int k = 0; k < 64; k++ )
        {
            std::optional<ttd::access_event> ev = t.next_access(ra, 1, s, X);
            if ( !ev )
                return UINT64_MAX;
            s = ev->step;
            if ( ev->ip != ra || t.thread_at(ev->step).value_or(0) != tid )
                continue;
            std::optional<ttd::access_event> prev = t.previous_instruction(ev->step, tid);
            if ( prev && is_ret_insn(*prev) )
                return prev->step;
        }
        return UINT64_MAX;
    }

    // The opcode of an executed instruction, past its prefixes, and the byte
    // after it; false when the bytes are not there.
    bool opcode_of(const ttd::access_event &ev, bool is64, uint8_t *op, uint8_t *modrm)
    {
        size_t n = std::min<size_t>(ev.size == 0 ? ev.payload.size() : (size_t)ev.size, ev.payload.size());
        size_t i = 0;
        for ( ; i < n; i++ )
        {
            uint8_t c = ev.payload[i];
            bool prefix = c == 0x66 || c == 0x67 || c == 0xF2 || c == 0xF3 || c == 0x2E || c == 0x3E
                       || c == 0x26 || c == 0x36 || c == 0x64 || c == 0x65 || c == 0xF0
                       || (is64 && c >= 0x40 && c <= 0x4F);
            if ( !prefix )
                break;
        }
        if ( i >= n )
            return false;
        *op    = ev.payload[i];
        *modrm = i + 1 < n ? ev.payload[i + 1] : 0;
        return true;
    }

    // E8, FF /2 and FF /3, and 9A on 32-bit.
    bool is_call_op(uint8_t op, uint8_t modrm, bool is64)
    {
        uint8_t reg = (modrm >> 3) & 7;
        return op == 0xE8 || (op == 0x9A && !is64) || (op == 0xFF && (reg == 2 || reg == 3));
    }

    bool is_ret_op(uint8_t op)
    {
        return op == 0xC3 || op == 0xC2 || op == 0xCB || op == 0xCA;
    }

    // Every call made in steps [s0, s1]. The reader lists calls by target, so
    // this walks the execute events: a call is recognised by its bytes, its
    // callee is the thread's next instruction, and its return is the first
    // ret on the thread that lands on its return address -- calls above it
    // on the thread's stack then left without returning (an exception, a
    // longjmp). A call that has not returned by s1 has no return.
    std::vector<ttd::call_event> every_call(ttd::trace &t, uint64_t s0, uint64_t s1, bool is64,
                                            const ttd::operation_control &ctl)
    {
        struct open_call { size_t index; uint64_t return_address; };
        struct thread_state
        {
            std::vector<open_call> open;
            std::optional<size_t>   call_pending;   // its callee is the next instruction
            std::optional<uint64_t> ret_pending;    // the step of a ret, until we see where it went
        };
        std::vector<ttd::call_event> out;
        if ( s0 > s1 )
            return out;
        std::unordered_map<uint32_t, thread_state> threads;
        const uint64_t X = (uint64_t)ttd::access_kind::execute;
        ttd::event_reader reader(t, t.first_event_after(s0 - 1));
        for ( uint64_t seen = 0;; seen++ )
        {
            std::optional<ttd::access_event> ev = reader.next(X);
            if ( !ev || ev->step > s1 )
                break;
            if ( (seen & 0xFFFF) == 0 )
            {
                ctl.check();
                if ( ctl.progress && s1 > s0 )
                    ctl.progress(ev->step - s0, s1 - s0);
            }
            uint32_t tid = t.thread_at(ev->step).value_or(0);
            thread_state &ts = threads[tid];
            if ( ts.call_pending )
            {
                out[*ts.call_pending].entry_step = ev->step;
                out[*ts.call_pending].target     = ev->ip;
                ts.call_pending.reset();
            }
            if ( ts.ret_pending )
            {
                for ( size_t k = ts.open.size(); k-- > 0; )
                    if ( ts.open[k].return_address == ev->ip )
                    {
                        out[ts.open[k].index].return_step = *ts.ret_pending;
                        ts.open.resize(k);
                        break;
                    }
                ts.ret_pending.reset();
            }
            uint8_t op = 0, modrm = 0;
            if ( !opcode_of(*ev, is64, &op, &modrm) )
                continue;
            if ( is_call_op(op, modrm, is64) )
            {
                ttd::call_event c;
                c.step      = ev->step;
                c.site      = ev->ip;
                c.thread_id = tid;
                c.is_call   = true;
                out.push_back(c);
                ts.call_pending = out.size() - 1;
                ts.open.push_back({ out.size() - 1, ev->ip + ev->size });
            }
            else if ( is_ret_op(op) )
            {
                ts.ret_pending = ev->step;
            }
        }
        // A ret on the last steps lands after s1: see where it went.
        for ( auto &[tid, ts] : threads )
        {
            if ( !ts.ret_pending )
                continue;
            std::optional<ttd::access_event> next = t.next_instruction(*ts.ret_pending, tid);
            if ( !next )
                continue;
            for ( size_t k = ts.open.size(); k-- > 0; )
                if ( ts.open[k].return_address == next->ip )
                {
                    out[ts.open[k].index].return_step = *ts.ret_pending;
                    break;
                }
        }
        // A call made on the last step has no callee in range.
        out.erase(std::remove_if(out.begin(), out.end(),
                                 [](const ttd::call_event &c) { return c.entry_step == 0; }),
                  out.end());
        return out;
    }

    int query_calls(ittd_backend *hb, const uint64_t *targets, size_t ntargets,
                    ittd_position_range when, ittd_call *buf, size_t cap,
                    size_t *out_count, int *out_truncated, const ittd_progress *progress)
    {
        backend_t *b = B(hb);
        if ( b == nullptr || (targets == nullptr && ntargets != 0) )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            std::lock_guard<std::mutex> lock(b->mtx);
            ttd::trace &t = *b->trace;
            uint64_t s0 = 0, s1 = 0;
            step_range(t, when, &s0, &s1);
            std::vector<ttd::call_event> all;
            // No targets: every call in the range -- for a short one, such as
            // the run of one function a call tree shows.
            if ( ntargets == 0 )
            {
                const ttd::module_entry *m = main_module(t);
                all = every_call(t, s0, s1, m == nullptr || m->machine != 0x14c, control(progress));
            }
            for ( size_t i = 0; i < ntargets; i++ )
            {
                // Each target's share of the whole: a pattern can name
                // thousands, and reported one by one the bar ran 0 to 100%
                // over and over.
                ttd::operation_control ctl = control(progress);
                if ( ctl.progress )
                {
                    auto whole = ctl.progress;
                    ctl.progress = [whole, i, ntargets](uint64_t done, uint64_t total)
                    {
                        uint64_t part = total == 0 ? 0 : std::min<uint64_t>(1000, done * 1000 / total);
                        whole((uint64_t)i * 1000 + part, (uint64_t)ntargets * 1000);
                    };
                }
                std::vector<ttd::call_event> v = t.calls_to(targets[i], s0, s1, ctl);
                all.insert(all.end(), v.begin(), v.end());
            }
            std::sort(all.begin(), all.end(), [](const ttd::call_event &a, const ttd::call_event &b)
                      { return a.entry_step < b.entry_step; });
            // In entry order, after the sort: each needs the CPU at its entry,
            // and the reader rebuilds that from the nearest checkpoint, which
            // it keeps only one of -- out of order, nearly every entry would
            // pay for its checkpoint again.
            for ( ttd::call_event &e : all )
                if ( !e.is_call && e.return_step == UINT64_MAX )
                    e.return_step = return_of_jump_entry(t, e.entry_step, e.thread_id);
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

    // The syscall table is decoded when the trace opens, so this is a copy. The
    // thread comes from the thread-switch table; the arguments are left to
    // regs_at, since the table does not hold them.
    int query_syscalls(ittd_backend *hb, ittd_syscall *buf, size_t cap, size_t *out_count,
                       int *out_truncated, const ittd_progress *)
    {
        backend_t *b = B(hb);
        if ( b == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            std::lock_guard<std::mutex> lock(b->mtx);
            const ttd::trace &t = *b->trace;
            std::span<const ttd::syscall_entry> v = t.syscalls();
            set_truncated(out_truncated, v.size(), cap, buf != nullptr);
            return fill(v, buf, cap, out_count, [&](const ttd::syscall_entry &e)
            {
                ittd_syscall x{};
                x.pos    = before_step(e.step);
                x.result = e.result;
                x.number = e.id;
                x.tid    = t.thread_at(e.step).value_or(0);
                if ( std::optional<std::string_view> n = t.syscall_name(e.id) )
                {
                    size_t len = std::min(n->size(), sizeof(x.name) - 1);
                    memcpy(x.name, n->data(), len);
                }
                return x;
            });
        });
    }

    // One pass over every write and execute event in the recording, in the
    // reader: seconds on a large trace, and progress counts events.
    int query_self_modifying(ittd_backend *hb, ittd_selfmod *buf, size_t cap, size_t *out_count,
                             int *out_truncated, const ittd_progress *progress)
    {
        backend_t *b = B(hb);
        if ( b == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            // Its own reader under scan_mtx: seconds of scanning must not
            // hold up the cursors' reads, which take 'mtx'.
            std::lock_guard<std::mutex> lock(b->scan_mtx);
            std::unique_ptr<ttd::trace> own = open_trace(b->path);
            ttd::trace &t = *own;
            const uint64_t need = (uint64_t)ttd::access_kind::write | (uint64_t)ttd::access_kind::execute;
            if ( (t.access_mask() & need) != need )
            {
                b->error = "this recording was made without write or execute events, "
                           "which finding self-modifying code needs";
                return ITTD_E_FAILED;
            }
            std::vector<ttd::self_modifying_hit> v = t.self_modifying_code(control(progress));
            set_truncated(out_truncated, v.size(), cap, buf != nullptr);
            return fill(v, buf, cap, out_count, [](const ttd::self_modifying_hit &h)
            {
                ittd_selfmod x{};
                x.address     = h.address;
                x.size        = h.size;
                x.write_pos   = before_step(h.write_step);
                x.write_ip    = h.write_ip;
                x.execute_pos = before_step(h.execute_step);
                x.executions  = h.executions;
                return x;
            });
        });
    }

    // ------------------------------------------------------------ forks

    // The folder this DLL was loaded from: the default registry folder is a
    // "registry" folder next to it.
    std::filesystem::path module_dir()
    {
        HMODULE self = nullptr;
        wchar_t buf[MAX_PATH] = {};
        if ( GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
                              | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                reinterpret_cast<LPCWSTR>(&module_dir), &self)
          && GetModuleFileNameW(self, buf, MAX_PATH) != 0 )
            return std::filesystem::path(buf).parent_path();
        return std::filesystem::current_path();
    }

    std::string manifest_value(const ttd::trace &t, std::string_view key)
    {
        for ( const auto &[k, v] : t.manifest() )
            if ( k == key )
                return v;
        return std::string();
    }

    // The setting if the caller's struct is new enough to carry it.
    template <typename T>
    const T *setting(const ittd_fork_settings *s, const T *field)
    {
        if ( s == nullptr )
            return nullptr;
        size_t end = reinterpret_cast<const char *>(field) - reinterpret_cast<const char *>(s) + sizeof(T);
        return end <= s->size ? field : nullptr;
    }

    // An emulator set up to replay 't' the way Sogen records: Unicorn, the
    // relative clock, the CPUID overrides, and a headless UI that takes the
    // recorded window input. 'strict' is set from the settings.
    std::unique_ptr<sogen::windows_emulator> replay_emulator(const ttd::trace &t, const ittd_fork_settings *settings,
                                                             bool *strict)
    {
        std::filesystem::path registry = module_dir() / "registry";
        std::filesystem::path root = manifest_value(t, "emulation_root");
        *strict = false;
        if ( const auto *const *v = setting(settings, &settings->registry_dir); v != nullptr && *v != nullptr && **v != '\0' )
            registry = utf8_path(*v);
        if ( const auto *const *v = setting(settings, &settings->emulation_root); v != nullptr && *v != nullptr )
            root = utf8_path(*v);
        bool allow_host = false;
        if ( const uint32_t *v = setting(settings, &settings->flags); v != nullptr )
        {
            *strict    = (*v & ITTD_FORK_STRICT) != 0;
            allow_host = (*v & ITTD_FORK_ALLOW_HOST) != 0;
        }
        // Against the host, the program's file and network operations reach
        // this machine for real. Only on request.
        if ( root.empty() && !allow_host )
            throw coded_error(ITTD_E_HOST_REPLAY, "this recording was made against the host, not an emulation root: "
                                     "replaying it runs the program's file and network operations on this "
                                     "machine again. Allow that explicitly to go ahead");
        if ( !std::filesystem::is_regular_file(registry / "SYSTEM") )
            throw coded_error(ITTD_E_NO_REGISTRY, "no registry hives (SYSTEM, SOFTWARE, ...) in " + registry.string()
                                                  + ": replaying the program loads the registry it ran against");

        sogen::emulator_settings es{};
        es.disable_logging    = true;
        es.use_relative_time  = true;
        es.emulation_root     = root;
        es.registry_directory = registry;
        sogen::emulator_interfaces ifs{};
        ifs.ui = std::make_unique<ttd::recordable_ui_backend>(std::make_unique<sogen::null_ui_backend>());
        auto emu = std::make_unique<sogen::windows_emulator>(sogen::unicorn::create_x86_64_emulator(), es,
                                                             sogen::emulator_callbacks{}, std::move(ifs));
        ttd::install_cpuid_overrides(*emu);
        ttd::require_deterministic(*emu);
        return emu;
    }

    // Seek a fresh emulator to the position: a checkpoint restore and up to a
    // checkpoint interval of replay, verified against the recording.
    int fork_open(ittd_backend *hb, ittd_position at_pos, const ittd_fork_settings *settings,
                  const ittd_progress *progress, ittd_fork **out)
    {
        backend_t *b = B(hb);
        if ( b == nullptr || out == nullptr )
            return ITTD_E_BAD_ARG;
        *out = nullptr;
        return guarded(b->error, [&]()
        {
            auto f = std::make_unique<fork_t>();
            f->owner = b;
            f->trace = open_trace(b->path);
            f->trace->set_checkpoint_cache_size(kCheckpointsPerReader);
            if ( !resolve(*f->trace, at_pos, &f->position) )
            {
                b->error = "that position is not in the recording";
                return ITTD_E_NO_POSITION;
            }
            bool strict = false;
            f->emu = replay_emulator(*f->trace, settings, &strict);
            ttd::seek(*f->emu, *f->trace, f->position, strict, control(progress));
            *out = reinterpret_cast<ittd_fork *>(f.release());
            return ITTD_OK;
        });
    }

    const x86_register kGp[ITTD_REG_GP_COUNT] = {
        x86_register::rax, x86_register::rcx, x86_register::rdx, x86_register::rbx,
        x86_register::rsp, x86_register::rbp, x86_register::rsi, x86_register::rdi,
        x86_register::r8,  x86_register::r9,  x86_register::r10, x86_register::r11,
        x86_register::r12, x86_register::r13, x86_register::r14, x86_register::r15,
        x86_register::rip,
    };

    int fork_regs(ittd_fork *hf, ittd_regs *out)
    {
        fork_t *f = F(hf);
        if ( f == nullptr || out == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(f->owner->error, [&]()
        {
            auto &cpu = f->emu->emu();
            *out = ittd_regs{};
            for ( int i = 0; i < ITTD_REG_GP_COUNT; i++ )
                out->gp[i] = cpu.reg<uint64_t>(kGp[i]);
            out->rflags  = cpu.reg<uint64_t>(x86_register::rflags);
            out->fs_base = cpu.reg<uint64_t>(x86_register::fs_base);
            out->gs_base = cpu.reg<uint64_t>(x86_register::gs_base);
            out->have = ITTD_REGS_GP;
            return ITTD_OK;
        });
    }

    int fork_set_regs(ittd_fork *hf, const ittd_regs *regs)
    {
        fork_t *f = F(hf);
        if ( f == nullptr || regs == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(f->owner->error, [&]()
        {
            if ( f->recorded )
                throw std::runtime_error("this fork has already run");
            auto &cpu = f->emu->emu();
            if ( (regs->have & ITTD_REGS_GP) != 0 )
            {
                for ( int i = 0; i < ITTD_REG_GP_COUNT; i++ )
                    cpu.reg<uint64_t>(kGp[i], regs->gp[i]);
                cpu.reg<uint64_t>(x86_register::rflags, regs->rflags);
            }
            if ( (regs->have & ITTD_REGS_SEG) != 0 )
            {
                cpu.reg<uint64_t>(x86_register::fs_base, regs->fs_base);
                cpu.reg<uint64_t>(x86_register::gs_base, regs->gs_base);
            }
            return ITTD_OK;
        });
    }

    int fork_write_memory(ittd_fork *hf, uint64_t ea, const void *buf, size_t size)
    {
        fork_t *f = F(hf);
        if ( f == nullptr || (buf == nullptr && size != 0) )
            return ITTD_E_BAD_ARG;
        return guarded(f->owner->error, [&]()
        {
            if ( f->recorded )
                throw std::runtime_error("this fork has already run");
            if ( !f->emu->memory.try_write_memory(ea, buf, size) )
                throw std::runtime_error("that memory is not mapped writable in the fork");
            return ITTD_OK;
        });
    }

    int fork_record(ittd_fork *hf, const char *path, uint64_t max_instructions, const char *note,
                    const ittd_progress *progress, uint64_t *out_instructions)
    {
        fork_t *f = F(hf);
        if ( f == nullptr || path == nullptr || *path == '\0' )
            return ITTD_E_BAD_ARG;
        return guarded(f->owner->error, [&]()
        {
            if ( f->recorded )
                throw std::runtime_error("this fork has already run");
            f->recorded = true;
            ttd::record_settings rs{};
            rs.path             = utf8_path(path);
            rs.max_instructions = max_instructions;
            rs.manifest = {
                { "tool", "ida-ttd" },
                { "parent", f->owner->path.u8string().empty() ? std::string()
                            : std::string(reinterpret_cast<const char *>(f->owner->path.u8string().c_str())) },
                { "parent_id", f->trace->id() },
                { "fork_position", std::to_string(f->position) },
            };
            if ( note != nullptr && *note != '\0' )
                rs.manifest.emplace_back("fork_changes", note);
            bool stopped = false;
            std::function<bool()> interrupted;
            if ( progress != nullptr && progress->cancelled != nullptr )
                interrupted = [progress, &stopped]()
                {
                    stopped = stopped || progress->cancelled(progress->ud) != 0;
                    return stopped;
                };
            uint64_t before = f->emu->get_executed_instructions();
            ttd::record(*f->emu, rs, interrupted);
            if ( out_instructions != nullptr )
                *out_instructions = f->emu->get_executed_instructions() - before;
            // A cancelled recording is still a finished, readable trace of
            // what ran before the stop.
            return ITTD_OK;
        });
    }

    void fork_close(ittd_fork *hf)
    {
        delete F(hf);
    }

    // ------------------------------------------------------------ replay scans

    // The position of text that appeared at 'step' (0: there from the start).
    ittd_position appeared_at(const ttd::trace &t, uint64_t step)
    {
        return step == 0 ? at(first_position(t)) : before_step(step);
    }

    // What a replay scan's answer depends on besides the recording.
    // Replay the whole recording with a scanner attached. Where the replay
    // diverges from the recording -- typically because this machine's files
    // are not the ones a host recording ran against -- it is not the end: the
    // next checkpoint holds the recording's own state, so the scan restores
    // it and goes on. 'leaving' runs before the restore and 'restored' after
    // it: a scanner that cannot watch a restore (the buffer scanner owns the
    // emulator's one mapping-change callback, which seek needs) is put away
    // and a new one attached; one that can is shown the restored memory.
    // Returns what was skipped, in words; empty when nothing was. Strict
    // replays still fail at the first divergence.
    std::string replay_scan(sogen::windows_emulator &emu, ttd::trace &t, const std::function<void()> &attach,
                            const std::function<void()> &leaving, const std::function<void()> &restored,
                            bool strict, const ittd_progress *progress)
    {
        try
        {
            ttd::replay_to_end(emu, t, attach, strict, true, control(progress));
            return std::string();
        }
        catch ( const ttd::divergence_error &e )
        {
            if ( strict )
                throw;
            std::string first = e.what();
            const uint64_t end = t.metadata().instruction_count;
            uint64_t skipped = 0;
            int gaps = 0;
            for ( ;; )
            {
                const uint64_t at = emu.get_executed_instructions();
                uint64_t next = end;
                for ( const auto &c : t.checkpoints() )
                    if ( c.step > at )
                    {
                        next = c.step;
                        break;
                    }
                skipped += next - at;
                gaps++;
                if ( next >= end )
                    break;
                leaving();
                ttd::seek(emu, t, next, strict, control(progress));
                restored();
                try
                {
                    ttd::run_to(emu, t, end, strict, control(progress));
                    break;
                }
                catch ( const ttd::divergence_error & )
                {
                }
            }
            // A fork's recording starts where it was forked, not at 0.
            const uint64_t total = end - std::min(end, t.start_position());
            char head[160];
            snprintf(head, sizeof(head), "the replay diverged from the recording %d time%s; %llu of %llu "
                     "instructions (%.1f%%) were skipped up to the next checkpoint. First: ",
                     gaps, gaps == 1 ? "" : "s", (unsigned long long)skipped, (unsigned long long)total,
                     total == 0 ? 0.0 : 100.0 * (double)skipped / (double)total);
            return head + first;
        }
    }

    std::string scan_key(const ittd_fork_settings *settings)
    {
        std::string key;
        if ( const uint32_t *v = setting(settings, &settings->flags); v != nullptr )
            key += std::to_string(*v);
        key += '|';
        if ( const auto *const *v = setting(settings, &settings->registry_dir); v != nullptr && *v != nullptr )
            key += *v;
        key += '|';
        if ( const auto *const *v = setting(settings, &settings->emulation_root); v != nullptr && *v != nullptr )
            key += *v;
        return key;
    }

    int query_strings(ittd_backend *hb, const ittd_fork_settings *settings, uint32_t min_length,
                      ittd_string_hit *buf, size_t cap, size_t *out_count,
                      int *out_truncated, const ittd_progress *progress)
    {
        backend_t *b = B(hb);
        if ( b == nullptr )
            return ITTD_E_BAD_ARG;
        if ( min_length < 2 )
            min_length = 2;
        return guarded(b->error, [&]()
        {
            std::lock_guard<std::mutex> lock(b->scan_mtx);
            const std::string key = std::to_string(min_length) + "|" + scan_key(settings);
            auto found = b->strings.find(key);
            if ( found == b->strings.end() )
            {
                std::unique_ptr<ttd::trace> t = open_trace(b->path);
                bool strict = false;
                auto emu = replay_emulator(*t, settings, &strict);
                std::optional<ttd::string_scanner> scanner;
                b->scan_notes[key] = replay_scan(*emu, *t, [&]()
                {
                    scanner.emplace(*emu, min_length);
                    scanner->scan_initial_memory();
                }, []() {}, [&]()
                {
                    // Attached by now, unless the replay was refused before
                    // it started.
                    if ( !scanner )
                        scanner.emplace(*emu, min_length);
                    scanner->scan_initial_memory();
                }, strict, progress);
                if ( !scanner )
                    throw std::runtime_error("the replay did not start");
                scanner->finish();
                std::vector<ittd_string_hit> v;
                for ( const ttd::recovered_string &s : scanner->results() )
                {
                    ittd_string_hit h{};
                    h.address = s.address;
                    h.pos     = appeared_at(*t, s.step);
                    h.wide    = s.encoding.find("16") != std::string::npos ? 1 : 0;
                    copy_str(h.text, sizeof(h.text), s.value);
                    // Characters, not bytes: UTF-8 continuation bytes do not count.
                    for ( unsigned char ch : s.value )
                        if ( (ch & 0xC0) != 0x80 )
                            h.length++;
                    v.push_back(h);
                }
                found = b->strings.emplace(key, std::move(v)).first;
            }
            b->scan_note = b->scan_notes[key];
            set_truncated(out_truncated, found->second.size(), cap, buf != nullptr);
            return fill(found->second, buf, cap, out_count, [](const ittd_string_hit &h) { return h; });
        });
    }

    int query_buffers(ittd_backend *hb, const ittd_fork_settings *settings,
                      ittd_buffer_hit *buf, size_t cap, size_t *out_count,
                      int *out_truncated, const ittd_progress *progress)
    {
        backend_t *b = B(hb);
        if ( b == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            std::lock_guard<std::mutex> lock(b->scan_mtx);
            const std::string key = scan_key(settings);
            auto found = b->buffers.find(key);
            if ( found == b->buffers.end() )
            {
                std::unique_ptr<ttd::trace> t = open_trace(b->path);
                bool strict = false;
                auto emu = replay_emulator(*t, settings, &strict);
                std::optional<ttd::buffer_scanner> scanner;
                // What scanners put away at a restore found, then the last one's.
                std::vector<ttd::recovered_buffer> found_before;
                auto put_away = [&]()
                {
                    if ( !scanner )
                        return;
                    scanner->finish();
                    found_before.insert(found_before.end(), scanner->results().begin(), scanner->results().end());
                    scanner.reset();
                };
                b->scan_notes[key] = replay_scan(*emu, *t, [&]() { scanner.emplace(*emu, *t); },
                                                 put_away, [&]() { scanner.emplace(*emu, *t); }, strict, progress);
                put_away();
                std::vector<ittd_buffer_hit> v;
                for ( const ttd::recovered_buffer &r : found_before )
                {
                    ittd_buffer_hit h{};
                    h.address   = r.address;
                    h.size      = r.size;
                    h.first_pos = before_step(r.first_step);
                    h.last_pos  = before_step(r.last_step);
                    h.writer_ip = r.writer_ip;
                    h.writes    = r.writes;
                    copy_str(h.kind, sizeof(h.kind), r.kind);
                    copy_str(h.preview, sizeof(h.preview), r.preview);
                    v.push_back(h);
                }
                found = b->buffers.emplace(key, std::move(v)).first;
            }
            b->scan_note = b->scan_notes[key];
            set_truncated(out_truncated, found->second.size(), cap, buf != nullptr);
            return fill(found->second, buf, cap, out_count, [](const ittd_buffer_hit &h) { return h; });
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
    // Who asked for a change the map records: the routine whose system call
    // made it (the call that entered the syscall's stub, so ntdll's
    // NtAllocateVirtualMemory) and the call sites that led there, innermost
    // first and one per module crossed -- what the Microsoft backend reports
    // from the calls it watches. Sogen records the outcome, not the call, so
    // the chain is walked back from the syscall instruction.
    void syscall_chain(ttd::trace &t, uint64_t sys_step, uint32_t tid,
                       const std::vector<std::pair<uint64_t, uint64_t>> &mods, ittd_mapping_change *m)
    {
        static const uint64_t kWalk   = 1ull << 16;    // instructions back, per frame
        static const int      kFrames = 32;
        auto module_of = [&mods](uint64_t a) -> size_t
        {
            for ( size_t i = 0; i < mods.size(); i++ )
                if ( a >= mods[i].first && a < mods[i].first + mods[i].second )
                    return i;
            return (size_t)-1;
        };
        std::optional<ttd::access_event> call = entering_call(t, sys_step - 1, tid, kWalk, false);
        if ( !call )
            return;
        if ( std::optional<ttd::access_event> entry = t.next_instruction(call->step, tid) )
            m->api = entry->ip;
        size_t last = (size_t)-2;
        for ( int f = 0; call && f < kFrames && m->chain_n < ITTD_CHAIN_MAX; f++ )
        {
            size_t mi = module_of(call->ip);
            if ( m->chain_n == 0 || mi != last )
            {
                m->chain[m->chain_n++] = call->ip;
                last = mi;
            }
            call = entering_call(t, call->step - 1, tid, kWalk, false);
        }
    }

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
            std::vector<std::pair<uint64_t, uint64_t>> mods;
            for ( const ttd::module_entry &me : t.modules() )
                mods.emplace_back(me.base, me.size);
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
                {
                    m.call_pos = before_step(it->step);
                    syscall_chain(*b->trace, it->step, m.tid, mods, &m);
                }
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
        a.size               = sizeof(ittd_backend_api);
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
        a.nav_step_over      = nav_step_over;
        a.nav_step_out       = nav_step_out;
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
        a.query_syscalls     = query_syscalls;
        a.query_self_modifying = query_self_modifying;
        a.fork_open          = fork_open;
        a.fork_regs          = fork_regs;
        a.fork_set_regs      = fork_set_regs;
        a.fork_write_memory  = fork_write_memory;
        a.fork_record        = fork_record;
        a.fork_close         = fork_close;
        a.query_strings      = query_strings;
        a.query_buffers      = query_buffers;
        a.scan_notice        = scan_notice;
        a.regs_at            = regs_at;
        a.query_instructions = query_instructions;
        a.position_add       = position_add;
        a.query_frame_entry  = query_frame_entry;
        a.query_mapping_files = query_mapping_files;
        return a;
    }();
}

extern "C" __declspec(dllexport) const ittd_backend_api *ida_ttd_backend(uint32_t abi_version)
{
    return abi_version == ITTD_ABI_VERSION ? &g_api : nullptr;
}
