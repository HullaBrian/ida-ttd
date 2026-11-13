// SPDX-License-Identifier: GPL-2.0-only
//
// ida-ttd backend for Sogen time-travel traces (.sogttd).
//
// A separate DLL, loaded by the ida-ttd core through the C ABI in
// abi/ida_ttd_backend.h. It links Sogen's trace reader and cpu_view
// (windows-ttd-reader, windows-ttd-view) and nothing of ida-ttd's, and never
// sees an IDA type. docs/modular-backends.md section 6 maps each entry point
// onto Sogen.
//
// Sogen is GPL-2.0-only, so a built ida-ttd-sogen.dll is a GPL-2.0 binary, and
// this file, which is only ever built into it, is GPL-2.0-only too
// (LICENSES/GPL-2.0-only.txt), unlike the rest of ida-ttd (Apache-2.0).
//
// Conventions used throughout:
//
//  - Positions. Sogen position N is the state after instruction N, which is
//    the state before instruction N + 1: the ABI's meaning. A cursor position
//    is therefore a Sogen position with hi = 0. An event's step is the
//    1-based number of the instruction that did it, so its ABI position is
//    step - 1 (the state just before it).
//  - No exception leaves an entry point. Bodies run through guarded(), which
//    maps operation_cancelled to ITTD_E_CANCELLED and anything else to
//    ITTD_E_FAILED with the reason in last_error.
//  - One sogen::ttd::trace per handle and per cursor, plus one for the long
//    queries (query_reader). A trace is not thread-safe (one ifstream,
//    mutable caches, a lazily built CPU), and opening another costs about
//    25 ms, so none is shared.

#include <abi/ida_ttd_backend.h>
#include <common/local_path.h>
#include <common/write_scans.h>

#include <ttd_trace.hpp>
#include <ttd_view.hpp>

// Forks: the emulator, Sogen's replay and recorder, and the headless UI a
// replay delivers recorded window input to.
#include <windows_emulator.hpp>
#include <ttd_session.hpp>
#include <ttd_network.hpp>
#include <ttd_ui.hpp>
#include <unicorn_x86_64_emulator.hpp>
#include <platform/ui_backend.hpp>
#include <platform/console_backend.hpp>
#include <network/dns_lookup.hpp>
#include <network/socket_factory.hpp>
#include <network/socket_wrapper.hpp>
#include <ttd_string_scan.hpp>
#include <ttd_buffer_scan.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ttd = sogen::ttd;
using sogen::x86_register;

namespace
{
    // ------------------------------------------------------------ handles

    // A message the core reads back through last_error or scan_notice.
    //
    // Written by whichever thread failed (a query on the core's worker, a
    // cursor call on IDA's main thread) and often read by another, so the
    // text is only touched under the mutex. The reader gets a copy in a
    // thread_local buffer, which stays valid until that thread asks again,
    // whatever other threads write meanwhile: the ABI's "valid until the next
    // call on the same handle".
    class text_slot
    {
      public:
        void set(std::string text)
        {
            std::lock_guard<std::mutex> lock(m_mtx);
            m_text = std::move(text);
        }

        void clear() { set(std::string()); }

        const char *get() const
        {
            thread_local std::string copy;
            std::lock_guard<std::mutex> lock(m_mtx);
            copy = m_text;
            return copy.c_str();
        }

      private:
        mutable std::mutex m_mtx;
        std::string m_text;
    };

    // One page as memory_at showed it, and the positions it holds for.
    //
    // memory_at walks the page's recorded accesses until every byte is
    // accounted for, which on a hot code page (ntdll's, executed millions of
    // times) costs tens of milliseconds. IDA reads a module's code page by
    // page after every stop, so uncached reads froze it for minutes. A page
    // only changes at a write to it or a change to its mapping, so one read
    // answers every position in between.
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

    // A thread and the span it ran over, from the switch table.
    struct thread_span
    {
        uint32_t tid = 0;
        uint64_t first_step = UINT64_MAX;
        uint64_t end_step = 0;          // one past the last step it ran
        bool     running_at_end = false;
    };

    struct backend_t
    {
        std::filesystem::path path;
        std::unique_ptr<ttd::trace> trace;   // for the short whole-trace calls
        std::mutex mtx;                      // guards 'trace'
        text_slot error;
        // The reader the long queries run on (query_reader), opened on first
        // use. Its own mutex means a query that takes seconds never holds
        // 'mtx', which the module and thread lists asked for at every stop
        // need.
        std::unique_ptr<ttd::trace> query_trace;
        std::mutex query_mtx;                // guards 'query_trace'
        page_cache pages;                    // shared by this backend's cursors
        // Every thread's span, computed once at open: the switch table is
        // fixed, and the thread list is asked for at every stop.
        std::vector<thread_span> spans;
        // Cached scan results: each scan is a full pass and count-then-fill
        // asks twice. A separate mutex keeps a scan from holding up the other
        // queries.
        std::mutex scan_mtx;
        // Keyed by what the replay ran with (scan_key), and for strings also
        // the minimum length, so a strict run is never answered by a lenient one.
        std::map<std::string, std::vector<ittd_string_hit>> strings;
        std::map<std::string, std::vector<ittd_buffer_hit>> buffers;
        // Whether a cached scan stopped keeping results at a scanner's own
        // limit, by the same keys, so a later fill still reports it.
        std::map<std::string, bool> strings_truncated, buffers_truncated;
        // query_executed's answer, kept between its count and fill calls,
        // and the ranges it was for.
        std::vector<std::pair<uint64_t, uint64_t>> executed_ranges;
        std::vector<uint64_t> executed;
        bool executed_valid = false;
        // Address ranges recorded as MMIO at any time (region kind 5), whose
        // pages are never cached: memory_at reads them from their accesses,
        // so they change at reads too, not only at writes.
        std::vector<std::pair<uint64_t, uint64_t>> mmio;
        // query_access_heat's answers, by page shift and slice count.
        std::map<std::string, std::vector<ittd_heat_cell>> heat;
        // What each cached scan skipped (scan_notice), by the same keys, and
        // the last scan's.
        std::map<std::string, std::string> scan_notes;
        text_slot scan_note;
    };

    struct cursor_t
    {
        backend_t *owner = nullptr;
        std::unique_ptr<ttd::trace> trace;   // this cursor's own reader
        uint64_t position = 0;
        std::vector<ittd_breakpoint> breakpoints;
        // The CPU at 'position', built on first use and dropped on every move.
        std::unique_ptr<ttd::cpu_view> view;
        // Cancel for the movements that walk (nav_set_progress); the core
        // keeps it valid until it clears it.
        const ittd_progress *progress = nullptr;
    };

    // A recording replayed to a position and held there (fork_open).
    struct fork_t
    {
        backend_t *owner = nullptr;
        std::unique_ptr<ttd::trace> trace;               // its own reader: seek needs one
        std::unique_ptr<sogen::windows_emulator> emu;
        uint64_t position = 0;
        bool     recorded = false;                       // fork_record runs once
        // From fork_open's settings, for fork_record (which has none).
        uint64_t access_kinds = ttd::all_access_kinds;
        uint64_t checkpoint_interval = 0;                // 0: Sogen's default
        // Set when the settings asked for the network: opened once the
        // replay has reached the position.
        std::shared_ptr<struct net_gate> net;
    };

    text_slot g_module_error;       // last_error(NULL)

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

    // The thread that runs the instruction after 'position'. cpu_view shows
    // its registers there, since a snapshot taken at a thread switch already
    // holds the incoming thread.
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
    int guarded(text_slot &err, F &&body)
    {
        try
        {
            return body();
        }
        catch ( const ttd::operation_cancelled & )
        {
            err.set("canceled");
            return ITTD_E_CANCELLED;
        }
        catch ( const coded_error &e )
        {
            err.set(e.what());
            return e.code;
        }
        catch ( const std::exception &e )
        {
            err.set(e.what());
            return ITTD_E_FAILED;
        }
        catch ( ... )
        {
            err.set("unknown error");
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

    // The ittd_access kind of a Sogen event. A host write (a syscall writing
    // guest memory) counts as a write for "who wrote this".
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
    // about the size of the program's committed memory, and every cursor has
    // a reader: with four, a session on a large recording passed half a
    // gigabyte. Two cover moving between a call and its return.
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

    // A reader for one pass that only moves forward (a scan, the heatmap, a
    // replay): it never returns to a checkpoint it has left, so keeping more
    // than the one decoded checkpoint would only hold memory.
    std::unique_ptr<ttd::trace> open_forward_trace(const std::filesystem::path &path)
    {
        std::unique_ptr<ttd::trace> t = open_trace(path);
        t->set_checkpoint_cache_size(1);
        return t;
    }

    // The backend's reader for one long query, held for the query's whole run.
    //
    // Calls, accesses, regs_at, exceptions and the like run for seconds on
    // the core's worker thread. On the shared reader under 'mtx' they blocked
    // every main-thread call that takes it (the module and thread lists at
    // every stop, the timeline), so IDA hung behind its own wait box. They
    // use this reader under 'query_mtx' instead. It is opened once and kept:
    // a count query's second call then finds the chunks the first decoded
    // still cached, and a reader (with its decoded checkpoints) is too large
    // to keep several. Long queries therefore run one at a time.
    class query_reader
    {
      public:
        explicit query_reader(backend_t *b) : m_lock(b->query_mtx)
        {
            if ( b->query_trace == nullptr )
            {
                b->query_trace = open_trace(b->path);
                b->query_trace->set_checkpoint_cache_size(kCheckpointsPerReader);
            }
            m_trace = b->query_trace.get();
        }

        ttd::trace &trace() const { return *m_trace; }

      private:
        std::lock_guard<std::mutex> m_lock;
        ttd::trace *m_trace = nullptr;
    };

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

    const ttd::module_entry *main_module(const ttd::trace &t)
    {
        // The program is the first .exe mapped, not the first module: Sogen
        // maps some system DLLs (win32u) before the executable.
        auto mods = t.modules();
        for ( const ttd::module_entry &m : mods )
        {
            std::string n = base_name(m.name.empty() ? m.path : m.name);
            if ( n.size() > 4 && _stricmp(n.c_str() + n.size() - 4, ".exe") == 0 )
                return &m;
        }
        return mods.empty() ? nullptr : &mods.front();
    }

    // Whether the program is 64-bit: anything but an i386 main module.
    bool is64(const ttd::trace &t)
    {
        const ttd::module_entry *m = main_module(t);
        return m == nullptr || m->machine != 0x14c;
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

    // The general-purpose registers in ittd_regs.gp order.
    const x86_register kGp[ITTD_REG_GP_COUNT] = {
        x86_register::rax, x86_register::rcx, x86_register::rdx, x86_register::rbx,
        x86_register::rsp, x86_register::rbp, x86_register::rsi, x86_register::rdi,
        x86_register::r8,  x86_register::r9,  x86_register::r10, x86_register::r11,
        x86_register::r12, x86_register::r13, x86_register::r14, x86_register::r15,
        x86_register::rip,
    };

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
            }
            opened = b.release();
            return ITTD_OK;
        });
        return reinterpret_cast<ittd_backend *>(opened);
    }

    backend_t *B(ittd_backend *b) { return reinterpret_cast<backend_t *>(b); }
    cursor_t  *C(ittd_cursor *c)  { return reinterpret_cast<cursor_t *>(c); }
    fork_t    *F(ittd_fork *f)    { return reinterpret_cast<fork_t *>(f); }

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
                              | ITTD_CAP_RECORDED_EXPORTS | ITTD_CAP_CHEAP_SEEK
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
        static const x86_register seg[ITTD_SEG_COUNT] = {
            x86_register::cs, x86_register::ss, x86_register::ds,
            x86_register::es, x86_register::fs, x86_register::gs,
        };
        *out = ittd_regs{};
        for ( int i = 0; i < ITTD_REG_GP_COUNT; i++ )
            out->gp[i] = view.read_register(kGp[i]);
        out->rflags  = view.read_register(x86_register::rflags);
        out->fs_base = view.read_register(x86_register::fs_base);
        out->gs_base = view.read_register(x86_register::gs_base);
        for ( int i = 0; i < ITTD_SEG_COUNT; i++ )
            out->seg[i] = (uint16_t)view.read_register(seg[i]);
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

    constexpr uint64_t kPage = 0x1000;
    constexpr size_t   kMaxCachedPages = 8192;      // 64 MiB of bytes and flags

    // The positions around 'position' over which the page cannot change: from
    // the last write to it at or before the position to just before the next,
    // narrowed by any mapping change in between (memory freed and allocated
    // again reads as zeros with no write). MMIO is read from its accesses,
    // reads included, so for an MMIO page ('mmio') reads bound the span too.
    void stable_span(ttd::trace &t, uint64_t page, uint64_t position, bool mmio, uint64_t *from, uint64_t *to)
    {
        uint64_t W = (uint64_t)ttd::access_kind::write | (uint64_t)ttd::access_kind::host_write;
        if ( mmio )
            W |= (uint64_t)ttd::access_kind::read;
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

    // An MMIO page as of 'position', from the accesses within kMmioWindow
    // steps of it. memory_at shows a byte of MMIO by the latest access up to
    // the position, else the first after it, and a byte no access touches
    // sends it through every access to the page in the recording, both ways.
    // KUSER_SHARED_DATA is MMIO in Sogen recordings, read all the time, and
    // most of it never: a 0x400-byte read there took 24 s in a 488 MB
    // recording, at every step that crossed one of its reads (the cached page
    // holds only between accesses). Bytes not shown within the window are
    // left unknown here; read_page fills them from other reads of the page.
    static const uint64_t kMmioWindow = 1ull << 20;

    void mmio_page_near(ttd::trace &t, uint64_t page, uint64_t position, uint8_t *dst, uint8_t *kn)
    {
        memset(dst, 0, kPage);
        memset(kn, 0, kPage);
        // Not across a change to the page's mapping.
        uint64_t lo = position > kMmioWindow ? position - kMmioWindow : 0;
        uint64_t hi = position + kMmioWindow;
        if ( t.has_memory_regions() )
            for ( const ttd::memory_region &r : t.memory_regions().regions )
            {
                if ( r.address >= page + kPage || r.address + r.size <= page )
                    continue;
                if ( r.step <= position && r.step > lo )
                    lo = r.step;
                else if ( r.step > position && r.step - 1 < hi )
                    hi = r.step - 1;
            }
        const uint64_t W = (uint64_t)ttd::access_kind::write | (uint64_t)ttd::access_kind::host_write;
        auto bytes_of = [&t](const ttd::access_event &e) -> std::vector<std::byte>
        {
            if ( e.kind == ttd::access_kind::execute )
            {
                const std::byte *p = reinterpret_cast<const std::byte *>(e.payload.data());
                return std::vector<std::byte>(p, p + std::min<uint64_t>(e.size, e.payload.size()));
            }
            return t.access_data(e);
        };
        auto by_step = [](const ttd::access_event &a, const ttd::access_event &b) { return a.step < b.step; };

        // The latest access up to the position shows a byte.
        std::vector<ttd::access_event> before = t.accesses(page, kPage, lo, position);
        std::stable_sort(before.begin(), before.end(), by_step);
        for ( const ttd::access_event &e : before )
        {
            std::vector<std::byte> d = bytes_of(e);
            for ( uint64_t a = std::max(e.address, page); a < std::min(e.address + e.size, page + kPage); a++ )
            {
                const size_t i = (size_t)(a - e.address);
                if ( i < d.size() )
                {
                    dst[a - page] = (uint8_t)d[i];
                    kn[a - page]  = 1;
                }
            }
        }
        // Any other byte still holds what the first later read shows, unless
        // something wrote it first.
        if ( position >= hi )
            return;
        std::vector<bool> settled(kPage);
        for ( size_t i = 0; i < kPage; i++ )
            settled[i] = kn[i] != 0;
        std::vector<ttd::access_event> after = t.accesses(page, kPage, position + 1, hi);
        std::stable_sort(after.begin(), after.end(), by_step);
        for ( const ttd::access_event &e : after )
        {
            const bool shows = ((uint64_t)e.kind & W) == 0;
            std::vector<std::byte> d;
            for ( uint64_t a = std::max(e.address, page); a < std::min(e.address + e.size, page + kPage); a++ )
            {
                const size_t o = (size_t)(a - page);
                if ( settled[o] )
                    continue;
                settled[o] = true;
                if ( !shows )
                    continue;
                if ( d.empty() )
                    d = bytes_of(e);
                const size_t i = (size_t)(a - e.address);
                if ( i < d.size() )
                {
                    dst[o] = (uint8_t)d[i];
                    kn[o]  = 1;
                }
            }
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

        // Never caching MMIO pages made every read of KUSER_SHARED_DATA (MMIO
        // in Sogen recordings, and read constantly by IDA's analysis of
        // ntdll) cost over a second, freezing IDA. They are cached over the
        // shorter span between accesses instead.
        bool mmio = false, all_mmio = false;
        for ( const auto &[lo, hi] : c->owner->mmio )
            if ( lo < page + kPage && page < hi )
            {
                mmio = true;
                all_mmio = all_mmio || (lo <= page && page + kPage <= hi);
            }

        cached_page e;
        e.bytes.assign(kPage, 0);
        e.known.assign(kPage, 0);
        if ( all_mmio )
        {
            // From the accesses near the position (mmio_page_near). What they
            // do not show comes from the page's other cached reads, nearest
            // first: most of KUSER_SHARED_DATA is read once, as the process
            // starts, and never changes. The first read of the page also
            // reads it at the start for that.
            mmio_page_near(*c->trace, page, c->position, e.bytes.data(), e.known.data());
            std::vector<cached_page> others;
            {
                std::lock_guard<std::mutex> lock(pc.mtx);
                auto it = pc.pages.find(page);
                if ( it != pc.pages.end() )
                    others = it->second;
            }
            if ( others.empty() && c->position > kMmioWindow )
            {
                cached_page s;
                s.bytes.assign(kPage, 0);
                s.known.assign(kPage, 0);
                mmio_page_near(*c->trace, page, 0, s.bytes.data(), s.known.data());
                stable_span(*c->trace, page, 0, true, &s.from, &s.to);
                others.push_back(s);
                std::lock_guard<std::mutex> lock(pc.mtx);
                s.used = ++pc.clock;
                pc.pages[page].push_back(std::move(s));
                pc.count++;
            }
            auto distance = [&](const cached_page &o)
            {
                return c->position < o.from ? o.from - c->position
                     : c->position > o.to   ? c->position - o.to : 0;
            };
            std::sort(others.begin(), others.end(),
                      [&](const cached_page &a, const cached_page &b) { return distance(a) < distance(b); });
            for ( size_t i = 0; i < kPage; i++ )
                for ( const cached_page &o : others )
                    if ( !e.known[i] && o.known[i] )
                    {
                        e.bytes[i] = o.bytes[i];
                        e.known[i] = 1;
                    }
        }
        else
        {
            std::vector<std::optional<uint8_t>> v = c->trace->memory_at(c->position, page, kPage);
            for ( size_t i = 0; i < kPage && i < v.size(); i++ )
                if ( v[i] )
                {
                    e.bytes[i] = *v[i];
                    e.known[i] = 1;
                }
        }
        memcpy(dst, e.bytes.data(), kPage);
        memcpy(kn, e.known.data(), kPage);
        stable_span(*c->trace, page, c->position, mmio, &e.from, &e.to);

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
            // A request past the top of the address space reads up to it and
            // marks the rest unknown. (Comparing against ea + size wrapped,
            // read nothing and left 'known' unwritten.)
            const uint64_t room = ea == 0 ? UINT64_MAX : 0ull - ea;
            const size_t   span = (size_t)std::min<uint64_t>(size, room);
            size_t n = 0;
            for ( size_t done = 0; done < span; )
            {
                const uint64_t a    = ea + done;
                const uint64_t base = a & ~(kPage - 1);
                const size_t   off  = (size_t)(a - base);
                const size_t   take = std::min<size_t>(kPage - off, span - done);
                read_page(c, base, page, kn);
                for ( size_t i = 0; i < take; i++ )
                {
                    if ( kn[off + i] )
                    {
                        dst[done + i] = page[off + i];
                        n++;
                    }
                    if ( known != nullptr )
                        known[done + i] = kn[off + i] ? 1 : 0;
                }
                done += take;
            }
            if ( known != nullptr && span < size )
                std::memset(known + span, 0, size - span);
            if ( out_known != nullptr )
                *out_known = n;
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

    // ------------------------------------------------------------ navigation

    // A single step moves one position, on whichever thread runs next: that
    // is what a Sogen position is, and it matches "step into" on a recording.
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
    // the temporary breakpoint on the return address minus one (the call's
    // last byte) and runs backward to it.
    //
    // next_access(s) answers steps above s, previous_access(s) steps below s.
    // At cursor position p the instruction about to run is step p + 1, so a
    // forward run looks at steps after it and a backward run at steps up to
    // p, the last one that already ran.
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
    // step, with the same convention as execution_of. A host write (a syscall
    // writing guest memory) counts as a write.
    std::optional<uint64_t> access_of(ttd::trace &t, const ittd_breakpoint &b, uint64_t position,
                                      bool forward)
    {
        const uint64_t mask = sogen_mask(b.kinds & (ITTD_ACCESS_READ | ITTD_ACCESS_WRITE));
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
    // it was. Each breakpoint is a page-index lookup; nothing is replayed.
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

    // C3, C2 imm16, and the far forms ("rep ret" included, by the prefixes).
    bool is_ret_op(uint8_t op)
    {
        return op == 0xC3 || op == 0xC2 || op == 0xCB || op == 0xCA;
    }

    // The navigator's tests, which do not know the program's bitness, decode
    // as 64-bit. 32-bit code differs only in far calls (9A) and in 40-4F,
    // which there are one-byte instructions and so never precede an opcode
    // within one instruction's bytes.
    bool is_call_insn(const ttd::access_event &e)
    {
        uint8_t op = 0, modrm = 0;
        return opcode_of(e, true, &op, &modrm) && is_call_op(op, modrm, true);
    }

    bool is_ret_insn(const ttd::access_event &e)
    {
        uint8_t op = 0, modrm = 0;
        return opcode_of(e, true, &op, &modrm) && is_ret_op(op);
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

    // The stack pointer of the thread about to run after 'position', or
    // nothing when the state there cannot be rebuilt.
    std::optional<uint64_t> sp_at(ttd::trace &t, uint64_t position)
    {
        try
        {
            ttd::cpu_view view(t, position);
            return view.read_register(x86_register::rsp);
        }
        catch ( const ttd::divergence_error & )
        {
            return std::nullopt;
        }
    }

    // The call that entered the frame thread 'tid' is in at cursor position
    // 'pos'. Walks the thread's instructions backward from the one about to
    // run, counting returns in and calls out: the first call met at depth
    // zero entered this frame. Each step is a lookup in the thread's runs, so
    // a short walk is cheap enough for every stop.
    //
    // Not every call is matched by a ret: one whose callee left by a syscall,
    // a context switch or an exception looks, walking back, just like the
    // entering call. The stack tells them apart: the entering call was made
    // from a shallower frame, with a stack pointer above the one here, and
    // the others below it. So a call at depth zero is accepted only if its
    // stack pointer (read just before it, where the running thread is
    // certainly this one) was higher. That costs a cpu_view per candidate,
    // and there is rarely more than one.
    //
    // 'check_sp' false skips the check, for callers walking many frames that
    // cannot afford a cpu_view per candidate and accept the small risk.
    //
    // 'progress', when given, can cancel the walk (operation_cancelled), which
    // over kNavFrameWalk instructions takes long enough to want a Cancel.
    std::optional<ttd::access_event> entering_call(ttd::trace &t, uint64_t pos, uint32_t tid,
                                                   uint64_t max_back, bool check_sp = true,
                                                   const ittd_progress *progress = nullptr)
    {
        const ttd::operation_control ctl = control(progress);
        std::optional<uint64_t> here_sp = check_sp && thread_after(t, pos) == tid ? sp_at(t, pos)
                                                                                  : std::nullopt;
        uint64_t s = pos + 1;               // the instruction about to run
        int64_t depth = 0;
        for ( uint64_t n = 0; n < max_back; n++ )
        {
            if ( (n & 0x3FFF) == 0x3FFF )
                ctl.check();
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

    int query_frame_entry_progress(ittd_backend *hb, ittd_position where, uint32_t tid, uint64_t max_back,
                                   ittd_position *out_call, uint64_t *out_entry, const ittd_progress *progress);

    int query_frame_entry(ittd_backend *hb, ittd_position where, uint32_t tid, uint64_t max_back,
                          ittd_position *out_call, uint64_t *out_entry)
    {
        return query_frame_entry_progress(hb, where, tid, max_back, out_call, out_entry, nullptr);
    }

    // The walk back checks 'progress' every 16,384 instructions
    // (entering_call), so a call tree's search of tens of millions can stop.
    int query_frame_entry_progress(ittd_backend *hb, ittd_position where, uint32_t tid, uint64_t max_back,
                                   ittd_position *out_call, uint64_t *out_entry, const ittd_progress *progress)
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
            std::optional<ttd::access_event> call = entering_call(t, pos, tid, max_back, true, progress);
            if ( !call )
            {
                b->error.set("no entering call within the search bound");
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
    // Stepping out of a frame that has run longer than this (main, say)
    // reports that no entering call was found instead of walking forever.
    static const uint64_t kNavFrameWalk = 1ull << 22;

    // The step of the ret that returned from the call at 'call_step' on 'tid'.
    // From calls_to, which pairs a call with its ret through the stack slot
    // of the return address, so it is exact under recursion.
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
    // and if it is a call, the whole call. The return comes from return_of,
    // which is exact under recursion, unlike "the next time this thread
    // reaches the return address".
    //
    // Backward: step back one instruction on this thread, and if that was a
    // ret, on back to just before the call it returned from.
    int nav_step_over(ittd_cursor *hc, int forward, int *out_stop)
    {
        cursor_t *c = C(hc);
        if ( c == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(c->owner->error, [&]()
        {
            ttd::trace &t = *c->trace;
            uint32_t tid = thread_after(t, c->position);
            int stop = ITTD_STOP_BOUNDARY;
            uint64_t dest = forward ? last_position(t) : first_position(t);
            if ( forward )
            {
                std::optional<ttd::access_event> cur = t.next_instruction(c->position, tid);
                std::optional<ttd::access_event> after = cur ? t.next_instruction(cur->step, tid) : std::nullopt;
                if ( cur && after )
                {
                    if ( is_call_insn(*cur) )
                    {
                        if ( std::optional<uint64_t> ret = return_of(t, cur->step, tid) )
                        {
                            dest = *ret;            // just after the ret
                            stop = ITTD_STOP_STEPPED;
                        }
                    }
                    else
                    {
                        dest = after->step - 1;
                        stop = ITTD_STOP_STEPPED;
                    }
                }
            }
            else if ( std::optional<ttd::access_event> prev = t.previous_instruction(c->position + 1, tid) )
            {
                // 'prev' is the last instruction this thread ran.
                dest = prev->step - 1;
                stop = ITTD_STOP_STEPPED;
                if ( is_ret_insn(*prev) )
                {
                    // Standing just before the ret is standing in the callee.
                    std::optional<ttd::access_event> call =
                        entering_call(t, prev->step - 1, tid, kNavFrameWalk, true, c->progress);
                    if ( call )
                        dest = call->step - 1;
                }
            }
            // A breakpoint inside the call stops the step there, as it would
            // on a live process.
            move_guarded(c, dest, forward != 0, &stop);
            if ( out_stop != nullptr )
                *out_stop = stop;
            return ITTD_OK;
        });
    }

    // Step out: find the call that entered this frame; backward, stop just
    // before it, forward, just after its ret. With no entering call in reach
    // (a thread's outermost frame, or one older than the walk), or a call
    // that never returns, the cursor stays put and the error says why.
    int nav_step_out(ittd_cursor *hc, int forward, int *out_stop)
    {
        cursor_t *c = C(hc);
        if ( c == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(c->owner->error, [&]()
        {
            ttd::trace &t = *c->trace;
            uint32_t tid = thread_after(t, c->position);
            std::optional<ttd::access_event> call = entering_call(t, c->position, tid, kNavFrameWalk, true, c->progress);
            if ( !call )
            {
                c->owner->error.set("no call entering this frame was found");
                return ITTD_E_FAILED;
            }
            uint64_t dest = 0;
            if ( forward )
            {
                std::optional<uint64_t> ret = return_of(t, call->step, tid);
                if ( !ret )
                {
                    c->owner->error.set("this frame does not return within the recording");
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

    int nav_set_progress(ittd_cursor *hc, const ittd_progress *progress)
    {
        cursor_t *c = C(hc);
        if ( c == nullptr )
            return ITTD_E_BAD_ARG;
        c->progress = progress;
        return ITTD_OK;
    }

    int nav_breakpoints(ittd_cursor *hc, const ittd_breakpoint *bpts, size_t count)
    {
        cursor_t *c = C(hc);
        if ( c == nullptr || (bpts == nullptr && count != 0) )
            return ITTD_E_BAD_ARG;
        return guarded(c->owner->error, [&]()
        {
            c->breakpoints.assign(bpts, bpts + count);
            return ITTD_OK;
        });
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

    // ------------------------------------------------------------ queries
    //
    // Each runs the Sogen query, holds the whole answer and copies out what
    // fits, so a count query's two calls run it twice; the second is cheaper
    // because the reader keeps the decoded chunks. The long ones run on
    // query_reader, not under 'mtx'.

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
            query_reader reader(b);
            ttd::trace &t = reader.trace();
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
            query_reader reader(b);
            ttd::trace &t = reader.trace();
            std::vector<std::pair<uint64_t, uint64_t>> want;
            for ( size_t i = 0; i < nranges; i++ )
                if ( ranges[i].end > ranges[i].start )
                    want.emplace_back(ranges[i].start, ranges[i].end);
            // The fill call of a count query asks the same as the count call
            // did: answer it from the set the first one built. The cache is
            // guarded by query_mtx, which 'reader' holds.
            if ( !b->executed_valid || b->executed_ranges != want )
            {
                b->executed_valid = false;
                b->executed.clear();
                std::set<uint64_t> seen;
                const ttd::operation_control ctl = control(progress);
                // Only cancellation reaches each accesses() call; progress is
                // reported here, over the whole request (report also checks
                // for cancellation).
                ttd::operation_control inner;
                inner.interrupted = ctl.interrupted;
                // The events are fetched a stretch of steps at a time, so a
                // hot range never holds every execution of the recording at
                // once, only those of one stretch. Each call decodes only the
                // chunks of its own stretch, so the stretches add little.
                constexpr uint64_t kSlice = 1ull << 21;
                const uint64_t last = last_position(t);
                const uint64_t slices = last / kSlice + 1;
                const uint64_t X = (uint64_t)ttd::access_kind::execute;
                for ( size_t i = 0; i < want.size(); i++ )
                {
                    const uint64_t lo = want[i].first, hi = want[i].second;
                    for ( uint64_t k = 0; k < slices; k++ )
                    {
                        ctl.report(i * slices + k, want.size() * slices);
                        const uint64_t s0 = k * kSlice;
                        const uint64_t s1 = k + 1 == slices ? UINT64_MAX : s0 + kSlice - 1;
                        for ( const ttd::access_event &e : t.accesses(lo, hi - lo, s0, s1, X, inner) )
                            if ( e.ip >= lo && e.ip < hi )
                                seen.insert(e.ip);
                    }
                }
                b->executed.assign(seen.begin(), seen.end());
                b->executed_ranges = std::move(want);
                b->executed_valid  = true;
            }
            const std::vector<uint64_t> &v = b->executed;
            set_truncated(out_truncated, v.size(), cap, buf != nullptr);
            return fill(v, buf, cap, out_count, [](uint64_t a) { return a; });
        });
    }

    // The return of a function entered by a jump (a tail call, an import
    // thunk, the CFG dispatcher's 'jmp rax'), which calls_to cannot pair
    // because there is no call of its own. Walking back finds the call that
    // led to the jump; its return address is that call's address plus its
    // length, and the function returned at the ret just before the next
    // execution of that address on this thread. Index lookups only: rebuilding
    // CPU state from a checkpoint would cost tens of milliseconds an entry.
    // UINT64_MAX when there is no such return (the thread ended in it, or
    // unwound past it).
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

    // Every call made in steps [s0, s1]. The reader lists calls by target
    // only, so this walks the execute events: a call is recognised by its
    // bytes, its callee is the thread's next instruction, and its return is
    // the first ret on the thread that lands on its return address (calls
    // opened after it then left without returning: an exception, a longjmp).
    // A call that has not returned by s1 has no return.
    std::vector<ttd::call_event> every_call(ttd::trace &t, uint64_t s0, uint64_t s1, bool is64,
                                            const ttd::operation_control &ctl)
    {
        struct open_call { size_t index; uint64_t return_address; };
        struct thread_state
        {
            std::vector<open_call> open;
            std::optional<size_t>   call_pending;   // its callee is the next instruction
            std::optional<uint64_t> ret_pending;    // the step of a ret, until where it went is known
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
            query_reader reader(b);
            ttd::trace &t = reader.trace();
            uint64_t s0 = 0, s1 = 0;
            step_range(t, when, &s0, &s1);
            std::vector<ttd::call_event> all;
            // No targets: every call in the range. Meant for a short range,
            // such as the run of one function a call tree shows.
            if ( ntargets == 0 )
                all = every_call(t, s0, s1, is64(t), control(progress));
            for ( size_t i = 0; i < ntargets; i++ )
            {
                // Each target reports its share of the whole: a pattern can
                // name thousands, and per-target progress ran the bar from 0
                // to 100% over and over.
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
            // In entry order: neighbouring entries walk the same stretch of
            // the event stream, whose decoded chunks the reader keeps.
            for ( ttd::call_event &e : all )
                if ( !e.is_call && e.return_step == UINT64_MAX )
                    e.return_step = return_of_jump_entry(t, e.entry_step, e.thread_id);
            set_truncated(out_truncated, all.size(), cap, buf != nullptr);
            return fill(all, buf, cap, out_count, [](const ttd::call_event &e)
            {
                ittd_call c{};
                c.pos       = before_step(e.step);
                c.entry_pos = before_step(e.entry_step);
                // Position = the ret's step is the state after it: back at the
                // return address with the result in RAX.
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
            query_reader reader(b);
            std::vector<std::pair<uint64_t, uint64_t>> r;
            for ( size_t i = 0; i < nranges; i++ )
                if ( ranges[i].end > ranges[i].start )
                    r.emplace_back(ranges[i].start, ranges[i].end - ranges[i].start);
            std::vector<ttd::indirect_branch> v =
                reader.trace().indirect_branches(r, (flags & ITTD_INDIRECT_JUMPS) != 0, control(progress));
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
            query_reader reader(b);
            std::vector<ttd::exception_event> v = reader.trace().exceptions(control(progress));
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

    // The syscall table is decoded when the trace opens, so this is a copy.
    // The thread comes from the switch table; the arguments, which the table
    // lacks, are left to regs_at.
    int query_syscalls(ittd_backend *hb, ittd_syscall *buf, size_t cap, size_t *out_count,
                       int *out_truncated, const ittd_progress *)
    {
        backend_t *b = B(hb);
        if ( b == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            std::lock_guard<std::mutex> lock(b->mtx);
            ttd::trace &t = *b->trace;
            std::span<const ttd::syscall_entry> v = t.syscalls();
            set_truncated(out_truncated, v.size(), cap, buf != nullptr);
            return fill(v, buf, cap, out_count, [&](const ttd::syscall_entry &e)
            {
                ittd_syscall x{};
                x.pos    = before_step(e.step);
                x.result = e.result;
                x.number = e.id;
                x.tid    = t.thread_at(e.step).value_or(0);
                // A syscall that can block (a wait, a delay, a completion
                // port) is recorded with the status its handler gave at once,
                // STATUS_SUCCESS, though the thread resumes with the real one
                // (STATUS_TIMEOUT for an expired wait) in rax: so for those
                // the result is rax where the thread resumes. cpu_view at a
                // position shows the thread that runs the next instruction.
                // Only for those, as a view costs about a millisecond.
                const std::optional<std::string_view> name = t.syscall_name(e.id);
                const bool may_block = name.has_value()
                    && (name->find("Wait") != std::string_view::npos || name->find("Delay") != std::string_view::npos
                     || name->find("RemoveIoCompletion") != std::string_view::npos);
                if ( buf != nullptr && x.tid != 0 && may_block )
                {
                    if ( std::optional<ttd::access_event> resume = t.next_instruction(e.step, x.tid) )
                    {
                        if ( resume->step > 0 )
                        {
                            ttd::cpu_view view(t, resume->step - 1);
                            ittd_regs r{};
                            read_regs(view, &r);
                            if ( (r.have & ITTD_REGS_GP) != 0 )
                                x.result = r.gp[ITTD_REG_RAX];
                        }
                    }
                }
                if ( std::optional<std::string_view> n = t.syscall_name(e.id) )
                {
                    size_t len = std::min(n->size(), sizeof(x.name) - 1);
                    memcpy(x.name, n->data(), len);
                }
                return x;
            });
        });
    }

    // One pass over every write and execute event, in the reader: seconds on
    // a large trace. Progress counts events.
    int query_self_modifying(ittd_backend *hb, ittd_selfmod *buf, size_t cap, size_t *out_count,
                             int *out_truncated, const ittd_progress *progress)
    {
        backend_t *b = B(hb);
        if ( b == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            // A reader of its own under scan_mtx, so seconds of scanning hold
            // neither 'mtx' nor the query reader.
            std::lock_guard<std::mutex> lock(b->scan_mtx);
            std::unique_ptr<ttd::trace> own = open_forward_trace(b->path);
            ttd::trace &t = *own;
            const uint64_t need = (uint64_t)ttd::access_kind::write | (uint64_t)ttd::access_kind::execute;
            if ( (t.access_mask() & need) != need )
            {
                b->error.set("this recording was made without write or execute events, "
                             "which finding self-modifying code needs");
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

    // The folder this DLL was loaded from; the default registry folder is
    // "registry" beside it.
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

    // For messages: the ABI's text is UTF-8, and path::string() throws on a
    // character missing from the ANSI code page.
    std::string path_utf8(const std::filesystem::path &p)
    {
        const std::u8string s = p.u8string();
        return std::string(s.begin(), s.end());
    }

    // ------------------------------------------------------------ registry hives

    // The hives Sogen loads, in the order it fingerprints them.
    constexpr const char *kHives[] = { "SYSTEM", "SECURITY", "SAM", "SOFTWARE", "HARDWARE", "NTUSER.DAT" };

    // ttd::registry_fingerprint (the manifest's "registry" value for a folder
    // of hives), cached until a hive changes size or time: the hives are well
    // over 100 MB, and the core checks a folder before every replay.
    std::string hive_fingerprint(const std::filesystem::path &dir)
    {
        std::wstring key = dir.native();
        for ( const char *hive : kHives )
        {
            std::error_code ec;
            const auto size = std::filesystem::file_size(dir / hive, ec);
            const auto when = std::filesystem::last_write_time(dir / hive, ec);
            key += L'|' + std::to_wstring(ec ? 0 : size) + L':'
                 + std::to_wstring(ec ? 0 : when.time_since_epoch().count());
        }
        static std::mutex mtx;
        static std::map<std::wstring, std::string> cache;
        {
            std::lock_guard<std::mutex> lock(mtx);
            if ( auto it = cache.find(key); it != cache.end() )
                return it->second;
        }
        std::string fp = ttd::registry_fingerprint(dir);
        std::lock_guard<std::mutex> lock(mtx);
        return cache.emplace(key, std::move(fp)).first->second;
    }

    // The manifest's "system_dlls" value for the System32 a replay would load
    // from: the emulation root's filesys\c\windows\system32, or this machine's
    // own for a recording made against the host. Assumes the guest's Windows
    // is C:\Windows (environment_differences reads the real system root from
    // the hives, which may be absent here when the recording carries them),
    // so a difference is only a warning.
    std::string system_dll_fingerprint(const std::string &root)
    {
        std::filesystem::path sys;
        if ( root.empty() )
        {
            wchar_t buf[MAX_PATH] = {};
            const UINT n = GetSystemWindowsDirectoryW(buf, MAX_PATH);
            if ( n == 0 || n >= MAX_PATH )
                return std::string();
            sys = std::filesystem::path(buf) / L"System32";
        }
        else
        {
            // The root comes from the recording: never reach out to a share
            // it names, only to say whether the DLLs match.
            if ( !idattd::is_local_drive_path(root.c_str()) )
                return std::string();
            sys = utf8_path(root.c_str()) / L"filesys" / L"c" / L"windows" / L"system32";
        }
        return ttd::system_dll_fingerprint(sys);
    }

    // Whether 'dir' holds the hives a recording that names 'recorded' was
    // made with (check_registry's codes), and why not, in words.
    int check_hives(const std::string &recorded, const std::filesystem::path &dir, std::string *why)
    {
        if ( !std::filesystem::is_regular_file(dir / "SYSTEM") )
        {
            *why = "no registry hives (SYSTEM, SOFTWARE, ...) in " + path_utf8(dir)
                 + ": replaying the program loads the registry it ran against";
            return ITTD_E_NO_REGISTRY;
        }
        if ( recorded.empty() )
            return ITTD_REGISTRY_UNVERIFIED;
        const std::string found = hive_fingerprint(dir);
        if ( found == recorded )
            return ITTD_OK;
        *why = "the registry hives in " + path_utf8(dir) + " are not the ones this recording was made "
               "with (it names hives " + recorded + "; these are " + found + "). A replay with them "
               "diverges wherever the program reads a key that differs. The right ones are the very "
               "files Sogen was given when it recorded";
        return ITTD_E_REGISTRY_MISMATCH;
    }

    // The setting at 'offset' (offsetof the field), if the caller's struct is
    // new enough to carry it. An offset, not &s->field, which is undefined
    // for a null 's'.
    template <typename T>
    const T *setting(const ittd_fork_settings *s, size_t offset)
    {
        if ( s == nullptr || offset + sizeof(T) > s->size )
            return nullptr;
        return reinterpret_cast<const T *>(reinterpret_cast<const char *>(s) + offset);
    }

    const char *const *setting_registry_dir(const ittd_fork_settings *s)
    {
        return setting<const char *>(s, offsetof(ittd_fork_settings, registry_dir));
    }

    const char *const *setting_emulation_root(const ittd_fork_settings *s)
    {
        return setting<const char *>(s, offsetof(ittd_fork_settings, emulation_root));
    }

    const uint32_t *setting_flags(const ittd_fork_settings *s)
    {
        return setting<uint32_t>(s, offsetof(ittd_fork_settings, flags));
    }

    // The ABI 3 settings, each with what an older caller (a smaller struct)
    // gets.
    uint32_t setting_network(const ittd_fork_settings *s)
    {
        const uint32_t *v = setting<uint32_t>(s, offsetof(ittd_fork_settings, network));
        return v != nullptr && *v == ITTD_NET_LIVE ? ITTD_NET_LIVE : ITTD_NET_OFFLINE;
    }

    bool setting_elevated(const ittd_fork_settings *s)
    {
        const uint32_t *v = setting<uint32_t>(s, offsetof(ittd_fork_settings, elevated));
        return v != nullptr && *v != 0;
    }

    // What a recording keeps, as Sogen's access kinds. The kernel's writes
    // into the program (host_write) are always kept: a replay of the result
    // puts them back where a syscall's live result differs from the recorded
    // one, so a recording without them could not be forked reliably.
    uint64_t setting_access_kinds(const ittd_fork_settings *s)
    {
        const uint32_t *v = setting<uint32_t>(s, offsetof(ittd_fork_settings, access_mask));
        const uint32_t mask = v != nullptr ? *v : 0;
        if ( mask == 0 )
            return ttd::all_access_kinds;
        uint64_t kinds = static_cast<uint64_t>(ttd::access_kind::host_write);
        if ( (mask & ITTD_ACCESS_READ) != 0 )
            kinds |= static_cast<uint64_t>(ttd::access_kind::read);
        if ( (mask & ITTD_ACCESS_WRITE) != 0 )
            kinds |= static_cast<uint64_t>(ttd::access_kind::write);
        if ( (mask & ITTD_ACCESS_EXEC) != 0 )
            kinds |= static_cast<uint64_t>(ttd::access_kind::execute);
        return kinds;
    }

    // 0 keeps ttd::record_settings' own default.
    uint64_t setting_checkpoint_interval(const ittd_fork_settings *s, uint64_t fallback)
    {
        const uint64_t *v = setting<uint64_t>(s, offsetof(ittd_fork_settings, checkpoint_interval));
        return v != nullptr && *v != 0 ? *v : fallback;
    }

    // Sogen's log and the program's console output, a line at a time, to the
    // caller's callback. The logger hands over text as printed, a line or
    // less or several at once, so whole lines are cut out here; what is left
    // at the end goes out when the emulator (which holds the relay through
    // its logger and callbacks) is destroyed.
    struct log_relay
    {
        void (*fn)(void *, const char *) = nullptr;
        void *ctx = nullptr;
        std::mutex lock;
        std::string pending;

        void add(std::string_view text)
        {
            std::lock_guard<std::mutex> g(lock);
            pending.append(text.data(), text.size());
            size_t start = 0;
            for ( size_t nl; (nl = pending.find('\n', start)) != std::string::npos; start = nl + 1 )
            {
                std::string line = pending.substr(start, nl - start);
                if ( !line.empty() && line.back() == '\r' )
                    line.pop_back();
                fn(ctx, line.c_str());
            }
            pending.erase(0, start);
        }

        ~log_relay()
        {
            if ( !pending.empty() )
                fn(ctx, pending.c_str());
        }
    };

    std::shared_ptr<log_relay> make_log_relay(const ittd_fork_settings *s)
    {
        using log_fn = void (*)(void *, const char *);
        const log_fn *fn = setting<log_fn>(s, offsetof(ittd_fork_settings, log));
        if ( fn == nullptr || *fn == nullptr )
            return nullptr;
        auto relay = std::make_shared<log_relay>();
        relay->fn = *fn;
        if ( void *const *ctx = setting<void *>(s, offsetof(ittd_fork_settings, log_ctx)); ctx != nullptr )
            relay->ctx = *ctx;
        return relay;
    }

    // Opens the real network once 'live' is set, and keeps the loopback-only
    // one until then: a fork reaches its position offline (the recording's
    // results stand in for what the network answered), then runs on with
    // the real one. Sockets made before the switch stay on the loopback
    // network, so a poll may hold both kinds; each goes to its own factory.
    struct net_gate
    {
        std::atomic<bool> live{false};
    };

    struct gated_dns_lookup : sogen::network::dns_lookup
    {
        std::shared_ptr<net_gate> gate;
        std::unique_ptr<sogen::network::dns_lookup> offline =
            sogen::network::create_dns_lookup(sogen::network::network_mode::offline);
        std::unique_ptr<sogen::network::dns_lookup> live =
            sogen::network::create_dns_lookup(sogen::network::network_mode::live);

        explicit gated_dns_lookup(std::shared_ptr<net_gate> g) : gate(std::move(g)) {}

        std::vector<sogen::network::address> resolve_host(std::string_view hostname,
                                                         std::optional<int> family) override
        {
            return (gate->live ? live : offline)->resolve_host(hostname, family);
        }
    };

    struct gated_socket_factory : sogen::network::socket_factory
    {
        std::shared_ptr<net_gate> gate;
        std::unique_ptr<sogen::network::socket_factory> offline =
            sogen::network::create_socket_factory(sogen::network::network_mode::offline);
        std::unique_ptr<sogen::network::socket_factory> live =
            sogen::network::create_socket_factory(sogen::network::network_mode::live);

        explicit gated_socket_factory(std::shared_ptr<net_gate> g) : gate(std::move(g)) {}

        std::unique_ptr<sogen::network::i_socket> create_socket(int af, int type, int protocol) override
        {
            return (gate->live ? live : offline)->create_socket(af, type, protocol);
        }

        int poll_sockets(std::span<sogen::network::poll_entry> entries) override
        {
            return poll(entries, std::nullopt);
        }

        // A pending request on a host socket waits here for the host (up to
        // 10 s of real time, during which guest time stands still), so the
        // guest's own timeouts do not run out first. Only the real sockets
        // wait, and not at all when a loopback socket is already ready.
        int wait_for_sockets(std::span<sogen::network::poll_entry> entries, std::chrono::milliseconds wait) override
        {
            return poll(entries, wait);
        }

        std::vector<sogen::network::address> get_local_addresses(int family) override
        {
            return (gate->live ? live : offline)->get_local_addresses(family);
        }

      private:
        int poll(std::span<sogen::network::poll_entry> entries, std::optional<std::chrono::milliseconds> wait)
        {
            // The real factory's sockets are socket_wrappers (and it throws on
            // any other); the loopback factory skips what is not its own.
            std::vector<sogen::network::poll_entry> real, loop;
            std::vector<size_t> real_at, loop_at;
            for ( size_t i = 0; i < entries.size(); i++ )
            {
                const bool is_real = dynamic_cast<sogen::network::socket_wrapper *>(entries[i].s) != nullptr;
                (is_real ? real : loop).push_back(entries[i]);
                (is_real ? real_at : loop_at).push_back(i);
            }
            int ready = 0;
            if ( !loop.empty() )
                ready += std::max(0, offline->poll_sockets(loop));
            if ( !real.empty() )
                ready += std::max(0, wait.has_value() && ready == 0 ? live->wait_for_sockets(real, *wait)
                                                                    : live->poll_sockets(real));
            for ( size_t i = 0; i < loop.size(); i++ )
                entries[loop_at[i]] = loop[i];
            for ( size_t i = 0; i < real.size(); i++ )
                entries[real_at[i]] = real[i];
            return ready;
        }
    };

    // What every emulator here has: Unicorn, the relative clock, a headless
    // UI whose window input can be recorded and replayed, no console input
    // from this process (inside IDA there is none to give), the log as the
    // settings ask, the CPUID overrides, and the checks TTD needs. 'gate',
    // when given, has the network follow it (gated_socket_factory).
    std::unique_ptr<sogen::windows_emulator> make_emulator(std::optional<sogen::application_settings> app,
                                                           sogen::emulator_settings es,
                                                           const ittd_fork_settings *settings,
                                                           const std::shared_ptr<net_gate> &gate)
    {
        // One vCPU and instruction precision, so the instruction hook may keep
        // the kernel lock from one instruction to the next instead of taking
        // it for each (Sogen's analyzer does the same). Nothing here waits,
        // inside a hook, for another thread that takes it: progress and log
        // callbacks only queue.
        es.keep_kernel_lock_between_instructions = true;
        sogen::emulator_interfaces ifs{};
        ifs.ui = std::make_unique<ttd::recordable_ui_backend>(std::make_unique<sogen::null_ui_backend>());
        ifs.console = std::make_unique<sogen::null_console_backend>();
        if ( gate != nullptr )
        {
            ifs.dns_lookup     = std::make_unique<gated_dns_lookup>(gate);
            ifs.socket_factory = std::make_unique<gated_socket_factory>(gate);
        }
        sogen::emulator_callbacks cbs{};
        const std::shared_ptr<log_relay> relay = make_log_relay(settings);
        if ( relay != nullptr )
        {
            cbs.on_stdout = [relay](std::string_view data) { relay->add(data); };
            // Most generic accesses are every file and key the program opens;
            // these two say the emulator has no answer for something, which is
            // where a program that fails quietly usually stopped.
            cbs.on_generic_access = [relay](std::string_view type, std::u16string_view name)
            {
                if ( type != "Rejecting message to unknown port" && type != "Opening unsupported device" )
                    return;
                std::string line(type);
                line += ": ";
                line += sogen::u16_to_u8(name);
                line += "\n";
                relay->add(line);
            };
        }
        auto emu = app.has_value()
                 ? std::make_unique<sogen::windows_emulator>(sogen::unicorn::create_x86_64_emulator(), std::move(*app),
                                                             es, std::move(cbs), std::move(ifs))
                 : std::make_unique<sogen::windows_emulator>(sogen::unicorn::create_x86_64_emulator(), es,
                                                             std::move(cbs), std::move(ifs));
        // Nothing reads emulator_settings::disable_logging any more; the
        // logger's own switch keeps its output off this process's stdout.
        emu->log.disable_output(true);
        if ( relay != nullptr )
            emu->log.set_sink([relay](sogen::color, std::string_view message) { relay->add(message); });
        ttd::install_cpuid_overrides(*emu);
        ttd::require_deterministic(*emu);
        return emu;
    }

    // An emulator set up to replay 't' the way Sogen records: Unicorn, the
    // relative clock, the CPUID overrides, and a headless UI that takes the
    // recorded window input. 'strict' is set from the settings. With 'gate'
    // given and the settings asking for the network, the network follows the
    // gate (fork_open opens it at the fork's position); otherwise it stays
    // offline, as a replay of the recording itself must.
    std::unique_ptr<sogen::windows_emulator> replay_emulator(const ttd::trace &t, const ittd_fork_settings *settings,
                                                             bool *strict, std::shared_ptr<net_gate> *gate = nullptr)
    {
        std::filesystem::path registry = module_dir() / "registry";
        const std::string recorded_root = manifest_value(t, "emulation_root");
        std::filesystem::path root = utf8_path(recorded_root.c_str());
        *strict = false;
        if ( const char *const *v = setting_registry_dir(settings); v != nullptr && *v != nullptr && **v != '\0' )
            registry = utf8_path(*v);
        if ( const char *const *v = setting_emulation_root(settings); v != nullptr && *v != nullptr )
        {
            root = utf8_path(*v);
        }
        else if ( !recorded_root.empty() && !idattd::is_local_drive_path(recorded_root.c_str()) )
        {
            // The root comes from the recording, which anyone may have made:
            // a UNC path would have Windows connect to that host (and offer
            // the user's credentials) as soon as the replay looked there.
            throw coded_error(ITTD_E_FAILED, "this recording names the emulation root \"" + recorded_root
                                             + "\", which is not a folder on a local drive. Give the emulation "
                                               "root explicitly to replay it");
        }
        // windows_emulator loads <root>\registry whenever there is a root and
        // ignores registry_directory, so that is the folder to check.
        if ( !root.empty() )
            registry = root / "registry";
        bool allow_host = false, any_registry = false;
        if ( const uint32_t *v = setting_flags(settings); v != nullptr )
        {
            *strict      = (*v & ITTD_FORK_STRICT) != 0;
            allow_host   = (*v & ITTD_FORK_ALLOW_HOST) != 0;
            any_registry = (*v & ITTD_FORK_ANY_REGISTRY) != 0;
        }
        // Against the host, the program's file operations reach this machine
        // for real, so only on request. (The network stays offline unless
        // the settings open it, and then only past a fork's position.)
        if ( root.empty() && !allow_host )
            throw coded_error(ITTD_E_HOST_REPLAY, "this recording was made against the host, not an emulation root: "
                                     "replaying it runs the program's file operations (creating, changing, "
                                     "deleting files) on this machine again. Allow that explicitly to go ahead");
        std::string why;
        const int hives = check_hives(manifest_value(t, "registry"), registry, &why);
        // A recording that carries what it read of its hives replays without
        // hive files (Sogen serves the registry from it in seek, run_to and
        // replay_to_end). The recording's own hive files are still loaded
        // when present, so a fork can read further than the recording did;
        // other hives would answer differently and are left out.
        const bool carried = t.has_registry_hives();
        const bool load = !carried || hives == ITTD_OK;
        // Without carried hives, wrong ones are refused (unless asked for)
        // before the replay spends minutes reaching the divergence.
        if ( !carried && (hives == ITTD_E_NO_REGISTRY || (hives == ITTD_E_REGISTRY_MISMATCH && !any_registry)) )
            throw coded_error(hives, why);

        sogen::emulator_settings es{};
        es.disable_logging    = true;
        es.use_relative_time  = true;
        es.emulation_root     = root;
        es.registry_directory = registry;
        es.load_registry      = load;
        // The emulator's own mode stays offline even for a fork that goes
        // live (it decides, once, what the network device shows); the gate
        // switches what sockets and name lookups reach.
        es.network            = sogen::network::network_mode::offline;
        std::shared_ptr<net_gate> g;
        if ( gate != nullptr && setting_network(settings) == ITTD_NET_LIVE )
        {
            g = std::make_shared<net_gate>();
            *gate = g;
        }
        return make_emulator(std::nullopt, es, settings, g);
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
                b->error.set("that position is not in the recording");
                return ITTD_E_NO_POSITION;
            }
            bool strict = false;
            f->access_kinds        = setting_access_kinds(settings);
            f->checkpoint_interval = setting_checkpoint_interval(settings, 0);
            f->emu = replay_emulator(*f->trace, settings, &strict, &f->net);
            ttd::seek(*f->emu, *f->trace, f->position, strict, control(progress));
            // A recording that logged what the network answered (every one
            // made since Sogen's network tap, 2026-11-11) is replayed from it, and the log stops the
            // emulator at the first question it has no answer for. A fork's
            // run differs from the recording, so from here on the network
            // answers again: the offline one, or the real one when the
            // settings asked for it. Sockets open at the fork position were
            // the recording's and answer as a connection the host reset.
            if ( std::optional<ttd::network_tap> tap = ttd::find_network_tap(*f->emu); tap.has_value() )
                tap->go_live();
            if ( f->net != nullptr )
                f->net->live = true;
            *out = reinterpret_cast<ittd_fork *>(f.release());
            return ITTD_OK;
        });
    }

    int fork_regs(ittd_fork *hf, ittd_regs *out)
    {
        fork_t *f = F(hf);
        if ( f == nullptr || out == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(f->owner->error, [&]()
        {
            auto &cpu = f->emu->x64_emu();
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
            auto &cpu = f->emu->x64_emu();
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

    // ------------------------------------------------------------ output files

    // A recording being replayed is read through std::ifstream, which shares
    // read and write but not delete: a new recording written over it would
    // change it under its reader (in this IDA or another). An exclusive open
    // fails on such a file, so it is refused before anything runs.
    void refuse_open_output(const std::filesystem::path &p)
    {
        HANDLE h = CreateFileW(p.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if ( h != INVALID_HANDLE_VALUE )
        {
            CloseHandle(h);
            return;
        }
        if ( GetLastError() == ERROR_SHARING_VIOLATION || GetLastError() == ERROR_LOCK_VIOLATION )
            throw coded_error(ITTD_E_BAD_ARG, path_utf8(p) + " is open, probably as a recording being replayed "
                                              "(in this IDA or another): record into another file, or close it first");
    }

    // A recording goes into a file beside its target and is moved into place
    // once complete, so one that fails leaves the old file as it was, and
    // the target is never half-written. Replacing needs delete access, which
    // a reader that opened the target meanwhile denies: the complete
    // recording then stays under its .partial name, and the error says so.
    std::filesystem::path partial_path(const std::filesystem::path &p)
    {
        return std::filesystem::path(p.native() + L".partial");
    }

    // Deletes the .partial file of a recording that did not complete; one
    // that did is kept (kept = true) even when it cannot be moved into place.
    struct partial_guard
    {
        std::filesystem::path path;
        bool kept = false;
        ~partial_guard()
        {
            if ( !kept )
            {
                std::error_code ec;
                std::filesystem::remove(path, ec);
            }
        }
    };

    void move_into_place(const std::filesystem::path &partial, const std::filesystem::path &p)
    {
        if ( MoveFileExW(partial.c_str(), p.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) )
            return;
        const DWORD err = GetLastError();
        throw coded_error(ITTD_E_FAILED, "the recording is complete in " + path_utf8(partial) + ", but "
                                         + path_utf8(p) + " could not be replaced (Windows error "
                                         + std::to_string(err) + "): it was opened while the recording ran");
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
            const std::filesystem::path target = utf8_path(path);
            refuse_open_output(target);
            f->recorded = true;
            ttd::record_settings rs{};
            rs.path             = partial_path(target);
            rs.max_instructions = max_instructions;
            rs.access_mask      = f->access_kinds;
            if ( f->checkpoint_interval != 0 )
                rs.checkpoint_interval = f->checkpoint_interval;
            const std::u8string parent = f->owner->path.u8string();
            rs.manifest = {
                { "tool", "ida-ttd" },
                { "parent", std::string(parent.begin(), parent.end()) },
                { "parent_id", f->trace->id() },
                { "fork_position", std::to_string(f->position) },
            };
            if ( note != nullptr && *note != '\0' )
                rs.manifest.emplace_back("fork_changes", note);
            if ( f->net != nullptr )
                rs.manifest.emplace_back("network", "live after the fork position");
            bool stopped = false;
            std::function<bool()> interrupted;
            if ( progress != nullptr && progress->cancelled != nullptr )
                interrupted = [progress, &stopped]()
                {
                    stopped = stopped || progress->cancelled(progress->ud) != 0;
                    return stopped;
                };
            uint64_t before = f->emu->get_executed_instructions();
            partial_guard guard{ rs.path };
            ttd::record(*f->emu, rs, interrupted);
            guard.kept = true;
            move_into_place(rs.path, target);
            if ( out_instructions != nullptr )
                *out_instructions = f->emu->get_executed_instructions() - before;
            // A cancelled recording is still a complete, readable trace of
            // what ran before the stop.
            return ITTD_OK;
        });
    }

    void fork_close(ittd_fork *hf)
    {
        delete F(hf);
    }

    // ------------------------------------------------------------ recording

    // UTF-8 to the UTF-16 Sogen keeps command lines in.
    std::u16string utf16(const char *s)
    {
        const std::wstring w = utf8_path(s).wstring();
        return std::u16string(w.begin(), w.end());
    }

    std::wstring lower(std::wstring s)
    {
        for ( wchar_t &c : s )
            c = (wchar_t)towlower(c);
        return s;
    }

    // The guest path ("c:\dir\x.exe") of a host path inside an emulation
    // root's file system (<root>\filesys\c\dir\x.exe), or nothing when it is
    // not in there. Windows paths compare without case.
    std::optional<std::filesystem::path> guest_path(const std::filesystem::path &root,
                                                    const std::filesystem::path &host)
    {
        std::wstring base = (root / L"filesys").lexically_normal().native();
        if ( !base.empty() && base.back() != L'\\' )
            base += L'\\';
        const std::wstring h = host.lexically_normal().native();
        if ( h.size() <= base.size() || lower(h).compare(0, base.size(), lower(base)) != 0 )
            return std::nullopt;
        const std::wstring rest = h.substr(base.size());
        const size_t slash = rest.find(L'\\');
        const std::wstring drive = rest.substr(0, slash);
        if ( drive.size() != 1 )
            return std::nullopt;
        return std::filesystem::path(drive + L":\\" + (slash == std::wstring::npos ? L"" : rest.substr(slash + 1)));
    }

    // Where a guest path lives in an emulation root: c:\dir\x -> <root>\filesys\c\dir\x.
    std::filesystem::path in_root(const std::filesystem::path &root, const std::filesystem::path &guest)
    {
        const std::wstring g = guest.native();
        if ( g.size() < 2 || g[1] != L':' )
            return {};
        std::wstring rest = g.substr(2);
        while ( !rest.empty() && (rest.front() == L'\\' || rest.front() == L'/') )
            rest.erase(rest.begin());
        return root / L"filesys" / std::wstring(1, (wchar_t)towlower(g[0])) / rest;
    }

    // A program or folder for a run in an emulation root, as the guest sees
    // it: a host path inside the root's file system becomes its guest path; a
    // path the root has (a guest path typed as such) is taken as it is; a
    // file elsewhere on this machine is refused, since the program sees only
    // the root.
    std::filesystem::path guest_for(const std::filesystem::path &root, const std::filesystem::path &given,
                                    const char *what)
    {
        if ( std::optional<std::filesystem::path> g = guest_path(root, given) )
            return *g;
        std::error_code ec;
        if ( std::filesystem::exists(in_root(root, given), ec) )
            return given;
        const std::string fs_dir = path_utf8(root / L"filesys");
        if ( std::filesystem::exists(given, ec) )
            throw coded_error(ITTD_E_BAD_ARG, std::string("the ") + what + " " + path_utf8(given)
                              + " is outside the emulation root, and a program running in it sees only "
                              + fs_dir + " (its C: drive is " + fs_dir + "\\c). Copy it in there and choose that copy");
        throw coded_error(ITTD_E_BAD_ARG, std::string("there is no ") + what + " " + path_utf8(given)
                          + " in the emulation root (" + fs_dir + ")");
    }

    // An emulation root is the folder holding filesys\ (the guest's drives)
    // and registry\ (its hives). Picking either of those instead of the root
    // is the likely mistake, so the message names the parent then.
    void check_emulation_root(const std::filesystem::path &root)
    {
        std::error_code ec;
        if ( std::filesystem::is_directory(root / L"filesys", ec) )
            return;
        std::string msg = path_utf8(root) + " is not an emulation root: an emulation root is the folder that "
                          "holds filesys\\ (the program's drives) and registry\\ (its hives)";
        const std::filesystem::path parent = root.parent_path();
        if ( std::filesystem::is_directory(parent / L"filesys", ec) )
            msg += ". Did you mean " + path_utf8(parent) + "?";
        throw coded_error(ITTD_E_BAD_ARG, msg);
    }

    // The program run from its start the way analyzer --ttd-record runs it
    // (one vCPU, Unicorn, the relative clock), against an emulation root or
    // this machine's files, recorded until it exits or the limit.
    int record_program(const ittd_record_request *req, const ittd_fork_settings *settings,
                       const ittd_progress *progress, uint64_t *out_instructions)
    {
        if ( req == nullptr || req->size < sizeof(ittd_record_request)
          || req->application == nullptr || *req->application == '\0'
          || req->out_path == nullptr || *req->out_path == '\0' )
            return ITTD_E_BAD_ARG;
        return guarded(g_module_error, [&]()
        {
            std::filesystem::path root;
            if ( const char *const *v = setting_emulation_root(settings); v != nullptr && *v != nullptr && **v != '\0' )
                root = utf8_path(*v);
            std::filesystem::path registry = module_dir() / "registry";
            if ( const char *const *v = setting_registry_dir(settings); v != nullptr && *v != nullptr && **v != '\0' )
                registry = utf8_path(*v);
            if ( !root.empty() )
            {
                check_emulation_root(root);
                registry = root / "registry";
            }
            const uint32_t *flags = setting_flags(settings);
            if ( root.empty() && (flags == nullptr || (*flags & ITTD_FORK_ALLOW_HOST) == 0) )
                throw coded_error(ITTD_E_HOST_REPLAY, "without an emulation root the program runs against this "
                                                      "machine's files, and whatever it creates, changes or deletes "
                                                      "happens for real. Allow that explicitly to go ahead");
            // The recording carries what it reads of the hives, so they are
            // only needed here, to run it.
            std::string why;
            if ( check_hives("", registry, &why) == ITTD_E_NO_REGISTRY )
                throw coded_error(ITTD_E_NO_REGISTRY, "no registry hives (SYSTEM, SOFTWARE, ...) in "
                                                      + path_utf8(registry) + ": Sogen runs the program "
                                                        "against a copy of the registry, which it needs");

            // In an emulation root the program and its folder are guest paths.
            std::filesystem::path program = utf8_path(req->application);
            std::filesystem::path cwd;
            if ( req->working_dir != nullptr && *req->working_dir != '\0' )
                cwd = utf8_path(req->working_dir);
            if ( !root.empty() )
            {
                program = guest_for(root, program, "program");
                if ( !cwd.empty() )
                    cwd = guest_for(root, cwd, "working directory");
            }
            sogen::application_settings app{};
            app.application = sogen::windows_path(program);
            if ( !cwd.empty() )
                app.working_directory = sogen::windows_path(cwd);
            // The command line as given, after the program's quoted name: the
            // program splits it itself, so it gets exactly what was typed.
            const std::wstring pw = program.wstring();
            std::u16string line = u"\"" + std::u16string(pw.begin(), pw.end()) + u"\"";
            if ( req->arguments != nullptr && *req->arguments != '\0' )
                line += u" " + utf16(req->arguments);
            app.command_line = line;

            sogen::emulator_settings es{};
            es.use_relative_time  = true;
            es.emulation_root     = root;
            es.registry_directory = registry;
            es.load_registry      = true;
            es.elevated           = setting_elevated(settings);
            // Where the relative clock's system time starts (1970 at 0). The
            // checkpoints carry it, so a replay needs nothing more.
            if ( req->start_time > 0 )
                es.relative_time_start = std::chrono::system_clock::time_point(std::chrono::seconds(req->start_time));
            // From the start: there is no recorded part to reach first.
            es.network = setting_network(settings) == ITTD_NET_LIVE ? sogen::network::network_mode::live
                                                                     : sogen::network::network_mode::offline;
            auto emu = make_emulator(std::move(app), es, settings, nullptr);

            ttd::record_settings rs{};
            const std::filesystem::path target = utf8_path(req->out_path);
            refuse_open_output(target);
            rs.path                = partial_path(target);
            rs.access_mask         = setting_access_kinds(settings);
            rs.checkpoint_interval = setting_checkpoint_interval(settings, rs.checkpoint_interval);
            rs.max_instructions    = req->max_instructions;
            rs.manifest = { { "tool", "ida-ttd" } };
            if ( es.network == sogen::network::network_mode::live )
                rs.manifest.emplace_back("network", "live");
            if ( req->start_time > 0 )
                rs.manifest.emplace_back("start_time", std::to_string(req->start_time));
            std::function<bool()> interrupted;
            if ( progress != nullptr && progress->cancelled != nullptr )
                interrupted = [progress]() { return progress->cancelled(progress->ud) != 0; };
            partial_guard guard{ rs.path };
            ttd::record(*emu, rs, interrupted);
            guard.kept = true;
            move_into_place(rs.path, target);
            if ( out_instructions != nullptr )
                *out_instructions = emu->get_executed_instructions();
            return ITTD_OK;
        });
    }

    // ------------------------------------------------------------ replay scans

    // The position of text that appeared at 'step'. A step at or before the
    // recording's start means "there from the start"; for a fork's recording,
    // which starts at the fork position, before_step would give a position
    // before its first.
    ittd_position appeared_at(const ttd::trace &t, uint64_t step)
    {
        return step <= first_position(t) ? at(first_position(t)) : before_step(step);
    }

    // Replay the whole recording with a scanner attached. A divergence
    // (typically this machine's files differing from those a host recording
    // ran against) does not end the scan: the next checkpoint holds the
    // recording's own state, so the scan restores it and goes on. 'leaving'
    // runs before the restore and 'restored' after it. A scanner that cannot
    // watch a restore (the buffer scanner owns the emulator's only
    // mapping-change callback, which seek needs) is put away and a new one
    // attached; one that can is shown the restored memory. Returns what was
    // skipped, in words, or "" when nothing was. Strict replays still fail at
    // the first divergence.
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

    // ------------------------------------------------------------ scans of the recorded writes
    //
    // A recording with write events and their bytes (the chunked formats, 7
    // on) already holds everything a string or buffer scan looks at: every
    // write, its step, the instruction that made it and what it stored. Read
    // from there, the scans run nothing (no registry, no emulation root, no
    // program re-run on this machine) and cannot diverge. The scanners
    // (common/write_scans.h) apply Sogen's rules, fed what its emulator hooks
    // would see:
    //
    //   - buffers: every guest write with its bytes, each execution and each
    //     mapping change, in recording order;
    //   - strings: after each instruction that wrote, the bytes around the
    //     write as memory then held them; and at the start, all committed
    //     memory.
    //
    // A recording without write data falls back to the replay.

    bool scans_from_recording(ttd::trace &t)
    {
        const uint64_t W = (uint64_t)ttd::access_kind::write;
        return t.has_access_data() && (t.access_mask() & W) == W;
    }

    // Guest memory as it stood after some step, for the string scan's reads.
    // A page is fetched from the recording when first read, then kept current
    // by every later write.
    class ShadowMemory
    {
    public:
        explicit ShadowMemory(ttd::trace &t) : m_t(t) {}

        // [addr, addr + n) as of 'position'. False when any of it is not
        // mapped (the emulator's read would fail); those bytes read as 0xFF.
        bool read(uint64_t addr, size_t n, uint8_t *out, uint64_t position)
        {
            bool all = true;
            while ( n != 0 )
            {
                const uint64_t page = addr / kPage;
                const size_t   off  = size_t(addr % kPage);
                const size_t   take = std::min<size_t>(n, kPage - off);
                const Page &p = fetch(page, position);
                memcpy(out, p.bytes.data() + off, take);
                if ( all && !p.all_mapped(off, take) )
                    all = false;
                out += take;
                addr += take;
                n -= take;
            }
            return all;
        }

        // As cursor_read_memory answers: [addr, addr + n) as of 'position',
        // known[i] 1 where the byte is mapped (out[i] its value), else 0
        // (out[i] 0).
        void read_known(uint64_t addr, size_t n, uint8_t *out, uint8_t *known, uint64_t position)
        {
            while ( n != 0 )
            {
                const uint64_t page = addr / kPage;
                const size_t   off  = size_t(addr % kPage);
                const size_t   take = std::min<size_t>(n, kPage - off);
                const Page &p = fetch(page, position);
                for ( size_t i = 0; i < take; i++ )
                {
                    const bool k = p.all_mapped(off + i, 1);
                    known[i] = k ? 1 : 0;
                    out[i]   = k ? p.bytes[off + i] : 0;
                }
                out += take;
                known += take;
                addr += take;
                n -= take;
            }
        }

        // A write, applied to the pages held; pages not held already have it
        // when fetched later.
        void apply(uint64_t addr, const uint8_t *b, size_t n)
        {
            while ( n != 0 )
            {
                const uint64_t page = addr / kPage;
                const size_t   off  = size_t(addr % kPage);
                const size_t   take = std::min<size_t>(n, kPage - off);
                auto it = m_pages.find(page);
                if ( it != m_pages.end() )
                {
                    memcpy(it->second.bytes.data() + off, b, take);
                    it->second.set_mapped(off, take);
                }
                b += take;
                addr += take;
                n -= take;
            }
        }

        // A mapping change: what the pages held is no longer there.
        void drop(uint64_t addr, uint64_t size)
        {
            if ( size == 0 )
                return;
            const uint64_t first = addr / kPage;
            const uint64_t last  = (addr + size - 1) / kPage;
            for ( auto it = m_pages.lower_bound(first); it != m_pages.end() && it->first <= last; )
                it = m_pages.erase(it);
        }

    private:
        // Every page read stays held for the rest of the pass (the scan of
        // the start reads all committed memory), so which bytes are mapped
        // is a bitmap: an eighth of the size of a flag per byte.
        struct Page
        {
            std::vector<uint8_t> bytes;
            uint64_t mapped[kPage / 64] = {};

            // The bits of word 'w' that [off, off + n) covers.
            static uint64_t word_mask(size_t w, size_t off, size_t n)
            {
                const size_t lo = std::max(off, w * 64) - w * 64;
                const size_t hi = std::min(off + n, w * 64 + 64) - w * 64;
                const uint64_t upto = hi == 64 ? ~0ull : (1ull << hi) - 1;
                return upto & ~((1ull << lo) - 1);
            }

            void set_mapped(size_t off, size_t n)
            {
                if ( n == 0 )
                    return;
                for ( size_t w = off / 64; w <= (off + n - 1) / 64; w++ )
                    mapped[w] |= word_mask(w, off, n);
            }

            bool all_mapped(size_t off, size_t n) const
            {
                if ( n == 0 )
                    return true;
                for ( size_t w = off / 64; w <= (off + n - 1) / 64; w++ )
                {
                    const uint64_t m = word_mask(w, off, n);
                    if ( (mapped[w] & m) != m )
                        return false;
                }
                return true;
            }
        };
        ttd::trace &m_t;
        std::map<uint64_t, Page> m_pages;

        const Page &fetch(uint64_t page, uint64_t position)
        {
            auto it = m_pages.find(page);
            if ( it != m_pages.end() )
                return it->second;
            Page p;
            p.bytes.assign(kPage, 0xFF);
            std::vector<std::optional<uint8_t>> got = m_t.memory_at(position, page * kPage, kPage);
            for ( size_t i = 0; i < got.size() && i < kPage; i++ )
            {
                if ( got[i] )
                {
                    p.bytes[i] = *got[i];
                    p.set_mapped(i, 1);
                }
            }
            return m_pages.emplace(page, std::move(p)).first->second;
        }
    };

    // ittd_backend_api::read_memory_at: many reads, each at its own position,
    // in one forward pass over the recording's writes instead of a cursor
    // seek and read per position. A cursor read at a position walks back from
    // it to the writes there, which for the stack pages a syscall decoder
    // reads is a fresh walk per syscall (about 6 ms each: 35 s for the 5,599
    // syscalls of a test recording). Here each page is read once, where it is
    // first needed, and kept up to date by applying the writes that follow,
    // as the string scan does (ShadowMemory).
    //
    // Exact only with checkpoint memory, where a position's bytes are the
    // latest write or host write before it, else the checkpoint's: a pass of
    // writes reproduces that. Without it memory_at also takes bytes from reads
    // and executions, which the pass would not see, so such a recording is
    // refused (ITTD_E_UNSUPPORTED) and the core reads per position as
    // before. MMIO pages, which no write describes, are read directly.
    int read_memory_at(ittd_backend *hb, const ittd_mem_read *reads, size_t count,
                       uint8_t *buf, uint8_t *known, const ittd_progress *progress)
    {
        backend_t *b = B(hb);
        if ( b == nullptr || (count != 0 && (reads == nullptr || buf == nullptr || known == nullptr)) )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            std::vector<std::pair<uint64_t, uint64_t>> mmio;
            {
                std::lock_guard<std::mutex> lock(b->mtx);
                if ( !b->trace->has_checkpoint_memory() )
                {
                    b->error.set("read_memory_at needs checkpoint memory; read per position instead");
                    return ITTD_E_UNSUPPORTED;
                }
                mmio = b->mmio;
            }
            if ( count == 0 )
                return ITTD_OK;

            // The pass's own readers: one for the events, one for memory_at,
            // so neither disturbs the other (as scan_recorded_writes).
            std::unique_ptr<ttd::trace> t = open_forward_trace(b->path);
            std::unique_ptr<ttd::trace> mem_trace = open_forward_trace(b->path);
            ShadowMemory shadow(*mem_trace);

            struct Item
            {
                uint64_t pos = 0;
                size_t   index = 0;
            };
            std::vector<Item> items;
            items.reserve(count);
            for ( size_t i = 0; i < count; i++ )
            {
                if ( reads[i].size == 0 )
                    continue;
                memset(known + reads[i].offset, 0, (size_t)reads[i].size);
                Item it;
                if ( !resolve(*t, reads[i].pos, &it.pos) )
                    continue;           // not a position: stays unknown
                it.index = i;
                items.push_back(it);
            }
            std::stable_sort(items.begin(), items.end(), [](const Item &x, const Item &y) { return x.pos < y.pos; });

            auto in_mmio = [&](uint64_t lo, uint64_t hi)
            {
                for ( const auto &[mlo, mhi] : mmio )
                    if ( lo < mhi && mlo < hi )
                        return true;
                return false;
            };
            size_t next = 0;
            // Every read at a position before 'limit' (all of them for
            // UINT64_MAX): the writes at or before it are applied by now.
            auto answer = [&](uint64_t limit)
            {
                for ( ; next < items.size() && items[next].pos < limit; next++ )
                {
                    const ittd_mem_read &r = reads[items[next].index];
                    uint8_t *out = buf + r.offset;
                    uint8_t *kn  = known + r.offset;
                    if ( in_mmio(r.addr, r.addr + r.size) )
                    {
                        std::vector<std::optional<uint8_t>> v = mem_trace->memory_at(items[next].pos, r.addr, r.size);
                        for ( size_t k = 0; k < (size_t)r.size; k++ )
                        {
                            const bool have = k < v.size() && v[k].has_value();
                            out[k] = have ? *v[k] : 0;
                            kn[k]  = have ? 1 : 0;
                        }
                        continue;
                    }
                    shadow.read_known(r.addr, (size_t)r.size, out, kn, items[next].pos);
                }
            };

            std::span<const ttd::mapping_change> maps =
                t->has_mapping_changes() ? t->mapping_changes() : std::span<const ttd::mapping_change>();
            size_t next_map = 0;
            const uint64_t kinds = (uint64_t)ttd::access_kind::write | (uint64_t)ttd::access_kind::host_write;
            const uint64_t total_events = std::max<uint64_t>(t->metadata().event_count, 1);
            const ttd::operation_control ctl = control(progress);
            ttd::event_reader reader(*t, 0);
            uint64_t seen = 0;
            while ( next < items.size() )
            {
                std::optional<ttd::access_event> ev = reader.next(kinds);
                if ( !ev )
                    break;
                const uint64_t number = reader.last_number();
                if ( (++seen & 0xFFFF) == 0 )
                {
                    ctl.check();
                    ctl.report(number, total_events);
                }
                // Mapping changes up to this event drop what the pages held
                // (dropping early only means reading a page again, exactly).
                while ( next_map < maps.size() && maps[next_map].event_number <= number )
                {
                    const ttd::mapping_change &m = maps[next_map++];
                    shadow.drop(m.address, m.size);
                }
                // The reads before this write's instruction see everything up
                // to and including their own (memory_at's "after the
                // instruction at the position").
                answer(ev->step);
                if ( ev->size == 0 )
                    continue;
                std::vector<std::byte> data = t->access_data(*ev);
                if ( data.size() != ev->size )
                    continue;
                shadow.apply(ev->address, reinterpret_cast<const uint8_t *>(data.data()), data.size());
            }
            while ( next_map < maps.size() )
            {
                const ttd::mapping_change &m = maps[next_map++];
                shadow.drop(m.address, m.size);
            }
            answer(UINT64_MAX);
            return ITTD_OK;
        });
    }

    // One pass over the recording for both answers. 'string_minimum' is the
    // shortest string kept.
    // '*strings_truncated' and '*buffers_truncated' say whether a scanner hit
    // its own limit on results, so the answer is a prefix.
    void scan_recorded_writes(const std::filesystem::path &path, size_t string_minimum,
                              const ittd_progress *progress,
                              std::vector<ittd_string_hit> *strings_out,
                              std::vector<ittd_buffer_hit> *buffers_out,
                              bool *strings_truncated, bool *buffers_truncated)
    {
        std::unique_ptr<ttd::trace> own = open_forward_trace(path);
        ttd::trace &t = *own;
        // The shadow's page reads use a reader of their own, so they never
        // disturb the event stream's.
        std::unique_ptr<ttd::trace> mem_trace = open_forward_trace(path);
        ShadowMemory shadow(*mem_trace);

        using namespace idattd::scans;
        StringScan<uint64_t> strings(string_minimum);
        BufferScan<uint64_t> buffers(250000);       // Sogen's: instructions

        const uint64_t start = t.start_position();
        const uint64_t last  = last_position(t);

        // One buffer reused for every read: this runs after each instruction
        // that wrote, and shadow.read fills all of what it is given.
        std::vector<uint8_t> window;
        // Cancel is checked per chunk while the start's memory is scanned:
        // every committed region, which can be hundreds of megabytes, before
        // the event loop's own checks begin.
        const ttd::operation_control start_ctl = control(progress);
        bool at_start = false;
        auto scan_range = [&](uint64_t address, uint64_t size, uint64_t read_at, uint64_t step)
        {
            for ( uint64_t off = 0; off < size; off += kScanChunk )
            {
                if ( at_start )
                    start_ctl.check();
                const uint64_t b = off > kStringContext ? off - kStringContext : 0;
                const uint64_t e = std::min<uint64_t>(size, off + kScanChunk + kStringContext);
                window.resize(size_t(e - b));
                if ( shadow.read(address + b, window.size(), window.data(), read_at) )
                {
                    strings.inspect(address + b, window, step);
                    continue;
                }
                // Part of the window is unreadable: read it a page at a time,
                // on whole-page boundaries. Pieces taken from the window's
                // own (unaligned) start would each straddle the unmapped page
                // and fail too, losing everything near it.
                const uint64_t hi = address + e;
                for ( uint64_t p = address + b; p < hi; )
                {
                    const uint64_t next = std::min<uint64_t>(hi, (p & ~uint64_t(kPage - 1)) + kPage);
                    window.resize(size_t(next - p));
                    if ( shadow.read(p, window.size(), window.data(), read_at) )
                        strings.inspect(p, window, step);
                    p = next;
                }
            }
        };

        // ---- what memory held at the start ------------------------------------
        if ( t.has_memory_regions() )
        {
            at_start = true;
            for ( const ttd::memory_region &r : t.memory_regions().regions )
            {
                if ( r.event_number != 0 || r.step != start )
                    continue;                           // a change, not the start map
                static const uint32_t MEM_COMMIT_ = 0x1000;
                if ( r.state != MEM_COMMIT_ || r.kind == 5 || r.kind == 6 )
                    continue;                           // MMIO, host-reserved
                scan_range(r.address, r.size, start, start);
            }
            at_start = false;
        }

        // ---- the writes, in order ----------------------------------------------
        const std::span<const ttd::mapping_change> maps =
            t.has_mapping_changes() ? t.mapping_changes() : std::span<const ttd::mapping_change>();
        size_t next_map = 0;

        // The guest writes of the current instruction, scanned for strings
        // once it is done, as Sogen does at the next instruction.
        std::vector<std::pair<uint64_t, uint64_t>> pending;
        uint64_t pending_step = 0;
        auto flush = [&]()
        {
            if ( pending.empty() )
                return;
            // The step after the writes, as the emulator counts it there.
            const uint64_t step = std::min(pending_step + 1, std::max<uint64_t>(last, pending_step));
            for ( const auto &[addr, size] : pending )
            {
                const uint64_t begin = addr > kStringContext ? addr - kStringContext : 0;
                const uint64_t end   = addr + size;
                scan_range(begin, end - begin + kStringContext, pending_step, step);
            }
            pending.clear();
        };

        const uint64_t kinds = (uint64_t)ttd::access_kind::write | (uint64_t)ttd::access_kind::host_write
                             | (uint64_t)ttd::access_kind::execute;
        const uint64_t total_events = std::max<uint64_t>(t.metadata().event_count, 1);
        const ttd::operation_control ctl = control(progress);
        ttd::event_reader reader(t, 0);
        uint64_t seen = 0;
        while ( std::optional<ttd::access_event> ev = reader.next(kinds) )
        {
            const uint64_t number = reader.last_number();
            if ( (++seen & 0xFFFF) == 0 )
                ctl.report(number, total_events);
            if ( ev->step != pending_step )
                flush();
            while ( next_map < maps.size() && maps[next_map].event_number <= number )
            {
                const ttd::mapping_change &m = maps[next_map++];
                shadow.drop(m.address, m.size);
                buffers.mapping_changed(m.address, m.size);
            }
            pending_step = ev->step;

            if ( ev->kind == ttd::access_kind::execute )
            {
                buffers.executed(ev->address, (size_t)ev->size);
                continue;
            }
            if ( ev->size == 0 )
                continue;
            std::vector<std::byte> data = t.access_data(*ev);
            if ( data.size() != ev->size )
                continue;
            const uint8_t *bytes = reinterpret_cast<const uint8_t *>(data.data());
            shadow.apply(ev->address, bytes, data.size());
            // Sogen's scanners hook the guest CPU's writes, not those Sogen
            // makes for the program (a syscall filling a buffer).
            if ( ev->kind != ttd::access_kind::write )
                continue;
            pending.emplace_back(ev->address, ev->size);
            for ( size_t off = 0; off < data.size(); off += kMaximumRegion )
            {
                const size_t n = std::min(kMaximumRegion, data.size() - off);
                buffers.ingest(ev->address + off, bytes + off, n, ev->step, ev->step, ev->ip);
            }
        }
        flush();
        buffers.finish();
        if ( strings_truncated != nullptr )
            *strings_truncated = strings.truncated;
        if ( buffers_truncated != nullptr )
            *buffers_truncated = buffers.truncated;

        if ( strings_out != nullptr )
        {
            strings.for_each([&](uint64_t address, const StringScan<uint64_t>::Entry &e)
            {
                ittd_string_hit h{};
                h.address = address;
                h.pos     = appeared_at(t, e.pos);
                h.wide    = e.wide ? 1 : 0;
                copy_str(h.text, sizeof(h.text), e.value);
                h.length  = (uint32_t)e.value.size();
                strings_out->push_back(h);
            });
        }
        if ( buffers_out != nullptr )
        {
            for ( const FoundBuffer<uint64_t> &r : buffers.results )
            {
                ittd_buffer_hit h{};
                h.address   = r.address;
                h.size      = r.size;
                h.first_pos = before_step(r.first);
                h.last_pos  = before_step(r.last);
                h.writer_ip = r.writer_ip;
                h.writes    = r.writes;
                copy_str(h.kind, sizeof(h.kind), r.kind);
                copy_str(h.preview, sizeof(h.preview), r.preview);
                buffers_out->push_back(h);
            }
        }
    }

    // What a replay scan's answer depends on besides the recording.
    std::string scan_key(const ittd_fork_settings *settings)
    {
        std::string key;
        if ( const uint32_t *v = setting_flags(settings); v != nullptr )
            key += std::to_string(*v);
        key += '|';
        if ( const char *const *v = setting_registry_dir(settings); v != nullptr && *v != nullptr )
            key += *v;
        key += '|';
        if ( const char *const *v = setting_emulation_root(settings); v != nullptr && *v != nullptr )
            key += *v;
        return key;
    }

    // Whether the open recording's scans read its writes (scans_from_recording).
    bool recorded_scans(backend_t *b)
    {
        std::lock_guard<std::mutex> lock(b->mtx);
        return scans_from_recording(*b->trace);
    }

    // The scan of the recorded writes for 'scan_min', run once and kept. The
    // same pass also fills the buffer answer.
    // '*truncated', when given, says whether the scan hit the string scanner's
    // own limit.
    const std::vector<ittd_string_hit> &recorded_strings(backend_t *b, size_t scan_min, const ittd_progress *progress,
                                                         bool *truncated = nullptr)
    {
        const std::string key = "recorded|" + std::to_string(scan_min);
        auto found = b->strings.find(key);
        if ( found == b->strings.end() )
        {
            std::vector<ittd_string_hit> s;
            std::vector<ittd_buffer_hit> v;
            bool s_cut = false, v_cut = false;
            scan_recorded_writes(b->path, scan_min, progress, &s, &v, &s_cut, &v_cut);
            // The first scan's buffers are kept, so is the first scan's flag.
            if ( b->buffers.emplace("recorded", std::move(v)).second )
                b->buffers_truncated["recorded"] = v_cut;
            b->strings_truncated[key] = s_cut;
            found = b->strings.emplace(key, std::move(s)).first;
        }
        if ( truncated != nullptr )
            *truncated = b->strings_truncated[key];
        return found->second;
    }

    // set_truncated, also reporting a scanner that stopped at its own limit.
    void set_scan_truncated(int *out_truncated, size_t have, size_t cap, bool buf_given, bool scanner_cut)
    {
        set_truncated(out_truncated, have, cap, buf_given);
        if ( out_truncated != nullptr && scanner_cut )
            *out_truncated = 1;
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
            if ( recorded_scans(b) )
            {
                // Scanned at the shortest length likely to be asked for, and
                // filtered for this request.
                bool cut = false;
                const std::vector<ittd_string_hit> *scanned =
                    &recorded_strings(b, std::min<size_t>(min_length, 4), progress, &cut);
                // The short scan filled the scanner's cap: 4 to 7 character
                // strings may have crowded out longer ones asked for. A scan
                // at the length asked for has the cap to itself. Only then,
                // as it is another full pass.
                if ( cut && min_length > 4 )
                    scanned = &recorded_strings(b, min_length, progress, &cut);
                const std::vector<ittd_string_hit> &all = *scanned;
                std::vector<ittd_string_hit> v;
                for ( const ittd_string_hit &h : all )
                    if ( h.length >= min_length )
                        v.push_back(h);
                b->scan_note.clear();
                set_scan_truncated(out_truncated, v.size(), cap, buf != nullptr, cut);
                return fill(v, buf, cap, out_count, [](const ittd_string_hit &h) { return h; });
            }
            const std::string key = std::to_string(min_length) + "|" + scan_key(settings);
            auto found = b->strings.find(key);
            if ( found == b->strings.end() )
            {
                std::unique_ptr<ttd::trace> t = open_forward_trace(b->path);
                bool strict = false;
                auto emu = replay_emulator(*t, settings, &strict);
                std::optional<ttd::string_scanner> scanner;
                b->scan_notes[key] = replay_scan(*emu, *t, [&]()
                {
                    scanner.emplace(*emu, min_length);
                    scanner->scan_initial_memory();
                }, []() {}, [&]()
                {
                    // Attached by now, unless the replay failed before it
                    // started.
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
            b->scan_note.set(b->scan_notes[key]);
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
            if ( recorded_scans(b) )
            {
                if ( b->buffers.find("recorded") == b->buffers.end() )
                    recorded_strings(b, 4, progress);
                const std::vector<ittd_buffer_hit> &v = b->buffers["recorded"];
                b->scan_note.clear();
                set_scan_truncated(out_truncated, v.size(), cap, buf != nullptr, b->buffers_truncated["recorded"]);
                return fill(v, buf, cap, out_count, [](const ittd_buffer_hit &h) { return h; });
            }
            const std::string key = scan_key(settings);
            auto found = b->buffers.find(key);
            if ( found == b->buffers.end() )
            {
                std::unique_ptr<ttd::trace> t = open_forward_trace(b->path);
                bool strict = false;
                auto emu = replay_emulator(*t, settings, &strict);
                std::optional<ttd::buffer_scanner> scanner;
                // What each scanner put away at a restore found, then the
                // last one's.
                std::vector<ttd::recovered_buffer> found_before;
                // A scanner checks every write against the recording and, at
                // the end, that none is missing. One put away at a divergence
                // fails both checks by definition; its results are kept
                // (finish hands them out before it throws).
                auto put_away = [&](bool diverged)
                {
                    if ( !scanner )
                        return;
                    try
                    {
                        scanner->finish();
                    }
                    catch ( const std::runtime_error & )
                    {
                        if ( !diverged )
                            throw;
                    }
                    found_before.insert(found_before.end(), scanner->results().begin(), scanner->results().end());
                    scanner.reset();
                };
                b->scan_notes[key] = replay_scan(*emu, *t, [&]() { scanner.emplace(*emu, *t); },
                                                 [&]() { put_away(true); }, [&]() { scanner.emplace(*emu, *t); },
                                                 strict, progress);
                // The last scanner ran to the end unless the last divergence
                // had no checkpoint after it.
                put_away(!b->scan_notes[key].empty());
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
            b->scan_note.set(b->scan_notes[key]);
            set_truncated(out_truncated, found->second.size(), cap, buf != nullptr);
            return fill(found->second, buf, cap, out_count, [](const ittd_buffer_hit &h) { return h; });
        });
    }

    // ------------------------------------------------------------ the memory heatmap
    //
    // Every recorded access, counted by page and by slice of the recording's
    // steps, in one pass over the event stream. A window (the heatmap zoomed
    // in) reads only its own stretch of events.
    bool whole_trace(ittd_position_range when)
    {
        return same(when.first, BEGIN) && same(when.last, END);
    }

    // Where the slices of 'when' count from, and how many steps they share.
    // The whole recording counts from start_position, as it always has.
    void heat_span(const ttd::trace &t, ittd_position_range when, uint64_t *start, uint64_t *span)
    {
        if ( whole_trace(when) )
        {
            *start = t.start_position();
            *span  = std::max<uint64_t>(last_position(t) - std::min(last_position(t), *start), 1);
            return;
        }
        // step_range gives the steps of the events inside the window: after
        // its first position, up to and including its last. The slices count
        // from that first position, so slice 0 begins exactly where asked.
        uint64_t lo = 0, hi = 0;
        step_range(t, when, &lo, &hi);
        *start = lo - 1;
        *span  = std::max<uint64_t>(hi >= *start ? hi - *start : 1, 1);
    }

    int query_access_heat_window(ittd_backend *hb, uint32_t page_shift, uint32_t slices,
                                 ittd_position_range when,
                                 ittd_heat_cell *buf, size_t cap, size_t *out_count,
                                 int *out_truncated, const ittd_progress *progress)
    {
        backend_t *b = B(hb);
        if ( b == nullptr || slices == 0 || slices > 4096 || page_shift < 8 || page_shift > 30 )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            std::lock_guard<std::mutex> lock(b->scan_mtx);
            const bool whole = whole_trace(when);
            std::string key = std::to_string(page_shift) + "|" + std::to_string(slices);
            if ( !whole )
                key += "|" + std::to_string(when.first.hi) + ":" + std::to_string(when.first.lo)
                     + "|" + std::to_string(when.last.hi) + ":" + std::to_string(when.last.lo);
            auto found = b->heat.find(key);
            if ( found == b->heat.end() )
            {
                // Zooming in and out asks for the same few windows. Past 16
                // entries every cached window is dropped (the whole-recording
                // answers stay), so the cache cannot grow without bound.
                if ( !whole && b->heat.size() > 16 )
                    for ( auto it = b->heat.begin(); it != b->heat.end(); )
                        it = std::count(it->first.begin(), it->first.end(), '|') > 1 ? b->heat.erase(it) : std::next(it);
                std::unique_ptr<ttd::trace> own = open_forward_trace(b->path);
                ttd::trace &t = *own;
                uint64_t start = 0, span = 1;
                heat_span(t, when, &start, &span);
                uint64_t lo = 0, hi = UINT64_MAX;
                if ( !whole )
                    step_range(t, when, &lo, &hi);
                const uint64_t total = std::max<uint64_t>(t.metadata().event_count, 1);
                // Keyed by page and slice, not packed into one integer: a page
                // number at the smallest shift takes 56 bits, the slice 12.
                struct cell_key
                {
                    uint64_t page;
                    uint64_t slice;
                    bool operator==(const cell_key &o) const { return page == o.page && slice == o.slice; }
                };
                struct cell_hash
                {
                    size_t operator()(const cell_key &k) const
                    {
                        return std::hash<uint64_t>()(k.page * 0x9E3779B97F4A7C15ull ^ k.slice);
                    }
                };
                std::unordered_map<cell_key, ittd_heat_cell, cell_hash> cells;
                const ttd::operation_control ctl = control(progress);
                ttd::event_reader reader(t, whole ? 0 : t.first_event_after(lo - 1));
                uint64_t seen = 0;
                while ( std::optional<ttd::access_event> ev = reader.next() )
                {
                    if ( (++seen & 0xFFFF) == 0 )
                        ctl.report(reader.last_number(), total);
                    if ( ev->step > hi )
                        break;              // past the window: events are in step order
                    if ( ev->step < lo )
                        continue;
                    uint64_t slice = (ev->step - std::min(ev->step, start)) * slices / span;
                    if ( slice >= slices )
                        slice = slices - 1;
                    const uint64_t page = ev->address >> page_shift;
                    ittd_heat_cell &c = cells[cell_key{ page, slice }];
                    c.page  = page;
                    c.slice = (uint32_t)slice;
                    switch ( ev->kind )
                    {
                        case ttd::access_kind::read:    c.reads++;    break;
                        case ttd::access_kind::execute: c.executes++; break;
                        default:                        c.writes++;   break;
                    }
                }
                std::vector<ittd_heat_cell> v;
                v.reserve(cells.size());
                for ( const auto &[k, c] : cells )
                    v.push_back(c);
                std::sort(v.begin(), v.end(), [](const ittd_heat_cell &a, const ittd_heat_cell &c)
                {
                    return a.page != c.page ? a.page < c.page : a.slice < c.slice;
                });
                found = b->heat.emplace(key, std::move(v)).first;
            }
            set_truncated(out_truncated, found->second.size(), cap, buf != nullptr);
            return fill(found->second, buf, cap, out_count, [](const ittd_heat_cell &c) { return c; });
        });
    }

    int query_access_heat(ittd_backend *hb, uint32_t page_shift, uint32_t slices,
                          ittd_heat_cell *buf, size_t cap, size_t *out_count,
                          int *out_truncated, const ittd_progress *progress)
    {
        return query_access_heat_window(hb, page_shift, slices, ittd_position_range{ BEGIN, END },
                                        buf, cap, out_count, out_truncated, progress);
    }

    int heat_window_slice_position(ittd_backend *hb, uint32_t slices, uint32_t slice,
                                   ittd_position_range when, ittd_position *out)
    {
        backend_t *b = B(hb);
        if ( b == nullptr || out == nullptr || slices == 0 )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            std::lock_guard<std::mutex> lock(b->mtx);
            const ttd::trace &t = *b->trace;
            uint64_t start = 0, span = 1;
            heat_span(t, when, &start, &span);
            *out = at(start + std::min<uint64_t>(slice, slices) * span / slices);
            return ITTD_OK;
        });
    }

    int heat_slice_position(ittd_backend *hb, uint32_t slices, uint32_t slice, ittd_position *out)
    {
        return heat_window_slice_position(hb, slices, slice, ittd_position_range{ BEGIN, END }, out);
    }

    // The instruction stream of one thread (or all) over a range of positions,
    // straight from the execute events: no replay, so a window costs only the
    // events it reads. Stops after 'cap'.
    int query_instructions(ittd_backend *hb, ittd_position_range when, uint32_t tid,
                           ittd_access *buf, size_t cap, size_t *out_count,
                           int *out_truncated, const ittd_progress *progress)
    {
        backend_t *b = B(hb);
        if ( b == nullptr || (buf == nullptr && cap != 0) )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            query_reader reader(b);
            ttd::trace &t = reader.trace();
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

    // Who asked for a recorded map change: the routine whose syscall made it
    // (the target of the call into the syscall stub, such as ntdll's
    // NtAllocateVirtualMemory) and the call sites that led there, innermost
    // first and one per library module crossed, but every frame in the
    // program's own module ('main_base') and outside every module, as the
    // Microsoft backend reports from the calls it watches: the program's
    // innermost frame is often a helper every allocation goes through. Sogen
    // records the outcome, not the call, so the chain is walked back from the
    // syscall instruction.
    void syscall_chain(ttd::trace &t, uint64_t sys_step, uint32_t tid,
                       const std::vector<std::pair<uint64_t, uint64_t>> &mods, uint64_t main_base,
                       ittd_mapping_change *m)
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
            const bool own = mi == (size_t)-1 || mods[mi].first == main_base;
            if ( m->chain_n == 0 || mi != last || own )
            {
                m->chain[m->chain_n++] = call->ip;
                last = mi;
            }
            call = entering_call(t, call->step - 1, tid, kWalk, false);
        }
    }

    // The memory map at the start and every change to it, from the trace's
    // memory regions section (format section 17). Each entry is what
    // NtQueryVirtualMemory showed for its range from its position on, i.e.
    // ITTD_MAP_STATE, which the core folds by overwriting the range. The
    // values are already Windows' own.
    int query_mapping_changes(ittd_backend *hb, ittd_mapping_change *buf, size_t cap,
                              size_t *out_count, int *out_truncated, const ittd_progress *progress)
    {
        backend_t *b = B(hb);
        if ( b == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(b->error, [&]()
        {
            query_reader reader(b);
            const ttd::trace &t = reader.trace();
            if ( !t.has_memory_regions() )
            {
                b->error.set("this trace was recorded before Sogen recorded the memory map");
                return ITTD_E_UNSUPPORTED;
            }
            const std::vector<ttd::memory_region> &v = t.memory_regions().regions;
            std::span<const ttd::syscall_entry> sys = t.syscalls();
            std::vector<std::pair<uint64_t, uint64_t>> mods;
            for ( const ttd::module_entry &me : t.modules() )
                mods.emplace_back(me.base, me.size);
            const ttd::module_entry *mainm = main_module(t);
            const uint64_t main_base = mainm != nullptr ? mainm->base : UINT64_MAX;
            const uint64_t start = first_position(t);
            set_truncated(out_truncated, v.size(), cap, buf != nullptr);
            auto conv = [&](const ttd::memory_region &r)
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
                // The syscall that made the change, if any, so the listing
                // can travel to where the memory was asked for.
                auto it = std::lower_bound(sys.begin(), sys.end(), r.step,
                                           [](const ttd::syscall_entry &e, uint64_t s) { return e.step < s; });
                if ( it != sys.end() && it->step == r.step )
                {
                    m.call_pos = before_step(it->step);
                    syscall_chain(reader.trace(), it->step, m.tid, mods, main_base, &m);
                }
                return m;
            };
            if ( out_count != nullptr )
                *out_count = v.size();
            if ( buf == nullptr )
                return ITTD_OK;
            // Each change made by a syscall walks back for its call chain
            // (syscall_chain), so thousands of allocations take a while:
            // with progress and Cancel, unlike a plain fill().
            const size_t n = std::min(v.size(), cap);
            for ( size_t i = 0; i < n; i++ )
            {
                if ( (i & 63) == 0 && progress != nullptr )
                {
                    if ( progress->cancelled != nullptr && progress->cancelled(progress->ud) != 0 )
                    {
                        // What was filled, so the rest is not read as
                        // (empty) changes.
                        if ( out_count != nullptr )
                            *out_count = i;
                        b->error.set("cancelled");
                        return ITTD_E_CANCELLED;
                    }
                    if ( progress->report != nullptr )
                        progress->report(progress->ud, uint32_t(i * 1000 / n));
                }
                buf[i] = conv(v[i]);
            }
            return ITTD_OK;
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
            query_reader reader(b);
            ttd::trace &t = reader.trace();
            ttd::operation_control ctl = control(progress);
            // The positions that exist, in position order, each with the slot
            // its registers go to. Positions that do not exist keep have == 0.
            std::vector<std::pair<uint64_t, size_t>> want;
            want.reserve(count);
            for ( size_t i = 0; i < count; i++ )
            {
                out[i] = ittd_regs{};
                uint64_t p = 0;
                if ( resolve(t, positions[i], &p) )
                    want.emplace_back(p, i);
            }
            std::sort(want.begin(), want.end());

            // cpu_views_at replays each register snapshot interval once for
            // all its positions (Sogen measured 4-6x over a cpu_view each, on
            // both ends of every call to a function). Positions go in chunks
            // so progress and Cancel are heard; a chunk boundary inside an
            // interval costs that interval one more replay. A position that
            // diverges fails its whole chunk, which is then rebuilt one
            // position at a time so the others survive.
            constexpr size_t kChunk = 1024;
            std::vector<uint64_t> steps;
            steps.reserve(std::min(want.size(), kChunk));
            for ( size_t first = 0; first < want.size(); first += kChunk )
            {
                const size_t last = std::min(want.size(), first + kChunk);
                steps.clear();
                for ( size_t k = first; k < last; k++ )
                    steps.push_back(want[k].first);
                try
                {
                    std::vector<ttd::cpu_view> views = ttd::cpu_views_at(t, steps);
                    for ( size_t k = first; k < last; k++ )
                        read_regs(views[k - first], &out[want[k].second]);
                }
                catch ( const ttd::divergence_error & )
                {
                    for ( size_t k = first; k < last; k++ )
                    {
                        try
                        {
                            read_regs(ttd::cpu_view(t, want[k].first), &out[want[k].second]);
                        }
                        catch ( const ttd::divergence_error & )
                        {
                            // Left with have == 0: this position could not be rebuilt.
                        }
                    }
                }
                ctl.report(last, want.size());
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
        a.nav_set_progress   = nav_set_progress;
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
        a.query_access_heat  = query_access_heat;
        a.heat_slice_position = heat_slice_position;
        a.query_access_heat_window   = query_access_heat_window;
        a.heat_window_slice_position = heat_window_slice_position;
        a.scan_notice        = scan_notice;
        a.regs_at            = regs_at;
        a.read_memory_at     = read_memory_at;
        a.query_instructions = query_instructions;
        a.position_add       = position_add;
        a.query_frame_entry  = query_frame_entry;
        a.query_frame_entry_progress = query_frame_entry_progress;
        a.query_mapping_files = query_mapping_files;
        a.replay_env         = replay_env;
        a.check_registry     = check_registry;
        a.record_program     = record_program;
        return a;
    }();
}

extern "C" __declspec(dllexport) const ittd_backend_api *ida_ttd_backend(uint32_t abi_version)
{
    return abi_version == ITTD_ABI_VERSION ? &g_api : nullptr;
}
