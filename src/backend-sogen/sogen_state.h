// SPDX-License-Identifier: GPL-2.0-only
//
// ida-ttd's backend for Sogen time-travel traces (.sogttd): what its files
// share.
//
// ida-ttd-sogen.dll is loaded by the ida-ttd core through the C ABI in
// abi/ida_ttd_backend.h. It reads a recording through Sogen's trace reader
// and cpu_view, and replays one in Sogen's emulator (forks, replay scans,
// recording a program). Of ida-ttd it uses only the ABI header,
// common/local_path.h and common/write_scans.h, and it never sees an IDA
// type.
//
// Sogen is GPL-2.0-only, so ida-ttd-sogen.dll is a GPL-2.0 binary, and these
// files, which are only ever built into it, are GPL-2.0-only too
// (LICENSES/GPL-2.0-only.txt). The rest of ida-ttd is Apache-2.0 OR
// GPL-2.0-only (docs/licensing.md): nothing of Sogen's, and nothing here that
// pulls in more of the plugin, may cross that line.
//
// The files:
//
//  - sogen_state.h      the handles, the readers, and the helpers all share
//  - sogen_session.cpp  identity, open and info, positions, cursors, threads,
//                       modules, the timeline, symbols, the replay environment
//  - sogen_memory.cpp   the page cache and cursor_read_memory
//  - sogen_insn.h       what an executed instruction is (call, ret)
//  - sogen_nav.cpp      stepping, running, the entering call of a frame
//  - sogen_queries.cpp  the whole-recording queries, the heatmap, regs_at
//  - sogen_emulator.cpp registry hives, fork settings, the log relay, the
//                       network gate, and the emulators everything replays in
//  - sogen_fork.cpp     forks, writing a recording, record_program
//  - sogen_scans.cpp    replay scans, scans of the recorded writes,
//                       read_memory_at
//  - sogen_backend.cpp  the ABI table and the export
//
// Only the emulator, fork and scans files include Sogen's emulator.
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
//  - Everything is in namespace idattd::sogen, where "sogen::" would name
//    that namespace: Sogen's own is "::sogen::", and "ttd::" is its
//    ::sogen::ttd.

#pragma once

#include <abi/ida_ttd_backend.h>
#include <common/local_path.h>

#include <ttd_trace.hpp>
#include <ttd_view.hpp>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

// Sogen's emulator, which only the files that run one include.
namespace sogen
{
    class windows_emulator;
    struct application_settings;
    struct emulator_settings;
}

namespace idattd::sogen
{
    namespace ttd = ::sogen::ttd;
    using ::sogen::x86_register;

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
        // For an MMIO page, the offsets 'known' marks, in order. A read of
        // KUSER_SHARED_DATA shows a few hundred of its bytes, and a miss
        // fills its unknown bytes from every other version of the page
        // cached (read_page), which grow with every stop: by these, a miss
        // costs what the versions know, not a page per version.
        std::vector<uint16_t> known_at;
    };

    struct page_cache
    {
        std::mutex mtx;
        std::unordered_map<uint64_t, std::vector<cached_page>> pages;   // by page base
        size_t   count = 0;
        uint64_t clock = 0;
    };

    // The memory regions section as an interval index over addresses, built
    // once at open. Every uncached page read asks which entries touch its
    // page (stable_span, mmio_page_near), and a walk of the whole table per
    // miss grew with every change the program made to its memory. A static
    // interval tree laid over the entries sorted by start: the middle entry
    // of each subrange keeps the highest end within the subrange.
    class region_index
    {
      public:
        void build(const std::vector<ttd::memory_region> &regions)
        {
            m_items.clear();
            m_items.reserve(regions.size());
            for ( const ttd::memory_region &r : regions )
                m_items.push_back({ r.address, r.address + r.size, r.step });
            std::sort(m_items.begin(), m_items.end(), [](const item &a, const item &b) { return a.lo < b.lo; });
            m_max.assign(m_items.size(), 0);
            build_max(0, m_items.size());
        }

        // fn(step) for every entry touching [lo, hi): starting below hi and
        // ending above lo. That counts an empty entry strictly inside the
        // range, as the table walk this replaces did.
        template <typename F>
        void for_each(uint64_t lo, uint64_t hi, F &&fn) const
        {
            visit(0, m_items.size(), lo, hi, fn);
        }

      private:
        struct item
        {
            uint64_t lo, hi, step;
        };
        std::vector<item>     m_items;
        std::vector<uint64_t> m_max;    // by the middle index of each subrange

        uint64_t build_max(size_t b, size_t e)
        {
            if ( b >= e )
                return 0;
            const size_t m = b + (e - b) / 2;
            const uint64_t v = std::max({ m_items[m].hi, build_max(b, m), build_max(m + 1, e) });
            m_max[m] = v;
            return v;
        }

        template <typename F>
        void visit(size_t b, size_t e, uint64_t lo, uint64_t hi, F &fn) const
        {
            if ( b >= e )
                return;
            const size_t m = b + (e - b) / 2;
            if ( m_max[m] <= lo )
                return;                     // nothing in this subrange ends above lo
            visit(b, m, lo, hi, fn);
            if ( m_items[m].lo >= hi )
                return;                     // this entry and all to its right start too high
            if ( m_items[m].hi > lo )
                fn(m_items[m].step);
            visit(m + 1, e, lo, hi, fn);
        }
    };

    // One query's answer, kept from its count call to its fill.
    //
    // count-then-fill asks every question twice, and a query that computes
    // its answer from scratch (a walk over the event stream, a replay) did
    // all its work twice. The answer is kept under the arguments it was
    // asked with ('key'), so a different question is never answered from
    // it, and dropped once filled, or straight away when it is empty (the
    // core skips the fill of an empty answer), as abi_export keeps the
    // Microsoft backend's. A failure or a cancel keeps nothing.
    template <typename T>
    struct kept_answer
    {
        std::mutex mtx;
        std::string key;
        std::shared_ptr<const std::vector<T>> data;
        int served = 0;
    };

    // The parts of a recovered string a listing needs. An ittd_string_hit
    // is about 288 bytes, mostly a fixed text buffer, and the cached scans
    // hold every string of the recording for the backend's life (135k on a
    // test recording: 39 MB); this keeps the text at its own length.
    struct kept_string
    {
        uint64_t      address = 0;
        ittd_position pos{};
        uint32_t      length = 0;       // as the listing counts it
        bool          wide = false;
        std::string   text;
    };

    // A thread and the span it ran over, from the switch table.
    struct thread_span
    {
        uint32_t tid = 0;
        uint64_t first_step = UINT64_MAX;
        uint64_t end_step = 0;          // one past the last step it ran
        bool     running_at_end = false;
    };

    // The results of the scans, kept for the backend's life: each is a full
    // pass, and count-then-fill asks twice. Their own mutex keeps a scan
    // from holding up the other queries; the self-modifying code query's
    // pass takes it too.
    struct scan_cache
    {
        std::mutex mtx;
        // Keyed by what the replay ran with (scan_key), and for strings also
        // the minimum length, so a strict run is never answered by a lenient one.
        std::map<std::string, std::vector<kept_string>> strings;
        std::map<std::string, std::vector<ittd_buffer_hit>> buffers;
        // Whether a cached scan stopped keeping results at a scanner's own
        // limit, by the same keys, so a later fill still reports it.
        std::map<std::string, bool> strings_truncated, buffers_truncated;
        // What each cached scan skipped (scan_notice), by the same keys.
        std::map<std::string, std::string> notes;
        // query_access_heat's answers, by page shift and slice count.
        std::map<std::string, std::vector<ittd_heat_cell>> heat;
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
        scan_cache scans;
        // query_executed's answer, kept between its count and fill calls,
        // and the ranges it was for.
        std::vector<std::pair<uint64_t, uint64_t>> executed_ranges;
        std::vector<uint64_t> executed;
        bool executed_valid = false;
        // Address ranges recorded as MMIO at any time (region kind 5), whose
        // pages are cached only between accesses: memory_at reads them from
        // their accesses, so they change at reads too, not only at writes.
        std::vector<std::pair<uint64_t, uint64_t>> mmio;
        // The memory regions section by address, for the page reads; fixed
        // after open, so read without a lock.
        region_index regions;
        // The answers of the queries that compute theirs from scratch, each
        // kept from its count call to its fill (kept_answer).
        kept_answer<ittd_access>      accesses_answer;
        kept_answer<ittd_call>        calls_answer;
        kept_answer<ittd_call_target> indirect_answer;
        kept_answer<ittd_exception>   exceptions_answer;
        kept_answer<ittd_selfmod>     selfmod_answer;
        // The last scan's notice (scan_notice).
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

    // Opens the real network once 'live' is set, and keeps the loopback-only
    // one until then: a fork reaches its position offline (the recording's
    // results stand in for what the network answered), then runs on with
    // the real one. Sockets made before the switch stay on the loopback
    // network, so a poll may hold both kinds; each goes to its own factory.
    struct net_gate
    {
        std::atomic<bool> live{false};
    };

    // A recording replayed to a position and held there (fork_open).
    struct fork_t
    {
        backend_t *owner = nullptr;
        std::unique_ptr<ttd::trace> trace;               // its own reader: seek needs one
        std::unique_ptr<::sogen::windows_emulator> emu;
        uint64_t position = 0;
        bool     recorded = false;                       // fork_record runs once
        // From fork_open's settings, for fork_record (which has none).
        uint64_t access_kinds = ttd::all_access_kinds;
        uint64_t checkpoint_interval = 0;                // 0: Sogen's default
        // Set when the settings asked for the network: opened once the
        // replay has reached the position.
        std::shared_ptr<net_gate> net;
    };

    // ------------------------------------------------------------ helpers

    constexpr ittd_position NONE  = { UINT64_MAX, UINT64_MAX };
    constexpr ittd_position BEGIN = { 0, 0 };
    constexpr ittd_position END   = { UINT64_MAX, UINT64_MAX - 1 };

    inline bool same(ittd_position a, ittd_position b) { return a.hi == b.hi && a.lo == b.lo; }

    inline ittd_position at(uint64_t position) { return { 0, position }; }

    // The ABI position of the instruction whose step is 'step': just before it.
    inline ittd_position before_step(uint64_t step)
    {
        if ( step == UINT64_MAX || step == 0 )
            return NONE;
        return at(step - 1);
    }

    inline uint64_t first_position(const ttd::trace &t) { return t.start_position(); }
    inline uint64_t last_position(const ttd::trace &t)  { return t.metadata().instruction_count; }

    // Resolve the sentinels; false for NONE or a position outside the trace.
    inline bool resolve(const ttd::trace &t, ittd_position p, uint64_t *out)
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
    inline void step_range(const ttd::trace &t, ittd_position_range when, uint64_t *lo, uint64_t *hi)
    {
        uint64_t a = first_position(t), b = last_position(t);
        resolve(t, when.first, &a);
        resolve(t, when.last, &b);
        *lo = a + 1;
        *hi = b;
    }

    // How much of 'src' a field of 'cap' bytes holds with its terminator, cut
    // on a character boundary, never inside a UTF-8 sequence.
    inline size_t fitted_length(const std::string &src, size_t cap)
    {
        size_t n = std::min(src.size(), cap - 1);
        while ( n > 0 && n < src.size() && (static_cast<unsigned char>(src[n]) & 0xC0) == 0x80 )
            n--;
        return n;
    }

    inline void copy_str(char *dst, size_t cap, const std::string &src)
    {
        const size_t n = fitted_length(src, cap);
        std::memcpy(dst, src.data(), n);
        dst[n] = '\0';
    }

    inline std::string base_name(const std::string &path)
    {
        size_t slash = path.find_last_of("/\\");
        return slash == std::string::npos ? path : path.substr(slash + 1);
    }

    // The thread that runs the instruction after 'position'. cpu_view shows
    // its registers there, since a snapshot taken at a thread switch already
    // holds the incoming thread.
    inline uint32_t thread_after(const ttd::trace &t, uint64_t position)
    {
        if ( auto tid = t.thread_at(position + 1) )
            return *tid;
        if ( auto tid = t.thread_at(position) )
            return *tid;
        return 0;
    }

    // An ittd_progress as Sogen's operation_control. Both of Sogen's callbacks
    // run on the calling thread, which the ABI's sink allows.
    inline ttd::operation_control control(const ittd_progress *p)
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
    inline int guarded(text_slot &err, F &&body)
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
    inline int fill(const Range &src, T *buf, size_t cap, size_t *out_count, Conv conv)
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
    inline uint32_t access_kind_of(ttd::access_kind k)
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

    inline uint64_t sogen_mask(uint32_t kinds)
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
    inline std::filesystem::path utf8_path(const char *s)
    {
        return std::filesystem::path(std::u8string(reinterpret_cast<const char8_t *>(s)));
    }

    // Decoded checkpoints each reader keeps (Sogen's default is four). Each is
    // about the size of the program's committed memory, and every cursor has
    // a reader: with four, a session on a large recording passed half a
    // gigabyte. Two cover moving between a call and its return.
    constexpr size_t kCheckpointsPerReader = 2;

    inline std::unique_ptr<ttd::trace> open_trace(const std::filesystem::path &path)
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
    inline std::unique_ptr<ttd::trace> open_forward_trace(const std::filesystem::path &path)
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

    inline const ttd::module_entry *main_module(const ttd::trace &t)
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
    inline bool is64(const ttd::trace &t)
    {
        const ttd::module_entry *m = main_module(t);
        return m == nullptr || m->machine != 0x14c;
    }

    // The general-purpose registers in ittd_regs.gp order.
    const x86_register kGp[ITTD_REG_GP_COUNT] = {
        x86_register::rax, x86_register::rcx, x86_register::rdx, x86_register::rbx,
        x86_register::rsp, x86_register::rbp, x86_register::rsi, x86_register::rdi,
        x86_register::r8,  x86_register::r9,  x86_register::r10, x86_register::r11,
        x86_register::r12, x86_register::r13, x86_register::r14, x86_register::r15,
        x86_register::rip,
    };

    // The segment selectors in ittd_regs.seg order.
    const x86_register kSeg[ITTD_SEG_COUNT] = {
        x86_register::cs, x86_register::ss, x86_register::ds,
        x86_register::es, x86_register::fs, x86_register::gs,
    };

    inline backend_t *B(ittd_backend *b) { return reinterpret_cast<backend_t *>(b); }
    inline cursor_t  *C(ittd_cursor *c)  { return reinterpret_cast<cursor_t *>(c); }
    inline fork_t    *F(ittd_fork *f)    { return reinterpret_cast<fork_t *>(f); }

    constexpr uint64_t kPage = 0x1000;

    inline void set_truncated(int *out_truncated, size_t have, size_t cap, bool buf_given)
    {
        if ( out_truncated != nullptr )
            *out_truncated = buf_given && have > cap ? 1 : 0;
    }

    // ------------------------------------------------------------ shared between the files
    //
    // The functions one file defines and others use. The ABI's entry points
    // follow, by file.

    // sogen_session.cpp
    extern text_slot g_module_error;       // last_error(NULL)
    void move(cursor_t *c, uint64_t position);
    void read_regs(const ttd::cpu_view &view, ittd_regs *out);

    // sogen_nav.cpp
    std::optional<ttd::access_event> entering_call(ttd::trace &t, uint64_t pos, uint32_t tid,
                                                   uint64_t max_back, bool check_sp = true,
                                                   const ittd_progress *progress = nullptr);

    // sogen_emulator.cpp
    std::string manifest_value(const ttd::trace &t, std::string_view key);
    std::string path_utf8(const std::filesystem::path &p);
    std::string system_dll_fingerprint(const std::string &root);
    int check_hives(const std::string &recorded, const std::filesystem::path &dir, std::string *why);
    const char *const *setting_registry_dir(const ittd_fork_settings *s);
    const char *const *setting_emulation_root(const ittd_fork_settings *s);
    const uint32_t *setting_flags(const ittd_fork_settings *s);
    uint32_t setting_network(const ittd_fork_settings *s);
    bool setting_elevated(const ittd_fork_settings *s);
    uint64_t setting_access_kinds(const ittd_fork_settings *s);
    uint64_t setting_checkpoint_interval(const ittd_fork_settings *s, uint64_t fallback);
    std::filesystem::path registry_for(const ittd_fork_settings *settings, const std::filesystem::path &root);
    std::unique_ptr<::sogen::windows_emulator> make_emulator(::sogen::application_settings *app,
                                                             ::sogen::emulator_settings es,
                                                             const ittd_fork_settings *settings,
                                                             const std::shared_ptr<net_gate> &gate);
    std::unique_ptr<::sogen::windows_emulator> replay_emulator(const ttd::trace &t, const ittd_fork_settings *settings,
                                                               bool *strict, std::shared_ptr<net_gate> *gate = nullptr);

    // ------------------------------------------------------------ the entry points

    // sogen_session.cpp
    const char *id();
    const char *display_name();
    const char *file_filter();
    int can_open(const char *path);
    ittd_backend *open(const char *path);
    void close(ittd_backend *b);
    const char *last_error(ittd_backend *b);
    const char *scan_notice(ittd_backend *b);
    int info(ittd_backend *hb, ittd_trace_info *out);
    int format_position(ittd_backend *, ittd_position p, char *buf, size_t buf_size);
    int parse_position(ittd_backend *, const char *text, ittd_position *out);
    const char *position_syntax(ittd_backend *);
    int position_add(ittd_backend *hb, ittd_position p, int64_t delta, ittd_position *out);
    ittd_cursor *cursor_open(ittd_backend *hb);
    void cursor_close(ittd_cursor *c);
    int cursor_position(ittd_cursor *hc, ittd_position *out);
    int cursor_seek(ittd_cursor *hc, ittd_position p);
    int cursor_thread(ittd_cursor *hc, uint32_t *out);
    int cursor_regs(ittd_cursor *hc, ittd_regs *out);
    int threads(ittd_backend *hb, ittd_thread *buf, size_t cap, size_t *out_count);
    int cursor_threads(ittd_cursor *hc, ittd_thread *buf, size_t cap, size_t *out_count);
    int modules(ittd_backend *hb, ittd_module *buf, size_t cap, size_t *out_count);
    int timeline(ittd_backend *hb, ittd_trace_event *buf, size_t cap, size_t *out_count);
    int module_symbols(ittd_backend *hb, uint64_t base, ittd_symbol *buf, size_t cap, size_t *out_count);
    int replay_env(ittd_backend *hb, ittd_replay_env *out);
    int check_registry(ittd_backend *hb, const char *dir);

    // sogen_memory.cpp
    int cursor_read_memory(ittd_cursor *hc, uint64_t ea, void *buf, uint8_t *known,
                           size_t size, size_t *out_known);

    // sogen_nav.cpp
    int nav_step(ittd_cursor *hc, int forward, int *out_stop);
    int nav_step_over(ittd_cursor *hc, int forward, int *out_stop);
    int nav_step_out(ittd_cursor *hc, int forward, int *out_stop);
    int nav_run_to(ittd_cursor *hc, uint64_t addr, int forward, int *out_stop);
    int nav_run(ittd_cursor *hc, int forward, int *out_stop);
    int nav_set_progress(ittd_cursor *hc, const ittd_progress *progress);
    int nav_breakpoints(ittd_cursor *hc, const ittd_breakpoint *bpts, size_t count);
    int query_frame_entry(ittd_backend *hb, ittd_position where, uint32_t tid, uint64_t max_back,
                          ittd_position *out_call, uint64_t *out_entry);
    int query_frame_entry_progress(ittd_backend *hb, ittd_position where, uint32_t tid, uint64_t max_back,
                                   ittd_position *out_call, uint64_t *out_entry, const ittd_progress *progress);

    // sogen_queries.cpp
    int query_accesses(ittd_backend *hb, uint64_t lo, uint64_t hi, uint32_t kinds,
                       ittd_position_range when, ittd_access *buf, size_t cap,
                       size_t *out_count, int *out_truncated, const ittd_progress *progress);
    int query_executed(ittd_backend *hb, const ittd_range *ranges, size_t nranges,
                       uint64_t *buf, size_t cap, size_t *out_count,
                       int *out_truncated, const ittd_progress *progress);
    int query_calls(ittd_backend *hb, const uint64_t *targets, size_t ntargets,
                    ittd_position_range when, ittd_call *buf, size_t cap,
                    size_t *out_count, int *out_truncated, const ittd_progress *progress);
    int query_indirect(ittd_backend *hb, const ittd_range *ranges, size_t nranges, uint32_t flags,
                       ittd_call_target *buf, size_t cap, size_t *out_count,
                       int *out_truncated, const ittd_progress *progress);
    int query_exceptions(ittd_backend *hb, ittd_exception *buf, size_t cap, size_t *out_count,
                         int *out_truncated, const ittd_progress *progress);
    int query_syscalls(ittd_backend *hb, ittd_syscall *buf, size_t cap, size_t *out_count,
                       int *out_truncated, const ittd_progress *);
    int query_self_modifying(ittd_backend *hb, ittd_selfmod *buf, size_t cap, size_t *out_count,
                             int *out_truncated, const ittd_progress *progress);
    int query_access_heat_window(ittd_backend *hb, uint32_t page_shift, uint32_t slices,
                                 ittd_position_range when,
                                 ittd_heat_cell *buf, size_t cap, size_t *out_count,
                                 int *out_truncated, const ittd_progress *progress);
    int query_access_heat(ittd_backend *hb, uint32_t page_shift, uint32_t slices,
                          ittd_heat_cell *buf, size_t cap, size_t *out_count,
                          int *out_truncated, const ittd_progress *progress);
    int heat_window_slice_position(ittd_backend *hb, uint32_t slices, uint32_t slice,
                                   ittd_position_range when, ittd_position *out);
    int heat_slice_position(ittd_backend *hb, uint32_t slices, uint32_t slice, ittd_position *out);
    int query_instructions(ittd_backend *hb, ittd_position_range when, uint32_t tid,
                           ittd_access *buf, size_t cap, size_t *out_count,
                           int *out_truncated, const ittd_progress *progress);
    int query_mapping_changes(ittd_backend *hb, ittd_mapping_change *buf, size_t cap,
                              size_t *out_count, int *out_truncated, const ittd_progress *progress);
    int query_mapping_files(ittd_backend *hb, ittd_name *buf, size_t cap, size_t *out_count);
    int regs_at(ittd_backend *hb, const ittd_position *positions, size_t count,
                ittd_regs *out, const ittd_progress *progress);

    // sogen_fork.cpp
    int fork_open(ittd_backend *hb, ittd_position at_pos, const ittd_fork_settings *settings,
                  const ittd_progress *progress, ittd_fork **out);
    int fork_regs(ittd_fork *hf, ittd_regs *out);
    int fork_set_regs(ittd_fork *hf, const ittd_regs *regs);
    int fork_write_memory(ittd_fork *hf, uint64_t ea, const void *buf, size_t size);
    int fork_record(ittd_fork *hf, const char *path, uint64_t max_instructions, const char *note,
                    const ittd_progress *progress, uint64_t *out_instructions);
    void fork_close(ittd_fork *hf);
    int record_program(const ittd_record_request *req, const ittd_fork_settings *settings,
                       const ittd_progress *progress, uint64_t *out_instructions);

    // sogen_scans.cpp
    int read_memory_at(ittd_backend *hb, const ittd_mem_read *reads, size_t count,
                       uint8_t *buf, uint8_t *known, const ittd_progress *progress);
    int query_strings(ittd_backend *hb, const ittd_fork_settings *settings, uint32_t min_length,
                      ittd_string_hit *buf, size_t cap, size_t *out_count,
                      int *out_truncated, const ittd_progress *progress);
    int query_buffers(ittd_backend *hb, const ittd_fork_settings *settings,
                      ittd_buffer_hit *buf, size_t cap, size_t *out_count,
                      int *out_truncated, const ittd_progress *progress);
}
