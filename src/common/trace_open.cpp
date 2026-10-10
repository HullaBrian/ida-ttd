#include "common/trace_open.h"

using namespace TTD;
using namespace TTD::Replay;

namespace idattd
{
    // String helpers
    std::string to_utf8(const wchar_t *w, size_t len)
    {
        if ( w == nullptr || len == 0 )
            return std::string();
        int n = WideCharToMultiByte(CP_UTF8, 0, w, (int)len, nullptr, 0, nullptr, nullptr);
        if ( n <= 0 )
            return std::string();
        std::string s((size_t)n, '\0');
        WideCharToMultiByte(CP_UTF8, 0, w, (int)len, s.data(), n, nullptr, nullptr);
        return s;
    }

    std::string to_utf8(const wchar_t *w)
    {
        return to_utf8(w, w != nullptr ? wcslen(w) : 0);
    }

    std::wstring to_wstring(const char *s)
    {
        if ( s == nullptr || *s == '\0' )
            return std::wstring();
        int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, nullptr, 0);
        if ( n <= 0 )
            return std::wstring();
        std::wstring w((size_t)n, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, s, -1, w.data(), n);
        if ( !w.empty() && w.back() == L'\0' )
            w.pop_back();
        return w;
    }

    std::string base_name(const std::string &path)
    {
        size_t p = path.find_last_of("\\/");
        return p == std::string::npos ? path : path.substr(p + 1);
    }

    // IdaErrorReporting
    void __fastcall IdaErrorReporting::VPrintError(char const *pFmt, va_list argList)
    {
        char buf[2048];
        qvsnprintf(buf, sizeof(buf), pFmt, argList);
        msg("[ida-ttd] TTD: %s\n", buf);
    }

    // Index building
    // Percentage published by the TTD indexing threads and rendered by the main
    // thread's wait-box loop in build_trace_index().
    static std::atomic<uint32_t> g_indexPct{ 0 };

    // TTD invokes this from its own indexing WORKER THREADS. It must therefore not
    // touch IDA at all: calling replace_wait_box() here deadlocked IDA outright
    // (process alive at 0% CPU, permanently unresponsive, no window repaint) on the
    // first load of any trace with no prebuilt .idx. Publish the percentage and
    // return; the main thread renders it.
    static void __stdcall index_progress(void const * /*ctx*/, IndexBuildProgressType const *d) noexcept
    {
        if ( d != nullptr && d->KeyframeCount > 0 )
        {
            uint32_t pct = (uint32_t)((uint64_t)d->KeyframesProcessed * 100 / d->KeyframeCount);
            g_indexPct.store(pct, std::memory_order_relaxed);
        }
    }

    bool build_trace_index(IReplayEngine *engine)
    {
        if ( engine == nullptr )
            return false;
        if ( engine->GetIndexStatus() == IndexStatus::IndexFileLoaded )
            return true;

        g_indexPct.store(0, std::memory_order_relaxed);
        std::atomic<bool> done{ false };
        IndexStatus       st = IndexStatus::IndexFileNotPresent;

        std::thread worker([engine, &done, &st]()
        {
            // 'done' must be set on every exit path: the main thread spins on it
            // and would otherwise wait forever behind a wait box with no Cancel.
            try { st = engine->BuildIndex(index_progress, nullptr, IndexBuildFlags::None); }
            catch ( ... ) {}
            done.store(true, std::memory_order_release);
        });

        show_wait_box("HIDECANCEL\nBuilding TTD index...");
        uint32_t shown = 101;                    // force the first repaint
        while ( !done.load(std::memory_order_acquire) )
        {
            uint32_t pct = g_indexPct.load(std::memory_order_relaxed);
            if ( pct != shown )
            {
                replace_wait_box("HIDECANCEL\nBuilding TTD index... %u%%", pct);
                shown = pct;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        worker.join();
        hide_wait_box();

        // IndexFileUnloadable here is normal and does not mean memory reads will
        // fail -- the engine builds and uses an in-memory index, while
        // GetIndexStatus()/this result describe the on-disk .idx file only.
        if ( st != IndexStatus::IndexFileLoaded )
            msg("[ida-ttd] TTD index build finished with status %d (in-memory index still usable).\n", (int)st);
        return true;
    }
}
