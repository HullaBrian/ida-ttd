#include "backend-msttd/msttd_trace_open.h"
#include "backend-msttd/msttd_backend.h"
#include "backend-msttd/msttd_host.h"

using namespace TTD;
using namespace TTD::Replay;

namespace idattd
{
    void __fastcall MsttdErrorReporting::VPrintError(char const *pFmt, va_list argList)
    {
        char buf[2048];
        vsnprintf(buf, sizeof(buf), pFmt, argList);
        msttd_log("[ida-ttd] TTD: %s\n", buf);
        if ( owner != nullptr )
            owner->set_error("TTD: %s", buf);
    }

    // TTD invokes this from its own indexing worker threads, with the sink as
    // its context. A sink takes calls from any thread; this only passes the
    // percentage on.
    static void __stdcall index_progress(void const *ctx, IndexBuildProgressType const *d) noexcept
    {
        ProgressSink *sink = (ProgressSink *)ctx;
        if ( sink != nullptr && d != nullptr && d->KeyframeCount > 0 )
            sink->report((uint32_t)((uint64_t)d->KeyframesProcessed * 100 / d->KeyframeCount));
    }

    bool build_trace_index(IReplayEngine *engine, ProgressSink *progress)
    {
        if ( engine == nullptr )
            return false;
        if ( engine->GetIndexStatus() == IndexStatus::IndexFileLoaded )
            return true;

        IndexStatus st = IndexStatus::IndexFileNotPresent;
        try { st = engine->BuildIndex(index_progress, progress, IndexBuildFlags::None); }
        catch ( ... ) {}

        // IndexFileUnloadable here is normal and does not mean memory reads will
        // fail -- the engine builds and uses an in-memory index, while
        // GetIndexStatus()/this result describe the on-disk .idx file only.
        if ( st != IndexStatus::IndexFileLoaded )
            msttd_log("[ida-ttd] TTD index build finished with status %d (in-memory index still usable).\n", (int)st);
        return true;
    }
}
