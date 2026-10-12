#pragma once

#include "backend-msttd/msttd_pch.h"
#include "common/strings.h"
#include "core/backend.h"

namespace idattd
{
    // Opening a TTD trace, shared by the plugin and the loader.
    //
    // The loader (ttd-loader.dll, in IDA's loaders/ directory) has to do the same
    // three things the debugger backend does before it can look at a recording --
    // create the engine, initialise it on the .run, and build the memory index if
    // the trace has none -- but it is a separate binary and cannot reach into
    // TraceManager. Everything both of them need lives here.

    // Error sink so the TTD engine's diagnostics reach the host's log.
    class MsttdErrorReporting : public TTD::ErrorReporting
    {
    public:
        void __fastcall VPrintError(char const *pFmt, va_list argList) override;
    };

    // Index building
    // Build the trace's memory index if it does not already have one. Without an
    // index, memory reads are severely limited.
    //
    // BuildIndex is fully synchronous and can run for minutes, so the caller
    // runs this on a worker thread: the core's run_query, behind a wait box.
    // The percentage goes to 'progress' (which may be null) from TTD's own
    // indexing threads; a sink must take that, and the core's does.
    //
    // The build cannot be interrupted: IndexBuildProgressCallback returns void and
    // BuildIndex exposes no cancellation flag.
    //
    // Returns true when the trace has a usable index afterwards. Note that a
    // status of IndexFileUnloadable is normal and still counts as usable: the
    // engine keeps an in-memory index, and GetIndexStatus() describes the on-disk
    // .idx file only.
    bool build_trace_index(TTD::Replay::IReplayEngine *engine, ProgressSink *progress);
}
