#pragma once

#include "backend-msttd/msttd_pch.h"
#include "common/strings.h"

namespace idattd
{
    // Opening a TTD trace, shared by the plugin and the loader.
    //
    // The loader (ttd-loader.dll, in IDA's loaders/ directory) has to do the same
    // three things the debugger backend does before it can look at a recording --
    // create the engine, initialise it on the .run, and build the memory index if
    // the trace has none -- but it is a separate binary and cannot reach into
    // TraceManager. Everything both of them need lives here.

    // Error sink so the TTD engine can report diagnostics into IDA's output.
    class IdaErrorReporting : public TTD::ErrorReporting
    {
    public:
        void __fastcall VPrintError(char const *pFmt, va_list argList) override;
    };

    // Index building
    // Build the trace's memory index if it does not already have one. Without an
    // index, memory reads are severely limited.
    //
    // BuildIndex is fully synchronous and can run for minutes, so it must not run
    // on the main thread: doing so blocks IDA's message loop for the whole build
    // (no repaint, no progress). It runs on a worker while the MAIN thread owns
    // the wait box and renders the percentage the worker publishes. The progress
    // callback must never touch IDA -- TTD dispatches it from its own indexing
    // threads, and calling replace_wait_box() from there deadlocked IDA outright.
    //
    // The build cannot be interrupted: IndexBuildProgressCallback returns void and
    // BuildIndex exposes no cancellation flag, so the box is HIDECANCEL rather
    // than offering a Cancel that could not do anything.
    //
    // Returns true when the trace has a usable index afterwards. Note that a
    // status of IndexFileUnloadable is normal and still counts as usable: the
    // engine keeps an in-memory index, and GetIndexStatus() describes the on-disk
    // .idx file only.
    bool build_trace_index(TTD::Replay::IReplayEngine *engine);
}
