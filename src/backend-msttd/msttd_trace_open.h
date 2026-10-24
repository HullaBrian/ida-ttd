#pragma once

#include "backend-msttd/msttd_pch.h"
#include "common/strings.h"
#include "core/backend.h"

namespace idattd
{
    // What opening a TTD trace needs besides the engine itself: somewhere for
    // its diagnostics to go, and the memory index.

    class MsTtdBackend;

    // Error sink so the TTD engine's diagnostics reach the host's log, and
    // become the backend's last error: the engine says why it failed here
    // and nowhere else.
    class MsttdErrorReporting : public TTD::ErrorReporting
    {
    public:
        void __fastcall VPrintError(char const *pFmt, va_list argList) override;

        const MsTtdBackend *owner = nullptr;
    };

    // Build the trace's memory index if it has none; without one, memory reads
    // are severely limited.
    //
    // BuildIndex is synchronous and can take minutes, so the core runs this on
    // a worker thread behind a wait box. The percentage reaches 'progress'
    // (may be null) from TTD's own indexing threads. The build cannot be
    // interrupted: the progress callback returns void and there is no
    // cancellation flag.
    //
    // Returns true when the trace has a usable index. IndexFileUnloadable still
    // counts: the engine keeps an in-memory index, and GetIndexStatus()
    // describes only the on-disk .idx file.
    bool build_trace_index(TTD::Replay::IReplayEngine *engine, ProgressSink *progress);
}
