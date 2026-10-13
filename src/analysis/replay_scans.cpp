#include "analysis/replay_scans.h"
#include "analysis/query_runner.h"
#include "debugger/trace_manager.h"

namespace idattd
{
    static const char SCAN_REGKEY[] = "ida-ttd";

    qstring saved_registry_dir()
    {
        qstring s;
        reg_read_string(&s, "ForkRegistryDir", SCAN_REGKEY);
        return s;
    }

    void save_registry_dir(const char *dir)
    {
        reg_write_string("ForkRegistryDir", dir != nullptr ? dir : "", SCAN_REGKEY);
    }

    static ITraceBackend *scanning_backend(TraceManager *mgr, qstring *error)
    {
        if ( mgr == nullptr || !mgr->is_active() || mgr->backend() == nullptr )
        {
            *error = "no recording is being replayed";
            return nullptr;
        }
        if ( !mgr->backend()->capabilities().replay_scans )
        {
            *error = "this recording's backend cannot replay it with a scanner";
            return nullptr;
        }
        return mgr->backend();
    }

    bool recover_strings(TraceManager *mgr, const ReplaySettings &settings, uint32_t min_length,
                         std::vector<StringHit> *out, bool *cancelled, qstring *error)
    {
        out->clear();
        *cancelled = false;
        error->clear();
        ITraceBackend *backend = scanning_backend(mgr, error);
        if ( backend == nullptr )
            return false;
        QueryResult qr = run_query("Replaying the recording to recover its strings", [&](ProgressSink *p)
        {
            return backend->query_strings(settings, min_length, out, p);
        });
        *cancelled = qr.cancelled;
        if ( !qr.ran )
            *error = backend->last_error();
        return qr.ran;
    }

    bool recover_buffers(TraceManager *mgr, const ReplaySettings &settings,
                         std::vector<BufferHit> *out, bool *cancelled, qstring *error)
    {
        out->clear();
        *cancelled = false;
        error->clear();
        ITraceBackend *backend = scanning_backend(mgr, error);
        if ( backend == nullptr )
            return false;
        QueryResult qr = run_query("Replaying the recording to recover the buffers it filled", [&](ProgressSink *p)
        {
            return backend->query_buffers(settings, out, p);
        });
        *cancelled = qr.cancelled;
        if ( !qr.ran )
            *error = backend->last_error();
        return qr.ran;
    }
}
