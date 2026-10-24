#include "analysis/replay_scans.h"
#include "analysis/query_runner.h"
#include "debugger/trace_manager.h"
#include "core/backend_module.h"
#include "plugin/settings.h"

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

    static void add_candidate(qstrvec_t *v, qstring dir)
    {
        while ( dir.length() > 3 && (dir.last() == '\\' || dir.last() == '/') )
            dir.remove_last();
        if ( dir.empty() )
            return;
        for ( const qstring &d : *v )
            if ( stricmp(d.c_str(), dir.c_str()) == 0 )
                return;
        v->push_back(dir);
    }

    // Per recording, for this session only: a root belongs to the machine
    // viewing the recording, and rarely moves.
    static std::map<qstring, qstring> g_roots;

    qstring chosen_emulation_root(TraceManager *mgr)
    {
        if ( mgr == nullptr )
            return qstring();
        auto it = g_roots.find(mgr->trace_path());
        return it != g_roots.end() ? it->second : qstring();
    }

    void choose_emulation_root(TraceManager *mgr, const char *dir)
    {
        if ( mgr != nullptr )
            g_roots[mgr->trace_path()] = dir != nullptr ? dir : "";
    }

    static bool get_env(TraceManager *mgr, ReplayEnv *env)
    {
        return mgr != nullptr && mgr->backend() != nullptr && mgr->backend()->replay_env(env);
    }

    qstrvec_t registry_candidates(TraceManager *mgr)
    {
        qstrvec_t v;
        ReplayEnv env;
        if ( get_env(mgr, &env) && !env.host )
        {
            qstring root = chosen_emulation_root(mgr);
            if ( root.empty() )
            {
                add_candidate(&v, env.registry_hint);
            }
            else
            {
                root.append("\\registry");
                add_candidate(&v, root);
            }
            return v;
        }
        add_candidate(&v, saved_registry_dir());
        if ( mgr != nullptr )
        {
            qstring beside = mgr->trace_path();
            ssize_t slash = beside.rfind('\\');
            if ( slash >= 0 )
            {
                beside.resize((size_t)slash);
                beside.append("\\registry");
                add_candidate(&v, beside);
            }
        }
        add_candidate(&v, settings().registry_folder);     // the registry_folder setting
        add_candidate(&v, user_data_dir("registry"));
        return v;
    }

    qstring find_registry_dir(TraceManager *mgr)
    {
        ITraceBackend *b = mgr != nullptr ? mgr->backend() : nullptr;
        if ( b == nullptr )
            return saved_registry_dir();
        ReplayEnv env;
        const bool known = get_env(mgr, &env);
        if ( known && !env.host )
            return qstring();
        qstring unverified, mismatch;
        for ( const qstring &dir : registry_candidates(mgr) )
        {
            switch ( b->check_registry(dir.c_str(), nullptr) )
            {
                case HiveCheck::Match:
                    return dir;
                case HiveCheck::Unverified:
                    if ( unverified.empty() )
                        unverified = dir;
                    break;
                case HiveCheck::Mismatch:
                    if ( mismatch.empty() )
                        mismatch = dir;
                    break;
                case HiveCheck::Missing:
                    break;
            }
        }
        // A recording carrying its hives replays without files; only its own
        // hives would add anything (a fork reading further than it did).
        if ( known && env.registry_carried )
            return qstring();
        return !unverified.empty() ? unverified : mismatch;
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
