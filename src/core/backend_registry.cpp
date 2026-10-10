#include "core/backend_registry.h"

namespace idattd
{
    BackendRegistry &BackendRegistry::instance()
    {
        // A function-local static, not a file-scope object: the registrations
        // run during static initialisation and would otherwise race the
        // registry's own construction across translation units.
        static BackendRegistry reg;
        return reg;
    }

    void BackendRegistry::add(Factory f)
    {
        if ( f != nullptr )
            m_factories.push_back(f);
    }

    const std::vector<BackendPtr> &BackendRegistry::all()
    {
        if ( m_backends.size() != m_factories.size() )
        {
            m_backends.clear();
            m_backends.reserve(m_factories.size());
            for ( Factory f : m_factories )
            {
                BackendPtr b = f();
                if ( b )
                    m_backends.push_back(std::move(b));
            }
        }
        return m_backends;
    }

    ITraceBackend *BackendRegistry::for_file(const char *path)
    {
        if ( path == nullptr || path[0] == '\0' )
            return nullptr;
        for ( const BackendPtr &b : all() )
            if ( b->can_open(path) )
                return b.get();
        return nullptr;
    }

    ITraceBackend *BackendRegistry::by_id(const char *id)
    {
        if ( id == nullptr )
            return nullptr;
        for ( const BackendPtr &b : all() )
            if ( qstrcmp(b->id(), id) == 0 )
                return b.get();
        return nullptr;
    }

    qstring BackendRegistry::file_filters()
    {
        qstring out;
        for ( const BackendPtr &b : all() )
        {
            const char *f = b->file_filter();
            if ( f == nullptr || f[0] == '\0' )
                continue;
            if ( !out.empty() )
                out.append('|');
            out.append(f);
        }
        return out;
    }
}
