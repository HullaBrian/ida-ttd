#include "core/backend_registry.h"

namespace idattd
{
    BackendRegistry &BackendRegistry::instance()
    {
        // A function-local static, not a file-scope object: the registrations
        // run during static initialization and would otherwise race the
        // registry's own construction across translation units.
        static BackendRegistry reg;
        return reg;
    }

    void BackendRegistry::add(Factory f)
    {
        if ( f != nullptr )
        {
            m_factories.push_back(f);
            m_dirty = true;
        }
    }

    void BackendRegistry::add_backend(BackendPtr b)
    {
        if ( b )
        {
            m_loaded.push_back(std::move(b));
            m_dirty = true;
        }
    }

    const std::vector<ITraceBackend *> &BackendRegistry::all()
    {
        if ( !m_dirty )
            return m_all;
        // Run any factory not yet run, then list everything, compiled-in
        // backends first so they win the can_open() tie-break. The two
        // vectors own the backends; this list only orders them.
        for ( size_t i = m_compiled.size(); i < m_factories.size(); i++ )
            m_compiled.push_back(m_factories[i]());
        m_all.clear();
        for ( const BackendPtr &b : m_compiled )
            if ( b )
                m_all.push_back(b.get());
        for ( const BackendPtr &b : m_loaded )
            m_all.push_back(b.get());
        m_dirty = false;
        return m_all;
    }

    ITraceBackend *BackendRegistry::for_file(const char *path)
    {
        if ( path == nullptr || path[0] == '\0' )
            return nullptr;
        for ( ITraceBackend *b : all() )
            if ( b->can_open(path) )
                return b;
        return nullptr;
    }

    ITraceBackend *BackendRegistry::by_id(const char *id)
    {
        if ( id == nullptr )
            return nullptr;
        for ( ITraceBackend *b : all() )
            if ( qstrcmp(b->id(), id) == 0 )
                return b;
        return nullptr;
    }

    qstring BackendRegistry::file_filters()
    {
        qstring out;
        for ( ITraceBackend *b : all() )
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
