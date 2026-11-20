#pragma once

#include "common/pch.h"
#include "core/backend.h"

namespace idattd
{
    // Which backends are available, and which one a file belongs to.
    //
    // Backends are separate DLLs the core loads at startup from its backend
    // directories (docs/modular-backends.md). Installing one is dropping a
    // file in, and each backend keeps its third-party dependencies and its
    // license to itself.
    //
    // add() is for a backend compiled into the core (none is today), such as
    // a test double.
    class BackendRegistry
    {
    public:
        static BackendRegistry &instance();

        using Factory = BackendPtr (*)();
        void add(Factory f);
        // A backend that already exists: one loaded from a DLL
        // (core/backend_module.h). Kept in the order added, after every
        // compiled-in one.
        void add_backend(BackendPtr b);

        // One instance of every registered backend, created on first use and
        // kept: can_open() and the identity accessors are valid before anything
        // is opened, and the chosen one then has open() called on it.
        const std::vector<ITraceBackend *> &all();

        // The first registered backend that says it handles 'path', or nullptr.
        // Registration order breaks ties, so can_open() should look at the
        // file, not only its extension.
        ITraceBackend *for_file(const char *path);
        ITraceBackend *by_id(const char *id);

        // The File > Open filter, with one entry per backend.
        qstring file_filters();

    private:
        std::vector<Factory>         m_factories;
        std::vector<BackendPtr>      m_compiled;   // owners, one per factory run
        std::vector<BackendPtr>      m_loaded;     // owners, from add_backend()
        std::vector<ITraceBackend *> m_all;        // both, compiled-in first
        bool                         m_dirty = true;
    };

    // Helper for the macro below.
    struct BackendRegistration
    {
        explicit BackendRegistration(BackendRegistry::Factory f)
        { BackendRegistry::instance().add(f); }
    };
}

// Put one of these at file scope in a backend's implementation:
//
//     REGISTER_TTD_BACKEND(MyTestBackend);
//
// 'type' must be default-constructible and derive from ITraceBackend. The
// object is created when the registry is first asked for its backends, not
// here, so a constructor may do real work.
#define REGISTER_TTD_BACKEND(type)                                            \
    namespace                                                                 \
    {                                                                         \
        ::idattd::BackendPtr make_##type() { return std::make_unique<type>(); } \
        const ::idattd::BackendRegistration register_##type{ &make_##type };  \
    }
