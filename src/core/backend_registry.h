#pragma once

#include "common/pch.h"
#include "core/backend.h"

namespace idattd
{
    // Which backends this build has, and which one a file belongs to.
    //
    // Backends are compiled in, not loaded at runtime: the core is a static
    // library and each backend is another, and the plugin DLL links whichever
    // the build asked for (see docs/modular-backends.md). A build with no Sogen
    // support therefore contains no Sogen code at all, rather than a module
    // that fails to load -- which matters because the two backends have
    // different third-party dependencies.
    //
    // Registration happens before IDA has done anything: each backend library
    // contributes one REGISTER_TTD_BACKEND at file scope, so adding a backend
    // to a build is a project-file change and nothing else.
    class BackendRegistry
    {
    public:
        static BackendRegistry &instance();

        using Factory = BackendPtr (*)();
        void add(Factory f);

        // One instance of every registered backend, created on first use and
        // kept: can_open() and the identity accessors are valid before anything
        // is opened, and the chosen one then has open() called on it.
        const std::vector<BackendPtr> &all();

        // The first registered backend that says it handles 'path', or nullptr.
        // Registration order is the tie-break, which is why a backend's
        // can_open() should look at the file rather than only its extension.
        ITraceBackend *for_file(const char *path);
        ITraceBackend *by_id(const char *id);

        // The File > Open filter, with one entry per backend.
        qstring file_filters();

    private:
        std::vector<Factory>   m_factories;
        std::vector<BackendPtr> m_backends;
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
//     REGISTER_TTD_BACKEND(MsTtdBackend);
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
