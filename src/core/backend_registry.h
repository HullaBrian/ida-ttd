#pragma once

#include "common/pch.h"
#include "core/backend.h"

namespace idattd
{
    // Which backends are available, and which one a file belongs to.
    //
    // Backends are separate DLLs the core loads at startup from its backend
    // directory (see docs/modular-backends.md). Installing one is dropping a
    // file in; a backend the user does not have is simply absent, rather than
    // code they paid for in the download. It also keeps each backend's
    // third-party dependencies -- and its licence -- to itself.
    //
    // add() exists for a backend compiled into the core, which none is today;
    // it is what a test double would use.
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
