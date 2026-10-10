// dllmain.cpp : Defines the entry point for the DLL application.
#include "common/pch.h"

// Our own module handle, kept so the plugin can work out the file name IDA
// knows it by. That is not a cosmetic question: load_debugger() selects a
// debugger by the file name of the plugin that provides it, not by
// debugger_t::name, so switching to ourselves programmatically needs it. The
// SDK's own win32 debugger shows this -- it calls load_debugger("win32_stub")
// while its debugger_t::name is "win32".
static HMODULE g_module = nullptr;

// Base name of this DLL without its extension ("ida-ttd"), or an empty string
// if it cannot be determined. Derived at runtime rather than hard-coded so a
// renamed plugin still finds itself.
qstring plugin_module_name()
{
    qstring out;
    if ( g_module == nullptr )
        return out;

    char path[QMAXPATH];
    DWORD n = GetModuleFileNameA(g_module, path, (DWORD)sizeof(path));
    if ( n == 0 || n >= sizeof(path) )
        return out;

    const char *base = path;
    for ( const char *p = path; *p != '\0'; p++ )
        if ( *p == '\\' || *p == '/' )
            base = p + 1;

    out = base;
    size_t dot = out.rfind('.');
    if ( dot != qstring::npos )
        out.resize(dot);
    return out;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        g_module = hModule;
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
