// DLL entry point.
#include "common/pch.h"

// The plugin's module handle, for the file name IDA knows it by.
// load_debugger() selects a debugger by its plugin's file name, not by
// debugger_t::name, so switching to this debugger programmatically needs it
// (the SDK's win32 debugger calls load_debugger("win32_stub") while its
// debugger_t::name is "win32").
static HMODULE g_module = nullptr;

// Base name of this DLL without its extension ("ida-ttd"), or empty if it
// cannot be determined. Derived at runtime so a renamed plugin still finds
// itself.
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
