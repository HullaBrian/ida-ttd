// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
//
// Dual-licensed like write_scans.h: shared by the plugin and both backends,
// so it stays header-only and standard-library-only (plus <windows.h>).
//
// A recording names host paths (module files, Sogen's emulation root) that
// the plugin then opens. A crafted recording could name a UNC path, which
// makes Windows connect to that host over SMB or WebDAV and send the user's
// NTLM credentials, or a device path (\\.\pipe\...) that blocks the reader.
// Only paths on a local drive letter are opened.

#pragma once

#include <string>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace idattd
{
    // True when 'path' is an absolute path on a local (non-network) drive:
    // "X:\..." or "\\?\X:\...". UNC, device and relative paths are refused,
    // and so is a drive letter mapped to a network share.
    inline bool is_local_drive_path(const std::wstring &path)
    {
        std::wstring p = path;
        for ( wchar_t &c : p )
            if ( c == L'/' )
                c = L'\\';
        if ( p.compare(0, 4, L"\\\\?\\") == 0 )
            p.erase(0, 4);
        if ( p.size() < 3 || p[1] != L':' || p[2] != L'\\' )
            return false;
        wchar_t d = p[0];
        if ( !((d >= L'A' && d <= L'Z') || (d >= L'a' && d <= L'z')) )
            return false;
        const wchar_t root[4] = { d, L':', L'\\', 0 };
        UINT type = GetDriveTypeW(root);
        return type == DRIVE_FIXED || type == DRIVE_REMOVABLE
            || type == DRIVE_CDROM || type == DRIVE_RAMDISK;
    }

    // UTF-8 overload.
    inline bool is_local_drive_path(const char *utf8)
    {
        if ( utf8 == nullptr || *utf8 == '\0' )
            return false;
        int n = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, nullptr, 0);
        if ( n <= 0 )
            return false;
        std::wstring w((size_t)n - 1, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, utf8, -1, w.data(), n);
        return is_local_drive_path(w);
    }
}
