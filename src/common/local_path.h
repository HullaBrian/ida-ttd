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
    // A legacy DOS device name (CON, PRN, AUX, NUL, COM0-9, LPT0-9), with or
    // without an extension: Win32 opens the device, whatever folder it is
    // in ("C:\x\CON.txt" is the console), and a read of the console waits
    // for keyboard input. Case-insensitive, trailing dots and blanks
    // ignored, as Win32 does.
    template <typename C>
    inline bool is_dos_device_name(const C *s, size_t n)
    {
        size_t stem = 0;
        while ( stem < n && s[stem] != C('.') )
            stem++;
        while ( stem > 0 && (s[stem - 1] == C(' ') || s[stem - 1] == C('.')) )
            stem--;
        auto up = [](C c) { return (c >= C('a') && c <= C('z')) ? C(c - C('a') + C('A')) : c; };
        auto is3 = [&](const char *w)
        {
            return up(s[0]) == C(w[0]) && up(s[1]) == C(w[1]) && up(s[2]) == C(w[2]);
        };
        if ( stem == 3 )
            return is3("CON") || is3("PRN") || is3("AUX") || is3("NUL");
        if ( stem == 4 && s[3] >= C('0') && s[3] <= C('9') )
            return is3("COM") || is3("LPT");
        return false;
    }

    // Any component of 'p' (separated by '\' or '/') is a DOS device name.
    template <typename C>
    inline bool has_dos_device_component(const C *p, size_t n)
    {
        size_t i = 0;
        while ( i < n )
        {
            size_t j = i;
            while ( j < n && p[j] != C('\\') && p[j] != C('/') )
                j++;
            if ( j > i && is_dos_device_name(p + i, j - i) )
                return true;
            i = j + 1;
        }
        return false;
    }

    // True when 'path' is an absolute path on a local (non-network) drive:
    // "X:\..." or "\\?\X:\...". UNC, device and relative paths are refused,
    // and so is a drive letter mapped to a network share, and a path naming
    // a DOS device (has_dos_device_component).
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
        if ( has_dos_device_component(p.c_str() + 3, p.size() - 3) )
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
