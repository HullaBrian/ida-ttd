#pragma once

#include "common/pch.h"

namespace idattd
{
    // String helpers, shared by the core and the backends.
    //
    // The TTD engine speaks wide strings and IDA speaks UTF-8, so every module
    // name and every trace path crosses this boundary.
    std::string  to_utf8(const wchar_t *w, size_t len);
    std::string  to_utf8(const wchar_t *w);
    std::wstring to_wstring(const char *s);
    // Everything after the last slash or backslash. Trace module names are full
    // paths from the recording machine, so this is how a module is compared
    // against a name the user or the database knows it by.
    std::string  base_name(const std::string &path);
}
