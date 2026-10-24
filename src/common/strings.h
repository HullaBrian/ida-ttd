#pragma once

#include "common/pch.h"

namespace idattd
{
    // String helpers shared by the core and the backends. The TTD engine uses
    // wide strings and IDA uses UTF-8.
    std::string  to_utf8(const wchar_t *w, size_t len);
    std::string  to_utf8(const wchar_t *w);
    std::wstring to_wstring(const char *s);
    // Everything after the last slash or backslash: how a module's full
    // recorded path is compared with the name the user or database knows.
    std::string  base_name(const std::string &path);
}
