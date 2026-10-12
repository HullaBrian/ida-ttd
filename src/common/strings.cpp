#include "common/strings.h"

namespace idattd
{
    std::string to_utf8(const wchar_t *w, size_t len)
    {
        if ( w == nullptr || len == 0 )
            return std::string();
        int n = WideCharToMultiByte(CP_UTF8, 0, w, (int)len, nullptr, 0, nullptr, nullptr);
        if ( n <= 0 )
            return std::string();
        std::string s((size_t)n, '\0');
        WideCharToMultiByte(CP_UTF8, 0, w, (int)len, s.data(), n, nullptr, nullptr);
        return s;
    }

    std::string to_utf8(const wchar_t *w)
    {
        return to_utf8(w, w != nullptr ? wcslen(w) : 0);
    }

    std::wstring to_wstring(const char *s)
    {
        if ( s == nullptr || *s == '\0' )
            return std::wstring();
        int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, nullptr, 0);
        if ( n <= 0 )
            return std::wstring();
        std::wstring w((size_t)n, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, s, -1, w.data(), n);
        if ( !w.empty() && w.back() == L'\0' )
            w.pop_back();
        return w;
    }

    std::string base_name(const std::string &path)
    {
        size_t p = path.find_last_of("\\/");
        return p == std::string::npos ? path : path.substr(p + 1);
    }
}
