#include "core/diag.h"

#include <cstdio>

namespace idattd
{
    static std::mutex g_mtx;

    static std::wstring log_path(const wchar_t *name)
    {
        wchar_t dir[MAX_PATH] = { 0 };
        DWORD n = GetTempPathW(MAX_PATH, dir);
        if ( n == 0 || n >= MAX_PATH )
            return std::wstring();
        return std::wstring(dir) + name;
    }

    void diag_rotate()
    {
        std::lock_guard<std::mutex> lock(g_mtx);
        std::wstring cur = log_path(L"ida-ttd-diag.log");
        std::wstring old = log_path(L"ida-ttd-diag.prev.log");
        if ( cur.empty() )
            return;
        DeleteFileW(old.c_str());
        MoveFileW(cur.c_str(), old.c_str());
    }

    void diag(const char *fmt, ...)
    {
        char line[2048];
        va_list va;
        va_start(va, fmt);
        vsnprintf(line, sizeof(line), fmt, va);
        va_end(va);

        SYSTEMTIME st;
        GetLocalTime(&st);
        std::lock_guard<std::mutex> lock(g_mtx);
        std::wstring path = log_path(L"ida-ttd-diag.log");
        FILE *f = path.empty() ? nullptr : _wfopen(path.c_str(), L"a");
        if ( f == nullptr )
            return;
        fprintf(f, "%02u:%02u:%02u.%03u [%5lu] %s\n", st.wHour, st.wMinute, st.wSecond,
                st.wMilliseconds, GetCurrentThreadId(), line);
        fclose(f);
    }

    DiagTimer::DiagTimer(const char *what, uint32_t threshold_ms)
        : m_what(what), m_threshold(threshold_ms), m_t0(GetTickCount64())
    {
    }

    DiagTimer::DiagTimer(const char *what, const qstring &detail, uint32_t threshold_ms)
        : m_what(what), m_detail(detail), m_threshold(threshold_ms), m_t0(GetTickCount64())
    {
    }

    DiagTimer::~DiagTimer()
    {
        uint64_t ms = GetTickCount64() - m_t0;
        if ( ms >= m_threshold )
            diag("%s%s%s: %llu ms", m_what, m_detail.empty() ? "" : " ", m_detail.c_str(), ms);
    }
}
