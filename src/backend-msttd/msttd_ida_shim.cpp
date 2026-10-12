// The IDA kernel functions the Microsoft backend reaches without meaning to.
//
// The backend is written in the core's vocabulary -- qstring, ea_t -- and
// pro.h's inline code for those calls into ida.dll for memory and
// formatting. A backend DLL must run without IDA (the probe loads it into a
// plain process), so it does not link ida.lib, and these stand in: the same
// contracts, over the C runtime.
//
// Only what the link asks for is here. A new unresolved external from ida.dll
// means the backend started using something of IDA's it should not.

#include "common/pch.h"

#include <cstdio>
#include <cstdlib>

idaman THREAD_SAFE void *ida_export qalloc(size_t size)
{
    return malloc(size != 0 ? size : 1);
}

idaman THREAD_SAFE void *ida_export qrealloc(void *alloc, size_t newsize)
{
    return realloc(alloc, newsize != 0 ? newsize : 1);
}

idaman THREAD_SAFE void ida_export qfree(void *alloc)
{
    free(alloc);
}

idaman THREAD_SAFE void *ida_export qcalloc(size_t nitems, size_t itemsize)
{
    return calloc(nitems != 0 ? nitems : 1, itemsize != 0 ? itemsize : 1);
}

// IDA declares the *_or_throw functions as not throwing, so an exception
// from here would end in std::terminate anyway; say why first.
[[noreturn]] static void out_of_memory()
{
    OutputDebugStringA("[ida-ttd] the Microsoft backend ran out of memory\n");
    abort();
}

idaman THREAD_SAFE void *ida_export qalloc_or_throw(size_t size)
{
    void *p = qalloc(size);
    if ( p == nullptr )
        out_of_memory();
    return p;
}

idaman THREAD_SAFE void *ida_export qrealloc_or_throw(void *ptr, size_t size)
{
    void *p = qrealloc(ptr, size);
    if ( p == nullptr )
        out_of_memory();
    return p;
}

// qvector<T> is { T *array; size_t n; size_t alloc; }. This grows its array
// to at least 'cnt' elements -- in place from 'old', or fresh when 'old' is
// null -- records the new capacity in the vector and returns the array.
// Growing by half again keeps repeated push_back amortised, as IDA's does.
idaman THREAD_SAFE void *ida_export qvector_reserve(void *vec, void *old, size_t cnt, size_t elsize)
{
    struct layout { void *array; size_t n; size_t alloc; };
    layout *v = static_cast<layout *>(vec);
    size_t want = v->alloc + v->alloc / 2;
    if ( want < cnt )
        want = cnt;
    if ( want < 4 )
        want = 4;
    void *p = old != nullptr ? qrealloc_or_throw(old, want * elsize) : qalloc_or_throw(want * elsize);
    v->alloc = want;
    return p;
}

idaman THREAD_SAFE AS_PRINTF(3, 0) int ida_export qvsnprintf(char *buffer, size_t n, const char *format, va_list va)
{
    if ( buffer == nullptr || n == 0 )
        return vsnprintf(nullptr, 0, format, va);
    int r = vsnprintf(buffer, n, format, va);
    buffer[n - 1] = '\0';
    return r;
}

idaman THREAD_SAFE AS_PRINTF(3, 4) int ida_export qsnprintf(char *buffer, size_t n, const char *format, ...)
{
    va_list va;
    va_start(va, format);
    int r = qvsnprintf(buffer, n, format, va);
    va_end(va);
    return r;
}
