#pragma once

#include "common/pch.h"
#include "core/guest_view.h"

namespace idattd
{
    // Calling-convention helpers used by the function tracer to read arguments
    // and return values out of the trace. The view passed in must already be
    // at the call site (for arguments) or just after the matching return (for
    // return values). Any backend's cursor gives one (core/guest_view.h).

    // Offset (in bytes) from the stack pointer to the n-th argument, summing the
    // sizes of the stack-resident arguments that precede it. 'slot' is the stack
    // slot granularity -- 8 for x64, 4 for x86.
    size_t stack_arg_offset(const tinfo_t &func_tinfo, size_t n, size_t first_stack_arg,
                            size_t slot);

    // Integer / pointer argument n of the function described by 'tinfo', read at
    // the view's position (call site). is64 selects the convention.
    uint64_t get_int_arg(const GuestView &view, const tinfo_t &tinfo, size_t n, bool is64);

    // Integer return value (RAX / EAX) at the view's position.
    uint64_t get_return_value(const GuestView &view, bool is64);

    // Read a (bounded) NUL-terminated narrow / wide string from guest memory,
    // rendered with escapes for control characters.
    qstring read_string_at(const GuestView &view, uint64_t addr);
    qstring read_wstring_at(const GuestView &view, uint64_t addr);
}
