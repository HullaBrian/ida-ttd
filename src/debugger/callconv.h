#pragma once

#include "common/pch.h"
#include "core/guest_view.h"

namespace idattd
{
    // Calling-convention helpers the function tracer uses to read arguments
    // and return values. The view must be at the call site (arguments) or
    // just after the matching return (return values); any backend's cursor
    // gives one (core/guest_view.h).

    // Byte offset of the n-th argument from the first stack argument: the
    // sizes of the stack arguments before it, each rounded up to 'slot'
    // (the stack slot size; only x86, with 4, uses this).
    size_t stack_arg_offset(const tinfo_t &func_tinfo, size_t n, size_t first_stack_arg,
                            size_t slot);

    // Integer / pointer argument n of the function described by 'tinfo', read at
    // the view's position (call site). is64 selects the convention.
    uint64_t get_int_arg(const GuestView &view, const tinfo_t &tinfo, size_t n, bool is64);
    // The same from a prototype already unpacked with get_func_details, so a
    // caller reading many calls of one function unpacks it once. Honours
    // __fastcall and __thiscall on x86, and a __usercall prototype's own
    // argument locations (general registers and the stack).
    uint64_t get_int_arg(const GuestView &view, const func_type_data_t &fd, size_t n, bool is64);

    // Integer return value (RAX / EAX) at the view's position.
    uint64_t get_return_value(const GuestView &view, bool is64);

    // Read a (bounded) NUL-terminated narrow / wide string from guest memory,
    // rendered with escapes for control characters.
    qstring read_string_at(const GuestView &view, uint64_t addr);
    qstring read_wstring_at(const GuestView &view, uint64_t addr);
}
