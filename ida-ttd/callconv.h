#pragma once

#include "pch.h"

namespace idattd
{
    // Calling-convention helpers used by the function tracer to read arguments
    // and return values out of the trace. The cursor passed in must already be
    // positioned at the call site (for arguments) or just after the matching
    // return (for return values). All reads go through the official TTD
    // ICursorView API.

    // Read 'size' bytes of guest memory into 'buf'; returns bytes actually read.
    size_t read_guest(TTD::Replay::ICursorView *cursor, uint64_t addr, void *buf, size_t size);

    // Offset (in bytes) from the stack pointer to the n-th argument, summing the
    // sizes of the stack-resident arguments that precede it. 'slot' is the stack
    // slot granularity — 8 for x64, 4 for x86.
    size_t stack_arg_offset(const tinfo_t &func_tinfo, size_t n, size_t first_stack_arg,
                            size_t slot);

    // Integer / pointer argument n of the function described by 'tinfo', read at
    // the current cursor position (call site). is64 selects the convention.
    uint64_t get_int_arg(TTD::Replay::ICursorView *cursor, const tinfo_t &tinfo, size_t n, bool is64);

    // Integer return value (RAX / EAX) at the current cursor position.
    uint64_t get_return_value(TTD::Replay::ICursorView *cursor, bool is64);

    // Read a (bounded) NUL-terminated narrow / wide string from guest memory,
    // rendered with escapes for control characters.
    qstring read_string_at(TTD::Replay::ICursorView *cursor, uint64_t addr);
    qstring read_wstring_at(TTD::Replay::ICursorView *cursor, uint64_t addr);
}
