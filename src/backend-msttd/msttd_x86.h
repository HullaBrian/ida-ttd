#pragma once

#include <cstddef>
#include <cstdint>

namespace idattd
{
    // Just enough x86 decoding for the navigator: is the instruction a call
    // (and how long, since its return address is just past it) or a return.
    // A backend has no IDA decoder, and these questions need only the opcode,
    // ModRM, SIB and displacement.
    struct X86Branch
    {
        bool is_call = false;   // E8, FF /2, FF /3, 9A
        bool is_ret  = false;   // C3, C2 iw, CB, CA iw
        int  len     = 0;       // the call's length; 0 when it is not one
    };

    // 'b' holds up to 'n' bytes starting at the instruction; 'is64' is the
    // code's mode (64-bit, or 32-bit including WoW64 code).
    X86Branch x86_branch(const uint8_t *b, size_t n, bool is64);
}
