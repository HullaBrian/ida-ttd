#pragma once

#include <cstddef>
#include <cstdint>

namespace idattd
{
    // Just enough x86 decoding for the navigator: is the instruction at hand a
    // call, and how long is it (its return address is just past it), or a
    // return. A backend runs outside IDA's database, so IDA's decoder is not
    // available -- and these two questions need only the opcode, ModRM, SIB
    // and displacement, never the operands' meaning.
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
