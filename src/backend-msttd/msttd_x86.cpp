#include "backend-msttd/msttd_x86.h"

namespace idattd
{
    // Bytes the ModRM operand takes after the ModRM byte itself (SIB and
    // displacement), or -1 when 'n' runs out first.
    static int modrm_tail(const uint8_t *b, size_t n, size_t at, bool addr16)
    {
        if ( at >= n )
            return -1;
        uint8_t modrm = b[at];
        uint8_t mod = modrm >> 6, rm = modrm & 7;
        if ( mod == 3 )
            return 0;
        if ( addr16 )
        {
            if ( mod == 0 )
                return rm == 6 ? 2 : 0;
            return mod == 1 ? 1 : 2;
        }
        int extra = 0;
        if ( rm == 4 )
        {
            if ( at + 1 >= n )
                return -1;
            extra = 1;
            uint8_t base = b[at + 1] & 7;
            if ( mod == 0 && base == 5 )
                return extra + 4;
        }
        if ( mod == 0 )
            return extra + (rm == 5 ? 4 : 0);    // rm 5: disp32, RIP-relative in 64-bit
        return extra + (mod == 1 ? 1 : 4);
    }

    X86Branch x86_branch(const uint8_t *b, size_t n, bool is64)
    {
        X86Branch r;
        size_t i = 0;
        bool addr16 = false;
        for ( ; i < n && i < 15; i++ )
        {
            uint8_t p = b[i];
            if ( p == 0x67 )
                addr16 = !is64;
            else if ( !(p == 0x66 || p == 0xF2 || p == 0xF3 || p == 0xF0 || p == 0x2E || p == 0x3E
                     || p == 0x26 || p == 0x36 || p == 0x64 || p == 0x65) )
                break;
        }
        if ( is64 && i < n && (b[i] & 0xF0) == 0x40 )
            i++;                                    // REX
        if ( i >= n )
            return r;

        uint8_t op = b[i];
        if ( op == 0xC3 || op == 0xC2 || op == 0xCB || op == 0xCA )
        {
            r.is_ret = true;
            return r;
        }
        if ( op == 0xE8 )
        {
            r.is_call = true;
            r.len     = (int)i + 5;
            return r;
        }
        if ( op == 0x9A && !is64 )
        {
            r.is_call = true;
            r.len     = (int)i + 7;                 // ptr16:32
            return r;
        }
        if ( op == 0xFF && i + 1 < n )
        {
            uint8_t reg = (b[i + 1] >> 3) & 7;
            if ( reg != 2 && reg != 3 )
                return r;
            int tail = modrm_tail(b, n, i + 1, addr16);
            if ( tail < 0 )
                return r;
            r.is_call = true;
            r.len     = (int)i + 2 + tail;
        }
        return r;
    }
}
