// SPDX-License-Identifier: GPL-2.0-only
//
// ida-ttd's Sogen backend: what an executed instruction is, from the bytes
// its execute event carries. See sogen_state.h.

#pragma once

#include "backend-sogen/sogen_state.h"

namespace idattd::sogen
{
    // The opcode of an executed instruction, past its prefixes, and the byte
    // after it; false when the bytes are not there.
    inline bool opcode_of(const ttd::access_event &ev, bool is64, uint8_t *op, uint8_t *modrm)
    {
        size_t n = std::min<size_t>(ev.size == 0 ? ev.payload.size() : (size_t)ev.size, ev.payload.size());
        size_t i = 0;
        for ( ; i < n; i++ )
        {
            uint8_t c = ev.payload[i];
            bool prefix = c == 0x66 || c == 0x67 || c == 0xF2 || c == 0xF3 || c == 0x2E || c == 0x3E
                       || c == 0x26 || c == 0x36 || c == 0x64 || c == 0x65 || c == 0xF0
                       || (is64 && c >= 0x40 && c <= 0x4F);
            if ( !prefix )
                break;
        }
        if ( i >= n )
            return false;
        *op    = ev.payload[i];
        *modrm = i + 1 < n ? ev.payload[i + 1] : 0;
        return true;
    }

    // E8, FF /2 and FF /3, and 9A on 32-bit.
    inline bool is_call_op(uint8_t op, uint8_t modrm, bool is64)
    {
        uint8_t reg = (modrm >> 3) & 7;
        return op == 0xE8 || (op == 0x9A && !is64) || (op == 0xFF && (reg == 2 || reg == 3));
    }

    // C3, C2 imm16, and the far forms ("rep ret" included, by the prefixes).
    inline bool is_ret_op(uint8_t op)
    {
        return op == 0xC3 || op == 0xC2 || op == 0xCB || op == 0xCA;
    }

    // The navigator's tests, which do not know the program's bitness, decode
    // as 64-bit. 32-bit code differs only in far calls (9A) and in 40-4F,
    // which there are one-byte instructions and so never precede an opcode
    // within one instruction's bytes.
    inline bool is_call_insn(const ttd::access_event &e)
    {
        uint8_t op = 0, modrm = 0;
        return opcode_of(e, true, &op, &modrm) && is_call_op(op, modrm, true);
    }

    inline bool is_ret_insn(const ttd::access_event &e)
    {
        uint8_t op = 0, modrm = 0;
        return opcode_of(e, true, &op, &modrm) && is_ret_op(op);
    }
}
