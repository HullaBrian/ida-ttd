#include "debugger/callconv.h"

namespace idattd
{
    size_t stack_arg_offset(const tinfo_t &func_tinfo, size_t n, size_t first_stack_arg,
                            size_t slot)
    {
        size_t off  = 0;
        size_t mask = slot - 1;
        for ( size_t i = first_stack_arg; i < n; i++ )
        {
            tinfo_t arg = func_tinfo.get_nth_arg((int)i);
            size_t sz = arg.get_size();
            if ( sz == BADSIZE )
                continue;
            if ( sz < slot )
                sz = slot;                       // stack slots are pointer-sized minimum
            off += (sz + mask) & ~mask;
        }
        return off;
    }

    // Read at the call instruction before it executes, so no return address
    // is pushed yet: register arguments are in their registers and stack
    // arguments at SP (+ shadow space on x64, + preceding stack arguments).
    uint64_t get_int_arg(const GuestView &view, const tinfo_t &tinfo, size_t n, bool is64)
    {
        func_type_data_t fd;
        if ( !tinfo.get_func_details(&fd) )
            return 0;
        return get_int_arg(view, fd, n, is64);
    }

    // stack_arg_offset over an unpacked prototype.
    static size_t stack_arg_offset(const func_type_data_t &fd, size_t n, size_t first_stack_arg,
                                   size_t slot)
    {
        size_t off  = 0;
        size_t mask = slot - 1;
        for ( size_t i = first_stack_arg; i < n && i < fd.size(); i++ )
        {
            size_t sz = fd[i].type.get_size();
            if ( sz == BADSIZE )
                continue;
            if ( sz < slot )
                sz = slot;
            off += (sz + mask) & ~mask;
        }
        return off;
    }

    uint64_t get_int_arg(const GuestView &view, const func_type_data_t &fd, size_t n, bool is64)
    {
        ittd_regs r{};
        if ( n >= fd.size() || !view.regs || !view.regs(&r) )
            return 0;

        const tinfo_t &arg = fd[n].type;
        const callcnv_t cc = fd.get_cc();

        // A __usercall prototype says where each argument is. IDA numbers
        // the x86 general registers as ITTD_REG_* does (rax 0 .. r15 15);
        // a stack location is an offset from the first stack argument, which
        // is where the stack pointer points at the call. Anything else (an
        // XMM register, a register pair, a scattered aggregate) reads as 0.
        if ( fd.is_user_cc() )
        {
            const argloc_t &loc = fd[n].argloc;
            const size_t sz = arg.get_size();
            if ( loc.is_reg1() && loc.reg1() >= 0 && loc.reg1() < 16 )
            {
                uint64_t v = r.gp[loc.reg1()] >> (8 * loc.regoff());
                return is64 ? v : (uint32_t)v;
            }
            if ( loc.is_stkoff() )
            {
                uint64_t sp = is64 ? r.gp[ITTD_REG_RSP] : (uint32_t)r.gp[ITTD_REG_RSP];
                uint64_t v = 0;
                view.read(sp + loc.stkoff(), &v, sz != BADSIZE && sz >= 1 && sz <= 8 ? sz : (is64 ? 8 : 4));
                return v;
            }
            return 0;
        }

        if ( is64 )
        {
            if ( n < 4 )
            {
                if ( arg.is_floating() )
                {
                    // The low 64 bits of XMM0..3.
                    uint64_t lo = 0;
                    memcpy(&lo, r.xmm[n], sizeof(lo));
                    return lo;
                }
                const int regs[4] = { ITTD_REG_RCX, ITTD_REG_RDX, ITTD_REG_R8, ITTD_REG_R8 + 1 /* R9 */ };
                return r.gp[regs[n]];
            }
            // Every x64 argument takes one 8-byte slot (anything not 1, 2, 4
            // or 8 bytes goes by reference), so type sizes are not summed.
            // 0x20 is the callee's shadow space.
            size_t off = 0x20 + 8 * (n - 4);
            uint64_t v = 0;
            view.read(r.gp[ITTD_REG_RSP] + off, &v, sizeof(v));
            return v;
        }

        // A 32-bit target's registers are the low halves.
        size_t first_stack_arg = 0;
        if ( cc == CM_CC_FASTCALL )
        {
            if ( n < 2 )
                return (uint32_t)r.gp[n == 0 ? ITTD_REG_RCX : ITTD_REG_RDX];
            first_stack_arg = 2;
        }
        else if ( cc == CM_CC_THISCALL )
        {
            if ( n == 0 )
                return (uint32_t)r.gp[ITTD_REG_RCX];
            first_stack_arg = 1;
        }
        size_t off = stack_arg_offset(fd, n, first_stack_arg, 4);
        size_t sz  = arg.get_size();
        uint64_t v = 0;
        view.read((uint32_t)r.gp[ITTD_REG_RSP] + off, &v, sz == 8 ? 8 : 4);
        return v;
    }

    uint64_t get_return_value(const GuestView &view, bool is64)
    {
        ittd_regs r{};
        if ( !view.regs || !view.regs(&r) )
            return 0;
        return is64 ? r.gp[ITTD_REG_RAX] : (uint32_t)r.gp[ITTD_REG_RAX];
    }

    static void cat_char(qstring *out, wchar_t c)
    {
        switch ( c )
        {
            case L'\n': out->append("\\n"); break;
            case L'\r': out->append("\\r"); break;
            case L'\t': out->append("\\t"); break;
            default:
                // Other control characters would land raw in a one-line listing.
                if ( c < 0x20 || c == 0x7F )
                    out->cat_sprnt("\\x%02X", (unsigned)c);
                else if ( (c >> 8) == 0 )
                    out->cat_sprnt("%c", (char)(c & 0xFF));
                else
                    out->cat_sprnt("%lc", c);
                break;
        }
    }

    // Both string readers read in chunks: per character, a 260-character
    // string cost 260 engine queries per argument of every traced call.
    static const int kMaxStrChars = 260;

    qstring read_string_at(const GuestView &view, uint64_t addr)
    {
        qstring out;
        char    chunk[64];
        int     done = 0;
        while ( done < kMaxStrChars )
        {
            size_t want = (size_t)(kMaxStrChars - done);
            if ( want > sizeof(chunk) )
                want = sizeof(chunk);
            size_t got = view.read(addr + done, chunk, want);
            if ( got == 0 )
                break;
            for ( size_t i = 0; i < got; i++ )
            {
                if ( chunk[i] == '\0' )
                    return out;
                cat_char(&out, (unsigned char)chunk[i]);
            }
            done += (int)got;
        }
        return out;
    }

    qstring read_wstring_at(const GuestView &view, uint64_t addr)
    {
        qstring out;
        wchar_t chunk[64];
        int     done = 0;
        while ( done < kMaxStrChars )
        {
            size_t want = (size_t)(kMaxStrChars - done) * sizeof(wchar_t);
            if ( want > sizeof(chunk) )
                want = sizeof(chunk);
            size_t got = view.read(addr + (uint64_t)done * sizeof(wchar_t), chunk, want);
            size_t nch = got / sizeof(wchar_t);
            if ( nch == 0 )
                break;
            for ( size_t i = 0; i < nch; i++ )
            {
                if ( chunk[i] == L'\0' )
                    return out;
                cat_char(&out, chunk[i]);
            }
            done += (int)nch;
        }
        return out;
    }
}
