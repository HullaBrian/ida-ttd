#include "callconv.h"

using namespace TTD;
using namespace TTD::Replay;

namespace idattd
{
    //-----------------------------------------------------------------------
    // Fill buf[0..size) from guest [addr, addr+size), zero-filling anything the
    // recording cannot supply, and return how many bytes are real counting from
    // the START of the range (so a caller reading one value can test == size,
    // and a string reader can scan exactly that far).
    //
    // The single unqualified QueryMemoryBuffer this replaces lost bytes two ways.
    // It named no policy, so the cursor's default answered rather than the
    // GloballyAggressive-then-InFragmentAggressive pair on_read_memory has always
    // used; and it stopped at the first unrecorded byte, so every recorded byte
    // past a hole was dropped. Neither is what a caller reading an argument out
    // of guest memory wants.
    size_t read_guest(ICursorView *cursor, uint64_t addr, void *buf, size_t size)
    {
        if ( cursor == nullptr || buf == nullptr || size == 0 )
            return 0;

        static const QueryMemoryPolicy kPolicies[] = {
            QueryMemoryPolicy::GloballyAggressive,   // cheap; zero-fills mapped memory
            QueryMemoryPolicy::InFragmentAggressive, // look across the whole fragment
        };

        uint8_t *out = (uint8_t *)buf;
        memset(out, 0, size);

        size_t off        = 0;   // next byte of the range to resolve
        size_t contiguous = 0;   // real bytes counted from the start, no holes
        bool   unbroken   = true;
        while ( off < size )
        {
            MemoryBuffer mb{};
            for ( QueryMemoryPolicy p : kPolicies )
            {
                mb = cursor->QueryMemoryBuffer(GuestAddress{ addr + off },
                                               BufferView{ out + off, size - off }, p);
                if ( mb.Memory.Size > 0 )
                    break;
            }
            if ( mb.Memory.Size == 0 )
            {
                unbroken = false;    // hole: keep the zero and step over it
                off++;
                continue;
            }

            size_t run = mb.Memory.Size;
            if ( run > size - off )
                run = size - off;
            off += run;
            if ( unbroken )
                contiguous = off;
        }
        return contiguous;
    }

    //-----------------------------------------------------------------------
    // 'slot' is the stack slot granularity: 8 on x64, 4 on x86. Passing 8 for
    // 32-bit code (as this used to do unconditionally) double-counts every
    // argument, so everything from the second stack argument onward was read
    // from the wrong address on x86 traces.
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

    //-----------------------------------------------------------------------
    // We sample at the call instruction *before* it executes, so the return
    // address has not been pushed yet: register args live in their registers and
    // stack args sit at SP + shadow space (+ preceding stack args).
    uint64_t get_int_arg(ICursorView *cursor, const tinfo_t &tinfo, size_t n, bool is64)
    {
        CROSS_PLATFORM_CONTEXT ctx = cursor->GetCrossPlatformContext();

        func_type_data_t fd;
        cm_t cc = CM_CC_UNKNOWN;
        if ( tinfo.get_func_details(&fd) )
            cc = fd.get_cc();

        if ( is64 )
        {
            const AMD64_CONTEXT &c = ctx.Amd64Context;
            if ( n < 4 )
            {
                // The MS x64 ABI assigns argument slots POSITIONALLY across two
                // parallel register files: slot n is RCX/RDX/R8/R9 for integers and
                // pointers, but XMM0-3 for float and double. Reading a float
                // argument out of the integer register (as this did unconditionally)
                // yields whatever the caller happened to leave there.
                tinfo_t arg = tinfo.get_nth_arg((int)n);
                if ( arg.is_floating() )
                {
                    const M128BIT xmm[4] = { c.Xmm0, c.Xmm1, c.Xmm2, c.Xmm3 };
                    return xmm[n].Low;
                }
                const uint64_t regs[4] = { c.Rcx, c.Rdx, c.R8, c.R9 };
                return regs[n];
            }
            // 0x20 bytes of shadow space precede the first stack argument.
            size_t off = 0x20 + stack_arg_offset(tinfo, n, 4, 8);
            uint64_t v = 0;
            read_guest(cursor, c.Rsp + off, &v, sizeof(v));
            return v;
        }

        const X86_NT5_CONTEXT &c = ctx.X86Nt5Context;
        size_t first_stack_arg = 0;
        if ( cc == CM_CC_FASTCALL )
        {
            if ( n < 2 )
            {
                const uint32_t regs[2] = { c.Ecx, c.Edx };
                return regs[n];
            }
            first_stack_arg = 2;
        }
        else if ( cc == CM_CC_THISCALL )
        {
            // 'this' travels in ECX and the rest go on the stack. Treating this
            // like cdecl (as before) shifted EVERY argument by one slot, so the
            // first stack argument was read from the second one's address.
            if ( n == 0 )
                return c.Ecx;
            first_stack_arg = 1;
        }
        // cdecl / stdcall: args on the stack, no return address pushed yet.
        size_t off = stack_arg_offset(tinfo, n, first_stack_arg, 4);
        // Read the argument at its own width, not always 4 bytes: a 64-bit
        // parameter (int64, double, a LARGE_INTEGER by value) occupies two stack
        // slots, and truncating to the low dword silently halved every one of them.
        tinfo_t arg = tinfo.get_nth_arg((int)n);
        size_t  sz  = arg.get_size();
        uint64_t v = 0;
        read_guest(cursor, (uint64_t)c.Esp + off, &v, sz == 8 ? 8 : 4);
        return v;
    }

    //-----------------------------------------------------------------------
    uint64_t get_return_value(ICursorView *cursor, bool is64)
    {
        CROSS_PLATFORM_CONTEXT ctx = cursor->GetCrossPlatformContext();
        return is64 ? (uint64_t)ctx.Amd64Context.Rax
                    : (uint64_t)ctx.X86Nt5Context.Eax;
    }

    //-----------------------------------------------------------------------
    static void cat_char(qstring *out, wchar_t c)
    {
        switch ( c )
        {
            case L'\n': out->append("\\n"); break;
            case L'\r': out->append("\\r"); break;
            case L'\t': out->append("\\t"); break;
            default:
                if ( (c >> 8) == 0 )
                    out->cat_sprnt("%c", (char)(c & 0xFF));
                else
                    out->cat_sprnt("%lc", c);
                break;
        }
    }

    //-----------------------------------------------------------------------
    // Both string readers pull the buffer in chunks rather than one character at
    // a time: at 260 characters, the per-character form cost 260 engine queries
    // for every string argument of every traced call.
    static const int kMaxStrChars = 260;

    qstring read_string_at(ICursorView *cursor, uint64_t addr)
    {
        qstring out;
        char    chunk[64];
        int     done = 0;
        while ( done < kMaxStrChars )
        {
            size_t want = (size_t)(kMaxStrChars - done);
            if ( want > sizeof(chunk) )
                want = sizeof(chunk);
            size_t got = read_guest(cursor, addr + done, chunk, want);
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

    //-----------------------------------------------------------------------
    qstring read_wstring_at(ICursorView *cursor, uint64_t addr)
    {
        qstring out;
        wchar_t chunk[64];
        int     done = 0;
        while ( done < kMaxStrChars )
        {
            size_t want = (size_t)(kMaxStrChars - done) * sizeof(wchar_t);
            if ( want > sizeof(chunk) )
                want = sizeof(chunk);
            size_t got = read_guest(cursor, addr + (uint64_t)done * sizeof(wchar_t), chunk, want);
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
