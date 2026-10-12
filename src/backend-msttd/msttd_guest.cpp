#include "backend-msttd/msttd_guest.h"

using namespace TTD;
using namespace TTD::Replay;

namespace idattd
{
    GuestRead msttd_read_plain(ICursorView *cursor)
    {
        return [cursor](uint64_t addr, void *buf, size_t size) -> size_t
        {
            if ( cursor == nullptr || buf == nullptr || size == 0 )
                return 0;
            MemoryBuffer mb = cursor->QueryMemoryBuffer(GuestAddress{ addr }, BufferView{ buf, size });
            return mb.Memory.Size;
        };
    }

    // Fill buf[0..size) from guest [addr, addr+size), zero-filling anything the
    // recording cannot supply, and return how many bytes are real counting from
    // the start of the range.
    //
    // Names its policies explicitly and steps over holes: QueryMemoryBuffer stops
    // at the first unrecorded byte, so a single call would drop every recorded
    // byte past one.
    static size_t read_aggressive(ICursorView *cursor, uint64_t addr, void *buf, size_t size)
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

    GuestRead msttd_read_aggressive(ICursorView *cursor)
    {
        return [cursor](uint64_t addr, void *buf, size_t size) -> size_t
        {
            return read_aggressive(cursor, addr, buf, size);
        };
    }

    GuestView msttd_view(ICursorView *cursor, bool is64)
    {
        GuestView v;
        v.read = msttd_read_aggressive(cursor);
        v.regs = [cursor, is64](ittd_regs *out)
        {
            if ( cursor == nullptr || out == nullptr )
                return false;
            regs_from_context(cursor->GetCrossPlatformContext(), is64, out);
            return true;
        };
        return v;
    }

    void regs_from_context(const CROSS_PLATFORM_CONTEXT &ctx, bool is64, ittd_regs *out)
    {
        *out = ittd_regs{};
        if ( is64 )
        {
            const AMD64_CONTEXT &c = ctx.Amd64Context;
            const uint64_t gp[ITTD_REG_GP_COUNT] = {
                c.Rax, c.Rcx, c.Rdx, c.Rbx, c.Rsp, c.Rbp, c.Rsi, c.Rdi,
                c.R8, c.R9, c.R10, c.R11, c.R12, c.R13, c.R14, c.R15, c.Rip,
            };
            memcpy(out->gp, gp, sizeof(gp));
            out->rflags = c.EFlags;
            out->seg[ITTD_SEG_CS] = c.SegCs;
            out->seg[ITTD_SEG_SS] = c.SegSs;
            out->seg[ITTD_SEG_DS] = c.SegDs;
            out->seg[ITTD_SEG_ES] = c.SegEs;
            out->seg[ITTD_SEG_FS] = c.SegFs;
            out->seg[ITTD_SEG_GS] = c.SegGs;
            const M128BIT *xmm = &c.Xmm0;
            for ( int i = 0; i < 16; i++ )
                memcpy(out->xmm[i], &xmm[i], 16);
            out->have = ITTD_REGS_GP | ITTD_REGS_SEG | ITTD_REGS_XMM;
        }
        else
        {
            // A 32-bit context in the 64-bit slots: EAX in RAX's place, and so
            // on, which is how the core reads them back for a 32-bit target.
            const X86_NT5_CONTEXT &c = ctx.X86Nt5Context;
            out->gp[ITTD_REG_RAX] = c.Eax;
            out->gp[ITTD_REG_RCX] = c.Ecx;
            out->gp[ITTD_REG_RDX] = c.Edx;
            out->gp[ITTD_REG_RBX] = c.Ebx;
            out->gp[ITTD_REG_RSP] = c.Esp;
            out->gp[ITTD_REG_RBP] = c.Ebp;
            out->gp[ITTD_REG_RSI] = c.Esi;
            out->gp[ITTD_REG_RDI] = c.Edi;
            out->gp[ITTD_REG_RIP] = c.Eip;
            out->rflags = c.EFlags;
            out->seg[ITTD_SEG_CS] = (uint16_t)c.SegCs;
            out->seg[ITTD_SEG_SS] = (uint16_t)c.SegSs;
            out->seg[ITTD_SEG_DS] = (uint16_t)c.SegDs;
            out->seg[ITTD_SEG_ES] = (uint16_t)c.SegEs;
            out->seg[ITTD_SEG_FS] = (uint16_t)c.SegFs;
            out->seg[ITTD_SEG_GS] = (uint16_t)c.SegGs;
            out->have = ITTD_REGS_GP | ITTD_REGS_SEG;
        }
    }
}
