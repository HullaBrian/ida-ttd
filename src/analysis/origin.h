#pragma once

#include "common/pch.h"
#include "core/position.h"

namespace idattd
{
    class TraceManager;

    // Where a value came from: "where did the current value of rax come
    // from?", "where did the bytes at this address come from?".
    //
    // Each hop finds the instruction that last set a register or wrote some
    // memory before a position. When that instruction only moved the value --
    // a mov, a push or pop, a string move, an SSE load or store -- the next hop
    // asks the same of its source, as it stood just before that instruction
    // ran. The chain ends at an instruction that computed the value, at the
    // system (a syscall's result, or memory the system wrote), at a constant
    // in the code, or where nothing in the recording changed it.
    //
    // Where it ends at a computation, the walk goes on by hand: the values the
    // instruction read (origin_inputs) are each a chain of their own, from
    // just before it ran.

    // A register or a range of memory, as of some position.
    struct OriginTarget
    {
        bool     is_reg = true;
        uint32_t reg  = 0;              // ITTD_REG_*, or ITTD_ORIGIN_XMM0 + n
        ea_t     addr = BADADDR;        // memory
        uint32_t size = 8;
    };
    qstring origin_target_text(const OriginTarget &t);   // "rax", "xmm0", "[0x1234], 8 bytes"
    // A value read back: "0x1234" up to 8 bytes, hex bytes above.
    qstring origin_value_text(const bytevec_t &v);
    // "rax", "eax" (as rax), "xmm3", "r12"; false for anything else.
    bool parse_register(const char *name, uint32_t *reg);

    enum class OriginKind
    {
        Copied,         // moved from somewhere else: the next hop follows it
        Computed,       // an instruction made the value: the chain ends there
        Constant,       // an immediate in the code
        System,         // a syscall's result, or memory the system wrote
        Unchanged,      // nothing in the searched span changed it
        Failed,
        Cancelled,
    };
    const char *origin_kind_name(OriginKind k);

    struct OriginHop
    {
        OriginTarget what;
        Position     at;                // the value asked about is as of here
        uint32_t     tid = 0;
        bytevec_t    value;             // its bytes there

        OriginKind   kind = OriginKind::Failed;
        Position     by_pos;            // the instruction that set it, before it ran
        ea_t         by_pc = BADADDR;
        uint32_t     by_tid = 0;
        qstring      insn;              // that instruction's disassembly
        qstring      note;              // in words: "copied from rsi", "written by NtReadFile"
    };

    // Follow 'what' back from the playhead, at most 'max_hops' hops. Each hop's
    // search runs behind a cancellable wait box. False when there is no
    // session.
    bool trace_value_origin(TraceManager *mgr, const OriginTarget &what, size_t max_hops,
                            std::vector<OriginHop> *out);
    // The same from 'at' instead of the playhead, on the thread running there.
    bool trace_value_origin(TraceManager *mgr, const OriginTarget &what, Position at, size_t max_hops,
                            std::vector<OriginHop> *out);

    // A value an instruction read, as it stood just before the instruction ran.
    struct OriginInput
    {
        OriginTarget what;
        bytevec_t    value;
        bool         address = false;   // a register that only formed an address
    };
    // What the instruction about to run at 'at' read: the registers and
    // memory it took operands from (the implicit ones of mul, div, cdq and
    // the like included), then the registers that formed an address it read
    // or wrote (for lea, those are its operands). Memory is the read the
    // recording has. Empty for a syscall, or an instruction that reads
    // nothing, or one that cannot be decoded. False when there is no session.
    bool origin_inputs(TraceManager *mgr, Position at, std::vector<OriginInput> *out);
}
