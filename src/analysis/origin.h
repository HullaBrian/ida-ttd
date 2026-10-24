#pragma once

#include "common/pch.h"
#include "core/position.h"

namespace idattd
{
    class TraceManager;

    // Where a value came from: the current rax, or the bytes at an address.
    //
    // Each hop finds the instruction that last set a register or wrote memory
    // before a position. When it only moved the value (mov, push or pop, a
    // string move, an SSE load or store), the next hop asks the same of its
    // source as it stood just before. The chain ends at a computation, at the
    // system (a syscall's result, or memory it wrote), at a constant in the
    // code, or where nothing in the recording changed the value.
    //
    // A computation from one value (lea rax, [rdi+0Dh]; inc rdi) is followed
    // through that value. One from several ends the chain; each value it read
    // (origin_inputs) starts a chain of its own, from just before it ran.

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
        // The instruction combined several values: the chain ends here and
        // continues from origin_inputs(by_pos).
        bool         combined = false;
    };

    // Follow 'what' back from the playhead, at most 'max_hops' hops, each
    // search behind a cancellable wait box. False when there is no session.
    // 'through_computations' false stops at every computation, even of a
    // single value.
    bool trace_value_origin(TraceManager *mgr, const OriginTarget &what, size_t max_hops,
                            std::vector<OriginHop> *out, bool through_computations = true);
    // The same from 'at' instead of the playhead, on the thread running there.
    bool trace_value_origin(TraceManager *mgr, const OriginTarget &what, Position at, size_t max_hops,
                            std::vector<OriginHop> *out, bool through_computations = true);

    // A value an instruction read, as it stood just before the instruction ran.
    struct OriginInput
    {
        OriginTarget what;
        bytevec_t    value;
        bool         address = false;   // a register that only formed an address
    };
    // What the instruction about to run at 'at' read: its operand registers
    // and memory (including implicit ones of mul, div, cdq, ...), then the
    // registers that formed an address (for lea, its operands). Memory is the
    // read the recording has. Empty for a syscall, an instruction that reads
    // nothing, or one that cannot be decoded. False when there is no session.
    bool origin_inputs(TraceManager *mgr, Position at, std::vector<OriginInput> *out);

    // Every chain at once, breadth first up to 'max_nodes' hops: from 'what'
    // as of 'at', and from each value read by an instruction that combined
    // several (address-only registers and the stack pointer left out). The
    // same register or memory at the same position is one node.
    struct OriginGraph
    {
        std::vector<OriginHop> nodes;   // [0] is the value asked about
        struct Edge
        {
            int  from = -1;             // the hop that used the value...
            int  to   = -1;             // ...and the hop that set it
            bool input = false;         // one of several the instruction read
        };
        std::vector<Edge> edges;
        bool truncated = false;         // inputs left unfollowed at the limit
        bool cancelled = false;
    };
    bool build_origin_graph(TraceManager *mgr, const OriginTarget &what, Position at, size_t max_nodes,
                            OriginGraph *out);
}
