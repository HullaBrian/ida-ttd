#pragma once

#include "common/pch.h"
#include "core/backend.h"
#include "debugger/memory_reader.h"
#include "debugger/module_registry.h"
#include "debugger/kept_functions.h"

namespace idattd
{
    // Lay [lo, hi) out as code in one linear pass, skipping existing code and
    // stepping a byte over what does not decode (jump tables, other embedded
    // data). Bounded, so a corrupt range cannot stall a stop. Also what
    // KeptFunctions lays kept bounds out with.
    void lay_out_linear(ea_t lo, ea_t hi);

    // Turning the code a recording executed into disassembly IDA can show.
    //
    // A recording contains code the binary does not: packed, injected and JIT
    // code exists only at runtime, and the recording is often its only
    // artifact. IDA's static analysis has nothing to work from there.
    //
    // The per-stop pipeline (on_stop) runs on every step, so it must not walk
    // the trace far. In order:
    //
    //   0. Re-read a module's exception table read from recorded memory when
    //      it does not cover the stop (a packer writes it when it unpacks).
    //   1. If IDA has a function at the stop address, grow it to the end its
    //      module's exception table gives (static analysis stops where it
    //      loses the flow, and the rest renders as a jump to nowhere), or
    //      refit it to the table entry it is a fragment of.
    //   2. Otherwise define the function from the module's .pdata bounds,
    //      which locate every x64 function with or without symbols.
    //   3. Failing that (dynamic code, with no module or exception table),
    //      join a function cut off at a loop head back to the one that runs
    //      into it, and grow a function over code it runs into; else find the
    //      frame's entry from the recording (bounded
    //      query_frame_entry) or a short window of this thread's instruction
    //      stream, and let IDA's recursive descent lay the function out, so
    //      code is disassembled in both directions.
    //   4. Define the functions called directly from what was laid out, one
    //      level deep, so call targets read as names instead of "call unk_".
    //
    // analyze_whole_function is the expensive version, on request only: it
    // walks the trace back to the enclosing function's real entry.
    class CodeAnalyzer
    {
    public:
        void bind(ITraceBackend *backend, ModuleRegistry *modules,
                  MemoryReader *memory, KeptFunctions *kept, bool is64);
        void reset();

        // The per-stop pipeline, for the function 'playhead' is standing in at
        // 'pc'.
        void on_stop(ITraceCursor *playhead, ea_t pc);

        // Find the call that entered the frame 'playhead' is in, lay out every
        // instruction the frame executed since, and define the function.
        // Expensive (up to 50,000 instructions of a thread's stream), so it
        // runs behind a cancellable wait box and never automatically.
        void analyze_whole_function(ITraceCursor *playhead);

    private:
        // Steps 1-4 above for the function at 'pc'.
        void  analyze_current_function(ITraceCursor *playhead, ea_t pc);
        // Grow a function IDA defined too short to the end its module's
        // exception table gives. Only grows, only into space no other function
        // claims, and once per function.
        void  extend_to_pdata_bounds(ea_t pc, const func_entry_info_t &fi);
        // Code without an exception table: a function the one before it falls
        // straight into is a fragment of it (a start guessed at a loop head),
        // so the two become one. The merged function's
        // start, or BADADDR.
        ea_t  merge_fragment(ITraceCursor *playhead, ea_t pc, const func_entry_info_t &fi);
        // A function that starts inside an exception table entry without
        // being one, redefined to the entry's bounds. Its start, or BADADDR.
        ea_t  fit_to_table(ea_t pc, const func_entry_info_t &fi, ea_t seg_end);
        // Likewise, code no function owns that the function before it falls
        // into: that function is laid out again to cover it.
        ea_t  extend_into(ITraceCursor *playhead, ea_t pc, ea_t seg_start);
        // The function at 'head', and the one at 'drop' merged in, laid out
        // again by recursive descent; kept only if it then covers 'pc'.
        ea_t  redefine_from(ea_t head, ea_t drop, ea_t pc);
        // Define every function called directly from [lo, hi), one level deep.
        // The session runs with AF_PROC/AF_PROCPTR off, the rule that would
        // create a function at each call target; doing it here one level at a
        // time names callees without the runaway cascade those flags caused.
        void  define_callees(ITraceCursor *playhead, ea_t lo, ea_t hi);
        // Define one function at 'ea', preferring its module's .pdata bounds
        // and marking library code FUNC_LIB. No-op when 'ea' already starts a
        // function. False when 'ea' is not mapped yet, so the caller can retry.
        bool  define_function_at(ea_t ea);
        // Where a call goes: the operand of a direct call, or the pointer in
        // the slot of an indirect call through memory (an IAT entry, which in
        // a replay holds its resolved value at the current position). BADADDR
        // when it cannot be known statically (a call through a register).
        ea_t  call_target_of(ITraceCursor *playhead,
                             const insn_t &insn, ea_t &slot_out);
        // For dynamic code with no module and no .pdata: lay out the
        // instructions that executed around 'pc', from a window of the
        // thread's instruction stream.
        void  lay_out_window(ITraceCursor *playhead, ea_t pc);
        // This thread's executed addresses near 'pc', from a window of its
        // instruction stream starting a little before the current position.
        // Shared by lay_out_window and find_dynamic_start.
        void  collect_window_pcs(ITraceCursor *playhead, ea_t pc,
                                 std::set<ea_t> &pcs);
        // Best guess at the start of dynamic code's function containing 'pc':
        // the lowest executed address contiguous by instruction with pc, so a
        // recursive-descent add_func() there also lays out the prologue.
        ea_t  find_dynamic_start(ITraceCursor *playhead, ea_t pc);
        // The head of the function the current position is in, from the
        // backend's bounded query_frame_entry (the call that entered this
        // frame), else the return address on the stack. BADADDR when neither
        // finds it (a thread entry, jmp-based shellcode), so the caller can
        // fall back.
        ea_t  find_dynamic_function_entry(ITraceCursor *playhead, ea_t pc);
        // find_dynamic_function_entry's fallback: the return address on the
        // stack, for a call older than the bound.
        ea_t  stack_scan_entry(ITraceCursor *playhead, ea_t pc);

        ITraceBackend              *m_backend = nullptr;
        ModuleRegistry             *m_modules = nullptr;
        MemoryReader               *m_memory  = nullptr;
        KeptFunctions              *m_kept    = nullptr;
        bool                        m_is64    = false;

        ea_t m_winLo = BADADDR;          // last laid-out window range
        ea_t m_winHi = 0;
        // Start of the function whose callees were last defined: stepping
        // inside one function finds nothing new until the function changes.
        ea_t m_calleeScanFunc = BADADDR;
        // Functions already considered for .pdata extension, so the check is
        // paid once per function.
        std::set<ea_t> m_pdataExtended;
        // Functions merge_fragment refused, so the check is paid once.
        std::set<ea_t> m_fragmentChecked;
        // Functions defined in dynamic code, start_ea -> hash of their bytes
        // at definition. Detects rewritten or reused regions (including a
        // travel to a position where the bytes differ) so they are
        // disassembled again.
        std::map<ea_t, uint64_t> m_dynFuncBytes;
        // Dynamic-code PCs where add_func made no function, pc -> hash of the
        // bytes there, so later stops skip the frame query and rebuild that
        // would fail the same way. Cleared with the session.
        std::map<ea_t, uint64_t> m_failedDyn;
    };
}
