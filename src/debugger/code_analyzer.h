#pragma once

#include "common/pch.h"
#include "core/backend.h"
#include "debugger/memory_reader.h"
#include "debugger/module_registry.h"

namespace idattd
{
    // Turning the code a recording executed into disassembly IDA can show.
    //
    // This is the part of the plugin that exists because a recording contains
    // code the binary does not: packed, injected and JIT-generated code only
    // exists at runtime, and a recording of it is often the only artifact
    // there is. IDA's own static analysis has nothing to work from there.
    //
    // The per-stop pipeline (on_stop) runs on every single step, so it must
    // never walk the trace. In order:
    //
    //   1. If IDA already has a function at the stop address, grow it to the
    //      end its module's exception table gives it -- static analysis stops
    //      where it loses the flow, and the rest renders as a jump to nowhere.
    //   2. Otherwise define the function from the module's .pdata bounds, which
    //      know where every x64 function starts with or without symbols.
    //   3. Failing that -- dynamically allocated code, which has no module and
    //      no exception table -- read a short window of this thread's
    //      instruction stream around the position (query_instructions) and
    //      lay out the instructions that actually ran, so a window of code is
    //      disassembled in both directions rather than one instruction at a
    //      time.
    //   4. Define the functions directly called from whatever was laid out, one
    //      level deep, so call targets read as names instead of "call unk_".
    //
    // analyze_whole_function is the expensive, explicitly-asked-for version:
    // it walks the trace backward to find the enclosing function's real entry.
    // The per-stop pipeline never does that.
    class CodeAnalyzer
    {
    public:
        void bind(ITraceBackend *backend, ModuleRegistry *modules,
                  MemoryReader *memory, bool is64);
        void reset();

        // The per-stop pipeline, for the function 'playhead' is standing in at
        // 'pc'.
        void on_stop(ITraceCursor *playhead, ea_t pc);

        // Find the call that entered the frame 'playhead' is in, lay out every
        // instruction the frame executed since, and define the function.
        // Expensive -- up to 50,000 instructions of a thread's stream -- so it
        // runs behind a cancellable wait box and is never automatic.
        void analyze_whole_function(ITraceCursor *playhead);

    private:
        // Cheap, replay-free disassembly of the function at 'pc' (step 1-2
        // above), falling back to the window walk for dynamic code.
        void  analyze_current_function(ITraceCursor *playhead, ea_t pc);
        // Grow a function IDA defined too short to the end its module's
        // exception table gives it. Only ever grows, only into space no other
        // function claims, and once per function.
        void  extend_to_pdata_bounds(ea_t pc, const func_entry_info_t &fi);
        // Define every function directly called from [lo, hi) -- one level
        // deep, no recursion into their callees. The session runs with
        // AF_PROC/AF_PROCPTR off, which is exactly the auto-analysis rule that
        // would otherwise create a function at a call target; doing it here one
        // level at a time gives named callees without the runaway cascade that
        // made those flags unusable.
        void  define_callees(ITraceCursor *playhead, ea_t lo, ea_t hi);
        // Define a single function at 'ea', preferring the authoritative .pdata
        // bounds of its module and marking library code FUNC_LIB. No-op when
        // 'ea' is already the start of a function.
        // False when 'ea' is not mapped yet, so the caller can try again later.
        bool  define_function_at(ea_t ea);
        // Where a call instruction transfers to: the operand for a direct call,
        // or the pointer stored at the slot for an indirect call through memory
        // (an import thunk's IAT entry). The latter only works because this is
        // a replay -- the IAT holds its real, resolved value at the current
        // position. BADADDR when it cannot be determined statically, i.e. a
        // call through a register.
        ea_t  call_target_of(ITraceCursor *playhead,
                             const insn_t &insn, ea_t &slot_out);
        // For runtime-allocated code with no module and no .pdata: lay out the
        // instructions that really executed around 'pc', from a window of the
        // thread's instruction stream.
        void  lay_out_window(ITraceCursor *playhead, ea_t pc);
        // This thread's executed instruction addresses near 'pc', from a window
        // of its instruction stream starting a little before the current
        // position -- what lay_out_window and find_dynamic_start share.
        void  collect_window_pcs(ITraceCursor *playhead, ea_t pc,
                                 std::set<ea_t> &pcs);
        // Best guess at the start of the function containing 'pc' in dynamic
        // code: the lowest executed address contiguous by instruction with pc,
        // so a recursive-descent add_func() there lays out the prologue above
        // it too.
        ea_t  find_dynamic_start(ITraceCursor *playhead, ea_t pc);
        // The true head of the function the current position is executing in,
        // recovered from the recording's call/return structure: the backend's
        // query_frame_entry, bounded, gives the call that entered this frame
        // and the entry it went to. BADADDR
        // when no enclosing call was captured -- a thread entry, jmp-based
        // shellcode, or a call older than the window -- so the caller can fall
        // back.
        ea_t  find_dynamic_function_entry(ITraceCursor *playhead, ea_t pc);

        ITraceBackend              *m_backend = nullptr;
        ModuleRegistry             *m_modules = nullptr;
        MemoryReader               *m_memory  = nullptr;
        bool                        m_is64    = false;

        ea_t m_winLo = BADADDR;          // last laid-out window range
        ea_t m_winHi = 0;
        // Start of the function whose callees were last defined. Stepping
        // inside one function re-enters the pipeline on every stop, and there
        // is nothing new to find until the function itself changes.
        ea_t m_calleeScanFunc = BADADDR;
        // Functions already considered for .pdata extension, so the check is
        // paid once rather than on every stop inside the same function.
        std::set<ea_t> m_pdataExtended;
        // Functions defined in dynamic (non-module) code, start_ea -> byte hash
        // at definition time. Detects self-modifying or reused regions --
        // including time travel to a position where the bytes differ -- so they
        // can be disassembled again.
        std::map<ea_t, uint64_t> m_dynFuncBytes;
    };
}
