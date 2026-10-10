#pragma once

#include "common/pch.h"
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
    //      no exception table -- replay a short window around the position and
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
        void bind(TTD::Replay::IReplayEngine *engine, ModuleRegistry *modules,
                  MemoryReader *memory, bool is64);
        void reset();

        // The per-stop pipeline, for the function 'playhead' is standing in at
        // 'pc'.
        void on_stop(TTD::Replay::ICursorView *playhead, ea_t pc);

        // Walk the trace backward from 'playhead' to find the entry of the
        // function it is executing in, and define the whole thing. Expensive --
        // a per-instruction backward replay -- so it runs behind a cancellable
        // wait box and is never automatic.
        void analyze_whole_function(TTD::Replay::ICursorView *playhead);

    private:
        // Cheap, replay-free disassembly of the function at 'pc' (step 1-2
        // above), falling back to the window walk for dynamic code.
        void  analyze_current_function(TTD::Replay::ICursorView *playhead, ea_t pc);
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
        void  define_callees(TTD::Replay::ICursorView *playhead, ea_t lo, ea_t hi);
        // Define a single function at 'ea', preferring the authoritative .pdata
        // bounds of its module and marking library code FUNC_LIB. No-op when
        // 'ea' is already the start of a function.
        void  define_function_at(ea_t ea);
        // Where a call instruction transfers to: the operand for a direct call,
        // or the pointer stored at the slot for an indirect call through memory
        // (an import thunk's IAT entry). The latter only works because this is
        // a replay -- the IAT holds its real, resolved value at the current
        // position. BADADDR when it cannot be determined statically, i.e. a
        // call through a register.
        ea_t  call_target_of(TTD::Replay::ICursorView *playhead,
                             const insn_t &insn, ea_t &slot_out);
        // For runtime-allocated code with no module and no .pdata: replay a
        // window around the current position and lay out the instructions that
        // really executed around 'pc'.
        void  lay_out_window(TTD::Replay::ICursorView *playhead, ea_t pc);
        // Forward-replay a window around the current position and collect this
        // thread's executed instruction addresses near 'pc' -- the shared
        // engine behind lay_out_window and find_dynamic_start.
        void  collect_window_pcs(TTD::Replay::ICursorView *playhead, ea_t pc,
                                 std::set<ea_t> &pcs);
        // Best guess at the start of the function containing 'pc' in dynamic
        // code: the lowest executed address contiguous by instruction with pc,
        // so a recursive-descent add_func() there lays out the prologue above
        // it too.
        ea_t  find_dynamic_start(TTD::Replay::ICursorView *playhead, ea_t pc);
        // The true head of the function the current position is executing in,
        // recovered from the recording's call/return structure: replay forward
        // over a look-back window tracking a per-thread call-frame stack, and
        // the top frame on arrival is the call that entered this one. BADADDR
        // when no enclosing call was captured -- a thread entry, jmp-based
        // shellcode, or a call older than the window -- so the caller can fall
        // back.
        ea_t  find_dynamic_function_entry(TTD::Replay::ICursorView *playhead, ea_t pc);

        // The scratch cursor the window walks replay on, created on first use.
        //
        // It must replay segments sequentially. The engine's default is to
        // replay several at once and dispatch callbacks from all of those
        // threads, and find_dynamic_function_entry's call/return callback
        // mutates an unsynchronized map -- the default would corrupt the heap.
        // Sequential replay also makes the walk chronological, which it needs.
        TTD::Replay::ICursorView *scratch();

        TTD::Replay::IReplayEngine *m_engine  = nullptr;
        ModuleRegistry             *m_modules = nullptr;
        MemoryReader               *m_memory  = nullptr;
        bool                        m_is64    = false;

        TTD::Replay::UniqueCursor   m_scratch;

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
