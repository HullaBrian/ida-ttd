#pragma once

#include "pch.h"
#include "event_queue.h"

namespace idattd
{
    class Plugin; // forward decl (set_plugin)

    // Error sink so the TTD engine can report diagnostics into IDA's output.
    class IdaErrorReporting : public TTD::ErrorReporting
    {
    public:
        void __fastcall VPrintError(char const *pFmt, va_list argList) override;
    };

    // Owns the TTD replay engine + cursor and translates IDA debugger events
    // (ev_*) into trace navigation, register/memory queries and IDA debug
    // events. One instance lives for the lifetime of the plugin.
    class TraceManager
    {
    public:
        struct NamedPosition
        {
            std::string   name;
            TTD::Replay::Position pos;
        };

        TraceManager();

        void set_plugin(Plugin *p) { m_plugin = p; }
        bool is_active() const { return (bool)m_cursor; }

        // ---- IDA debugger event handlers (return drc_t in an ssize_t) ------
        ssize_t on_init();
        ssize_t on_term();
        ssize_t on_get_processes(procinfo_vec_t *procs);
        ssize_t on_get_debapp_attrs(debapp_attrs_t *attrs);
        ssize_t on_start_process(const char *path, const char *input_path, qstring *errbuf);
        ssize_t on_get_debug_event(gdecode_t *code, debug_event_t *event, int timeout_ms);
        ssize_t on_read_memory(size_t *nbytes, ea_t ea, void *buffer, size_t size);
        ssize_t on_get_memory_info(meminfo_vec_t *ranges);
        ssize_t on_read_registers(thid_t tid, int clsmask, regval_t *values);
        ssize_t on_rebase_if_required_to(ea_t new_base);
        ssize_t on_resume(debug_event_t *event);
        ssize_t on_set_backwards(bool backwards);
        ssize_t on_set_resume_mode(thid_t tid, resume_mode_t resmod);
        ssize_t on_update_bpts(int *nbpts, update_bpt_info_t *bpts, int nadd, int ndel);
        ssize_t on_exit_process();

        // ---- UI helpers ----------------------------------------------------
        void                       set_next_position(const TTD::Replay::Position &p);
        void                       goto_position();
        void                       request_backward_step();
        void                       request_single_step(bool forward);
        void                       request_run(bool forward);
        void                       request_step_out_backward();
        TTD::Replay::Position              current_position() const;
        std::vector<NamedPosition> collect_positions() const;

        // Create a fresh cursor over the loaded trace (empty if no trace). Used
        // by the function tracer for independent sweeps.
        TTD::Replay::UniqueCursor  make_cursor();
        bool                       is64() const { return m_is64; }

        // Resolve a name pattern to the set of matching function addresses.
        // Supports shell-style wildcards (* and ?), case-insensitive, with an
        // optional "module!" qualifier, e.g. "kernel32!Virtual*" or "*Alloc".
        std::vector<ea_t>          resolve_function_pattern(const char *pattern) const;

        // Apply offline export-symbol names for the module loaded at 'base',
        // reading its PE at the module's recorded load position. Deduplicated:
        // a given base is only attempted once per trace.
        void                       resolve_symbols(ea_t base, bool is64);

        // Silently drive IDA's PDB plugin to load symbols for the module at
        // 'base' (no per-module "load symbols?" prompt). Deduplicated per module.
        void                       load_module_pdb(ea_t base);

        // Called once per stop (from HT_DBG dbg_suspend_process), when the
        // debugger memory cache is valid for the new position: name exports for
        // any newly-seen module and disassemble a run of code around RIP.
        void                       on_suspended();

        // Explicit, user-triggered deep analysis: walk the trace backward from the
        // current position to find the enclosing function's entry and define the
        // whole function. Expensive (per-step backward replay), so it runs behind
        // a cancellable wait box — never automatically.
        void                       analyze_whole_function();

    private:
        thid_t                     current_tid() const;
        ea_t                       program_counter() const;
        std::map<uint32_t, thid_t> snapshot_threads() const;
        std::set<const TTD::Replay::Module *> snapshot_modules() const;
        TTD::Replay::EventType navigate_steps(bool forward, TTD::Replay::StepCount steps);
        // Forward step-over (step_out=false) / step-out (step_out=true), honoring
        // user breakpoints. Returns EventType::MemoryWatchpoint if a breakpoint
        // was hit during the run, otherwise a normal-stop reason.
        TTD::Replay::EventType navigate_over(bool step_out);
        // Run backward until the current function is exited (we reach the call
        // that entered this frame), honoring user breakpoints. Shows a cancellable
        // wait box because it single-steps backward.
        TTD::Replay::EventType navigate_out_backward();
        // Run forward to 'addr' on thread 'utid' with SP >= min_sp (skips deeper
        // recursion); also stops on any user breakpoint. Returns 0=reached addr,
        // 1=user breakpoint, 2=trace boundary.
        int   run_to_addr_guarded(ea_t addr, uint64_t min_sp, uint32_t utid);
        void  navigate_to(const TTD::Replay::Position &p);
        // Record a stop (breakpoint when !is_step, single-step otherwise) at the
        // cursor's current PC, and queue code creation there so runtime-revealed
        // code is disassembled as a whole block rather than one insn at a time.
        void  emit_stop(bool is_step);
        void  apply_differences(const std::map<uint32_t, thid_t> &threads_before,
                                const std::map<uint32_t, thid_t> &threads_after,
                                const std::set<const TTD::Replay::Module *> &mods_before,
                                const std::set<const TTD::Replay::Module *> &mods_after);
        bool  is_target_module(const TTD::Replay::Module &m) const;
        void  emit_module_load(const TTD::Replay::Module &m);
        void  resolve_loaded_modules();   // resolve exports for every loaded module
        // Cheap, replay-free disassembly of the function at 'pc'. Prefers the
        // module's .pdata bounds (whole function at once); falls back to linear
        // forward layout. Runs on every stop; must not walk the trace.
        void  analyze_current_function(ea_t pc);
        // Look up the [start,end) of the function containing 'pc' from the cached
        // .pdata ranges of its module. Returns false if unknown (x86, no .pdata).
        bool  function_range_at(ea_t pc, ea_t &start, ea_t &end) const;
        // For runtime-allocated code with no module/.pdata (shellcode, unpacked):
        // seek a scratch cursor a little before the current position and replay
        // FORWARD (cheap), laying out the real executed instructions around PC so
        // a window of code is disassembled in both directions, not one at a time.
        void  lay_out_window(ea_t pc);

    private:
        Plugin           *m_plugin = nullptr;
        IdaErrorReporting m_err;

        TTD::Replay::UniqueReplayEngine m_engine;
        TTD::Replay::UniqueCursor       m_cursor;

        TTD::Replay::UniqueCursor       m_symCursor; // scratch cursor for symbol reads
        TTD::Replay::UniqueCursor       m_anaCursor; // scratch cursor for forward window walks
        ea_t                            m_winLo = BADADDR; // last laid-out window range
        ea_t                            m_winHi = 0;
        std::set<ea_t>                  m_resolvedBases; // modules whose exports we've named
        std::set<ea_t>                  m_pdbBases;      // modules whose PDB we've requested
        // Per-module function bounds from the PE exception table (.pdata), keyed
        // by module base; each vector is sorted by start address.
        std::map<ea_t, std::vector<std::pair<ea_t, ea_t>>> m_funcRanges;

        EventQueue   m_events;
        bool         m_is64 = false;
        bool         m_isForward = true;
        bool         m_backwardSingleStep = false;
        bool         m_forwardSingleStep = false;
        bool         m_runOnce = false;
        bool         m_runForward = true;
        bool         m_stepOutBackward = false;
        resume_mode_t m_resumeMode = RESMOD_NONE;
        int          m_activeBpts = 0;

        pid_t         m_pid = 1;
        TTD::Replay::Position m_nextPosition;
        bool          m_hasNextPosition = false;

        std::string m_targetName; // file name of the analyzed binary (for rebase)
    };
}
