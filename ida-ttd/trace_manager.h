#pragma once

#include "pch.h"
#include "event_queue.h"
#include "symbols.h"
#include "trace_open.h"
#include "memmap.h"

namespace idattd
{
    class Plugin; // forward decl (set_plugin)

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
        // Run the trace BACKWARD until execution reaches 'addr' (or a user
        // breakpoint, or the start of the trace) -- our own "run to cursor
        // backwards". IDA greys out its native ThreadRunToCursorBackwards for this
        // backend, so we drive it ourselves like Continue/Step-out backwards.
        void                       request_run_to_cursor_backward(ea_t addr);
        // Run the trace FORWARD until execution reaches 'addr' (or a user
        // breakpoint, or the end of the trace) -- our own "run to cursor". IDA's
        // native ThreadRunToCursor intermittently fails on this read-only backend
        // (it tries to plant a real/source breakpoint), so we drive it ourselves
        // with a temporary Execute watchpoint, like the backward variant.
        void                       request_run_to_cursor_forward(ea_t addr);
        TTD::Replay::Position              current_position() const;
        // The instruction the cursor is standing on. Bookmarks record this so the
        // list can show where each mark is without seeking to every row.
        ea_t                       current_pc_ea() const;
        // Loaded module containing 'ea', as [lo, hi). False when 'ea' belongs to
        // no module (dynamically allocated code).
        bool                       module_range_at(ea_t ea, ea_t &lo, ea_t &hi) const;
        // Name of the module containing 'ea', without directory or extension
        // ("kernel32"), or empty when 'ea' is in no module.
        qstring                    module_name_at(ea_t ea) const;
        // Same, but keeping the extension and made safe to use as an IDA name
        // ("kernel32_dll"). Used to name the segment a memory region maps to.
        qstring                    module_ident_at(ea_t ea) const;
        // Every loaded module as [lo, hi), sorted by base.
        std::vector<std::pair<ea_t, ea_t>> module_ranges() const;

        // [start, end) of the function containing 'pc', from the exception
        // table of its module. This is the authority on where a function in a
        // system DLL begins, with or without symbols -- x64 unwinding requires
        // the table, so every module carries one. False for x86 modules, for a
        // module whose table has not been read, and for addresses outside any
        // recorded function. Populated as a side effect of resolve_symbols().
        bool function_range_at(ea_t pc, ea_t &start, ea_t &end) const;

        // One load of one module: where it went, how big it was, its base name,
        // and the position at which the trace saw it mapped. That last field is
        // what makes reading a module's own headers or export table possible --
        // they can only be read at a position where the module exists.
        struct ModuleLoad
        {
            ea_t     base = BADADDR;
            uint64_t size = 0;
            qstring  name;                    // base name, as recorded
            TTD::Replay::Position pos;        // where it was loaded
        };
        // Every module LOAD in the trace, in load order. A module loaded twice at
        // the same address appears twice, which is deliberate: each load needs
        // its own read position.
        std::vector<ModuleLoad> module_loads() const;

        // Identity of the loaded recording, so something cached in the database
        // against one trace is not shown against another. Zero with no trace.
        uint64_t trace_fingerprint() const;

        // The recording's reconstructed memory map. Empty until a sweep has been
        // run (or a saved one loaded), in which case the debugger's memory layout
        // is the single flat range it has always been.
        // Non-const on purpose: any caller that can change the map invalidates
        // the folded layout cached below, and doing that here means no call site
        // can forget to.
        MemoryMap &memmap() { m_foldValid = false; return m_memmap; }
        // Tell IDA to re-read the memory layout, if the regions in force at the
        // current position differ from the ones it was last given. Called on
        // every stop: time travel can change the map underneath it.
        void refresh_memory_layout();
        // Last position of the loaded trace (Position::Invalid with no trace).
        // Used to turn a replay progress position into a percentage.
        TTD::Replay::Position              last_position() const;
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

        // True if 'ea' is inside a loaded module OTHER than the analyzed binary
        // (module 0) -- i.e. library/system code. Used to mark library functions
        // FUNC_LIB as their PDB/export names are applied.
        bool                       is_library_address(ea_t ea) const;

        // Explicit, user-triggered deep analysis: walk the trace backward from the
        // current position to find the enclosing function's entry and define the
        // whole function. Expensive (per-step backward replay), so it runs behind
        // a cancellable wait box -- never automatically.
        void                       analyze_whole_function();

    private:
        // Compose the memory layout IDA should see at the current position
        // from the reconstructed map (see on_get_memory_info).
        void   build_memory_layout(meminfo_vec_t *out) const;
        thid_t                     current_tid() const;
        ea_t                       program_counter() const;
        std::map<uint32_t, thid_t> snapshot_threads() const;
        std::set<const TTD::Replay::Module *> snapshot_modules() const;
        TTD::Replay::EventType navigate_steps(bool forward, TTD::Replay::StepCount steps);
        // Forward step-over (step_out=false) / step-out (step_out=true), honoring
        // user breakpoints. Returns EventType::MemoryWatchpoint if a breakpoint
        // was hit during the run, otherwise a normal-stop reason.
        TTD::Replay::EventType navigate_over(bool step_out);
        // Backward step-over: one backward step, and if that landed us inside a
        // callee that had just returned (deeper frame on the same thread), rewind
        // on out to the call that entered it. IDA has no RESMOD_BACKOVER -- it
        // sends ev_set_backwards plus RESMOD_OVER -- and that path previously took
        // a plain backward step, i.e. it stepped INTO the returning callee.
        TTD::Replay::EventType navigate_over_backward();
        // Run backward until the current function is exited (we reach the call
        // that entered this frame), honoring user breakpoints.
        TTD::Replay::EventType navigate_out_backward();
        // Position of the CALL that entered the frame the cursor is currently in.
        //
        // Found by replaying FORWARD from a look-back start up to the playhead
        // while tracking a per-thread frame stack, which is one bulk engine call
        // per attempt. The obvious implementation -- single-step backward counting
        // call/ret depth -- is what this replaces: every backward step re-seeks a
        // keyframe, so stepping out of a frame entered a few thousand instructions
        // ago took minutes and pegged the "depth N" counter climbing forever.
        //
        // The look-back widens across sequences until the entering call is
        // captured; 'cancelled' distinguishes "the user gave up" from "the call is
        // further back than we are willing to search".
        bool  find_frame_entry_position(TTD::Replay::Position &out, bool &cancelled);
        // Seek the main cursor BACKWARD to 'p' in one engine call, with user
        // breakpoints still armed so anything in between still stops us.
        TTD::Replay::EventType rewind_to(const TTD::Replay::Position &p);
        // Run backward to 'addr' (a temporary Execute watchpoint + ReplayBackward),
        // stopping at the first earlier execution of 'addr' or any user breakpoint.
        // One ReplayBackward call (the engine seeks to the hit), so it is cheap --
        // unlike a backward single-step loop.
        TTD::Replay::EventType navigate_backward_to(ea_t addr);
        // Run forward to 'addr' (a temporary Execute watchpoint + ReplayForward),
        // stopping at the next execution of 'addr' or any user breakpoint. If the
        // cursor is already sitting on 'addr', a single step is taken first so we
        // advance to the NEXT occurrence rather than matching the current one.
        TTD::Replay::EventType navigate_forward_to(ea_t addr);
        // After a navigation that stopped on its own (not at a user breakpoint),
        // flag a pending "start/end of the trace" notice if the cursor came to rest
        // on the trace's first/last position. Shown (once) from on_suspended, where
        // a modal popup is safe -- not from inside the resume handler.
        void  settle_after_navigation(TTD::Replay::EventType sr, bool forward);
        // Pull the cursor back inside [GetFirstPosition(), GetLastPosition()].
        //
        // A forward run to the end does NOT leave the cursor on the last recorded
        // instruction -- it leaves it past the end, at the Position::Max sentinel
        // the replay was limited by. Every subsequent operation then works from a
        // position that does not exist in the trace: a single backward step ran to
        // the very beginning instead of moving one instruction, and the frame
        // search subtracted its look-back window from a sequence number far beyond
        // the trace, so every window landed past the end and found nothing.
        // Clamping after each navigation keeps the playhead on a real position.
        void  clamp_to_trace();
        // Run forward to 'addr' on thread 'utid' with SP >= min_sp (skips deeper
        // recursion); also stops on any user breakpoint. Returns 0=reached addr,
        // 1=user breakpoint, 2=trace boundary.
        int   run_to_addr_guarded(ea_t addr, uint64_t min_sp, uint32_t utid);
        // Install a temporary 1-byte Execute watchpoint at 'addr' for a step/run
        // operation, filling 'wp'. TTD keys watchpoints by (address, size, mask,
        // thread), so an identical user breakpoint is the SAME watchpoint: adding
        // and then removing ours would delete theirs. Returns true only when we
        // actually created one -- i.e. when the caller owns its removal.
        bool  add_temp_exec_watchpoint(ea_t addr, TTD::Replay::MemoryWatchpointData &wp);
        // Counterpart to add_temp_exec_watchpoint: removes 'wp' only if we own it.
        void  drop_temp_exec_watchpoint(const TTD::Replay::MemoryWatchpointData &wp, bool owned);
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
        // Find the on-disk image of the module containing 'ea' (loading + caching it
        // on first use). Returns nullptr if 'ea' is in no module or the file is
        // unavailable; on success 'base_out' is the module's runtime base so the
        // caller can form rva = ea - base. Used to serve never-recorded bytes.
        const ModuleImage *image_for(ea_t ea, ea_t &base_out);
        // The engine's Module record for the module based at 'base', or nullptr.
        // (Several call sites used to open-code this linear scan.)
        const TTD::Replay::Module *module_at(ea_t base) const;
        // Lazily create the scratch analysis cursor. It MUST replay segments
        // sequentially: the default is parallel multi-segment replay, which
        // dispatches callbacks from several threads at once, and the call/return
        // callback in find_dynamic_function_entry mutates an unsynchronized map.
        TTD::Replay::ICursorView *ana_cursor();
        // Reconstruct the real bytes of [lo,hi) from the trace's recorded WRITES.
        // The position-based memory query returns zero-fill for non-module memory
        // that was written earlier (e.g. an unpacker decompressing a beacon) but not
        // executed at the current position. We replay forward to the current
        // position with a Write watchpoint over [lo,hi), capturing the latest written
        // value of each byte (this is how WinDbg shows those bytes). Cached; served
        // by on_read_memory. Returns true if any byte was recovered.
        bool  reconstruct_region(ea_t lo, ea_t hi);
        // Cheap, replay-free disassembly of the function at 'pc'. Prefers the
        // module's .pdata bounds (whole function at once); falls back to linear
        // forward layout. Runs on every stop; must not walk the trace.
        void  analyze_current_function(ea_t pc);
        // Grow a function IDA defined too short to the end its module's
        // exception table gives it. IDA's static analysis stops where it loses
        // the flow (a noreturn call, an opaque tail jump), and the rest of the
        // function then renders as a JUMPOUT to somewhere outside it. Only ever
        // grows, only into space no other function claims, once per function.
        void  extend_to_pdata_bounds(ea_t pc, const func_entry_info_t &fi);
        // Define every function DIRECTLY called from [lo,hi) -- one level deep, no
        // recursion into their callees. Without this, call targets stay undefined
        // and render as "call unk_<addr>": we run with AF_PROC/AF_PROCPTR switched
        // off (see on_start_process), which is exactly the auto-analysis rule that
        // would otherwise create a function at a call target. Doing it ourselves,
        // one level at a time, gives named callees without the runaway cascade
        // that made those flags unusable here.
        void  define_callees(ea_t lo, ea_t hi);
        // Define a single function at 'ea', preferring the authoritative .pdata
        // bounds of its module and marking library code FUNC_LIB. No-op when 'ea'
        // is already the start of a function.
        void  define_function_at(ea_t ea);
        // Resolve the address a call instruction transfers to: the operand itself
        // for a direct call, or the pointer STORED at the slot for an indirect
        // call through memory (an import thunk's IAT entry). The latter only works
        // because we are replaying: the IAT holds its real, resolved value at the
        // current position. BADADDR when the target cannot be determined
        // statically (call through a register).
        ea_t  call_target_of(const insn_t &insn, ea_t &slot_out);
        // For runtime-allocated code with no module/.pdata (shellcode, unpacked):
        // seek a scratch cursor a little before the current position and replay
        // FORWARD (cheap), laying out the real executed instructions around PC so
        // a window of code is disassembled in both directions, not one at a time.
        void  lay_out_window(ea_t pc);
        // Forward-replay a window around the current position and collect the
        // current thread's executed instruction addresses within +/-0x2000 of pc
        // (the shared engine behind lay_out_window and find_dynamic_start).
        void  collect_window_pcs(ea_t pc, std::set<ea_t> &pcs);
        // Best guess at the start of the function containing 'pc' for dynamic code:
        // the lowest executed address contiguous (by instruction) with pc, so a
        // recursive-descent add_func() there lays out the prologue above pc too.
        ea_t  find_dynamic_start(ea_t pc);
        // Recover the TRUE head of the function the current position is executing
        // in (for dynamic code) from the trace's call/return structure: replay
        // FORWARD over a look-back window tracking a per-thread call-frame stack;
        // the top frame when we reach the current position is the call that
        // entered this frame, so its target is the function head. Returns BADADDR
        // when no enclosing call was captured (thread entry, jmp-based shellcode,
        // or the call predates the window) so the caller can fall back.
        ea_t  find_dynamic_function_entry(ea_t pc);

        // Sorted [base,end) table of the engine's modules, rebuilt only when the
        // engine's module count changes. The naive form of this -- a linear scan of
        // GetModuleList() -- was being run once per applied symbol name (~14000 of
        // them when a PDB loads) from the idb_event::renamed handler.
        struct ModuleSpan
        {
            ea_t base = 0, end = 0;
            bool operator<(const ModuleSpan &o) const { return base < o.base; }
        };
        const std::vector<ModuleSpan> &module_spans() const;
        // Index into module_spans() of the module containing 'ea', or SIZE_MAX.
        size_t module_index_at(ea_t ea) const;

    private:
        Plugin           *m_plugin = nullptr;
        IdaErrorReporting m_err;

        TTD::Replay::UniqueReplayEngine m_engine;
        TTD::Replay::UniqueCursor       m_cursor;

        TTD::Replay::UniqueCursor       m_symCursor; // scratch cursor for symbol reads
        TTD::Replay::UniqueCursor       m_anaCursor; // scratch cursor for forward window walks
        // Dedicated cursor for serving IDA's memory reads. It is ONLY ever
        // SetPosition'd (never used to execute/replay), because a cursor left "in
        // execution" answers memory queries with the thread-local policy regardless
        // of the requested policy -- which made non-executed bytes (the rest of a
        // shellcode function) read back as zeros. A position-only cursor honors the
        // aggressive policies, matching what WinDbg/Binja show.
        TTD::Replay::UniqueCursor       m_memCursor;
        TTD::Replay::Position           m_memPos{};       // position m_memCursor is parked at
        bool                            m_memPosValid = false;
        // Scratch "which bytes did we resolve" mask, reused across on_read_memory
        // calls. That function is on the hottest path in the plugin (every
        // disassembly line, register deref and stack row), so it must not heap
        // allocate per call; assign() reuses the existing capacity.
        std::vector<uint8_t>            m_readFilled;
        // Scratch destination for the ThreadLocal probe that tells a recorded
        // run of zeros apart from the engine's "mapped, here is zero" answer.
        // Only used for all-zero runs, and reused for the same reason as above.
        std::vector<uint8_t>            m_readProbe;
        ea_t                            m_winLo = BADADDR; // last laid-out window range
        ea_t                            m_winHi = 0;
        // Start of the function whose callees we last defined. Stepping inside one
        // function re-enters analyze_current_function on every stop, and there is
        // nothing new to find until the function itself changes.
        ea_t                            m_calleeScanFunc = BADADDR;
        // Functions already considered for .pdata extension, so the check is
        // paid once rather than on every stop inside the same function.
        std::set<ea_t>                  m_pdataExtended;
        uint32                          m_savedAf = 0;     // INF_AF saved over the session
        bool                            m_afSaved = false;
        // Cache backing module_spans(); mutable so the const lookups above can
        // refresh it lazily. m_spanCount is the module count it was built from.
        mutable std::vector<ModuleSpan> m_moduleSpans;
        mutable size_t                  m_spanCount = (size_t)-1;
        std::set<ea_t>                  m_resolvedBases; // modules whose exports we've named
        std::set<ea_t>                  m_pdbBases;      // modules whose PDB we've requested
        // Per-module function bounds from the PE exception table (.pdata), keyed
        // by module base; each vector is sorted by start address.
        std::map<ea_t, std::vector<std::pair<ea_t, ea_t>>> m_funcRanges;
        // Per-module on-disk image cache, keyed by module base, for filling memory
        // bytes TTD never recorded (image-backed never-executed code). An entry with
        // ok==false means we already tried and the file was missing/not a PE.
        std::map<ea_t, ModuleImage> m_moduleImages;
        // Bytes reconstructed from recorded WRITES, for non-module memory the
        // position query only zero-fills (unpacked/JIT code never executed at the
        // current position). Served by on_read_memory.
        struct ReconRegion
        {
            ea_t                 lo = 0, hi = 0;
            std::vector<uint8_t> data;     // hi-lo bytes
            std::vector<bool>    known;    // which bytes were recovered
        };
        std::vector<ReconRegion> m_reconRegions;
        // Functions WE defined in dynamic (non-module) code, keyed by start_ea ->
        // byte-hash at definition time. Used to detect self-modifying / reused
        // regions (incl. time-travel to a position where the bytes differ) and
        // re-disassemble them.
        std::map<ea_t, uint64_t>        m_dynFuncBytes;

        EventQueue   m_events;
        bool         m_is64 = false;
        bool         m_isForward = true;
        bool         m_backwardSingleStep = false;
        bool         m_forwardSingleStep = false;
        bool         m_runOnce = false;
        bool         m_runForward = true;
        bool         m_stepOutBackward = false;
        bool         m_runToCursorBackward = false;
        bool         m_runToCursorForward = false;
        ea_t         m_runToCursorAddr = BADADDR;
        resume_mode_t m_resumeMode = RESMOD_NONE;
        int          m_activeBpts = 0;
        // Watchpoints registered on behalf of USER breakpoints. Temporary
        // step/run watchpoints check this so their cleanup can never remove a
        // user breakpoint that happens to sit at the same address.
        std::set<TTD::Replay::MemoryWatchpointData> m_userWatchpoints;
        // Pending "edge of trace" notice (shown from on_suspended): 0 none,
        // 1 start of trace, 2 end of trace.
        enum { BOUNDARY_NONE = 0, BOUNDARY_START, BOUNDARY_END };
        int          m_pendingBoundary = BOUNDARY_NONE;
        // Free-form notice queued from inside a navigation and shown from
        // on_suspended, for the same reason as m_pendingBoundary: a modal popup
        // raised while handling ev_resume is not safe.
        qstring      m_pendingNotice;

        // The reconstructed memory map, and the layout it last produced. The
        // layout is kept so on_get_memory_info can answer DRC_NOCHG rather than
        // making IDA rebuild every debugger segment on every single step.
        MemoryMap     m_memmap;
        meminfo_vec_t m_lastLayout;      // what IDA was last given
        bool          m_haveLayout = false;
        // The layout folded for one position, so a stop that asks for it twice
        // (once to decide whether it changed, once to hand it over) folds once.
        mutable meminfo_vec_t         m_foldLayout;
        mutable TTD::Replay::Position m_foldPos;
        mutable bool                  m_foldValid = false;

        pid_t         m_pid = 1;
        TTD::Replay::Position m_nextPosition;
        bool          m_hasNextPosition = false;

        std::string m_targetName; // file name of the analyzed binary (for rebase)
    };
}
