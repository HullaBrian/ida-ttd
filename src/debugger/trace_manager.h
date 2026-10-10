#pragma once

#include "common/pch.h"
#include "core/position.h"
#include "debugger/event_queue.h"
#include "debugger/module_registry.h"
#include "debugger/memory_reader.h"
#include "debugger/code_analyzer.h"
#include "debugger/segment_layout.h"
#include "common/trace_open.h"

namespace idattd
{
    // What the plugin wants done when a trace session begins and ends. This is
    // the backend's only way back out to the plugin, so debugger/ does not
    // depend on plugin/ at all.
    struct SessionHooks
    {
        std::function<void()> on_start;   // a trace is loaded: show the TTD UI
        std::function<void()> on_end;     // the trace is closing: tear it down
    };

    // Owns the TTD replay engine + cursor and translates IDA debugger events
    // (ev_*) into trace navigation, register/memory queries and IDA debug
    // events. One instance lives for the lifetime of the plugin.
    class TraceManager
    {
    public:
        struct NamedPosition
        {
            std::string name;
            Position    pos;
        };

        TraceManager() = default;

        void set_session_hooks(SessionHooks h) { m_hooks = std::move(h); }
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

        // What the UI has asked for, to be carried out by the next ev_resume.
        //
        // One request rather than a flag per kind. Eleven mutually exclusive
        // booleans had nothing to stop two being set: two request_* calls
        // before a resume was drained resolved by the order of an if-chain in
        // on_resume, and the loser survived to fire on the following resume --
        // a time jump the user never asked for. A single value cannot be in
        // two states, and setting a request plainly replaces the previous one.
        enum class Request
        {
            None,               // nothing queued: follow IDA's resume mode
            GotoPosition,       // 'position'
            Step,               // one instruction, in 'forward'
            Run,                // to a breakpoint or the trace edge, in 'forward'
            StepOutBackward,    // rewind out of the current frame
            RunToCursor,        // to 'address', in 'forward'
        };

        // ---- UI helpers ----------------------------------------------------
        void                       set_next_position(const Position &p);
        void                       goto_position();
        void                       request_backward_step();
        void                       request_single_step(bool forward);
        void                       request_run(bool forward);
        void                       request_step_out_backward();
        // Run the trace backward until execution reaches 'addr' (or a user
        // breakpoint, or the start of the trace) -- our own "run to cursor
        // backwards". IDA greys out its native ThreadRunToCursorBackwards for this
        // backend, so we drive it ourselves like Continue/Step-out backwards.
        void                       request_run_to_cursor_backward(ea_t addr);
        // Run the trace forward until execution reaches 'addr' (or a user
        // breakpoint, or the end of the trace) -- our own "run to cursor". IDA's
        // native ThreadRunToCursor intermittently fails on this read-only backend
        // (it tries to plant a real/source breakpoint), so we drive it ourselves
        // with a temporary Execute watchpoint, like the backward variant.
        void                       request_run_to_cursor_forward(ea_t addr);
        Position                   current_position() const;
        // The instruction the cursor is standing on. Bookmarks record this so the
        // list can show where each mark is without seeking to every row.
        ea_t                       current_pc_ea() const;

        // What the plugin knows about the modules the recording loaded: where
        // they are, what they are called, where their functions start, which of
        // their addresses have names, and their on-disk images. This class only
        // tells it when a session begins and ends.
        ModuleRegistry       &modules()       { return m_modules; }
        const ModuleRegistry &modules() const { return m_modules; }

        // Identity of the loaded recording, so something cached in the database
        // against one trace is not shown against another. Zero with no trace.
        uint64_t trace_fingerprint() const;

        // What IDA is told the recorded address space looks like, and the
        // reconstructed memory map behind it.
        SegmentLayout       &layout()       { return m_layout; }
        const SegmentLayout &layout() const { return m_layout; }
        // Shorthands, because almost every caller wants the map rather than
        // the layout machinery around it.
        const MemoryMap &memmap() const        { return m_layout.map(); }
        MemoryMap       &memmap_for_update()   { return m_layout.map_for_update(); }
        // Last position of the loaded trace, or Position::none() without one.
        // Its 'hi' word is what a replay progress readout divides by.
        Position                   last_position() const;
        std::vector<NamedPosition> collect_positions() const;

        // Create a fresh cursor over the loaded trace (empty if no trace). Used
        // by the function tracer for independent sweeps.
        TTD::Replay::UniqueCursor  make_cursor();
        bool                       is64() const { return m_is64; }

        // Called once per stop (from HT_DBG dbg_suspend_process), when the
        // debugger memory cache is valid for the new position: name exports for
        // any newly-seen module and disassemble a run of code around RIP.
        void                       on_suspended();

        // Explicit, user-triggered deep analysis: walk the trace backward from the
        // current position to find the enclosing function's entry and define the
        // whole function. Expensive (per-step backward replay), so it runs behind
        // a cancellable wait box -- never automatically.
        void                       analyze_whole_function();

    private:
        // Drop everything that belongs to one trace: cursors, caches, queued
        // events and pending navigation. Called when a session ends and again
        // when one starts, so a second trace cannot inherit the first's
        // reconstructed bytes or module tables.
        void   reset_session_state();
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
        // sends ev_set_backwards plus RESMOD_OVER.
        TTD::Replay::EventType navigate_over_backward();
        // Run backward until the current function is exited (we reach the call
        // that entered this frame), honoring user breakpoints.
        TTD::Replay::EventType navigate_out_backward();
        // Position of the CALL that entered the frame the cursor is currently in.
        //
        // Found by replaying forward from a look-back start up to the playhead
        // while tracking a per-thread frame stack, which is one bulk engine call
        // per attempt. Not a backward single-step loop counting call/ret depth:
        // every backward step re-seeks a keyframe, which makes that approach
        // O(n x keyframe distance).
        //
        // The look-back widens across sequences until the entering call is
        // captured; 'cancelled' distinguishes "the user gave up" from "the call is
        // further back than we are willing to search".
        bool  find_frame_entry_position(TTD::Replay::Position &out, bool &cancelled);
        // Scratch cursor for the frame search above, created on first use.
        // Sequential, unfiltered replay: the search's call/return callback
        // mutates an unsynchronized map, and the engine's default dispatches
        // callbacks from several segment threads at once.
        //
        // CodeAnalyzer keeps one of its own for the same reason. One cursor
        // shared between the two would be a mutable resource two unrelated
        // concerns both install callbacks on; a cursor is cheap, and the
        // engine is built to hand out several.
        TTD::Replay::ICursorView *frame_cursor();
        // Seek the main cursor backward to 'p' in one engine call, with user
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
        // advance to the next occurrence rather than matching the current one.
        TTD::Replay::EventType navigate_forward_to(ea_t addr);
        // After a navigation that stopped on its own (not at a user breakpoint),
        // flag a pending "start/end of the trace" notice if the cursor came to rest
        // on the trace's first/last position. Shown (once) from on_suspended, where
        // a modal popup is safe -- not from inside the resume handler.
        void  settle_after_navigation(TTD::Replay::EventType sr, bool forward);
        // Pull the cursor back inside [GetFirstPosition(), GetLastPosition()].
        //
        // A forward run to the end does not leave the cursor on the last recorded
        // instruction -- it leaves it past the end, at the Position::Max sentinel
        // the replay was limited by. Every subsequent operation then works from a
        // position that does not exist in the trace: a single backward step ran to
        // the very beginning instead of moving one instruction, and the frame
        // search subtracted its look-back window from a sequence number far beyond
        // the trace, so every window landed past the end and found nothing.
        // Clamping after each navigation keeps the playhead on a real position.
        void  clamp_to_trace();
        // How a guarded forward run ended.
        enum class RunStop
        {
            Reached,        // execution came back to the address asked for
            Breakpoint,     // a user breakpoint stopped it first
            TraceBoundary,  // the recording ended first
        };
        // Run forward to 'addr' on thread 'utid' with SP >= min_sp (so deeper
        // recursion through the same address is skipped); also stops on any user
        // breakpoint.
        RunStop run_to_addr_guarded(ea_t addr, uint64_t min_sp, uint32_t utid);
        // Install a temporary 1-byte Execute watchpoint at 'addr' for a step/run
        // operation, filling 'wp'. TTD keys watchpoints by (address, size, mask,
        // thread), so an identical user breakpoint is the same watchpoint: adding
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
    private:
        SessionHooks      m_hooks;
        ModuleRegistry    m_modules;
        MemoryReader      m_memory;
        CodeAnalyzer      m_code;
        SegmentLayout     m_layout;
        IdaErrorReporting m_err;

        TTD::Replay::UniqueReplayEngine m_engine;
        TTD::Replay::UniqueCursor       m_cursor;
        TTD::Replay::UniqueCursor       m_frameCursor;  // see frame_cursor()

        uint32                          m_savedAf = 0;     // INF_AF saved over the session
        bool                            m_afSaved = false;
        EventQueue   m_events;
        bool         m_is64 = false;
        bool         m_isForward = true;
        resume_mode_t m_resumeMode = RESMOD_NONE;
        int          m_activeBpts = 0;
        // Watchpoints registered on behalf of user breakpoints. Temporary
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

        pid_t         m_pid = 1;

        // The one queued request; see Request above. Only the fields its kind
        // names are meaningful.
        struct PendingRequest
        {
            Request               kind    = Request::None;
            bool                  forward = true;
            ea_t                  address = BADADDR;    // RunToCursor
            TTD::Replay::Position position;             // GotoPosition
        };
        PendingRequest m_pending;

        std::string m_targetName; // file name of the analyzed binary (for rebase)
    };
}
