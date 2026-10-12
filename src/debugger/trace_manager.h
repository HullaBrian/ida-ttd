#pragma once

#include "common/pch.h"
#include "core/position.h"
#include "core/backend.h"
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

    // The debugger session: translates IDA debugger events (ev_*) into
    // movement through a recording, register and memory reads, and IDA debug
    // events, through whichever backend reads the recording (core/backend.h)
    // -- Microsoft TTD for a .run, Sogen for a .sogttd. It owns the backend's
    // playhead cursor and navigator; everything it does with them is the
    // interface's, so nothing here knows which engine is underneath. One
    // instance lives for the lifetime of the plugin.
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

        // Re-read [lo, hi) from the recording and re-analyze it.
        //
        // The bytes IDA shows come from a cache that is filled the first time an
        // address is displayed. A range read before its module was mapped, or
        // before the write that produced its contents was replayed, keeps the
        // answer it was first given. This throws that away, rebuilds the range
        // from the recording's writes, and lets IDA disassemble it again.
        //
        // Returns the number of bytes recovered from recorded writes.
        size_t                     reread_range(ea_t lo, ea_t hi);

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

        // A Microsoft TTD engine cursor over the loaded trace: empty with no
        // trace, and with any other backend. For the analyses that still drive
        // the Microsoft engine themselves until they become queries (step 5 of
        // docs/modular-backends.md); they say so and stop when it is empty.
        TTD::Replay::UniqueCursor  make_cursor();
        bool                       is64() const { return m_is64; }

        // The backend reading the open recording, and the playhead cursor.
        // Null with no session.
        ITraceBackend             *backend() const { return m_backend; }
        ITraceCursor              *cursor() const  { return m_cursor.get(); }

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
        void   reset_session_state();

        thid_t current_tid() const;
        ea_t   program_counter() const;

        // What the playhead sees, to tell IDA about the threads and modules
        // that a movement started or ended.
        std::set<uint32_t>                          snapshot_threads() const;
        std::map<std::pair<ea_t, Position>, const ModuleInfo *> snapshot_modules() const;
        void  apply_differences(const std::set<uint32_t> &threads_before,
                                const std::set<uint32_t> &threads_after,
                                const std::map<std::pair<ea_t, Position>, const ModuleInfo *> &mods_before,
                                const std::map<std::pair<ea_t, Position>, const ModuleInfo *> &mods_after);
        bool  is_target_module(const ModuleInfo &m) const;
        void  emit_module_load(const ModuleInfo &m);

        // One movement through the navigator, with everything around it:
        // the thread and module events it caused, the boundary the user is
        // told about, and any notice the navigator left. 'move' does the
        // movement and says why it stopped.
        StopReason navigate(bool forward, const std::function<StopReason()> &move);
        void  navigate_to(Position p);
        void  emit_stop(bool is_step);

    private:
        SessionHooks      m_hooks;
        ModuleRegistry    m_modules;
        MemoryReader      m_memory;
        CodeAnalyzer      m_code;
        SegmentLayout     m_layout;

        ITraceBackend              *m_backend = nullptr;
        CursorPtr                   m_cursor;       // the playhead
        std::unique_ptr<INavigator> m_nav;          // moves m_cursor
        std::vector<Breakpoint>     m_bpts;         // what IDA has set

        uint32                          m_savedAf = 0;     // INF_AF saved over the session
        bool                            m_afSaved = false;

        EventQueue   m_events;
        bool         m_is64 = false;

        bool          m_isForward = true;
        resume_mode_t m_resumeMode = RESMOD_NONE;

        // The edge of the recording a movement ran into, reported once the
        // stop is shown (a modal box inside ev_resume would be unsafe).
        enum { BOUNDARY_NONE = 0, BOUNDARY_START, BOUNDARY_END };
        int          m_pendingBoundary = BOUNDARY_NONE;
        qstring      m_pendingNotice;

        pid_t         m_pid = 1;

        // The movement the UI asked for, carried out by the next ev_resume.
        struct PendingRequest
        {
            Request  kind    = Request::None;
            bool     forward = true;
            ea_t     address = BADADDR;      // RunToCursor
            Position position;               // GotoPosition
        };
        PendingRequest m_pending;

        std::string m_targetName; // file name of the analyzed binary (for rebase)
    };
}
