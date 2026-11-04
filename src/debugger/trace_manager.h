#pragma once

#include "common/pch.h"
#include "core/position.h"
#include "core/backend.h"
#include "debugger/event_queue.h"
#include "debugger/module_registry.h"
#include "debugger/memory_reader.h"
#include "debugger/code_analyzer.h"
#include "debugger/kept_functions.h"
#include "debugger/segment_layout.h"
#include "common/strings.h"

namespace idattd
{
    // What the plugin wants done when a trace session begins and ends. This is
    // the only way back out to the plugin, so debugger/ does not depend on
    // plugin/.
    struct SessionHooks
    {
        std::function<void()> on_start;   // a trace is loaded: show the TTD UI
        std::function<void()> on_end;     // the trace is closing: tear it down
    };

    // The debugger session: translates IDA debugger events (ev_*) into
    // movement through a recording, register and memory reads, and IDA debug
    // events, through whichever backend reads the recording (core/backend.h;
    // Microsoft TTD for a .run, Sogen for a .sogttd). It owns the backend's
    // playhead cursor and navigator and uses only the interface, so nothing
    // here knows which engine is underneath. One instance lives as long as the
    // plugin.
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
        // A movement is replaying the playhead cursor; anything that would use
        // the backend from a message pump during it should wait.
        bool is_navigating() const { return m_navigating; }

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
        const qstring &last_resume() const { return m_lastResume; }
        // The recording this session replays, as IDA was given it.
        const qstring &trace_path() const { return m_tracePath; }
        // Counts ev_resume calls, so the UI can tell what a movement did
        // (between a resume and its stop) from what the user did.
        uint64 resume_serial() const { return m_resumeSerial; }
        const std::deque<qstring> &event_log() const { return m_eventLog; }

        // When a movement's thread and module changes are reported relative to
        // its stop. Under IDA's step modes any non-step event ends the step
        // there and leaves the step's own event queued, so the order matters.
        // Experimental, set from the script API:
        //   0  changes, then the stop
        //   1  the stop, then the changes
        //   2  as 0, but during IDA's step modes the changes are held back and
        //      reported with the next stop outside one
        void set_event_order(int order) { m_eventOrder = order; }
        int  event_order() const        { return m_eventOrder; }
        ssize_t on_set_backwards(bool backwards);
        ssize_t on_set_resume_mode(thid_t tid, resume_mode_t resmod);
        ssize_t on_update_bpts(int *nbpts, update_bpt_info_t *bpts, int nadd, int ndel);
        ssize_t on_exit_process();

        // What the UI has asked for, carried out by the next ev_resume. One
        // value rather than a flag per kind, so of two requests made before a
        // resume only the later fires.
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
        // Travel to 'p' at the next resume. Shows a wait box until the stop
        // there is fully processed (end_travel_wait), which can take seconds
        // because a backend may rebuild the state only when it is first read.
        void                       set_next_position(const Position &p);
        void                       end_travel_wait();
        void                       goto_position();
        void                       request_single_step(bool forward);
        void                       request_run(bool forward);
        void                       request_step_out_backward();
        // Run backward until execution reaches 'addr', a user breakpoint or
        // the start of the trace. IDA greys out its own
        // ThreadRunToCursorBackwards for this debugger.
        void                       request_run_to_cursor_backward(ea_t addr);
        // Run forward until execution reaches 'addr', a user breakpoint or the
        // end of the trace. IDA's own ThreadRunToCursor plants a real
        // breakpoint, which intermittently fails on a read-only recording.
        void                       request_run_to_cursor_forward(ea_t addr);
        Position                   current_position() const;
        // The instruction the cursor stands on. Bookmarks record it so the list
        // shows where each mark is without seeking to every row.
        ea_t                       current_pc_ea() const;

        // Re-read [lo, hi) from the recording and re-analyze it.
        //
        // IDA's byte cache keeps the first answer for an address, so a range
        // read before its module was mapped, or before the write that produced
        // it was replayed, stays stale. This drops that answer, rebuilds the
        // range from recorded writes and lets IDA disassemble it again.
        //
        // Returns the number of bytes recovered from recorded writes.
        size_t                     reread_range(ea_t lo, ea_t hi);

        // The modules the recording loaded (see ModuleRegistry). This class
        // only tells the registry when a session begins and ends.
        ModuleRegistry       &modules()       { return m_modules; }
        const ModuleRegistry &modules() const { return m_modules; }

        // Identity of the loaded recording, so something cached in the database
        // against one trace is not shown against another. Zero with no trace.
        uint64_t trace_fingerprint() const;

        // What IDA is told the recorded address space looks like, and the
        // reconstructed memory map behind it.
        SegmentLayout       &layout()       { return m_layout; }
        const SegmentLayout &layout() const { return m_layout; }
        // Shorthands: almost every caller wants the map, not the layout.
        const MemoryMap &memmap() const        { return m_layout.map(); }
        MemoryMap       &memmap_for_update()   { return m_layout.map_for_update(); }
        // Last position of the loaded trace, or Position::none() without one.
        // Its 'hi' word is what a replay progress readout divides by.
        Position                   last_position() const;
        std::vector<NamedPosition> collect_positions() const;

        bool                       is64() const { return m_is64; }

        // The backend reading the open recording, and the playhead cursor.
        // Null with no session.
        ITraceBackend             *backend() const { return m_backend; }
        ITraceCursor              *cursor() const  { return m_cursor.get(); }

        // ---- a fork being prepared ------------------------------------------
        //
        // "Fork here" fixes a position. Registers and memory changed there
        // through IDA (registers window, hex view, patching) are kept as the
        // fork's changes and shown instead of the recording's while the cursor
        // stands there; elsewhere the recording is read-only. Recording the
        // fork turns them into a ForkRequest.
        struct ForkDraft
        {
            bool     active = false;
            Position at;
            thid_t   tid = NO_THREAD;           // the thread that runs next
            std::map<int, uint64_t> regs;       // IDA register index, value
            std::map<ea_t, uchar>   bytes;
        };
        void             begin_fork_draft();
        void             discard_fork_draft() { m_draft = ForkDraft{}; }
        const ForkDraft &fork_draft() const { return m_draft; }
        // The cursor stands at the draft's position.
        bool             at_fork_draft() const;
        // The draft's position and changes, as a request to record.
        void             fill_fork_request(ForkRequest *req) const;
        ssize_t on_write_register(thid_t tid, int regidx, const regval_t *value, qstring *errbuf);
        ssize_t on_write_memory(size_t *nbytes, ea_t ea, const void *buffer, size_t size, qstring *errbuf);

        // Called once per stop (HT_DBG dbg_suspend_process), when the debugger
        // memory cache is valid for the new position: names exports of newly
        // seen modules and disassembles code around RIP.
        void                       on_suspended();

        // Explicit, user-triggered deep analysis (CodeAnalyzer::analyze_whole_function).
        void                       analyze_whole_function();

        // The user's work on functions outside every module, kept across
        // sessions (KeptFunctions).
        KeptFunctions             &kept() { return m_kept; }
        // Apply what was kept to the functions defined since the last call.
        // Only while stopped. True when anything was restored.
        bool                       restore_kept();

    private:
        void   reset_session_state();
        // Replace the pending request with 'kind' and have IDA resume to carry
        // it out. Warns and does nothing without a session.
        void   queue_request(Request kind, bool forward, ea_t address = BADADDR);

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

        // One movement through the navigator, behind a wait box, recording
        // the boundary it hit and any notice the navigator left. 'move' does
        // the movement and says why it stopped.
        StopReason navigate(bool forward, const std::function<StopReason()> &move);
        void  navigate_to(Position p);
        // How a stop is reported to IDA: a single step, a breakpoint the
        // movement stopped on, or neither (a travel, the trace's edge).
        enum class StopEvent { Step, Breakpoint, Suspended };
        static StopEvent stop_event(StopReason sr)
        { return sr == StopReason::Breakpoint ? StopEvent::Breakpoint : StopEvent::Suspended; }
        void  emit_stop(StopEvent kind);
        // Report the threads and modules that differ from what IDA was last
        // told, and remember the new state as told.
        void  report_differences();

    private:
        SessionHooks      m_hooks;
        ModuleRegistry    m_modules;
        MemoryReader      m_memory;
        CodeAnalyzer      m_code;
        SegmentLayout     m_layout;
        KeptFunctions     m_kept;

        ITraceBackend              *m_backend = nullptr;
        CursorPtr                   m_cursor;       // the playhead
        std::unique_ptr<INavigator> m_nav;          // moves m_cursor
        std::vector<Breakpoint>     m_bpts;         // what IDA has set

        uint32                          m_savedAf = 0;     // INF_AF saved over the session
        bool                            m_afSaved = false;
        bool                            m_dinfoWasOn = false;  // DOPT_LOAD_DINFO before the session
        bool                            m_dinfoSaved = false;

        EventQueue   m_events;
        bool         m_is64 = false;

        bool          m_isForward = true;
        resume_mode_t m_resumeMode = RESMOD_NONE;
        // What the last ev_resume carried, for the script API's 'state'; it is
        // otherwise invisible which movement IDA asked for.
        qstring       m_lastResume;
        qstring       m_tracePath;
        uint64        m_resumeSerial = 0;
        // The threads and modules IDA has been told about.
        std::set<uint32_t> m_toldThreads;
        std::map<std::pair<ea_t, Position>, const ModuleInfo *> m_toldMods;
        int           m_eventOrder = 2;
        bool          m_stepMode   = false;   // this resume is one of IDA's step modes
        bool          m_travelWait = false;   // set_next_position's wait box is up
        // A movement is in progress. Its wait box pumps messages, so IDA can
        // deliver another ev_resume meanwhile, which must not move the same
        // navigator again.
        bool          m_navigating = false;
        // IDA changed breakpoints during a movement; navigate() hands the new
        // set to the navigator once it ends.
        bool          m_bptsDeferred = false;
        // The last few events handed to IDA, resumes received and breakpoint
        // updates, oldest first, for diagnosing what IDA asked for.
        static constexpr size_t EVENT_LOG_LINES = 48;
        std::deque<qstring> m_eventLog;
        void log_event(const qstring &line);

        // The recording edge a movement ran into, reported once the stop is
        // shown (a modal box inside ev_resume is unsafe).
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
        ForkDraft   m_draft;
    };
}
