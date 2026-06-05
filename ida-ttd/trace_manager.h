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
        TTD::Replay::Position              current_position() const;
        std::vector<NamedPosition> collect_positions() const;

    private:
        thid_t                     current_tid() const;
        ea_t                       program_counter() const;
        std::map<uint32_t, thid_t> snapshot_threads() const;
        std::set<const TTD::Replay::Module *> snapshot_modules() const;
        TTD::Replay::EventType navigate_steps(bool forward, TTD::Replay::StepCount steps);
        void  navigate_to(const TTD::Replay::Position &p);
        void  apply_differences(const std::map<uint32_t, thid_t> &threads_before,
                                const std::map<uint32_t, thid_t> &threads_after,
                                const std::set<const TTD::Replay::Module *> &mods_before,
                                const std::set<const TTD::Replay::Module *> &mods_after);
        bool  is_target_module(const TTD::Replay::Module &m) const;
        void  emit_module_load(const TTD::Replay::Module &m);

    private:
        Plugin           *m_plugin = nullptr;
        IdaErrorReporting m_err;

        TTD::Replay::UniqueReplayEngine m_engine;
        TTD::Replay::UniqueCursor       m_cursor;

        EventQueue   m_events;
        bool         m_is64 = false;
        bool         m_isForward = true;
        bool         m_backwardSingleStep = false;
        resume_mode_t m_resumeMode = RESMOD_NONE;
        int          m_activeBpts = 0;

        pid_t         m_pid = 1;
        TTD::Replay::Position m_nextPosition;
        bool          m_hasNextPosition = false;

        std::string m_targetName; // file name of the analyzed binary (for rebase)
    };
}
