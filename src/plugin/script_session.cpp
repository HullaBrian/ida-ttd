// The script commands on the debugger session: its state, starting,
// waiting, moving and switching, what IDA shows (registers, memory,
// segments), and the plugin's backends and settings.
#include "plugin/script_internal.h"
#include "plugin/settings.h"
#include "core/backend_registry.h"
#include "core/backend_module.h"

namespace idattd
{
    // ------------------------------------------------------------------ session

    void need_session()
    {
        if ( get_process_state() == DSTATE_NOTASK || !mgr().is_active() )
            fail("no replay session is running; use 'start'");
    }

    // Wait for the debugger to stop again, and say where.
    static void wait_stop(int timeout, JObj &out)
    {
        // WFNE_SILENT: a script has nobody to answer a modal box.
        dbg_event_code_t code = wait_for_next_event(WFNE_SUSP | WFNE_SILENT, timeout);
        out.num("event", code);
        if ( code == DEC_TIMEOUT )
            out.boolean("timed_out", true);
        if ( mgr().is_active() )
        {
            out.str("pos", format_position(mgr().current_position()))
               .hex("pc", mgr().current_pc_ea());
            thid_t tid = get_current_thread();
            out.num("tid", tid);
        }
        out.num("process_state", get_process_state());
    }

    static void cmd_state(const Args &, JObj &out)
    {
        out.num("process_state", get_process_state()).boolean("session", mgr().is_active())
           .boolean("actions_visible", g_plugin->actions_visible());
        if ( mgr().is_active() )
            out.str("pos", format_position(mgr().current_position())).hex("pc", mgr().current_pc_ea())
               .str("trace", mgr().trace_path());
        out.str("drv_backend", g_drv.backend != nullptr ? g_drv.backend->id() : "")
           .str("last_resume", mgr().last_resume());
        JArr log;
        for ( const qstring &l : mgr().event_log() )
        {
            qstring q;
            json_escape(&q, l.c_str());
            log.add(q);
        }
        out.raw("event_log", log.done());
    }

    static void cmd_start(const Args &a, JObj &out)
    {
        if ( get_process_state() != DSTATE_NOTASK )
            fail("a debugging session is already running");
        // No dialogs from a script: a modal box (the recording moved, the
        // debugger cannot be selected) would hang the caller.
        qstring err;
        a.only(1, { "timeout=" });
        const int timeout = timeout_of(a, 0);
        if ( !g_plugin->start_trace_session(&err) )
            fail("%s", err.c_str());
        wait_stop(timeout, out);
    }

    static void cmd_wait(const Args &a, JObj &out)
    {
        a.only(1, { "timeout=" });
        wait_stop(timeout_of(a, 0), out);
    }

    // switch PATH [TIMEOUT]: end any session and replay PATH in this
    // database, as the Fork manager's switch does but without its timer.
    static void cmd_switch(const Args &a, JObj &out)
    {
        qstring path = a.at(0);
        a.only(2, { "timeout=" });
        const int timeout = timeout_of(a, 1);
        // Before ending anything: a mistyped path must not cost the session.
        if ( !qfileexist(path.c_str()) )
            fail("there is no recording at %s", path.c_str());
        if ( get_process_state() != DSTATE_NOTASK )
        {
            exit_process();
            wait_for_next_event(WFNE_ANY | WFNE_SILENT, 10);
        }
        if ( get_process_state() != DSTATE_NOTASK )
            fail("the running session did not end");
        if ( !g_plugin->start_trace_at(path.c_str(), true) )
            fail("the replay of %s did not start (see the output window)", path.c_str());
        wait_stop(timeout, out);
        out.str("trace", mgr().trace_path());
    }

    // The switch as the Fork manager makes it (timer, then IDA's request
    // queue), returning at once. Poll "state" for the new trace.
    static void cmd_switch_ui(const Args &a, JObj &out)
    {
        g_plugin->switch_trace(a.at(0));
        out.str("queued", a.at(0));
    }

    // One movement of the debugger session, then wait for the stop. Backward
    // movements go the way the TTD toolbar sends them.
    static void cmd_move(const Args &a, JObj &out)
    {
        need_session();
        const qstring &c = a.v[0];
        // runto takes its address first; every movement takes a direction
        // and a timeout, and nothing else.
        a.only(c == "runto" ? 1 : 0, { "back", "backward", "backwards", "timeout=" });
        const bool back = a.back();
        const int timeout = timeout_of(a);
        if ( c == "step" )
            back ? request_step_into_backwards() : request_step_into();
        else if ( c == "over" )
            back ? request_step_over_backwards() : request_step_over();
        else if ( c == "out" )
        {
            if ( back ) { mgr().request_step_out_backward(); wait_stop(timeout, out); return; }
            request_step_until_ret();
        }
        else if ( c == "run" )
        {
            if ( back ) { mgr().request_run(false); wait_stop(timeout, out); return; }
            request_continue_process();
        }
        else if ( c == "runto" )
        {
            ea_t ea = (ea_t)a.u64(0);
            back ? mgr().request_run_to_cursor_backward(ea) : mgr().request_run_to_cursor_forward(ea);
            wait_stop(timeout, out);
            return;
        }
        run_requests();
        wait_stop(timeout, out);
    }

    static void cmd_goto(const Args &a, JObj &out)
    {
        need_session();
        a.only(1, { "timeout=" });
        const int timeout = timeout_of(a);
        mgr().set_next_position(position_arg(a.at(0)));
        request_continue_process();
        run_requests();
        wait_stop(timeout, out);
    }

    static void cmd_regs(const Args &, JObj &out)
    {
        need_session();
        static const char *names64[] = { "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
                                         "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
                                         "RIP", "EFL" };
        static const char *names32[] = { "EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP",
                                         "EIP", "EFL" };
        bool is64 = inf_is_64bit();
        JObj regs;
        size_t n = is64 ? qnumber(names64) : qnumber(names32);
        for ( size_t i = 0; i < n; i++ )
        {
            const char *name = is64 ? names64[i] : names32[i];
            uint64 v = 0;
            if ( get_reg_val(name, &v) )
            {
                qstring key = name;
                qstrlwr(key.begin());
                regs.hex(key.c_str(), v);
            }
        }
        out.str("pos", format_position(mgr().current_position())).raw("regs", regs.done());
    }

    static void cmd_read(const Args &a, JObj &out)
    {
        need_session();
        uint64_t ea = a.u64(0), size = a.u64_or(1, 0x40);
        if ( size == 0 || size > 0x10000 )
            fail("read at most 0x10000 bytes");
        std::vector<uint8_t> buf((size_t)size);
        ssize_t got = read_dbg_memory((ea_t)ea, buf.data(), buf.size());
        out.hex("ea", ea).num("got", got)
           .raw("bytes", bytes_json(buf.data(), nullptr, got > 0 ? (size_t)got : 0));
    }

    static void cmd_segments(const Args &a, JObj &out)
    {
        uint64_t max = a.u64_or(0, 400);
        JArr arr;
        for ( int i = 0; i < get_segm_qty() && arr.size() < max; i++ )
        {
            segment_info_t si;
            if ( !get_segment_info_by_num(&si, i, GSI_NAME | GSI_SCLASS) )
                continue;
            JObj o;
            o.str("name", si.get_name()).str("class", si.get_sclass())
             .hex("start", si.start_ea).hex("end", si.end_ea)
             .num("perm", si.get_perm()).boolean("debugger", si.is_debugger_segm());
            arr.add(o.done());
        }
        out.num("count", get_segm_qty()).raw("segments", arr.done());
    }

    static void cmd_stop(const Args &, JObj &out)
    {
        if ( get_process_state() != DSTATE_NOTASK )
        {
            exit_process();
            wait_for_next_event(WFNE_ANY | WFNE_SILENT, 10);
        }
        out.num("process_state", get_process_state());
    }

    static void cmd_backends(const Args &, JObj &out)
    {
        load_backend_modules();
        JArr arr;
        for ( ITraceBackend *b : BackendRegistry::instance().all() )
        {
            JObj o;
            BackendModule *m = dynamic_cast<BackendModule *>(b);
            o.str("id", b->id()).str("name", b->display_name()).str("filter", b->file_filter())
             .str("path", m != nullptr ? m->path() : qstring("(built in)"));
            arr.add(o.done());
        }
        out.raw("backends", arr.done());
    }

    // The settings as the plugin holds them (re-read first if
    // ida-config.json changed), so a test can see a change arrive.
    static void cmd_settings(const Args &, JObj &out)
    {
        reload_settings_if_changed();
        const Settings &s = settings();
        out.boolean("replay_on_open", s.replay_on_open)
           .boolean("symbol_downloads", s.symbol_downloads)
           .str("symbol_server", s.symbol_server)
           .boolean("auto_coverage", s.auto_coverage)
           .boolean("auto_callsites", s.auto_callsites)
           .str("fork_instructions", qstring().sprnt("%llu", (unsigned long long)s.fork_instructions))
           .str("registry_folder", s.registry_folder)
           .boolean("sogen_network", s.sogen_network)
           .str("sogen_checkpoint_interval",
                qstring().sprnt("%llu", (unsigned long long)s.sogen_checkpoint_interval))
           .boolean("sogen_record_reads", s.sogen_record_reads)
           .boolean("sogen_record_writes", s.sogen_record_writes)
           .boolean("sogen_record_executes", s.sogen_record_executes)
           .boolean("sogen_elevated", s.sogen_elevated)
           .boolean("sogen_log", s.sogen_log)
           .boolean("sogen_start_now", s.sogen_start_now)
           .str("sogen_emulation_root", s.sogen_emulation_root)
           .boolean("diagnostics_log", s.diagnostics_log)
           .boolean("memmap_flag_code", s.memmap_flag_code);
    }

    // ------------------------------------------------------------------ commands

    static const Command SESSION_COMMANDS[] = {
        { "state",          cmd_state,          "the debugger and session state" },
        { "backends",       cmd_backends,       "the backends loaded, and the folders they came from" },
        { "settings",       cmd_settings,       "the plugin's settings, as it holds them" },
        { "start",          cmd_start,          "[TIMEOUT|timeout=N] start the replay for this database and wait for the first stop" },
        { "wait",           cmd_wait,           "[TIMEOUT|timeout=N] wait for the debugger to stop" },
        { "step",           cmd_move,           "[back] [timeout=N] one instruction" },
        { "over",           cmd_move,           "[back] [timeout=N] step over" },
        { "out",            cmd_move,           "[back] [timeout=N] step out" },
        { "run",            cmd_move,           "[back] [timeout=N] to a breakpoint or the edge of the trace" },
        { "runto",          cmd_move,           "EA [back] [timeout=N] run to an address" },
        { "goto",           cmd_goto,           "POS [timeout=N] travel to a position" },
        { "regs",           cmd_regs,           "the registers IDA shows" },
        { "read",           cmd_read,           "EA [SIZE] debugger memory, as IDA reads it" },
        { "segments",       cmd_segments,       "[MAX] the segments, debugger ones included" },
        { "stop",           cmd_stop,           "end the session" },
        { "switch",         cmd_switch,         "PATH [TIMEOUT|timeout=N] replay another recording (a fork) in this database" },
        { "switch.ui",      cmd_switch_ui,      "PATH replay another recording the way the Fork manager does it (returns at once)" },
    };

    std::span<const Command> session_commands() { return SESSION_COMMANDS; }
}
