// SPDX-License-Identifier: GPL-2.0-only
//
// ida-ttd's Sogen backend: the ABI table and the export the core looks
// for. See sogen_state.h.

#include "backend-sogen/sogen_state.h"

namespace idattd::sogen
{
    // ------------------------------------------------------------ the table

    const ittd_backend_api g_api = []()
    {
        ittd_backend_api a{};
        a.abi_version        = ITTD_ABI_VERSION;
        a.size               = sizeof(ittd_backend_api);
        a.id                 = id;
        a.display_name       = display_name;
        a.file_filter        = file_filter;
        a.can_open           = can_open;
        a.open               = open;
        a.close              = close;
        a.last_error         = last_error;
        a.info               = info;
        a.prepare            = nullptr;     // no keyframes: every seek is a cpu_view
        a.format_position    = format_position;
        a.parse_position     = parse_position;
        a.position_syntax    = position_syntax;
        a.cursor_open        = cursor_open;
        a.cursor_close       = cursor_close;
        a.cursor_position    = cursor_position;
        a.cursor_seek        = cursor_seek;
        a.cursor_thread      = cursor_thread;
        a.cursor_regs        = cursor_regs;
        a.cursor_read_memory = cursor_read_memory;
        a.cursor_threads     = cursor_threads;
        a.nav_step           = nav_step;
        a.nav_step_over      = nav_step_over;
        a.nav_step_out       = nav_step_out;
        a.nav_run            = nav_run;
        a.nav_run_to         = nav_run_to;
        a.nav_breakpoints    = nav_breakpoints;
        a.nav_set_progress   = nav_set_progress;
        a.modules            = modules;
        a.threads            = threads;
        a.timeline           = timeline;
        a.query_accesses     = query_accesses;
        a.query_executed     = query_executed;
        a.query_calls        = query_calls;
        a.query_indirect     = query_indirect;
        a.query_mapping_changes = query_mapping_changes;
        a.module_symbols     = module_symbols;
        a.module_functions   = nullptr;     // the core reads .pdata from the file
        a.query_exceptions   = query_exceptions;
        a.query_syscalls     = query_syscalls;
        a.query_self_modifying = query_self_modifying;
        a.fork_open          = fork_open;
        a.fork_regs          = fork_regs;
        a.fork_set_regs      = fork_set_regs;
        a.fork_write_memory  = fork_write_memory;
        a.fork_record        = fork_record;
        a.fork_close         = fork_close;
        a.query_strings      = query_strings;
        a.query_buffers      = query_buffers;
        a.query_access_heat  = query_access_heat;
        a.heat_slice_position = heat_slice_position;
        a.query_access_heat_window   = query_access_heat_window;
        a.heat_window_slice_position = heat_window_slice_position;
        a.scan_notice        = scan_notice;
        a.regs_at            = regs_at;
        a.read_memory_at     = read_memory_at;
        a.query_instructions = query_instructions;
        a.position_add       = position_add;
        a.query_frame_entry  = query_frame_entry;
        a.query_frame_entry_progress = query_frame_entry_progress;
        a.query_mapping_files = query_mapping_files;
        a.replay_env         = replay_env;
        a.check_registry     = check_registry;
        a.record_program     = record_program;
        return a;
    }();
}

extern "C" __declspec(dllexport) const ittd_backend_api *ida_ttd_backend(uint32_t abi_version)
{
    // Any core since the last layout change: what the core passes in is read
    // only up to its 'size' (setting() in sogen_emulator.cpp).
    return abi_version >= ITTD_ABI_LAYOUT ? &idattd::sogen::g_api : nullptr;
}
