#pragma once

#include "common/pch.h"
#include "core/backend.h"

namespace idattd
{
    class TraceManager;

    // Forking the recording: replay it to a position, change registers and
    // memory there, and run on, recording into a new trace (ITTD_CAP_FORK).

    // Numbers are hex, as IDA shows them (0x optional); 0n or # for decimal.
    //
    // "rax=1 rcx=0x10, rip=140001000" into register edits. Names are the
    // 64-bit general registers, rip and rflags; separators are spaces, commas
    // or semicolons. False with 'err' set on anything it cannot read.
    bool parse_fork_registers(const char *text, std::vector<std::pair<int, uint64_t>> *out, qstring *err);

    // Memory edits, separated by semicolons or new lines:
    //   0x140007000 = 90 90 C3        bytes, in hex
    //   0x140007000 = q:0x1234        a little-endian 64-bit value
    //   0x140007000 = d:5             a little-endian 32-bit value
    bool parse_fork_memory(const char *text, std::vector<std::pair<ea_t, bytevec_t>> *out, qstring *err);

    // Where a fork of the current recording at 'at' goes by default: next to
    // the recording, named after it and the position.
    qstring default_fork_path(TraceManager *mgr, Position at);

    // Run the fork behind a cancellable wait box. Cancelling during the
    // recording keeps what was recorded so far, as a complete trace.
    ForkResult run_fork(TraceManager *mgr, const ForkRequest &req);

    // Start another IDA on 'path'. False when it could not be started.
    bool open_in_new_ida(const char *path);
}
