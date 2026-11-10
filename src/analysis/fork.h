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
    // "rax=1 rcx=0x10, rip=140001000" into register edits: the 64-bit general
    // registers, rip and rflags, separated by spaces, commas or semicolons.
    // False with 'err' set on anything unreadable.
    bool parse_fork_registers(const char *text, std::vector<std::pair<int, uint64_t>> *out, qstring *err);

    // Memory edits, separated by semicolons or new lines:
    //   0x140007000 = 90 90 C3        bytes, in hex
    //   0x140007000 = q:0x1234        a little-endian 64-bit value
    //   0x140007000 = d:5             a little-endian 32-bit value
    bool parse_fork_memory(const char *text, std::vector<std::pair<ea_t, bytevec_t>> *out, qstring *err);

    // Default path for a fork at 'at': beside the recording, named after it
    // and the position.
    qstring default_fork_path(TraceManager *mgr, Position at);

    // Run the fork behind a cancellable wait box. Cancelling while recording
    // keeps what was recorded so far as a complete trace.
    ForkResult run_fork(TraceManager *mgr, const ForkRequest &req);

    // The first loaded backend that can record a program from its start
    // (Sogen's), or nullptr. Loads the backend modules if need be.
    ITraceBackend *find_recorder();

    // Whether a program in emulation root 'root' can see 'path' (a file or
    // folder): it is inside <root>\filesys\, or it is a guest path the root
    // has (c:\x.exe as <root>\filesys\c\x.exe). The backend turns the first
    // into the second.
    bool visible_in_emulation_root(const char *root, const char *path);

    enum class PlaceResult
    {
        Placed,     // copied there
        Same,       // an identical copy was there already
        Differs,    // another file is there; nothing done (replace to overwrite)
        Failed,     // 'err' says why
    };
    // Copy 'program' into emulation root 'root' at guest folder 'guest_dir'
    // ("C:\samples"; "\samples" and "samples" are on C:), creating the folder:
    // a program recorded in the root sees only the root. '*placed' is the
    // copy's host path (inside <root>\filesys). A folder climbing out of the
    // root ("..") is refused.
    PlaceResult place_in_emulation_root(const char *root, const char *program, const char *guest_dir,
                                        bool replace, qstring *placed, qstring *err);

    // Record a program behind a cancellable wait box (see RecordRequest).
    // Cancelling keeps what ran so far as a complete recording.
    ForkResult run_record(const RecordRequest &req);

    // "rax=0x1, 8 bytes at 0x1400070A8", or "no changes".
    qstring describe_fork_changes(const ForkRequest &req);

    // Start another IDA on 'path'. False when it could not be started.
    bool open_in_new_ida(const char *path);
}
