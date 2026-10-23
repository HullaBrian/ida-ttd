#pragma once

#include "common/pch.h"

namespace idattd
{
    // Fetching PDBs off the symbol server ourselves, on a worker thread.
    //
    // IDA's PDB plugin downloads on the thread that calls it, which is the main
    // thread, so a slow or unreachable symbol server freezes the whole UI for as
    // long as the fetch takes. Nothing in that plugin can be moved off the main
    // thread, but the download can: it is ordinary file I/O over HTTPS and
    // touches no IDA state.
    //
    // So the download happens here, in the background, into a local store laid
    // out exactly like a symbol server. The plugin is then only ever asked for a
    // PDB that is already on disk, which it resolves without touching the
    // network. Nothing new leaves the machine: the same module identities were
    // already being sent to the same server, just from the main thread.

    // The local store, created on first use. Mirrors the symbol-server layout
    // (<store>/<name>/<signature>/<name>) so other tools can read it too.
    qstring symbol_store_dir();

    // Where a PDB with this identity belongs in the store.
    qstring symbol_store_path(const char *name, const char *signature);

    // Put the store on this process's _NT_SYMBOL_PATH, ahead of whatever was
    // there, so IDA's PDB plugin looks in it before reaching for the network.
    // Anything the user had configured is kept after it. Call once per session.
    void symsrv_install_path();

    // Ask for a PDB. Returns immediately.
    //
    //   Cached   the file is already in the store; load it now
    //   Fetching a worker is downloading it; symsrv_take_completed() will report
    //   Failed   there is nothing to wait for (a bad identity, or a fetch of
    //            it already running; a fetch that failed may be asked again)
    //
    // A few downloads run at a time, and one the server did not answer is
    // tried again after a pause before it is reported as failed.
    //   Off      not in the store, and downloads are turned off
    enum class FetchState { Cached, Fetching, Failed, Off };
    FetchState fetch_pdb(const char *name, const char *signature, ea_t base);

    // The symbol_downloads and symbol_server settings, before any fetch (and
    // before symsrv_install_path). False when 'url' is not an HTTP(S) URL,
    // which keeps the server in use.
    bool symsrv_configure(bool enabled, const char *url);

    // The server PDBs come from, as a URL.
    qstring symsrv_server_url();

    // One finished download, taken off the completion queue.
    struct FetchResult
    {
        ea_t    base = BADADDR;     // the module it was wanted for
        qstring name;               // e.g. "ntdll.pdb"
        qstring path;               // where it landed, empty when it failed
        qstring error;              // why, when it failed
    };

    // Drain the finished downloads. Call from the main thread only: it is what
    // hands work back to IDA. Returns the number of results written to 'out'.
    size_t symsrv_take_completed(std::vector<FetchResult> *out);

    // How many downloads are still running.
    size_t symsrv_pending();

    // Stop accepting new work, ask running fetches to give up, and wait for the
    // threads to finish. Safe to call more than once.
    void symsrv_shutdown();
}
