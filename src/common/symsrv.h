#pragma once

#include "common/pch.h"

namespace idattd
{
    // Fetching PDBs from the symbol server on worker threads.
    //
    // IDA's PDB plugin downloads on the main thread, so a slow or unreachable
    // server freezes the UI. The download itself touches no IDA state, so it
    // runs here in the background, into a local store laid out like a symbol
    // server; the PDB plugin is then only asked for files already on disk.
    // No new data leaves the machine: the same identities went to the same
    // server before, from the main thread.

    // The local store, created on first use. Mirrors the symbol-server layout
    // (<store>/<name>/<signature>/<name>) so other tools can read it too.
    qstring symbol_store_dir();

    // Where a PDB with this identity belongs in the store; empty when the name
    // or signature is not a safe path component.
    qstring symbol_store_path(const char *name, const char *signature);

    // Put the store at the front of this process's _NT_SYMBOL_PATH so IDA's
    // PDB plugin looks there before the network. The user's own path is kept
    // after it. Call once per session.
    void symsrv_install_path();

    // Ask for a PDB. Returns immediately.
    //
    //   Cached   the file is already in the store; load it now
    //   Fetching a worker is downloading it (perhaps for an earlier request,
    //            whose 'base' the completion then carries);
    //            symsrv_take_completed() reports
    //   Failed   nothing to wait for (a bad identity, or shutting down; a
    //            failed fetch may be asked for again)
    //   Off      not in the store, and downloads are turned off
    //
    // A few downloads run at a time; one the server did not answer is retried
    // after a pause before it is reported as failed.
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

    // Drain the finished downloads. Main thread only (it hands work back to
    // IDA). Returns the number of results appended to 'out'.
    size_t symsrv_take_completed(std::vector<FetchResult> *out);

    // How many downloads are still running.
    size_t symsrv_pending();

    // Stop accepting new work, ask running fetches to give up, and wait for the
    // threads to finish. Safe to call more than once.
    void symsrv_shutdown();
}
