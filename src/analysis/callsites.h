#pragma once

#include "common/pch.h"

namespace idattd
{
    class TraceManager;

    struct CallSiteResult
    {
        size_t sites      = 0;   // indirect call sites that resolved to something
        size_t targets    = 0;   // distinct targets across all of them
        size_t polymorphic = 0;  // sites that reached more than one target
        size_t undefined   = 0;  // call sites IDA has no instruction at
        size_t typed       = 0;  // sites given their callee's prototype
        bool   truncated  = false;
        bool   cancelled  = false;
    };

    // Replay the recording, watch where every indirect call actually went, and
    // write that back into the database: a repeatable comment naming the targets,
    // and a real code cross-reference to each one so the call stops being a dead
    // end in the graph and in the xref list.
    //
    // A site that reached several targets keeps all of them, and the comment
    // says so.
    //
    // A site that reached exactly one function with a known prototype -- its
    // own type in the database, or the type library's entry for its name, as
    // for an API export -- gets that prototype as its call type, the way IDA
    // types a direct call to an import, so the decompiler types the arguments
    // (a WinHttpOpen through a function pointer reads as one). A site that
    // already has a type keeps it.
    //
    // 'ranges' limits which call sites are annotated. It cannot make the sweep
    // cheaper: the call/return callback is not a maskable event, so the engine
    // has nothing to filter on and replays everything either way.
    bool annotate_indirect_calls(TraceManager *mgr,
                                 const std::vector<std::pair<ea_t, ea_t>> &ranges,
                                 CallSiteResult *out);

    // Remove the comments, cross-references and call types a previous run
    // wrote.
    size_t clear_indirect_call_annotations();

    // Automatic resolution in the function you stop in: the auto_callsites
    // setting (TTD > Settings...).
    bool callsites_auto_enabled();
    // Annotated by auto_annotate_function() in this session.
    bool callsites_function_done(ea_t start);
    // The session ended: drop the sweeps kept for it.
    void callsites_session_ended();

    // Annotate the indirect calls made from [start, end). The first function
    // in a module pays for a sweep of that whole module (or of all code in no
    // module), shown behind a cancellable wait box; later ones in it are
    // answered from that sweep. False when it did not complete.
    bool auto_annotate_function(TraceManager *mgr, ea_t start, ea_t end);
}
