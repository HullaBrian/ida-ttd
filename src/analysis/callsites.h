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
        qstring error;           // why annotate_indirect_calls returned false
    };

    // Replay the recording, see where each indirect call went, and write it
    // into the database: a repeatable comment naming the targets (all of them
    // for a site with several) and a code cross-reference to each, so the call
    // is no longer a dead end in the graph and xref list.
    //
    // A site that reached one function with a known prototype (its database
    // type, or the type library's entry for its name) gets it as its call
    // type, as IDA types a direct call to an import, so the decompiler types
    // the arguments. A site that already has a type keeps it.
    //
    // False, with out->error set and no dialog shown (the caller shows it),
    // when there is no trace, the scope is empty or the backend failed.
    //
    // 'ranges' limits which sites are annotated, not the sweep's cost: the
    // call/return callback is not maskable, so the engine replays everything.
    bool annotate_indirect_calls(TraceManager *mgr,
                                 const std::vector<std::pair<ea_t, ea_t>> &ranges,
                                 CallSiteResult *out);

    // The note an annotation put in a repeatable comment ("TTD: calls ...",
    // with its indented target lines), wherever it sits in the comment: it
    // follows the user's own text when there is some. Empty when there is
    // none.
    qstring ttd_call_note(const qstring &cmt);

    // Remove the comments, cross-references and types a previous run wrote.
    size_t clear_indirect_call_annotations();

    // Automatic resolution in the function stopped in: the auto_callsites
    // setting (TTD > Settings...).
    bool callsites_auto_enabled();
    // Annotated by auto_annotate_function() in this session.
    bool callsites_function_done(ea_t start);
    // The session ended: drop the sweeps kept for it.
    void callsites_session_ended();

    // Annotate the indirect calls made from [start, end). The first function
    // in a module (or in no module) pays for a sweep of the whole scope behind
    // a cancellable wait box; later ones reuse it. False when it did not
    // complete.
    bool auto_annotate_function(TraceManager *mgr, ea_t start, ea_t end);
}
