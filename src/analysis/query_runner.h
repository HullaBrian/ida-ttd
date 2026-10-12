#pragma once

#include "common/pch.h"
#include "core/backend.h"

namespace idattd
{
    // Run a whole-trace query behind a cancellable wait box.
    //
    // 'query' runs on a worker thread and is handed a ProgressSink; the main
    // thread owns the wait box, shows the percentage the query reports and
    // passes Cancel back through the sink. The sink only stores and reads
    // atomics, so a backend may call it from any thread -- the engine's own
    // replay threads included -- and the query must not touch IDA itself.
    //
    // Why a worker: a query can take minutes, and on the main thread IDA's
    // message loop would be blocked for all of it -- no repaint, no Cancel.
    //
    // 'what' is the wait-box line with no punctuation and no percentage, e.g.
    // "Measuring execution coverage".
    QueryResult run_query(const char *what, const std::function<QueryResult(ProgressSink *)> &query);
}
