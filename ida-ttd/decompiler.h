#pragma once

#include "pch.h"

namespace idattd
{
    // Pseudocode coverage highlighting.
    //
    // The decompiler cannot be linked against unconditionally -- plenty of IDA
    // installs have no Hex-Rays -- so everything here is a no-op when
    // init_decompiler() reports it is absent, and the plugin works exactly as
    // before in that case.
    //
    // Nothing new is stored for this. Coverage already lives in the database as
    // a per-instruction colour, so a pseudocode line is painted by asking the
    // address it came from what colour it has.
    bool init_decompiler();     // true when Hex-Rays is present and hooked
    void term_decompiler();

    // Repaint every open pseudocode view in place and redraw it. Call after a
    // coverage sweep or an annotation pass changes what the database says.
    void refresh_pseudocode_views();

    // Close pseudocode views whose function lives in memory that only exists
    // while a trace is loaded, and do it without saving them to the desktop.
    //
    // Code the recording allocated at runtime has no segment once the session
    // ends. A view left open on it is saved in the desktop, restored when the
    // database is reopened, and then greets the user with "cannot convert to
    // microcode" every time they touch that tab, because there are no bytes to
    // decompile any more. Called at session end.
    void close_volatile_pseudocode_views();
}
