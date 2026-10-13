#pragma once

#include "common/pch.h"

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

    // Decompile every open pseudocode view again: types changed under it.
    void redecompile_pseudocode_views();

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

    // Every open pseudocode view. Asks IDA by window title rather than
    // remembering what was seen opening: IDA's source-level debugging opens
    // views without Hex-Rays reporting them.
    void list_pseudocode_views(std::vector<TWidget *> &out);

    // The entry of the function a pseudocode view shows; BADADDR when the
    // widget is not a pseudocode view or shows nothing.
    ea_t pseudocode_function(TWidget *view);

    // Whether the function starting at func_ea decompiles. Silent: a failure
    // shows no dialog. Successes are cached by Hex-Rays, so asking again is cheap.
    bool can_decompile(ea_t func_ea);

    // Show the function containing ea in this pseudocode view, caret on ea,
    // without opening another window. False when the function cannot be
    // decompiled; the view is then left as it was.
    bool show_in_pseudocode(TWidget *view, ea_t ea);
}
