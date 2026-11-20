#pragma once

#include "common/pch.h"

namespace idattd
{
    // Pseudocode coverage highlighting.
    //
    // Many IDA installs have no Hex-Rays, so everything here is a no-op when
    // init_decompiler() reports it absent.
    //
    // Nothing new is stored: coverage is already a per-instruction color in
    // the database, and a pseudocode line takes the color of the addresses it
    // came from.
    bool init_decompiler();     // true when Hex-Rays is present and hooked
    void term_decompiler();

    // Called with the function's entry when the user renames, retypes or
    // comments a variable, or comments the pseudocode: edits Hex-Rays keeps
    // itself, with no IDB event. Null to stop.
    void set_function_edit_hook(void (*hook)(ea_t func_ea));

    // Decompile every open pseudocode view again: types changed under it.
    void redecompile_pseudocode_views();

    // Repaint every open pseudocode view in place and redraw it. Call after a
    // coverage sweep or an annotation pass changes what the database says.
    void refresh_pseudocode_views();

    // Something a paint reads changed without an IDB event (the conditional
    // moves found never to have moved), so the next refresh repaints even a
    // view painted since the last color change.
    void pseudocode_paint_inputs_changed();

    // Close, without saving to the desktop, pseudocode views of code that
    // exists only while a trace is loaded. Called at session end: runtime
    // allocated code has no segment afterwards, and a view restored from the
    // desktop would fail with "cannot convert to microcode" on every touch.
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

    // Show the function containing ea in this pseudocode view, caret on the
    // statement holding ea, without opening another window. False when the function cannot be
    // decompiled; the view is then left as it was.
    bool show_in_pseudocode(TWidget *view, ea_t ea);
}
