#pragma once

// What the plugin's files share. plugin.cpp has the constructor,
// destructor and entry point; plugin_actions.cpp the action table, the
// toolbar and the position readout; plugin_menu.cpp the TTD menu;
// plugin_session.cpp starting, switching and offering a replay;
// plugin_stopviews.cpp the work around a stop (views, coverage, kept
// functions); plugin_events.cpp the IDA notifications. The TTD menu's
// names are here because the action table, the menu and the destructor
// all use them; anything used by one file stays in it.
#include "plugin/plugin.h"

#include <initializer_list>

namespace idattd
{
    // The top-level TTD menu, beside File / Edit / Jump.
    //
    // Name and label are both "TTD" on purpose: whether a path resolves by
    // name or label, "TTD/" then means this menu. (Toolbars are a separate
    // namespace, "TTDToolBar".)
    inline const char *const TTD_MENU = "TTD";

    // Submenus of the TTD menu, in display order. An ActionDesc names one by
    // 'name'; a submenu's rows are consecutive in the table. Paths resolve by
    // label, so a label holds no '/' or '&'.
    inline const char *const SUB_FORKS    = "TTDForks";
    inline const char *const SUB_MEMORY   = "TTDMemory";
    inline const char *const SUB_WRITTEN  = "TTDWritten";
    inline const char *const SUB_ANNOTATE = "TTDAnnotate";
    // Not a session submenu: always there, last, built by rebuild_ttd_menu().
    inline const char *const SUB_BACKENDS       = "TTDBackends";
    inline const char *const SUB_BACKENDS_LABEL = "Backends";
    struct SubmenuDesc
    {
        const char *name;
        const char *label;
        bool        new_group;      // separator above it in the TTD menu
        const char *icon_svg;       // nullptr: none
    };
    // In display order; defined in plugin_menu.cpp, beside the icons
    // it names.
    extern const SubmenuDesc TTD_SUBMENUS[4];

    // A separator goes above a menu item, not a submenu, so the one above a
    // submenu belongs to a hidden action just above it, one per submenu (an
    // action goes on a menu once). It needs a real label: IDA 9.4 refuses to
    // attach an action labelled "-", separator and all.
    inline constexpr char SEP_CARRIER_LABEL[] = "separator";
    inline const char *const SUBMENU_SEP_ACTIONS[] =
    {
        "idattd:menu_sep_0", "idattd:menu_sep_1", "idattd:menu_sep_2", "idattd:menu_sep_3",
    };
    inline constexpr char SUB_BACKENDS_SEP[] = "idattd:menu_sep_backends";

    inline constexpr char SETTINGS_ACTION[] = "idattd:settings";

    // ida_ttd_qt.<fn>(args...), for the Qt changes the SDK has no call for
    // (plugin_menu.cpp).
    bool call_qt(const char *fn, std::initializer_list<const char *> args);

    // The live plugin, or nullptr once it is gone (plugin.cpp).
    extern Plugin *g_live_plugin;
}
