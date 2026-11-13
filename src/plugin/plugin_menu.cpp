// The TTD menu: rebuilt whole whenever its contents change, with the
// session's submenus, Backends and Settings.
#include "plugin/plugin_internal.h"
#include "common/installer_labels.h"
#include "common/python_eval.h"
#include "ui/icons.hh"

namespace idattd
{
    static const char *TTD_MENU_PATH = "TTD/";      // path items attach under

    const SubmenuDesc TTD_SUBMENUS[] =
    {
        // Among the items with icons, so each has one too.
        { SUB_FORKS,    "Forks",             true,  icons_fork_svg },
        // Beside Syscalls and Handles, in their section.
        { SUB_MEMORY,   "Memory",            false, icons_memory_map_svg },
        { SUB_WRITTEN,  "Written data",      false, icons_written_data_svg },
        // Everything that changes the database, in a section of its own.
        { SUB_ANNOTATE, "Annotate database", true,  icons_annotate_svg },
    };

    // ida_ttd_qt.<fn>(args...) (scripts/ida_ttd_qt.py), for the Qt changes
    // the SDK has no call for. The arguments go as quoted string literals.
    bool call_qt(const char *fn, std::initializer_list<const char *> args)
    {
        if ( !python_available() )
            return false;
        qstring err;
        if ( call_py("ida_ttd_qt", fn, args, &err) )
            return true;
        msg("[ida-ttd] ida_ttd_qt.%s failed: %s\n", fn, err.c_str());
        return false;
    }

    // create_menu() takes no icon.
    static void set_submenu_icon(const char *label, const char *svg)
    {
        call_qt("set_submenu_icon", { TTD_MENU, label, svg });
    }

    struct MenuSepHandler : public action_handler_t
    {
        int idaapi activate(action_activation_ctx_t *) override { return 0; }
        action_state_t idaapi update(action_update_ctx_t *) override { return AST_DISABLE_ALWAYS; }
    };
    static MenuSepHandler g_menuSep;

    // TTD > Settings...: the IDA Settings Editor on ida-ttd's settings, or how
    // to change them without it (scripts/ida_ttd_settings.py).
    struct SettingsHandler : public action_handler_t
    {
        int idaapi activate(action_activation_ctx_t *) override
        {
            qstring err;
            if ( !eval_py("import ida_ttd_settings\n"
                          "ida_ttd_settings.show_editor()\n", &err) )
                warning("ida-ttd's settings are changed with "
                        "\"hcli plugin config ida-ttd set KEY VALUE\"%s%s",
                        err.empty() ? "" : "\n\n", err.c_str());
            return 1;
        }
        action_state_t idaapi update(action_update_ctx_t *) override { return AST_ENABLE_ALWAYS; }
    };
    static SettingsHandler g_settingsHandler;

    void Plugin::rebuild_ttd_menu()
    {
        // A headless idalib worker has no menus to build, and the plugin's
        // teardown deletes them.
        if ( !is_idaq() || m_tearingDown )
            return;

        // The actions that belong to the menu rather than to a session, once.
        if ( !m_menuActionsRegistered )
        {
            m_menuActionsRegistered = true;
            for ( const char *sep : SUBMENU_SEP_ACTIONS )
                register_action(ACTION_DESC_LITERAL_PLUGMOD(sep, SEP_CARRIER_LABEL, &g_menuSep, this,
                                                            nullptr, nullptr, -1));
            register_action(ACTION_DESC_LITERAL_PLUGMOD(SUB_BACKENDS_SEP, SEP_CARRIER_LABEL, &g_menuSep, this,
                                                        nullptr, nullptr, -1));
            // Section headings: always disabled, so they read as labels.
            register_action(ACTION_DESC_LITERAL_PLUGMOD(
                actions::BACKEND_HDR_MS, "Microsoft TTD", &g_menuSep, this, nullptr, nullptr, -1));
            register_action(ACTION_DESC_LITERAL_PLUGMOD(
                actions::BACKEND_HDR_SOGEN, "Sogen", &g_menuSep, this, nullptr, nullptr, -1));
            register_action(ACTION_DESC_LITERAL_PLUGMOD(
                actions::INSTALL_RUNTIME, INSTALL_RUNTIME_LABEL,
                &m_installRuntime, this, nullptr, INSTALL_RUNTIME_TOOLTIP, -1));
            register_action(ACTION_DESC_LITERAL_PLUGMOD(
                actions::INSTALL_SOGEN, INSTALL_SOGEN_LABEL,
                &m_installSogen, this, nullptr, INSTALL_SOGEN_TOOLTIP, -1));
            register_action(ACTION_DESC_LITERAL_PLUGMOD(
                actions::RECORD_PROGRAM, "Record a program with Sogen...",
                &m_recordProgram, this, nullptr,
                "Run a program from its start in Sogen's emulator and record it into a "
                "new Sogen recording (.sogttd), with the Sogen settings: network access, "
                "checkpoint interval, what is recorded", -1));
            register_action(ACTION_DESC_LITERAL_PLUGMOD(
                SETTINGS_ACTION, "Settings...", &g_settingsHandler, this, nullptr,
                "ida-ttd's settings (symbol downloads, automatic coverage and call-site "
                "comments, fork length, Sogen recording, ...), in the IDA Settings Editor. "
                "Changes apply from the next stop of the replay", -1));
        }

        // From scratch, in order. Deleting a menu takes its items with it;
        // the actions stay registered.
        delete_menu(SUB_BACKENDS);
        for ( const SubmenuDesc &s : TTD_SUBMENUS )
            delete_menu(s.name);
        delete_menu(TTD_MENU);

        // create_menu() first: attach_action_to_menu() resolves its path
        // against existing menus, so attaching under "TTD/" before the menu
        // exists silently does nothing.
        //
        // No position argument: create_menu() would read one as an existing
        // menu or item and nest TTD inside it. Without one, IDA appends the
        // menu to the menu bar.
        create_menu(TTD_MENU, "TTD");
        bool above = false;     // anything in the menu yet, to separate from

        if ( m_actionsRegistered )
        {
            attach_session_menu();
            above = true;
        }

        // Backends: one section per backend, separated. The separator above
        // the submenu is carried by a hidden action (see SEP_CARRIER_LABEL).
        if ( above )
        {
            attach_action_to_menu(TTD_MENU_PATH, SUB_BACKENDS_SEP, SETMENU_APP | SETMENU_ENSURE_SEP);
            update_action_visibility(SUB_BACKENDS_SEP, false);
        }
        create_menu(SUB_BACKENDS, SUB_BACKENDS_LABEL, TTD_MENU_PATH);
        qstring bpath;
        bpath.sprnt("%s%s/", TTD_MENU_PATH, SUB_BACKENDS_LABEL);
        attach_action_to_menu(bpath.c_str(), actions::BACKEND_HDR_MS, SETMENU_APP);
        attach_action_to_menu(bpath.c_str(), actions::INSTALL_RUNTIME, SETMENU_APP);
        attach_action_to_menu(bpath.c_str(), actions::BACKEND_HDR_SOGEN, SETMENU_APP | SETMENU_ENSURE_SEP);
        attach_action_to_menu(bpath.c_str(), actions::INSTALL_SOGEN, SETMENU_APP);
        attach_action_to_menu(bpath.c_str(), actions::RECORD_PROGRAM, SETMENU_APP);
        attach_action_to_menu(TTD_MENU_PATH, SETTINGS_ACTION, SETMENU_APP);
    }

    // The session's part of the TTD menu: every menu row of the action
    // table, in its submenu.
    void Plugin::attach_session_menu()
    {
        CASSERT(qnumber(SUBMENU_SEP_ACTIONS) >= qnumber(TTD_SUBMENUS));
        // A recording that cannot be forked (Microsoft's) gets no Forks menu.
        const bool can_fork = can_fork_recording();
        int wanted = 0, attached = 0;
        const char *open_sub = nullptr;     // the submenu the last row went in
        qstring path = TTD_MENU_PATH;
        for ( const ActionDesc &d : m_actions )
        {
            if ( !d.on_menu || (d.submenu == SUB_FORKS && !can_fork) )
                continue;
            if ( d.submenu != open_sub )
            {
                open_sub = d.submenu;
                path = TTD_MENU_PATH;
                for ( size_t i = 0; open_sub != nullptr && i < qnumber(TTD_SUBMENUS); i++ )
                {
                    const SubmenuDesc &s = TTD_SUBMENUS[i];
                    if ( strcmp(s.name, open_sub) != 0 )
                        continue;
                    if ( s.new_group )
                    {
                        attach_action_to_menu(TTD_MENU_PATH, SUBMENU_SEP_ACTIONS[i],
                                              SETMENU_APP | SETMENU_ENSURE_SEP);
                        update_action_visibility(SUBMENU_SEP_ACTIONS[i], false);
                    }
                    create_menu(s.name, s.label, TTD_MENU_PATH);
                    if ( s.icon_svg != nullptr )
                        set_submenu_icon(s.label, s.icon_svg);
                    path.sprnt("%s%s/", TTD_MENU_PATH, s.label);
                }
            }
            wanted++;
            if ( attach_action_to_menu(path.c_str(), d.id,
                                       SETMENU_APP | (d.new_group ? SETMENU_ENSURE_SEP : 0)) )
                attached++;
        }
        if ( attached != wanted )
            msg("[ida-ttd] only %d of %d TTD menu entries could be attached.\n",
                attached, wanted);
    }
}
