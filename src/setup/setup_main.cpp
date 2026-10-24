// ---------------------------------------------------------------------------
// ida-ttd loader setup
//
// Puts the trace loader where IDA looks for loaders. HCLI installs only into
// plugins\ida-ttd\ (no install hook), while IDA finds loaders only in the
// loaders\ folders of $IDAUSR and the IDA directory. So the package carries
// ttd-loader.dll beside this component, which copies it into $IDAUSR\loaders\
// as IDA starts.
//
// A separate plugin because of timing: PLUGIN_FIX plugins load at startup,
// before File > Open or a command-line file, while the main plugin loads with
// a database. From there, a fresh install would not recognize a recording
// until some other database had been opened.
//
// It also shows TTD > Backends while no database is open (the main plugin's
// menu, with the same installers, exists only with a database). The menu is
// removed as a database opens and restored when it closes. Without the GUI or
// the installer script, init() returns nullptr once the loader is in place,
// and nothing stays loaded.
// ---------------------------------------------------------------------------
#include "common/pch.h"
#include <diskio.hpp>
#include <expr.hpp>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <system_error>
#include <vector>

namespace fs = std::filesystem;

namespace
{
    const wchar_t LOADER_NAME[] = L"ttd-loader.dll";

    fs::path module_dir()
    {
        HMODULE self = nullptr;
        wchar_t buf[MAX_PATH * 2];
        if ( !GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
                               | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                 reinterpret_cast<LPCWSTR>(&module_dir), &self) )
            return {};
        DWORD n = GetModuleFileNameW(self, buf, qnumber(buf));
        if ( n == 0 || n >= qnumber(buf) )
            return {};
        return fs::path(std::wstring(buf, n)).parent_path();
    }

    fs::path utf8_path(const char *s)
    {
        qwstring w;
        utf8_utf16(&w, s);
        return fs::path(reinterpret_cast<const wchar_t *>(w.c_str()));
    }

    qstring display(const fs::path &p)
    {
        qstring out;
        utf16_utf8(&out, reinterpret_cast<const wchar16_t *>(p.c_str()));
        return out;
    }

    bool read_file(const fs::path &p, std::vector<char> *out)
    {
        std::ifstream f(p, std::ios::binary);
        if ( !f )
            return false;
        out->assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
        return !f.bad();
    }

    // Whether 'installed' is byte-identical to the bundled loader. Content,
    // not timestamp: an upgrade can carry an older file time, and a downgrade
    // is a change too.
    bool same_contents(const fs::path &bundled, const fs::path &installed)
    {
        std::error_code ec;
        if ( !fs::is_regular_file(installed, ec) )
            return false;
        if ( fs::file_size(bundled, ec) != fs::file_size(installed, ec) || ec )
            return false;
        std::vector<char> a, b;
        return read_file(bundled, &a) && read_file(installed, &b) && a == b;
    }

    // Copy 'bundled' over 'target' without a half-written DLL ever sitting in
    // loaders\: stage under a name IDA does not load, then rename into place.
    // A loader mapped by another IDA cannot be replaced but can be renamed, so
    // it is moved aside and deleted on a later start.
    bool install(const fs::path &bundled, const fs::path &target, qstring *err)
    {
        // The process id keeps two IDAs starting at once from writing the
        // same staging file; the name still does not end in .dll.
        const fs::path staged = fs::path(target).concat(L"." + std::to_wstring(GetCurrentProcessId()) + L".new");
        const fs::path aside = fs::path(target).concat(L".old");
        std::error_code ec;
        fs::remove(aside, ec);      // left by an earlier update; fails while still mapped
        if ( !fs::copy_file(bundled, staged, fs::copy_options::overwrite_existing, ec) )
        {
            err->sprnt("could not write %s: %s", display(staged).c_str(), ec.message().c_str());
            return false;
        }
        const DWORD flags = MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH;
        if ( MoveFileExW(staged.c_str(), target.c_str(), flags) )
            return true;
        if ( MoveFileExW(target.c_str(), aside.c_str(), MOVEFILE_REPLACE_EXISTING) )
        {
            if ( MoveFileExW(staged.c_str(), target.c_str(), flags) )
                return true;
            // Put the old loader back rather than leave none.
            DWORD e = GetLastError();
            MoveFileExW(aside.c_str(), target.c_str(), 0);
            SetLastError(e);
        }
        err->sprnt("could not replace %s (error %lu)", display(target).c_str(), GetLastError());
        fs::remove(staged, ec);
        return false;
    }

    // Copy the bundled loader into $IDAUSR\loaders\ when it is not already
    // there as it is. 'dir' is this DLL's folder.
    void install_loader(const fs::path &dir)
    {
        // Only a package install has the loader beside this DLL; elsewhere
        // (a build folder copied into plugins\) there is nothing to do.
        const fs::path bundled = dir / LOADER_NAME;
        std::error_code ec;
        if ( !fs::is_regular_file(bundled, ec) )
            return;

        // A loader the user put in the IDA directory wins; a second copy would
        // list the format twice in File > Open.
        if ( fs::is_regular_file(utf8_path(idadir(LDR_SUBDIR)) / LOADER_NAME, ec) )
            return;

        const fs::path loaders = utf8_path(get_user_idadir()) / L"loaders";
        const fs::path target = loaders / LOADER_NAME;
        if ( same_contents(bundled, target) )
        {
            fs::remove(fs::path(target).concat(L".old"), ec);
            return;
        }

        const bool update = fs::exists(target, ec);
        fs::create_directories(loaders, ec);
        qstring err;
        if ( install(bundled, target, &err) )
            msg("[ida-ttd] %s the trace loader in %s: File > Open now recognizes "
                ".run and .sogttd recordings. It is not removed when the plugin is "
                "uninstalled; delete it by hand then.%s\n",
                update ? "Updated" : "Installed", display(loaders).c_str(),
                update ? "" : " TTD > Backends installs what opening them needs: "
                              "the TTD runtime for Microsoft recordings, the Sogen "
                              "backend for Sogen ones.");
        else
            msg("[ida-ttd] Could not install the trace loader, so File > Open will not "
                "recognize recordings (%s). Copy %s into %s by hand.\n",
                err.c_str(), display(bundled).c_str(), display(loaders).c_str());
    }

    //-----------------------------------------------------------------------
    // TTD > Backends while no database is open
    //-----------------------------------------------------------------------
    // Internal names distinct from the main plugin's "TTD" menu, so the two
    // are never confused while both exist. The labels (used in the paths
    // below) match, so the menu looks the same with or without a database.
    const char MENU[]            = "idattd_setup:TTD";
    const char SUBMENU[]         = "idattd_setup:Backends";
    const char ACT_RUNTIME[]     = "idattd_setup:install_runtime";
    const char ACT_SOGEN[]       = "idattd_setup:install_sogen";

    // Runs one function of ida_ttd_runtime (in ida-ttd-python\ beside the main
    // plugin) through IDAPython, like the main plugin's installer actions. With
    // no database open that folder is not on sys.path yet, so the snippet adds
    // it.
    struct installer_t : public action_handler_t
    {
        qstring pydir;          // forward slashes, quotes escaped
        const char *func;       // "install_runtime" or "install_sogen"
        const char *what;       // for the failure message

        installer_t(const char *f, const char *w) : func(f), what(w) {}

        int idaapi activate(action_activation_ctx_t *) override
        {
            extlang_object_t py = find_extlang_by_name("Python");
            if ( py == nullptr || py->eval_snippet == nullptr )
            {
                warning("Installing %s needs IDAPython, which is not available.", what);
                return 1;
            }
            qstring code;
            code.sprnt("import sys\n"
                       "if '%s' not in sys.path:\n"
                       "    sys.path.append('%s')\n"
                       "import ida_ttd_runtime\n"
                       "ida_ttd_runtime.%s()\n", pydir.c_str(), pydir.c_str(), func);
            qstring err;
            if ( !py->eval_snippet(code.c_str(), &err) )
                warning("Installing %s failed: %s", what, err.c_str());
            return 1;
        }

        action_state_t idaapi update(action_update_ctx_t *) override
        {
            return AST_ENABLE_ALWAYS;
        }
    };

    struct setup_plugin_t : public plugmod_t, public event_listener_t
    {
        installer_t runtime{ "install_runtime", "the TTD runtime" };
        installer_t sogen{ "install_sogen", "the Sogen backend" };
        qtimer_t    timer = nullptr;
        bool        db_open = false;
        bool        shown = false;

        explicit setup_plugin_t(const qstring &pydir)
        {
            runtime.pydir = pydir;
            sogen.pydir = pydir;
            register_action(ACTION_DESC_LITERAL_PLUGMOD(
                ACT_RUNTIME, "Install the TTD runtime (WinDbg)...", &runtime, this, nullptr,
                "Get Microsoft's TTD replay runtime, which Microsoft TTD recordings "
                "need: copied from an installed WinDbg, or WinDbg downloaded from "
                "Microsoft once you accept its license", -1));
            register_action(ACTION_DESC_LITERAL_PLUGMOD(
                ACT_SOGEN, "Install the Sogen backend...", &sogen, this, nullptr,
                "The package includes the Sogen backend. This installs another build "
                "of it (ida-ttd-sogen.dll, or a release zip holding it) into "
                "ida-ttd\\backends in your IDA user directory, where it takes the "
                "packaged one's place", -1));
            ::hook_event_listener(HT_UI, this, this);
            // Not from init(): the menu bar may not exist yet. A command-line
            // file may open before or after this fires; ui_initing_database
            // removes the menu again if after.
            timer = register_timer(0, [](void *ud) -> int
            {
                setup_plugin_t *self = static_cast<setup_plugin_t *>(ud);
                self->timer = nullptr;
                if ( !self->db_open )
                    self->show_menu();
                return -1;
            }, this);
        }

        ~setup_plugin_t() override
        {
            if ( timer != nullptr )
                unregister_timer(timer);
            hide_menu();
            ::unhook_event_listener(HT_UI, this);
        }

        bool idaapi run(size_t) override { return true; }

        void show_menu()
        {
            if ( shown )
                return;
            // No position: appended to the menu bar, like the main plugin's.
            create_menu(MENU, "TTD");
            create_menu(SUBMENU, "Backends", "TTD/");
            attach_action_to_menu("TTD/Backends/", ACT_RUNTIME, SETMENU_APP);
            attach_action_to_menu("TTD/Backends/", ACT_SOGEN, SETMENU_APP);
            shown = true;
        }

        void hide_menu()
        {
            if ( !shown )
                return;
            delete_menu(SUBMENU);
            delete_menu(MENU);
            shown = false;
        }

        ssize_t idaapi on_event(ssize_t code, va_list) override
        {
            switch ( code )
            {
                case ui_initing_database:
                    db_open = true;
                    hide_menu();
                    break;
                case ui_database_closed:
                    db_open = false;
                    show_menu();
                    break;
            }
            return 0;
        }
    };
}

static plugmod_t *idaapi init()
{
    const fs::path dir = module_dir();
    if ( dir.empty() )
        return nullptr;
    install_loader(dir);

    // The menu needs the GUI and the installer script, which the package puts
    // in ida-ttd-python\ one level up.
    if ( !is_idaq() )
        return nullptr;
    std::error_code ec;
    const fs::path pydir = dir.parent_path() / L"ida-ttd-python";
    if ( !fs::is_regular_file(pydir / L"ida_ttd_runtime.py", ec) )
        return nullptr;
    qstring py = display(pydir);
    py.replace("\\", "/");      // a Python string literal without escapes...
    py.replace("'", "\\'");     // ...except a quote (C:/Users/O'Neil)
    return new setup_plugin_t(py);
}

plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,
    PLUGIN_FIX | PLUGIN_HIDE | PLUGIN_MULTI,
    init,
    nullptr,
    nullptr,
    "Installs the ida-ttd trace loader",
    nullptr,
    "ida-ttd loader setup",
    nullptr,
};
