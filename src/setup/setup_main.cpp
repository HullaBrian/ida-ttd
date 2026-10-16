// ---------------------------------------------------------------------------
// ida-ttd loader setup
//
// Puts the trace loader where IDA looks for loaders. HCLI installs the plugin
// package into plugins\ida-ttd\ and nowhere else (an archive cannot place a
// file outside its plugin folder, and there is no install hook), while IDA
// finds loaders only in the loaders\ folders of $IDAUSR and of the IDA
// directory. So the package carries ttd-loader.dll beside this component, and
// this component copies it into $IDAUSR\loaders\ when IDA starts.
//
// It is a separate plugin, not code in ida-ttd.dll, because of when it has to
// run: PLUGIN_FIX plugins load as IDA starts, before File > Open or a file named
// on the command line, while the main plugin loads with a database. Done from
// there, a fresh install would not recognize a recording until some other
// database had been opened once. The main plugin keeps its own flags: it is the
// debugger, and keeping it resident for the whole session would be a change of
// its own.
//
// Its whole job is in init(), which then returns nullptr (a PLUGIN_MULTI
// plugin declining to load), so nothing of it stays loaded.
// ---------------------------------------------------------------------------
#include "common/pch.h"
#include <diskio.hpp>

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

    // Whether 'installed' already holds exactly the bundled loader. Compared
    // by content, not timestamp: an upgrade can ship an older file time, and
    // a downgrade is a real change too.
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

    // Copy 'bundled' over 'target' without leaving a half-written DLL in
    // loaders\ (IDA would offer it to every file it opens): write a staging
    // file whose name IDA does not load, then rename it into place. A loader
    // another IDA process has mapped cannot be replaced but can be renamed,
    // so that one is moved aside first and deleted on a later start.
    bool install(const fs::path &bundled, const fs::path &target, qstring *err)
    {
        const fs::path staged = fs::path(target).concat(L".new");
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
}

static plugmod_t *idaapi init()
{
    const fs::path dir = module_dir();
    if ( dir.empty() )
        return nullptr;
    // Only a package install has the loader beside this DLL. A copy of this
    // DLL anywhere else (a build folder copied into plugins\ wholesale) has
    // nothing to install and stays quiet.
    const fs::path bundled = dir / LOADER_NAME;
    std::error_code ec;
    if ( !fs::is_regular_file(bundled, ec) )
        return nullptr;

    // A loader installed by hand in the IDA directory is the user's choice.
    // A second copy under $IDAUSR would put the format in File > Open twice.
    if ( fs::is_regular_file(utf8_path(idadir(LDR_SUBDIR)) / LOADER_NAME, ec) )
        return nullptr;

    const fs::path loaders = utf8_path(get_user_idadir()) / L"loaders";
    const fs::path target = loaders / LOADER_NAME;
    if ( same_contents(bundled, target) )
    {
        fs::remove(fs::path(target).concat(L".old"), ec);
        return nullptr;
    }

    const bool update = fs::exists(target, ec);
    fs::create_directories(loaders, ec);
    qstring err;
    if ( install(bundled, target, &err) )
        msg("[ida-ttd] %s the trace loader in %s: File > Open now recognizes "
            ".run and .sogttd recordings. It is not removed when the plugin is "
            "uninstalled; delete it by hand then.\n",
            update ? "Updated" : "Installed", display(loaders).c_str());
    else
        msg("[ida-ttd] Could not install the trace loader, so File > Open will not "
            "recognize recordings (%s). Copy %s into %s by hand.\n",
            err.c_str(), display(bundled).c_str(), display(loaders).c_str());
    return nullptr;
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
