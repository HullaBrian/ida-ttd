#pragma once

// The labels and tooltips of TTD > Backends' two installers. The main plugin
// shows them in the TTD menu of a database; the setup component
// (ida-ttd-loader-setup.dll) shows the same actions while no database is
// open. Written once here so the two menus cannot drift apart.
namespace idattd
{
    constexpr const char INSTALL_RUNTIME_LABEL[] = "Install the TTD runtime (WinDbg)...";
    constexpr const char INSTALL_RUNTIME_TOOLTIP[] =
        "Get Microsoft's TTD replay runtime, which Microsoft TTD recordings "
        "need: copied from an installed WinDbg, or WinDbg downloaded from "
        "Microsoft once you accept its license";

    constexpr const char INSTALL_SOGEN_LABEL[] = "Install the Sogen backend...";
    constexpr const char INSTALL_SOGEN_TOOLTIP[] =
        "The package includes the Sogen backend. This installs another build "
        "of it (ida-ttd-sogen.dll, or a release zip holding it) into "
        "ida-ttd\\backends in your IDA user directory, where it takes the "
        "packaged one's place";
}
