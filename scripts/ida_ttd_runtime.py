"""Install the TTD replay runtime that Microsoft recordings need.

The Microsoft TTD backend replays a .run through TTDReplay.dll and
TTDReplayCPU.dll. Only Microsoft may distribute them, so ida-ttd cannot ship
them. They come with WinDbg, whose terms allow any use, commercial included
(the standalone TTD package's terms do not, so it is not used). This module
does what installing WinDbg by hand would: download WinDbg from Microsoft,
show Microsoft's license, and only after the user accepts it unpack the x64
package into

    $IDAUSR/ida-ttd/windbg/

where the backend looks for amd64/ttd/TTDReplay.dll. That folder is outside
the plugin's package folder, so upgrades leave it alone. (Earlier versions
used $IDAUSR/plugins/ida-ttd-backends/windbg/; the backend still looks there,
and install_runtime() moves it.) With WinDbg already installed (Microsoft
Store, winget, Microsoft's installer), nothing is downloaded: its amd64/ttd
folder is copied instead, since Windows will not load DLLs from an installed
package's folder into IDA.

WinDbg is published as one bundle (about 1.2 GB) with an uncompressed package
per architecture. Only the x64 package (about 400 MB) is downloaded, through
HTTP range requests: the bundle's zip directory, then the license inside the
x64 package, then that package.

In IDA: TTD > Backends > Install the TTD runtime (WinDbg)..., or
install_runtime(). The functions it calls to find, download, unpack and copy
WinDbg use no IDA module, so they can be tested outside IDA.

The same menu installs another build of the Sogen backend: install_sogen(),
at the end of this module.
"""

import ctypes
import datetime
import io
import json
import os
import re
import shutil
import threading
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

APPINSTALLER_URL = "https://aka.ms/windbg/download"
X64_PACKAGE = "windbg_win-x64.msix"
WINDBG_FAMILY = "Microsoft.WinDbg_8wekyb3d8bbwe"
RUNTIME_FILES = ("TTDReplay.dll", "TTDReplayCPU.dll")
TTD_SUBDIR = os.path.join("amd64", "ttd")
MARKER = "ida-ttd-install.json"


class InstallError(RuntimeError):
    """A step of the install failed; the message says which, for the user."""


class Cancelled(Exception):
    pass


# --------------------------------------------------------------------------
# Where a runtime already is

def has_runtime(root):
    """Whether 'root' is a WinDbg folder holding the replay runtime."""
    ttd = os.path.join(root, TTD_SUBDIR)
    return all(os.path.isfile(os.path.join(ttd, f)) for f in RUNTIME_FILES)


def installed_windbg():
    """(folder, version) of WinDbg installed as a Windows package for this
    user, if it holds the runtime, else None. Windows refuses to load a DLL
    from a package folder into a process outside the package (reading is
    allowed), so the runtime is copied out."""
    try:
        k32 = ctypes.WinDLL("kernel32")
        count = ctypes.c_uint32(0)
        buflen = ctypes.c_uint32(0)
        # The first call only sizes the buffers (ERROR_INSUFFICIENT_BUFFER).
        rc = k32.GetPackagesByPackageFamily(WINDBG_FAMILY, ctypes.byref(count), None,
                                            ctypes.byref(buflen), None)
        if rc not in (0, 122) or count.value == 0:
            return None
        names = (ctypes.c_wchar_p * count.value)()
        buf = ctypes.create_unicode_buffer(buflen.value)
        if k32.GetPackagesByPackageFamily(WINDBG_FAMILY, ctypes.byref(count), names,
                                          ctypes.byref(buflen), buf) != 0:
            return None
        for name in names[:count.value]:
            plen = ctypes.c_uint32(0)
            k32.GetPackagePathByFullName(name, ctypes.byref(plen), None)
            path = ctypes.create_unicode_buffer(plen.value or 1)
            if k32.GetPackagePathByFullName(name, ctypes.byref(plen), path) == 0 \
               and has_runtime(path.value):
                # A full name is Name_Version_Architecture_ResourceId_PublisherId.
                parts = name.split("_")
                return path.value, parts[1] if len(parts) > 1 else "?"
    except (OSError, AttributeError):
        pass
    return None


def read_marker(target):
    try:
        with open(os.path.join(target, MARKER), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


# --------------------------------------------------------------------------
# Reading Microsoft's package over HTTP

def _check_microsoft(url):
    """Refuse anything but Microsoft over HTTPS, checked after redirects."""
    u = urllib.parse.urlsplit(url)
    host = (u.hostname or "").lower()
    if u.scheme != "https" or not (host == "microsoft.com" or host.endswith(".microsoft.com")):
        raise InstallError("refusing to download from %s: not a Microsoft HTTPS address" % url)


def _open(url, headers=None, timeout=60):
    r = urllib.request.urlopen(urllib.request.Request(url, headers=headers or {}), timeout=timeout)
    _check_microsoft(r.geturl())
    return r


def resolve_latest():
    """(version, bundle URL) of the current WinDbg, from the App Installer
    file Microsoft's download link points to."""
    with _open(APPINSTALLER_URL) as r:
        root = ET.fromstring(r.read(1 << 20))
    for el in root.iter():
        if el.tag.rsplit("}", 1)[-1] == "MainBundle":
            url, version = el.get("Uri"), el.get("Version")
            if url and version:
                _check_microsoft(url)
                return version, url
    raise InstallError("Microsoft's WinDbg download page did not name a package")


class _HttpFile(io.RawIOBase):
    """A remote file read through range requests, enough for zipfile."""

    def __init__(self, url, base=0, size=None):
        self.url, self.base, self.pos = url, base, 0
        if size is None:
            req = urllib.request.Request(url, method="HEAD")
            with urllib.request.urlopen(req, timeout=60) as r:
                _check_microsoft(r.geturl())
                self.url = r.geturl()
                size = int(r.headers["Content-Length"])
        self.size = size

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.pos

    def seek(self, off, whence=0):
        self.pos = {0: off, 1: self.pos + off, 2: self.size + off}[whence]
        return self.pos

    def readinto(self, b):
        n = min(len(b), self.size - self.pos)
        if n <= 0:
            return 0
        start = self.base + self.pos
        with _open(self.url, {"Range": "bytes=%d-%d" % (start, start + n - 1)}) as r:
            if r.status != 206:
                raise InstallError("Microsoft's server does not allow partial downloads")
            data = r.read(n)
        b[:len(data)] = data
        self.pos += len(data)
        return len(data)


def _member_offset(f, info):
    """Where a zip member's data starts: after its local header."""
    f.seek(info.header_offset)
    h = f.read(30)
    if h[:4] != b"PK\x03\x04":
        raise InstallError("the WinDbg package is not laid out as expected")
    return info.header_offset + 30 + int.from_bytes(h[26:28], "little") \
        + int.from_bytes(h[28:30], "little")


class Release(object):
    """One WinDbg release: its version, its license, and where in the bundle
    the x64 package is."""

    def __init__(self, version, url):
        self.version, self.url = version, url
        raw = _HttpFile(url)
        self.url = raw.url
        f = io.BufferedReader(raw, buffer_size=1 << 16)
        try:
            info = zipfile.ZipFile(f).getinfo(X64_PACKAGE)
        except (KeyError, zipfile.BadZipFile):
            raise InstallError("the WinDbg bundle has no %s" % X64_PACKAGE)
        if info.compress_type != zipfile.ZIP_STORED:
            raise InstallError("the WinDbg bundle stores its x64 package compressed")
        self.offset = _member_offset(f, info)
        self.size = info.file_size
        self.crc = info.CRC

    def license_text(self):
        inner = io.BufferedReader(_HttpFile(self.url, self.offset, self.size), buffer_size=1 << 16)
        try:
            rtf = zipfile.ZipFile(inner).read("eula.rtf")
        except (KeyError, zipfile.BadZipFile):
            raise InstallError("the WinDbg package has no license file (eula.rtf)")
        return rtf_to_text(rtf)


def latest_release():
    return Release(*resolve_latest())


def download(release, dest, progress=None, chunk=1 << 20):
    """Download the x64 package to 'dest'. progress(done, total) is called
    as it goes; Cancelled is raised once 'progress' returns False."""
    done = 0
    crc = 0
    end = release.offset + release.size - 1
    with _open(release.url, {"Range": "bytes=%d-%d" % (release.offset, end)}, timeout=120) as r, \
         open(dest, "wb") as out:
        if r.status != 206:
            raise InstallError("Microsoft's server does not allow partial downloads")
        while done < release.size:
            data = r.read(min(chunk, release.size - done))
            if not data:
                raise InstallError("the download stopped after %d of %d bytes" % (done, release.size))
            out.write(data)
            crc = zipfile.crc32(data, crc)
            done += len(data)
            if progress is not None and progress(done, release.size) is False:
                raise Cancelled()
    # The bundle's directory holds the package's CRC; a mismatch is a broken
    # download.
    if crc != release.crc:
        raise InstallError("the download is damaged (checksum mismatch); try again")


# Package metadata, not WinDbg's files.
_PACKAGE_META = ("[Content_Types].xml",)


def _kept(name):
    """Whether a package member (its unquoted, '/'-separated name) is
    unpacked: anything under amd64/ttd, and the license beside it."""
    ttd = TTD_SUBDIR.replace(os.sep, "/").lower() + "/"
    n = name.replace("\\", "/").lower()
    return n.startswith(ttd) or n == "eula.rtf"


def unpack(package, target, version, progress=None):
    """Unpack a downloaded package into 'target', replacing what is there.
    It is unpacked beside it and renamed into place, so a failure leaves the
    old install (or none), never half of one."""
    staging = target + ".new"
    shutil.rmtree(staging, ignore_errors=True)
    os.makedirs(staging)
    root = os.path.realpath(staging)
    with zipfile.ZipFile(package) as z:
        # Only what copy_installed takes from an installed WinDbg: the TTD
        # runtime and the license. The rest of the package is the whole
        # debugger (hundreds of MB) and most of the unpacking time.
        members = [m for m in z.infolist() if not m.is_dir() and m.filename not in _PACKAGE_META
                   and _kept(urllib.parse.unquote(m.filename))]
        for i, m in enumerate(members):
            # Package part names are percent-encoded ("Third%20Party...").
            name = urllib.parse.unquote(m.filename).replace("/", os.sep)
            path = os.path.realpath(os.path.join(staging, name))
            if os.path.commonpath([root, path]) != root:
                raise InstallError("the package holds a file outside its folder: %s" % m.filename)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with z.open(m) as src, open(path, "wb") as dst:
                shutil.copyfileobj(src, dst, 1 << 20)
            if progress is not None and progress(i + 1, len(members)) is False:
                raise Cancelled()
    _finish(staging, target, version, APPINSTALLER_URL,
            "Microsoft Software License Terms - WinDbg, accepted in IDA before download")


def copy_installed(source, target, version):
    """Copy the TTD runtime (amd64/ttd) and the license out of an installed
    WinDbg into 'target', replacing what is there."""
    staging = target + ".new"
    shutil.rmtree(staging, ignore_errors=True)
    shutil.copytree(os.path.join(source, TTD_SUBDIR), os.path.join(staging, TTD_SUBDIR))
    if os.path.isfile(os.path.join(source, "eula.rtf")):
        shutil.copy2(os.path.join(source, "eula.rtf"), staging)
    _finish(staging, target, version, source,
            "Microsoft Software License Terms - WinDbg, as installed with WinDbg")


def _finish(staging, target, version, source, license_note):
    """Stamp a complete 'staging' folder and rename it to 'target'."""
    if not has_runtime(staging):
        shutil.rmtree(staging, ignore_errors=True)
        raise InstallError("WinDbg %s does not contain %s" % (version, " or ".join(RUNTIME_FILES)))
    with open(os.path.join(staging, MARKER), "w", encoding="utf-8") as f:
        json.dump({
            "version": version,
            "source": source,
            "installed": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
            "license": license_note,
        }, f, indent=2)

    old = target + ".old"
    if os.path.exists(old):
        if os.path.exists(target):
            shutil.rmtree(old, ignore_errors=True)
            if os.path.exists(old):
                # Not all of it could go (a DLL in it is still loaded by an
                # IDA): moved aside under a name of its own, or the rename
                # of the target onto it below would fail and every later
                # install would say the runtime is in use.
                aside = "%s.%d" % (old, int(time.time()))
                try:
                    os.rename(old, aside)
                except OSError:
                    pass
        else:
            # An earlier install stopped between its two renames: the old
            # folder is the only working copy, so it is put back rather
            # than deleted.
            try:
                os.rename(old, target)
            except OSError as e:
                shutil.rmtree(staging, ignore_errors=True)
                raise InstallError("Could not restore %s from %s (%s). Close every IDA that has "
                                   "a Microsoft recording open, then try again." % (target, old, e))
    moved = False
    if os.path.exists(target):
        try:
            os.rename(target, old)
            moved = True
        except OSError:
            shutil.rmtree(staging, ignore_errors=True)
            raise InstallError("%s is in use. Close every IDA that has a Microsoft recording "
                               "open, then try again." % target)
    try:
        os.rename(staging, target)
    except OSError as e:
        # Put the previous runtime back, so a failed upgrade leaves it working.
        if moved:
            try:
                os.rename(old, target)
            except OSError:
                pass
        shutil.rmtree(staging, ignore_errors=True)
        raise InstallError("Could not move the new runtime into %s (%s); the previous one "
                           "was kept." % (target, e))
    shutil.rmtree(old, ignore_errors=True)


# --------------------------------------------------------------------------
# RTF to text, enough for a license file

_RTF_TOKEN = re.compile(r"\\([a-z]{1,32})(-?\d{1,10})? ?|\\'([0-9a-f]{2})|\\([^a-z])|([{}])|[\r\n]+|(.)",
                        re.I | re.S)

# Groups that hold formatting tables or metadata, never text.
_RTF_SKIP = {
    "fonttbl", "colortbl", "stylesheet", "info", "pict", "header", "footer",
    "headerl", "headerr", "headerf", "footerl", "footerr", "footerf",
    "listtable", "listoverridetable", "rsidtbl", "generator", "xmlnstbl",
    "themedata", "colorschememapping", "latentstyles", "datastore",
    "pgdsctbl", "filetbl", "revtbl", "object", "fldinst", "mmathPr",
}
_RTF_CHARS = {
    "par": "\n", "line": "\n", "sect": "\n\n", "page": "\n\n", "tab": "\t",
    "cell": "\t", "row": "\n", "emdash": "\u2014", "endash": "\u2013",
    "lquote": "\u2018", "rquote": "\u2019", "ldblquote": "\u201c",
    "rdblquote": "\u201d", "bullet": "\u2022", "emspace": " ", "enspace": " ",
}


def rtf_to_text(rtf):
    if isinstance(rtf, bytes):
        rtf = rtf.decode("latin-1")
    stack = []
    skip = False         # inside a group that holds no text
    ucskip = 1           # characters after \uN that stand in for it
    pending = 0          # of those, still to drop
    out = []
    for word, arg, hexc, sym, brace, char in (m.groups() for m in _RTF_TOKEN.finditer(rtf)):
        if brace:
            pending = 0
            if brace == "{":
                stack.append((skip, ucskip))
            elif stack:
                skip, ucskip = stack.pop()
        elif sym:
            pending = 0
            if sym == "*":
                skip = True
            elif sym in "\\{}":
                if not skip:
                    out.append(sym)
            elif sym == "~":
                if not skip:
                    out.append("\u00a0")
            elif sym in "\r\n":
                if not skip:
                    out.append("\n")
        elif word:
            pending = 0
            w = word.lower()
            if w in _RTF_SKIP:
                skip = True
            elif skip:
                pass
            elif w == "uc":
                ucskip = int(arg or 1)
            elif w == "u":
                # \u takes a signed 16-bit number; a missing or out-of-range
                # one (a damaged file) becomes U+FFFD rather than an error.
                c = int(arg) if arg else None
                if c is not None and c < 0:
                    c += 0x10000
                if c is None or not 0 <= c <= 0x10FFFF or 0xD800 <= c <= 0xDFFF:
                    c = 0xFFFD
                out.append(chr(c))
                pending = ucskip
            elif w in _RTF_CHARS:
                out.append(_RTF_CHARS[w])
        elif hexc:
            if pending:
                pending -= 1
            elif not skip:
                out.append(bytes([int(hexc, 16)]).decode("cp1252", "replace"))
        elif char:
            if pending:
                pending -= 1
            elif not skip:
                out.append(char)
    text = "".join(out)
    text = re.sub(r"[ \t]+\n", "\n", text)
    return re.sub(r"\n{3,}", "\n\n", text).strip() + "\n"


# --------------------------------------------------------------------------
# In IDA

def user_data_dir(*parts):
    """$IDAUSR/ida-ttd: what the user adds after installing
    (src/core/backend_module.h, user_data_dir). Not the package folder,
    which HCLI replaces on every upgrade, and not under plugins/, since none
    of it is a plugin."""
    import ida_diskio
    return os.path.join(ida_diskio.get_user_idadir(), "ida-ttd", *parts)


def legacy_dir(*parts):
    """$IDAUSR/plugins/ida-ttd-backends: where earlier versions installed
    the runtime and the Sogen backend. Still searched, so nothing breaks."""
    import ida_diskio
    return os.path.join(ida_diskio.get_user_idadir(), "plugins", "ida-ttd-backends", *parts)


def default_target():
    return user_data_dir("windbg")


def adopt_folder(old, new):
    """Move folder 'old' to 'new' when only the old one exists. False when
    it cannot (a DLL in it is loaded, say); the old copy then stays where it
    is found anyway."""
    if os.path.exists(new) or not os.path.isdir(old):
        return False
    try:
        os.makedirs(os.path.dirname(new), exist_ok=True)
        os.replace(old, new)
        return True
    except OSError:
        return False


def _in_background(title, work, status):
    """Run work(cancel) on a worker thread behind a cancellable wait box.
    The thread does only network and file work; every IDA call stays on the
    main thread. status() is the wait box's current text."""
    import ida_kernwin
    result = {}
    cancel = threading.Event()

    def run():
        try:
            result["value"] = work(cancel)
        except BaseException as e:      # handed to the main thread below
            result["error"] = e

    t = threading.Thread(target=run, name="ida-ttd runtime install", daemon=True)
    ida_kernwin.show_wait_box(title)
    try:
        t.start()
        shown = None
        while t.is_alive():
            t.join(0.15)
            if ida_kernwin.user_cancelled():
                cancel.set()
            text = status()
            if text and text != shown:
                ida_kernwin.replace_wait_box(text)
                shown = text
    finally:
        ida_kernwin.hide_wait_box()
    if "error" in result:
        raise result["error"]
    return result.get("value")


def _ask_license(release, target, text):
    """Show WinDbg's license; True only if the user accepts it."""
    intro = ("ida-ttd needs Microsoft's TTD replay runtime (TTDReplay.dll) to open "
             "Microsoft TTD recordings. It comes with WinDbg, and Microsoft does not allow "
             "anyone else to distribute it, so ida-ttd cannot include it.\n\n"
             "This will download WinDbg %s (%d MB) from Microsoft and unpack it into\n%s\n\n"
             "WinDbg is Microsoft's software, licensed to you by Microsoft under the terms "
             "below. Accept installs it; Decline installs nothing."
             % (release.version, (release.size + (1 << 19)) >> 20, target))
    try:
        from PySide6 import QtWidgets
    except ImportError:
        QtWidgets = None
    if QtWidgets is None:
        import ida_kernwin
        path = os.path.join(os.path.dirname(target), "WinDbg-license.txt")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        os.startfile(path)
        return ida_kernwin.ask_buttons("Accept", "Decline", "", 0,
                                       "%s\n\nThe license is open in a text editor (%s)."
                                       % (intro, path)) == 1

    return _license_dialog(QtWidgets, intro, text).exec() == QtWidgets.QDialog.Accepted


def _license_dialog(QtWidgets, intro, text):
    dlg = QtWidgets.QDialog(QtWidgets.QApplication.activeWindow())
    dlg.setWindowTitle("Install the TTD runtime: WinDbg license")
    lay = QtWidgets.QVBoxLayout(dlg)
    head = QtWidgets.QLabel(intro)
    head.setWordWrap(True)
    lay.addWidget(head)
    body = QtWidgets.QPlainTextEdit()
    body.setReadOnly(True)
    # The license puts a tab after each clause number ("1.\tINSTALLATION");
    # Qt's default tab stop is eight characters wide.
    body.setTabStopDistance(3 * body.fontMetrics().horizontalAdvance("0"))
    body.setPlainText(text)
    lay.addWidget(body, 1)
    buttons = QtWidgets.QDialogButtonBox()
    accept = buttons.addButton("Accept", QtWidgets.QDialogButtonBox.AcceptRole)
    decline = buttons.addButton("Decline", QtWidgets.QDialogButtonBox.RejectRole)
    decline.setDefault(True)
    accept.setAutoDefault(False)
    buttons.accepted.connect(dlg.accept)
    buttons.rejected.connect(dlg.reject)
    lay.addWidget(buttons)
    dlg.resize(760, 640)
    return dlg


def install_runtime(target=None):
    """TTD > Backends > Install the TTD runtime (WinDbg)...: find, or else
    install, WinDbg's TTD runtime. Returns the folder holding it, or None."""
    import ida_kernwin
    if target is None:
        target = default_target()
        # Move an earlier version's runtime here, so the version checks below
        # see it.
        if adopt_folder(legacy_dir("windbg"), target):
            ida_kernwin.msg("[ida-ttd] Moved the TTD runtime from %s to %s.\n" % (legacy_dir("windbg"), target))

    mine = read_marker(target) if has_runtime(target) else None
    found = installed_windbg()
    if found:
        source, version = found
        if mine is not None and mine.get("version") == version:
            ida_kernwin.info("ida-ttd already has the TTD runtime of WinDbg %s, the version "
                             "installed on this computer:\n%s" % (version, target))
            return target
        if ida_kernwin.ask_yn(ida_kernwin.ASKBTN_YES,
                              "WinDbg %s is installed on this computer.\n\n"
                              "Copy its TTD runtime for ida-ttd? Windows does not let other "
                              "programs load it from where WinDbg is installed, so ida-ttd keeps "
                              "a copy in\n%s\n\nRun this again after WinDbg updates to copy the "
                              "new version." % (version, target)) != ida_kernwin.ASKBTN_YES:
            return None
        try:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            copy_installed(source, target, version)
        except Exception as e:
            shutil.rmtree(target + ".new", ignore_errors=True)
            ida_kernwin.warning("Copying the TTD runtime from WinDbg failed: %s" % e)
            return None
        return _installed(version, target)

    state = {"text": "Asking Microsoft for the current WinDbg..."}
    try:
        release = _in_background("HIDECANCEL\n" + state["text"],
                                 lambda cancel: latest_release(), lambda: state["text"])
    except Exception as e:
        ida_kernwin.warning("Could not reach Microsoft's WinDbg download: %s" % e)
        return None

    if mine is not None:
        if mine.get("version") == release.version:
            ida_kernwin.info("WinDbg %s, the current version, is already installed for ida-ttd:\n%s"
                             % (release.version, target))
            return target
        if ida_kernwin.ask_yn(ida_kernwin.ASKBTN_YES,
                              "WinDbg %s is installed for ida-ttd; %s is available.\n\nUpdate it?"
                              % (mine.get("version", "?"), release.version)) != ida_kernwin.ASKBTN_YES:
            return target

    try:
        text = _in_background("HIDECANCEL\nReading the WinDbg license...",
                              lambda cancel: release.license_text(), lambda: None)
    except Exception as e:
        ida_kernwin.warning("Could not read the WinDbg license: %s" % e)
        return None
    if not _ask_license(release, target, text):
        ida_kernwin.msg("[ida-ttd] The WinDbg license was declined; nothing was installed.\n")
        return None

    os.makedirs(os.path.dirname(target), exist_ok=True)
    package = target + ".msix.part"
    total_mb = release.size >> 20

    def work(cancel):
        def dl(done, total):
            state["text"] = "Downloading WinDbg %s from Microsoft: %d of %d MB" % (
                release.version, done >> 20, total_mb)
            return not cancel.is_set()

        def up(done, total):
            state["text"] = "Unpacking WinDbg: %d of %d files" % (done, total)
            return not cancel.is_set()
        try:
            download(release, package, dl)
            state["text"] = "Unpacking WinDbg..."
            unpack(package, target, release.version, up)
        finally:
            try:
                os.remove(package)
            except OSError:
                pass

    state["text"] = "Downloading WinDbg %s from Microsoft..." % release.version
    try:
        _in_background(state["text"], work, lambda: state["text"])
    except Cancelled:
        shutil.rmtree(target + ".new", ignore_errors=True)
        ida_kernwin.msg("[ida-ttd] The WinDbg install was cancelled; nothing was installed.\n")
        return None
    except Exception as e:
        shutil.rmtree(target + ".new", ignore_errors=True)
        ida_kernwin.warning("Installing WinDbg failed: %s" % e)
        return None

    return _installed(release.version, target)


def _installed(version, target):
    import ida_kernwin
    ida_kernwin.msg("[ida-ttd] Installed the TTD runtime of WinDbg %s in %s; Microsoft TTD "
                    "recordings can be replayed now.\n" % (version, target))
    ida_kernwin.info("The TTD runtime of WinDbg %s is installed in\n%s\n\nMicrosoft TTD recordings "
                     "can be replayed now: start the debugger (Debugger > Start process) to begin."
                     % (version, target))
    return target


# --------------------------------------------------------------------------
# The Sogen backend
#
# The package ships ida-ttd-sogen.dll. This installs another build of it
# into $IDAUSR/ida-ttd/backends/, which upgrades leave alone and which
# ida-ttd searches first, so it takes the packaged one's place. The source
# is a file the user picks: the DLL, or a zip holding it (its license and
# notice files are kept beside it). The functions up to install_sogen() use
# no IDA module.

SOGEN_DLL = "ida-ttd-sogen.dll"
SOGEN_LICENSES = "ida-ttd-sogen-licenses"
# The one symbol every backend exports (src/abi/ida_ttd_backend.h).
BACKEND_ENTRY = b"ida_ttd_backend\0"


def sogen_target():
    return user_data_dir("backends")


def retire_sogen(folder):
    """Take the backend out of 'folder' (where an earlier version installed
    it), so IDA does not load that copy too. A loaded DLL cannot be deleted
    but can be renamed; .old files are removed on a later run. True when
    there was one."""
    final = os.path.join(folder, SOGEN_DLL)
    if not os.path.isdir(folder):
        return False
    for old in os.listdir(folder):
        if old.startswith(SOGEN_DLL + ".old"):
            try:
                os.remove(os.path.join(folder, old))
            except OSError:
                pass                    # still loaded by an IDA somewhere
    if not os.path.exists(final):
        return False
    n = 0
    while os.path.exists("%s.old%d" % (final, n)):
        n += 1
    os.rename(final, "%s.old%d" % (final, n))
    shutil.rmtree(os.path.join(folder, SOGEN_LICENSES), ignore_errors=True)
    return True


def _check_backend(data, where):
    if data[:2] != b"MZ" or BACKEND_ENTRY not in data:
        raise InstallError("%s is not an ida-ttd backend DLL" % where)


def stage_sogen(source, target):
    """Put the backend from 'source' (the DLL, or a zip holding it) into
    target/ida-ttd-sogen.dll.new, and any license or notice files the zip
    has into target/ida-ttd-sogen-licenses.new/. Returns the staged DLL."""
    os.makedirs(target, exist_ok=True)
    staged = os.path.join(target, SOGEN_DLL + ".new")
    lic_dir = os.path.join(target, SOGEN_LICENSES + ".new")
    shutil.rmtree(lic_dir, ignore_errors=True)
    if zipfile.is_zipfile(source):
        with zipfile.ZipFile(source) as z:
            names = [n for n in z.namelist() if not n.endswith("/")]
            dlls = [n for n in names if os.path.basename(n).lower() == SOGEN_DLL]
            if not dlls:
                raise InstallError("%s holds no %s" % (os.path.basename(source), SOGEN_DLL))
            data = z.read(dlls[0])
            _check_backend(data, dlls[0])
            folder = os.path.dirname(dlls[0])
            for n in names:
                base = os.path.basename(n)
                if os.path.dirname(n) == folder and re.match(r"(?i)(license|copying|notice|third-party)", base):
                    os.makedirs(lic_dir, exist_ok=True)
                    with open(os.path.join(lic_dir, base), "wb") as f:
                        f.write(z.read(n))
    else:
        with open(source, "rb") as f:
            data = f.read()
        _check_backend(data, os.path.basename(source))
    with open(staged, "wb") as f:
        f.write(data)
    return staged


def place_sogen(staged, target):
    """Move the staged backend (and its licenses) into place. A loaded
    backend cannot be overwritten but can be renamed, so it is moved aside
    and removed on the next run. True when one was replaced (IDA needs a
    restart to use the new one)."""
    final = os.path.join(target, SOGEN_DLL)
    for old in os.listdir(target):
        if old.startswith(SOGEN_DLL + ".old"):
            try:
                os.remove(os.path.join(target, old))
            except OSError:
                pass                    # still loaded by an IDA somewhere
    replaced = os.path.exists(final)
    if replaced:
        try:
            os.replace(staged, final)
        except PermissionError:
            n = 0
            while os.path.exists("%s.old%d" % (final, n)):
                n += 1
            os.rename(final, "%s.old%d" % (final, n))
            os.replace(staged, final)
    else:
        os.replace(staged, final)
    lic_new = os.path.join(target, SOGEN_LICENSES + ".new")
    if os.path.isdir(lic_new):
        lic = os.path.join(target, SOGEN_LICENSES)
        shutil.rmtree(lic, ignore_errors=True)
        os.replace(lic_new, lic)
    return replaced


def install_sogen(source=None, target=None):
    """TTD > Backends > Install the Sogen backend...: install
    ida-ttd-sogen.dll from a file. Returns where it went, or None."""
    import ida_kernwin
    legacy = legacy_dir() if target is None else None
    target = target or sogen_target()
    if source is None:
        source = ida_kernwin.ask_file(0, "ida-ttd-sogen.dll;*.zip",
                                      "Choose the Sogen backend (ida-ttd-sogen.dll, or a zip holding it)")
        if not source:
            return None
    try:
        staged = stage_sogen(source, target)
        replaced = place_sogen(staged, target)
    except Exception as e:
        try:
            os.remove(os.path.join(target, SOGEN_DLL + ".new"))
        except OSError:
            pass
        shutil.rmtree(os.path.join(target, SOGEN_LICENSES + ".new"), ignore_errors=True)
        ida_kernwin.warning("Installing the Sogen backend failed: %s" % e)
        return None
    # The new backend is in place from here on, so a failure tidying up
    # after an earlier version is reported, not taken for a failed install.
    leftover = None
    if legacy is not None:
        try:
            # An earlier version's copy would still load if this one failed
            # to, and be the version nobody expects.
            if retire_sogen(legacy):
                replaced = True
            # Its registry hives sat beside it; the plugin now looks in
            # ida-ttd/registry.
            adopt_folder(os.path.join(legacy, "registry"), user_data_dir("registry"))
        except Exception as e:
            leftover = "Could not move the earlier copy out of %s (%s). Delete %s there by hand, " \
                       "or IDA may load that one too." % (legacy, e, SOGEN_DLL)
    final = os.path.join(target, SOGEN_DLL)
    ida_kernwin.msg("[ida-ttd] Installed the Sogen backend in %s; restart IDA to load it.\n" % final)
    if leftover:
        ida_kernwin.msg("[ida-ttd] %s\n" % leftover)
    ida_kernwin.info("The Sogen backend is installed in\n%s\n\nRestart IDA to use it%s: "
                     "backends are loaded when IDA starts. Then Sogen recordings (.sogttd) "
                     "open like Microsoft ones, and the Forks menu appears for them.%s"
                     % (final, " (it replaces the one loaded now)" if replaced else "",
                        "\n\nWarning: " + leftover if leftover else ""))
    return final
