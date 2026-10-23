"""Get the Sogen backend ready to ship: its licenses, and its source.

    python scripts/sogen_dist.py --sogen <Sogen tree> [--git <Sogen checkout>]
                                 [--build build/Release] [--out dist] [--no-source]

ida-ttd-sogen.dll is GPL-2.0-only (it links Sogen and Unicorn), so it goes out
with the GPL text, the notices of what it contains, and its complete source
(docs/licensing.md). This writes:

    <build>/backends/ida-ttd-sogen-licenses/
        COPYING.txt             the GPL-2.0 text, which the DLL is under
        README.txt              what the DLL contains, and where its source is
        <component>-<file>      each component's own license or notice
    <out>/ida-ttd-sogen-source.zip
        sogen/                  the Sogen tree it was built from, deps included
        ida-ttd/                ida-ttd at the commit being built (the backend's
                                source, the shared header, the build files)

scripts/package.py puts the DLL and the licenses folder in the plugin package;
the release workflow attaches the source archive to the same release.

Two of Sogen's submodules state no license at all, so they are left out of the
archive and named instead: minidump_cpp (its headers are on the include path,
but none of its code is in the DLL; docs/licensing.md says how that is checked)
and sogen-linux-files (test data). Sogen's build fetches both as submodules.

--sogen is the tree that was built (a checkout with its submodules, or a
snapshot of one). --git is a Sogen git checkout to read the submodule commits
from, when --sogen is a snapshot without .git; it is only read.
"""
import argparse
import io
import pathlib
import subprocess
import tarfile
import zipfile

REPO = pathlib.Path(__file__).resolve().parent.parent
LICENSES = "ida-ttd-sogen-licenses"
SOURCE_ZIP = "ida-ttd-sogen-source.zip"
EXCLUDED = ("minidump_cpp", "sogen-linux-files")

# What the DLL contains, by the symbols in its PDB (docs/licensing.md), and
# the files in each component's tree that carry its terms.
NOTICES = [
    ("Sogen", "", ["LICENSE"]),
    ("unicorn", "deps/unicorn", ["COPYING", "COPYING.LGPL2", "COPYING_GLIB"]),
    ("capstone", "deps/capstone", ["LICENSES/LICENSE.TXT", "LICENSES/LICENSE_BSD_3_CLAUSE.txt",
                                    "LICENSES/LICENSE_LLVM.TXT"]),
    ("mbedtls", "deps/mbedtls", ["LICENSE"]),
    ("zstd", "deps/zstd", ["LICENSE", "COPYING"]),
    ("base64", "deps/base64", ["LICENSE"]),
    ("reflect", "deps/reflect", ["reflect"]),      # MIT, in the header itself
    ("Vulkan-Headers", "deps/Vulkan-Headers", ["LICENSE.md"]),
]


def read_pin():
    pin = {}
    for line in (REPO / "msbuild" / "sogen.pin").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            pin[k.strip()] = v.strip()
    return pin


def submodule_commits(git, commit):
    """{name: commit} of Sogen's deps/ at 'commit', or {} without git."""
    if git is None or not (git / ".git").exists():
        return {}
    out = subprocess.run(["git", "-C", str(git), "ls-tree", commit, "deps/"],
                         capture_output=True, text=True)
    if out.returncode != 0:
        return {}
    found = {}
    for line in out.stdout.splitlines():
        meta, path = line.split("\t", 1)
        mode, kind, sha = meta.split()
        if kind == "commit":
            found[path[len("deps/"):]] = sha
    return found


def submodule_urls(sogen):
    urls, path = {}, None
    gm = sogen / ".gitmodules"
    if not gm.is_file():
        return urls
    for line in gm.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("path"):
            path = line.split("=", 1)[1].strip()
        elif line.startswith("url") and path:
            urls[path[len("deps/"):]] = line.split("=", 1)[1].strip()
    return urls


def ida_ttd_commit():
    out = subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True, text=True)
    return out.stdout.strip() if out.returncode == 0 else "unknown"


def readme(pin, commits, urls):
    lines = [
        "ida-ttd-sogen.dll: the Sogen backend of ida-ttd",
        "",
        "This DLL is licensed under the GNU General Public License, version 2 only",
        "(COPYING.txt). It contains:",
        "",
        "  - ida-ttd's Sogen backend (src/backend-sogen/sogen_backend.cpp, GPL-2.0-only)",
        "    and its string and buffer scanners (src/common/write_scans.h, taken here",
        "    under GPL-2.0-only)",
        "  - Sogen, GPL-2.0-only (Sogen-LICENSE)",
        "  - Unicorn, with parts of QEMU, GPL-2.0 (unicorn-*)",
        "  - Capstone, BSD-3-Clause, with LLVM parts under the NCSA license (capstone-*)",
        "  - Mbed TLS, Apache-2.0 OR GPL-2.0-or-later, here under the GPL (mbedtls-LICENSE)",
        "  - zstd, BSD OR GPL-2.0 (zstd-*)",
        "  - base64 and reflect, MIT (base64-LICENSE, reflect-reflect)",
        "  - Vulkan-Headers, Apache-2.0 OR MIT (Vulkan-Headers-LICENSE.md)",
        "",
        "Source",
        "",
        "The complete source it was built from is %s, attached to" % SOURCE_ZIP,
        "the same ida-ttd release as this package (https://github.com/HullaBrian/ida-ttd/releases).",
        "",
        "  Sogen    %s at %s" % (pin["repository"], pin["commit"]),
        "  ida-ttd  https://github.com/HullaBrian/ida-ttd at %s" % ida_ttd_commit(),
        "",
        "Built with docs/building-the-sogen-backend.md and .github/workflows/release.yml",
        "of that ida-ttd commit. Two Sogen submodules state no license and are not in",
        "the archive; none of their code is in this DLL. Sogen's build expects them:",
        "",
    ]
    for name in EXCLUDED:
        lines.append("  deps/%-18s %s at %s" % (name, urls.get(name, "?"), commits.get(name, "the commit Sogen records")))
    if commits:
        lines += ["", "Every submodule, at the commits Sogen %s records:" % pin["commit"][:8], ""]
        for name in sorted(commits):
            lines.append("  deps/%-18s %s" % (name, commits[name]))
    return "\n".join(lines) + "\n"


def write_licenses(sogen, dest, pin, commits, urls):
    dest.mkdir(parents=True, exist_ok=True)
    for old in dest.iterdir():
        old.unlink()
    (dest / "COPYING.txt").write_bytes((REPO / "LICENSES" / "GPL-2.0-only.txt").read_bytes())
    for component, folder, names in NOTICES:
        for name in names:
            src = sogen / folder / name
            if not src.is_file():
                raise SystemExit("missing %s: is %s a full Sogen tree?" % (src, sogen))
            (dest / ("%s-%s" % (component, pathlib.PurePath(name).name))).write_bytes(src.read_bytes())
    (dest / "README.txt").write_text(readme(pin, commits, urls), encoding="utf-8", newline="\r\n")


def write_source(sogen, out):
    out.parent.mkdir(parents=True, exist_ok=True)
    skip = {"deps/" + n for n in EXCLUDED}
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        n = 0
        for p in sorted(sogen.rglob("*")):
            rel = p.relative_to(sogen).as_posix()
            first = rel.split("/", 1)[0]
            if first in (".git", "build") or any(rel == s or rel.startswith(s + "/") for s in skip):
                continue
            if "/.git/" in "/" + rel + "/" or not p.is_file() or p.is_symlink():
                continue
            z.write(p, "sogen/" + rel)
            n += 1
        # ida-ttd at HEAD, as git has it (no build output, no local files).
        arch = subprocess.run(["git", "-C", str(REPO), "archive", "--format=tar", "HEAD"],
                              capture_output=True, check=True).stdout
        with tarfile.open(fileobj=io.BytesIO(arch)) as t:
            for m in t.getmembers():
                if m.isfile():
                    z.writestr("ida-ttd/" + m.name, t.extractfile(m).read())
                    n += 1
    return n


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--sogen", required=True)
    ap.add_argument("--git")
    ap.add_argument("--build", default=str(REPO / "build" / "Release"))
    ap.add_argument("--out", default=str(REPO / "dist"))
    ap.add_argument("--no-source", action="store_true")
    args = ap.parse_args()
    sogen = pathlib.Path(args.sogen)
    pin = read_pin()
    commits = submodule_commits(pathlib.Path(args.git) if args.git else sogen, pin["commit"])
    urls = submodule_urls(sogen)

    lic = pathlib.Path(args.build) / "backends" / LICENSES
    write_licenses(sogen, lic, pin, commits, urls)
    print("wrote %s" % lic)
    if not args.no_source:
        dest = pathlib.Path(args.out) / SOURCE_ZIP
        n = write_source(sogen, dest)
        print("wrote %s (%d files, %.1f MB)" % (dest, n, dest.stat().st_size / 1e6))


if __name__ == "__main__":
    main()
