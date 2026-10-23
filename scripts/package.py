"""Build the plugin package (ida-ttd.zip) from a build folder.

    python scripts/package.py [--build build/Release] [--out dist]

The zip is what HCLI installs into $IDAUSR/plugins/ida-ttd/ and what the
plugin repository indexes. Everything is under one top-level ida-ttd/ folder,
which HCLI requires of a suite (a plugin with components); inside it, the
layout is the installed layout:

    ida-plugin.json                 the suite root (components: below)
    ida-ttd.dll                     the plugin
    ida-ttd-backends/               the backends: Microsoft TTD (Apache-2.0
        ida-ttd-msttd.dll           OR GPL-2.0-only, like the plugin) and,
        ida-ttd-sogen.dll           when the build has it, Sogen (GPL-2.0-only),
        ida-ttd-sogen-licenses/     with its license, notices and where its
                                    source is (scripts/sogen_dist.py)
    ida-ttd-data/                   API metadata, found beside ida-ttd.dll
    ida-ttd-python/                 the ida_ttd module, found beside ida-ttd.dll
    LICENSE, THIRD-PARTY-NOTICES.txt, README.md
    ida-ttd-loader-setup/           a component: a PLUGIN_FIX plugin that
        ida-plugin.json             copies ttd-loader.dll into $IDAUSR/loaders/
        ida-ttd-loader-setup.dll    as IDA starts, since HCLI can install
        ttd-loader.dll              nothing outside the plugin folder

The Sogen backend is optional here (--require-sogen makes it not): a build
without it packages the rest. It never goes in without its licenses folder.

The component's ida-plugin.json is written here from the root one, so its
version, authors and URLs cannot drift from the suite's. The zip is built with
zipfile rather than Compress-Archive so entry names always use '/' and the JSON
carries no byte-order mark: HCLI reads both strictly.
"""
import argparse
import json
import pathlib
import zipfile

REPO = pathlib.Path(__file__).resolve().parent.parent
SETUP = "ida-ttd-loader-setup"


def component_manifest(root):
    plugin = root["plugin"]
    keep = ("version", "license", "platforms", "idaVersions", "urls", "authors", "maintainers")
    meta = {k: plugin[k] for k in keep if k in plugin}
    meta.update({
        "name": SETUP,
        "entryPoint": SETUP,
        "description": "Installs the ida-ttd trace loader into IDA's loaders folder, "
                       "so File > Open recognizes recordings.",
        "categories": ["file-parsers-and-loaders"],
        "keywords": ["ttd", "loader"],
    })
    return {
        "$schema": root.get("$schema", "https://hcli.docs.hex-rays.com/schemas/ida-plugin.json"),
        "IDAMetadataDescriptorVersion": root["IDAMetadataDescriptorVersion"],
        "plugin": meta,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--build", default=str(REPO / "build" / "Release"))
    ap.add_argument("--out", default=str(REPO / "dist"))
    ap.add_argument("--require-sogen", action="store_true",
                    help="fail when the build has no Sogen backend")
    args = ap.parse_args()
    build = pathlib.Path(args.build)
    out = pathlib.Path(args.out)

    root = json.loads((REPO / "ida-plugin.json").read_text(encoding="utf-8"))
    if SETUP not in root["plugin"].get("components", []):
        raise SystemExit("ida-plugin.json does not declare the %s component" % SETUP)

    # (path in the zip, file on disk); missing files fail here, before the
    # zip exists, rather than producing a package without them.
    files = [
        ("ida-plugin.json", REPO / "ida-plugin.json"),
        ("ida-ttd.dll", build / "ida-ttd.dll"),
        ("ida-ttd-backends/ida-ttd-msttd.dll", build / "backends" / "ida-ttd-msttd.dll"),
        ("LICENSE", REPO / "LICENSE"),
        ("THIRD-PARTY-NOTICES.txt", REPO / "THIRD-PARTY-NOTICES.txt"),
        ("README.md", REPO / "README.md"),
        (SETUP + "/" + SETUP + ".dll", build / (SETUP + ".dll")),
        (SETUP + "/ttd-loader.dll", build / "ttd-loader.dll"),
    ]
    sogen = build / "backends" / "ida-ttd-sogen.dll"
    licenses = build / "backends" / "ida-ttd-sogen-licenses"
    if sogen.is_file():
        found = sorted(p for p in licenses.glob("*") if p.is_file())
        if not any(p.name == "COPYING.txt" for p in found):
            raise SystemExit("%s has no licenses beside it (%s): run scripts/sogen_dist.py"
                             % (sogen, licenses))
        files.append(("ida-ttd-backends/ida-ttd-sogen.dll", sogen))
        files += [("ida-ttd-backends/ida-ttd-sogen-licenses/" + p.name, p) for p in found]
    elif args.require_sogen:
        raise SystemExit("no Sogen backend in the build (%s)" % sogen)
    for folder in ("ida-ttd-data", "ida-ttd-python"):
        found = sorted(p for p in (build / folder).glob("*") if p.is_file())
        if not found:
            raise SystemExit("nothing in %s" % (build / folder))
        files += [(folder + "/" + p.name, p) for p in found]
    missing = [str(src) for _, src in files if not src.is_file()]
    if missing:
        raise SystemExit("missing from the build:\n  " + "\n  ".join(missing))

    out.mkdir(parents=True, exist_ok=True)
    dest = out / "ida-ttd.zip"
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
        for name, src in files:
            z.write(src, "ida-ttd/" + name)
        z.writestr("ida-ttd/" + SETUP + "/ida-plugin.json",
                   json.dumps(component_manifest(root), indent=2) + "\n")
    print("wrote %s (%d files)" % (dest, len(files) + 1))


if __name__ == "__main__":
    main()
