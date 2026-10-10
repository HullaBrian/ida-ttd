"""Generate .vcxproj.filters mirroring the src/ folder tree, from the project's
own item lists, so the two can never drift."""
import pathlib, re, uuid, hashlib

HEADER_EXT = {".h", ".hh", ".hpp", ".inl"}


def stable_guid(name):
    h = hashlib.md5(("ida-ttd:" + name).encode()).hexdigest()
    return "{%s}" % str(uuid.UUID(h)).upper()


def gen(proj_path):
    proj = pathlib.Path(proj_path)
    text = proj.read_text()
    items = re.findall(r'<(ClInclude|ClCompile) Include="\$\(SrcDir\)\\([^"]+)" />', text)

    folders = []
    rows = []
    for tag, rel in items:
        rel = rel.replace("/", "\\")
        folder = "\\".join(rel.split("\\")[:-1])
        if folder and folder not in folders:
            folders.append(folder)
        rows.append((tag, rel, folder))

    # every intermediate folder needs its own <Filter> entry
    all_folders = []
    for f in folders:
        parts = f.split("\\")
        for i in range(1, len(parts) + 1):
            p = "\\".join(parts[:i])
            if p not in all_folders:
                all_folders.append(p)
    all_folders.sort()

    out = ['<?xml version="1.0" encoding="utf-8"?>',
           '<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">',
           '  <!-- Generated to mirror the src/ tree; see msbuild/gen_filters.py. -->',
           '  <ItemGroup>']
    for f in all_folders:
        out.append('    <Filter Include="%s">' % f)
        out.append('      <UniqueIdentifier>%s</UniqueIdentifier>' % stable_guid(f))
        out.append('    </Filter>')
    out.append('  </ItemGroup>')

    for tag in ("ClInclude", "ClCompile"):
        group = [r for r in rows if r[0] == tag]
        if not group:
            continue
        out.append('  <ItemGroup>')
        for _, rel, folder in group:
            out.append('    <%s Include="$(SrcDir)\\%s">' % (tag, rel))
            out.append('      <Filter>%s</Filter>' % folder)
            out.append('    </%s>' % tag)
        out.append('  </ItemGroup>')

    out.append('  <ItemGroup>')
    out.append('    <None Include="packages.config" />')
    out.append('  </ItemGroup>')
    out.append('</Project>')
    dest = proj.with_suffix(".vcxproj.filters")
    dest.write_text("\n".join(out) + "\n")
    print("wrote", dest, len(rows), "items")


gen("msbuild/ida-ttd.vcxproj")
gen("msbuild/ttd-loader.vcxproj")
