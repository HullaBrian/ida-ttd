# Licensing: what ships, under what terms

Settled 2026-10-22, against Sogen `8a9fb161` and TTD Replay SDK 0.9.5;
checked again 2026-11-09 for Sogen `253c9488` (the PDB still holds no
minidump_cpp or flatbuffers code; the DLL now also contains Unicorn's AArch64
target, under Unicorn's same terms; the new `deps/libadrenotools`, BSD-2-Clause,
is Android-only and in the source archive only), and 2026-11-11 for
`f848464d` (eight source files changed, no dependency). Not legal advice; where a
point is a reading rather than a fact, it says so.

**In short:** ida-ttd is `Apache-2.0 OR GPL-2.0-only`, at the recipient's
choice. The plugin package ships both backends: the Microsoft one under the
same dual license, the Sogen one under GPL-2.0-only with its license, notices
and source. Everything can be used commercially.

## Why dual

The Sogen backend is GPL-2.0-only: it links Sogen (GPL-2.0-only) and Unicorn
(GPL-2.0, with QEMU code from many contributors). The plugin loads it into the
same process and calls it, and one reading of the GPL makes the two a single
combined work, which then has to be GPL-2.0-compatible as a whole. The FSF
holds Apache-2.0 incompatible with GPL-2.0. So the plugin is offered under
GPL-2.0-only as well: taken that way, plugin and backend combine under one
license, whichever reading is right. Anyone not shipping the Sogen backend can
keep taking ida-ttd under Apache-2.0, exactly as before.

An exception from Sogen's author would not have been enough: it could cover
Sogen, but not Unicorn, whose copyright is not his.

## What is in each binary, and its terms

| Binary | Terms | Contents |
| --- | --- | --- |
| `ida-ttd.dll`, `ttd-loader.dll`, the setup DLL | Apache-2.0 OR GPL-2.0-only | ida-ttd's code; IDA SDK headers and import libraries (MIT); the API metadata loader `src/common/apimeta` (Apache-2.0, ttd-capa-cpp); Codicons (CC BY 4.0) and Material Symbols (Apache-2.0) icons |
| `ida-ttd-msttd.dll` | Apache-2.0 OR GPL-2.0-only | ida-ttd's code; the TTD Replay SDK's headers and import libraries (NuGet `Microsoft.TimeTravelDebugging.Apis`, MIT) |
| `ida-ttd-sogen.dll` | GPL-2.0-only | below |
| `ida-ttd-data/*.bin` | MIT | built from win32metadata/win32json and phnt |

The apimeta loader and the icons stay under their own licenses by choice. The
loader is the same author's code, so his own distribution of it alongside the
GPL backend cannot breach his own terms. The icons are embedded images. They
are not GPL-compatible in the FSF's reading, but they're not program code
either.

The TTD **runtime** (`TTDReplay.dll`, `TTDReplayCPU.dll`) is not in the
package and must never be. WinDbg's license forbids redistributing it but
not commercial use; the standalone TTD package's license forbids both. It is
copied from the user's own WinDbg, or downloaded from Microsoft as WinDbg
after the user accepts WinDbg's license (`scripts/ida_ttd_runtime.py`).

### ida-ttd-sogen.dll

It imports only the MSVC runtime and Windows, and does not link the IDA SDK
or the rest of ida-ttd; it meets the plugin at `src/abi/ida_ttd_backend.h`
(CC0). What it links, from the link inputs and the symbols in its PDB:

| Component | License | Notes |
| --- | --- | --- |
| Sogen (windows-ttd, emulator, ...) | GPL-2.0-only | makes the DLL GPL-2.0-only |
| Unicorn, with QEMU/TCG/softfloat | GPL-2.0 (QEMU parts GPL-2.0-or-later, BSD, MIT) | |
| Capstone (x86) | BSD-3-Clause, LLVM parts NCSA | |
| Mbed TLS, everest, p256-m | Apache-2.0 OR GPL-2.0-or-later | taken under the GPL |
| zstd | BSD OR GPL-2.0 | |
| base64, reflect (headers) | MIT | |
| Vulkan-Headers (headers) | Apache-2.0 OR MIT | |
| ida-ttd: `sogen_backend.cpp` | GPL-2.0-only | |
| ida-ttd: `write_scans.h` | Apache-2.0 OR GPL-2.0-only | taken under the GPL |

Two of Sogen's dependencies would be problems and are **not** in the DLL:
**minidump_cpp** (no license at all) and **flatbuffers** (Apache-2.0). The
linker drops both. A search of the PDB finds no `minidump` or `flatbuffers`
symbol: `minidump_cpp` appears only as an include path in compiler command
lines. The same search finds Unicorn, Mbed TLS and zstd. **Check again whenever
the pin in `msbuild/sogen.pin` moves**:

```
grep -a -o -i "minidump[A-Za-z_:]*" ida-ttd-sogen.pdb | sort -u    # only minidump_cpp
grep -a -o -i "flatbuffers[A-Za-z_:]*" ida-ttd-sogen.pdb | sort -u # nothing
```

If either shows real symbols, the DLL cannot ship until it is gone.

## What shipping it takes (all automated)

GPL-2.0 sections 1 and 3: the license text, the notices, and the complete
corresponding source go with the binary.

- **License and notices:** `scripts/sogen_dist.py` writes
  `ida-ttd-backends/ida-ttd-sogen-licenses/`: the GPL text as `COPYING.txt`,
  each component's own license file, and a `README.txt` that says what the
  DLL contains and where its source is. `scripts/package.py` refuses to
  package the DLL without that folder.
- **Source:** `sogen_dist.py` also writes `ida-ttd-sogen-source.zip`:
  - the Sogen tree at the pin, its submodules included;
  - ida-ttd at the commit being built.

  The release workflow attaches it to the same release as the package (source
  offered "from the same place", section 3). minidump_cpp and
  sogen-linux-files state no license, so they are left out of it. The README
  names their repositories and commits; none of their code is in the DLL.
- **Build:** the release workflow builds Sogen at `msbuild/sogen.pin`, then
  the backend, and packages with `--require-sogen`.

## Using it at work

GPL-2.0 puts no restriction on use, commercial or otherwise. Its obligations
fall only on whoever distributes the binary. Anyone who passes the package on
has the same obligations the project does, which the steps above meet. The
TTD runtime comes from WinDbg on the user's machine, under WinDbg's license,
which allows commercial use.

## Corrections to older documents

- `docs/modular-backends.md` section 3 calls the IDA SDK proprietary. The SDK
  headers and import libraries are MIT now (`ida-sdk/LICENSE`). IDA itself is
  still proprietary. Nothing changes: no backend links either.
