# Licensing: what ships, under what terms

Reviewed 2026-10-20, against Sogen `9fa4e1a3` and TTD Replay SDK 0.9.5. Not
legal advice; where a point is a reading rather than a fact, it says so.

The goal: ship the plugin with **both** backends, and let people use it at
work. Short answer: **both can ship, and both can be used commercially.** The
Microsoft backend needs nothing further. The Sogen backend ships as a GPL-2.0
binary with its source (below, "Before the Sogen backend ships").

## What is in each binary

### ida-ttd.dll, ttd-loader.dll, the setup DLL (Apache-2.0)

| Component | License | Source of the claim |
| --- | --- | --- |
| ida-ttd's own code | Apache-2.0 | `LICENSE` |
| IDA SDK headers and import libraries | MIT, "Copyright (c) 2025 Hex-Rays SA" | `ida-sdk/LICENSE` |
| API metadata loader (`src/common/apimeta`) | Apache-2.0 (ttd-capa-cpp, same author) | `ttd-capa-cpp/LICENSE` |
| `data/*.bin` (built from win32metadata/win32json and phnt) | MIT | `THIRD-PARTY-NOTICES.txt` |
| Codicons (icons) | CC BY 4.0 | github.com/microsoft/vscode-codicons (`LICENSE`; `LICENSE-CODE` is MIT for code) |
| Material Symbols (icons) | Apache-2.0 | github.com/google/material-design-icons |

IDA itself (`ida.dll`), IDAPython and PySide6/Qt come with the user's IDA and
are not redistributed. All of the above is compatible with Apache-2.0
distribution; the notices are in `THIRD-PARTY-NOTICES.txt` (the icons were
added there on 2026-10-20).

### ida-ttd-msttd.dll (Apache-2.0): ships, commercial use fine

- Built against the TTD Replay SDK, NuGet `Microsoft.TimeTravelDebugging.Apis`
  0.9.5: headers and import libraries only. Its nuspec says
  `<license type="expression">MIT</license>`, no acceptance required; nuget.org
  shows the same. So a DLL built from it may be redistributed and used
  commercially, keeping the MIT notice (already in the notices file).
- The TTD **runtime** (`TTDReplay.dll`, `TTDReplayCPU.dll`) is not in the
  package and must never be. WinDbg's license forbids redistributing it but
  not commercial use; the standalone TTD package's license forbids both. So it
  is copied from the user's own WinDbg install, or downloaded from Microsoft as
  WinDbg after the user accepts WinDbg's license
  (`scripts/ida_ttd_runtime.py`). That is how it works today.

### ida-ttd-sogen.dll: GPL-2.0, ships with its source

It does **not** link the IDA SDK or any of ida-ttd's libraries: it imports only
the MSVC runtime and Windows (checked on the built DLL), and talks to the
plugin through `src/abi/ida_ttd_backend.h`, which is CC0. What it does link,
from the link inputs, the CMake build and the symbols in its PDB:

| Component | License | Notes |
| --- | --- | --- |
| Sogen (windows-ttd, emulator, ...) | GPL-2.0-only (`LICENSE`, `pyproject.toml`) | makes the DLL GPL-2.0-only |
| Unicorn, with QEMU/TCG/softfloat | GPL-2.0 (`deps/unicorn/COPYING`; QEMU parts GPL-2.0-or-later, BSD, MIT) | 68 `uc_*` symbols in the PDB |
| Capstone (x86) | BSD-3-Clause, LLVM parts NCSA | notice required |
| Mbed TLS, everest, p256-m | Apache-2.0 OR GPL-2.0-or-later | taken under GPL here |
| zstd | BSD OR GPL-2.0 | notice required |
| base64, reflect (headers) | MIT | |
| Vulkan-Headers (headers) | Apache-2.0 OR MIT | |
| ida-ttd: `sogen_backend.cpp` | GPL-2.0-only (since 2026-10-20) | |
| ida-ttd: `write_scans.h` | Apache-2.0 OR GPL-2.0-only (since 2026-10-20) | taken under GPL here |
| ida-ttd: `ida_ttd_backend.h` | CC0-1.0 | |

Two dependencies looked like problems and are not in the DLL: **minidump_cpp**
(no license at all; GitHub reports none) and **flatbuffers** (Apache-2.0,
incompatible with GPL-2.0-only). Sogen's minidump loader uses the first; the
linker drops it, and a symbol search of the PDB finds no `minidump` or
`flatbuffers` symbol (the same search finds Unicorn, Mbed TLS and zstd). **Check
again whenever the Sogen pin moves**: if either appears, the DLL cannot ship
until it is gone or minidump_cpp's author grants a license.

Swapping Unicorn for Sogen's icicle (MIT OR Apache-2.0) or WHP backend would
not change the outcome. Sogen itself is GPL-2.0-only, and the view that
reads registers links Unicorn directly.

## Using it at work

GPL-2.0 puts no restriction on use, commercial or otherwise; its obligations
apply only to whoever *distributes* the binary. An analyst who installs the
Sogen backend and uses it on the job owes nothing. A company that passes the
DLL on to others has the same obligations as the project (below). The
Microsoft backend and the plugin are Apache-2.0 and MIT throughout. The TTD
runtime comes from WinDbg on the user's machine, under WinDbg's license, which
permits commercial use.

## Before the Sogen backend ships

1. **Done 2026-10-20: the two ida-ttd files compiled into it are relicensed.**
   They were Apache-2.0, which the FSF holds incompatible with GPL-2.0. Now
   `sogen_backend.cpp` is GPL-2.0-only (it is only ever built into the GPL
   binary), and `write_scans.h` is Apache-2.0 OR GPL-2.0-only. GPL-only would
   have made the Microsoft backend, which compiles it too, a GPL binary. The
   GPL text is in `LICENSES/GPL-2.0-only.txt`. Everything else in the
   repository is Apache-2.0, apart from the ABI header (CC0).
2. **Distribute the source with the binary.** GPL-2.0 section 3: the DLL goes
   out with the complete corresponding source, or a written offer good for
   three years. The source is:
   - the exact Sogen commit and every `deps/` submodule commit;
   - `src/backend-sogen/`, `src/common/write_scans.h`, `src/abi/`;
   - the build files (`backend-sogen.vcxproj`, the CMake options).

   The simplest compliant form is a source archive attached to the same
   release as the DLL. Section 3's last paragraph allows source offered "from
   the same place". A link to someone else's GitHub repository is weaker.
3. **Ship the license and notices with the DLL**: the GPL-2.0 text, plus the
   notices for Capstone, zstd, Mbed TLS and the header-only libraries.
4. **Keep it a separate download** (the TODO plan: CI builds it from the pinned
   commit and attaches it to the release, and a menu item fetches it, like the
   TTD runtime). The plugin and the backend are separate works that meet only
   at a published C ABI that another backend also implements. Putting them in
   one zip would be "mere aggregation" on that reading. A separate download
   keeps the question from arising, so the Apache-2.0 package on the plugin
   repository stays free of GPL code.

Asking Sogen's author for an exception is **not needed** for this route.
GPL-2.0 already allows everything above. An exception could not cover Unicorn
in any case, and Unicorn's copyright is not his.

## Corrections to older documents

- `docs/modular-backends.md` section 3 calls the IDA SDK proprietary. The SDK
  headers and import libraries are MIT now (`ida-sdk/LICENSE`). IDA itself is
  still proprietary. Nothing changes: no backend links either.
