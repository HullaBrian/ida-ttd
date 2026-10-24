// pch.h: precompiled header for the ida-ttd plugin.
//
// Order matters: Windows first (lean, NOMINMAX, so it does not clobber the IDA
// SDK or the STL), then the IDA SDK. The TTD Replay SDK belongs to the
// Microsoft backend alone (backend-msttd/msttd_pch.h).
#ifndef PCH_H
#define PCH_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

// ---------------------------------------------------------------------------
// IDA SDK
//
// Defined before the SDK so pro.h does not "poison" the standard file and
// string functions (fgetc/fputc redefined to dont_use_* breaks <fstream>).
// ---------------------------------------------------------------------------
#ifndef USE_DANGEROUS_FUNCTIONS
#define USE_DANGEROUS_FUNCTIONS 1
#endif
#ifndef USE_STANDARD_FILE_FUNCTIONS
#define USE_STANDARD_FILE_FUNCTIONS
#endif
#ifndef NO_OBSOLETE_FUNCS
#define NO_OBSOLETE_FUNCS
#endif

#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <idd.hpp>
#include <dbg.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <segment.hpp>
#include <name.hpp>
#include <bytes.hpp>
#include <nalt.hpp>
#include <offset.hpp>
#include <netnode.hpp>
#include <funcs.hpp>
#include <typeinf.hpp>
#include <ua.hpp>
#include <auto.hpp>
#include <registry.hpp>

// ---------------------------------------------------------------------------
// STL
// ---------------------------------------------------------------------------
#include <memory>
#include <array>
#include <functional>
#include <vector>
#include <deque>
#include <mutex>
#include <atomic>
#include <thread>
#include <chrono>
#include <set>
#include <string>
#include <optional>
#include <algorithm>
#include <filesystem>
#include <fstream>

#endif //PCH_H
