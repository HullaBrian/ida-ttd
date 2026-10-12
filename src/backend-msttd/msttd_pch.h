#pragma once

// What every file of the Microsoft backend includes first: the shared
// precompiled header, then the TTD Replay SDK, which nothing outside
// src/backend-msttd/ may see.
#include "common/pch.h"

// ---------------------------------------------------------------------------
// Microsoft TTD Replay SDK
// ---------------------------------------------------------------------------
#include <cassert>
#ifndef DBG_ASSERT
#define DBG_ASSERT(cond) assert(cond)
#endif

#include <TTD/IReplayEngine.h>
#include <TTD/IReplayEngineStl.h>
#include <TTD/IReplayEngineRegisters.h>
#include <TTD/ErrorReporting.h>
