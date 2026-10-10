#pragma once

#include "common/pch.h"

namespace idattd
{
    // Copy ASCII text to the Windows clipboard. IDA exposes no clipboard API, so
    // this is the platform call.
    void copy_to_clipboard(const char *text);
}
