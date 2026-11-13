#pragma once

#include "common/pch.h"

namespace idattd
{
    // Append UTF-8 's' as a quoted JSON string, which is also a Python
    // string literal: the one escaper for every model an IDAPython window
    // asks for (graphs, the call tree, the heatmap) and every string the
    // plugin passes to Python code it runs. Plain ASCII apart from
    // characters outside the BMP (as UTF-8); bytes that are not UTF-8 come
    // out as U+FFFD.
    void json_str(qstring *out, const char *s);
}
