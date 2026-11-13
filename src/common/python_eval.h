#pragma once

#include "common/pch.h"
#include <expr.hpp>

#include <initializer_list>

namespace idattd
{
    // Running Python through IDAPython's extlang, which is how the plugin
    // reaches the Qt changes, the settings and the windows that live in
    // scripts/. Every caller used to look the extlang up and check its
    // members itself; these are that code, once.
    //
    // IDAPython can be missing (not installed, or not loaded yet in an idalib
    // worker), so each caller decides what that means: some stay silent,
    // some say so.

    // IDAPython is loaded and can run statements (and, with 'with_expr',
    // evaluate an expression too).
    bool python_available(bool with_expr = false);

    // Run 'code' as Python statements. False without IDAPython, with *err
    // left as it was, or when the code raised, with the message in *err.
    bool eval_py(const char *code, qstring *err);

    // Evaluate the Python expression 'expr' into *rv. False without
    // IDAPython (or without its expression evaluator), with *err left as it
    // was, or when the expression raised, with the message in *err.
    bool eval_py_expr(idc_value_t *rv, const char *expr, qstring *err);

    // import <module>; <module>.<fn>(args...), each argument passed as a
    // quoted string literal (json_str). As eval_py otherwise.
    bool call_py(const char *module, const char *fn,
                 std::initializer_list<const char *> args, qstring *err);
}
