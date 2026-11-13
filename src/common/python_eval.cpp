#include "common/python_eval.h"
#include "common/json_str.h"

namespace idattd
{
    bool python_available(bool with_expr)
    {
        extlang_object_t py = find_extlang_by_name("Python");
        return py != nullptr && py->eval_snippet != nullptr
            && (!with_expr || py->eval_expr != nullptr);
    }

    bool eval_py(const char *code, qstring *err)
    {
        extlang_object_t py = find_extlang_by_name("Python");
        return py != nullptr && py->eval_snippet != nullptr
            && py->eval_snippet(code, err);
    }

    bool eval_py_expr(idc_value_t *rv, const char *expr, qstring *err)
    {
        extlang_object_t py = find_extlang_by_name("Python");
        return py != nullptr && py->eval_snippet != nullptr && py->eval_expr != nullptr
            && py->eval_expr(rv, BADADDR, expr, err);
    }

    bool call_py(const char *module, const char *fn,
                 std::initializer_list<const char *> args, qstring *err)
    {
        qstring code;
        code.sprnt("import %s\n%s.%s(", module, module, fn);
        bool first = true;
        for ( const char *a : args )
        {
            if ( !first )
                code.append(", ");
            first = false;
            json_str(&code, a);
        }
        code.append(")\n");
        return eval_py(code.c_str(), err);
    }
}
