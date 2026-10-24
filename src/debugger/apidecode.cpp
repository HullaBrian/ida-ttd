#include "debugger/apidecode.h"
#include "debugger/callconv.h"
#include "debugger/module_registry.h"
#include "analysis/syscalls.h"

namespace idattd
{
    using win32meta::ArgKind;
    using win32meta::AuxKind;
    using win32meta::FuncSig;
    using win32meta::ParamSig;

    namespace
    {
        const size_t kMaxPreview = 32;      // bytes of a buffer shown
        const size_t kX86Align   = 4;
        const size_t kMaxParams  = 32;

        bool    g_tried = false;
        qstring g_error;

        bool ensure_loaded()
        {
            if ( !g_tried )
            {
                g_tried = true;
                std::string err;
                if ( !win32meta::loadIndex({}, err) )
                {
                    g_error = err.c_str();
                    msg("[ida-ttd] API metadata not loaded (%s): calls are decoded from IDA's types only.\n",
                        err.c_str());
                }
            }
            return win32meta::index().loaded();
        }

        bool type_is(const ParamSig &p, const char *name)
        {
            return p.type != nullptr && strcmp(p.type, name) == 0;
        }

        // From ttd-capa's abi.cpp: what one parameter occupies on the x86
        // stack, or 0 when the metadata cannot say (a by-value aggregate, an
        // ambiguous 8-byte scalar), after which no offset can be trusted.
        size_t x86_footprint(const ParamSig &p)
        {
            if ( p.x86Footprint != 0 )
                return (p.x86Footprint + kX86Align - 1) / kX86Align * kX86Align;
            if ( p.kind == ArgKind::StructPtr )
            {
                size_t len = p.type != nullptr ? strlen(p.type) : 0;
                bool by_value = len == 0
                             || (p.type[len - 1] != '*' && !(len >= 2 && p.type[len - 2] == '[' && p.type[len - 1] == ']'));
                if ( by_value )
                    return 0;
            }
            size_t size = 4;
            switch ( p.kind )
            {
                case ArgKind::Double:
                    size = 8;
                    break;
                case ArgKind::Integer:
                case ArgKind::Enum:
                case ArgKind::Bool:
                    if ( p.pointeeSize == 8 )
                    {
                        if ( type_is(p, "UIntPtr") || type_is(p, "IntPtr") )
                            size = 4;
                        else if ( type_is(p, "UInt64") || type_is(p, "Int64") )
                            size = 8;
                        else
                            return 0;
                    }
                    else
                    {
                        size = p.pointeeSize >= 1 && p.pointeeSize < 8 ? p.pointeeSize : 4;
                    }
                    break;
                default:
                    break;
            }
            return (size + kX86Align - 1) / kX86Align * kX86Align;
        }

        // Each parameter's byte offset from the first stack argument; false
        // when a footprint is unknown.
        bool x86_offsets(const FuncSig &sig, std::vector<size_t> *offsets)
        {
            size_t footprint[kMaxParams] = { 0 };
            uint8_t max_slot = 0;
            for ( uint8_t i = 0; i < sig.paramCount; i++ )
            {
                const ParamSig &p = sig.params[i];
                if ( p.slot >= kMaxParams )
                    return false;
                size_t b = x86_footprint(p);
                if ( b == 0 )
                    return false;
                footprint[p.slot] = b;
                max_slot = std::max(max_slot, p.slot);
            }
            size_t running[kMaxParams] = { 0 }, off = 0;
            for ( uint8_t s = 0; s <= max_slot; s++ )
            {
                running[s] = off;
                off += footprint[s] != 0 ? footprint[s] : kX86Align;
            }
            offsets->resize(sig.paramCount);
            for ( uint8_t i = 0; i < sig.paramCount; i++ )
                (*offsets)[i] = running[sig.params[i].slot];
            return true;
        }

        bool read_exact(const GuestView &v, uint64_t addr, void *buf, size_t n)
        {
            return addr != 0 && v.read && v.read(addr, buf, n) == n;
        }

        uint64_t read_uint(const GuestView &v, uint64_t addr, size_t n, bool *ok)
        {
            uint64_t x = 0;
            *ok = n <= 8 && read_exact(v, addr, &x, n);
            return x;
        }

        bool is_pointer_kind(ArgKind k)
        {
            switch ( k )
            {
                case ArgKind::AnsiString: case ArgKind::WideString:
                case ArgKind::AnsiBuffer: case ArgKind::WideBuffer: case ArgKind::ByteBuffer:
                case ArgKind::PtrToInt: case ArgKind::StructPtr: case ArgKind::Guid:
                case ArgKind::Pointer: case ArgKind::PtrToAnsiString: case ArgKind::PtrToWideString:
                case ArgKind::CountedAnsiString: case ArgKind::CountedWideString:
                    return true;
                default:
                    return false;
            }
        }

        qstring hex(uint64_t x)
        {
            qstring s;
            s.sprnt("0x%llX", (unsigned long long)x);
            return s;
        }

        qstring number(uint64_t x)
        {
            qstring s;
            if ( x < 10 )
                s.sprnt("%llu", (unsigned long long)x);
            else
                s = hex(x);
            return s;
        }

        // "NAME|NAME" for a value of a parameter with an enum, or empty.
        qstring enum_text(const ParamSig &p, uint64_t val)
        {
            qstring s;
            if ( !p.hasEnum() )
                return s;
            for ( const std::string &name : win32meta::index().decodeEnum(p.enumIndex, val) )
            {
                if ( !s.empty() )
                    s.append('|');
                s.append(name.c_str());
            }
            return s;
        }

        qstring int_text(const ParamSig &p, uint64_t val)
        {
            qstring s = enum_text(p, val);
            return s.empty() ? number(val) : s;
        }

        uint32_t pointee_width(const ParamSig &p, bool is64)
        {
            return p.pointeeSize >= 1 && p.pointeeSize <= 8 ? p.pointeeSize : (is64 ? 8 : 4);
        }

        // A buffer's length in bytes, from the parameter that holds it.
        uint64_t buffer_bytes(const DecodedCall &c, const ParamSig &p, const GuestView *at_return)
        {
            uint64_t n = 0;
            const size_t unit = p.kind == ArgKind::WideBuffer ? 2 : p.pointeeSize != 0 ? p.pointeeSize : 1;
            if ( p.auxKind == AuxKind::CountConst )
                return (uint64_t)p.auxValue * unit;
            if ( p.auxKind != AuxKind::BytesFromParam && p.auxKind != AuxKind::CountFromParam )
                return 0;
            if ( p.auxValue < 0 || (size_t)p.auxValue >= c.args.size() )
                return 0;
            const ParamSig &len = c.sig->params[p.auxValue];
            n = c.args[p.auxValue].raw;
            // A length passed by pointer (DWORD *lpNumberOfBytesRead): its value,
            // at the return when there is one.
            if ( len.kind == ArgKind::PtrToInt && at_return != nullptr )
            {
                bool ok = false;
                n = read_uint(*at_return, n, len.pointeeSize != 0 ? len.pointeeSize : 4, &ok);
                if ( !ok )
                    return 0;
            }
            else if ( len.kind == ArgKind::PtrToInt )
            {
                return 0;
            }
            return p.auxKind == AuxKind::CountFromParam ? n * unit : n;
        }

        qstring preview_bytes(const GuestView &v, uint64_t addr, uint64_t n, bool wide_text)
        {
            if ( addr == 0 )
                return "NULL";
            qstring s = hex(addr);
            if ( n == 0 )
                return s;
            std::vector<uint8_t> b((size_t)std::min<uint64_t>(n, kMaxPreview));
            size_t got = v.read ? v.read(addr, b.data(), b.size()) : 0;
            if ( got == 0 )
                return s;
            b.resize(got);
            // Text when it reads as text, else hex.
            size_t printable = 0;
            for ( size_t i = 0; i < b.size(); i += wide_text ? 2 : 1 )
                printable += b[i] >= 0x20 && b[i] < 0x7F;
            const size_t chars = wide_text ? (b.size() + 1) / 2 : b.size();
            s.cat_sprnt(" [%llu]: ", (unsigned long long)n);
            if ( chars != 0 && printable * 10 >= chars * 9 )
            {
                s.append('"');
                for ( size_t i = 0; i < b.size(); i += wide_text ? 2 : 1 )
                    s.append(b[i] >= 0x20 && b[i] < 0x7F ? (char)b[i] : '.');
                s.append('"');
            }
            else
            {
                for ( uint8_t c : b )
                    s.cat_sprnt("%02X", c);
            }
            if ( n > b.size() )
                s.append("...");
            return s;
        }

        qstring counted_string(const GuestView &v, uint64_t us, bool wide, bool is64)
        {
            if ( us == 0 )
                return "NULL";
            uint16_t len = 0;
            bool ok = false;
            len = (uint16_t)read_uint(v, us, 2, &ok);
            if ( !ok )
                return hex(us);
            uint64_t buf = read_uint(v, us + (is64 ? 8 : 4), is64 ? 8 : 4, &ok);
            if ( !ok || buf == 0 )
                return hex(us);
            std::vector<uint8_t> b(std::min<size_t>(len, 1024));
            if ( !read_exact(v, buf, b.data(), b.size()) )
                return hex(us);
            qstring s("\"");
            if ( wide )
            {
                qstring u8;
                utf16_utf8(&u8, (const wchar16_t *)b.data(), (int)(b.size() / 2));
                s.append(u8);
            }
            else
            {
                s.append((const char *)b.data(), b.size());
            }
            s.append('"');
            return s;
        }

        // How one value reads, as of the view.
        qstring render(const GuestView &v, const DecodedCall &c, const ParamSig &p, uint64_t x,
                       const GuestView *at_return)
        {
            const bool is64 = c.is64;
            if ( is_pointer_kind(p.kind) && x == 0 )
                return "NULL";
            switch ( p.kind )
            {
                case ArgKind::Bool:
                    return (uint32_t)x != 0 ? "TRUE" : "FALSE";
                case ArgKind::Handle:
                    if ( x == ~0ull || (!is64 && x == 0xFFFFFFFFull) )
                        return "-1";
                    return hex(x);
                case ArgKind::Enum:
                    return int_text(p, x);
                case ArgKind::Integer:
                {
                    qstring s = enum_text(p, x);
                    return !s.empty() ? s : number(p.pointeeSize == 4 ? (uint32_t)x : x);
                }
                case ArgKind::AnsiString:
                    return qstring("\"") + read_string_at(v, x) + "\"";
                case ArgKind::WideString:
                    return qstring("L\"") + read_wstring_at(v, x) + "\"";
                case ArgKind::AnsiBuffer:
                case ArgKind::WideBuffer:
                case ArgKind::ByteBuffer:
                    return preview_bytes(v, x, buffer_bytes(c, p, at_return), p.kind == ArgKind::WideBuffer);
                case ArgKind::PtrToInt:
                {
                    bool ok = false;
                    uint64_t val = read_uint(v, x, pointee_width(p, is64), &ok);
                    return ok ? hex(x) + " -> " + int_text(p, val) : hex(x);
                }
                case ArgKind::Guid:
                {
                    uint8_t b[16];
                    if ( !read_exact(v, x, b, sizeof(b)) )
                        return hex(x);
                    qstring s;
                    s.sprnt("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                            *(uint32_t *)b, *(uint16_t *)(b + 4), *(uint16_t *)(b + 6),
                            b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
                    return s;
                }
                case ArgKind::PtrToAnsiString:
                case ArgKind::PtrToWideString:
                {
                    bool ok = false;
                    uint64_t str = read_uint(v, x, is64 ? 8 : 4, &ok);
                    if ( !ok || str == 0 )
                        return hex(x);
                    return hex(x) + " -> " + (p.kind == ArgKind::PtrToWideString
                                              ? qstring("L\"") + read_wstring_at(v, str) + "\""
                                              : qstring("\"") + read_string_at(v, str) + "\"");
                }
                case ArgKind::StructPtr:
                    // The one structure worth opening: what a native call names.
                    if ( type_is(p, "OBJECT_ATTRIBUTES*") )
                    {
                        bool ok = false;
                        uint64_t us = read_uint(v, x + (is64 ? 16 : 8), is64 ? 8 : 4, &ok);
                        return ok && us != 0 ? counted_string(v, us, true, is64) : hex(x);
                    }
                    return hex(x);
                case ArgKind::CountedAnsiString:
                    return counted_string(v, x, false, is64);
                case ArgKind::CountedWideString:
                    return counted_string(v, x, true, is64);
                default:
                    return hex(x);
            }
        }

        bool is_native(const char *name)
        {
            return (name[0] == 'N' && name[1] == 't') || (name[0] == 'Z' && name[1] == 'w')
                || strncmp(name, "Rtl", 3) == 0 || strncmp(name, "Ldr", 3) == 0;
        }
    }

    const qstring &api_metadata_error()
    {
        ensure_loaded();
        return g_error;
    }

    const FuncSig *api_signature(const char *name)
    {
        if ( name == nullptr || *name == '\0' || !ensure_loaded() )
            return nullptr;
        qstring n(name);
        // Strip "module!", IDA's import and thunk prefixes, and its "_0"
        // suffix for a second name.
        ssize_t bang = n.rfind('!');
        if ( bang >= 0 )
            n.remove(0, (size_t)bang + 1);
        if ( strncmp(n.c_str(), "__imp_", 6) == 0 )
            n.remove(0, 6);
        if ( strncmp(n.c_str(), "j_", 2) == 0 )
            n.remove(0, 2);
        const FuncSig *sig = win32meta::index().lookup(std::string_view(n.c_str(), n.length()));
        if ( sig == nullptr )
        {
            ssize_t us = n.rfind('_');
            if ( us > 0 && us + 1 < (ssize_t)n.length() && qisdigit(n[us + 1]) )
            {
                n.resize((size_t)us);
                sig = win32meta::index().lookup(std::string_view(n.c_str(), n.length()));
            }
        }
        return sig != nullptr && !sig->unsupported() ? sig : nullptr;
    }

    const FuncSig *api_signature(ModuleRegistry *mods, ea_t func_ea)
    {
        if ( mods != nullptr )
        {
            qstring e = mods->export_name_at(func_ea);
            if ( !e.empty() )
                if ( const FuncSig *s = api_signature(e.c_str()) )
                    return s;
        }
        qstring n;
        if ( get_name(&n, func_ea) > 0 )
            return api_signature(n.c_str());
        return nullptr;
    }

    void decode_api_args(const GuestView &v, const FuncSig &sig, bool is64, DecodedCall *out)
    {
        out->sig  = &sig;
        out->is64 = is64;
        out->args.clear();
        ittd_regs r{};
        if ( !v.regs || !v.regs(&r) )
            return;
        std::vector<size_t> offs;
        const bool have_offs = is64 || x86_offsets(sig, &offs);
        out->args.resize(sig.paramCount);
        // The raw values first: a buffer's length can live in a later parameter.
        for ( uint8_t i = 0; i < sig.paramCount; i++ )
        {
            const ParamSig &p = sig.params[i];
            DecodedArg &a = out->args[i];
            a.name = p.name;
            // The metadata marks OBJECT_ATTRIBUTES "out"; its name goes in.
            a.out  = p.isOut() && is_pointer_kind(p.kind) && !type_is(p, "OBJECT_ATTRIBUTES*");
            bool ok = true;
            if ( is64 )
            {
                static const int GP[4] = { ITTD_REG_RCX, ITTD_REG_RDX, ITTD_REG_R8, ITTD_REG_R8 + 1 /* R9 */ };
                if ( p.slot < 4 && p.isFloat() )
                    memcpy(&a.raw, r.xmm[p.slot], sizeof(a.raw));     // the low 64 bits of XMMn
                else if ( p.slot < 4 )
                    a.raw = r.gp[GP[p.slot]];
                else
                    a.raw = read_uint(v, r.gp[ITTD_REG_RSP] + 0x20 + 8 * (uint64_t)(p.slot - 4), 8, &ok);
            }
            else if ( have_offs )
            {
                size_t n = x86_footprint(p) == 8 ? 8 : 4;
                a.raw = read_uint(v, r.gp[ITTD_REG_RSP] + offs[i], n, &ok);
            }
            else
            {
                ok = false;
            }
            if ( !ok )
                a.text = "?";
        }
        for ( uint8_t i = 0; i < sig.paramCount; i++ )
        {
            DecodedArg &a = out->args[i];
            if ( a.text == "?" )
                continue;
            const ParamSig &p = sig.params[i];
            if ( p.isFloat() )
            {
                if ( p.kind == ArgKind::Float )
                {
                    float f;
                    uint32_t bits = (uint32_t)a.raw;
                    memcpy(&f, &bits, 4);
                    a.text.sprnt("%g", f);
                }
                else
                {
                    double d;
                    memcpy(&d, &a.raw, 8);
                    a.text.sprnt("%g", d);
                }
                continue;
            }
            // An out parameter is only its address until the callee has run.
            a.text = a.out ? (a.raw == 0 ? qstring("NULL") : hex(a.raw)) : render(v, *out, p, a.raw, nullptr);
            if ( a.out && a.raw != 0 && p.kind == ArgKind::PtrToInt )
            {
                bool ok = false;
                uint64_t val = read_uint(v, a.raw, pointee_width(p, is64), &ok);
                if ( ok )
                    a.pointee_before = val;
            }
        }
    }

    std::vector<std::pair<size_t, uint32_t>> api_int_outs(const DecodedCall &call)
    {
        std::vector<std::pair<size_t, uint32_t>> v;
        if ( call.sig == nullptr )
            return v;
        for ( size_t i = 0; i < call.args.size() && i < call.sig->paramCount; i++ )
        {
            const ParamSig &p = call.sig->params[i];
            if ( !call.args[i].out || call.args[i].raw == 0 || p.kind != ArgKind::PtrToInt )
                continue;
            uint32_t w = p.pointeeSize == 4 || p.pointeeSize == 8 ? p.pointeeSize : (call.is64 ? 8 : 4);
            v.emplace_back(i, w);
        }
        return v;
    }

    qstring api_args_text(const DecodedCall &call)
    {
        qstring text;
        for ( const DecodedArg &a : call.args )
        {
            if ( !text.empty() )
                text.append(", ");
            text.cat_sprnt("%s=%s", a.name.c_str(), a.text.c_str());
        }
        return text;
    }

    void decode_api_outs(const GuestView &v, DecodedCall *call)
    {
        if ( call->sig == nullptr )
            return;
        for ( size_t i = 0; i < call->args.size() && i < call->sig->paramCount; i++ )
        {
            DecodedArg &a = call->args[i];
            if ( !a.out || a.raw == 0 || a.text == "?" )
                continue;
            const ParamSig &p = call->sig->params[i];
            if ( p.kind == ArgKind::PtrToInt && i < call->out_values.size() && call->out_values[i].has_value() )
            {
                a.text = hex(a.raw) + " -> " + int_text(p, *call->out_values[i]);
                continue;
            }
            if ( !v.read )
                continue;
            a.text = render(v, *call, p, a.raw, &v);
            if ( p.kind == ArgKind::PtrToInt )
            {
                bool ok = false;
                uint64_t val = read_uint(v, a.raw, pointee_width(p, call->is64), &ok);
                if ( ok )
                    a.pointee_after = val;
            }
        }
    }

    qstring decode_api_return(const DecodedCall &call, uint64_t rv)
    {
        qstring s;
        // Nt and Zw calls return an NTSTATUS. Rtl and Ldr ones mostly do, but
        // some return a pointer (RtlAllocateHeap) or a count, and the metadata
        // does not say which. A status written to eax clears rax's upper half,
        // so a value with upper bits set is not one, and truncating it would
        // show a wrong pointer.
        const bool status = call.sig != nullptr && is_native(call.sig->name)
                         && (call.sig->name[0] == 'N' || call.sig->name[0] == 'Z'
                          || !call.is64 || (rv >> 32) == 0);
        if ( status )
        {
            const char *st = ntstatus_name((uint32_t)rv);
            if ( st != nullptr )
                return st;
            s.sprnt("0x%08X", (uint32_t)rv);
            return s;
        }
        if ( !call.is64 )
            rv = (uint32_t)rv;
        s.sprnt("0x%llX", (unsigned long long)rv);
        return s;
    }
}
