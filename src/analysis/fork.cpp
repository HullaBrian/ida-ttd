#include "analysis/fork.h"
#include "analysis/query_runner.h"
#include "debugger/trace_manager.h"
#include "analysis/fork_registry.h"
#include "analysis/replay_scans.h"

#include <filesystem>

namespace idattd
{
    static const struct { const char *name; int index; } g_fork_regs[] = {
        { "rax", ITTD_REG_RAX }, { "rcx", ITTD_REG_RCX }, { "rdx", ITTD_REG_RDX },
        { "rbx", ITTD_REG_RBX }, { "rsp", ITTD_REG_RSP }, { "rbp", ITTD_REG_RBP },
        { "rsi", ITTD_REG_RSI }, { "rdi", ITTD_REG_RDI },
        { "r8", ITTD_REG_R8 }, { "r9", ITTD_REG_R8 + 1 }, { "r10", ITTD_REG_R8 + 2 },
        { "r11", ITTD_REG_R8 + 3 }, { "r12", ITTD_REG_R8 + 4 }, { "r13", ITTD_REG_R8 + 5 },
        { "r14", ITTD_REG_R8 + 6 }, { "r15", ITTD_REG_R15 }, { "rip", ITTD_REG_RIP },
        { "rflags", FORK_REG_RFLAGS }, { "eflags", FORK_REG_RFLAGS },
    };

    static bool is_sep(char c)
    {
        return c == ' ' || c == '\t' || c == ',' || c == ';' || c == '\r' || c == '\n';
    }

    // Hex, as IDA shows addresses and registers ("140001000", "0x10"); "0n"
    // or "#" in front for decimal. Never base 0: "140001000" read as decimal,
    // or "0000000000401000" as octal, would change the wrong thing.
    static bool parse_u64(const qstring &s, uint64_t *out)
    {
        if ( s.empty() )
            return false;
        const char *p = s.c_str();
        int base = 16;
        if ( p[0] == '0' && (p[1] == 'x' || p[1] == 'X') )
            p += 2;
        else if ( p[0] == '0' && (p[1] == 'n' || p[1] == 'N') )
            p += 2, base = 10;
        else if ( p[0] == '#' )
            p += 1, base = 10;
        // A minus sign is two's complement ("-1" is all ones). strtoull would
        // also take leading blanks and a plus sign, and saturate on overflow:
        // none of those is a value anyone meant to write.
        const char d = *p == '-' ? p[1] : *p;
        if ( base == 16 ? !qisxdigit(d) : !qisdigit(d) )
            return false;
        char *end = nullptr;
        errno = 0;
        unsigned long long v = strtoull(p, &end, base);
        if ( end == nullptr || *end != '\0' || errno == ERANGE )
            return false;
        *out = v;
        return true;
    }

    static qstring trimmed(const qstring &s)
    {
        size_t a = 0, b = s.length();
        while ( a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n') )
            a++;
        while ( b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n') )
            b--;
        return s.substr(a, b);
    }

    bool parse_fork_registers(const char *text, std::vector<std::pair<int, uint64_t>> *out, qstring *err)
    {
        out->clear();
        qstring t(text != nullptr ? text : "");
        size_t i = 0;
        while ( i < t.length() )
        {
            while ( i < t.length() && is_sep(t[i]) )
                i++;
            if ( i >= t.length() )
                break;
            size_t j = i;
            while ( j < t.length() && !is_sep(t[j]) )
                j++;
            qstring item = t.substr(i, j);
            i = j;
            ssize_t eq = item.find('=');
            if ( eq <= 0 )
            {
                err->sprnt("\"%s\" is not REGISTER=VALUE", item.c_str());
                return false;
            }
            qstring name = item.substr(0, eq);
            qstring value = item.substr(eq + 1);
            for ( size_t k = 0; k < name.length(); k++ )
                name[k] = qtolower(name[k]);
            int index = -1;
            for ( const auto &r : g_fork_regs )
                if ( name == r.name )
                    index = r.index;
            if ( index < 0 )
            {
                err->sprnt("unknown register \"%s\" (the 64-bit general registers, rip and rflags "
                           "can be changed)", name.c_str());
                return false;
            }
            uint64_t v = 0;
            if ( !parse_u64(value, &v) )
            {
                err->sprnt("\"%s\" is not a number", value.c_str());
                return false;
            }
            out->emplace_back(index, v);
        }
        return true;
    }

    bool parse_fork_memory(const char *text, std::vector<std::pair<ea_t, bytevec_t>> *out, qstring *err)
    {
        out->clear();
        qstring t(text != nullptr ? text : "");
        size_t i = 0;
        while ( i <= t.length() )
        {
            size_t j = i;
            while ( j < t.length() && t[j] != ';' && t[j] != '\n' )
                j++;
            qstring item = trimmed(t.substr(i, j));
            i = j + 1;
            if ( item.empty() )
                continue;
            ssize_t eq = item.find('=');
            uint64_t ea = 0;
            if ( eq <= 0 || !parse_u64(trimmed(item.substr(0, eq)), &ea) )
            {
                err->sprnt("\"%s\" is not ADDRESS=VALUE", item.c_str());
                return false;
            }
            qstring value = trimmed(item.substr(eq + 1));
            bytevec_t bytes;
            if ( value.length() > 2 && (value[0] == 'q' || value[0] == 'd') && value[1] == ':' )
            {
                uint64_t v = 0;
                if ( !parse_u64(trimmed(value.substr(2)), &v) )
                {
                    err->sprnt("\"%s\" is not a number", value.c_str() + 2);
                    return false;
                }
                size_t n = value[0] == 'q' ? 8 : 4;
                // Unsigned, or negative as a 32-bit two's complement ("d:-1").
                const int64_t sv = (int64_t)v;
                if ( n == 4 && v > 0xFFFFFFFFull && !(sv < 0 && sv >= INT32_MIN) )
                {
                    err->sprnt("\"%s\" does not fit in 32 bits", value.c_str() + 2);
                    return false;
                }
                for ( size_t k = 0; k < n; k++ )
                    bytes.push_back((uchar)(v >> (8 * k)));
            }
            else
            {
                qstring hex;
                for ( char c : value )
                    if ( c != ' ' && c != '\t' )
                        hex.append(c);
                if ( hex.empty() || hex.length() % 2 != 0 )
                {
                    err->sprnt("\"%s\" is not hex bytes (write them as 90 90 C3)", value.c_str());
                    return false;
                }
                for ( size_t k = 0; k < hex.length(); k += 2 )
                {
                    // Both digits checked: strtoul would take "-1" or "+1".
                    if ( !qisxdigit(hex[k]) || !qisxdigit(hex[k + 1]) )
                    {
                        err->sprnt("\"%s\" is not hex bytes", value.c_str());
                        return false;
                    }
                    char pair[3] = { hex[k], hex[k + 1], '\0' };
                    bytes.push_back((uchar)strtoul(pair, nullptr, 16));
                }
            }
            out->emplace_back((ea_t)ea, std::move(bytes));
        }
        return true;
    }

    qstring default_fork_path(TraceManager *mgr, Position at)
    {
        if ( mgr == nullptr || mgr->trace_path().empty() )
            return qstring("fork.sogttd");
        std::filesystem::path p = std::filesystem::u8path(mgr->trace_path().c_str());
        qstring pos = format_position(at);
        for ( size_t k = 0; k < pos.length(); k++ )
            if ( pos[k] == ':' )
                pos[k] = '-';
        std::u8string base = p.stem().u8string();
        base += u8"-fork-";
        base += reinterpret_cast<const char8_t *>(pos.c_str());
        // Another fork at the same position gets a name of its own rather
        // than the earlier one's: -2, -3, ...
        for ( int n = 1; ; n++ )
        {
            std::u8string name = base;
            if ( n > 1 )
                name += reinterpret_cast<const char8_t *>(("-" + std::to_string(n)).c_str());
            name += u8".sogttd";
            std::u8string out = (p.parent_path() / std::filesystem::path(name)).u8string();
            qstring q(reinterpret_cast<const char *>(out.c_str()));
            if ( !qfileexist(q.c_str()) || n >= 1000 )
                return q;
        }
    }

    qstring describe_fork_changes(const ForkRequest &req)
    {
        qstring s;
        for ( const auto &[idx, v] : req.regs )
        {
            const char *name = "?";
            for ( const auto &r : g_fork_regs )
                if ( r.index == idx )
                {
                    name = r.name;
                    break;
                }
            s.cat_sprnt("%s%s=0x%llX", s.empty() ? "" : ", ", name, (unsigned long long)v);
        }
        for ( const auto &[ea, bytes] : req.memory )
            s.cat_sprnt("%s%u byte%s at 0x%llX", s.empty() ? "" : ", ", (uint)bytes.size(),
                        bytes.size() == 1 ? "" : "s", (unsigned long long)ea);
        return s.empty() ? qstring("no changes") : s;
    }

    ForkResult run_fork(TraceManager *mgr, const ForkRequest &req)
    {
        ForkResult result;
        if ( mgr == nullptr || !mgr->is_active() || mgr->backend() == nullptr )
        {
            result.error = "no recording is being replayed";
            return result;
        }
        ITraceBackend *backend = mgr->backend();
        if ( !backend->capabilities().fork )
        {
            result.error = "this recording's backend cannot fork it";
            return result;
        }
        // The hives the user chose, or the documented folder, whoever built
        // the request (the Fork dialog fills it in; a script may not).
        ForkRequest full = req;
        if ( full.registry_dir.empty() )
            full.registry_dir = saved_registry_dir();
        run_query("Forking the recording: replaying to the position, then recording", [&](ProgressSink *p)
        {
            result = backend->record_fork(full, p);
            QueryResult q;
            q.ran = result.ok;
            q.cancelled = result.cancelled;
            return q;
        });
        // A failure that left no words of its own (the backend threw, say)
        // still has to say something.
        if ( !result.ok && !result.cancelled && result.error.empty() )
        {
            result.error = backend->last_error();
            if ( result.error.empty() )
                result.error = "the fork did not complete";
        }
        // Remembered for the Fork manager, whoever asked for it.
        if ( result.ok )
        {
            ForkRecord rec;
            rec.path         = req.path;
            rec.parent       = mgr->trace_path();
            rec.at           = format_position(req.at);
            rec.changes      = describe_fork_changes(req);
            rec.instructions = result.instructions;
            rec.time         = (uint64_t)qtime64();
            add_fork_record(rec);
        }
        return result;
    }

    bool open_in_new_ida(const char *path)
    {
        wchar_t exe[MAX_PATH] = {};
        if ( GetModuleFileNameW(nullptr, exe, MAX_PATH) == 0 )
            return false;
        qwstring wpath;
        utf8_utf16(&wpath, path);
        std::wstring cmd = L"\"";
        cmd += exe;
        cmd += L"\" \"";
        cmd += wpath.c_str();
        cmd += L"\"";
        STARTUPINFOW si{};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        if ( !CreateProcessW(exe, cmd.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi) )
            return false;
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return true;
    }
}
