#include "analysis/fork.h"
#include "analysis/query_runner.h"
#include "debugger/trace_manager.h"

#include <filesystem>

namespace idattd
{
    static const struct { const char *name; int index; } g_fork_regs[] = {
        { "rax", ITTD_REG_RAX }, { "rcx", ITTD_REG_RCX }, { "rdx", ITTD_REG_RDX },
        { "rbx", ITTD_REG_RBX }, { "rsp", ITTD_REG_RSP }, { "rbp", ITTD_REG_RBP },
        { "rsi", ITTD_REG_RSI }, { "rdi", ITTD_REG_RDI }, { "r8", 8 },  { "r9", 9 },
        { "r10", 10 }, { "r11", 11 }, { "r12", 12 }, { "r13", 13 }, { "r14", 14 },
        { "r15", ITTD_REG_R15 }, { "rip", ITTD_REG_RIP },
        { "rflags", FORK_REG_RFLAGS }, { "eflags", FORK_REG_RFLAGS },
    };

    static bool is_sep(char c)
    {
        return c == ' ' || c == '\t' || c == ',' || c == ';' || c == '\r' || c == '\n';
    }

    static bool parse_u64(const qstring &s, uint64_t *out)
    {
        if ( s.empty() )
            return false;
        char *end = nullptr;
        unsigned long long v = strtoull(s.c_str(), &end, 0);
        if ( end == nullptr || *end != '\0' )
        {
            // Plain hex without 0x, as IDA shows registers ("7FF6A0001000").
            v = strtoull(s.c_str(), &end, 16);
            if ( end == nullptr || *end != '\0' )
                return false;
        }
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
                    char pair[3] = { hex[k], hex[k + 1], '\0' };
                    char *end = nullptr;
                    unsigned long b = strtoul(pair, &end, 16);
                    if ( end == nullptr || *end != '\0' )
                    {
                        err->sprnt("\"%s\" is not hex bytes", value.c_str());
                        return false;
                    }
                    bytes.push_back((uchar)b);
                }
            }
            out->emplace_back((ea_t)ea, std::move(bytes));
        }
        return true;
    }

    qstring default_fork_path(TraceManager *mgr)
    {
        if ( mgr == nullptr || mgr->trace_path().empty() )
            return qstring("fork.sogttd");
        std::filesystem::path p = std::filesystem::u8path(mgr->trace_path().c_str());
        qstring pos = format_position(mgr->current_position());
        for ( size_t k = 0; k < pos.length(); k++ )
            if ( pos[k] == ':' )
                pos[k] = '-';
        std::u8string name = p.stem().u8string();
        name += u8"-fork-";
        name += reinterpret_cast<const char8_t *>(pos.c_str());
        name += u8".sogttd";
        std::u8string out = (p.parent_path() / std::filesystem::path(name)).u8string();
        return qstring(reinterpret_cast<const char *>(out.c_str()));
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
        run_query("Forking the recording: replaying to the position, then recording", [&](ProgressSink *p)
        {
            result = backend->record_fork(req, p);
            QueryResult q;
            q.ran = result.ok;
            q.cancelled = result.cancelled;
            return q;
        });
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
