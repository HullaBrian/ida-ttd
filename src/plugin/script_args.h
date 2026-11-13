#pragma once

// Reading a script command's words: the tokenizer, the arguments with
// their number, flag and option parsers, and the recording and replay
// options. A bad word throws ScriptError (fail), which dispatch turns into
// the command's error. The parsers' rules are beside their definitions in
// script_args.cpp.
#include "common/pch.h"
#include "core/backend.h"
#include "core/position.h"

#include <initializer_list>
#include <vector>

namespace idattd
{
    // ------------------------------------------------------------------ input

    // The words of a command line; double quotes group a word.
    std::vector<qstring> tokenize(const char *line);
    // A number as every command takes it: hex, or decimal after "0n".
    bool parse_u64(const qstring &s, uint64_t *out);
    // Throw a ScriptError with the formatted message.
    [[noreturn]] void fail(const char *fmt, ...);

    // Thrown for a bad command; turned into {"ok":false,"error":...}.
    struct ScriptError
    {
        qstring what;
    };

    struct Args
    {
        std::vector<qstring> v;     // v[0] is the command

        size_t count() const { return v.size() - 1; }
        const qstring &at(size_t i) const
        {
            if ( i + 1 >= v.size() )
                fail("'%s' needs more arguments; see 'help'", v[0].c_str());
            return v[i + 1];
        }
        uint64_t u64(size_t i) const
        {
            uint64_t x = 0;
            if ( !parse_u64(at(i), &x) )
                fail("'%s' is not a hex number", at(i).c_str());
            return x;
        }
        uint64_t u64_or(size_t i, uint64_t dflt) const { return i < count() ? u64(i) : dflt; }
        static bool is_back(const qstring &w)
        {
            return w == "back" || w == "backward" || w == "backwards";
        }
        // A "back", "backward" or "backwards" after the positional arguments
        // reverses a movement.
        bool back() const
        {
            for ( size_t i = 1; i < v.size(); i++ )
                if ( is_back(v[i]) )
                    return true;
            return false;
        }
        // The value of a "name=VALUE" word, or nullptr.
        const char *option(const char *name) const
        {
            const size_t n = qstrlen(name);
            for ( size_t i = 1; i < v.size(); i++ )
                if ( v[i].length() > n && v[i][n] == '=' && strneq(v[i].c_str(), name, n) )
                    return v[i].c_str() + n + 1;
            return nullptr;
        }
        // Refuse any word after the first 'positional' arguments that is
        // not one of 'words' (a flag, or "name=" for an option): a typo
        // ("runto 401000 bakc") must not quietly do something else.
        void only(size_t positional, std::initializer_list<const char *> words) const
        {
            for ( size_t i = positional + 1; i < v.size(); i++ )
            {
                bool known = false;
                for ( const char *w : words )
                {
                    const size_t n = qstrlen(w);
                    known = n != 0 && w[n - 1] == '='
                          ? strneq(v[i].c_str(), w, n)
                          : v[i] == w;
                    if ( known )
                        break;
                }
                if ( !known )
                    fail("'%s': unknown word '%s'; see 'help'", v[0].c_str(), v[i].c_str());
            }
        }
    };

    // An "rwx"-style word as access bits, in the caller's numbering.
    uint8_t rwx_mask(const qstring &k, uint8_t r, uint8_t w, uint8_t x);
    // A session position typed by the script.
    Position position_arg(const qstring &text);
    // A word that sets how a recording is made; false when it is not one.
    bool record_option(const qstring &t, RecordOptions *o);

    // What replay_option accepts, for the message refusing anything else.
    inline constexpr char REPLAY_OPTIONS[] = "registry=DIR, root=DIR, strict, host, anyregistry, "
                                             "net, nonet, ckpt=N, access=rwx, elevated or log";

    // A word that sets up a Sogen replay: registry=DIR, root=DIR (the
    // emulation root, when it is elsewhere here), strict, host, or
    // anyregistry (accept hives that are not the recording's), or one of
    // record_option's. ForkRequest and ReplaySettings name the fields alike.
    template <typename T>
    inline bool replay_option(const qstring &t, T *s)
    {
        if ( record_option(t, &s->rec) )
            return true;
        if ( t.starts_with("registry=") )
            s->registry_dir = t.substr(9);
        else if ( t.starts_with("root=") )
            s->emulation_root = t.substr(5);
        else if ( t == "strict" )
            s->strict = true;
        else if ( t == "host" )
            s->allow_host = true;
        else if ( t == "anyregistry" )
            s->any_registry = true;
        else
            return false;
        return true;
    }

    // How long to wait for a stop, in seconds (timeout=N, else the
    // positional argument 'positional' when there is one, else a minute).
    int timeout_of(const Args &a, size_t positional = SIZE_MAX);
    // The replay options from argument 'from' on.
    ReplaySettings replay_args(const Args &a, size_t from);
    // How many arguments come before the first replay option.
    size_t plain_args(const Args &a, size_t most);
}
