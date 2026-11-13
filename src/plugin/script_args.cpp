#include "plugin/script_args.h"
#include "plugin/script_internal.h"
#include "plugin/settings.h"
#include "analysis/replay_scans.h"

#include <errno.h>

namespace idattd
{
    // ------------------------------------------------------------------ input

    std::vector<qstring> tokenize(const char *line)
    {
        std::vector<qstring> out;
        const char *p = line;
        while ( *p != '\0' )
        {
            while ( *p == ' ' || *p == '\t' )
                p++;
            if ( *p == '\0' )
                break;
            // Quotes may sit anywhere in a word: registry="C:\Program Files\x"
            // is one argument. There is no escape for a literal quote.
            qstring tok;
            bool quoted = false;
            for ( ; *p != '\0' && (quoted || (*p != ' ' && *p != '\t')); p++ )
            {
                if ( *p == '"' )
                    quoted = !quoted;
                else
                    tok.append(*p);
            }
            out.push_back(tok);
        }
        return out;
    }

    // Every number a command takes is hex, with or without "0x", as IDA and
    // WinDbg show addresses; "0n" marks a decimal one, as in WinDbg ("0n10"
    // is ten). One rule for addresses and counts alike: "an.strings 10" is
    // sixteen characters.
    bool parse_u64(const qstring &s, uint64_t *out)
    {
        const char *p = s.c_str();
        int base = 16;
        if ( p[0] == '0' && (p[1] == 'x' || p[1] == 'X') )
            p += 2;
        else if ( p[0] == '0' && (p[1] == 'n' || p[1] == 'N') )
        {
            p += 2;
            base = 10;
        }
        // Reject what strtoull would accept but is no number here: leading
        // blanks, a sign ("-1" as 0xFFFF...), overflow.
        if ( base == 16 ? !isxdigit((unsigned char)*p) : !isdigit((unsigned char)*p) )
            return false;
        char *end = nullptr;
        errno = 0;
        *out = strtoull(p, &end, base);
        return end != nullptr && *end == '\0' && errno != ERANGE;
    }

    [[noreturn]] void fail(const char *fmt, ...)
    {
        va_list va;
        va_start(va, fmt);
        ScriptError e;
        e.what.vsprnt(fmt, va);
        va_end(va);
        throw e;
    }

    // An "rwx"-style word as access bits: any of the letters r, w and x, at
    // least one, nothing else (so "an.search LO HI 50", a MAX where the kinds
    // go, is refused rather than read as no kinds). The backend ABI and the
    // analyses number the kinds differently, so the caller supplies the bits.
    uint8_t rwx_mask(const qstring &k, uint8_t r, uint8_t w, uint8_t x)
    {
        uint8_t m = 0;
        for ( size_t i = 0; i < k.length(); i++ )
        {
            switch ( k[i] )
            {
                case 'r': m |= r; break;
                case 'w': m |= w; break;
                case 'x': m |= x; break;
                default:
                    fail("'%s': access kinds are the letters r, w and x", k.c_str());
            }
        }
        if ( m == 0 )
            fail("'%s': name at least one of r, w and x", k.c_str());
        return m;
    }

    // A session position typed by the script, or a failure that says why.
    Position position_arg(const qstring &text)
    {
        Position p;
        if ( !parse_position(text.c_str(), &p) )
            fail("'%s' is not a position (%s)", text.c_str(), position_syntax());
        return p;
    }

    // A word that sets how a recording is made (RecordOptions), over the
    // Sogen settings: net / nonet (network access past a fork's position, or
    // from a new recording's start), ckpt=N (the checkpoint interval, hex
    // like every number here), access=rwx (what is kept: any of r, w, x),
    // elevated (new recordings), log (the emulator's log to the output
    // window).
    bool record_option(const qstring &t, RecordOptions *o)
    {
        if ( t == "net" )
            o->network = true;
        else if ( t == "nonet" )
            o->network = false;
        else if ( t == "elevated" )
            o->elevated = true;
        else if ( t == "log" )
            o->log = true;
        else if ( t.starts_with("ckpt=") )
        {
            uint64_t n = 0;
            if ( !parse_u64(t.substr(5), &n) )
                fail("'%s': the checkpoint interval is a hex number", t.c_str());
            o->checkpoint_interval = n;
        }
        else if ( t.starts_with("access=") )
        {
            o->access_mask = rwx_mask(t.substr(7), ITTD_ACCESS_READ, ITTD_ACCESS_WRITE, ITTD_ACCESS_EXEC);
        }
        else
            return false;
        return true;
    }

    // How long to wait for a stop: "timeout=N" seconds anywhere, else the
    // positional argument 'positional' when the command has one (start,
    // wait and switch take it bare), else a minute.
    int timeout_of(const Args &a, size_t positional)
    {
        uint64_t s = 0x3C;
        if ( const char *t = a.option("timeout") )
        {
            if ( !parse_u64(t, &s) )
                fail("'timeout=%s': the timeout is a number of seconds (hex, or 0n for decimal)", t);
        }
        else if ( positional != SIZE_MAX && positional < a.count() )
        {
            s = a.u64(positional);
        }
        // Capped at a day: a cast alone would turn a large value negative,
        // which IDA reads as "wait forever".
        return (int)qmin(s, uint64_t(86400));
    }

    // Replay options (replay_option) from argument 'from' on. Any other word
    // is refused, so a typo (registy=) is not silently ignored.
    ReplaySettings replay_args(const Args &a, size_t from)
    {
        ReplaySettings rs;
        rs.registry_dir = find_registry_dir(&mgr());
        rs.emulation_root = chosen_emulation_root(&mgr());
        rs.rec = recording_options();
        for ( size_t i = from; i < a.count(); i++ )
            if ( !replay_option(a.at(i), &rs) )
                fail("'%s' is not %s", a.at(i).c_str(), REPLAY_OPTIONS);
        return rs;
    }

    // How many arguments come before the first replay option; more than
    // 'most' is refused, so a stray word is not silently ignored.
    size_t plain_args(const Args &a, size_t most)
    {
        ReplaySettings scratch;
        size_t n = 0;
        while ( n < a.count() && !replay_option(a.at(n), &scratch) )
            n++;
        if ( n > most )
            fail("'%s': at most %d number(s) come before the options, which are %s",
                 a.at(most).c_str(), (int)most, REPLAY_OPTIONS);
        return n;
    }
}
