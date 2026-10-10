#include "core/position.h"

namespace idattd
{
    const char *position_syntax()
    {
        return "Sequence:Steps in hex";
    }

    qstring format_position(Position p)
    {
        qstring out;
        if ( !p.is_valid() )
            return out;
        out.sprnt("%llX:%llX", (uint64_t)p.hi, (uint64_t)p.lo);
        return out;
    }

    // One hex field, which must be non-empty and entirely hex. strtoull alone
    // would read "zzz" as 0 and send the cursor to the start of the recording
    // rather than saying the input was not a position.
    static bool parse_hex_field(const char *begin, const char *end, uint64_t *out)
    {
        while ( begin < end && qisspace(*begin) )
            begin++;
        while ( end > begin && qisspace(end[-1]) )
            end--;
        if ( begin == end )
            return false;

        uint64_t v = 0;
        for ( const char *c = begin; c < end; c++ )
        {
            int digit;
            if ( *c >= '0' && *c <= '9' )
                digit = *c - '0';
            else if ( *c >= 'a' && *c <= 'f' )
                digit = *c - 'a' + 10;
            else if ( *c >= 'A' && *c <= 'F' )
                digit = *c - 'A' + 10;
            else
                return false;
            if ( v > (UINT64_MAX >> 4) )
                return false;               // would overflow
            v = (v << 4) | (uint64_t)digit;
        }
        *out = v;
        return true;
    }

    bool parse_position(const char *text, Position *out)
    {
        if ( text == nullptr || out == nullptr )
            return false;
        const char *colon = strchr(text, ':');
        if ( colon == nullptr )
            return false;

        uint64_t hi = 0, lo = 0;
        if ( !parse_hex_field(text, colon, &hi)
          || !parse_hex_field(colon + 1, text + qstrlen(text), &lo) )
            return false;

        Position p{ hi, lo };
        // The sentinels are not positions a user can ask to go to.
        if ( p.is_sentinel() )
            return false;
        *out = p;
        return true;
    }
}
