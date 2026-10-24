#pragma once

#include "common/pch.h"

namespace idattd
{
    // A point in a recording, as the backend that loaded it means it.
    //
    // Two 64-bit words: Microsoft TTD uses (sequence, steps), Sogen a single
    // instruction counter in 'lo' with 'hi' zero. The core never interprets
    // them; it compares them, stores them, and asks the backend to render and
    // parse them.
    //
    // Lexicographic order on (hi, lo) must be the recording's chronology,
    // which both backends satisfy.
    //
    // Two words rather than an opaque handle so a position is cheap to copy
    // (every listing row holds one), trivially comparable, and storable in a
    // netnode blob without a backend call to read it back (bookmarks and the
    // memory map keep thousands).
    struct Position
    {
        uint64_t hi = SENTINEL_WORD;
        uint64_t lo = SENTINEL_WORD;

        constexpr Position() = default;
        constexpr Position(uint64_t h, uint64_t l) : hi(h), lo(l) {}

        constexpr bool operator==(const Position &o) const { return hi == o.hi && lo == o.lo; }
        constexpr bool operator!=(const Position &o) const { return !(*this == o); }
        constexpr bool operator< (const Position &o) const { return hi != o.hi ? hi < o.hi : lo < o.lo; }
        constexpr bool operator> (const Position &o) const { return o < *this; }
        constexpr bool operator<=(const Position &o) const { return !(o < *this); }
        constexpr bool operator>=(const Position &o) const { return !(*this < o); }

        // The three sentinels every backend has to be able to express.
        //
        // 'none' is "no position": a default-constructed Position, and what a
        // query that found nothing returns. 'begin' and 'end' mean "the
        // start/end of the recording, wherever that is"; a seek resolves them.
        // They differ from the first and last recorded positions in
        // TraceInfo. A backend translates all three explicitly and must not
        // assume the bit patterns mean anything to its engine.
        static constexpr Position none()  { return { SENTINEL_WORD, SENTINEL_WORD }; }
        static constexpr Position begin() { return { 0, 0 }; }
        static constexpr Position end()   { return { SENTINEL_WORD, SENTINEL_WORD - 1 }; }

        constexpr bool is_valid() const { return *this != none(); }
        constexpr bool is_sentinel() const
        { return *this == none() || *this == begin() || *this == end(); }

    private:
        // Beyond any real position: Microsoft's sequence ids stop well short of
        // it, and Sogen would need 2^64 instructions to reach it.
        static constexpr uint64_t SENTINEL_WORD = UINT64_MAX;
    };

    class ITraceBackend;

    // Render a position the way the recording's own tooling numbers it, and
    // parse it back, through the running session's backend
    // (set_position_backend): instruction numbers for Sogen, Sequence:Steps
    // for Microsoft. With none set, Microsoft's notation, in which positions
    // stored before backends existed are written.
    //
    // An invalid position formats as "", so a listing column comes out blank
    // rather than FFFFFFFFFFFFFFFF.
    qstring     format_position(Position p);
    bool        parse_position(const char *text, Position *out);
    // What to put next to an input box that takes one.
    const char *position_syntax();

    // The backend the three above defer to; nullptr for none. The session
    // sets it when a recording opens and clears it when it closes.
    void set_position_backend(const ITraceBackend *backend);

    // Microsoft TTD's notation, two hex words "Sequence:Steps": the default
    // above, and what its backend answers with.
    qstring     format_hex_position(Position p);
    bool        parse_hex_position(const char *text, Position *out);
    const char *hex_position_syntax();

    // A span of a recording, from 'first' to 'last'. begin() to end() is the
    // whole recording, the default for a query with no range.
    struct PositionRange
    {
        Position first = Position::begin();
        Position last  = Position::end();

        constexpr bool whole_trace() const
        { return first == Position::begin() && last == Position::end(); }
    };
}
