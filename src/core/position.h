#pragma once

#include "common/pch.h"

namespace idattd
{
    // A point in a recording, as the backend that loaded it means it.
    //
    // Two 64-bit words, which is what the backends need and no more: Microsoft
    // TTD numbers a position (sequence, steps); Sogen's is a single instruction
    // counter. The core never interprets the words -- it compares them, stores
    // them in the database, and asks the backend to render and parse them.
    //
    // Ordering is the recording's own chronology, so lexicographic order on
    // (hi, lo) has to be the order the backend replays in. Both satisfy that:
    // Microsoft's sequence/steps pair is already ordered that way, and Sogen's
    // counter goes in 'hi' with 'lo' zero.
    //
    // Two words rather than an opaque handle because a position has to be
    // cheap to copy (every row of every listing holds one), trivially
    // comparable, and storable in a netnode blob -- bookmarks and the memory
    // map keep thousands of them in the database and must not grow a backend
    // call to read one back.
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
        // 'none' is "no position", which is what a default-constructed Position
        // is and what a query that found nothing returns. 'begin' and 'end' mean
        // "the start/end of the recording, wherever that is" -- a seek resolves
        // them, and they are not the same as the first and last recorded
        // positions, which the backend reports in TraceInfo. A backend
        // translates these three explicitly; it must not assume the bit
        // patterns mean anything to its own engine.
        static constexpr Position none()  { return { SENTINEL_WORD, SENTINEL_WORD }; }
        static constexpr Position begin() { return { 0, 0 }; }
        static constexpr Position end()   { return { SENTINEL_WORD, SENTINEL_WORD - 1 }; }

        constexpr bool is_valid() const { return *this != none(); }
        constexpr bool is_sentinel() const
        { return *this == none() || *this == begin() || *this == end(); }

    private:
        // Out of the range of any real position in either backend: Microsoft's
        // sequence ids stop well short of it, and Sogen would need 2^64
        // instructions to reach it.
        static constexpr uint64_t SENTINEL_WORD = UINT64_MAX;
    };

    // Render a position the way the recording's own tooling numbers it, and
    // parse that rendering back.
    //
    // In phase 3 of docs/modular-backends.md these route through the active
    // backend (ITraceBackend::format_position). Until then there is one
    // backend and this is its convention: two hex words separated by a colon,
    // which is exactly Microsoft TTD's "Sequence:Steps".
    //
    // format_position() of an invalid position is the empty string, so a
    // listing column for a position that was never recorded comes out blank
    // rather than saying FFFFFFFFFFFFFFFF.
    qstring     format_position(Position p);
    bool        parse_position(const char *text, Position *out);
    // What to put next to an input box that takes one.
    const char *position_syntax();

    // A half-open [first, last] span of a recording. 'first' as begin() and
    // 'last' as end() is "the whole thing", which is what a query with no range
    // given means.
    struct PositionRange
    {
        Position first = Position::begin();
        Position last  = Position::end();

        constexpr bool whole_trace() const
        { return first == Position::begin() && last == Position::end(); }
    };
}
