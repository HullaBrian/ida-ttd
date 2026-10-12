#pragma once

#include "backend-msttd/msttd_pch.h"
#include "core/position.h"

namespace idattd
{
    // Inside namespace idattd an unqualified Position is the core's, so
    // engine-side code that means the Microsoft one says TtdPosition. That is
    // not only disambiguation: it marks every line that is specific to this
    // backend, which is what phase 3 of docs/modular-backends.md has to move.
    using TtdPosition = TTD::Replay::Position;

    // Microsoft TTD positions in and out of the core's representation.
    //
    // The core's Position is two 64-bit words with no meaning of its own, so
    // for this backend the conversion is nearly the identity -- a TTD position
    // *is* a (sequence, steps) pair. What needs care is the three sentinels,
    // whose bit patterns differ on the two sides and must be translated by
    // name rather than by reinterpretation.
    //
    //   core none()  <-> Position::Invalid  = { TTD::SequenceId::Invalid, 0 }
    //   core begin() <-> Position::Min      = { 0, 0 }
    //   core end()   <-> Position::Max      = { SequenceId::Max, StepCount::Max }
    //
    // That the round trip is lossless rests on one fact: SequenceId::Invalid is
    // UINT64_MAX, so no real TTD position has a sequence of UINT64_MAX, and the
    // core's two high sentinels (which both do) cannot collide with one.
    // Position::Min is {0, 0}, which is both the first position and the core's
    // begin() -- the same place either way, so mapping between them loses
    // nothing.
    //
    // Order matters in to_core: Position::Max must be tested before IsValid(),
    // because Max's sequence is UINT64_MAX - 1 but a future SDK could narrow
    // that, and testing the named constant first is correct either way.

    inline Position to_core(const TTD::Replay::Position &p)
    {
        if ( p == TTD::Replay::Position::Max )
            return Position::end();
        if ( !p.IsValid() )
            return Position::none();
        return Position{ (uint64_t)p.Sequence, (uint64_t)p.Steps };
    }

    inline TTD::Replay::Position from_core(const Position &p)
    {
        if ( p == Position::none() )
            return TTD::Replay::Position::Invalid;
        if ( p == Position::begin() )
            return TTD::Replay::Position::Min;
        if ( p == Position::end() )
            return TTD::Replay::Position::Max;
        return TTD::Replay::Position{ (TTD::SequenceId)p.hi,
                                      (TTD::Replay::StepCount)p.lo };
    }
}
