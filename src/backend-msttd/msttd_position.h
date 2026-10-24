#pragma once

#include "backend-msttd/msttd_pch.h"
#include "core/position.h"

namespace idattd
{
    // Inside namespace idattd an unqualified Position is the core's, so
    // engine-side code that means the Microsoft one says TtdPosition.
    using TtdPosition = TTD::Replay::Position;

    // Microsoft TTD positions in and out of the core's representation.
    //
    // The core's Position is two opaque 64-bit words, so the conversion is
    // nearly the identity: a TTD position is a (sequence, steps) pair. Only
    // the three sentinels differ in bit pattern and are translated by name.
    //
    //   core none()  <-> Position::Invalid  = { TTD::SequenceId::Invalid, 0 }
    //   core begin() <-> Position::Min      = { 0, 0 }
    //   core end()   <-> Position::Max      = { SequenceId::Max, StepCount::Max }
    //
    // The round trip is lossless because SequenceId::Invalid is UINT64_MAX:
    // no real position has that sequence, so the core's two high sentinels
    // (which do) cannot collide with one. Position::Min {0, 0} is both the
    // first position and begin(), the same place either way.
    //
    // to_core tests Position::Max before IsValid(): Max's sequence is
    // UINT64_MAX - 1 today, and testing the named constant first stays
    // correct if a future SDK changes that.

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
