#pragma once

#include "backend-msttd/msttd_pch.h"
#include "core/guest_view.h"

namespace idattd
{
    // Microsoft TTD's side of core/guest_view.h: a TTD cursor as a GuestRead
    // or GuestView. Two read behaviours, because the callers relied on two:
    //
    //   plain       one QueryMemoryBuffer with the cursor's default policy --
    //               what PE header and export parsing has always used.
    //   aggressive  GloballyAggressive then InFragmentAggressive, stepping over
    //               holes -- what argument and string decoding has always used,
    //               because a call's arguments are often in memory the calling
    //               thread did not itself touch at that position.
    GuestRead msttd_read_plain(TTD::Replay::ICursorView *cursor);
    GuestRead msttd_read_aggressive(TTD::Replay::ICursorView *cursor);
    GuestView msttd_view(TTD::Replay::ICursorView *cursor, bool is64);

    // The engine's register context as the ABI's canonical register set.
    void regs_from_context(const CROSS_PLATFORM_CONTEXT &ctx, bool is64, ittd_regs *out);
}
