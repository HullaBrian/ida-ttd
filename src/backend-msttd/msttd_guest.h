#pragma once

#include "backend-msttd/msttd_pch.h"
#include "core/guest_view.h"

namespace idattd
{
    // Microsoft TTD's side of core/guest_view.h: a TTD cursor as a GuestRead
    // (one QueryMemoryBuffer with the cursor's default policy), for PE header
    // and export parsing.
    GuestRead msttd_read_plain(TTD::Replay::ICursorView *cursor);

    // One word of 'width' bytes (4 or 8) at 'addr', through a cursor or a
    // thread view with its default policy; false unless all of it is known.
    template <typename V>
    inline bool msttd_read_word(V const *v, uint64_t addr, uint32_t width, uint64_t *out) noexcept
    {
        uint64_t tmp = 0;
        const auto mb = v->QueryMemoryBuffer(TTD::GuestAddress{ addr }, TTD::BufferView{ &tmp, width });
        if ( mb.Memory.Size != width )
            return false;
        *out = tmp;
        return true;
    }

    // The engine's register context as the ABI's canonical register set.
    void regs_from_context(const CROSS_PLATFORM_CONTEXT &ctx, bool is64, ittd_regs *out);
}
