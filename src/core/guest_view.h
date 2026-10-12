#pragma once

#include "common/pch.h"
#include "abi/ida_ttd_backend.h"

namespace idattd
{
    class ITraceCursor;

    // Guest memory at one position, as code that parses it wants it: fill
    // buf[0..size) from [addr, addr + size) and return how many bytes are
    // real, counted from the start without a hole -- so a caller reading one
    // structure tests == size, and a string reader scans exactly that far.
    //
    // A function rather than a cursor type, so PE parsing, string reading and
    // argument decoding are written once for every backend. The backend's
    // cursor is what answers it.
    using GuestRead = std::function<size_t(uint64_t addr, void *buf, size_t size)>;

    // Memory and registers at one position: what a calling convention reads.
    struct GuestView
    {
        GuestRead read;
        // The registers there; false when the backend cannot produce them.
        std::function<bool(ittd_regs *out)> regs;
    };

    // Through a backend's cursor at its current position. A byte the cursor
    // marks as a placeholder (mapped, value unknown) counts as real zero, which
    // is what a reader of a structure has always been given for one.
    GuestRead guest_read(ITraceCursor *cursor);
    GuestView guest_view(ITraceCursor *cursor);
}
