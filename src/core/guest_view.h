#pragma once

#include "common/pch.h"
#include "abi/ida_ttd_backend.h"

namespace idattd
{
    class ITraceCursor;

    // Guest memory at one position, as parsers want it: fill buf[0..size)
    // from [addr, addr + size) and return how many leading bytes are real,
    // with no hole. A structure reader tests == size; a string reader scans
    // exactly that far.
    //
    // A function rather than a cursor type, so PE parsing, string reading and
    // argument decoding are written once for every backend.
    using GuestRead = std::function<size_t(uint64_t addr, void *buf, size_t size)>;

    // Memory and registers at one position: what a calling convention reads.
    struct GuestView
    {
        GuestRead read;
        // The registers there; false when the backend cannot produce them.
        std::function<bool(ittd_regs *out)> regs;
    };

    // Through a backend's cursor at its current position. A placeholder byte
    // (mapped, value unknown) counts as a real zero, as structure readers have
    // always been given.
    GuestRead guest_read(ITraceCursor *cursor);
    GuestView guest_view(ITraceCursor *cursor);
}
