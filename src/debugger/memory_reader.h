#pragma once

#include "common/pch.h"
#include "core/backend.h"
#include "debugger/module_registry.h"

namespace idattd
{
    // Serving IDA's memory reads from a recording.
    //
    // This is the hottest path in the plugin -- every disassembly line, every
    // register dereference and every row of the stack view comes through it.
    // A read is assembled from these sources, in order of authority:
    //
    //   1. What the backend's cursor says the recording holds at the current
    //      position, including anything it rebuilt from recorded writes.
    //   2. The module's on-disk image, for bytes the recording never captured:
    //      image-backed code that did not run on this pass, such as the other
    //      side of a branch or a cold epilogue. This is what WinDbg does.
    //   3. The backend's placeholder zeros -- memory it knows is mapped but has
    //      no value for -- only once nothing better exists. Believing those
    //      first is what made a string literal lose its first eight bytes.
    class MemoryReader
    {
    public:
        void bind(ModuleRegistry *modules);
        void reset();

        // Fill 'buffer' with 'size' bytes at 'ea', as of 'playhead''s position.
        // '*nbytes' receives how many bytes were resolved, and the return is a
        // drc_t: DRC_FAILED when nothing at 'ea' is known at all, which matters
        // -- a silent zero-fill makes IDA treat the whole advertised address
        // space as readable, and the register and stack views then dereference
        // a garbage pointer into 0, then dereference that 0, forever.
        ssize_t read(ITraceCursor *playhead, size_t *nbytes, ea_t ea, void *buffer, size_t size);

        // Have the backend rebuild [lo, hi) from the recording's writes, keeping
        // anything it already rebuilt there; true when any byte was recovered.
        // For code the position query only zero-fills -- an unpacker's output
        // before it runs.
        bool reconstruct(ITraceCursor *playhead, ea_t lo, ea_t hi);

        // The same, replacing what was rebuilt for the range before. Returns
        // the bytes recovered.
        size_t reread(ITraceCursor *playhead, ea_t lo, ea_t hi);

    private:
        ModuleRegistry *m_modules = nullptr;

        // Scratch, reused across calls: this function must not heap allocate
        // per call, and assign() keeps the existing capacity.
        std::vector<uint8_t> m_known;
    };
}
