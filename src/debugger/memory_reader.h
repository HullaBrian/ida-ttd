#pragma once

#include "common/pch.h"
#include "core/backend.h"
#include "debugger/module_registry.h"

namespace idattd
{
    // Serving IDA's memory reads from a recording.
    //
    // The hottest path in the plugin: every disassembly line, register
    // dereference and stack view row comes through it. A read is assembled
    // from these sources, in order of authority:
    //
    //   1. What the backend's cursor says the recording holds at the current
    //      position, including anything it rebuilt from recorded writes.
    //   2. The module's on-disk image, for bytes the recording never captured
    //      (code that did not run, such as the other side of a branch or a
    //      cold epilogue). WinDbg does the same.
    //   3. The backend's placeholder zeros (mapped, value unknown), only when
    //      nothing better exists. Believing those first made a string literal
    //      lose its first eight bytes.
    class MemoryReader
    {
    public:
        void bind(ModuleRegistry *modules);
        void reset();

        // Fill 'buffer' with 'size' bytes at 'ea' as of 'playhead''s position.
        // '*nbytes' receives how many bytes were resolved; the return is a
        // drc_t. DRC_FAILED when nothing at 'ea' is known matters: a silent
        // zero-fill makes IDA treat the whole advertised address space as
        // readable, and the register and stack views then follow garbage
        // pointers to 0 and dereference that 0 forever.
        ssize_t read(ITraceCursor *playhead, size_t *nbytes, ea_t ea, void *buffer, size_t size);

        // Have the backend rebuild [lo, hi) from recorded writes, keeping what
        // it already rebuilt there; true when any byte was recovered. For code
        // the position query only zero-fills, such as an unpacker's output
        // before it runs.
        bool reconstruct(ITraceCursor *playhead, ea_t lo, ea_t hi);

        // The same, replacing what was rebuilt for the range before. Returns
        // the bytes recovered.
        size_t reread(ITraceCursor *playhead, ea_t lo, ea_t hi);

    private:
        ModuleRegistry *m_modules = nullptr;

        // Scratch reused across calls so a read does not heap allocate:
        // clear() and resize() keep the existing capacity.
        std::vector<uint8_t> m_known;
    };
}
