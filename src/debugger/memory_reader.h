#pragma once

#include "common/pch.h"
#include "debugger/module_registry.h"

namespace idattd
{
    // Serving IDA's memory reads from a recording.
    //
    // This is the hottest path in the plugin -- every disassembly line, every
    // register dereference and every row of the stack view comes through it --
    // and it is also where the recording is least straightforward. A trace only
    // holds memory that was accessed, and the replay engine answers "I do not
    // know" and "this page is mapped and reads as zero" with the same shape of
    // answer. Getting that distinction wrong is what made a string literal
    // render with its first eight bytes missing.
    //
    // So a read is assembled from three sources, in order of authority:
    //
    //   1. What the recording holds at the current position, which reflects the
    //      true state including self-modified code.
    //   2. Bytes rebuilt from the recording's own writes, for memory the
    //      position query will only zero-fill -- an unpacker's output that has
    //      not been executed yet at this position.
    //   3. The module's on-disk image, for bytes the recording never captured:
    //      image-backed code that did not run on this pass, such as the other
    //      side of a branch or a cold epilogue. This is what WinDbg does.
    //
    // Only then are the engine's zero placeholders served, because by that
    // point nothing better exists.
    class MemoryReader
    {
    public:
        void bind(TTD::Replay::IReplayEngine *engine, ModuleRegistry *modules);
        void reset();

        // Fill 'buffer' with 'size' bytes at 'ea', as of 'playhead''s position.
        // '*nbytes' receives how many bytes were resolved, and the return is a
        // drc_t: DRC_FAILED when nothing at 'ea' is known at all, which matters
        // -- a silent zero-fill makes IDA treat the whole advertised address
        // space as readable, and the register and stack views then dereference
        // a garbage pointer into 0, then dereference that 0, forever.
        ssize_t read(TTD::Replay::ICursorView *playhead,
                     size_t *nbytes, ea_t ea, void *buffer, size_t size);

        // Rebuild the real bytes of [lo, hi) from the recording's writes, up to
        // 'playhead''s position, and keep them for later reads.
        //
        // The position query zero-fills non-module memory that was written
        // earlier but not executed at the current position -- an unpacker
        // decompressing a payload is the usual case. Replaying forward with a
        // Write watchpoint over the range captures the latest written value of
        // each byte, which is what WinDbg shows there. True when any byte was
        // recovered.
        bool reconstruct(TTD::Replay::ICursorView *playhead, ea_t lo, ea_t hi);

    private:
        TTD::Replay::IReplayEngine *m_engine  = nullptr;
        ModuleRegistry             *m_modules = nullptr;

        // Reads are served from a cursor that is only ever positioned, never
        // executed. The execution cursor cannot do this job: a cursor left "in
        // execution" answers memory queries with the thread-local policy
        // whatever policy was asked for, so the aggressive policies below were
        // simply ignored and non-executed bytes came back as zeros.
        TTD::Replay::UniqueCursor m_cursor;
        TTD::Replay::Position     m_pos{};        // where m_cursor is parked
        bool                      m_posValid = false;

        // Scratch buffers, reused across calls. This function must not heap
        // allocate per call; assign() keeps the existing capacity.
        std::vector<uint8_t> m_filled;   // what is known about each output byte
        std::vector<uint8_t> m_probe;    // destination for the all-zero probe

        struct ReconRegion
        {
            ea_t                 lo = 0, hi = 0;
            std::vector<uint8_t> data;     // hi - lo bytes
            std::vector<bool>    known;    // which of them were recovered
        };
        std::vector<ReconRegion> m_regions;
    };
}
